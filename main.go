package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/davidbyttow/govips/v2/vips"
	"github.com/google/uuid"
)

const (
	keyFile   = "image-file"
	keyWidth  = "width"
	keyFormat = "format"
	keyQuality = "quality"
)

var (
	port = "8080"
	key  = "secret"
)

func main() {
	// Get environment config
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}
	if k := os.Getenv("API_KEY"); k != "" {
		key = k
	}

	// Get the logger
	logger := getLogger()
	logger.Debug("Starting")

	// Create the server
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/transform-image", func(w http.ResponseWriter, r *http.Request) {
		// Check the API key
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		// Parse the form
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			logger.ErrorContext(r.Context(), "Failed to parse form", "err", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Bad Request"))
			return
		}

		// Get width from the args
		swidth := r.FormValue(keyWidth)
    width, err := parseSize(swidth)
    if err != nil {
      logger.ErrorContext(r.Context(), "Failed to parse width", "err", err)
      w.WriteHeader(http.StatusBadRequest)
      w.Write([]byte("Bad Request. Invalid width."))
      return
    }
		
    // Get width from the args
    qual := 80
		if squal := r.FormValue(keyQuality); squal != "" {
      qual, err = parseSize(squal)
      if err != nil {
        logger.ErrorContext(r.Context(), "Failed to parse quality", "err", err)
        w.WriteHeader(http.StatusBadRequest)
        w.Write([]byte("Bad Request. Invalid quality."))
        return
      }
    }
		
		// Get height from the args
    format, err := parseFormat(r.FormValue(keyFormat))
    if err != nil {
      logger.ErrorContext(r.Context(), "Failed to parse format", "err", err)
      w.WriteHeader(http.StatusBadRequest)
      w.Write([]byte("Bad Request. Invalid format."))
      return
    }

		// Get the file
		f, _, err := r.FormFile(keyFile)
		if err != nil {
			logger.ErrorContext(r.Context(), "Failed to get file", "err", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Bad Request"))
			return
		}
    defer f.Close()

    // Read the image to a buffer
    buf, err := io.ReadAll(f)
    if err != nil {
      logger.ErrorContext(r.Context(), "Failed to read file", "err", err)
      w.WriteHeader(http.StatusInternalServerError)
      w.Write([]byte("Internal Server Error"))
      return
    }

    // Make the image
    img, err := vips.NewImageFromBuffer(buf)
    if err != nil {
      logger.ErrorContext(r.Context(), "Failed to create image", "err", err)
      w.WriteHeader(http.StatusInternalServerError)
      w.Write([]byte("Internal Server Error"))
      return
    }

    // Resize the image
    if width > 0 {
      resize := float64(width) / float64(img.Width())
      if err := img.Resize(resize, vips.KernelLanczos3); err != nil {
        logger.ErrorContext(r.Context(), "Failed to resize image", "err", err)
        w.WriteHeader(http.StatusInternalServerError)
        w.Write([]byte("Internal Server Error"))
        return
      }
    }

    // Encode the image
    var out []byte
    switch format {
    case "jpeg":
      out, _, err = img.ExportJpeg(&vips.JpegExportParams{
        StripMetadata: true,
        Quality: qual,
      })
    case "webp":
      out, _, err = img.ExportWebp(&vips.WebpExportParams{
        StripMetadata: true,
        Quality: qual,
      })
    case "avif":
      out, _, err = img.ExportAvif(&vips.AvifExportParams{
        StripMetadata: true,
        Quality: qual,
      })
    default:
      logger.ErrorContext(
        r.Context(),
        "Invalid format. How'd that get here!",
        "format", format,
      )
      w.WriteHeader(http.StatusInternalServerError)
      w.Write([]byte("Internal Server Error"))
      return
    }
    if err != nil {
      logger.ErrorContext(r.Context(), "Failed to encode image", "err", err)
      w.WriteHeader(http.StatusInternalServerError)
      w.Write([]byte("Internal Server Error"))
      return
    }

    // Write the image
    w.Header().Set("Content-Type", "image/"+format)
    w.Header().Set("Content-Length", strconv.Itoa(len(out)))
    w.WriteHeader(http.StatusOK)
    w.Write(out)

	})
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	// Create the context
	ctx := context.Background()

	// Start the server
	svr := &http.Server{
		Addr:         ":" + port,
		Handler:      makeLogMiddleware(logger)(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	// Start the server
	go func() {
		if err := svr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", "err", err)
		}
	}()

	// Wait for a signal to stop
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Gracefully shutdown the server (w/ a 30s timeout)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := svr.Shutdown(ctx); err != nil {
		logger.Error("Server shutdown failed", "err", err)
	}
}

func getLogger() *slog.Logger {
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	return slog.New(h)
}

func makeLogMiddleware(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rid, err := uuid.NewRandom()
			if err != nil {
				logger.ErrorContext(
					r.Context(),
					"Failed to generate request ID. Not Stopping.",
					"err", err,
				)
			}

			// Add the request ID to the context
			ctx := context.WithValue(r.Context(), "requestId", rid.String())
			logger.DebugContext(ctx, "Request received")

      // Add the request ID to the response
      w.Header().Set("X-Request-ID", rid.String())

			// Call the next handler
			start := time.Now()
			next.ServeHTTP(w, r.WithContext(ctx))
			dur := time.Since(start)

			// Log the request
			logger.InfoContext(
				ctx,
				"Request",
				"method", r.Method,
				"path", r.URL.Path,
				"duration", dur,
				"remoteAddr", r.RemoteAddr,
				"userAgent", r.UserAgent(),
				"bodySize", r.ContentLength,
			)
		})
	}
}

func parseFormat(f string) (string, error) {
	switch f {
	case "jpeg", "webp", "avif":
		return f, nil
	}
	return "", fmt.Errorf("invalid format %q", f)
}

func parseSize(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	if n < 1 || n > 4096 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n, nil
}
