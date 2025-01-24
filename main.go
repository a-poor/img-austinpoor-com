package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
)

const (
	keyFile = "image-file"
	keySize = "image-size"
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

		// Get the file

		// Process the request
		// ...
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
		Handler:      mux,
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
