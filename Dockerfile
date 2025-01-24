FROM golang:1.23.5-alpine
ENV CGO_ENABLED=1
WORKDIR /app
RUN apk update \
 && apk upgrade \
 && apk add --no-cache vips vips-dev build-base libheif-tools
COPY go.mod go.sum .
RUN go mod download
COPY . .
RUN go build -o /app/main .
CMD [ "/app/main" ]
