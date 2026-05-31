FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY static/ ./static/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o hermit-dock .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=builder /app/hermit-dock /usr/local/bin/hermit-dock

EXPOSE 8080
CMD ["hermit-dock"]
