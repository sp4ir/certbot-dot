FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o certbot-dot .

FROM alpine:3.20
COPY --from=builder /app/certbot-dot /usr/local/bin/
ENTRYPOINT ["certbot-dot"]
