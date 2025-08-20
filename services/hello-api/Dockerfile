# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/hello-api main.go

# Run stage
FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=builder /out/hello-api /app/hello-api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/hello-api"]
