# Build stage
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/scan ./cmd/scan

# Runtime: pandoc optional for docx (apk add pandoc)
FROM alpine:3.20
RUN apk add --no-cache ca-certificates docker-cli pandoc
COPY --from=build /out/scan /usr/local/bin/scan
WORKDIR /workspace
ENV DAST_WORKDIR=/workspace/work
ENTRYPOINT ["/usr/local/bin/scan"]
