.PHONY: build run clean test

# Build the oauth-proxy binary
build:
	go build -o oauth-proxy cmd/oauth-proxy/main.go

# Run the oauth-proxy service
run:
	./run.sh

# Run directly with go run
dev:
	go run cmd/oauth-proxy/main.go

# Clean build artifacts
clean:
	rm -f oauth-proxy

# Test build without running
test:
	go build -o /dev/null cmd/oauth-proxy/main.go

# Install dependencies
deps:
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Check for issues
vet:
	go vet ./...
