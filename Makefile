.PHONY: test test-verbose test-coverage test-all clean

# Run all tests
test:
	DNSBOX_DOMAIN=test.com DNSBOX_IP=127.0.0.1 DNSBOX_NS_NAME=ns1 go test ./...

# Run tests with verbose output
test-verbose:
	DNSBOX_DOMAIN=test.com DNSBOX_IP=127.0.0.1 DNSBOX_NS_NAME=ns1 go test -v ./...

# Run tests with coverage
test-coverage:
	DNSBOX_DOMAIN=test.com DNSBOX_IP=127.0.0.1 DNSBOX_NS_NAME=ns1 go test -cover ./...

# Run tests with coverage report
test-coverage-html:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run tests for specific package
test-resolver:
	go test -v ./internal/resolver/...

test-blacklist:
	go test -v ./internal/blacklist/...

test-txtstore:
	go test -v ./internal/txtstore/...

test-certshare:
	go test -v ./internal/certshare/...

test-customdns:
	go test -v ./internal/customdns/...

# Run all tests with race detector
test-race:
	go test -race ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Clean test artifacts
clean:
	rm -f coverage.out coverage.html

# Run linter (if golangci-lint is installed)
lint:
	golangci-lint run

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

