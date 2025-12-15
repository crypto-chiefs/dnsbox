# Testing Guide for DNSBox

This document describes the testing infrastructure and how to run tests for DNSBox.

## Test Coverage

We've created comprehensive unit tests for the following critical components:

### ✅ Completed Test Suites

1. **`internal/resolver/`** - IP address parsing
   - Tests for `ParseIPv4()` with various formats (dash, dot, edge cases)
   - Tests for `ParseIPv6()` with compressed and full formats
   - Benchmark tests for performance

2. **`internal/blacklist/`** - IP blocking functionality
   - Tests for exact IP matching
   - Tests for CIDR range blocking
   - Tests for IPv6 blocking
   - Tests for idempotent loading

3. **`internal/txtstore/`** - TXT record storage
   - Tests for Set/Get/Delete operations
   - Tests for TTL expiration
   - Tests for concurrent access
   - Tests for FQDN normalization

4. **`internal/certshare/`** - Certificate encryption/sharing
   - Tests for ephemeral key generation
   - Tests for shared key computation (ECDH)
   - Tests for certificate encryption/decryption
   - Tests for wrong key decryption (security)
   - Benchmark tests

5. **`internal/customdns/`** - Custom DNS record matching
   - Tests for various record types (A, TXT, CNAME, MX)
   - Tests for case-insensitive matching
   - Tests for FQDN handling

## Running Tests

### Using Make (Recommended)

```bash
# Run all tests
make test

# Run tests with verbose output
make test-verbose

# Run tests with coverage
make test-coverage

# Generate HTML coverage report
make test-coverage-html

# Run tests for specific package
make test-resolver
make test-blacklist
make test-txtstore
make test-certshare
make test-customdns

# Run tests with race detector
make test-race

# Run benchmarks
make bench
```

### Using Go Directly

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run tests for specific package
go test -v ./internal/resolver/...

# Run tests with race detector
go test -race ./...

# Run benchmarks
go test -bench=. -benchmem ./...

# Run specific test
go test -v -run TestParseIPv4 ./internal/resolver/...
```

## Test Structure

Each test file follows Go testing conventions:

- Test functions start with `Test`
- Benchmark functions start with `Benchmark`
- Table-driven tests for multiple scenarios
- Helper functions for test setup/teardown

## Continuous Integration

A GitHub Actions workflow (`.github/workflows/test.yml`) is configured to:

- Run tests on push and pull requests
- Test against multiple Go versions (1.21, 1.22, 1.23)
- Run race detector
- Generate coverage reports
- Run linter (golangci-lint)

## Writing New Tests

When adding new functionality, follow these guidelines:

1. **Test file naming**: `*_test.go` in the same package
2. **Test function naming**: `TestFunctionName` or `TestFeature_Scenario`
3. **Use table-driven tests** for multiple test cases:
   ```go
   tests := []struct {
       name     string
       input    string
       expected string
   }{
       {"case1", "input1", "expected1"},
       {"case2", "input2", "expected2"},
   }
   for _, tt := range tests {
       t.Run(tt.name, func(t *testing.T) {
           // test code
       })
   }
   ```

4. **Test edge cases**: empty strings, nil values, boundary conditions
5. **Test error cases**: invalid input, missing resources
6. **Test concurrency**: when applicable, test concurrent access
7. **Add benchmarks**: for performance-critical code

## Test Coverage Goals

- **Current**: Core functionality covered
- **Target**: 80%+ coverage for critical paths
- **Priority**: Security-critical functions (encryption, validation)

## Known Limitations

1. **Integration tests**: Currently only unit tests exist. Integration tests for:
   - DNS server responses
   - Let's Encrypt certificate issuance (requires staging environment)
   - Peer discovery
   - HTTP API endpoints

2. **Mock dependencies**: Some tests may require mocking external dependencies:
   - DNS queries
   - HTTP requests
   - File system operations

## Future Test Improvements

- [ ] Add integration tests for DNS server
- [ ] Add integration tests for certificate issuance (staging)
- [ ] Add tests for API handlers
- [ ] Add tests for DNS handler
- [ ] Add tests for HTTPS proxy
- [ ] Add tests for peer discovery
- [ ] Add tests for configuration loading
- [ ] Add fuzzing tests for input validation

## Contributing

When contributing code:

1. Write tests for new functionality
2. Ensure all tests pass: `make test`
3. Maintain or improve test coverage
4. Update this document if adding new test infrastructure

