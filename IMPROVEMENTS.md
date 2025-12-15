# DNSBox - Future Improvements Analysis

## Executive Summary

DNSBox is a well-structured Go project that provides DNS services and Let's Encrypt certificate management for IP addresses. This document outlines potential improvements across multiple dimensions: code quality, security, testing, performance, observability, and maintainability.

---

## 1. Testing & Quality Assurance

### Current State
- **No test files found** in the repository
- No CI/CD pipeline visible (though goreleaser.yaml exists)
- No test coverage metrics

### Recommendations

#### 1.1 Unit Tests
- **Priority: HIGH**
- Add unit tests for core functionality:
  - `resolver.ParseIPv4()` and `ParseIPv6()` - critical parsing logic
  - `blacklist.IsBlocked()` - security-critical
  - `txtstore` operations - data integrity
  - `certshare` encryption/decryption - security-critical
  - `customdns.Match()` - DNS record matching

#### 1.2 Integration Tests
- **Priority: MEDIUM**
- Test DNS server responses for various query types
- Test Let's Encrypt certificate issuance flow (using staging environment)
- Test peer discovery and certificate sharing

#### 1.3 Test Infrastructure
```go
// Example test structure
// internal/resolver/resolver_test.go
func TestParseIPv4(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected net.IP
    }{
        {"dash format", "1-2-3-4.dnsbox.io", net.ParseIP("1.2.3.4")},
        {"dot format", "1.2.3.4.dnsbox.io", net.ParseIP("1.2.3.4")},
    }
    // ...
}
```

#### 1.4 CI/CD Pipeline
- Add GitHub Actions workflow for:
  - Running tests on PR
  - Linting (golangci-lint)
  - Security scanning (gosec, govulncheck)
  - Test coverage reporting

---

## 2. Error Handling & Resilience

### Current Issues

#### 2.1 DNS Server Error Handling
**File**: `internal/dnsserver/server.go`
- UDP server errors are fatal but run in goroutine
- TCP server blocks main thread on error
- No graceful shutdown mechanism

**Recommendation**:
```go
func Start() error {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    var wg sync.WaitGroup
    errChan := make(chan error, 2)
    
    // UDP server
    wg.Add(1)
    go func() {
        defer wg.Done()
        if err := dns.ListenAndServe(":53", "udp", nil); err != nil {
            errChan <- fmt.Errorf("UDP server: %w", err)
        }
    }()
    
    // TCP server
    wg.Add(1)
    go func() {
        defer wg.Done()
        if err := dns.ListenAndServe(":53", "tcp", nil); err != nil {
            errChan <- fmt.Errorf("TCP server: %w", err)
        }
    }()
    
    // Wait for first error or context cancellation
    select {
    case err := <-errChan:
        cancel()
        return err
    case <-ctx.Done():
        return ctx.Err()
    }
}
```

#### 2.2 Certificate Issuance Retry Logic
**File**: `internal/letsencrypt/letsencrypt.go`
- No retry mechanism for failed certificate issuance
- Rate limiting not handled (Let's Encrypt has rate limits)

**Recommendation**:
- Implement exponential backoff for retries
- Add rate limit detection and handling
- Cache failed attempts to avoid repeated failures

#### 2.3 Peer Discovery Failures
**File**: `internal/utils/peers.go`
- Single point of failure if root servers are unreachable
- No fallback mechanism
- Cache expiration might cause thundering herd

**Recommendation**:
- Implement multiple fallback strategies
- Add jitter to cache expiration
- Use background refresh before expiration

---

## 3. Security Enhancements

### Current Security Concerns

#### 3.1 API Endpoint Security
**File**: `internal/api/server.go`
- No authentication on `/acme-challenge` endpoint
- No rate limiting on API endpoints
- No input validation on some endpoints

**Recommendations**:
```go
// Add rate limiting middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
    limiter := rate.NewLimiter(rate.Every(time.Second), 10)
    return func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
            return
        }
        next(w, r)
    }
}

// Add input validation
func validateFQDN(fqdn string) bool {
    // Validate FQDN format
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, fqdn)
    return matched && len(fqdn) < 255
}
```

#### 3.2 Certificate Storage Security
**File**: `internal/letsencrypt/letsencrypt.go`
- Certificates stored with 0600 permissions (good)
- No encryption at rest for stored certificates
- Hard-coded path `/var/lib/dnsbox/certs`

**Recommendations**:
- Make certificate directory configurable
- Consider encryption at rest for sensitive environments
- Add certificate rotation policy

#### 3.3 DNS Query Security
**File**: `internal/dnsserver/handler.go`
- No query rate limiting
- Potential for DNS amplification attacks
- No validation of query source

**Recommendations**:
- Implement per-IP rate limiting
- Add response size limits
- Consider DNS-over-HTTPS (DoH) support

#### 3.4 Certificate Sharing Security
**File**: `internal/certshare/certshare.go`
- Ephemeral key exchange looks secure (X25519)
- No verification of peer identity
- Callback URL could be manipulated

**Recommendations**:
- Add peer authentication/authorization
- Validate callback URLs
- Add timeout for certificate sharing operations

---

## 4. Configuration Management

### Current State
- Configuration via environment variables only
- Hard-coded values scattered throughout code
- No configuration file support

### Recommendations

#### 4.1 Structured Configuration
```go
// internal/config/config.go
type Config struct {
    Domain      string        `yaml:"domain" env:"DNSBOX_DOMAIN"`
    IP          string        `yaml:"ip" env:"DNSBOX_IP"`
    NSName      string        `yaml:"ns_name" env:"DNSBOX_NS_NAME"`
    Debug       bool          `yaml:"debug" env:"DNSBOX_DEBUG"`
    
    // New configurable options
    CertDir     string        `yaml:"cert_dir" env:"DNSBOX_CERT_DIR" default:"/var/lib/dnsbox/certs"`
    DNSPort     int           `yaml:"dns_port" env:"DNSBOX_DNS_PORT" default:"53"`
    HTTPPort    int           `yaml:"http_port" env:"DNSBOX_HTTP_PORT" default:"80"`
    HTTPSPort   int           `yaml:"https_port" env:"DNSBOX_HTTPS_PORT" default:"443"`
    CacheTTL    time.Duration `yaml:"cache_ttl" env:"DNSBOX_CACHE_TTL" default:"5m"`
    
    // Security settings
    RateLimit   RateLimitConfig `yaml:"rate_limit"`
    TLS         TLSConfig       `yaml:"tls"`
}

func LoadConfig(path string) (*Config, error) {
    // Support YAML/JSON config files with env var overrides
}
```

#### 4.2 Configuration Validation
- Validate IP addresses format
- Validate domain names
- Check port availability
- Validate file paths and permissions

---

## 5. Observability & Monitoring

### Current State
- Basic logging via custom logger
- No metrics collection
- No distributed tracing
- No health check endpoints

### Recommendations

#### 5.1 Structured Logging
```go
// Replace custom logger with structured logging (e.g., zerolog or logrus)
import "github.com/rs/zerolog"

logger := zerolog.New(os.Stdout).
    With().
    Timestamp().
    Str("service", "dnsbox").
    Logger()

logger.Info().
    Str("domain", domain).
    Str("ip", ip).
    Msg("DNS query received")
```

#### 5.2 Metrics Collection
```go
// Add Prometheus metrics
import "github.com/prometheus/client_golang/prometheus"

var (
    dnsQueriesTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "dns_queries_total",
            Help: "Total number of DNS queries",
        },
        []string{"type", "status"},
    )
    
    certIssuanceDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "cert_issuance_duration_seconds",
            Help: "Time taken to issue certificate",
        },
        []string{"domain", "status"},
    )
)
```

#### 5.3 Health Check Endpoint
```go
// internal/api/health.go
func handleHealth(w http.ResponseWriter, r *http.Request) {
    health := map[string]interface{}{
        "status": "healthy",
        "dns": checkDNSServer(),
        "cert_dir": checkCertDir(),
        "peers": checkPeerConnectivity(),
    }
    json.NewEncoder(w).Encode(health)
}
```

#### 5.4 Distributed Tracing
- Add OpenTelemetry support for tracing certificate issuance flow
- Track DNS queries across components

---

## 6. Performance Optimizations

### Current Issues

#### 6.1 DNS Handler Performance
**File**: `internal/dnsserver/handler.go`
- Large switch statement with repeated logic
- No connection pooling for peer queries
- Synchronous peer discovery in hot path

**Recommendations**:
- Refactor handler into separate handlers per query type
- Use connection pooling for HTTP requests to peers
- Make peer discovery async with background refresh

#### 6.2 Certificate Caching
**File**: `internal/httpsproxy/httpsproxy.go`
- Certificates loaded from disk on every TLS handshake
- No in-memory certificate cache

**Recommendations**:
```go
type certCache struct {
    mu    sync.RWMutex
    certs map[string]*tls.Certificate
    times map[string]time.Time
}

func (c *certCache) Get(domain string) (*tls.Certificate, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    cert, ok := c.certs[domain]
    if ok && time.Since(c.times[domain]) < 1*time.Hour {
        return cert, true
    }
    return nil, false
}
```

#### 6.3 TXT Store Performance
**File**: `internal/txtstore/memory.go`
- Sequential peer queries
- No connection reuse

**Recommendations**:
- Query peers in parallel
- Use HTTP connection pooling
- Implement better caching strategy

---

## 7. Code Quality & Maintainability

### Current Issues

#### 7.1 Code Duplication
- DNS record creation logic repeated in handler
- Similar error handling patterns

**Recommendation**: Extract helper functions
```go
func createARecord(name string, ip net.IP, ttl uint32) *dns.A {
    return &dns.A{
        Hdr: dns.RR_Header{
            Name:   dns.Fqdn(name),
            Rrtype: dns.TypeA,
            Class:  dns.ClassINET,
            Ttl:    ttl,
        },
        A: ip,
    }
}
```

#### 7.2 Magic Numbers
- Hard-coded TTL values (60, 300, etc.)
- Hard-coded timeouts
- Hard-coded ports

**Recommendation**: Extract to constants or configuration

#### 7.3 Error Messages
- Some error messages are in Russian (e.g., line 74 in handlers.go)
- Inconsistent error formatting

**Recommendation**: Standardize on English, use structured errors

#### 7.4 Function Complexity
- `handleQuery()` is very long (394 lines)
- Multiple responsibilities

**Recommendation**: Split into smaller, focused functions

---

## 8. Documentation

### Current State
- Good README with multiple languages
- No API documentation
- No code comments for complex logic
- No architecture diagrams

### Recommendations

#### 8.1 Code Documentation
- Add godoc comments to all exported functions
- Document complex algorithms (e.g., peer discovery)
- Add examples for key functions

#### 8.2 API Documentation
- Document REST API endpoints (OpenAPI/Swagger)
- Document DNS query/response formats
- Add usage examples

#### 8.3 Architecture Documentation
- Create architecture diagram
- Document certificate issuance flow
- Document peer discovery mechanism

---

## 9. Feature Enhancements

### 9.1 Certificate Renewal
**Current**: Certificates checked on access, reissued if invalid
**Enhancement**: Background renewal job before expiration
```go
func StartRenewalScheduler() {
    ticker := time.NewTicker(24 * time.Hour)
    go func() {
        for range ticker.C {
            renewExpiringCertificates()
        }
    }()
}
```

### 9.2 DNS-over-HTTPS (DoH) Support
- Add DoH endpoint for DNS queries
- Improve privacy and security

### 9.3 DNS-over-TLS (DoT) Support
- Add DoT server on port 853
- Encrypted DNS queries

### 9.4 IPv6 Support Improvements
- Better IPv6 parsing and handling
- IPv6 peer discovery

### 9.5 Admin API
- REST API for managing custom DNS records
- Certificate management endpoints
- Statistics and monitoring endpoints

### 9.6 Configuration Hot Reload
- Reload configuration without restart
- Reload custom DNS records without restart

---

## 10. Dependency Management

### Current State
- Minimal dependencies (good)
- Using `golang.org/x/crypto` for ACME
- Using `miekg/dns` for DNS

### Recommendations
- Regular dependency updates
- Use `go mod tidy` regularly
- Monitor for security vulnerabilities (use `govulncheck`)
- Consider dependency pinning for production

---

## 11. Deployment & Operations

### Current State
- Installation script available
- Systemd service file
- Goreleaser for releases

### Recommendations

#### 11.1 Container Support
- Add Dockerfile
- Add Docker Compose for development
- Support for Kubernetes deployments

#### 11.2 Health Checks
- Systemd health check
- Kubernetes liveness/readiness probes

#### 11.3 Graceful Shutdown
```go
func main() {
    // Setup signal handling
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    // Start servers with context
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // Graceful shutdown
    <-sigChan
    logger.Info("Shutting down...")
    cancel()
    // Wait for servers to stop
}
```

---

## 12. Priority Matrix

### High Priority (Security & Stability)
1. ✅ Add authentication/rate limiting to API endpoints
2. ✅ Implement proper error handling and graceful shutdown
3. ✅ Add unit tests for security-critical functions
4. ✅ Fix hard-coded paths and add configuration management

### Medium Priority (Quality & Maintainability)
5. ✅ Add structured logging and metrics
6. ✅ Refactor large functions (especially `handleQuery`)
7. ✅ Add health check endpoints
8. ✅ Implement certificate caching

### Low Priority (Features & Polish)
9. ✅ Add DoH/DoT support
10. ✅ Add admin API
11. ✅ Improve documentation
12. ✅ Add container support

---

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)
- Add unit tests for core functions
- Implement structured configuration
- Add graceful shutdown
- Fix error handling

### Phase 2: Security & Observability (Weeks 3-4)
- Add API authentication/rate limiting
- Implement structured logging
- Add metrics collection
- Add health checks

### Phase 3: Performance & Quality (Weeks 5-6)
- Refactor DNS handler
- Implement certificate caching
- Optimize peer queries
- Code cleanup and documentation

### Phase 4: Features (Weeks 7-8)
- Background certificate renewal
- Admin API
- Container support
- Additional DNS protocols (DoH/DoT)

---

## Conclusion

DNSBox is a solid foundation with good architecture. The main areas for improvement are:
1. **Testing** - Critical for reliability
2. **Security** - API endpoints need protection
3. **Observability** - Need metrics and better logging
4. **Code Quality** - Refactoring and documentation
5. **Configuration** - More flexibility needed

Following these recommendations will significantly improve the project's reliability, security, and maintainability.

