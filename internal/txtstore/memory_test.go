package txtstore

import (
	"testing"
	"time"
)

func TestSetAndGetLocal(t *testing.T) {
	// Clear store before test
	mu.Lock()
	store = make(map[string]entry)
	mu.Unlock()

	fqdn := "test.example.com"
	value := "test-value"
	ttl := 60

	Set(fqdn, value, ttl)

	got, ok := GetLocal(fqdn)
	if !ok {
		t.Errorf("GetLocal(%q) = (_, false), want (_, true)", fqdn)
	}
	if got != value {
		t.Errorf("GetLocal(%q) = %q, want %q", fqdn, got, value)
	}
}

func TestGetLocalExpired(t *testing.T) {
	// Clear store before test
	mu.Lock()
	store = make(map[string]entry)
	mu.Unlock()

	fqdn := "expired.example.com"
	value := "expired-value"
	ttl := 1 // 1 second TTL

	Set(fqdn, value, ttl)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	got, ok := GetLocal(fqdn)
	if ok {
		t.Errorf("GetLocal(%q) = (%q, true), want (_, false) after expiration", fqdn, got)
	}
	if got != "" {
		t.Errorf("GetLocal(%q) = %q, want empty string after expiration", fqdn, got)
	}
}

func TestGetLocalNotExists(t *testing.T) {
	// Clear store before test
	mu.Lock()
	store = make(map[string]entry)
	mu.Unlock()

	fqdn := "nonexistent.example.com"

	got, ok := GetLocal(fqdn)
	if ok {
		t.Errorf("GetLocal(%q) = (%q, true), want (_, false)", fqdn, got)
	}
	if got != "" {
		t.Errorf("GetLocal(%q) = %q, want empty string", fqdn, got)
	}
}

func TestDelete(t *testing.T) {
	// Clear store before test
	mu.Lock()
	store = make(map[string]entry)
	mu.Unlock()

	fqdn := "delete.example.com"
	value := "to-delete"

	Set(fqdn, value, 60)

	// Verify it exists
	got, ok := GetLocal(fqdn)
	if !ok || got != value {
		t.Fatalf("Set failed: GetLocal(%q) = (%q, %v), want (%q, true)", fqdn, got, ok, value)
	}

	Delete(fqdn)

	// Verify it's deleted
	got, ok = GetLocal(fqdn)
	if ok {
		t.Errorf("GetLocal(%q) = (%q, true) after Delete, want (_, false)", fqdn, got)
	}
}

func TestNormalizeFQDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "FQDN with trailing dot",
			input:    "example.com.",
			expected: "example.com",
		},
		{
			name:     "FQDN without trailing dot",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeFQDN(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeFQDN(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSetWithDifferentTTL(t *testing.T) {
	// Clear store before test
	mu.Lock()
	store = make(map[string]entry)
	mu.Unlock()

	fqdn := "ttl-test.example.com"
	value := "test-value"

	// Set with short TTL
	Set(fqdn, value, 1)
	time.Sleep(500 * time.Millisecond)

	// Should still be valid
	got, ok := GetLocal(fqdn)
	if !ok {
		t.Errorf("GetLocal(%q) expired too early", fqdn)
	}

	// Set with longer TTL
	Set(fqdn, value, 60)
	time.Sleep(2 * time.Second)

	// Should still be valid
	got, ok = GetLocal(fqdn)
	if !ok {
		t.Errorf("GetLocal(%q) expired after setting longer TTL", fqdn)
	}
	if got != value {
		t.Errorf("GetLocal(%q) = %q, want %q", fqdn, got, value)
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Clear store before test
	mu.Lock()
	store = make(map[string]entry)
	mu.Unlock()

	// Test concurrent writes and reads
	done := make(chan bool)
	numGoroutines := 10

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			fqdn := "concurrent.example.com"
			value := "value"
			Set(fqdn, value, 60)
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func() {
			fqdn := "concurrent.example.com"
			_, _ = GetLocal(fqdn)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines*2; i++ {
		<-done
	}

	// Final read should succeed
	got, ok := GetLocal("concurrent.example.com")
	if !ok {
		t.Error("Concurrent access failed: final GetLocal returned false")
	}
	if got != "value" {
		t.Errorf("Concurrent access failed: final GetLocal = %q, want %q", got, "value")
	}
}

func TestWasMissRecently(t *testing.T) {
	// Clear miss cache by deleting entries
	missCache.Range(func(key, value interface{}) bool {
		missCache.Delete(key)
		return true
	})

	fqdn := "miss-test.example.com"

	// Should not be a recent miss initially
	if wasMissRecently(fqdn) {
		t.Error("wasMissRecently() = true for new FQDN, want false")
	}

	// Mark as miss
	markMiss(fqdn)

	// Should be a recent miss
	if !wasMissRecently(fqdn) {
		t.Error("wasMissRecently() = false immediately after markMiss, want true")
	}

	// Wait for expiration (30 seconds)
	// Note: This test might be slow, so we'll just verify the mechanism works
	time.Sleep(100 * time.Millisecond)
	if !wasMissRecently(fqdn) {
		t.Error("wasMissRecently() = false too soon after markMiss")
	}
}

func BenchmarkSet(t *testing.B) {
	// Clear store before benchmark
	mu.Lock()
	store = make(map[string]entry)
	mu.Unlock()

	fqdn := "benchmark.example.com"
	value := "benchmark-value"

	for i := 0; i < t.N; i++ {
		Set(fqdn, value, 60)
	}
}

func BenchmarkGetLocal(t *testing.B) {
	// Clear store and set up
	mu.Lock()
	store = make(map[string]entry)
	mu.Unlock()

	fqdn := "benchmark.example.com"
	Set(fqdn, "value", 3600)

	for i := 0; i < t.N; i++ {
		_, _ = GetLocal(fqdn)
	}
}
