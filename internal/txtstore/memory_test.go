package txtstore

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func emptyStore(t *testing.T) {
	t.Helper()
	mu.Lock()
	store = make(map[string]entry)
	mu.Unlock()
	t.Cleanup(func() { mu.Lock(); store = make(map[string]entry); mu.Unlock() })
}
func TestCanonicalNamesAndExpiry(t *testing.T) {
	emptyStore(t)
	if err := Put("_ACME-CHALLENGE.Host.Example.", "token", 120); err != nil {
		t.Fatal(err)
	}
	if got, ok := Get("_acme-challenge.host.example"); !ok || got != "token" {
		t.Fatalf("got %q %v", got, ok)
	}
	mu.Lock()
	store["_acme-challenge.host.example."] = entry{"old", time.Now().Add(-time.Second)}
	mu.Unlock()
	if _, ok := Get("_acme-challenge.host.example"); ok {
		t.Fatal("expired entry returned")
	}
	if len(store) != 0 {
		t.Fatal("expired entry not reclaimed")
	}
	Set("a.example", "a", 1)
	Delete("A.EXAMPLE.")
	if _, ok := GetLocal("a.example"); ok {
		t.Fatal("delete was not canonical")
	}
}
func TestCapacityAndValidation(t *testing.T) {
	emptyStore(t)
	for i := 0; i < MaxEntries; i++ {
		store[fmt.Sprintf("%d.example.", i)] = entry{"x", time.Now().Add(time.Hour)}
	}
	if err := Put("overflow.example", "x", 60); err == nil {
		t.Fatal("capacity not enforced")
	}
	if err := Put("0.example", "updated", 60); err != nil {
		t.Fatal("updates must work at capacity", err)
	}
	for _, tc := range []struct {
		name, value string
		ttl         int
	}{{".", "x", 1}, {"a.example", "", 1}, {"a.example", "x", 0}, {"a.example", "x", MaxTTL + 1}} {
		if err := Put(tc.name, tc.value, tc.ttl); err == nil {
			t.Fatalf("accepted invalid input %+v", tc)
		}
	}
	store["0.example."] = entry{"x", time.Now().Add(-time.Second)}
	if err := Put("new.example", "x", 60); err != nil {
		t.Fatal("expired capacity not recovered", err)
	}
}
func TestConcurrentAccess(t *testing.T) {
	emptyStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("%d.example", i)
			for n := 0; n < 100; n++ {
				Set(name, "x", 60)
				Get(name)
				Delete(name)
			}
		}(i)
	}
	wg.Wait()
}
