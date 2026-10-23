package txtstore

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func emptyStore(t *testing.T) {
	t.Helper()
	defaultStore = New()
	t.Cleanup(func() { defaultStore = New() })
}
func TestCanonicalNamesAndExpiry(t *testing.T) {
	emptyStore(t)
	if err := Put("_ACME-CHALLENGE.Host.Example.", "token", 120); err != nil {
		t.Fatal(err)
	}
	if got, ok := Get("_acme-challenge.host.example"); !ok || got != "token" {
		t.Fatalf("got %q %v", got, ok)
	}
	defaultStore.mu.Lock()
	defaultStore.records["_acme-challenge.host.example."]["token"] = time.Now().Add(-time.Second)
	defaultStore.mu.Unlock()
	if _, ok := Get("_acme-challenge.host.example"); ok {
		t.Fatal("expired entry returned")
	}
	if len(defaultStore.records) != 0 {
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
		defaultStore.records[fmt.Sprintf("%d.example.", i)] = map[string]time.Time{"x": time.Now().Add(time.Hour)}
	}
	if err := Put("overflow.example", "x", 60); err == nil {
		t.Fatal("capacity not enforced")
	}
	if err := Put("0.example", "updated", 60); err != nil {
		t.Fatal("replacement must work at capacity", err)
	}
	if err := Add("0.example", "another", 60); err == nil {
		t.Fatal("additive values must count toward capacity")
	}
	for _, tc := range []struct {
		name, value string
		ttl         int
	}{{".", "x", 1}, {"a.example", "", 1}, {"a.example", "x", 0}, {"a.example", "x", MaxTTL + 1}} {
		if err := Put(tc.name, tc.value, tc.ttl); err == nil {
			t.Fatalf("accepted invalid input %+v", tc)
		}
	}
	defaultStore.records["0.example."] = map[string]time.Time{"x": time.Now().Add(-time.Second)}
	if err := Put("new.example", "x", 60); err != nil {
		t.Fatal("expired capacity not recovered", err)
	}
}
func TestIndependentValuesAndExactCleanup(t *testing.T) {
	store := New()
	for _, value := range []string{"node-b", "node-a", "node-c"} {
		if err := store.Add("HOST.EXAMPLE.", value, 60); err != nil {
			t.Fatal(err)
		}
	}
	if got := store.GetAll("host.example"); !reflect.DeepEqual(got, []string{"node-a", "node-b", "node-c"}) {
		t.Fatal(got)
	}
	store.DeleteValue("host.example", "node-b")
	if got := store.GetAll("host.example"); !reflect.DeepEqual(got, []string{"node-a", "node-c"}) {
		t.Fatal(got)
	}
	store.mu.Lock()
	store.records["host.example."]["node-a"] = time.Now().Add(-time.Second)
	store.mu.Unlock()
	if got := store.GetAll("host.example"); !reflect.DeepEqual(got, []string{"node-c"}) {
		t.Fatal(got)
	}
	if err := store.Put("host.example", "management-value", 60); err != nil {
		t.Fatal(err)
	}
	if got := store.GetAll("host.example"); !reflect.DeepEqual(got, []string{"management-value"}) {
		t.Fatal(got)
	}
}
func TestConcurrentIssuersCannotDeleteEachOther(t *testing.T) {
	store := New()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value := fmt.Sprintf("node-%d", i)
			for n := 0; n < 100; n++ {
				if err := store.Add("host.example", value, 60); err != nil {
					t.Error(err)
				}
				store.GetAll("host.example")
				store.DeleteValue("host.example", value)
			}
			if err := store.Add("host.example", value, 60); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if len(store.GetAll("host.example")) != 20 {
		t.Fatal("concurrent cleanup removed another issuer's value")
	}
}
