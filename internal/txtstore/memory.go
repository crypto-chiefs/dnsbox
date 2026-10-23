package txtstore

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const MaxEntries = 4096
const MaxValuesPerName = 64
const MaxTTL = 24 * 60 * 60
const MaxValueBytes = 4096

// Store holds independently expiring values. Different ACME issuers may publish
// challenges for the same hostname without replacing each other's records.
type Store struct {
	mu      sync.Mutex
	records map[string]map[string]time.Time
}

func New() *Store { return &Store{records: make(map[string]map[string]time.Time)} }

var defaultStore = New()

func validate(fqdn, value string, ttlSeconds int) error {
	if _, ok := dns.IsDomainName(fqdn); !ok || fqdn == "." || len(fqdn) > 254 {
		return fmt.Errorf("invalid TXT record name")
	}
	if value == "" || len(value) > MaxValueBytes || ttlSeconds <= 0 || ttlSeconds > MaxTTL {
		return fmt.Errorf("invalid TXT value or lifetime")
	}
	return nil
}

// prune removes expired values and returns the remaining value count.
func (s *Store) prune(now time.Time) int {
	count := 0
	for name, values := range s.records {
		for value, expires := range values {
			if !now.Before(expires) {
				delete(values, value)
			}
		}
		if len(values) == 0 {
			delete(s.records, name)
		} else {
			count += len(values)
		}
	}
	return count
}

func (s *Store) write(fqdn, value string, ttlSeconds int, replace bool) error {
	fqdn = normalizeFQDN(fqdn)
	if err := validate(fqdn, value, ttlSeconds); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]map[string]time.Time)
	}
	now := time.Now()
	count := s.prune(now)
	values := s.records[fqdn]
	_, existing := values[value]
	if replace {
		if count-len(values) >= MaxEntries {
			return fmt.Errorf("TXT record store is full")
		}
		values = make(map[string]time.Time)
	} else if !existing && (count >= MaxEntries || len(values) >= MaxValuesPerName) {
		return fmt.Errorf("TXT record store is full")
	}
	if values == nil {
		values = make(map[string]time.Time)
	}
	values[value] = now.Add(time.Duration(ttlSeconds) * time.Second)
	s.records[fqdn] = values
	return nil
}

// Put replaces all values at a name for the legacy management API.
func (s *Store) Put(fqdn, value string, ttlSeconds int) error {
	return s.write(fqdn, value, ttlSeconds, true)
}

// Add adds or refreshes one value, preserving other simultaneous challenges.
func (s *Store) Add(fqdn, value string, ttlSeconds int) error {
	return s.write(fqdn, value, ttlSeconds, false)
}
func (s *Store) GetAll(fqdn string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	fqdn = normalizeFQDN(fqdn)
	values := s.records[fqdn]
	result := make([]string, 0, len(values))
	now := time.Now()
	for value, expires := range values {
		if !now.Before(expires) {
			delete(values, value)
			continue
		}
		result = append(result, value)
	}
	if len(values) == 0 {
		delete(s.records, fqdn)
	}
	sort.Strings(result)
	return result
}
func (s *Store) DeleteValue(fqdn, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fqdn = normalizeFQDN(fqdn)
	values := s.records[fqdn]
	delete(values, value)
	if len(values) == 0 {
		delete(s.records, fqdn)
	}
}
func (s *Store) Delete(fqdn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, normalizeFQDN(fqdn))
}

func Put(fqdn, value string, ttlSeconds int) error { return defaultStore.Put(fqdn, value, ttlSeconds) }
func Add(fqdn, value string, ttlSeconds int) error { return defaultStore.Add(fqdn, value, ttlSeconds) }
func GetAll(fqdn string) []string                  { return defaultStore.GetAll(fqdn) }
func DeleteValue(fqdn, value string)               { defaultStore.DeleteValue(fqdn, value) }
func Delete(fqdn string)                           { defaultStore.Delete(fqdn) }
func Set(fqdn, value string, ttlSeconds int)       { _ = Put(fqdn, value, ttlSeconds) }
func Get(fqdn string) (string, bool)               { return GetLocal(fqdn) }
func GetLocal(fqdn string) (string, bool) {
	values := GetAll(fqdn)
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}
func normalizeFQDN(fqdn string) string { return dns.Fqdn(strings.ToLower(strings.TrimSpace(fqdn))) }
