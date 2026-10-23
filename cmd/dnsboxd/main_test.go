package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofrs/flock"
)

func TestLocalIssueDoesNotOpenListeners(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	dir := t.TempDir()
	args := []string{"--domain=home.arpa", "--ip=127.0.0.1", "--tls-mode=local", "--allowed-cidrs=127.0.0.1/32",
		"--data-dir=" + dir, "--issue=127.0.0.1.home.arpa", "--dns-listen=" + occupied.Addr().String(), "--https-listen=" + occupied.Addr().String()}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca/root.crt", "certs/127.0.0.1.home.arpa.crt", "certs/127.0.0.1.home.arpa.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	lock := flock.New(filepath.Join(dir, ".dnsbox.lock"))
	if ok, err := lock.TryLock(); err != nil || !ok {
		t.Fatal("lock not released", err)
	}
	defer lock.Close()
	if err := run(args); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatal("did not reject occupied data directory", err)
	}
}

func TestACMEIssueReportsDNSBindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	dir := t.TempDir()
	err = run([]string{"--domain=example.test", "--ip=127.0.0.1", "--data-dir=" + dir,
		"--dns-listen=" + occupied.Addr().String(), "--issue=8.8.8.8.example.test"})
	if err == nil || !strings.Contains(err.Error(), "listen DNS TCP") {
		t.Fatal("expected bind error", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "acme")); !os.IsNotExist(err) {
		t.Fatal("ACME started before DNS was ready")
	}
}
