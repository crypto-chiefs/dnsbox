package main

import (
	"github.com/crypto-chiefs/dnsbox/internal/api"
	"github.com/crypto-chiefs/dnsbox/internal/dnsserver"
	"github.com/crypto-chiefs/dnsbox/internal/httpsproxy"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
)

func main() {
	logger.Info("[dnsboxd] starting DNS server...")

	// Start DNS server (UDP + TCP)
	go func() {
		err := dnsserver.Start()
		if err != nil {
			logger.Fatal("DNS server error: %v", err)
		}
	}()

	// Start REST API (for TXT challenge records)
	go func() {
		err := api.Start()
		if err != nil {
			logger.Fatal("API server error: %v", err)
		}
	}()

	go func() {
		err := httpsproxy.Start()
		if err != nil {
			logger.Fatal("HTTPS proxy error: %v", err)
		}
	}()

	// Block forever
	select {}
}
