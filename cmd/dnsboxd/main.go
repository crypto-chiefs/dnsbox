package main

import (
	"github.com/crypto-chiefs/dnsbox/internal/api"
	"github.com/crypto-chiefs/dnsbox/internal/dnsserver"
	"log"
)

func main() {
	log.Println("[dnsboxd] starting DNS server...")

	// Start DNS server (UDP + TCP)
	go func() {
		err := dnsserver.Start()
		if err != nil {
			log.Fatalf("DNS server error: %v", err)
		}
	}()

	// Start REST API (for TXT challenge records)
	go func() {
		err := api.Start()
		if err != nil {
			log.Fatalf("API server error: %v", err)
		}
	}()

	// Block forever
	select {}
}
