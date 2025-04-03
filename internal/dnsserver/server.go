package dnsserver

import (
	"github.com/miekg/dns"
	"log"
)

func Start() error {
	dns.HandleFunc(".", handleQuery)

	go func() {
		if err := dns.ListenAndServe(":53", "udp", nil); err != nil {
			log.Fatalf("failed to start DNS server (udp): %v", err)
		}
	}()

	if err := dns.ListenAndServe(":53", "tcp", nil); err != nil {
		log.Fatalf("failed to start DNS server (tcp): %v", err)
	}

	return nil
}
