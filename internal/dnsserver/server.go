package dnsserver

import (
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"github.com/miekg/dns"
)

func Start() error {
	dns.HandleFunc(".", handleQuery)

	go func() {
		if err := dns.ListenAndServe(":53", "udp", nil); err != nil {
			logger.Fatal("failed to start DNS server (udp): %v", err)
		}
	}()

	if err := dns.ListenAndServe(":53", "tcp", nil); err != nil {
		logger.Fatal("failed to start DNS server (tcp): %v", err)
	}

	return nil
}
