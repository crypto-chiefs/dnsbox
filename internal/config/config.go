package config

import (
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"os"
)

var (
	Domain string
	IP     string
	NSName string
	Debug  bool
)

func init() {
	Domain = os.Getenv("DNSBOX_DOMAIN")
	IP = os.Getenv("DNSBOX_IP")
	NSName = os.Getenv("DNSBOX_NS_NAME")
	Debug = os.Getenv("DNSBOX_DEBUG") == "true"

	if Domain == "" || IP == "" || NSName == "" {
		logger.Fatal("Missing env vars: DNSBOX_DOMAIN, DNSBOX_IP, DNSBOX_NS_NAME")
	}

	logger.SetDebugMode(Debug)
}
