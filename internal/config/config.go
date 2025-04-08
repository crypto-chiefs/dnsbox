package config

import (
	"log"
	"os"
)

var (
	Domain string
	IP     string
	NSName string
)

func init() {
	Domain = os.Getenv("DNSBOX_DOMAIN")
	IP = os.Getenv("DNSBOX_IP")
	NSName = os.Getenv("DNSBOX_NS_NAME")

	if Domain == "" || IP == "" || NSName == "" {
		log.Fatalf("Missing env vars: DNSBOX_DOMAIN, DNSBOX_IP, DNSBOX_NS_NAME")
	}
}
