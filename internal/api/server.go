package api

import (
	"log"
	"net/http"
)

func Start() error {
	http.HandleFunc("/acme-challenge", handleACMEChallenge)
	http.HandleFunc("/.dnsbox/ask-cert", handleAskCert)
	http.HandleFunc("/.dnsbox/receive-cert", handleReceiveCert)
	http.HandleFunc("/.dnsbox/txt/", handleTxtHTTP)
	log.Println("[api] listening on :80")
	return http.ListenAndServe(":80", nil)
}
