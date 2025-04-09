package api

import (
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"net/http"
)

func Start() error {
	http.HandleFunc("/acme-challenge", handleACMEChallenge)
	http.HandleFunc("/.dnsbox/ask-cert", handleAskCert)
	http.HandleFunc("/.dnsbox/receive-cert", handleReceiveCert)
	http.HandleFunc("/.dnsbox/txt/", handleTxtHTTP)
	logger.Info("[api] listening on :80")
	return http.ListenAndServe(":80", nil)
}
