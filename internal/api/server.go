package api

import (
	"log"
	"net/http"
)

func Start() error {
	http.HandleFunc("/acme-challenge", handleACMEChallenge)
	log.Println("[api] listening on :8080")
	return http.ListenAndServe(":8080", nil)
}
