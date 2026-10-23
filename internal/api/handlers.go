package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
)

type challengeRequest struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

func handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req challengeRequest
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "expected one JSON object", http.StatusBadRequest)
		return
	}
	name := strings.TrimSuffix(strings.ToLower(req.FQDN), ".")
	host := strings.TrimPrefix(name, "_acme-challenge.")
	if host == name {
		http.Error(w, "expected an ACME challenge name", http.StatusBadRequest)
		return
	}
	if _, err := config.ValidateHostname(host); err != nil {
		http.Error(w, "challenge name is outside the permitted hosts", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodDelete {
		txtstore.Delete(name)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if req.Value == "" || len(req.Value) > 255 || req.TTL < 1 || req.TTL > 3600 {
		http.Error(w, "value must be 1..255 bytes and ttl 1..3600 seconds", http.StatusBadRequest)
		return
	}
	if err := txtstore.Put(name, req.Value, req.TTL); err != nil {
		http.Error(w, "challenge storage unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
