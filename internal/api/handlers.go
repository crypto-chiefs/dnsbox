package api

import (
	"encoding/json"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"io"
	"net/http"
)

type challengeRequest struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"` // seconds
}

func handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req challengeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.FQDN == "" || req.Value == "" || req.TTL <= 0 {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}

	txtstore.Set(req.FQDN+".", req.Value, req.TTL)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}
