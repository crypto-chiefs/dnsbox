package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/crypto-chiefs/dnsbox/internal/certshare"
	"github.com/crypto-chiefs/dnsbox/internal/httpsproxy"
	"github.com/crypto-chiefs/dnsbox/internal/letsencrypt"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"io"
	"log"
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

// POST /.dnsbox/ask-cert
func handleAskCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req certshare.AskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ask-cert] ❌ invalid JSON: %v", err)
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("[ask-cert] received request for domain: %s from %s", req.Domain, req.FromIP)

	if req.Domain == "" || req.EphemeralPub == "" || req.Callback == "" {
		log.Printf("[ask-cert] ❌ missing fields in request")
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}

	// Проверка наличия сертификата
	if !letsencrypt.HasCertificate(req.Domain) {
		log.Printf("[ask-cert] ❌ no cert available for %s", req.Domain)
		json.NewEncoder(w).Encode(certshare.AskResponse{HasCert: false})
		return
	}

	cert, err := letsencrypt.LoadCertificate(req.Domain)
	if err != nil {
		log.Printf("[ask-cert] ❌ failed to load cert for %s: %v", req.Domain, err)
		http.Error(w, "cert load error", http.StatusInternalServerError)
		return
	}

	// Парсинг публичного ключа клиента
	peerPub, err := base64.StdEncoding.DecodeString(req.EphemeralPub)
	if err != nil || len(peerPub) != 32 {
		log.Printf("[ask-cert] ❌ invalid ephemeral pub key")
		http.Error(w, "invalid ephemeral pub key", http.StatusBadRequest)
		return
	}

	// Генерация ephemeral приватного ключа и вычисление shared key
	priv, _, err := certshare.GenerateEphemeralKeyPair()
	if err != nil {
		log.Printf("[ask-cert] ❌ failed to generate ephemeral keypair: %v", err)
		http.Error(w, "ephemeral key error", http.StatusInternalServerError)
		return
	}

	sharedKey, err := certshare.ComputeSharedKey(peerPub, priv)
	if err != nil {
		log.Printf("[ask-cert] ❌ failed to compute shared key: %v", err)
		http.Error(w, "shared key error", http.StatusInternalServerError)
		return
	}

	// Шифруем сертификат
	cipher, nonce, err := certshare.EncryptWithSharedKey(cert, sharedKey)
	if err != nil {
		log.Printf("[ask-cert] ❌ failed to encrypt cert: %v", err)
		http.Error(w, "encryption error", http.StatusInternalServerError)
		return
	}

	encCert := certshare.EncryptedCert{
		Domain:    req.Domain,
		Encrypted: base64.StdEncoding.EncodeToString(cipher),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
	}

	data, _ := json.Marshal(encCert)

	go func() {
		resp, err := http.Post(req.Callback, "application/json", bytes.NewReader(data))
		if err != nil {
			log.Printf("[ask-cert] ❌ failed to POST encrypted cert to %s: %v", req.Callback, err)
			return
		}
		defer resp.Body.Close()
		log.Printf("[ask-cert] ✅ cert sent to %s, status: %s", req.Callback, resp.Status)
	}()

	_ = json.NewEncoder(w).Encode(certshare.AskResponse{HasCert: true})
}

// POST /.dnsbox/receive-cert
func handleReceiveCert(w http.ResponseWriter, r *http.Request) {
	var enc certshare.EncryptedCert
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &enc); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	httpsproxy.StoreEncryptedCert(enc.Domain, body)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}
