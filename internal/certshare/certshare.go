package certshare

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"net/http"
)

type AskRequest struct {
	Domain       string `json:"domain"`
	FromIP       string `json:"from_ip"`
	EphemeralPub string `json:"epk"` // base64-encoded X25519 ephemeral public key
	Callback     string `json:"callback"`
}

type AskResponse struct {
	HasCert bool `json:"has_cert"`
}

type EncryptedCert struct {
	Domain    string `json:"domain"`
	Encrypted string `json:"encrypted"` // base64
	Nonce     string `json:"nonce"`     // base64
}

// GenerateEphemeralKeyPair generates ephemeral X25519 key pairs
func GenerateEphemeralKeyPair() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	_, err = rand.Read(priv)
	if err != nil {
		return nil, nil, err
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, err
}

// ComputeSharedKey derives a shared key from peerPub and localPriv
func ComputeSharedKey(peerPub, localPriv []byte) ([]byte, error) {
	return curve25519.X25519(localPriv, peerPub)
}

// EncryptWithSharedKey encrypts the cert and key using the shared key
func EncryptWithSharedKey(cert tls.Certificate, sharedKey []byte) (ciphertext, nonce []byte, err error) {
	var certPEM bytes.Buffer
	for _, b := range cert.Certificate {
		certPEM.Write(b)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	bundle := append(certPEM.Bytes(), keyBytes...)

	block, err := aes.NewCipher(sharedKey[:32])
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aesgcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = aesgcm.Seal(nil, nonce, bundle, nil)
	return ciphertext, nonce, nil
}

// DecryptCertWithSharedKey decrypts the cert and key using the shared key
func DecryptCertWithSharedKey(ciphertext, nonce, sharedKey []byte) (tls.Certificate, error) {
	block, err := aes.NewCipher(sharedKey[:32])
	if err != nil {
		return tls.Certificate{}, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return tls.Certificate{}, err
	}
	plain, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(plain, plain)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

// SendAskRequest sends a request to another peer and parses the response
func SendAskRequest(peerURL string, req AskRequest) (bool, error) {
	body, _ := json.Marshal(req)
	resp, err := http.Post(peerURL+"/.dnsbox/ask-cert", "application/json", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("peer responded with %d", resp.StatusCode)
	}
	var result AskResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.HasCert, nil
}

// EncodeEncryptedCert encodes the data to JSON for sending
func EncodeEncryptedCert(enc EncryptedCert) ([]byte, error) {
	return json.Marshal(enc)
}

// DecodeEncryptedCert decodes JSON into a struct
func DecodeEncryptedCert(data []byte) (EncryptedCert, error) {
	var c EncryptedCert
	err := json.Unmarshal(data, &c)
	return c, err
}
