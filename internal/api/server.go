package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/httpserver"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
)

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/acme-challenge", authorized(handleACMEChallenge))
	mux.HandleFunc("/.dnsbox/ask-cert", removed)
	mux.HandleFunc("/.dnsbox/receive-cert", removed)
	return mux
}

func removed(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "unauthenticated certificate sharing has been removed", http.StatusGone)
}

func authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if config.APIToken == "" {
			http.Error(w, "management mutations are disabled", http.StatusForbidden)
			return
		}
		expected := "Bearer " + config.APIToken
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func Serve(ctx context.Context) error {
	if config.APIListen == "" {
		<-ctx.Done()
		return nil
	}
	server := &http.Server{Addr: config.APIListen, Handler: Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	logger.Info("[api] listening on %s", config.APIListen)
	return httpserver.Serve(ctx, server, false)
}

func Start() error { return Serve(context.Background()) }
