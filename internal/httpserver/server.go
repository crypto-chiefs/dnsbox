// Package httpserver shares lifecycle handling for the HTTP services.
package httpserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

func Serve(ctx context.Context, srv *http.Server, tls bool) error {
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	return serveListener(ctx, srv, listener, tls)
}

// ServeListener serves an already-bound listener with the shared graceful
// shutdown lifecycle. It takes ownership of the listener.
func ServeListener(ctx context.Context, srv *http.Server, listener net.Listener, tls bool) error {
	return serveListener(ctx, srv, listener, tls)
}

func serveListener(ctx context.Context, srv *http.Server, listener net.Listener, tls bool) error {
	var err error
	srv.BaseContext = func(net.Listener) context.Context { return ctx }
	done := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				_ = srv.Close()
			}
		case <-done:
		}
	}()
	if tls {
		err = srv.ServeTLS(listener, "", "")
	} else {
		err = srv.Serve(listener)
	}
	close(done)
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
