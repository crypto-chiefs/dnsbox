package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/customdns"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"github.com/miekg/dns"
)

func Start() error { return Serve(context.Background()) }

func Serve(ctx context.Context) error { return ServeReady(ctx, nil) }

// ServeReady binds both transports before starting either and sends readiness
// only after both are serving. A nil ready channel disables the notification.
func ServeReady(ctx context.Context, ready chan<- struct{}) error {
	if err := customdns.Configure(config.RecordsFile, config.Domain); err != nil {
		return err
	}
	lc := net.ListenConfig{}
	tcp, err := lc.Listen(ctx, "tcp", config.DNSListen)
	if err != nil {
		return fmt.Errorf("listen DNS TCP: %w", err)
	}
	udp, err := lc.ListenPacket(ctx, "udp", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		return fmt.Errorf("listen DNS UDP: %w", err)
	}
	return serveListenersReady(ctx, tcp, udp, ready)
}

func serveListeners(ctx context.Context, tcp net.Listener, udp net.PacketConn) error {
	return serveListenersReady(ctx, tcp, udp, nil)
}

func serveListenersReady(ctx context.Context, tcp net.Listener, udp net.PacketConn, ready chan<- struct{}) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", handleQuery)
	servers := []*dns.Server{
		{Listener: tcp, Net: "tcp", Handler: mux, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxTCPQueries: 100},
		{PacketConn: udp, Net: "udp", Handler: mux, UDPSize: 1232},
	}
	results := make(chan error, len(servers))
	started := make(chan struct{}, len(servers))
	for _, srv := range servers {
		srv := srv
		srv.NotifyStartedFunc = func() { started <- struct{}{} }
		go func() { results <- srv.ActivateAndServe() }()
	}
	var result error
	received := 0
	for count := 0; count < len(servers); count++ {
		select {
		case <-started:
		case <-ctx.Done():
			goto shutdown
		case result = <-results:
			received++
			goto shutdown
		}
	}
	logger.Info("[dns] listening on %s (TCP and UDP)", tcp.Addr())
	if ready != nil {
		select {
		case ready <- struct{}{}:
		case <-ctx.Done():
			goto shutdown
		}
	}
	select {
	case <-ctx.Done():
	case result = <-results:
		received++
	}

shutdown:
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		// ShutdownContext can run before ActivateAndServe marks a server as
		// started. Closing the listeners also covers that startup race.
		_ = srv.ShutdownContext(stopCtx)
	}
	_ = tcp.Close()
	_ = udp.Close()
	for received < len(servers) {
		select {
		case err := <-results:
			received++
			if result == nil && err != nil && !errors.Is(err, net.ErrClosed) {
				result = err
			}
		case <-stopCtx.Done():
			return fmt.Errorf("DNS shutdown timed out")
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	return result
}
