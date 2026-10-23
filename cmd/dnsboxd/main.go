package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gofrs/flock"

	"github.com/crypto-chiefs/dnsbox/internal/api"
	"github.com/crypto-chiefs/dnsbox/internal/cluster"
	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/customdns"
	"github.com/crypto-chiefs/dnsbox/internal/dnsserver"
	"github.com/crypto-chiefs/dnsbox/internal/httpsproxy"
	"github.com/crypto-chiefs/dnsbox/internal/letsencrypt"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "dnsboxd:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if err := config.Load(args); err != nil {
		return err
	}
	if config.ShowVersion {
		fmt.Println("dnsboxd", version)
		return nil
	}
	logger.SetDebugMode(config.Debug)
	if err := customdns.Configure(config.RecordsFile, config.Domain); err != nil {
		return err
	}
	var peers *cluster.Manager
	if config.ClusterFile != "" {
		var err error
		peers, err = cluster.Load(config.ClusterFile)
		if err != nil {
			return fmt.Errorf("cluster configuration: %w", err)
		}
	}
	letsencrypt.SetChallengePublisher(nil)
	if peers != nil {
		letsencrypt.SetChallengePublisher(peers.Publish)
	}
	if config.CheckConfig {
		fmt.Println("configuration is valid")
		return nil
	}
	if err := os.MkdirAll(config.DataDir, 0700); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(config.DataDir, ".dnsbox.lock"), flock.SetPermissions(0600))
	locked, err := lock.TryLock()
	if err != nil {
		return fmt.Errorf("lock data directory: %w", err)
	}
	if !locked {
		return fmt.Errorf("data directory is already used by another DNSBox process: %s", config.DataDir)
	}
	defer lock.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, 4)
	var wg sync.WaitGroup
	start := func(name string, serve func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serve(ctx); err != nil {
				errorsCh <- fmt.Errorf("%s: %w", name, err)
				cancel()
			}
		}()
	}
	if config.IssueHostname == "" || config.TLSMode == "acme" {
		if err := customdns.RefreshAliases(ctx); err != nil {
			return fmt.Errorf("resolve DNS aliases: %w", err)
		}
		if peers != nil {
			ready := make(chan struct{})
			start("cluster", func(ctx context.Context) error { return peers.ServeReady(ctx, ready) })
			select {
			case <-ready:
			case err := <-errorsCh:
				cancel()
				wg.Wait()
				return err
			case <-ctx.Done():
				wg.Wait()
				select {
				case err := <-errorsCh:
					return err
				default:
					return ctx.Err()
				}
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			customdns.RunAliasRefresh(ctx)
		}()
	}
	if config.IssueHostname != "" {
		if config.TLSMode == "acme" {
			ready := make(chan struct{})
			start("DNS", func(ctx context.Context) error { return dnsserver.ServeReady(ctx, ready) })
			select {
			case <-ready:
			case err := <-errorsCh:
				cancel()
				wg.Wait()
				return err
			case <-ctx.Done():
				wg.Wait()
				select {
				case err := <-errorsCh:
					return err
				default:
					return ctx.Err()
				}
			}
		}
		result := make(chan error, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := letsencrypt.IssueCertificateContext(ctx, config.IssueHostname)
			result <- err
		}()
		var err error
		select {
		case err = <-result:
		case err = <-errorsCh:
		case <-ctx.Done():
			err = ctx.Err()
		}
		cancel()
		wg.Wait()
		select {
		case serverErr := <-errorsCh:
			return serverErr
		default:
		}
		if err == nil {
			fmt.Println("certificate exported to", filepath.Join(config.DataDir, "certs", config.IssueHostname+".crt"))
		}
		return err
	}
	start("DNS", dnsserver.Serve)
	start("API", api.Serve)
	start("HTTPS", httpsproxy.Serve)
	if config.TLSMode == "local" {
		logger.Info("local CA trust certificate: %s", filepath.Join(config.DataDir, "ca", "root.crt"))
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := letsencrypt.RenewCached(ctx); err != nil && ctx.Err() == nil {
			logger.Error("renew certificates: %v", err)
		}
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := letsencrypt.RenewCached(ctx); err != nil && ctx.Err() == nil {
					logger.Error("renew certificates: %v", err)
				}
			}
		}
	}()
	<-ctx.Done()
	wg.Wait()
	select {
	case err := <-errorsCh:
		return err
	default:
		return nil
	}
}
