package letsencrypt

import (
	"context"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
)

// ChallengePublisher installs a value on every authoritative node and returns
// exact-value cleanup. A publisher must undo partial work when returning error.
type ChallengePublisher func(context.Context, string, string, int) (func(context.Context) error, error)

var challengePublisher ChallengePublisher = publishLocally

// SetChallengePublisher is called once before services start. Passing nil keeps
// the single-node behavior; the certificate package does not depend on cluster.
func SetChallengePublisher(publisher ChallengePublisher) {
	if publisher == nil {
		challengePublisher = publishLocally
	} else {
		challengePublisher = publisher
	}
}

func publishLocally(ctx context.Context, name, value string, ttl int) (func(context.Context) error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := txtstore.Add(name, value, ttl); err != nil {
		return nil, err
	}
	return func(context.Context) error { txtstore.DeleteValue(name, value); return nil }, nil
}

func cleanupChallenge(cleanup func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cleanup(ctx); err != nil {
		logger.Warn("DNS-01 cleanup failed; remaining values will expire: %v", err)
	}
}
