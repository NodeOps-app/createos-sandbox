// Package hostwarm maintains control-to-host HTTP connection pools so user
// requests do not pay a cold TCP and mTLS handshake.
package hostwarm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/models"
)

const (
	defaultConnections = 20
	defaultInterval    = 20 * time.Second
)

// Warmer periodically opens authenticated connections to active compute hosts
// in one region. It is safe to run until its context is cancelled.
type Warmer struct {
	repo        *models.Repo
	client      *http.Client
	region      string
	connections int
	interval    time.Duration
}

func New(repo *models.Repo, client *http.Client, region string) *Warmer {
	return &Warmer{
		repo:        repo,
		client:      client,
		region:      region,
		connections: defaultConnections,
		interval:    defaultInterval,
	}
}

// Run warms immediately and then once per interval until ctx is cancelled.
func (w *Warmer) Run(ctx context.Context) {
	w.warm(ctx)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.warm(ctx)
		}
	}
}

func (w *Warmer) warm(ctx context.Context) {
	hosts, err := w.repo.ListHosts(ctx)
	if err != nil {
		log.WithContext(ctx).Warnf("[control] host connection warm: list hosts: %v", err)
		return
	}

	var wg sync.WaitGroup
	var attempted, ready, reused, fresh atomic.Int64
	for _, host := range hosts {
		if host.Status != models.HostStatusActive || host.Role != models.HostRoleCompute || host.Region != w.region {
			continue
		}
		addr := host.Addr
		if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
			addr = "https://" + addr
		}
		url := strings.TrimRight(addr, "/") + "/v1/internal/connection-warm"
		for range w.connections {
			attempted.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				var gotReused atomic.Bool
				reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
					gotReused.Store(info.Reused)
				}}
				req, err := http.NewRequestWithContext(httptrace.WithClientTrace(reqCtx, trace), http.MethodGet, url, nil)
				if err != nil {
					return
				}
				resp, err := w.client.Do(req)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					ready.Add(1)
					if gotReused.Load() {
						reused.Add(1)
					} else {
						fresh.Add(1)
					}
				}
			}()
		}
	}
	wg.Wait()
	log.WithContext(ctx).Infof("[control] host connections warm ready=%d attempted=%d reused=%d new=%d region=%s",
		ready.Load(), attempted.Load(), reused.Load(), fresh.Load(), w.region)
}
