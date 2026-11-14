package ingress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ingressRoute is deliberately narrower than models.Sandbox. It is the only
// sandbox data the public ingress process may receive from control.
type ingressRoute struct {
	ID              string `json:"id"`
	HostAddr        string `json:"host_addr"`
	Status          string `json:"status"`
	IngressEnabled  bool   `json:"ingress_enabled"`
	Region          string `json:"region"`
	BandwidthCapped bool   `json:"bandwidth_capped"`
}

type controlRouteClient struct {
	bases  []string
	client *http.Client
}

func newControlRouteClient(bases []string, client *http.Client) *controlRouteClient {
	return &controlRouteClient{bases: bases, client: client}
}

// sortedControlURLs returns deduplicated endpoints ordered lexically by
// region name. This is deterministic fallback order, not locality detection.
func sortedControlURLs(byRegion map[string]string) []string {
	regions := make([]string, 0, len(byRegion))
	for region := range byRegion {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	seen := make(map[string]struct{}, len(regions))
	out := make([]string, 0, len(regions))
	for _, region := range regions {
		base := strings.TrimRight(strings.TrimSpace(byRegion[region]), "/")
		if base == "" {
			continue
		}
		if _, ok := seen[base]; ok {
			continue
		}
		seen[base] = struct{}{}
		out = append(out, base)
	}
	return out
}

func (c *controlRouteClient) Get(ctx context.Context, sandboxID string) (ingressRoute, error) {
	if c == nil || c.client == nil || len(c.bases) == 0 {
		return ingressRoute{}, errors.New("control route client is not configured")
	}
	var attempts []error
	for _, base := range c.bases {
		route, found, err := c.getFrom(ctx, base, sandboxID)
		if err != nil {
			attempts = append(attempts, err)
			continue
		}
		if found {
			return route, nil
		}
	}
	if len(attempts) > 0 {
		return ingressRoute{}, errors.Join(attempts...)
	}
	return ingressRoute{}, nil
}

func (c *controlRouteClient) getFrom(
	ctx context.Context, base, sandboxID string,
) (ingressRoute, bool, error) {
	endpoint := base + "/v1/internal/ingress/routes/" + url.PathEscape(sandboxID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ingressRoute{}, false, fmt.Errorf("build route request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return ingressRoute{}, false, fmt.Errorf("route lookup %s: %w", base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ingressRoute{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return ingressRoute{}, false, fmt.Errorf("route lookup %s returned %d", base, resp.StatusCode)
	}
	var envelope struct {
		Status string       `json:"status"`
		Data   ingressRoute `json:"data"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := dec.Decode(&envelope); err != nil {
		return ingressRoute{}, false, fmt.Errorf("decode route lookup %s: %w", base, err)
	}
	if envelope.Status != "success" || envelope.Data.ID == "" {
		return ingressRoute{}, false, fmt.Errorf("route lookup %s returned an invalid response", base)
	}
	if envelope.Data.ID != sandboxID {
		return ingressRoute{}, false, fmt.Errorf(
			"route lookup %s returned sandbox %q for %q", base, envelope.Data.ID, sandboxID)
	}
	return envelope.Data, true, nil
}
