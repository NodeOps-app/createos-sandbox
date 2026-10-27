package ingress

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRouteCacheExpiryAndBound(t *testing.T) {
	c := newCache(time.Minute, -time.Second)
	for i := 0; i < 10000; i++ {
		id := fmt.Sprint(i)
		c.putNegative(id)
		if _, _, hit := c.get(id); hit {
			t.Fatal("expired entry returned")
		}
	}
	if len(c.data) != 0 {
		t.Fatalf("retained %d expired entries", len(c.data))
	}
	c = newCache(time.Minute, time.Minute)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				id := fmt.Sprintf("%d-%d", n, i)
				if n%2 == 0 {
					c.putNegative(id)
				} else {
					c.putPositive(id, ingressRoute{ID: id}, time.Minute)
				}
				c.get(id)
			}
		}(n)
	}
	wg.Wait()
	if len(c.data) > maxRouteCacheEntries {
		t.Fatalf("cache grew to %d", len(c.data))
	}
	c.putPositive("fresh", ingressRoute{ID: "fresh"}, time.Minute)
	route, ok, hit := c.get("fresh")
	if !hit || !ok || route.ID != "fresh" {
		t.Fatal("positive cache failed")
	}
	c.putNegative("missing")
	_, ok, hit = c.get("missing")
	if !hit || ok {
		t.Fatal("negative cache failed")
	}
}
