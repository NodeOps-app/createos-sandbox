package ingress

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrencyCapConcurrentReleaseAndAcquire(t *testing.T) {
	cap := newConcurrencyCap(1)
	var active, violations atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 5000; n++ {
				if !cap.Acquire("sandbox") {
					runtime.Gosched()
					continue
				}
				if active.Add(1) != 1 {
					violations.Add(1)
				}
				runtime.Gosched()
				active.Add(-1)
				cap.Release("sandbox")
			}
		}()
	}
	wg.Wait()
	if violations.Load() != 0 {
		t.Fatalf("admitted overlapping requests with cap=1: %d", violations.Load())
	}
	if len(cap.counters) != 0 {
		t.Fatal("idle counters were not reclaimed")
	}
	if !cap.Acquire("sandbox") {
		t.Fatal("sandbox cannot be admitted again")
	}
	if cap.Acquire("sandbox") {
		t.Fatal("cap was not enforced")
	}
	cap.Release("sandbox")
}
