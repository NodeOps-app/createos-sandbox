package process

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type inputRecorder struct {
	strings.Builder
	closed bool
}

func (w *inputRecorder) Close() error { w.closed = true; return nil }

func TestCanceledQueuedInput(t *testing.T) {
	for _, kind := range []inputOperationKind{inputOperationWrite, inputOperationClose} {
		t.Run(map[inputOperationKind]string{inputOperationWrite: "write", inputOperationClose: "close"}[kind], func(t *testing.T) {
			writer := &inputRecorder{}
			r := &processRecord{mode: processModePipes, state: processStateRunning, stdin: writer, inputOps: make(chan inputOperation, 8), done: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			returned := make(chan error, 1)
			go func() { _, err := r.submitInput(ctx, kind, []byte("canceled")); returned <- err }()
			deadline := time.Now().Add(time.Second)
			for len(r.inputOps) == 0 {
				if time.Now().After(deadline) {
					t.Fatal("input not queued")
				}
				time.Sleep(time.Millisecond)
			}
			cancel()
			if err := <-returned; !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
			go r.runInputLoop()
			defer close(r.done)
			liveCtx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			seq, err := r.submitInput(liveCtx, inputOperationWrite, []byte("healthy"))
			if err != nil {
				t.Fatalf("healthy input after cancellation: %v", err)
			}
			if got := writer.String(); got != "healthy" || writer.closed || seq != 1 {
				t.Fatalf("canceled operation applied: contents=%q closed=%v sequence=%d", got, writer.closed, seq)
			}
		})
	}
}
