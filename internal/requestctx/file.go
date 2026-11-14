package requestctx

import (
	"context"
	"io"
	"net"
	"net/http/httptrace"
	"sync"
	"time"
)

// WithFileUpload interrupts an inbound streamed body if the upstream closes.
// net/http can otherwise wait for its write loop to finish reading that body
// before returning the upstream error. Observe closure without consuming any
// HTTP/TLS bytes, and join readers before Fiber can recycle the request.
func WithFileUpload(parent context.Context, reader io.Reader, conn net.Conn) (context.Context, io.ReadCloser, func()) {
	body := &fileBody{reader: reader, conn: conn}
	var mu sync.Mutex
	var stops []func()
	finished := false
	ctx := httptrace.WithClientTrace(parent, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			if finished {
				return
			}
			watch, stop := WithDisconnect(parent, info.Conn)
			done := make(chan struct{})
			context.AfterFunc(watch, func() {
				defer close(done)
				_ = body.Close()
			})
			stops = append(stops, func() { stop(); <-done })
		},
	})
	return ctx, body, func() {
		mu.Lock()
		defer mu.Unlock()
		if finished {
			return
		}
		finished = true
		_ = body.Close()
		for _, stop := range stops {
			stop()
		}
	}
}

type fileBody struct {
	reader   io.Reader
	conn     net.Conn
	mu       sync.Mutex
	reading  bool
	closed   bool
	readDone sync.WaitGroup
}

func (b *fileBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	b.reading = true
	b.readDone.Add(1)
	b.mu.Unlock()
	n, err := b.reader.Read(p)
	b.mu.Lock()
	b.reading = false
	b.mu.Unlock()
	b.readDone.Done()
	return n, err
}

func (b *fileBody) Close() error {
	b.mu.Lock()
	b.closed = true
	reading := b.reading
	b.mu.Unlock()
	if reading {
		_ = b.conn.Close()
	}
	b.readDone.Wait()
	return nil
}

// WithFileTransfer applies a 30-minute ceiling and observes disconnects before any
// response bytes arrive. Closing the connection on cancellation also releases
// blocked inbound body reads and downstream writes. Stop the callback before
// normal cleanup so a successful HTTP keep-alive connection remains reusable.
func WithFileTransfer(parent context.Context, conn net.Conn) (context.Context, context.CancelFunc) {
	ctx, stopDisconnect := WithDisconnect(parent, conn)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	done := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = conn.Close()
	})
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			if !stopClose() {
				<-done
			}
			cancel()
			stopDisconnect()
		})
	}
}
