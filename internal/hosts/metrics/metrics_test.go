package metrics

import (
	"context"
	"strings"
	"testing"
)

func TestServeRejectsEnabledListenerWithoutTokenFile(t *testing.T) {
	err := Serve(context.Background(), ServeConfig{Addr: "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "token file is required") {
		t.Fatalf("Serve() error = %v; want missing token-file error", err)
	}
}
