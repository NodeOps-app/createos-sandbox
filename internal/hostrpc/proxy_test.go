package hostrpc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/NodeOps-app/sandbox/internal/utils"
	"github.com/NodeOps-app/sandbox/models"
)

func TestForwardBuildsSanitizedHostRequest(t *testing.T) {
	t.Parallel()

	var gotMethod, gotQuery, gotBody, gotAuthorization, gotConnection, gotUserID string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotMethod = r.Method
		gotQuery = r.URL.RawQuery
		gotAuthorization = r.Header.Get("Authorization")
		gotConnection = r.Header.Get("Connection")
		gotUserID = r.Header.Get(utils.HeaderUserID)
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    r,
		}, nil
	})}

	response, err := Forward(context.Background(), client, models.Host{Addr: "https://host.test"}, ForwardRequest{
		Method: http.MethodPatch,
		Path:   "/v1/sandboxes/sb-1",
		Query:  "force=true",
		Header: http.Header{
			"Authorization": []string{"Bearer secret"},
			"Connection":    []string{"keep-alive"},
			"X-Test":        []string{"kept"},
		},
		Body:          strings.NewReader(`{"status":"running"}`),
		ContentLength: int64(len(`{"status":"running"}`)),
		UserID:        "user-1",
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusAccepted)
	}
	if gotMethod != http.MethodPatch || gotQuery != "force=true" || gotBody != `{"status":"running"}` {
		t.Fatalf("request = method %q query %q body %q", gotMethod, gotQuery, gotBody)
	}
	if gotAuthorization != "" || gotConnection != "" {
		t.Fatalf("unsafe headers forwarded: authorization=%q connection=%q", gotAuthorization, gotConnection)
	}
	if gotUserID != "user-1" {
		t.Fatalf("user id = %q, want user-1", gotUserID)
	}
}

func TestReadResponseBodyLimit(t *testing.T) {
	t.Parallel()

	response := &http.Response{Body: io.NopCloser(strings.NewReader("12345"))}
	body, err := ReadResponseBody(response, 5)
	if err != nil || string(body) != "12345" {
		t.Fatalf("exact-limit read = %q, %v", body, err)
	}

	response = &http.Response{Body: io.NopCloser(strings.NewReader("123456"))}
	_, err = ReadResponseBody(response, 5)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("over-limit error = %v, want ErrResponseTooLarge", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
