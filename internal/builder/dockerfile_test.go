package builder

import "testing"

func TestValidateDockerfile_Accept(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"plain debian", "FROM nodeops/sandbox:debian\nRUN apt-get update", "nodeops/sandbox:debian"},
		{"plain alpine", "FROM nodeops/sandbox:alpine\nRUN apk add curl", "nodeops/sandbox:alpine"},
		{"comments + blank", "# build my thing\n\nFROM nodeops/sandbox:alpine\n", "nodeops/sandbox:alpine"},
		{"continuation", "FROM nodeops/sandbox:debian\nRUN apt-get update && \\\n  apt-get install -y curl", "nodeops/sandbox:debian"},
		{"platform flag", "FROM --platform=linux/amd64 nodeops/sandbox:debian", "nodeops/sandbox:debian"},
		{"as alias", "FROM nodeops/sandbox:debian AS builder", "nodeops/sandbox:debian"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateDockerfile([]byte(tc.body), nil)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestValidateDockerfile_Reject(t *testing.T) {
	cases := []struct {
		name string
		body string
		msg  string
	}{
		{"no FROM", "RUN echo hi", "no FROM"},
		{"FROM ubuntu", "FROM ubuntu:22.04", "not in allowlist"},
		{"FROM scratch", "FROM scratch", "scratch"},
		{"two FROM", "FROM nodeops/sandbox:debian\nFROM nodeops/sandbox:alpine", "multi-stage"},
		{"COPY", "FROM nodeops/sandbox:debian\nCOPY . /app", "COPY"},
		{"ADD", "FROM nodeops/sandbox:debian\nADD https://example.com/x /tmp/x", "ADD"},
		{"ARG FROM", "ARG B=nodeops/sandbox:debian\nFROM ${B}", "ARG-substituted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateDockerfile([]byte(tc.body), nil)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.msg)
			}
			if !contains(err.Error(), tc.msg) {
				t.Fatalf("err=%q does not contain %q", err.Error(), tc.msg)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
