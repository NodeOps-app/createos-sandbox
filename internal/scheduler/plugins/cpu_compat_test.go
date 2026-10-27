package plugins

import (
	"testing"

	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

func TestCPUCompatFilter(t *testing.T) {
	f := CPUCompatFilter{}
	amd := &models.Host{CPUVendor: "AuthenticAMD"}
	intel := &models.Host{CPUVendor: "GenuineIntel"}
	noVendor := &models.Host{}

	cases := []struct {
		name   string
		source string
		host   *models.Host
		wantOK bool
	}{
		{"amd source pins to amd host", "AuthenticAMD", amd, true},
		{"amd source rejects intel host", "AuthenticAMD", intel, false},
		{"intel source rejects amd host", "GenuineIntel", amd, false},
		{"empty source is a no-op (cold create)", "", intel, true},
		{"host with no recorded vendor is rejected", "AuthenticAMD", noVendor, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &framework.Request{SourceCPUVendor: tc.source}
			ok, reason := f.Filter(req, tc.host)
			if ok != tc.wantOK {
				t.Errorf("Filter(source=%q, host vendor=%q) = %v (%q), want %v",
					tc.source, tc.host.CPUVendor, ok, reason, tc.wantOK)
			}
		})
	}
}
