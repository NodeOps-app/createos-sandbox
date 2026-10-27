package agent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	ntpEpochOffset      = 2_208_988_800
	ntpPacketSize       = 48
	guestTimeSyncPeriod = 6 * time.Hour
	guestTimeSyncLimit  = 3 * time.Second
)

var publicTimeServers = []string{
	// Cloudflare's documented anycast NTP endpoints. Fixed IPv4 addresses
	// avoid DNS and match the host-side infrastructure egress exemption.
	"162.159.200.1:123",
	"162.159.200.123:123",
}

// startPublicTimeSync maintains wall-clock accuracy without a resident NTP
// daemon. One successful cycle is a single 48-byte UDP request and response;
// at the six-hour interval that is four exchanges (384 payload bytes) per day.
// The host's MMDS now_ns remains responsible for the immediate restore-time
// correction, so this loop is deliberately off the boot/readiness path.
func startPublicTimeSync() {
	go func() {
		// Give phase 2, DNS and tenant startup traffic time to settle. Long-lived
		// drift is measured in ppm, so there is no value in racing VM readiness.
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		<-timer.C

		for {
			if networkTime, offset, err := fetchPublicTime(); err != nil {
				fmt.Printf("agent: public time sync failed: %v\n", err)
				writeTimeSyncStatus(fmt.Sprintf("error time=%d message=%q\n", time.Now().Unix(), err))
			} else if absDuration(offset) >= time.Millisecond {
				setSystemClockNS(networkTime.UnixNano())
				fmt.Printf("agent[%s]: synchronized clock offset=%s\n",
					time.Now().Format("15:04:05.000"), offset.Round(time.Millisecond))
				writeTimeSyncStatus(fmt.Sprintf("ok time=%d offset_ns=%d stepped=true\n",
					time.Now().Unix(), offset.Nanoseconds()))
			} else {
				writeTimeSyncStatus(fmt.Sprintf("ok time=%d offset_ns=%d stepped=false\n",
					time.Now().Unix(), offset.Nanoseconds()))
			}
			timer.Reset(guestTimeSyncPeriod)
			<-timer.C
		}
	}()
}

func fetchPublicTime() (time.Time, time.Duration, error) {
	var lastErr error
	for _, server := range publicTimeServers {
		t, offset, err := querySNTP(server, guestTimeSyncLimit)
		if err == nil {
			return t, offset, nil
		}
		lastErr = err
	}
	return time.Time{}, 0, lastErr
}

// querySNTP implements the four-timestamp SNTP offset calculation from
// RFC 4330. The returned time includes half-round-trip compensation rather
// than blindly applying the server's (already stale) transmit timestamp.
func querySNTP(server string, timeout time.Duration) (time.Time, time.Duration, error) {
	// Sandboxes currently receive IPv4 networking only. Force udp4 so a DNS
	// AAAA answer cannot consume the timeout before the provider's A record.
	conn, err := net.DialTimeout("udp4", server, timeout)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := make([]byte, ntpPacketSize)
	req[0] = 0x23 // leap=0, version=4, mode=3 (client)
	t1 := time.Now()
	putNTPTime(req[40:48], t1)
	if _, err := conn.Write(req); err != nil {
		return time.Time{}, 0, err
	}
	resp := make([]byte, ntpPacketSize)
	n, err := conn.Read(resp)
	t4 := time.Now()
	if err != nil {
		return time.Time{}, 0, err
	}
	// Accept only a synchronized server response for this exact request.
	// Checking the originate timestamp rejects unrelated, delayed and most
	// trivially spoofed UDP packets without adding protocol overhead.
	if n < ntpPacketSize || resp[0]&7 != 4 || resp[0]>>6 == 3 ||
		resp[1] == 0 || resp[1] > 15 || !bytes.Equal(resp[24:32], req[40:48]) {
		return time.Time{}, 0, fmt.Errorf("invalid NTP response")
	}
	t2 := parseNTPTime(resp[32:40])
	t3 := parseNTPTime(resp[40:48])
	if t2.IsZero() || t3.IsZero() {
		return time.Time{}, 0, fmt.Errorf("NTP response missing timestamps")
	}
	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	return t4.Add(offset), offset, nil
}

func writeTimeSyncStatus(status string) {
	_ = os.MkdirAll("/run/createos", 0o755)
	_ = os.WriteFile("/run/createos/time-sync.status", []byte(status), 0o644)
}

func putNTPTime(dst []byte, t time.Time) {
	sec := uint64(t.Unix() + ntpEpochOffset)
	frac := uint64(t.Nanosecond()) << 32 / 1_000_000_000
	binary.BigEndian.PutUint32(dst[0:4], uint32(sec))
	binary.BigEndian.PutUint32(dst[4:8], uint32(frac))
}

func parseNTPTime(src []byte) time.Time {
	sec := int64(binary.BigEndian.Uint32(src[0:4])) - ntpEpochOffset
	frac := uint64(binary.BigEndian.Uint32(src[4:8]))
	nsec := int64(frac * 1_000_000_000 >> 32)
	return time.Unix(sec, nsec)
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
