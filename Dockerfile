FROM golang:1.27.3 AS builder

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# GOAMD64=v3 matches the Makefile target — see its comment block for the
# CPU-feature rationale. The control plane runs on the same AMD
# EPYC class, so v3 (AVX, AVX2, BMI1/2, FMA, LZCNT,
# MOVBE) is safe and shaves ~1-3 % off hot crypto / hash / memmove paths.
# Drop to v1 if you migrate the cluster to a CPU older than Haswell.
RUN CGO_ENABLED=0 GOAMD64=v3 go build -tags=control -ldflags="-s -w" -trimpath -o /out/control ./cmd/control

# GeoIP country DB from db-ip.com Lite (free, no signup, CC-BY-4.0,
# monthly-refreshed). Used by control to label the create-latency
# histogram with the caller's country. The file rolls on the 1st of
# each month, so try the current month and fall back to the previous
# month while the fresh dump is being published. Missing DB is a soft
# failure at runtime — control still starts, country label just reads
# "unknown". Attribution required per CC-BY-4.0: see docs/geoip.md.
RUN set -eux; \
    mkdir -p /out/geoip; \
    Y="$(date -u +%Y)"; M="$(date -u +%m)"; \
    pY="$(date -u -d 'last month' +%Y)"; pM="$(date -u -d 'last month' +%m)"; \
    for u in \
      "https://download.db-ip.com/free/dbip-country-lite-${Y}-${M}.mmdb.gz" \
      "https://download.db-ip.com/free/dbip-country-lite-${pY}-${pM}.mmdb.gz" ; do \
      if curl -fsSL "$u" -o /tmp/geo.mmdb.gz ; then \
        gunzip -c /tmp/geo.mmdb.gz > /out/geoip/country.mmdb ; \
        rm /tmp/geo.mmdb.gz ; \
        break ; \
      fi ; \
    done ; \
    test -s /out/geoip/country.mmdb || echo "warning: geoip DB not fetched; country label will be \"unknown\""

ENTRYPOINT ["/out/control"]
