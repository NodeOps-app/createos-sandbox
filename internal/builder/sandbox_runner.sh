#!/bin/sh
# Runs inside a disposable devbox:1 sandbox. The builder uploads the user
# Dockerfile and a build-scoped config; the builder's API key never enters here.
set -eu

CONFIG=/workspace/build.json
LOG=/scratch/build.log
LOG_STATE=/scratch/build-log.state
LOG_LOCK=/scratch/build-log.lock
# Bound user-controlled Docker output sent to control/ClickHouse. A 32 KiB
# raw chunk remains below control's 256 KiB body limit even when jq expands
# every byte as a JSON escape. The state file is shared by the background
# uploader and final flush so neither can resend an already-accounted range.
MAX_LOG_BYTES=$((1024 * 1024))
MAX_LOG_CHUNK_BYTES=$((32 * 1024))
MAX_LOG_LINES=10000
mkdir -p /scratch/rootfs
: > "$LOG"
printf '0 0 0 0\n' > "$LOG_STATE" # offset, bytes, lines, truncation notice sent

TPL_ID=$(jq -r .template_id "$CONFIG")
CONTROL_URL=$(jq -r .control_url "$CONFIG")
JWT=$(jq -r .jwt "$CONFIG")
ROOTFS_PUT_URL=$(jq -r .rootfs_put_url "$CONFIG")
SIZE_CAP_MIB=$(jq -r .size_cap_mib "$CONFIG")

log_post() {
    flock 9
    read -r last_byte sent_bytes sent_lines truncation_sent < "$LOG_STATE"
    cur=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
    [ "$cur" -le "$last_byte" ] && return 0

    remaining_bytes=$((MAX_LOG_BYTES - sent_bytes))
    remaining_lines=$((MAX_LOG_LINES - sent_lines))
    if [ "$remaining_bytes" -le 0 ] || [ "$remaining_lines" -le 0 ]; then
        if [ "$truncation_sent" -eq 0 ]; then
            notice="[runner] build log truncated after ${sent_bytes} bytes / ${sent_lines} lines"
            printf '%s' "$notice" | jq -Rsc '{line:.}' | curl --max-time 10 -fsS -X POST "$CONTROL_URL/$TPL_ID/log" \
                -H "Authorization: Bearer $JWT" -H 'Content-Type: application/x-ndjson' \
                --data-binary @- >/dev/null 2>&1 || true
            truncation_sent=1
            printf '%s %s %s %s\n' "$last_byte" "$sent_bytes" "$sent_lines" "$truncation_sent" > "$LOG_STATE"
        fi
        return 0
    fi

    available=$((cur - last_byte))
    take=$available
    [ "$take" -gt "$MAX_LOG_CHUNK_BYTES" ] && take=$MAX_LOG_CHUNK_BYTES
    [ "$take" -gt "$remaining_bytes" ] && take=$remaining_bytes
    new=$(tail -c +$((last_byte + 1)) "$LOG" | head -c "$take")
    last_byte=$((last_byte + take))
    sent_bytes=$((sent_bytes + take))
    if [ -n "$new" ]; then
        encoded=$(printf '%s' "$new" | jq -Rsc 'split("\n") | map(select(length>0) | {line:.})')
        available_lines=$(printf '%s' "$encoded" | jq 'length')
        emit_lines=$available_lines
        [ "$emit_lines" -gt "$remaining_lines" ] && emit_lines=$remaining_lines
        payload=""
        if [ "$emit_lines" -gt 0 ]; then
            payload=$(printf '%s' "$encoded" | jq -c --argjson limit "$emit_lines" '.[:$limit][]')
            sent_lines=$((sent_lines + emit_lines))
        fi
        if [ "$available_lines" -gt "$emit_lines" ]; then
            truncation_sent=1
        fi
        # Account the range before network I/O. If shutdown interrupts curl,
        # the final flush drops that best-effort chunk instead of duplicating
        # it or exceeding the cumulative budget.
        printf '%s %s %s %s\n' "$last_byte" "$sent_bytes" "$sent_lines" "$truncation_sent" > "$LOG_STATE"
        if [ -n "$payload" ]; then
            printf '%s\n' "$payload" | curl --max-time 10 -fsS -X POST "$CONTROL_URL/$TPL_ID/log" \
                -H "Authorization: Bearer $JWT" -H 'Content-Type: application/x-ndjson' \
                --data-binary @- >/dev/null 2>&1 || true
        fi
        if [ "$available_lines" -gt "$emit_lines" ]; then
            notice="[runner] build log truncated after ${sent_bytes} bytes / ${sent_lines} lines"
            printf '%s' "$notice" | jq -Rsc '{line:.}' | curl --max-time 10 -fsS -X POST "$CONTROL_URL/$TPL_ID/log" \
                -H "Authorization: Bearer $JWT" -H 'Content-Type: application/x-ndjson' \
                --data-binary @- >/dev/null 2>&1 || true
        fi
    fi
    printf '%s %s %s %s\n' "$last_byte" "$sent_bytes" "$sent_lines" "$truncation_sent" > "$LOG_STATE"
} 9>"$LOG_LOCK"

tail_loop() { while :; do sleep 1; log_post || true; done; }
flush_logs() {
    # Drain the backlog left by a fast/noisy build. Stop once all bytes are
    # accounted or log_post records that a cumulative limit was reached.
    while :; do
        read -r last_byte _ _ truncation_sent < "$LOG_STATE"
        cur=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
        [ "$cur" -le "$last_byte" ] && return 0
        [ "$truncation_sent" -eq 1 ] && return 0
        before=$last_byte
        log_post || return 0
        read -r last_byte _ _ truncation_sent < "$LOG_STATE"
        [ "$last_byte" -le "$before" ] && return 0
    done
}
tail_loop &
TAIL_PID=$!

on_fail() {
    rc=$?
    trap - EXIT INT TERM
    kill "$TAIL_PID" 2>/dev/null || true
    wait "$TAIL_PID" 2>/dev/null || true
    flush_logs || true
    curl --max-time 30 -fsS -X PATCH "$CONTROL_URL/$TPL_ID" \
        -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
        -d '{"status":"failed"}' >/dev/null 2>&1 || true
    exit "$rc"
}
trap on_fail EXIT INT TERM

{
    echo "[runner] $(date -u +%Y-%m-%dT%H:%M:%SZ) building $TPL_ID"
    start-docker
    docker build --network=host -t createos-template-build -f /workspace/Dockerfile /workspace
    container=$(docker create createos-template-build)
    docker export "$container" | tar -xf - -C /scratch/rootfs
    docker rm "$container"
} >>"$LOG" 2>&1

EXT4_BYTES=$(du -sb /scratch/rootfs | cut -f1)
EXT4_MIB=$((EXT4_BYTES / 1048576 + 1))
if [ "$EXT4_MIB" -gt "$SIZE_CAP_MIB" ]; then
    echo "ext4 size ${EXT4_MIB} MiB exceeds cap ${SIZE_CAP_MIB} MiB" >>"$LOG"
    false
fi

SIZE_MIB=$((EXT4_MIB + 200))
truncate -s "${SIZE_MIB}M" /scratch/rootfs.ext4
mkfs.ext4 -q -F -d /scratch/rootfs /scratch/rootfs.ext4 >>"$LOG" 2>&1
zstd -1 -q -o /scratch/rootfs.ext4.zst /scratch/rootfs.ext4 >>"$LOG" 2>&1
SHA=$(sha256sum /scratch/rootfs.ext4.zst | cut -d' ' -f1)
SIZE=$(stat -c %s /scratch/rootfs.ext4.zst)
echo "[runner] uploading rootfs.ext4.zst sha=$SHA size=$SIZE ext4=$EXT4_BYTES" >>"$LOG"

curl --max-time 600 -fsS -X PUT --data-binary @/scratch/rootfs.ext4.zst \
    -H 'Content-Type: application/zstd' "$ROOTFS_PUT_URL" >>"$LOG" 2>&1
body=$(printf '{"status":"ready","sha256":"%s","size_bytes":%s,"ext4_size_bytes":%s}' "$SHA" "$SIZE" "$EXT4_BYTES")
curl --max-time 30 -fsS -X PATCH "$CONTROL_URL/$TPL_ID" \
    -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' -d "$body" >>"$LOG" 2>&1

kill "$TAIL_PID" 2>/dev/null || true
wait "$TAIL_PID" 2>/dev/null || true
flush_logs || true
trap - EXIT INT TERM
echo "[runner] $(date -u +%Y-%m-%dT%H:%M:%SZ) done $TPL_ID" >>"$LOG"
log_post || true
