#!/bin/sh
# test.sh
# Summary: Validation suite for hpm TCP publish and consume mode.
# Author:  KaisarCode
# Website: https://kaisarcode.com
# License: https://www.gnu.org/licenses/gpl-3.0.html

BIN=bin/x86_64/linux/hpm
PASS=0
FAIL=0
status=0
TMP_ROOT=/tmp/hpm-test-$$
PORT_BASE=$((20000 + $$ % 20000))
IPID=
HPID=
UPID=

# Prints a failure line and increments counter.
# @param $1 Failure message.
# @return 1 on failure.
kc_test_fail() {
    FAIL=$((FAIL+1))
    printf '\033[31m[FAIL]\033[0m %s\n' "$1"
    return 1
}

# Prints a success line and increments counter.
# @param $1 Success message.
# @return 0 on success.
kc_test_pass() {
    PASS=$((PASS+1))
    printf '\033[32m[PASS]\033[0m %s\n' "$1"
    return 0
}

# Verifies build artifacts exist.
# @return 0 on success, 1 on failure.
kc_test_binary() {
    if [ ! -x "$BIN" ]; then kc_test_fail "hpm not found: $BIN"; return 1; fi
    if [ ! -f "bin/x86_64/linux/libhpm.a" ]; then kc_test_fail "libhpm.a not found"; return 1; fi
    if [ ! -f "bin/x86_64/linux/libhpm.so" ]; then kc_test_fail "libhpm.so not found"; return 1; fi
    kc_test_pass "binaries"; return 0
}

# Tests help, version, and CLI validation.
# @return 0 on success, 1 on failure.
kc_test_cli() {
    if ! "$BIN" --help > /dev/null 2>&1; then kc_test_fail "cli: --help"; return 1; fi
    if ! "$BIN" --version > /dev/null 2>&1; then kc_test_fail "cli: --version"; return 1; fi
    if "$BIN" > /dev/null 2>&1; then kc_test_fail "cli: no args should fail"; return 1; fi
    if "$BIN" set foo@127.0.0.1:1 > /dev/null 2>&1; then kc_test_fail "cli: set without protocol should fail"; return 1; fi
    if "$BIN" con foo@127.0.0.1:1 > /dev/null 2>&1; then kc_test_fail "cli: con without protocol should fail"; return 1; fi
    if "$BIN" set 'bad:id@127.0.0.1:1' --tcp 1 > /dev/null 2>&1; then kc_test_fail "cli: invalid set id should fail"; return 1; fi
    if "$BIN" con 'bad@id@127.0.0.1:1' --tcp 1 > /dev/null 2>&1; then kc_test_fail "cli: invalid con id should fail"; return 1; fi
    if "$BIN" del 'bad:id@127.0.0.1:1' > /dev/null 2>&1; then kc_test_fail "cli: invalid del id should fail"; return 1; fi
    kc_test_pass "cli"; return 0
}

# Starts the index server in background.
# @param $1 Index port.
# @param $2 PoW bits.
# @param $3 Shared password.
# @param $4 Test label.
# @param $5 Optional HPM_VIP text.
# @return 0 on success, 1 on failure.
kc_test_index_start() {
    port=$1
    pow_bits=$2
    pass_key=$3
    label=$4
    vip_text=$5
    if [ -n "$pass_key" ] && [ -n "$vip_text" ]; then
        HPM_PASS="$pass_key" HPM_VIP="$vip_text" "$BIN" idx "$port" --pow "$pow_bits" > "$TMP_ROOT/idx.log" 2>&1 &
    elif [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" idx "$port" --pow "$pow_bits" > "$TMP_ROOT/idx.log" 2>&1 &
    elif [ -n "$vip_text" ]; then
        HPM_VIP="$vip_text" "$BIN" idx "$port" --pow "$pow_bits" > "$TMP_ROOT/idx.log" 2>&1 &
    else
        "$BIN" idx "$port" --pow "$pow_bits" > "$TMP_ROOT/idx.log" 2>&1 &
    fi
    IPID=$!
    sleep 1
    if [ -z "$label" ]; then
        label=$port
    fi
    if kill -0 "$IPID" 2>/dev/null; then kc_test_pass "index-start-$label"; return 0; fi
    kc_test_fail "index-start-$label"; return 1
}

# Verifies VIP seat registration precedence and malformed VIP configs.
# @param $1 Protected index port for VIP success case.
# @param $2 Protected index port for VIP wrong password case.
# @param $3 Protected index port for global fallback case.
# @param $4 Protected index port for odd-token VIP failure case.
# @param $5 Protected index port for duplicate VIP failure case.
# @param $6 Backend port for VIP success case.
# @param $7 Backend port for VIP wrong password case.
# @param $8 Backend port for global fallback case.
# @param $9 Protected index port for invalid VIP id case.
# @return 0 on success, 1 on failure.
kc_test_vip_register() {
    vip_port_ok=$1
    vip_port_bad=$2
    vip_port_global=$3
    vip_port_odd=$4
    vip_port_dup=$5
    vip_backend_ok=$6
    vip_backend_bad=$7
    vip_backend_global=$8
    vip_port_invalid=$9
    vip_text='vipseat vip-pass admin-seat admin-pass'

    kc_test_index_start "$vip_port_ok" 0 global vip-ok "$vip_text" || return 1
    kc_test_set_tcp "$vip_port_ok" vipseat "$vip_backend_ok" vip-pass || return 1
    kc_test_index_stop

    kc_test_index_start "$vip_port_bad" 0 global vip-wrong-pass "$vip_text" || return 1
    kc_test_tcp_start "$vip_backend_bad" || return 1
    HPM_PASS=global "$BIN" set vipseat@127.0.0.1:"$vip_port_bad" --tcp "$vip_backend_bad" > "$TMP_ROOT/vip-bad.log" 2>&1 &
    spid=$!
    sleep 2
    if kill -0 "$spid" 2>/dev/null; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_fail "vip-wrong-pass"
        return 1
    fi
    wait "$spid" 2>/dev/null || true
    kill -9 "$HPID" 2>/dev/null
    wait "$HPID" 2>/dev/null
    kc_test_pass "vip-wrong-pass"
    kc_test_index_stop

    kc_test_index_start "$vip_port_global" 0 global vip-global-fallback "$vip_text" || return 1
    kc_test_set_tcp "$vip_port_global" plainseat "$vip_backend_global" global || return 1
    kc_test_index_stop

    if HPM_PASS=global HPM_VIP='vipseat' "$BIN" idx "$vip_port_odd" > "$TMP_ROOT/vip-odd.log" 2>&1; then
        kc_test_fail "vip-odd"
        return 1
    fi
    kc_test_pass "vip-odd"

    if HPM_PASS=global HPM_VIP='vipseat one vipseat two' "$BIN" idx "$vip_port_dup" > "$TMP_ROOT/vip-dup.log" 2>&1; then
        kc_test_fail "vip-dup"
        return 1
    fi
    kc_test_pass "vip-dup"

    if HPM_PASS=global HPM_VIP='bad:id nope' "$BIN" idx "$vip_port_invalid" > "$TMP_ROOT/vip-invalid.log" 2>&1; then
        kc_test_fail "vip-invalid-id"
        return 1
    fi
    kc_test_pass "vip-invalid-id"

    kc_test_pass "vip-register"
    return 0
}

# Stops the current index process.
# @return 0 on success.
kc_test_index_stop() {
    if [ -n "$IPID" ]; then
        kill -9 "$IPID" 2>/dev/null || true
        wait "$IPID" 2>/dev/null || true
        IPID=
    fi
    return 0
}

# Verifies the index listens only on TCP.
# @param $1 Index port.
# @return 0 on success, 1 on failure.
kc_test_index_tcp_only() {
    port=$1
    if ! ss -ltnH "( sport = :$port )" | grep -q LISTEN; then
        kc_test_fail "index-tcp-listen-$port"
        return 1
    fi
    if ss -lunH "( sport = :$port )" | grep -q .; then
        kc_test_fail "index-no-udp-$port"
        return 1
    fi
    kc_test_pass "index-tcp-only-$port"
    return 0
}

# Verifies LIST, LOOKUP, and DEREGISTER over TCP control.
# @param $1 Index port.
# @param $2 Backend port.
# @return 0 on success, 1 on failure.
kc_test_control_catalog() {
    port=$1
    backend_port=$2
    list_out="$TMP_ROOT/list.out"
    lookup_out="$TMP_ROOT/lookup.out"
    miss_out="$TMP_ROOT/miss.out"

    kc_test_tcp_start "$backend_port" || return 1
    "$BIN" set control@127.0.0.1:"$port" --tcp "$backend_port" > "$TMP_ROOT/control-set.log" 2>&1 &
    spid=$!
    sleep 2
    if ! kill -0 "$spid" 2>/dev/null; then
        wait "$spid" 2>/dev/null || true
        kill -9 "$HPID" 2>/dev/null || true
        wait "$HPID" 2>/dev/null || true
        kc_test_fail "control-register"
        return 1
    fi
    if ! printf 'LIST\n' | nc -w 2 127.0.0.1 "$port" > "$list_out" 2>/dev/null; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_fail "control-list"
        return 1
    fi
    if ! grep -q '^PEER:control$' "$list_out"; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_fail "control-list"
        return 1
    fi
    if ! printf 'LOOKUP:control\n' | nc -w 2 127.0.0.1 "$port" > "$lookup_out" 2>/dev/null; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_fail "control-lookup"
        return 1
    fi
    if ! grep -q '^PEER:control$' "$lookup_out"; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_fail "control-lookup"
        return 1
    fi
    if ! "$BIN" del control@127.0.0.1:"$port" > "$TMP_ROOT/control-del.log" 2>&1; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_fail "control-deregister"
        return 1
    fi
    if ! printf 'LOOKUP:control\n' | nc -w 2 127.0.0.1 "$port" > "$miss_out" 2>/dev/null; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_fail "control-post-del"
        return 1
    fi
    kill -9 "$spid" "$HPID" 2>/dev/null || true
    wait "$spid" "$HPID" 2>/dev/null || true
    if ! grep -q '^NOT_FOUND$' "$miss_out"; then
        kc_test_fail "control-post-del"
        return 1
    fi
    kc_test_pass "control-catalog"
    return 0
}

# Starts a local TCP echo backend.
# @param $1 Backend port.
# @return 0 on success, 1 on failure.
kc_test_tcp_start() {
    tcp_port=$1
    socat TCP-LISTEN:"$tcp_port",reuseaddr,fork EXEC:cat 2>/dev/null &
    HPID=$!
    sleep 1
    if kill -0 "$HPID" 2>/dev/null; then return 0; fi
    kc_test_fail "tcp-backend-$tcp_port"; return 1
}

# Sends one TCP payload and waits for the echoed reply.
# @param $1 Destination port.
# @param $2 Message.
# @param $3 Output file.
# @return 0 on success, 1 on failure.
kc_test_tcp_roundtrip() {
    dst_port=$1
    msg=$2
    out=$3
    i=0
    while [ "$i" -lt 20 ]; do
        if printf '%s' "$msg" | socat -t 5 - TCP:127.0.0.1:"$dst_port" > "$out" 2>/dev/null; then
            return 0
        fi
        i=$((i+1))
        sleep 1
    done
    return 1
}

# Starts a local UDP echo backend using netcat.
# @param $1 Backend port.
# @return 0 on success, 1 on failure.
kc_test_udp_start() {
    udp_port=$1
    while true; do
        nc -u -l -p "$udp_port" -c 'cat' 2>/dev/null
    done &
    UPID=$!
    sleep 1
    if kill -0 "$UPID" 2>/dev/null; then return 0; fi
    kc_test_fail "udp-backend-$udp_port"; return 1
}

# Sends one UDP datagram and waits for the echoed reply.
# @param $1 Destination port.
# @param $2 Message.
# @param $3 Output file.
# @return 0 on success, 1 on failure.
kc_test_udp_roundtrip() {
    dst_port=$1
    msg=$2
    out=$3
    printf '%s' "$msg" | socat -t 1 - UDP:127.0.0.1:"$dst_port" > "$out" 2>/dev/null
}

# Starts a TCP publisher and verifies it stays alive.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Shared password.
# @return 0 on success, 1 on failure.
kc_test_set_tcp() {
    port=$1
    host=$2
    backend_port=$3
    pass_key=$4
    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/set-$host.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/set-$host.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    if kill -0 "$spid" 2>/dev/null; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_pass "set-tcp-$host"; return 0
    fi
    kill -9 "$HPID" 2>/dev/null
    wait "$HPID" 2>/dev/null
    kc_test_fail "set-tcp-$host"; return 1
}

# Verifies one TCP payload crosses the tunnel.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Listen port.
# @param $5 Shared password.
# @return 0 on success, 1 on failure.
kc_test_tcp_echo() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    out="$TMP_ROOT/tcp-client.out"

    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/tcp-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/tcp-set.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/tcp-con.log" 2>&1 &
    cpid=$!
    sleep 2

    if ! kc_test_tcp_roundtrip "$listen_port" "ping" "$out"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-echo-$host"; return 1
    fi
    if ! grep -q "ping" "$out"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-echo-$host"; return 1
    fi

    kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
    wait "$spid" "$cpid" "$HPID" 2>/dev/null
    kc_test_pass "tcp-echo-$host"; return 0
}

# Verifies two consecutive TCP requests reuse one running consumer.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Listen port.
# @param $5 Shared password.
# @return 0 on success, 1 on failure.
kc_test_tcp_reconnect() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    out1="$TMP_ROOT/reconnect-1.out"
    out2="$TMP_ROOT/reconnect-2.out"

    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/reconnect-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/reconnect-set.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/reconnect-con.log" 2>&1 &
    cpid=$!
    sleep 2

    if ! kc_test_tcp_roundtrip "$listen_port" "again1" "$out1"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-reconnect-$host"; return 1
    fi
    if ! kc_test_tcp_roundtrip "$listen_port" "again2" "$out2"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-reconnect-$host"; return 1
    fi
    if ! grep -q "again1" "$out1" || ! grep -q "again2" "$out2"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-reconnect-$host"; return 1
    fi

    kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
    wait "$spid" "$cpid" "$HPID" 2>/dev/null
    kc_test_pass "tcp-reconnect-$host"; return 0
}

# Verifies a large TCP payload survives byte-for-byte.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Listen port.
# @param $5 Shared password.
# @return 0 on success, 1 on failure.
kc_test_tcp_large() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    in="$TMP_ROOT/large.in"
    out="$TMP_ROOT/large.out"

    dd if=/dev/urandom of="$in" bs=1048576 count=10 status=none || return 1
    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/large-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/large-set.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/large-con.log" 2>&1 &
    cpid=$!
    sleep 2

    if ! socat -t 60 - TCP:127.0.0.1:"$listen_port" < "$in" > "$out" 2>/dev/null; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-large-$host"; return 1
    fi
    if ! cmp -s "$in" "$out"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-large-$host"; return 1
    fi

    kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
    wait "$spid" "$cpid" "$HPID" 2>/dev/null
    kc_test_pass "tcp-large-$host"; return 0
}

# Verifies dropped TCP DATA frames are recovered by retransmission.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Listen port.
# @param $5 Shared password.
# @return 0 on success, 1 on failure.
kc_test_tcp_loss() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    out="$TMP_ROOT/loss.out"

    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-set.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    HPM_DEBUG_STREAM_DROP_EVERY=1 "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/loss-con.log" 2>&1 &
    cpid=$!
    sleep 2

    if ! kc_test_tcp_roundtrip "$listen_port" "losscheck" "$out"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-loss-$host"; return 1
    fi
    if ! grep -q "losscheck" "$out"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-loss-$host"; return 1
    fi

    kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
    wait "$spid" "$cpid" "$HPID" 2>/dev/null
    kc_test_pass "tcp-loss-$host"; return 0
}

# Verifies dropped DATA frames are recovered in both directions.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Listen port.
# @param $5 Shared password.
# @return 0 on success, 1 on failure.
kc_test_tcp_loss_bidir() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    out="$TMP_ROOT/loss-bidir.out"

    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" HPM_DEBUG_STREAM_DROP_EVERY=1 "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-bidir-set.log" 2>&1 &
    else
        HPM_DEBUG_STREAM_DROP_EVERY=1 "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-bidir-set.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    HPM_DEBUG_STREAM_DROP_EVERY=1 "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/loss-bidir-con.log" 2>&1 &
    cpid=$!
    sleep 2

    if ! kc_test_tcp_roundtrip "$listen_port" "lossbidir" "$out"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-loss-bidir-$host"; return 1
    fi
    if ! grep -q "lossbidir" "$out"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-loss-bidir-$host"; return 1
    fi

    kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
    wait "$spid" "$cpid" "$HPID" 2>/dev/null
    kc_test_pass "tcp-loss-bidir-$host"; return 0
}

# Verifies out-of-order TCP DATA frames are reconstructed correctly.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Listen port.
# @param $5 Shared password.
# @return 0 on success, 1 on failure.
kc_test_tcp_reorder() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    in="$TMP_ROOT/reorder.in"
    out="$TMP_ROOT/reorder.out"

    dd if=/dev/urandom of="$in" bs=4096 count=1 status=none || return 1
    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/reorder-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/reorder-set.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    HPM_DEBUG_STREAM_REORDER_EVERY=1 "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/reorder-con.log" 2>&1 &
    cpid=$!
    sleep 2

    if ! socat -t 20 - TCP:127.0.0.1:"$listen_port" < "$in" > "$out" 2>/dev/null; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-reorder-$host"; return 1
    fi
    if ! cmp -s "$in" "$out"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-reorder-$host"; return 1
    fi

    kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
    wait "$spid" "$cpid" "$HPID" 2>/dev/null
    kc_test_pass "tcp-reorder-$host"; return 0
}

# Verifies two concurrent TCP payloads cross the tunnel.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Listen port.
# @param $5 Shared password.
# @return 0 on success, 1 on failure.
kc_test_tcp_concurrent() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    out1="$TMP_ROOT/concurrent-1.out"
    out2="$TMP_ROOT/concurrent-2.out"

    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/concurrent-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/concurrent-set.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/concurrent-con.log" 2>&1 &
    cpid=$!
    sleep 2

    kc_test_tcp_roundtrip "$listen_port" "one1" "$out1" &
    q1=$!
    kc_test_tcp_roundtrip "$listen_port" "two2" "$out2" &
    q2=$!
    wait "$q1" "$q2" 2>/dev/null || {
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-concurrent-$host"; return 1
    }
    if ! grep -q "one1" "$out1" || ! grep -q "two2" "$out2"; then
        kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
        wait "$spid" "$cpid" "$HPID" 2>/dev/null
        kc_test_fail "tcp-concurrent-$host"; return 1
    fi

    kill -9 "$spid" "$cpid" "$HPID" 2>/dev/null
    wait "$spid" "$cpid" "$HPID" 2>/dev/null
    kc_test_pass "tcp-concurrent-$host"; return 0
}

# Starts a UDP publisher and verifies it stays alive.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Shared password.
# @return 0 on success, 1 on failure.
kc_test_set_udp() {
    port=$1
    host=$2
    backend_port=$3
    pass_key=$4
    kc_test_udp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/set-udp-$host.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/set-udp-$host.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    if kill -0 "$spid" 2>/dev/null; then
        kill -9 "$spid" "$UPID" 2>/dev/null
        wait "$spid" "$UPID" 2>/dev/null
        kc_test_pass "set-udp-$host"; return 0
    fi
    kill -9 "$UPID" 2>/dev/null
    wait "$UPID" 2>/dev/null
    kc_test_fail "set-udp-$host"; return 1
}

# Verifies one UDP roundtrip crosses the tunnel.
# @param $1 Index port.
# @param $2 Hostname.
# @param $3 Backend port.
# @param $4 Listen port.
# @param $5 Shared password.
# @return 0 on success, 1 on failure.
kc_test_udp_echo() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    out="$TMP_ROOT/udp-client.out"

    kc_test_udp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        HPM_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/udp-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/udp-set.log" 2>&1 &
    fi
    spid=$!
    sleep 2
    "$BIN" con "${host}@127.0.0.1:${port}" --udp "$listen_port" > "$TMP_ROOT/udp-con.log" 2>&1 &
    cpid=$!
    sleep 2
    if ! kc_test_udp_roundtrip "$listen_port" "hello-udp" "$out"; then
        kill -9 "$spid" "$cpid" "$UPID" 2>/dev/null
        wait "$spid" "$cpid" "$UPID" 2>/dev/null
        kc_test_fail "udp-echo-$host"; return 1
    fi
    if ! grep -q "hello-udp" "$out"; then
        kill -9 "$spid" "$cpid" "$UPID" 2>/dev/null
        wait "$spid" "$cpid" "$UPID" 2>/dev/null
        kc_test_fail "udp-echo-$host"; return 1
    fi
    kill -9 "$spid" "$cpid" "$UPID" 2>/dev/null
    wait "$spid" "$cpid" "$UPID" 2>/dev/null
    kc_test_pass "udp-echo-$host"; return 0
}

# Verifies protected registration succeeds and failures are rejected.
# @param $1 Protected index port for success case.
# @param $2 Protected index port for wrong password case.
# @param $3 Protected index port for missing password case.
# @param $4 Protected index port for pow case.
# @param $5 Protected index port for public consumer case.
# @param $6 Backend port for success case.
# @param $7 Backend port for wrong password case.
# @param $8 Backend port for missing password case.
# @param $9 Backend port for public consumer case.
# @param $10 Listen port for public consumer case.
# @return 0 on success, 1 on failure.
kc_test_auth_register() {
    auth_port_ok=$1
    auth_port_bad=$2
    auth_port_missing=$3
    auth_port_pow=$4
    auth_port_public=$5
    auth_backend_ok=$6
    auth_backend_bad=$7
    auth_backend_missing=$8
    auth_backend_public=$9
    auth_listen_public=${10}

    kc_test_index_start "$auth_port_ok" 0 abc auth-ok || return 1
    kc_test_set_tcp "$auth_port_ok" authok "$auth_backend_ok" abc || return 1
    kc_test_index_stop
    kc_test_index_start "$auth_port_bad" 0 abc auth-wrong-pass || return 1
    kc_test_tcp_start "$auth_backend_bad" || return 1
    HPM_PASS=wrong "$BIN" set authbad@127.0.0.1:"$auth_port_bad" --tcp "$auth_backend_bad" > "$TMP_ROOT/auth-bad.log" 2>&1 &
    spid=$!
    sleep 2
    if kill -0 "$spid" 2>/dev/null; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_fail "auth-wrong-pass"
        return 1
    fi
    wait "$spid" 2>/dev/null || true
    kill -9 "$HPID" 2>/dev/null
    wait "$HPID" 2>/dev/null
    kc_test_pass "auth-wrong-pass"
    kc_test_index_stop
    kc_test_index_start "$auth_port_missing" 0 abc auth-missing-pass || return 1
    kc_test_tcp_start "$auth_backend_missing" || return 1
    "$BIN" set authmissing@127.0.0.1:"$auth_port_missing" --tcp "$auth_backend_missing" > "$TMP_ROOT/auth-missing.log" 2>&1 &
    spid=$!
    sleep 2
    if kill -0 "$spid" 2>/dev/null; then
        kill -9 "$spid" "$HPID" 2>/dev/null
        wait "$spid" "$HPID" 2>/dev/null
        kc_test_fail "auth-missing-pass"
        return 1
    fi
    wait "$spid" 2>/dev/null || true
    kill -9 "$HPID" 2>/dev/null
    wait "$HPID" 2>/dev/null
    kc_test_pass "auth-missing-pass"
    kc_test_index_stop
    kc_test_index_start "$auth_port_pow" 20 abc auth-pow || return 1
    kc_test_set_tcp "$auth_port_pow" authpow "$auth_backend_ok" abc || return 1
    kc_test_index_stop
    kc_test_index_start "$auth_port_public" 0 abc auth-public-con || return 1
    kc_test_tcp_echo "$auth_port_public" authpub "$auth_backend_public" "$auth_listen_public" abc || return 1
    kc_test_index_stop
    kc_test_pass "auth-register"
    return 0
}

# Runs the validation suite.
# @return 0 on success, 1 on failure.
kc_test_main() {
    mkdir -p "$TMP_ROOT"
    index_port=$PORT_BASE
    backend_tcp_1=$((PORT_BASE + 10))
    backend_tcp_2=$((PORT_BASE + 11))
    backend_tcp_3=$((PORT_BASE + 12))
    backend_tcp_4=$((PORT_BASE + 17))
    backend_tcp_5=$((PORT_BASE + 18))
    backend_tcp_6=$((PORT_BASE + 19))
    backend_tcp_7=$((PORT_BASE + 22))
    backend_udp_1=$((PORT_BASE + 20))
    backend_udp_2=$((PORT_BASE + 21))
    listen_tcp_1=$((PORT_BASE + 110))
    listen_tcp_2=$((PORT_BASE + 111))
    listen_tcp_3=$((PORT_BASE + 113))
    listen_tcp_4=$((PORT_BASE + 114))
    listen_tcp_5=$((PORT_BASE + 115))
    listen_tcp_6=$((PORT_BASE + 116))
    listen_udp_1=$((PORT_BASE + 120))
    public_pow_port=$((PORT_BASE + 1))
    auth_port_1=$((PORT_BASE + 2))
    auth_port_2=$((PORT_BASE + 3))
    auth_port_3=$((PORT_BASE + 4))
    auth_port_4=$((PORT_BASE + 5))
    auth_port_5=$((PORT_BASE + 6))
    vip_port_1=$((PORT_BASE + 7))
    vip_port_2=$((PORT_BASE + 8))
    vip_port_3=$((PORT_BASE + 9))
    vip_port_4=$((PORT_BASE + 23))
    vip_port_5=$((PORT_BASE + 24))
    vip_port_6=$((PORT_BASE + 28))
    auth_backend_1=$((PORT_BASE + 13))
    auth_backend_2=$((PORT_BASE + 14))
    auth_backend_3=$((PORT_BASE + 15))
    auth_backend_4=$((PORT_BASE + 16))
    vip_backend_1=$((PORT_BASE + 25))
    vip_backend_2=$((PORT_BASE + 26))
    vip_backend_3=$((PORT_BASE + 27))
    control_backend=$((PORT_BASE + 29))
    auth_listen_1=$((PORT_BASE + 112))

    kc_test_binary || return 1
    kc_test_cli || return 1
    kc_test_index_start "$index_port" 0 "" public-default || return 1
    kc_test_index_tcp_only "$index_port" || return 1
    kc_test_control_catalog "$index_port" "$control_backend" || return 1
    kc_test_set_tcp "$index_port" host1 "$backend_tcp_1" "" || return 1
    kc_test_tcp_echo "$index_port" web "$backend_tcp_2" "$listen_tcp_1" "" || return 1
    kc_test_tcp_concurrent "$index_port" web2 "$backend_tcp_3" "$listen_tcp_2" "" || return 1
    kc_test_tcp_reconnect "$index_port" web3 "$auth_backend_1" "$auth_listen_1" "" || return 1
    kc_test_tcp_loss "$index_port" web4 "$backend_tcp_4" "$listen_tcp_3" "" || return 1
    kc_test_tcp_large "$index_port" web5 "$backend_tcp_5" "$listen_tcp_4" "" || return 1
    kc_test_tcp_loss_bidir "$index_port" web6 "$backend_tcp_6" "$listen_tcp_5" "" || return 1
    kc_test_tcp_reorder "$index_port" web7 "$backend_tcp_7" "$listen_tcp_6" "" || return 1
    kc_test_set_udp "$index_port" game0 "$backend_udp_1" "" || return 1
    kc_test_udp_echo "$index_port" game1 "$backend_udp_2" "$listen_udp_1" "" || return 1
    kc_test_index_stop
    kc_test_index_start "$public_pow_port" 20 "" public-pow || return 1
    kc_test_set_tcp "$public_pow_port" publicpow "$auth_backend_1" "" || return 1
    kc_test_index_stop
    kc_test_auth_register "$auth_port_1" "$auth_port_2" "$auth_port_3" \
        "$auth_port_4" "$auth_port_5" "$auth_backend_2" "$auth_backend_3" \
        "$auth_backend_4" "$auth_backend_1" "$auth_listen_1" || return 1
    kc_test_vip_register "$vip_port_1" "$vip_port_2" "$vip_port_3" \
        "$vip_port_4" "$vip_port_5" "$vip_backend_1" "$vip_backend_2" \
        "$vip_backend_3" "$vip_port_6" || return 1
    pkill -9 -P $$ 2>/dev/null || true
    wait 2>/dev/null || true
    return 0
}

trap 'status=$?; pkill -9 -P $$ 2>/dev/null || true; pkill -9 -f "bin/x86_64/linux/hpm" 2>/dev/null || true; rm -rf "$TMP_ROOT"; exit "${status:-0}"' EXIT INT HUP TERM

kc_test_main
exit $FAIL
