#!/bin/sh
# test.sh
# Summary: Validation suite for rp2p TCP publish and consume mode.
# Author:  KaisarCode
# Website: https://kaisarcode.com
# License: https://www.gnu.org/licenses/gpl-3.0.html

BIN=bin/x86_64/linux/rp2p
PASS=0
FAIL=0
status=0
TMP_ROOT=/tmp/p2p-test-$$
PORT_BASE=$((20000 + $$ % 20000))
IPID=
HPID=
UPID=

# Prints a failure line and increments counter.
# @return 1 on failure.
kc_test_fail() {
    FAIL=$((FAIL+1))
    printf '\033[31m[FAIL]\033[0m %s\n' "$1"
    return 1
}

# Reports one passed assertion.
# @return 0 on success, 1 on failure.
kc_test_pass() {
    PASS=$((PASS+1))
    printf '\033[32m[PASS]\033[0m %s\n' "$1"
    return 0
}

# Verifies build artifacts exist. Silent prerequisite, not a test.
# @return 0 on success.
kc_test_ensure_binary() {
    if [ ! -x "$BIN" ]; then printf 'prerequisite: rp2p not found at %s\n' "$BIN" >&2; return 1; fi
    if [ ! -f "bin/x86_64/linux/librp2p.a" ]; then printf 'prerequisite: librp2p.a not found\n' >&2; return 1; fi
    if [ ! -f "bin/x86_64/linux/librp2p.so" ]; then printf 'prerequisite: librp2p.so not found\n' >&2; return 1; fi
    return 0
}

# Starts the index server in background. Silent setup.
# @return 0 on success, 1 on failure.
kc_test_index_start() {
    port=$1
    pow_bits=$2
    pass_key=$3
    label=$4
    vip_text=$5
    if [ -n "$pass_key" ] && [ -n "$vip_text" ]; then
        RP2P_PASS="$pass_key" RP2P_VIP="$vip_text" "$BIN" idx "$port" --pow "$pow_bits" > "$TMP_ROOT/idx-$label.log" 2>&1 &
    elif [ -n "$pass_key" ]; then
        RP2P_PASS="$pass_key" "$BIN" idx "$port" --pow "$pow_bits" > "$TMP_ROOT/idx-$label.log" 2>&1 &
    elif [ -n "$vip_text" ]; then
        RP2P_VIP="$vip_text" "$BIN" idx "$port" --pow "$pow_bits" > "$TMP_ROOT/idx-$label.log" 2>&1 &
    else
        "$BIN" idx "$port" --pow "$pow_bits" > "$TMP_ROOT/idx-$label.log" 2>&1 &
    fi
    IPID=$!
    if ! kc_test_wait_port "$port"; then
        kc_test_fail "index start on port $port: expected LISTEN state, process did not start"
        return 1
    fi
    return 0
}

# Verifies VIP seat registration precedence and malformed VIP configs.
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
    vip_text='vipseat vip-pass adminseat admin-pass'

    kc_test_index_start "$vip_port_ok" 0 global vip-ok "$vip_text" || return 1
    kc_test_set_tcp "$vip_port_ok" vipseat "$vip_backend_ok" vip-pass || return 1
    kc_test_index_stop
    kc_test_pass "VIP seat correct pass: publisher registered"

    kc_test_index_start "$vip_port_bad" 0 global vip-wrong-pass "$vip_text" || return 1
    kc_test_tcp_start "$vip_backend_bad" || return 1
    RP2P_PASS=global "$BIN" set vipseat@127.0.0.1:"$vip_port_bad" --tcp "$vip_backend_bad" > "$TMP_ROOT/vip-bad.log" 2>&1 &
    spid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if ! kill -0 "$spid" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    if kill -0 "$spid" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_index_stop
        kc_test_fail "VIP seat wrong password: expected process to exit, stayed alive"
        return 1
    fi
    wait "$spid" 2>/dev/null || true
    kc_test_kill "$HPID"
    kc_test_pass "VIP seat wrong password: rejected"
    kc_test_index_stop

    kc_test_index_start "$vip_port_global" 0 global vip-global-fallback "$vip_text" || return 1
    kc_test_set_tcp "$vip_port_global" plainseat "$vip_backend_global" global || return 1
    kc_test_index_stop
    kc_test_pass "VIP global fallback: non-VIP seat uses global pass"

    if RP2P_PASS=global RP2P_VIP='vipseat' "$BIN" idx "$vip_port_odd" > "$TMP_ROOT/vip-odd.log" 2>&1; then
        kc_test_fail "VIP odd token count (1 token): expected index to reject, got exit 0"
        return 1
    fi
    kc_test_pass "VIP reject odd token count"

    if RP2P_PASS=global RP2P_VIP='vipseat one vipseat two' "$BIN" idx "$vip_port_dup" > "$TMP_ROOT/vip-dup.log" 2>&1; then
        kc_test_fail "VIP duplicate seat name: expected index to reject, got exit 0"
        return 1
    fi
    kc_test_pass "VIP reject duplicate seat name"

    if RP2P_PASS=global RP2P_VIP='bad:id nope' "$BIN" idx "$vip_port_invalid" > "$TMP_ROOT/vip-invalid.log" 2>&1; then
        kc_test_fail "VIP invalid seat name (colon): expected index to reject, got exit 0"
        return 1
    fi
    kc_test_pass "VIP reject invalid seat name (colon)"

    if RP2P_PASS=global RP2P_VIP='vipseat bad`tick' "$BIN" idx "$vip_port_invalid" > "$TMP_ROOT/vip-invalid-pass.log" 2>&1; then
        kc_test_fail "VIP invalid password (backtick): expected index to reject, got exit 0"
        return 1
    fi
    kc_test_pass "VIP reject invalid password (backtick)"

    return 0
}

# Verifies VIP seats reserve capacity before runtime and do not cap VIP count.
# @return 0 on success, 1 on failure.
kc_test_vip_seat_reserve() {
    full_port=$1
    open_port=$2
    over_port=$3
    full_backend=$4
    open_backend=$5
    over_backend_1=$6
    over_backend_2=$7

    RP2P_VIP='vip vip-pass' "$BIN" idx "$full_port" --max 1 --pow 0 > "$TMP_ROOT/vip-seat-full-idx.log" 2>&1 &
    IPID=$!
    if ! kc_test_wait_port "$full_port"; then
        kc_test_fail "VIP seat reserve: expected index on port $full_port, did not start"
        return 1
    fi
    kc_test_tcp_start "$full_backend" || return 1
    "$BIN" set test@127.0.0.1:"$full_port" --tcp "$full_backend" > "$TMP_ROOT/vip-seat-full-set.log" 2>&1 &
    spid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if ! kill -0 "$spid" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    if kill -0 "$spid" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_index_stop
        kc_test_fail "VIP seat reserve (max=1, vip seat taken): expected non-VIP registration rejected, stayed alive"
        return 1
    fi
    wait "$spid" 2>/dev/null || true
    kc_test_kill "$HPID"
    kc_test_index_stop
    kc_test_pass "VIP seat reserve: non-VIP rejected when max=1 with VIP seat"

    RP2P_VIP='vip vip-pass' "$BIN" idx "$open_port" --max 2 --pow 0 > "$TMP_ROOT/vip-seat-open-idx.log" 2>&1 &
    IPID=$!
    if ! kc_test_wait_port "$open_port"; then
        kc_test_fail "VIP seat reserve: expected index on port $open_port, did not start"
        return 1
    fi
    kc_test_set_tcp "$open_port" test "$open_backend" "" || return 1
    kc_test_index_stop
    kc_test_pass "VIP seat reserve: non-VIP accepted when max=2 with VIP seat"

    RP2P_VIP='vip1 pass1 vip2 pass2' "$BIN" idx "$over_port" --max 1 --pow 0 > "$TMP_ROOT/vip-seat-over-idx.log" 2>&1 &
    IPID=$!
    if ! kc_test_wait_port "$over_port"; then
        kc_test_fail "VIP seat reserve: expected index on port $over_port, did not start"
        return 1
    fi
    kc_test_set_tcp "$over_port" vip1 "$over_backend_1" pass1 || return 1
    kc_test_set_tcp "$over_port" vip2 "$over_backend_2" pass2 || return 1
    kc_test_index_stop
    kc_test_pass "VIP seat reserve: VIP count exceeds max allowed"

    return 0
}

# Stops the current index process gracefully.
# @return 0 on success.
kc_test_index_stop() {
    if [ -n "$IPID" ]; then
        kc_test_kill "$IPID"
        IPID=
    fi
    return 0
}

# Stops background processes started by the integration suite.
# @return 0 on success.
kc_test_cleanup() {
    pkill -9 -P $$ 2>/dev/null || true
    pkill -9 -f "bin/x86_64/linux/rp2p" 2>/dev/null || true
    pkill -9 -f "socat TCP-LISTEN:" 2>/dev/null || true
    pkill -9 -f "nc -u -l -p" 2>/dev/null || true
    rm -rf "$TMP_ROOT"
    return 0
}

# Wait for a TCP port to enter LISTEN state.
# Uses _wait_port for the variable to avoid shadowing callers' $port.
# @return 0 once ready, 1 after ~2s timeout.
kc_test_wait_port() {
    _wait_port=$1
    _wait_max=${2:-10}
    _wait_i=0
    while [ "$_wait_i" -lt "$_wait_max" ]; do
        if ss -ltnH "( sport = :$_wait_port )" 2>/dev/null | grep -q LISTEN; then
            return 0
        fi
        sleep 0.2
        _wait_i=$((_wait_i+1))
    done
    return 1
}

# Wait for a UDP port to be listening.
# UDP sockets show as UNCONN (not LISTEN) in ss output.
# @return 0 once ready, 1 after ~2s timeout.
kc_test_wait_udp() {
    _wudp_port=$1
    _wudp_max=${2:-10}
    _wudp_i=0
    while [ "$_wudp_i" -lt "$_wudp_max" ]; do
        if ss -ulnH "( sport = :$_wudp_port )" 2>/dev/null | grep -q UNCONN; then
            return 0
        fi
        sleep 0.2
        _wudp_i=$((_wudp_i+1))
    done
    return 1
}

# Graceful shutdown with SIGTERM, fallback to SIGKILL after ~1s.
# @return 0 on success.
kc_test_kill() {
    for _kpid in "$@"; do
        [ -z "$_kpid" ] && continue
        kill "$_kpid" 2>/dev/null || true
    done
    _ki=0
    while [ "$_ki" -lt 5 ]; do
        _alive=
        for _kpid in "$@"; do
            [ -z "$_kpid" ] && continue
            if kill -0 "$_kpid" 2>/dev/null; then _alive=1; break; fi
        done
        [ -z "$_alive" ] && { for _kpid in "$@"; do wait "$_kpid" 2>/dev/null || true; done; return 0; }
        sleep 0.2
        _ki=$((_ki+1))
    done
    for _kpid in "$@"; do
        [ -z "$_kpid" ] && continue
        kill -9 "$_kpid" 2>/dev/null || true
        wait "$_kpid" 2>/dev/null || true
    done
    return 0
}

# Verifies the index listens only on TCP.
# @return 0 on success, 1 on failure.
kc_test_index_tcp_only() {
    port=$1
    if ! ss -ltnH "( sport = :$port )" | grep -q LISTEN; then
        kc_test_fail "index TCP listener on port $port: expected LISTEN state, no TCP listener found"
        return 1
    fi
    if ss -lunH "( sport = :$port )" | grep -q .; then
        kc_test_fail "index UDP isolation on port $port: expected no UDP listener, found UDP listener bound"
        return 1
    fi
    kc_test_pass "index TCP-only on port $port"
    return 0
}

# Verifies HELLO, LIST, LOOKUP, DEREGISTER, and malformed rejection over TCP.
# @return 0 on success, 1 on failure.
kc_test_control_catalog() {
    port=$1
    backend_port=$2
    list_out="$TMP_ROOT/list.out"
    lookup_out="$TMP_ROOT/lookup.out"
    miss_out="$TMP_ROOT/miss.out"
    bad_lookup_out="$TMP_ROOT/bad-lookup.out"
    multi_out="$TMP_ROOT/multi.out"
    bad_punch_out="$TMP_ROOT/bad-punch.out"
    no_hello_out="$TMP_ROOT/no-hello.out"
    old_hello_out="$TMP_ROOT/old-hello.out"
    new_hello_out="$TMP_ROOT/new-hello.out"
    bad_hello_out="$TMP_ROOT/bad-hello.out"
    repeat_hello_out="$TMP_ROOT/repeat-hello.out"

    kc_test_tcp_start "$backend_port" || return 1
    "$BIN" set control@127.0.0.1:"$port" --tcp "$backend_port" > "$TMP_ROOT/control-set.log" 2>&1 &
    spid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if kill -0 "$spid" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    if ! kill -0 "$spid" 2>/dev/null; then
        kc_test_kill "$HPID"
        kc_test_fail "control register publisher: expected process to stay alive, exited early"
        return 1
    fi
    _i=0
    while [ "$_i" -lt 15 ]; do
        if grep -q "published" "$TMP_ROOT/control-set.log" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done

    if ! printf 'LOOKUP:control\n' | nc -w 2 127.0.0.1 "$port" > "$no_hello_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control HELLO required: expected ERROR:version mismatch, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:version mismatch$' "$no_hello_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control HELLO required: expected ERROR:version mismatch line, got $(tr '\n' '|' < "$no_hello_out" | head -c 80)"
        return 1
    fi
    kc_test_pass "control reject command without HELLO"

    if ! printf 'HELLO RP2P/0\n' | nc -w 2 127.0.0.1 "$port" > "$old_hello_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control old protocol HELLO: expected ERROR:version mismatch, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:version mismatch$' "$old_hello_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control old protocol HELLO (v0): expected ERROR:version mismatch, got $(tr '\n' '|' < "$old_hello_out" | head -c 60)"
        return 1
    fi
    kc_test_pass "control reject HELLO RP2P/0"

    if ! printf 'HELLO RP2P/2\n' | nc -w 2 127.0.0.1 "$port" > "$new_hello_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control new protocol HELLO: expected ERROR:version mismatch, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:version mismatch$' "$new_hello_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control new protocol HELLO (v2): expected ERROR:version mismatch, got $(tr '\n' '|' < "$new_hello_out" | head -c 60)"
        return 1
    fi
    kc_test_pass "control reject HELLO RP2P/2"

    if ! printf 'HELLO RP2P/x\n' | nc -w 2 127.0.0.1 "$port" > "$bad_hello_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control malformed HELLO version: expected ERROR:version mismatch, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:version mismatch$' "$bad_hello_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control malformed HELLO version (RP2P/x): expected ERROR:version mismatch, got $(tr '\n' '|' < "$bad_hello_out" | head -c 60)"
        return 1
    fi
    kc_test_pass "control reject HELLO RP2P/x"

    if ! printf 'HELLO RP2P/1\nHELLO RP2P/1\n' | nc -w 2 127.0.0.1 "$port" > "$repeat_hello_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control repeat HELLO: expected OK:HELLO then ERROR:version mismatch, nc failed"
        return 1
    fi
    if ! grep -q '^OK:HELLO$' "$repeat_hello_out" || ! grep -q '^ERROR:version mismatch$' "$repeat_hello_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control repeat HELLO: expected both OK:HELLO and ERROR:version mismatch, got $(tr '\n' '|' < "$repeat_hello_out" | head -c 80)"
        return 1
    fi
    kc_test_pass "control reject duplicate HELLO"

    if ! printf 'HELLO RP2P/1\nLIST\n' | nc -w 2 127.0.0.1 "$port" > "$list_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control LIST after register: expected PEER line, nc failed"
        return 1
    fi
    if ! grep -q '^PEER:control$' "$list_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control LIST after register: expected PEER:control, got $(tr '\n' '|' < "$list_out" | head -c 60)"
        return 1
    fi
    kc_test_pass "control LIST returns registered peer"

    if ! printf 'HELLO RP2P/1\nLOOKUP:control\n' | nc -w 2 127.0.0.1 "$port" > "$lookup_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control LOOKUP existing peer: expected PEER:control, nc failed"
        return 1
    fi
    if ! grep -q '^PEER:control$' "$lookup_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control LOOKUP existing peer: expected PEER:control, got $(tr '\n' '|' < "$lookup_out" | head -c 60)"
        return 1
    fi
    kc_test_pass "control LOOKUP returns registered peer"

    if ! printf 'HELLO RP2P/1\nLOOKUP:control:extra\n' | nc -w 2 127.0.0.1 "$port" > "$bad_lookup_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control LOOKUP with extra fields: expected ERROR:malformed, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:malformed$' "$bad_lookup_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control LOOKUP with extra fields: expected ERROR:malformed, got $(tr '\n' '|' < "$bad_lookup_out" | head -c 60)"
        return 1
    fi
    kc_test_pass "control reject malformed LOOKUP"

    if ! printf 'HELLO RP2P/1\nLIST\nLOOKUP:control\n' | nc -w 2 127.0.0.1 "$port" > "$multi_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control multi-command (LIST + LOOKUP): expected PEER lines, nc failed"
        return 1
    fi
    if ! grep -q '^PEER:control$' "$multi_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control multi-command: expected PEER:control in output, got $(tr '\n' '|' < "$multi_out" | head -c 80)"
        return 1
    fi
    kc_test_pass "control multi-command pipelining"

    if ! printf 'HELLO RP2P/1\nPUNCH_REQ2:c-1:control:abc\nCAND:bad:127.0.0.1:1\nEND\n' | nc -w 2 127.0.0.1 "$port" > "$bad_punch_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control PUNCH_REQ2 with bad candidate: expected ERROR:malformed, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:malformed$' "$bad_punch_out"; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control PUNCH_REQ2 with bad candidate type: expected ERROR:malformed, got $(tr '\n' '|' < "$bad_punch_out" | head -c 60)"
        return 1
    fi
    kc_test_pass "control reject punch with bad candidate type"

    if ! "$BIN" del control@127.0.0.1:"$port" > "$TMP_ROOT/control-del.log" 2>&1; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control DEREGISTER via CLI: expected exit 0, got non-zero"
        return 1
    fi
    kc_test_pass "control DEREGISTER via CLI"

    if ! printf 'HELLO RP2P/1\nLOOKUP:control\n' | nc -w 2 127.0.0.1 "$port" > "$miss_out" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_fail "control LOOKUP after deregister: expected NOT_FOUND, nc failed"
        return 1
    fi
    kc_test_kill "$spid" "$HPID"
    if ! grep -q '^NOT_FOUND$' "$miss_out"; then
        kc_test_fail "control LOOKUP after deregister: expected NOT_FOUND, got $(tr '\n' '|' < "$miss_out" | head -c 60)"
        return 1
    fi
    kc_test_pass "control LOOKUP confirms deregistration"
    return 0
}

# Verifies TCP control and direct tunnel operation over IPv6 loopback.
# @return 0 on success, 1 on failure.
kc_test_ipv6_loopback() {
    port=$1
    backend_port=$2
    listen_port=$3
    out="$TMP_ROOT/ipv6.out"
    list_out="$TMP_ROOT/ipv6-list.out"

    if [ ! -r /proc/net/if_inet6 ] ||
        ! grep -q '00000000000000000000000000000001' /proc/net/if_inet6
    then
        kc_test_pass "skip IPv6 (no loopback)"
        return 0
    fi
    kc_test_index_start "$port" 0 "" ipv6 || return 1
    if ! printf 'HELLO RP2P/1\nLIST\n' | socat -t 2 - "TCP6:[::1]:$port" > "$list_out" 2>/dev/null; then
        kc_test_index_stop
        kc_test_fail "IPv6 control over [::1]:$port: expected successful LIST via TCP6, socat failed"
        return 1
    fi
    if ! grep -q '^END$' "$list_out"; then
        kc_test_index_stop
        kc_test_fail "IPv6 control LIST over [::1]:$port: expected END line, got $(tr '\n' '|' < "$list_out" | head -c 60)"
        return 1
    fi
    kc_test_pass "IPv6 control protocol over loopback"
    kc_test_tcp_start "$backend_port" || return 1
    "$BIN" set "ipv6tcp@[::1]:$port" --tcp "$backend_port" > "$TMP_ROOT/ipv6-set.log" 2>&1 &
    spid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if kill -0 "$spid" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    if ! kill -0 "$spid" 2>/dev/null; then
        kc_test_kill "$HPID"
        kc_test_index_stop
        kc_test_fail "IPv6 publisher on [::1]:$port: expected process to stay alive, exited early"
        return 1
    fi
    _i=0
    while [ "$_i" -lt 15 ]; do
        if grep -q "published" "$TMP_ROOT/ipv6-set.log" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    "$BIN" con "ipv6tcp@[::1]:$port" --tcp "$listen_port" > "$TMP_ROOT/ipv6-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 15; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_index_stop
        kc_test_fail "IPv6 consumer on port $listen_port: expected consumer ready, port did not open"
        return 1
    fi
    if ! kc_test_tcp_roundtrip "$listen_port" "ip6" "$out"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_index_stop
        kc_test_fail "IPv6 TCP echo over [::1]:$port: expected echoed payload, got timeout"
        return 1
    fi
    if ! grep -q "ip6" "$out"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_index_stop
        kc_test_fail "IPv6 TCP echo payload: expected 'ip6' in output, got $(head -c 40 < "$out")"
        return 1
    fi
    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_index_stop
    kc_test_pass "IPv6 TCP echo roundtrip"
    return 0
}

# Starts a local TCP echo backend. Silent setup.
# @return 0 on success, 1 on failure.
kc_test_tcp_start() {
    tcp_port=$1
    socat TCP-LISTEN:"$tcp_port",reuseaddr,fork EXEC:cat 2>/dev/null &
    HPID=$!
    if ! kc_test_wait_port "$tcp_port"; then
        kc_test_fail "TCP echo backend on port $tcp_port: expected LISTEN state, socat failed to start"
        return 1
    fi
    return 0
}

# Waits for the publisher registration to appear in a log file.
# Polls for "published" up to ~3s.
# @return 0 once published, 1 on timeout.
kc_test_wait_published() {
    _wp_log=$1
    _wp_i=0
    while [ "$_wp_i" -lt 15 ]; do
        if grep -q "published" "$_wp_log" 2>/dev/null; then return 0; fi
        sleep 0.2
        _wp_i=$((_wp_i+1))
    done
    return 1
}

# Waits for a process to start and stay alive up to ~2s.
# @return 0 if alive, 1 if exited.
kc_test_wait_pid() {
    _wpid=$1
    _wp_i=0
    while [ "$_wp_i" -lt 10 ]; do
        if kill -0 "$_wpid" 2>/dev/null; then return 0; fi
        sleep 0.2
        _wp_i=$((_wp_i+1))
    done
    return 1
}

# Sends one TCP payload and waits for the echoed reply.
# @return 0 on success, 1 on failure.
kc_test_tcp_roundtrip() {
    dst_port=$1
    msg=$2
    out=$3
    _tri=0
    while [ "$_tri" -lt 20 ]; do
        if printf '%s' "$msg" | socat -t 5 - TCP:127.0.0.1:"$dst_port" > "$out" 2>/dev/null; then
            return 0
        fi
        _tri=$((_tri+1))
        sleep 1
    done
    return 1
}

# Starts a local UDP echo backend using netcat. Silent setup.
# @return 0 on success, 1 on failure.
kc_test_udp_start() {
    udp_port=$1
    while true; do
        nc -u -l -p "$udp_port" -c 'cat' 2>/dev/null
    done &
    UPID=$!
    if ! kc_test_wait_udp "$udp_port"; then
        kc_test_fail "UDP echo backend on port $udp_port: expected LISTEN state, nc failed to start"
        return 1
    fi
    return 0
}

# Sends one UDP datagram and waits for the echoed reply.
# @return 0 on success, 1 on failure.
kc_test_udp_roundtrip() {
    dst_port=$1
    msg=$2
    out=$3
    printf '%s' "$msg" | socat -t 1 - UDP:127.0.0.1:"$dst_port" > "$out" 2>/dev/null
}

# Starts a TCP publisher, waits for it to register, then cleans up.
# Silent -- validates the publisher lifecycle, no PASS/FAIL output.
# @return 0 on success, 1 on failure.
kc_test_set_tcp() {
    port=$1
    host=$2
    backend_port=$3
    pass_key=$4
    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/set-$host.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/set-$host.log" 2>&1 &
    fi
    _spid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if ! kill -0 "$_spid" 2>/dev/null; then
            kc_test_kill "$HPID"
            return 1
        fi
        sleep 0.2
        _i=$((_i+1))
    done
    kc_test_kill "$_spid" "$HPID"
    return 0
}

# Verifies one TCP payload crosses the tunnel.
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
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/tcp-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/tcp-set.log" 2>&1 &
    fi
    spid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if kill -0 "$spid" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    if ! kill -0 "$spid" 2>/dev/null; then
        kc_test_kill "$HPID"
        kc_test_fail "TCP echo $host: publisher process exited early"
        return 1
    fi
    _i=0
    while [ "$_i" -lt 15 ]; do
        if grep -q "published" "$TMP_ROOT/tcp-set.log" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/tcp-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP echo $host: expected consumer listening on port $listen_port, port did not open"
        return 1
    fi

    if ! kc_test_tcp_roundtrip "$listen_port" "ping" "$out"; then
        _conlog=$(head -c 80 < "$TMP_ROOT/tcp-con.log" 2>/dev/null)
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP echo $host: expected ping echoed, got timeout (con: $_conlog)"
        return 1
    fi
    if ! grep -q "ping" "$out"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP echo $host: expected 'ping' in response, got $(head -c 40 < "$out")"
        return 1
    fi

    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_pass "TCP echo $host: ping roundtrip OK"
    return 0
}

# Verifies two consecutive TCP requests reuse one running consumer.
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
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/reconnect-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/reconnect-set.log" 2>&1 &
    fi
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "TCP reconnect $host: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/reconnect-set.log" || { kc_test_kill "$HPID"; kc_test_fail "TCP reconnect $host: publisher registration timeout"; return 1; }
    "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/reconnect-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP reconnect $host: expected consumer on port $listen_port, port did not open"
        return 1
    fi

    if ! kc_test_tcp_roundtrip "$listen_port" "again1" "$out1"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP reconnect $host: first roundtrip expected echoed 'again1', got timeout"
        return 1
    fi
    if ! kc_test_tcp_roundtrip "$listen_port" "again2" "$out2"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP reconnect $host: second roundtrip expected echoed 'again2', got timeout"
        return 1
    fi
    if ! grep -q "again1" "$out1"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP reconnect $host: expected 'again1' in first response, got $(head -c 40 < "$out1")"
        return 1
    fi
    if ! grep -q "again2" "$out2"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP reconnect $host: expected 'again2' in second response, got $(head -c 40 < "$out2")"
        return 1
    fi

    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_pass "TCP reconnect $host: two sequential roundtrips OK"
    return 0
}

# Verifies a large TCP payload survives byte-for-byte.
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
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/large-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/large-set.log" 2>&1 &
    fi
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "TCP large $host: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/large-set.log" || { kc_test_kill "$HPID"; kc_test_fail "TCP large $host: publisher registration timeout"; return 1; }
    "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/large-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP large $host (10 MiB): expected consumer on port $listen_port, port did not open"
        return 1
    fi

    if ! socat -t 60 - TCP:127.0.0.1:"$listen_port" < "$in" > "$out" 2>/dev/null; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP large $host (10 MiB): expected successful transfer, socat failed"
        return 1
    fi
    if ! cmp -s "$in" "$out"; then
        _size=$(wc -c < "$out")
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP large $host (10 MiB): expected byte-identical 10 MiB output, got ${_size} bytes"
        return 1
    fi

    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_pass "TCP large $host: 10 MiB byte-identical transfer OK"
    return 0
}

# Verifies dropped TCP DATA frames are recovered by retransmission.
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
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-set.log" 2>&1 &
    fi
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "TCP loss $host: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/loss-set.log" || { kc_test_kill "$HPID"; kc_test_fail "TCP loss $host: publisher registration timeout"; return 1; }
    RP2P_DEBUG_STREAM_DROP_EVERY=1 "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/loss-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP loss $host: expected consumer on port $listen_port, port did not open"
        return 1
    fi

    if ! kc_test_tcp_roundtrip "$listen_port" "losscheck" "$out"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP loss $host: expected retransmission recovery, got timeout"
        return 1
    fi
    if ! grep -q "losscheck" "$out"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP loss $host: expected 'losscheck' echoed, got $(head -c 40 < "$out")"
        return 1
    fi

    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_pass "TCP loss $host: retransmission recovery OK"
    return 0
}

# Verifies dropped DATA frames are recovered in both directions.
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
        RP2P_PASS="$pass_key" RP2P_DEBUG_STREAM_DROP_EVERY=1 "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-bidir-set.log" 2>&1 &
    else
        RP2P_DEBUG_STREAM_DROP_EVERY=1 "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-bidir-set.log" 2>&1 &
    fi
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "TCP loss bidirectional $host: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/loss-bidir-set.log" || { kc_test_kill "$HPID"; kc_test_fail "TCP loss bidirectional $host: publisher registration timeout"; return 1; }
    RP2P_DEBUG_STREAM_DROP_EVERY=1 "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/loss-bidir-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP loss bidirectional $host: expected consumer on port $listen_port, port did not open"
        return 1
    fi

    if ! kc_test_tcp_roundtrip "$listen_port" "lossbidir" "$out"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP loss bidirectional $host: expected retransmission recovery both directions, got timeout"
        return 1
    fi
    if ! grep -q "lossbidir" "$out"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP loss bidirectional $host: expected 'lossbidir' echoed, got $(head -c 40 < "$out")"
        return 1
    fi

    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_pass "TCP loss bidirectional $host: retransmission both directions OK"
    return 0
}

# Verifies out-of-order TCP DATA frames are reconstructed correctly.
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
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/reorder-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/reorder-set.log" 2>&1 &
    fi
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "TCP reorder $host: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/reorder-set.log" || { kc_test_kill "$HPID"; kc_test_fail "TCP reorder $host: publisher registration timeout"; return 1; }
    RP2P_DEBUG_STREAM_REORDER_EVERY=1 "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/reorder-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP reorder $host: expected consumer on port $listen_port, port did not open"
        return 1
    fi

    if ! socat -t 20 - TCP:127.0.0.1:"$listen_port" < "$in" > "$out" 2>/dev/null; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP reorder $host (4 KiB): expected successful out-of-order transfer, socat failed"
        return 1
    fi
    if ! cmp -s "$in" "$out"; then
        _size=$(wc -c < "$out")
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP reorder $host (4 KiB): expected byte-identical output after reorder, got ${_size} bytes"
        return 1
    fi

    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_pass "TCP reorder $host: 4 KiB out-of-order reconstruction OK"
    return 0
}

# Verifies two concurrent TCP payloads cross the tunnel.
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
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/concurrent-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/concurrent-set.log" 2>&1 &
    fi
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "TCP concurrent $host: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/concurrent-set.log" || { kc_test_kill "$HPID"; kc_test_fail "TCP concurrent $host: publisher registration timeout"; return 1; }
    "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/concurrent-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP concurrent $host: expected consumer on port $listen_port, port did not open"
        return 1
    fi

    kc_test_tcp_roundtrip "$listen_port" "one1" "$out1" &
    q1=$!
    kc_test_tcp_roundtrip "$listen_port" "two2" "$out2" &
    q2=$!
    wait "$q1" "$q2" 2>/dev/null || {
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP concurrent $host: expected two concurrent roundtrips, one timed out"
        return 1
    }
    if ! grep -q "one1" "$out1"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP concurrent $host: expected 'one1' in first response, got $(head -c 40 < "$out1")"
        return 1
    fi
    if ! grep -q "two2" "$out2"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP concurrent $host: expected 'two2' in second response, got $(head -c 40 < "$out2")"
        return 1
    fi

    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_pass "TCP concurrent $host: two simultaneous roundtrips OK"
    return 0
}

# Starts a UDP publisher, waits for registration, then cleans up. Silent.
# @return 0 on success, 1 on failure.
kc_test_set_udp() {
    port=$1
    host=$2
    backend_port=$3
    pass_key=$4
    kc_test_udp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/set-udp-$host.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/set-udp-$host.log" 2>&1 &
    fi
    _spid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if ! kill -0 "$_spid" 2>/dev/null; then
            kc_test_kill "$UPID"
            return 1
        fi
        sleep 0.2
        _i=$((_i+1))
    done
    kc_test_kill "$_spid" "$UPID"
    return 0
}

# Verifies one UDP roundtrip crosses the tunnel.
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
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/udp-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/udp-set.log" 2>&1 &
    fi
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$UPID"; kc_test_fail "UDP echo $host: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/udp-set.log" || { kc_test_kill "$UPID"; kc_test_fail "UDP echo $host: publisher registration timeout"; return 1; }
    "$BIN" con "${host}@127.0.0.1:${port}" --udp "$listen_port" > "$TMP_ROOT/udp-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_udp "$listen_port" 15; then
        kc_test_kill "$spid" "$cpid" "$UPID"
        kc_test_fail "UDP echo $host: expected consumer on UDP port $listen_port, port did not open"
        return 1
    fi
    if ! kc_test_udp_roundtrip "$listen_port" "hello-udp" "$out"; then
        kc_test_kill "$spid" "$cpid" "$UPID"
        kc_test_fail "UDP echo $host: expected 'hello-udp' echoed, got timeout"
        return 1
    fi
    if ! grep -q "hello-udp" "$out"; then
        kc_test_kill "$spid" "$cpid" "$UPID"
        kc_test_fail "UDP echo $host: expected 'hello-udp' in response, got $(head -c 40 < "$out")"
        return 1
    fi
    kc_test_kill "$spid" "$cpid" "$UPID"
    kc_test_pass "UDP echo $host: roundtrip OK"
    return 0
}

# Verifies protected registration succeeds and failures are rejected.
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
    RP2P_PASS=wrong "$BIN" set authbad@127.0.0.1:"$auth_port_bad" --tcp "$auth_backend_bad" > "$TMP_ROOT/auth-bad.log" 2>&1 &
    spid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if ! kill -0 "$spid" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    if kill -0 "$spid" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_index_stop
        kc_test_fail "auth register with wrong password: expected process to exit, stayed alive"
        return 1
    fi
    wait "$spid" 2>/dev/null || true
    kc_test_kill "$HPID"
    kc_test_pass "auth register with wrong password: rejected"
    kc_test_index_stop
    kc_test_index_start "$auth_port_missing" 0 abc auth-missing-pass || return 1
    kc_test_tcp_start "$auth_backend_missing" || return 1
    "$BIN" set authmissing@127.0.0.1:"$auth_port_missing" --tcp "$auth_backend_missing" > "$TMP_ROOT/auth-missing.log" 2>&1 &
    spid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if ! kill -0 "$spid" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    if kill -0 "$spid" 2>/dev/null; then
        kc_test_kill "$spid" "$HPID"
        kc_test_index_stop
        kc_test_fail "auth register without password: expected process to exit, stayed alive"
        return 1
    fi
    wait "$spid" 2>/dev/null || true
    kc_test_kill "$HPID"
    kc_test_pass "auth register without password: rejected"
    kc_test_index_stop
    kc_test_index_start "$auth_port_pow" 20 abc auth-pow || return 1
    kc_test_set_tcp "$auth_port_pow" authpow "$auth_backend_ok" abc || return 1
    kc_test_index_stop
    kc_test_pass "auth register with 20-bit PoW: accepted"
    kc_test_index_start "$auth_port_public" 0 abc auth-public-con || return 1
    kc_test_tcp_echo "$auth_port_public" authpub "$auth_backend_public" "$auth_listen_public" abc || { kc_test_index_stop; return 1; }
    kc_test_index_stop
    kc_test_pass "auth register: all auth scenarios OK"
    return 0
}

# Verifies a large UDP datagram (1400 bytes, near MTU) crosses the tunnel.
# @return 0 on success, 1 on failure.
kc_test_udp_large() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    in="$TMP_ROOT/udp-large.in"
    out="$TMP_ROOT/udp-large.out"
    msg=$(openssl rand -base64 1050 2>/dev/null | tr -d '\n' | head -c 1400)
    printf '%s' "$msg" > "$in"

    kc_test_udp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        RP2P_PASS="$pass_key" "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/udp-large-set.log" 2>&1 &
    else
        "$BIN" set "${host}@127.0.0.1:${port}" --udp "$backend_port" > "$TMP_ROOT/udp-large-set.log" 2>&1 &
    fi
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$UPID"; kc_test_fail "UDP large $host: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/udp-large-set.log" || { kc_test_kill "$UPID"; kc_test_fail "UDP large $host: publisher registration timeout"; return 1; }
    "$BIN" con "${host}@127.0.0.1:${port}" --udp "$listen_port" > "$TMP_ROOT/udp-large-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_udp "$listen_port" 15; then
        kc_test_kill "$spid" "$cpid" "$UPID"
        kc_test_fail "UDP large $host (1400 B): expected consumer on UDP port $listen_port, port did not open"
        return 1
    fi
    if ! socat -t 2 - UDP:127.0.0.1:"$listen_port" < "$in" > "$out" 2>/dev/null; then
        kc_test_kill "$spid" "$cpid" "$UPID"
        kc_test_fail "UDP large $host (1400 B): expected datagram echo, socat failed"
        return 1
    fi
    if ! cmp -s "$in" "$out"; then
        _size=$(wc -c < "$out")
        kc_test_kill "$spid" "$cpid" "$UPID"
        kc_test_fail "UDP large $host (1400 B): expected byte-identical echo, got ${_size} bytes"
        return 1
    fi
    kc_test_kill "$spid" "$cpid" "$UPID"
    kc_test_pass "UDP large $host: 1400 B datagram echo OK"
    return 0
}

# Verifies moderate DATA frame loss with 1 MiB transfer.
# @return 0 on success, 1 on failure.
kc_test_tcp_loss_moderate() {
    port=$1
    host=$2
    backend_port=$3
    listen_port=$4
    pass_key=$5
    in="$TMP_ROOT/loss-moderate-$host.in"
    out="$TMP_ROOT/loss-moderate-$host.out"

    dd if=/dev/urandom of="$in" bs=131072 count=1 status=none || return 1
    kc_test_tcp_start "$backend_port" || return 1
    if [ -n "$pass_key" ]; then
        RP2P_PASS="$pass_key" RP2P_DEBUG_STREAM_DROP_EVERY=20 "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-moderate-set.log" 2>&1 &
    else
        RP2P_DEBUG_STREAM_DROP_EVERY=20 "$BIN" set "${host}@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/loss-moderate-set.log" 2>&1 &
    fi
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "TCP loss moderate $host: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/loss-moderate-set.log" || { kc_test_kill "$HPID"; kc_test_fail "TCP loss moderate $host: publisher registration timeout"; return 1; }
    "$BIN" con "${host}@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/loss-moderate-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP loss moderate $host (128 KiB): expected consumer on port $listen_port, port did not open"
        return 1
    fi

    if ! socat -t 180 - TCP:127.0.0.1:"$listen_port" < "$in" > "$out" 2>/dev/null; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP loss moderate $host (128 KiB): expected successful transfer under 1/20 drop rate, socat failed"
        return 1
    fi
    if ! cmp -s "$in" "$out"; then
        _size=$(wc -c < "$out")
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "TCP loss moderate $host (128 KiB): expected byte-identical output under 1/20 drop, got ${_size} bytes"
        return 1
    fi

    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_pass "TCP loss moderate $host: 128 KiB byte-identical under 1/20 drop OK"
    return 0
}

# Tests adversarial protocol messages against the index.
# @return 0 on success, 1 on failure.
kc_test_protocol_vectors() {
    port=$1
    out="$TMP_ROOT/proto-unknown.out"
    if ! printf 'HELLO RP2P/1\nBOGUS\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol unknown command BOGUS: expected ERROR:unknown command, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:unknown command$' "$out"; then
        kc_test_fail "protocol unknown command BOGUS: expected ERROR:unknown command, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject unknown command"
    out="$TMP_ROOT/proto-reg-bad-id.out"
    if ! printf 'HELLO RP2P/1\nREGISTER:bad id\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol REGISTER with spaces in id: expected ERROR:invalid id, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:invalid id$' "$out"; then
        kc_test_fail "protocol REGISTER with spaces: expected ERROR:invalid id, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject REGISTER with space in id"
    out="$TMP_ROOT/proto-reg-colon-id.out"
    if ! printf 'HELLO RP2P/1\nREGISTER:bad:id\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol REGISTER with colon in id: expected ERROR:invalid id, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:invalid id$' "$out"; then
        kc_test_fail "protocol REGISTER with colon: expected ERROR:invalid id, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject REGISTER with colon in id"
    out="$TMP_ROOT/proto-reg-empty.out"
    if ! printf 'HELLO RP2P/1\nREGISTER:\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol REGISTER with empty id: expected ERROR:invalid id, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:invalid id$' "$out"; then
        kc_test_fail "protocol REGISTER empty id: expected ERROR:invalid id, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject REGISTER with empty id"
    out="$TMP_ROOT/proto-reg-valid.out"
    if ! printf 'HELLO RP2P/1\nREGISTER:validproto\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol REGISTER valid id: expected CHALLENGE response, nc failed"
        return 1
    fi
    if grep -q '^ERROR:' "$out"; then
        _err=$(grep '^ERROR:' "$out" | head -1)
        kc_test_fail "protocol REGISTER valid id: expected no ERROR, got $_err"
        return 1
    fi
    if ! grep -q '^CHALLENGE:' "$out"; then
        kc_test_fail "protocol REGISTER valid id: expected CHALLENGE line, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol REGISTER valid id returns CHALLENGE"
    out="$TMP_ROOT/proto-reg-bad-sol.out"
    if ! printf 'HELLO RP2P/1\nREGISTER:badproof:SOLUTION:xx:PROOF:yy\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol REGISTER with bad proof: expected AUTH_FAILED, nc failed"
        return 1
    fi
    if ! grep -q '^AUTH_FAILED$' "$out"; then
        kc_test_fail "protocol REGISTER bad proof: expected AUTH_FAILED, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol REGISTER bad proof returns AUTH_FAILED"
    out="$TMP_ROOT/proto-list-extra.out"
    if ! printf 'HELLO RP2P/1\nLIST:extra\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol LIST with extra fields: expected ERROR:malformed, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:malformed$' "$out"; then
        kc_test_fail "protocol LIST with extra: expected ERROR:malformed, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject LIST with extra fields"
    out="$TMP_ROOT/proto-dereg-no-key.out"
    if ! printf 'HELLO RP2P/1\nDEREGISTER:test\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol DEREGISTER without key: expected ERROR:malformed, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:malformed$' "$out"; then
        kc_test_fail "protocol DEREGISTER no key: expected ERROR:malformed, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject DEREGISTER without key"
    out="$TMP_ROOT/proto-dereg-bad-key.out"
    if ! printf 'HELLO RP2P/1\nDEREGISTER:nonexistent:KEY:abc\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol DEREGISTER nonexistent with bad key: expected ERROR:invalid key, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:invalid key$' "$out"; then
        kc_test_fail "protocol DEREGISTER bad key: expected ERROR:invalid key, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject DEREGISTER with nonexistent key"
    out="$TMP_ROOT/proto-punch-bad-self.out"
    if ! printf 'HELLO RP2P/1\nPUNCH_REQ2:bad@self:target:sess\nEND\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol PUNCH_REQ2 with @ in self id: expected ERROR:malformed, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:malformed$' "$out"; then
        kc_test_fail "protocol PUNCH_REQ2 bad self: expected ERROR:malformed, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject PUNCH_REQ2 with @ in self id"
    out="$TMP_ROOT/proto-punch-extra.out"
    if ! printf 'HELLO RP2P/1\nPUNCH_REQ2:c-1:target:sess:extra\nEND\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol PUNCH_REQ2 with extra fields: expected ERROR:malformed, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:malformed$' "$out"; then
        kc_test_fail "protocol PUNCH_REQ2 extra fields: expected ERROR:malformed, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject PUNCH_REQ2 with extra fields"
    out="$TMP_ROOT/proto-punch-ipv6-cand.out"
    if ! printf 'HELLO RP2P/1\nPUNCH_REQ2:c-1:nosuch:sess\nCAND:HOST:[::1]:1234\nEND\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol PUNCH_REQ2 to missing peer: expected no ERROR for valid IPv6 candidate, nc failed"
        return 1
    fi
    if grep -q '^ERROR:malformed$' "$out"; then
        kc_test_fail "protocol PUNCH_REQ2 IPv6 candidate: expected no ERROR:malformed, but got it"
        return 1
    fi
    kc_test_pass "protocol accept IPv6 candidate in PUNCH_REQ2"
    out="$TMP_ROOT/proto-ack-bad.out"
    if ! printf 'HELLO RP2P/1\nPUNCH_ACK2:validtarget:bad@ack:sess\nEND\n' | nc -w 2 127.0.0.1 "$port" > "$out" 2>/dev/null; then
        kc_test_fail "protocol PUNCH_ACK2 with @ in ack id: expected ERROR:malformed, nc failed"
        return 1
    fi
    if ! grep -q '^ERROR:malformed$' "$out"; then
        kc_test_fail "protocol PUNCH_ACK2 bad id: expected ERROR:malformed, got $(tr '\n' '|' < "$out" | head -c 60)"
        return 1
    fi
    kc_test_pass "protocol reject PUNCH_ACK2 with @ in id"
    kc_test_pass "protocol: all adversarial vectors handled correctly"
    return 0
}

# Verifies the tunnel survives index disappearance.
# @return 0 on success, 1 on failure.
kc_test_index_disappearance() {
    port=$1
    backend_port=$2
    listen_port=$3
    out1="$TMP_ROOT/disappear-idx1.out"
    out2="$TMP_ROOT/disappear-idx2.out"
    kc_test_tcp_start "$backend_port" || return 1
    "$BIN" set "idxdis@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/disappear-set.log" 2>&1 &
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "index disappearance: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/disappear-set.log" || { kc_test_kill "$HPID"; kc_test_fail "index disappearance: publisher registration timeout"; return 1; }
    "$BIN" con "idxdis@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/disappear-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "index disappearance: expected consumer on port $listen_port, port did not open"
        return 1
    fi
    if ! kc_test_tcp_roundtrip "$listen_port" "predis" "$out1"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "index disappearance: expected echo before index kill, got timeout"
        return 1
    fi
    if ! grep -q "predis" "$out1"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "index disappearance: expected 'predis' before index kill, got $(head -c 40 < "$out1")"
        return 1
    fi
    kc_test_pass "index disappearance: tunnel working before index kill"
    kc_test_index_stop
    if ! kc_test_tcp_roundtrip "$listen_port" "postdis" "$out2"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "index disappearance: expected echo after index kill (direct path), got timeout"
        return 1
    fi
    if ! grep -q "postdis" "$out2"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "index disappearance: expected 'postdis' after index kill, got $(head -c 40 < "$out2")"
        return 1
    fi
    kc_test_kill "$spid" "$cpid" "$HPID"
    kc_test_pass "index disappearance: tunnel survives index kill"
    return 0
}

# Verifies one peer can disappear without crashing the other.
# @return 0 on success, 1 on failure.
kc_test_peer_disappearance() {
    port=$1
    backend_port=$2
    listen_port=$3
    out1="$TMP_ROOT/disappear-peer.out"
    kc_test_tcp_start "$backend_port" || return 1
    "$BIN" set "peerd@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/disappear-peer-set.log" 2>&1 &
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "peer disappearance: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/disappear-peer-set.log" || { kc_test_kill "$HPID"; kc_test_fail "peer disappearance: publisher registration timeout"; return 1; }
    "$BIN" con "peerd@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/disappear-peer-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "peer disappearance: expected consumer on port $listen_port, port did not open"
        return 1
    fi
    if ! kc_test_tcp_roundtrip "$listen_port" "peertest" "$out1"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "peer disappearance: expected echo before consumer kill, got timeout"
        return 1
    fi
    if ! grep -q "peertest" "$out1"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "peer disappearance: expected 'peertest' echoed, got $(head -c 40 < "$out1")"
        return 1
    fi
    kc_test_pass "peer disappearance: tunnel working before consumer kill"
    kc_test_kill "$cpid"
    sleep 1
    if ! kill -0 "$spid" 2>/dev/null; then
        kc_test_kill "$HPID"
        kc_test_fail "peer disappearance: expected publisher alive after consumer kill, publisher exited"
        return 1
    fi
    kc_test_kill "$spid" "$HPID"
    kc_test_pass "peer disappearance: publisher survives consumer kill"

    kc_test_tcp_start "$backend_port" || return 1
        "$BIN" set "peerd2@127.0.0.1:${port}" --tcp "$backend_port" > "$TMP_ROOT/disappear-pub-set.log" 2>&1 &
    spid=$!
    kc_test_wait_pid "$spid" || { kc_test_kill "$HPID"; kc_test_fail "peer disappearance: publisher failed to start"; return 1; }
    kc_test_wait_published "$TMP_ROOT/disappear-pub-set.log" || { kc_test_kill "$HPID"; kc_test_fail "peer disappearance: publisher registration timeout"; return 1; }
    "$BIN" con "peerd2@127.0.0.1:${port}" --tcp "$listen_port" > "$TMP_ROOT/disappear-pub-con.log" 2>&1 &
    cpid=$!
    if ! kc_test_wait_port "$listen_port" 20; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "peer disappearance (pub): expected consumer on port $listen_port, port did not open"
        return 1
    fi

    out2="$TMP_ROOT/disappear-pub2.out"
    if ! kc_test_tcp_roundtrip "$listen_port" "pubtest" "$out2"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "peer disappearance (pub): expected echo before publisher kill, got timeout"
        return 1
    fi
    if ! grep -q "pubtest" "$out2"; then
        kc_test_kill "$spid" "$cpid" "$HPID"
        kc_test_fail "peer disappearance (pub): expected 'pubtest' echoed, got $(head -c 40 < "$out2")"
        return 1
    fi
    kc_test_pass "peer disappearance: tunnel working before publisher kill"
    kc_test_kill "$spid"
    sleep 1
    if ! kill -0 "$cpid" 2>/dev/null; then
        kc_test_kill "$HPID"
        kc_test_fail "peer disappearance: expected consumer alive after publisher kill, consumer exited"
        return 1
    fi
    kc_test_kill "$cpid" "$HPID"
    kc_test_pass "peer disappearance: consumer survives publisher kill"
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
    listen_udp_2=$((PORT_BASE + 124))
    backend_udp_3=$((PORT_BASE + 41))
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
    vip_seat_port_1=$((PORT_BASE + 30))
    vip_seat_port_2=$((PORT_BASE + 31))
    vip_seat_port_3=$((PORT_BASE + 32))
    auth_backend_1=$((PORT_BASE + 13))
    auth_backend_2=$((PORT_BASE + 14))
    auth_backend_3=$((PORT_BASE + 15))
    auth_backend_4=$((PORT_BASE + 16))
    vip_backend_1=$((PORT_BASE + 25))
    vip_backend_2=$((PORT_BASE + 26))
    vip_backend_3=$((PORT_BASE + 27))
    vip_seat_backend_1=$((PORT_BASE + 33))
    vip_seat_backend_2=$((PORT_BASE + 34))
    vip_seat_backend_3=$((PORT_BASE + 35))
    vip_seat_backend_4=$((PORT_BASE + 36))
    control_backend=$((PORT_BASE + 29))
    auth_listen_1=$((PORT_BASE + 112))
    ipv6_port=$((PORT_BASE + 37))
    ipv6_backend=$((PORT_BASE + 38))
    ipv6_listen=$((PORT_BASE + 121))
    backend_tcp_8=$((PORT_BASE + 39))
    backend_tcp_9=$((PORT_BASE + 40))
    listen_tcp_7=$((PORT_BASE + 122))
    listen_tcp_8=$((PORT_BASE + 123))
    backend_disappear=$((PORT_BASE + 42))
    backend_disappear2=$((PORT_BASE + 43))
    listen_disappear=$((PORT_BASE + 125))
    listen_disappear2=$((PORT_BASE + 126))

    if ! kc_test_ensure_binary; then
        printf 'prerequisites missing, cannot run suite\n' >&2
        return 1
    fi
    kc_test_index_start "$index_port" 0 "" public-default || return 1
    kc_test_index_tcp_only "$index_port" || return 1
    kc_test_control_catalog "$index_port" "$control_backend" || return 1
    kc_test_ipv6_loopback "$ipv6_port" "$ipv6_backend" "$ipv6_listen" || return 1
    kc_test_set_tcp "$index_port" host1 "$backend_tcp_1" "" || return 1
    kc_test_tcp_echo "$index_port" web "$backend_tcp_2" "$listen_tcp_1" "" || return 1
    kc_test_tcp_concurrent "$index_port" web2 "$backend_tcp_3" "$listen_tcp_2" "" || return 1
    kc_test_tcp_reconnect "$index_port" web3 "$auth_backend_1" "$auth_listen_1" "" || return 1
    kc_test_tcp_loss "$index_port" web4 "$backend_tcp_4" "$listen_tcp_3" "" || return 1
    kc_test_tcp_large "$index_port" web5 "$backend_tcp_5" "$listen_tcp_4" "" || return 1
    kc_test_tcp_loss_bidir "$index_port" web6 "$backend_tcp_6" "$listen_tcp_5" "" || return 1
    kc_test_tcp_reorder "$index_port" web7 "$backend_tcp_7" "$listen_tcp_6" "" || return 1
    kc_test_tcp_loss_moderate "$index_port" web8 "$backend_tcp_8" "$listen_tcp_7" "" || return 1
    kc_test_tcp_loss_moderate "$index_port" web9 "$backend_tcp_9" "$listen_tcp_8" "" || return 1
    kc_test_protocol_vectors "$index_port" || return 1
    kc_test_peer_disappearance "$index_port" "$backend_disappear" "$listen_disappear" || return 1
    kc_test_set_udp "$index_port" game0 "$backend_udp_1" "" || return 1
    kc_test_udp_echo "$index_port" game1 "$backend_udp_2" "$listen_udp_1" "" || return 1
    kc_test_udp_large "$index_port" game2 "$backend_udp_3" "$listen_udp_2" "" || return 1
    kc_test_index_disappearance "$index_port" "$backend_disappear2" "$listen_disappear2" || return 1
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
    kc_test_vip_seat_reserve "$vip_seat_port_1" "$vip_seat_port_2" \
        "$vip_seat_port_3" "$vip_seat_backend_1" "$vip_seat_backend_2" \
        "$vip_seat_backend_3" "$vip_seat_backend_4" || return 1
    kc_test_index_start "$((PORT_BASE + 44))" 0 "" failure-index || return 1
    _conn_out="$TMP_ROOT/fail-connect-nonexistent.out"
    if "$BIN" con "nobody@127.0.0.1:$((PORT_BASE + 44))" --tcp "$((PORT_BASE + 45))" > "$_conn_out" 2>&1; then
        kc_test_fail "failure connect to nonexistent peer: expected non-zero exit, got 0"
        kc_test_index_stop
        kc_test_cleanup
        return 1
    fi
    kc_test_pass "failure connect to nonexistent peer: rejected"
    kc_test_index_stop

    _full_port=$((PORT_BASE + 46))
    "$BIN" idx "$_full_port" --max 1 --pow 0 > "$TMP_ROOT/fail-full-idx.log" 2>&1 &
    _full_ipid=$!
    if ! kc_test_wait_port "$_full_port"; then
        kc_test_fail "failure full index: expected index on port $_full_port, did not start"
        kc_test_kill "$_full_ipid"
        kc_test_cleanup
        return 1
    fi
    kc_test_tcp_start "$((PORT_BASE + 47))" || return 1
    "$BIN" set "first@127.0.0.1:$_full_port" --tcp "$((PORT_BASE + 47))" > "$TMP_ROOT/fail-full-first.log" 2>&1 &
    _first_pid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if ! kill -0 "$_first_pid" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    kc_test_tcp_start "$((PORT_BASE + 48))" || return 1
    "$BIN" set "second@127.0.0.1:$_full_port" --tcp "$((PORT_BASE + 48))" > "$TMP_ROOT/fail-full-second.log" 2>&1 &
    _second_pid=$!
    _i=0
    while [ "$_i" -lt 10 ]; do
        if ! kill -0 "$_second_pid" 2>/dev/null; then break; fi
        sleep 0.2
        _i=$((_i+1))
    done
    if kill -0 "$_second_pid" 2>/dev/null; then
        kc_test_kill "$_first_pid" "$_second_pid" "$HPID"
        kc_test_kill "$_full_ipid"
        kc_test_cleanup
        kc_test_fail "failure full index (max=1): expected second registration rejected, was accepted"
        return 1
    fi
    wait "$_second_pid" 2>/dev/null || true
    kc_test_kill "$_first_pid" "$HPID"
    kc_test_kill "$_full_ipid"
    kc_test_pass "failure full index (max=1): second registration rejected"

    kc_test_cleanup
    return 0
}

trap 'status=$?; kc_test_cleanup; exit "${status:-0}"' EXIT INT HUP TERM

if kc_test_main; then
    exit 0
fi
exit 1
