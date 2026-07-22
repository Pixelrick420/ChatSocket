#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT_DIR/bootstrap.sh"

ensure_build_prereqs

read -r -a OPENSSL_FLAGS <<<"$(pkg-config --cflags --libs openssl)"

BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chatsocket-build.XXXXXX")"
RUNTIME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chatsocket-runtime.XXXXXX")"
PORT="${PORT:-24877}"

cleanup() {
  local status=$?

  if [ -n "${CLIENT_A_PID:-}" ]; then
    kill "$CLIENT_A_PID" 2>/dev/null || true
  fi
  if [ -n "${CLIENT_B_PID:-}" ]; then
    kill "$CLIENT_B_PID" 2>/dev/null || true
  fi
  if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi

  exec 3>&- 2>/dev/null || true
  exec 4>&- 2>/dev/null || true

  if [ "$status" -eq 0 ]; then
    rm -rf "$BUILD_DIR" "$RUNTIME_DIR"
  else
    echo "Smoke test artifacts preserved in $RUNTIME_DIR" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

compile_target() {
  local output=$1
  shift
  "$BUILD_CC" "$@" "${OPENSSL_FLAGS[@]}" -lpthread -Wall -Wextra -O2 -o "$output"
}

wait_for_match() {
  local file=$1
  local pattern=$2
  local label=$3

  for _ in $(seq 1 80); do
    if grep -Eq "$pattern" "$file"; then
      return 0
    fi
    sleep 0.25
  done

  echo "Timed out waiting for $label" >&2
  echo "--- $file ---" >&2
  tail -n 80 "$file" >&2 || true
  return 1
}

wait_for_count() {
  local file=$1
  local pattern=$2
  local expected=$3
  local label=$4

  for _ in $(seq 1 80); do
    if [ "$(grep -Ec "$pattern" "$file" || true)" -ge "$expected" ]; then
      return 0
    fi
    sleep 0.25
  done

  echo "Timed out waiting for $label" >&2
  tail -n 80 "$file" >&2 || true
  return 1
}

ensure_process_alive() {
  local pid=$1
  local label=$2
  local log_file=$3

  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    return 0
  fi

  echo "$label exited unexpectedly" >&2
  echo "--- $log_file ---" >&2
  tail -n 80 "$log_file" >&2 || true
  return 1
}

compile_target "$BUILD_DIR/server" \
  "$ROOT_DIR/Server/server.c" \
  "$ROOT_DIR/Utils/socketUtil.c" \
  "$ROOT_DIR/Utils/sha256.c" \
  "$ROOT_DIR/Utils/identity.c" \
  "$ROOT_DIR/Utils/tls.c" \
  "$ROOT_DIR/Utils/platform.c" \
  "$ROOT_DIR/Utils/protocol.c" \
  "$ROOT_DIR/Utils/aes.c"

compile_target "$BUILD_DIR/client" \
  "$ROOT_DIR/Client/client.c" \
  "$ROOT_DIR/Utils/socketUtil.c" \
  "$ROOT_DIR/Utils/sha256.c" \
  "$ROOT_DIR/Utils/aes.c" \
  "$ROOT_DIR/Utils/contacts.c" \
  "$ROOT_DIR/Utils/identity.c" \
  "$ROOT_DIR/Utils/ecdh.c" \
  "$ROOT_DIR/Utils/history.c" \
  "$ROOT_DIR/Utils/tls.c" \
  "$ROOT_DIR/Utils/platform.c" \
  "$ROOT_DIR/Utils/protocol.c"

mkdir -p "$RUNTIME_DIR/home_server" "$RUNTIME_DIR/home_a" "$RUNTIME_DIR/home_b"
mkfifo "$RUNTIME_DIR/a.in" "$RUNTIME_DIR/b.in"

HOME="$RUNTIME_DIR/home_server" PORT="$PORT" "$BUILD_DIR/server" \
  >"$RUNTIME_DIR/server.out" 2>&1 &
SERVER_PID=$!
ensure_process_alive "$SERVER_PID" "server" "$RUNTIME_DIR/server.out"

exec 3<>"$RUNTIME_DIR/a.in"
exec 4<>"$RUNTIME_DIR/b.in"

HOME="$RUNTIME_DIR/home_a" "$BUILD_DIR/client" "127.0.0.1:$PORT" \
  <"$RUNTIME_DIR/a.in" >"$RUNTIME_DIR/a.out" 2>&1 &
CLIENT_A_PID=$!

HOME="$RUNTIME_DIR/home_b" "$BUILD_DIR/client" "127.0.0.1:$PORT" \
  <"$RUNTIME_DIR/b.in" >"$RUNTIME_DIR/b.out" 2>&1 &
CLIENT_B_PID=$!

wait_for_match "$RUNTIME_DIR/a.out" "Connected to .*:$PORT" "client A connection"
wait_for_match "$RUNTIME_DIR/b.out" "Connected to .*:$PORT" "client B connection"

printf '/name Alice\n' >&3
printf '/name Bob\n' >&4
sleep 0.5

printf '/create lounge\n' >&3
sleep 0.3
printf '/rooms\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "lounge" "room list output"
printf '/enter lounge\n' >&3
printf '/enter lounge\n' >&4
wait_for_match "$RUNTIME_DIR/a.out" "Entered room" "client A room entry"
wait_for_match "$RUNTIME_DIR/b.out" "Entered room" "client B room entry"

printf '/name Alice\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Name is already in use" "duplicate name rejection"
printf 'still Bob\n' >&4
wait_for_match "$RUNTIME_DIR/a.out" "Bob: still Bob" "name rejection preserves identity"

printf 'hello room from Alice\n' >&3
wait_for_match "$RUNTIME_DIR/b.out" "Alice: hello room from Alice" "room message delivery"

printf '/topic Secure lounge\n' >&3
wait_for_match "$RUNTIME_DIR/b.out" "Alice set topic: Secure lounge" "room topic update"
printf '/topic Unauthorized update\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Only room owner may change topic" "room topic authorization"
printf '/topic\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Topic: Secure lounge" "room topic lookup"
printf '/members\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Members in #lounge" "room member list"
wait_for_match "$RUNTIME_DIR/b.out" "Alice.*\[owner\]" "room owner marker"

printf '/create vault -p\n' >&3
wait_for_match "$RUNTIME_DIR/a.out" "New room secret:" "protected room creation prompt"
printf 'correct-horse\n' >&3
wait_for_match "$RUNTIME_DIR/a.out" "Room created" "protected room creation"
printf '/enter vault\n' >&3
wait_for_match "$RUNTIME_DIR/a.out" "Room secret:" "client A protected room prompt"
printf 'correct-horse\n' >&3
wait_for_count "$RUNTIME_DIR/a.out" "Entered room" 2 "client A protected room entry"
printf '/members\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Bob.*\[owner\]" "room ownership transfer"

printf '/enter vault\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Room secret:" "client B protected room prompt"
printf 'wrong-secret\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Incorrect room secret" "protected room rejection"
printf '/enter vault\n' >&4
wait_for_count "$RUNTIME_DIR/b.out" "Room secret:" 2 "client B protected room retry"
printf 'correct-horse\n' >&4
wait_for_count "$RUNTIME_DIR/b.out" "Entered room" 2 "client B protected room entry"
printf '/members\n' >&3
wait_for_match "$RUNTIME_DIR/a.out" "Members in #vault" "protected room membership sync"

printf 'encrypted hello from Alice\n' >&3
wait_for_match "$RUNTIME_DIR/b.out" "Alice: encrypted hello from Alice" "protected room message"

printf '/create\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Usage: /create" "bare create usage"
printf '/create short-inline -p password\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "at least 12 characters" "short inline secret rejection"
printf '/create inline-vault -p password1234\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Room created" "inline protected room creation"
printf '/enter inline-vault\n' >&3
wait_for_match "$RUNTIME_DIR/a.out" "Room secret:" "inline protected room prompt"
printf 'password1234\n' >&3
wait_for_count "$RUNTIME_DIR/a.out" "Entered room" 3 "inline protected room entry"

printf '/token\n' >&4
wait_for_match "$RUNTIME_DIR/b.out" "Your token: [0-9a-f]{64}" "client B token"
B_TOKEN="$(grep -Eo 'Your token: [0-9a-f]{64}' "$RUNTIME_DIR/b.out" | tail -n1 | awk '{print $3}')"
if [ -z "$B_TOKEN" ]; then
  echo "Failed to capture client B token" >&2
  exit 1
fi

printf '/dm %s\n' "$B_TOKEN" >&3
wait_for_match "$RUNTIME_DIR/a.out" "DM session ready with" "client A DM handshake"
wait_for_match "$RUNTIME_DIR/b.out" "DM session established with" "client B DM handshake"

printf '/dm %s\n' "$B_TOKEN" >&3
wait_for_match "$RUNTIME_DIR/a.out" "Close current DM with /dmleave first" "active DM replacement rejection"

printf '/nick Work Friend\n' >&3
sleep 0.4
printf 'hello dm from Alice\n' >&3
wait_for_match "$RUNTIME_DIR/a.out" "Nickname saved" "nickname confirmation"
wait_for_match "$RUNTIME_DIR/a.out" "DM:Work Friend" "nickname-visible DM prompt"

printf 'hello back from Bob\n' >&4
wait_for_match "$RUNTIME_DIR/a.out" "Work Friend: hello back from Bob" "nickname-visible incoming DM"

printf '/list\n' >&3
printf '/search work\n' >&3
wait_for_match "$RUNTIME_DIR/a.out" "1\\. Work Friend \\([0-9a-f]{12}\\)" "contact list numbering"
wait_for_match "$RUNTIME_DIR/a.out" "Contacts matching \"work\"" "contact search results"

printf '/dmleave\n' >&3
sleep 0.3
printf '/dm 1\n' >&3
wait_for_match "$RUNTIME_DIR/a.out" "DM request sent to Work Friend" "DM reopen by number"
wait_for_match "$RUNTIME_DIR/a.out" "DM session ready with Work Friend" "DM reopen handshake"

printf '/exit\n' >&3 || true
printf '/exit\n' >&4 || true
wait "$CLIENT_A_PID" || true
wait "$CLIENT_B_PID" || true

echo "Smoke test passed on port $PORT"
