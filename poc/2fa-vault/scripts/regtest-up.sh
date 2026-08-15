#!/bin/sh
# Detached one-command POC start: Nigiri Bitcoin regtest + private Emulator + UI.
# Run from anywhere; resolves the emulator repository root from this script.
set -eu

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd docker
need_cmd nigiri
need_cmd curl
if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose plugin required" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "docker daemon is not reachable; start Docker and retry" >&2
  exit 1
fi

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

COMPOSE="docker compose -f docker-compose.regtest.yml -f poc/2fa-vault/docker-compose.yml"
HEALTH_URL="http://127.0.0.1:8787/health"
HEALTH_TRIES=90

# Official Nigiri `nigiri start` (without --ark=false) names its Ark node "ark".
# Mixing that container with this overlay's arkd is undefined.
if docker ps --format '{{.Names}}' | grep -qx ark; then
  echo "official Nigiri ark container is running; stop it before this POC" >&2
  exit 1
fi

RPC_TRIES=30
RPC_SLEEP=2

wait_nigiri_rpc() {
  i=0
  while [ "$i" -lt "$RPC_TRIES" ]; do
    if nigiri rpc getblockchaininfo >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep "$RPC_SLEEP"
  done
  return 1
}

# A running Nigiri can fail getblockchaininfo while bitcoind warms. Poll
# before deciding it is absent; do not tear down the user's Nigiri data.
if wait_nigiri_rpc; then
  echo "reusing ready Nigiri Bitcoin RPC"
else
  echo "starting Nigiri Bitcoin regtest (no ark/liquid/ln)"
  start_log="$(mktemp)"
  set +e
  nigiri start --ci --ark=false --liquid=false --ln=false >"$start_log" 2>&1
  start_st=$?
  set -e
  already=0
  if grep -qiE 'already running|already started' "$start_log"; then
    already=1
  fi
  if [ "$start_st" -ne 0 ] && [ "$already" -eq 0 ]; then
    cat "$start_log" >&2
    rm -f "$start_log"
    echo "nigiri start failed" >&2
    exit 1
  fi
  rm -f "$start_log"
  if wait_nigiri_rpc; then
    echo "Nigiri Bitcoin RPC is ready"
  elif [ "$already" -eq 1 ]; then
    echo "Nigiri reports already running but Bitcoin RPC stayed unavailable (stale or still warming). Wait and retry, or inspect Nigiri yourself. This launcher will not stop or delete your Nigiri state." >&2
    exit 1
  else
    echo "Nigiri start finished but Bitcoin RPC stayed unavailable (warming or stale). Wait and retry, or inspect Nigiri yourself. This launcher will not stop or delete your Nigiri state." >&2
    exit 1
  fi
fi

# Core 30+ only. The ~117-byte packet exceeds the pre-v30 83-byte
# datacarrier default. Do not fake a Core extra-args override; Nigiri
# does not consume one. testmempoolaccept remains the publish policy gate.
require_core30() {
  # Nigiri `rpc` pretty-prints through aurora (ANSI). Read raw JSON the
  # same way Nigiri invokes Core: docker exec bitcoin bitcoin-cli.
  if ! info="$(docker exec bitcoin bitcoin-cli getnetworkinfo)"; then
    echo "docker exec bitcoin bitcoin-cli getnetworkinfo failed after Bitcoin RPC was ready" >&2
    exit 1
  fi
  ver="$(printf '%s\n' "$info" | tr ',' '\n' | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
  case "$ver" in
    ''|*[!0-9]*)
      echo "Bitcoin Core version is missing or not numeric (need >= 300000 / Core 30+). The ~117-byte Arkade packet exceeds the pre-v30 83-byte datacarrier default, so current Nigiri/Core 30+ is required. testmempoolaccept remains the authoritative custom-policy gate at publish." >&2
      exit 1
      ;;
  esac
  if [ "$ver" -lt 300000 ]; then
    echo "Bitcoin Core version $ver is too old (need >= 300000 / Core 30+). The ~117-byte Arkade packet exceeds the pre-v30 83-byte datacarrier default, so current Nigiri/Core 30+ is required. testmempoolaccept remains the authoritative custom-policy gate at publish." >&2
    exit 1
  fi
}
require_core30

echo "validating merged compose"
$COMPOSE config >/dev/null

echo "starting private emulator + vault-provider"
$COMPOSE up -d --build

i=0
while ! curl -sf "$HEALTH_URL" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge "$HEALTH_TRIES" ]; then
    echo "provider did not become healthy at $HEALTH_URL" >&2
    $COMPOSE logs --tail=200 >&2 || true
    exit 1
  fi
  sleep 2
done

# Runtime topology: no host port, not on nigiri, exactly one attached
# network, and that network is Internal=true.
if ! docker inspect emulator >/dev/null 2>&1; then
  echo "emulator container not found" >&2
  $COMPOSE logs --tail=200 >&2 || true
  exit 1
fi
if docker port emulator 2>/dev/null | grep -q .; then
  echo "emulator publishes a host port" >&2
  docker port emulator >&2 || true
  exit 1
fi
ports="$(docker inspect -f '{{json .NetworkSettings.Ports}}' emulator)"
if printf '%s' "$ports" | grep -Eq '":\[\{'; then
  echo "emulator has a host port mapping" >&2
  echo "$ports" >&2
  exit 1
fi

nets="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' emulator)"
set -- $nets
if [ "$#" -ne 1 ]; then
  echo "emulator must have exactly one attached network: $nets" >&2
  exit 1
fi
net="$1"
if [ "$net" = nigiri ] || [ "$net" = default ]; then
  echo "emulator is attached to the shared nigiri network: $net" >&2
  exit 1
fi
if [ "$(docker network inspect -f '{{.Internal}}' "$net")" != true ]; then
  echo "emulator network $net is not Internal=true" >&2
  exit 1
fi

echo "http://localhost:8787"
