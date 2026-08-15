#!/bin/sh
# Opt-in golden path: Chrome PRF -> Provider -> private RemoteSigner -> Core.
# The Compose project and provider volume are unique to this run. Nigiri data
# is shared but never stopped or deleted by this script.
set -eu

if [ "${VAULT_LIVE_ACCEPTANCE:-}" != 1 ]; then
  echo "refusing live regtest acceptance without VAULT_LIVE_ACCEPTANCE=1" >&2
  exit 1
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

run_bounded() {
  seconds="$1"
  shift
  bun "$BOUND_RUNNER" "$seconds" "$@"
}

need_cmd docker
need_cmd nigiri
need_cmd curl
need_cmd bun
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BOUND_RUNNER="$SCRIPT_DIR/run-bounded.mjs"
if ! run_bounded 15 docker compose version >/dev/null 2>&1; then
  echo "docker compose plugin required" >&2
  exit 1
fi
if ! run_bounded 15 docker info >/dev/null 2>&1; then
  echo "docker daemon is not reachable" >&2
  exit 1
fi

ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)"
cd "$ROOT"

PROJECT="arkade-vault-e2e-$(date +%s)-$$"
export COMPOSE_PROJECT_NAME="$PROJECT"

RESULT_FILE="$(mktemp)"
TX_STATUS_FILE="$(mktemp)"
VAULT_STATUS_FILE="$(mktemp)"
CORE_FILE="$(mktemp)"
started=0

cleanup() {
  st=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "$started" -eq 1 ]; then
    owned=1
    for container in emulator arkd arkd-wallet nbxplorer pgnbxplorer vault-provider; do
      if run_bounded 10 docker inspect "$container" >/dev/null 2>&1; then
        label="$(run_bounded 10 docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$container" 2>/dev/null)"
        if [ "$label" != "$PROJECT" ]; then
          echo "refusing cleanup: container '$container' belongs to project '$label', not '$PROJECT'" >&2
          owned=0
        fi
      fi
    done
    if [ "$st" -ne 0 ]; then
      run_bounded 20 docker compose -f docker-compose.regtest.yml -f poc/2fa-vault/docker-compose.yml logs --tail=200 >&2 || true
    fi
    if [ "$owned" -eq 1 ]; then
      # This removes only the nonce-named acceptance project and fresh volume.
      # External Nigiri networks, containers and data are never removed.
      run_bounded 30 docker compose -f docker-compose.regtest.yml -f poc/2fa-vault/docker-compose.yml down -v >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$RESULT_FILE" "$TX_STATUS_FILE" "$VAULT_STATUS_FILE" "$CORE_FILE"
  exit "$st"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

# Fixed container names mean two POC stacks cannot safely coexist. Refuse to
# touch either a running demo or stale stopped containers from another run.
for container in emulator arkd arkd-wallet nbxplorer pgnbxplorer vault-provider; do
  if run_bounded 10 docker inspect "$container" >/dev/null 2>&1; then
    echo "existing POC container '$container' found; stop/remove that stack before live acceptance" >&2
    exit 1
  fi
done
if run_bounded 10 docker volume inspect "${PROJECT}_vault-provider-data" >/dev/null 2>&1; then
  echo "refusing to reuse an existing acceptance volume" >&2
  exit 1
fi

started=1
run_bounded 600 env COMPOSE_PROJECT_NAME="$PROJECT" ./poc/2fa-vault/scripts/regtest-up.sh

run_bounded 600 env VAULT_E2E_RESULT_FILE="$RESULT_FILE" bun poc/2fa-vault/web/e2e/live-app.mjs

if [ ! -s "$RESULT_FILE" ]; then
  echo "browser acceptance did not write a result" >&2
  exit 1
fi

TXID="$(run_bounded 10 env RESULT_FILE="$RESULT_FILE" bun -e 'const r=await Bun.file(process.env.RESULT_FILE).json(); if(!/^[0-9a-f]{64}$/.test(r.txid||"")) process.exit(2); process.stdout.write(r.txid)')"
CHALLENGE="$(run_bounded 10 env RESULT_FILE="$RESULT_FILE" bun -e 'const r=await Bun.file(process.env.RESULT_FILE).json(); if(!/^[0-9a-f]{64}$/.test(r.challenge||"")) process.exit(2); process.stdout.write(r.challenge)')"

# Restart only the acceptance provider. Its named volume must preserve the
# immutable descriptor, completed issuance and budget state.
provider_project="$(run_bounded 10 docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' vault-provider)"
if [ "$provider_project" != "$PROJECT" ]; then
  echo "vault-provider belongs to '$provider_project', not acceptance project '$PROJECT'" >&2
  exit 1
fi
run_bounded 60 docker compose -f docker-compose.regtest.yml -f poc/2fa-vault/docker-compose.yml restart vault-provider >/dev/null
i=0
while ! curl -sf --connect-timeout 2 --max-time 5 http://127.0.0.1:8787/health >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 90 ]; then
    echo "provider did not become healthy after restart" >&2
    exit 1
  fi
  sleep 1
done

curl -sf --connect-timeout 5 --max-time 15 "http://127.0.0.1:8787/v1/tx?challenge=$CHALLENGE" -o "$TX_STATUS_FILE"
curl -sf --connect-timeout 5 --max-time 15 http://127.0.0.1:8787/v1/status -o "$VAULT_STATUS_FILE"
run_bounded 30 docker exec bitcoin bitcoin-cli getrawtransaction "$TXID" true >"$CORE_FILE"

run_bounded 15 env RESULT_FILE="$RESULT_FILE" TX_STATUS_FILE="$TX_STATUS_FILE" VAULT_STATUS_FILE="$VAULT_STATUS_FILE" CORE_FILE="$CORE_FILE" bun -e '
  const result = await Bun.file(process.env.RESULT_FILE).json();
  const tx = await Bun.file(process.env.TX_STATUS_FILE).json();
  const status = await Bun.file(process.env.VAULT_STATUS_FILE).json();
  const core = await Bun.file(process.env.CORE_FILE).json();
  const fail = (message) => { throw new Error(message); };
  if (tx.txid !== result.txid || Number(tx.confirmations) < 1) fail("challenge status did not survive restart");
  if (!status.enrolled || Number(status.periodSpent) !== 20500 || Number(status.periodRemaining) !== 79500) fail("budget state did not survive restart");
  if (status.operationalAddress !== result.operationalAddress || status.operationalScript !== result.operationalScript) fail("vault descriptor changed after restart");
  if (core.txid !== result.txid || Number(core.confirmations) < 1) fail("Bitcoin Core did not confirm the exact published txid");
'

echo "remote browser acceptance passed: txid=$TXID confirmations>=1 restart=durable"
