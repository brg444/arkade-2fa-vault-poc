#!/bin/sh
# REGTEST ONLY: make the disposable arkd operator wallet ready for the POC.
# `arkd wallet create` prints its mnemonic, so its stdout must stay suppressed.
set -eu

WALLET_CONTAINER="${ARKD_REGTEST_WALLET_CONTAINER:-arkd}"
WALLET_PASSWORD="${ARKD_REGTEST_WALLET_PASSWORD:-arkade-regtest-only-wallet-fixture}"
WALLET_TRIES="${ARKD_REGTEST_WALLET_TRIES:-60}"
WALLET_SLEEP="${ARKD_REGTEST_WALLET_SLEEP:-2}"
COMMAND_TIMEOUT="${ARKD_REGTEST_WALLET_COMMAND_TIMEOUT:-15}"

case "$WALLET_PASSWORD" in
  '')
    echo "ARKD_REGTEST_WALLET_PASSWORD must not be empty" >&2
    exit 1
    ;;
esac
case "$WALLET_TRIES" in
  ''|*[!0-9]*|0)
    echo "ARKD_REGTEST_WALLET_TRIES must be a positive integer" >&2
    exit 1
    ;;
esac
case "$WALLET_SLEEP" in
  ''|*[!0-9]*)
    echo "ARKD_REGTEST_WALLET_SLEEP must be a non-negative integer" >&2
    exit 1
    ;;
esac
case "$COMMAND_TIMEOUT" in
  ''|*[!0-9]*|0)
    echo "ARKD_REGTEST_WALLET_COMMAND_TIMEOUT must be a positive integer" >&2
    exit 1
    ;;
esac

# The pinned arkd image is Alpine and supplies BusyBox timeout. This keeps
# every admin CLI request bounded as well as bounding the outer poll loop.
arkd_wallet() {
  docker exec "$WALLET_CONTAINER" timeout "$COMMAND_TIMEOUT" arkd wallet "$@"
}

status_value() {
  key="$1"
  # Keep this portable to macOS/BSD sed as well as BusyBox/GNU sed. Basic
  # regular-expression alternation (`\\|`) is not available everywhere.
  printf '%s\n' "$wallet_status" |
    sed -n "s/^${key}:[[:space:]]*//p"
}

read_wallet_status() {
  if ! wallet_status="$(arkd_wallet status 2>/dev/null)"; then
    return 1
  fi
  wallet_initialized="$(status_value initialized)"
  wallet_unlocked="$(status_value unlocked)"
  wallet_synced="$(status_value synced)"
  case "$wallet_initialized:$wallet_unlocked:$wallet_synced" in
    true:true:true|true:true:false|true:false:true|true:false:false|false:false:true|false:false:false)
      return 0
      ;;
  esac
  return 1
}

attempt=1
create_succeeded=0
while [ "$attempt" -le "$WALLET_TRIES" ]; do
  if read_wallet_status; then
    if [ "$wallet_initialized" = false ]; then
      if [ "$create_succeeded" -eq 0 ]; then
        echo "creating disposable REGTEST arkd wallet"
        # Successful create prints the newly generated mnemonic to stdout.
        # Never expose it in launcher, CI, or acceptance logs.
        if ! arkd_wallet create --password "$WALLET_PASSWORD" >/dev/null; then
          echo "failed to create disposable REGTEST arkd wallet" >&2
          exit 1
        fi
        create_succeeded=1
      fi
    elif [ "$wallet_unlocked" = false ]; then
      echo "unlocking disposable REGTEST arkd wallet"
      if ! arkd_wallet unlock --password "$WALLET_PASSWORD" >/dev/null; then
        echo "failed to unlock disposable REGTEST arkd wallet" >&2
        exit 1
      fi
    elif [ "$wallet_synced" = true ]; then
      echo "arkd wallet is initialized, unlocked, and synced"
      exit 0
    fi
  fi

  if [ "$attempt" -lt "$WALLET_TRIES" ]; then
    sleep "$WALLET_SLEEP"
  fi
  attempt=$((attempt + 1))
done

echo "arkd wallet did not become initialized, unlocked, and synced after $WALLET_TRIES attempts" >&2
exit 1
