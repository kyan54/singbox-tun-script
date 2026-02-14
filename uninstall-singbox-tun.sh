#!/usr/bin/env bash
set -euo pipefail

prompt_yn() {
  local label="$1"
  local default="$2"
  local input
  read -r -p "$label [$default]: " input
  input="${input:-$default}"
  case "${input,,}" in
    y|yes) return 0 ;;
    *) return 1 ;;
  esac
}

STATE_DIRS=()
add_state_dir() {
  local dir="$1"
  local existing
  [[ -z "$dir" || "$dir" == "." || "$dir" == "/" ]] && return
  for existing in "${STATE_DIRS[@]:-}"; do
    [[ "$existing" == "$dir" ]] && return
  done
  STATE_DIRS+=("$dir")
}

echo "[*] sing-box TUN uninstall"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_SB_BIN="${SB_BIN-}"
ENV_CONF_PATH="${CONF_PATH-}"
ENV_HELPER_PATH="${HELPER_PATH-}"
ENV_LOG_PATH="${LOG_PATH-}"
ENV_PID_PATH="${PID_PATH-}"
ENV_CONF_FILE="${CONF_FILE-}"

CONF_FILE="${ENV_CONF_FILE:-$SCRIPT_DIR/singbox-tun.conf}"
CONF_SOURCE="default"
if [[ -f "$CONF_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONF_FILE"
  CONF_SOURCE="file"
fi

SB_BIN="${ENV_SB_BIN:-${BIN_PATH:-/usr/local/bin/sing-box}}"
CONF_PATH="${ENV_CONF_PATH:-${CONF_PATH:-/etc/sing-box-tun.json}}"
HELPER_PATH="${ENV_HELPER_PATH:-${HELPER_PATH:-$HOME/.local/bin/sb-tun}}"
LOG_PATH="${ENV_LOG_PATH:-${LOG_PATH:-$HOME/.local/state/sing-box/sing-box-tun.log}}"
PID_PATH="${ENV_PID_PATH:-${PID_PATH:-$HOME/.local/state/sing-box/sing-box-tun.pid}}"

UNIT_PATH="/etc/systemd/system/sing-box-tun.service"
ROUTE_SCRIPT="/usr/local/lib/sing-box/sb-tun-route.sh"
ROUTE_DIR="/usr/local/lib/sing-box"
add_state_dir "$(dirname "$LOG_PATH")"
add_state_dir "$(dirname "$PID_PATH")"

echo ""
echo "  conf:    $CONF_FILE ($CONF_SOURCE)"
echo "Targets:"
echo "  binary:  $SB_BIN"
echo "  config:  $CONF_PATH"
echo "  helper:  $HELPER_PATH"
echo "  log:     $LOG_PATH"
echo "  pid:     $PID_PATH"
echo "  unit:    $UNIT_PATH"
echo "  route:   $ROUTE_SCRIPT"
echo "  state:   ${STATE_DIRS[*]:-<none>}"
echo ""

if ! prompt_yn "Continue uninstall?" "N"; then
  echo "Aborted."
  exit 1
fi

if command -v systemctl >/dev/null 2>&1 && systemctl cat sing-box-tun.service >/dev/null 2>&1; then
  echo "[*] Stopping systemd service..."
  sudo systemctl stop sing-box-tun.service || true
  sudo systemctl disable sing-box-tun.service || true
  sudo rm -f "$UNIT_PATH"
  sudo systemctl daemon-reload || true
else
  if [[ -x "$HELPER_PATH" ]]; then
    if prompt_yn "Helper exists. Try stop?" "Y"; then
      "$HELPER_PATH" stop || true
    fi
  fi
fi

if prompt_yn "Remove route helper script?" "Y"; then
  sudo rm -f "$ROUTE_SCRIPT"
  sudo rmdir "$ROUTE_DIR" 2>/dev/null || true
fi

if prompt_yn "Remove helper script?" "Y"; then
  rm -f "$HELPER_PATH"
fi

if prompt_yn "Remove config?" "N"; then
  sudo rm -f "$CONF_PATH"
fi

if prompt_yn "Remove sing-box binary?" "N"; then
  sudo rm -f "$SB_BIN"
fi

if prompt_yn "Remove log file?" "Y"; then
  rm -f "$LOG_PATH"
fi

if prompt_yn "Remove pid file?" "Y"; then
  rm -f "$PID_PATH"
fi

if prompt_yn "Remove state dir(s) (logs/pid) if empty?" "Y"; then
  for state_dir in "${STATE_DIRS[@]:-}"; do
    rmdir "$state_dir" 2>/dev/null || true
  done
fi

echo "[+] Done."
