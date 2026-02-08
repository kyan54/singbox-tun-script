#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Missing required command: $1" >&2
    exit 1
  }
}

prompt() {
  local label="$1"
  local default="$2"
  local input
  if [[ -n "$default" ]]; then
    read -r -p "$label [$default]: " input
    echo "${input:-$default}"
  else
    read -r -p "$label: " input
    echo "$input"
  fi
}

detect_default_gw() {
  ip route 2>/dev/null | awk '/^default / {for (i=1; i<=NF; i++) if ($i=="via") {print $(i+1); exit}}'
}

detect_default_dev() {
  ip route 2>/dev/null | awk '/^default / {for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}'
}

has_systemd() {
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

parse_vless_url() {
  local url="$1"
  python3 - "$url" <<'PY'
import sys
import urllib.parse
import shlex

url = sys.argv[1]
u = urllib.parse.urlparse(url)
if u.scheme != "vless":
  print("echo \"[!] Invalid VLESS URL (scheme must be vless)\" >&2")
  print("exit 1")
  sys.exit(0)

uuid = u.username or ""
host = u.hostname or ""
port = str(u.port) if u.port else ""
qs = urllib.parse.parse_qs(u.query)

def get(k):
  return (qs.get(k, [""])[0] or "")

fields = {
  "VLESS_UUID": uuid,
  "VLESS_HOST": host,
  "VLESS_PORT": port,
  "VLESS_FLOW": get("flow"),
  "VLESS_SNI": get("sni"),
  "VLESS_FP": get("fp"),
  "VLESS_PBK": get("pbk"),
  "VLESS_SID": get("sid"),
}

for k, v in fields.items():
  if v:
    print(f"{k}={shlex.quote(v)}")
PY
}

default_bypass_cidrs() {
  echo "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16"
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

csv_to_json_array() {
  local csv="$1"
  local out=""
  local item
  IFS=',' read -r -a items <<<"$csv"
  for item in "${items[@]}"; do
    item="$(trim "$item")"
    [[ -z "$item" ]] && continue
    if [[ -n "$out" ]]; then
      out+=", "
    fi
    out+="\"$item\""
  done
  if [[ -z "$out" ]]; then
    echo "[]"
  else
    echo "[$out]"
  fi
}

detect_tun_if() {
  local i
  for i in {0..9}; do
    if ! ip link show "tun${i}" >/dev/null 2>&1; then
      echo "tun${i}"
      return
    fi
  done
  echo "tun0"
}

detect_tun_addr() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import ipaddress
import re
import subprocess
import sys

def read_lines(cmd):
  try:
    out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
  except Exception:
    return []
  return out.splitlines()

routes = read_lines(["ip", "-o", "-4", "route", "show"])
addrs = read_lines(["ip", "-o", "-4", "addr", "show"])

occupied = []
for line in routes + addrs:
  for m in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d+\b', line):
    try:
      occupied.append(ipaddress.ip_network(m, strict=False))
    except ValueError:
      pass

ranges = [
  "172.19.0.0/16",
  "172.20.0.0/16",
  "172.30.0.0/16",
  "10.10.0.0/16",
  "10.20.0.0/16",
  "192.168.200.0/24",
  "192.168.201.0/24",
]

for r in ranges:
  net = ipaddress.ip_network(r)
  for sub in net.subnets(new_prefix=30):
    if not any(sub.overlaps(o) for o in occupied):
      host = sub.network_address + 1
      print(f"{host}/{sub.prefixlen}")
      sys.exit(0)

print("172.19.0.1/30")
PY
  else
    echo "172.19.0.1/30"
  fi
}

require_cmd curl
require_cmd tar
require_cmd ip
require_cmd awk

echo "[*] sing-box TUN one-click installer"
echo ""

VERSION="$(prompt "Sing-box version" "1.13.0-beta.7")"
ARCH="$(prompt "Release arch (e.g., linux-amd64)" "linux-amd64")"
BIN_PATH="$(prompt "Install path for sing-box binary" "/usr/local/bin/sing-box")"
CONF_PATH="$(prompt "Config path" "/etc/sing-box-tun.json")"

VLESS_URL_INPUT="$(prompt "VLESS URL (optional)" "${VLESS_URL:-}")"
if [[ -n "$VLESS_URL_INPUT" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 is required to parse VLESS URL." >&2
    exit 1
  fi
  eval "$(parse_vless_url "$VLESS_URL_INPUT")"
fi

SERVER_IP="${SERVER_IP:-${VLESS_HOST:-}}"
if [[ -z "$SERVER_IP" ]]; then
  SERVER_IP="$(prompt "VLESS server IP" "YOUR_SERVER_IP")"
fi
SERVER_PORT="${SERVER_PORT:-${VLESS_PORT:-}}"
if [[ -z "$SERVER_PORT" ]]; then
  SERVER_PORT="$(prompt "VLESS server port" "443")"
fi
UUID="${UUID:-${VLESS_UUID:-}}"
if [[ -z "$UUID" ]]; then
  UUID="$(prompt "VLESS UUID" "YOUR_UUID")"
fi
FLOW="${FLOW:-${VLESS_FLOW:-}}"
if [[ -z "$FLOW" ]]; then
  FLOW="$(prompt "Flow" "xtls-rprx-vision")"
fi
SERVER_NAME="${SERVER_NAME:-${VLESS_SNI:-}}"
if [[ -z "$SERVER_NAME" ]]; then
  SERVER_NAME="$(prompt "TLS server_name (SNI)" "${SERVER_NAME:-your.sni.host}")"
fi
FINGERPRINT="${FINGERPRINT:-${VLESS_FP:-}}"
if [[ -z "$FINGERPRINT" ]]; then
  FINGERPRINT="$(prompt "uTLS fingerprint" "chrome")"
fi
PUBLIC_KEY="${PUBLIC_KEY:-${VLESS_PBK:-}}"
if [[ -z "$PUBLIC_KEY" ]]; then
  PUBLIC_KEY="$(prompt "Reality public_key" "YOUR_PUBLIC_KEY")"
fi
SHORT_ID="${SHORT_ID:-${VLESS_SID:-}}"
if [[ -z "$SHORT_ID" ]]; then
  SHORT_ID="$(prompt "Reality short_id" "YOUR_SHORT_ID")"
fi

TUN_IF="${TUN_IF:-$(detect_tun_if)}"
TUN_ADDR="${TUN_ADDR:-$(detect_tun_addr)}"

GW_DETECTED="$(detect_default_gw || true)"
DEV_DETECTED="$(detect_default_dev || true)"
GW="${GW:-${GW_DETECTED:-}}"
DEV="${DEV:-${DEV_DETECTED:-eth0}}"
BYPASS_CIDRS="${BYPASS_CIDRS:-$(default_bypass_cidrs)}"
BYPASS_JSON="$(csv_to_json_array "$BYPASS_CIDRS")"
ROUTE_RULES=""
if [[ "$BYPASS_JSON" != "[]" ]]; then
  ROUTE_RULES="  \"rules\": [ { \"ip_cidr\": $BYPASS_JSON, \"outbound\": \"direct\" } ],"
fi

USE_SYSTEMD="${USE_SYSTEMD:-auto}"
if [[ "$USE_SYSTEMD" == "auto" ]]; then
  if has_systemd; then
    USE_SYSTEMD="1"
  else
    USE_SYSTEMD="0"
  fi
fi
if [[ "$USE_SYSTEMD" == "1" ]] && ! has_systemd; then
  echo "[!] systemd requested but not available." >&2
  exit 1
fi

HELPER_PATH="$(prompt "Helper script path" "$HOME/.local/bin/sb-tun")"
LOG_PATH="$(prompt "Helper log path" "$HOME/.local/state/sing-box/sing-box-tun.log")"
PID_PATH="$(prompt "Helper pid path" "$HOME/.local/state/sing-box/sing-box-tun.pid")"

URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-${ARCH}.tar.gz"

echo ""
echo "[*] Preparing to install:"
echo "    URL: $URL"
echo "    Binary: $BIN_PATH"
echo "    Config: $CONF_PATH"
echo "    Helper: $HELPER_PATH"
echo "    SNI: $SERVER_NAME"
echo "    TUN: $TUN_IF ($TUN_ADDR)"
echo "    Route: gw=${GW:-<none>} dev=$DEV"
echo "    Bypass: ${BYPASS_CIDRS}"
if [[ "$USE_SYSTEMD" == "1" ]]; then
  echo "    systemd: enabled"
else
  echo "    systemd: disabled"
fi
echo ""

read -r -p "Continue? [y/N]: " confirm
case "${confirm,,}" in
  y|yes) ;;
  *) echo "Aborted."; exit 1 ;;
esac

sudo -v

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT

mkdir -p "$(dirname "$HELPER_PATH")" "$(dirname "$LOG_PATH")" "$(dirname "$PID_PATH")"

LOCAL_TAR="$PWD/sing-box.tar.gz"
if [[ -f "$LOCAL_TAR" ]]; then
  echo "[*] Using existing tarball: $LOCAL_TAR"
  TAR_SRC="$LOCAL_TAR"
else
  echo "[*] Downloading sing-box..."
  TAR_SRC="$tmp_dir/sing-box.tar.gz"
  curl -fL -o "$TAR_SRC" "$URL"
fi

echo "[*] Extracting..."
tar -xzf "$TAR_SRC" -C "$tmp_dir"

bin_src="$(find "$tmp_dir" -maxdepth 2 -type f -name sing-box | head -n 1)"
if [[ -z "${bin_src:-}" ]]; then
  echo "[!] Failed to locate sing-box binary in archive." >&2
  exit 1
fi

echo "[*] Installing binary..."
sudo install -m 755 "$bin_src" "$BIN_PATH"

if [[ -f "$CONF_PATH" ]]; then
  read -r -p "[?] Config exists at $CONF_PATH, overwrite? [y/N]: " ow_conf
  if [[ "${ow_conf,,}" != "y" && "${ow_conf,,}" != "yes" ]]; then
    echo "[*] Keeping existing config."
  else
    sudo cp -f "$CONF_PATH" "${CONF_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    sudo tee "$CONF_PATH" >/dev/null <<EOF
{
  "log": { "level": "info" },

  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "$TUN_IF",
      "address": ["$TUN_ADDR"],
      "auto_route": false,
      "strict_route": false,
      "sniff": true
    }
  ],

  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "$SERVER_IP",
      "server_port": $SERVER_PORT,
      "uuid": "$UUID",
      "flow": "$FLOW",
      "tls": {
        "enabled": true,
        "server_name": "$SERVER_NAME",
        "utls": { "enabled": true, "fingerprint": "$FINGERPRINT" },
        "reality": {
          "enabled": true,
          "public_key": "$PUBLIC_KEY",
          "short_id": "$SHORT_ID"
        }
      }
    },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],

  "route": {
$ROUTE_RULES
    "final": "proxy"
  }
}
EOF
  fi
else
  sudo tee "$CONF_PATH" >/dev/null <<EOF
{
  "log": { "level": "info" },

  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "$TUN_IF",
      "address": ["$TUN_ADDR"],
      "auto_route": false,
      "strict_route": false,
      "sniff": true
    }
  ],

  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "$SERVER_IP",
      "server_port": $SERVER_PORT,
      "uuid": "$UUID",
      "flow": "$FLOW",
      "tls": {
        "enabled": true,
        "server_name": "$SERVER_NAME",
        "utls": { "enabled": true, "fingerprint": "$FINGERPRINT" },
        "reality": {
          "enabled": true,
          "public_key": "$PUBLIC_KEY",
          "short_id": "$SHORT_ID"
        }
      }
    },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],

  "route": {
$ROUTE_RULES
    "final": "proxy"
  }
}
EOF
fi

if [[ "$USE_SYSTEMD" == "1" ]]; then
  ROUTE_SCRIPT="/usr/local/lib/sing-box/sb-tun-route.sh"
  UNIT_PATH="/etc/systemd/system/sing-box-tun.service"

  echo "[*] Installing systemd unit..."
  sudo mkdir -p "$(dirname "$ROUTE_SCRIPT")"
  sudo tee "$ROUTE_SCRIPT" >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail

GW="${GW}"
DEV="${DEV}"
SERVER_IP="$SERVER_IP"
TUN_IF="$TUN_IF"
BYPASS_CIDRS="$BYPASS_CIDRS"

set_default_route() {
  if [[ -n "\$GW" ]]; then
    ip route replace default via "\$GW" dev "\$DEV"
  else
    ip route replace default dev "\$DEV"
  fi
}

set_bypass_route() {
  if [[ -n "\$GW" ]]; then
    ip route replace "\$SERVER_IP/32" via "\$GW" dev "\$DEV"
  else
    ip route replace "\$SERVER_IP/32" dev "\$DEV"
  fi
}

set_bypass_cidrs() {
  local cidr
  IFS=',' read -r -a items <<<"\$BYPASS_CIDRS"
  for cidr in "\${items[@]}"; do
    cidr="\${cidr#"\${cidr%%[![:space:]]*}"}"
    cidr="\${cidr%"\${cidr##*[![:space:]]}"}"
    [[ -z "\$cidr" ]] && continue
    if [[ -n "\$GW" ]]; then
      ip route replace "\$cidr" via "\$GW" dev "\$DEV"
    else
      ip route replace "\$cidr" dev "\$DEV"
    fi
  done
}

wait_for_tun() {
  for i in {1..30}; do
    if ip link show "\$TUN_IF" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "[!] \$TUN_IF not found"
  return 1
}

case "\${1:-}" in
  pre)
    set_default_route
    set_bypass_route
    set_bypass_cidrs
    ;;
  post)
    wait_for_tun
    ip route replace default dev "\$TUN_IF"
    ;;
  stop)
    set_default_route
    ip route del "\$SERVER_IP/32" 2>/dev/null || true
    ;;
  *)
    echo "Usage: \$0 {pre|post|stop}"
    exit 1
    ;;
esac
EOF
  sudo chmod +x "$ROUTE_SCRIPT"

  sudo tee "$UNIT_PATH" >/dev/null <<EOF
[Unit]
Description=sing-box TUN
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=$ROUTE_SCRIPT pre
ExecStart=$BIN_PATH run -c $CONF_PATH
ExecStartPost=$ROUTE_SCRIPT post
ExecStopPost=$ROUTE_SCRIPT stop
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  if [[ "${ENABLE_ON_BOOT:-0}" == "1" ]]; then
    sudo systemctl enable sing-box-tun.service
  fi

  if [[ -f "$HELPER_PATH" ]]; then
    read -r -p "[?] Helper exists at $HELPER_PATH, overwrite? [y/N]: " ow_helper
    if [[ "${ow_helper,,}" != "y" && "${ow_helper,,}" != "yes" ]]; then
      echo "[*] Keeping existing helper."
    else
      cp -f "$HELPER_PATH" "${HELPER_PATH}.bak.$(date +%Y%m%d%H%M%S)"
      cat > "$HELPER_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail

cmd="\${1:-}"
case "\$cmd" in
  start|stop|restart|status|enable|disable)
    sudo systemctl "\$cmd" sing-box-tun.service
    ;;
  logs)
    sudo journalctl -u sing-box-tun.service -n 120 --no-pager
    ;;
  *)
    echo "Usage: \$0 {start|stop|restart|status|logs|enable|disable}"
    exit 1
    ;;
esac
EOF
      chmod +x "$HELPER_PATH"
    fi
  else
    cat > "$HELPER_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail

cmd="\${1:-}"
case "\$cmd" in
  start|stop|restart|status|enable|disable)
    sudo systemctl "\$cmd" sing-box-tun.service
    ;;
  logs)
    sudo journalctl -u sing-box-tun.service -n 120 --no-pager
    ;;
  *)
    echo "Usage: \$0 {start|stop|restart|status|logs|enable|disable}"
    exit 1
    ;;
esac
EOF
    chmod +x "$HELPER_PATH"
  fi
else
if [[ -f "$HELPER_PATH" ]]; then
  read -r -p "[?] Helper exists at $HELPER_PATH, overwrite? [y/N]: " ow_helper
  if [[ "${ow_helper,,}" != "y" && "${ow_helper,,}" != "yes" ]]; then
    echo "[*] Keeping existing helper."
  else
    cp -f "$HELPER_PATH" "${HELPER_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    cat > "$HELPER_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail

SB_BIN="$BIN_PATH"
SB_CONF="$CONF_PATH"
PID_FILE="$PID_PATH"
LOG_FILE="$LOG_PATH"

GW="${GW}"
DEV="${DEV}"
SERVER_IP="$SERVER_IP"
TUN_IF="$TUN_IF"
BYPASS_CIDRS="$BYPASS_CIDRS"

is_running() {
  [[ -f "\$PID_FILE" ]] && kill -0 "\$(cat "\$PID_FILE")" 2>/dev/null
}

set_default_route() {
  if [[ -n "\$GW" ]]; then
    sudo ip route replace default via "\$GW" dev "\$DEV"
  else
    sudo ip route replace default dev "\$DEV"
  fi
}

set_bypass_route() {
  if [[ -n "\$GW" ]]; then
    sudo ip route replace "\$SERVER_IP/32" via "\$GW" dev "\$DEV"
  else
    sudo ip route replace "\$SERVER_IP/32" dev "\$DEV"
  fi
}

set_bypass_cidrs() {
  local cidr
  IFS=',' read -r -a items <<<"\$BYPASS_CIDRS"
  for cidr in "\${items[@]}"; do
    cidr="\${cidr#"\${cidr%%[![:space:]]*}"}"
    cidr="\${cidr%"\${cidr##*[![:space:]]}"}"
    [[ -z "\$cidr" ]] && continue
    if [[ -n "\$GW" ]]; then
      sudo ip route replace "\$cidr" via "\$GW" dev "\$DEV"
    else
      sudo ip route replace "\$cidr" dev "\$DEV"
    fi
  done
}

start() {
  echo "[*] Starting sing-box TUN (background)..."

  sudo -v

  if [[ ! -x "\$SB_BIN" ]]; then
    echo "[!] sing-box not found: \$SB_BIN"; exit 1
  fi
  if [[ ! -f "\$SB_CONF" ]]; then
    echo "[!] config not found: \$SB_CONF"; exit 1
  fi

  if is_running; then
    echo "[*] Already running (pid=\$(cat "\$PID_FILE"))"
    exit 0
  fi

  set_default_route
  set_bypass_route
  set_bypass_cidrs

  : > "\$LOG_FILE"
  setsid sudo "\$SB_BIN" run -c "\$SB_CONF" >>"\$LOG_FILE" 2>&1 < /dev/null &
  PID=\$!
  echo "\$PID" > "\$PID_FILE"

  for i in {1..30}; do
    if ip link show "\$TUN_IF" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done

  if ! ip link show "\$TUN_IF" >/dev/null 2>&1; then
    echo "[!] \$TUN_IF not found; sing-box may have failed to start."
    rm -f "\$PID_FILE"
    tail -n 120 "\$LOG_FILE" 2>/dev/null || true
    exit 1
  fi

  sudo ip route replace default dev "\$TUN_IF"

  echo "[+] Started. pid=\$PID"
  echo "[*] Log: \$LOG_FILE"
}

stop() {
  echo "[*] Stopping sing-box TUN..."

  set_default_route
  sudo ip route del "\$SERVER_IP/32" 2>/dev/null || true

  if [[ -f "\$PID_FILE" ]]; then
    PID="\$(cat "\$PID_FILE" || true)"
    if [[ -n "\${PID:-}" ]] && kill -0 "\$PID" 2>/dev/null; then
      sudo kill "\$PID" 2>/dev/null || true
      sleep 0.5
      sudo kill -9 "\$PID" 2>/dev/null || true
    fi
    rm -f "\$PID_FILE"
  fi

  sudo pkill -f "sing-box run -c \$SB_CONF" 2>/dev/null || true

  echo "[+] Stopped."
}

status() {
  echo "---- process ----"
  if is_running; then
    echo "[+] running pid=\$(cat "\$PID_FILE")"
  else
    echo "[-] not running"
  fi

  echo ""
  echo "---- routes ----"
  ip route

  echo ""
  echo "---- \$TUN_IF ----"
  ip addr show "\$TUN_IF" 2>/dev/null || echo "(\$TUN_IF not found)"
}

logs() {
  tail -n 120 "\$LOG_FILE"
}

case "\${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  logs) logs ;;
  *)
    echo "Usage: \$0 {start|stop|restart|status|logs}"
    exit 1
    ;;
esac
EOF
    chmod +x "$HELPER_PATH"
  fi
else
  cat > "$HELPER_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail

SB_BIN="$BIN_PATH"
SB_CONF="$CONF_PATH"
PID_FILE="$PID_PATH"
LOG_FILE="$LOG_PATH"

GW="${GW}"
DEV="${DEV}"
SERVER_IP="$SERVER_IP"
TUN_IF="$TUN_IF"

is_running() {
  [[ -f "\$PID_FILE" ]] && kill -0 "\$(cat "\$PID_FILE")" 2>/dev/null
}

set_default_route() {
  if [[ -n "\$GW" ]]; then
    sudo ip route replace default via "\$GW" dev "\$DEV"
  else
    sudo ip route replace default dev "\$DEV"
  fi
}

set_bypass_route() {
  if [[ -n "\$GW" ]]; then
    sudo ip route replace "\$SERVER_IP/32" via "\$GW" dev "\$DEV"
  else
    sudo ip route replace "\$SERVER_IP/32" dev "\$DEV"
  fi
}

set_bypass_cidrs() {
  local cidr
  IFS=',' read -r -a items <<<"\$BYPASS_CIDRS"
  for cidr in "\${items[@]}"; do
    cidr="\${cidr#"\${cidr%%[![:space:]]*}"}"
    cidr="\${cidr%"\${cidr##*[![:space:]]}"}"
    [[ -z "\$cidr" ]] && continue
    if [[ -n "\$GW" ]]; then
      sudo ip route replace "\$cidr" via "\$GW" dev "\$DEV"
    else
      sudo ip route replace "\$cidr" dev "\$DEV"
    fi
  done
}

start() {
  echo "[*] Starting sing-box TUN (background)..."

  sudo -v

  if [[ ! -x "\$SB_BIN" ]]; then
    echo "[!] sing-box not found: \$SB_BIN"; exit 1
  fi
  if [[ ! -f "\$SB_CONF" ]]; then
    echo "[!] config not found: \$SB_CONF"; exit 1
  fi

  if is_running; then
    echo "[*] Already running (pid=\$(cat "\$PID_FILE"))"
    exit 0
  fi

  set_default_route
  set_bypass_route
  set_bypass_cidrs

  : > "\$LOG_FILE"
  setsid sudo "\$SB_BIN" run -c "\$SB_CONF" >>"\$LOG_FILE" 2>&1 < /dev/null &
  PID=\$!
  echo "\$PID" > "\$PID_FILE"

  for i in {1..30}; do
    if ip link show "\$TUN_IF" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done

  if ! ip link show "\$TUN_IF" >/dev/null 2>&1; then
    echo "[!] \$TUN_IF not found; sing-box may have failed to start."
    rm -f "\$PID_FILE"
    tail -n 120 "\$LOG_FILE" 2>/dev/null || true
    exit 1
  fi

  sudo ip route replace default dev "\$TUN_IF"

  echo "[+] Started. pid=\$PID"
  echo "[*] Log: \$LOG_FILE"
}

stop() {
  echo "[*] Stopping sing-box TUN..."

  set_default_route
  sudo ip route del "\$SERVER_IP/32" 2>/dev/null || true

  if [[ -f "\$PID_FILE" ]]; then
    PID="\$(cat "\$PID_FILE" || true)"
    if [[ -n "\${PID:-}" ]] && kill -0 "\$PID" 2>/dev/null; then
      sudo kill "\$PID" 2>/dev/null || true
      sleep 0.5
      sudo kill -9 "\$PID" 2>/dev/null || true
    fi
    rm -f "\$PID_FILE"
  fi

  sudo pkill -f "sing-box run -c \$SB_CONF" 2>/dev/null || true

  echo "[+] Stopped."
}

status() {
  echo "---- process ----"
  if is_running; then
    echo "[+] running pid=\$(cat "\$PID_FILE")"
  else
    echo "[-] not running"
  fi

  echo ""
  echo "---- routes ----"
  ip route

  echo ""
  echo "---- \$TUN_IF ----"
  ip addr show "\$TUN_IF" 2>/dev/null || echo "(\$TUN_IF not found)"
}

logs() {
  tail -n 120 "\$LOG_FILE"
}

case "\${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  logs) logs ;;
  *)
    echo "Usage: \$0 {start|stop|restart|status|logs}"
    exit 1
    ;;
esac
EOF
  chmod +x "$HELPER_PATH"
fi
fi

echo ""
echo "[+] Installation complete."
if [[ "$USE_SYSTEMD" == "1" ]]; then
  echo "    systemd: $UNIT_PATH"
  echo "    Start: sudo systemctl start sing-box-tun"
  echo "    Stop:  sudo systemctl stop sing-box-tun"
  echo "    Status:sudo systemctl status sing-box-tun"
  echo "    Logs:  sudo journalctl -u sing-box-tun -n 120 --no-pager"
  echo "    Helper: $HELPER_PATH {start|stop|restart|status|logs|enable|disable}"
  echo "    Enable: sudo systemctl enable --now sing-box-tun"
else
  echo "    Start: $HELPER_PATH start"
  echo "    Stop:  $HELPER_PATH stop"
  echo "    Status:$HELPER_PATH status"
fi
