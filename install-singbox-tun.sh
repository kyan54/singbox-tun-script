#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Missing required command: $1" >&2
    exit 1
  }
}

detect_default_gw() {
  ip route 2>/dev/null | awk '
    $1=="default" {
      dev="";
      for (i=1; i<=NF; i++) if ($i=="dev") dev=$(i+1)
      if (dev ~ /^tun[0-9]+$/) next
      for (i=1; i<=NF; i++) if ($i=="via") {print $(i+1); exit}
    }'
}

detect_default_dev() {
  local dev
  dev="$(ip route 2>/dev/null | awk '
    $1=="default" {
      d="";
      for (i=1; i<=NF; i++) if ($i=="dev") d=$(i+1)
      if (d ~ /^tun[0-9]+$/) next
      if (d != "") {print d; exit}
    }')"
  if [[ -n "$dev" ]]; then
    echo "$dev"
    return
  fi
  ip -o -4 addr show up 2>/dev/null | awk '{print $2}' | grep -v '^tun' | head -n 1
}

is_wsl() {
  grep -qi microsoft /proc/version 2>/dev/null
}

guess_wsl_gw() {
  local dev="$1"
  local cidr
  cidr="$(ip -o -4 route show dev "$dev" 2>/dev/null | awk '/proto kernel/ {print $1; exit}')"
  if [[ -z "$cidr" ]]; then
    return 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$cidr" <<'PY'
import ipaddress
import sys

cidr = sys.argv[1]
try:
    net = ipaddress.ip_network(cidr, strict=False)
    gw = net.network_address + 1
    print(gw)
except Exception:
    pass
PY
  else
    return 1
  fi
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


array_to_json() {
  local -n arr="$1"
  local out=""
  local item
  for item in "${arr[@]}"; do
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

array_to_csv() {
  local -n arr="$1"
  local out=""
  local item
  for item in "${arr[@]}"; do
    [[ -z "$item" ]] && continue
    if [[ -n "$out" ]]; then
      out+=","
    fi
    out+="$item"
  done
  echo "$out"
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

detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) echo "linux-amd64" ;;
    aarch64|arm64) echo "linux-arm64" ;;
    armv7l) echo "linux-armv7" ;;
    armv6l) echo "linux-armv6" ;;
    *)
      echo "[!] Unsupported arch: $m" >&2
      exit 1
      ;;
  esac
}

detect_latest_version() {
  python3 - <<'PY'
import json
import sys
import urllib.request

url = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
try:
    with urllib.request.urlopen(url, timeout=10) as f:
        data = json.load(f)
except Exception as e:
    print("[!] Failed to fetch latest sing-box version:", e, file=sys.stderr)
    sys.exit(1)

tag = data.get("tag_name", "")
if not tag:
    print("[!] Could not determine latest version", file=sys.stderr)
    sys.exit(1)
if tag.startswith("v"):
    tag = tag[1:]
print(tag)
PY
}

require_cmd curl
require_cmd tar
require_cmd ip
require_cmd awk
require_cmd python3

echo "[*] sing-box TUN installer"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${CONF_FILE:-$SCRIPT_DIR/singbox-tun.conf}"
if [[ ! -f "$CONF_FILE" ]]; then
  echo "[!] Config file not found: $CONF_FILE" >&2
  echo "    Create it based on: $SCRIPT_DIR/singbox-tun.conf" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$CONF_FILE"

if [[ -z "${VLESS_URL:-}" ]]; then
  echo "[!] VLESS_URL is required in $CONF_FILE" >&2
  exit 1
fi

eval "$(parse_vless_url "$VLESS_URL")"

SERVER_IP="${VLESS_HOST:-}"
SERVER_PORT="${VLESS_PORT:-}"
UUID="${VLESS_UUID:-}"
FLOW="${VLESS_FLOW:-}"
SERVER_NAME="${VLESS_SNI:-}"
FINGERPRINT="${VLESS_FP:-}"
PUBLIC_KEY="${VLESS_PBK:-}"
SHORT_ID="${VLESS_SID:-}"

if [[ -z "$SERVER_IP" || -z "$SERVER_PORT" || -z "$UUID" || -z "$FLOW" || -z "$SERVER_NAME" || -z "$FINGERPRINT" || -z "$PUBLIC_KEY" || -z "$SHORT_ID" ]]; then
  echo "[!] VLESS_URL is missing required fields (host/port/uuid/flow/sni/fp/pbk/sid)." >&2
  exit 1
fi

VERSION="${VERSION:-}"
ARCH="${ARCH:-}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/sing-box}"
CONF_PATH="${CONF_PATH:-/etc/sing-box-tun.json}"

TUN_IF="${TUN_IF:-$(detect_tun_if)}"
TUN_ADDR="${TUN_ADDR:-$(detect_tun_addr)}"

GW_DETECTED="$(detect_default_gw || true)"
DEV_DETECTED="$(detect_default_dev || true)"
GW="${GW:-${GW_DETECTED:-}}"
DEV="${DEV:-${DEV_DETECTED:-eth0}}"
if [[ -z "$GW" && -n "$DEV" ]] && is_wsl; then
  GW_GUESS="$(guess_wsl_gw "$DEV" || true)"
  if [[ -n "${GW_GUESS:-}" ]]; then
    GW="$GW_GUESS"
  fi
fi

DIRECT_DOMAINS=(${DIRECT_DOMAINS[@]:-})
DIRECT_IPS=(${DIRECT_IPS[@]:-})
DIRECT_CIDRS=(${DIRECT_CIDRS[@]:-})

DIRECT_DOMAINS_JSON="$(array_to_json DIRECT_DOMAINS)"

DIRECT_IP_CIDRS=()
for ip in "${DIRECT_IPS[@]}"; do
  [[ -z "$ip" ]] && continue
  if [[ "$ip" == */* ]]; then
    DIRECT_IP_CIDRS+=("$ip")
  else
    DIRECT_IP_CIDRS+=("${ip}/32")
  fi
done
for cidr in "${DIRECT_CIDRS[@]}"; do
  [[ -z "$cidr" ]] && continue
  DIRECT_IP_CIDRS+=("$cidr")
done
DIRECT_IP_CIDRS_JSON="$(array_to_json DIRECT_IP_CIDRS)"
DIRECT_IP_CIDRS_CSV="$(array_to_csv DIRECT_IP_CIDRS)"

ROUTE_RULES=""
if [[ "$DIRECT_DOMAINS_JSON" != "[]" || "$DIRECT_IP_CIDRS_JSON" != "[]" ]]; then
  ROUTE_RULES="    \"rules\": ["
  if [[ "$DIRECT_DOMAINS_JSON" != "[]" ]]; then
    ROUTE_RULES+=" { \"domain\": $DIRECT_DOMAINS_JSON, \"outbound\": \"direct\" }"
    if [[ "$DIRECT_IP_CIDRS_JSON" != "[]" ]]; then
      ROUTE_RULES+=","
    fi
  fi
  if [[ "$DIRECT_IP_CIDRS_JSON" != "[]" ]]; then
    ROUTE_RULES+=" { \"ip_cidr\": $DIRECT_IP_CIDRS_JSON, \"outbound\": \"direct\" }"
  fi
  ROUTE_RULES+=" ],"
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

HELPER_PATH="${HELPER_PATH:-$HOME/.local/bin/sb-tun}"
LOG_PATH="${LOG_PATH:-$HOME/.local/state/sing-box/sing-box-tun.log}"
PID_PATH="${PID_PATH:-$HOME/.local/state/sing-box/sing-box-tun.pid}"

OVERWRITE_CONF="${OVERWRITE_CONF:-0}"
OVERWRITE_HELPER="${OVERWRITE_HELPER:-0}"

if [[ -z "$ARCH" ]]; then
  ARCH="$(detect_arch)"
fi

LOCAL_TAR="$PWD/sing-box.tar.gz"
USE_LOCAL_TAR="0"
if [[ -f "$LOCAL_TAR" ]]; then
  USE_LOCAL_TAR="1"
fi

if [[ -z "$VERSION" && "$USE_LOCAL_TAR" != "1" ]]; then
  VERSION="$(detect_latest_version)"
fi

if [[ "$USE_LOCAL_TAR" == "1" ]]; then
  URL="local: $LOCAL_TAR"
else
  URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-${ARCH}.tar.gz"
fi

echo ""
echo "[*] Preparing to install:"
echo "    URL: $URL"
echo "    Binary: $BIN_PATH"
echo "    Config: $CONF_PATH"
echo "    Helper: $HELPER_PATH"
echo "    SNI: $SERVER_NAME"
echo "    TUN: $TUN_IF ($TUN_ADDR)"
echo "    Route: gw=${GW:-<none>} dev=$DEV"
if [[ "$USE_SYSTEMD" == "1" ]]; then
  echo "    systemd: enabled"
else
  echo "    systemd: disabled"
fi
echo ""

if [[ "$OVERWRITE_CONF" != "1" && -f "$CONF_PATH" ]]; then
  read -r -p "[?] 检测到已有配置文件，是否覆盖？[y/N]: " ow_conf
  case "${ow_conf,,}" in
    y|yes) OVERWRITE_CONF="1" ;;
  esac
fi

if [[ "$OVERWRITE_HELPER" != "1" && -f "$HELPER_PATH" ]]; then
  read -r -p "[?] 检测到已有 helper 脚本，是否覆盖？[y/N]: " ow_helper
  case "${ow_helper,,}" in
    y|yes) OVERWRITE_HELPER="1" ;;
  esac
fi

sudo -v

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT

mkdir -p "$(dirname "$HELPER_PATH")" "$(dirname "$LOG_PATH")" "$(dirname "$PID_PATH")"

if [[ "$USE_LOCAL_TAR" == "1" ]]; then
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
  if [[ "$OVERWRITE_CONF" != "1" ]]; then
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
DIRECT_IP_CIDRS="$DIRECT_IP_CIDRS_CSV"

is_wsl() {
  grep -qi microsoft /proc/version 2>/dev/null
}

guess_wsl_gw() {
  local dev="\$1"
  local cidr
  cidr="\$(ip -o -4 route show dev "\$dev" 2>/dev/null | awk '/proto kernel/ {print \$1; exit}')"
  if [[ -z "\$cidr" ]]; then
    return 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "\$cidr" <<'PY'
import ipaddress
import sys

cidr = sys.argv[1]
try:
    net = ipaddress.ip_network(cidr, strict=False)
    gw = net.network_address + 1
    print(gw)
except Exception:
    pass
PY
  else
    return 1
  fi
}

resolve_base_route() {
  local dev gw
  dev="$DEV"
  gw="$GW"
  if [[ -z "$dev" || "$dev" =~ ^tun[0-9]+$ || ! -e "/sys/class/net/$dev" ]]; then
    dev="$(ip -o -4 route show default 2>/dev/null | awk '$0 !~ / dev tun[0-9]+/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
    if [[ -z "$dev" ]]; then
      dev="$(ip -o -4 addr show up 2>/dev/null | awk '{print $2}' | grep -v '^tun' | head -n1)"
    fi
  fi
  if [[ -z "$gw" ]]; then
    gw="$(ip -o -4 route show default 2>/dev/null | awk '$0 !~ / dev tun[0-9]+/ {for (i=1;i<=NF;i++) if ($i=="via") {print $(i+1); exit}}')"
  fi
  if [[ -z "$gw" && -n "$dev" ]] && is_wsl; then
    gw="$(guess_wsl_gw "$dev" || true)"
  fi
  DEV="$dev"
  GW="$gw"
}

set_default_route() {
  resolve_base_route
  if [[ -z "$DEV" ]]; then
    echo "[!] No base DEV found; skip default route restore" >&2
    return 0
  fi
  if [[ -n "\$GW" ]]; then
    ip route replace default via "\$GW" dev "\$DEV" || {
      echo "[!] Failed to set default route via \$GW dev \$DEV" >&2
      return 0
    }
  else
    ip route replace default dev "\$DEV" || {
      echo "[!] Failed to set default route dev \$DEV" >&2
      return 0
    }
  fi
}

set_bypass_route() {
  resolve_base_route
  if [[ -z "$DEV" ]]; then
    echo "[!] No base DEV found; skip bypass route" >&2
    return 0
  fi
  if [[ -n "\$GW" ]]; then
    ip route replace "\$SERVER_IP/32" via "\$GW" dev "\$DEV" || {
      echo "[!] Failed to add bypass route for \$SERVER_IP" >&2
      return 0
    }
  else
    ip route replace "\$SERVER_IP/32" dev "\$DEV" || {
      echo "[!] Failed to add bypass route for \$SERVER_IP" >&2
      return 0
    }
  fi
}

set_direct_routes() {
  local cidr
  IFS=',' read -r -a items <<<"\$DIRECT_IP_CIDRS"
  for cidr in "\${items[@]}"; do
    cidr="\${cidr#"\${cidr%%[![:space:]]*}"}"
    cidr="\${cidr%"\${cidr##*[![:space:]]}"}"
    [[ -z "\$cidr" ]] && continue
    if [[ -n "\$GW" ]]; then
      if ! ip route replace "\$cidr" via "\$GW" dev "\$DEV"; then
        echo "[!] Failed to add direct route: \$cidr" >&2
      fi
    else
      if ! ip route replace "\$cidr" dev "\$DEV"; then
        echo "[!] Failed to add direct route: \$cidr" >&2
      fi
    fi
  done
}

del_direct_routes() {
  local cidr
  IFS=',' read -r -a items <<<"\$DIRECT_IP_CIDRS"
  for cidr in "\${items[@]}"; do
    cidr="\${cidr#"\${cidr%%[![:space:]]*}"}"
    cidr="\${cidr%"\${cidr##*[![:space:]]}"}"
    [[ -z "\$cidr" ]] && continue
    ip route del "\$cidr" 2>/dev/null || true
  done
}


wait_for_tun() {
  for i in {1..100}; do
    if ip link show "\$TUN_IF" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "[!] \$TUN_IF not found after waiting; skip default route switch" >&2
  return 1
}

case "\${1:-}" in
  pre)
    set_default_route
    set_bypass_route
    set_direct_routes
    ;;
  post)
    if wait_for_tun; then
      if ! ip route replace default dev "\$TUN_IF"; then
        echo "[!] Failed to set default route to \$TUN_IF" >&2
      fi
    fi
    ;;
  stop)
    set_default_route
    ip route del "\$SERVER_IP/32" 2>/dev/null || true
    del_direct_routes
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
    if [[ "$OVERWRITE_HELPER" != "1" ]]; then
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
  if [[ "$OVERWRITE_HELPER" != "1" ]]; then
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
DIRECT_IP_CIDRS="$DIRECT_IP_CIDRS_CSV"

is_wsl() {
  grep -qi microsoft /proc/version 2>/dev/null
}

guess_wsl_gw() {
  local dev="\$1"
  local cidr
  cidr="\$(ip -o -4 route show dev "\$dev" 2>/dev/null | awk '/proto kernel/ {print \$1; exit}')"
  if [[ -z "\$cidr" ]]; then
    return 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "\$cidr" <<'PY'
import ipaddress
import sys

cidr = sys.argv[1]
try:
    net = ipaddress.ip_network(cidr, strict=False)
    gw = net.network_address + 1
    print(gw)
except Exception:
    pass
PY
  else
    return 1
  fi
}

resolve_base_route() {
  local dev gw
  dev="$DEV"
  gw="$GW"
  if [[ -z "$dev" || "$dev" =~ ^tun[0-9]+$ || ! -e "/sys/class/net/$dev" ]]; then
    dev="$(ip -o -4 route show default 2>/dev/null | awk '$0 !~ / dev tun[0-9]+/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
    if [[ -z "$dev" ]]; then
      dev="$(ip -o -4 addr show up 2>/dev/null | awk '{print $2}' | grep -v '^tun' | head -n1)"
    fi
  fi
  if [[ -z "$gw" ]]; then
    gw="$(ip -o -4 route show default 2>/dev/null | awk '$0 !~ / dev tun[0-9]+/ {for (i=1;i<=NF;i++) if ($i=="via") {print $(i+1); exit}}')"
  fi
  if [[ -z "$gw" && -n "$dev" ]] && is_wsl; then
    gw="$(guess_wsl_gw "$dev" || true)"
  fi
  DEV="$dev"
  GW="$gw"
}

is_running() {
  [[ -f "\$PID_FILE" ]] && kill -0 "\$(cat "\$PID_FILE")" 2>/dev/null
}

set_default_route() {
  resolve_base_route
  if [[ -z "\$DEV" ]]; then
    echo "[!] No base DEV found; skip default route restore" >&2
    return 0
  fi
  if [[ -n "\$GW" ]]; then
    sudo ip route replace default via "\$GW" dev "\$DEV" || {
      echo "[!] Failed to set default route via \$GW dev \$DEV" >&2
      return 0
    }
  else
    sudo ip route replace default dev "\$DEV" || {
      echo "[!] Failed to set default route dev \$DEV" >&2
      return 0
    }
  fi
}

set_bypass_route() {
  resolve_base_route
  if [[ -z "\$DEV" ]]; then
    echo "[!] No base DEV found; skip bypass route" >&2
    return 0
  fi
  if [[ -n "\$GW" ]]; then
    sudo ip route replace "\$SERVER_IP/32" via "\$GW" dev "\$DEV" || {
      echo "[!] Failed to add bypass route for \$SERVER_IP" >&2
      return 0
    }
  else
    sudo ip route replace "\$SERVER_IP/32" dev "\$DEV" || {
      echo "[!] Failed to add bypass route for \$SERVER_IP" >&2
      return 0
    }
  fi
}

set_direct_routes() {
  local cidr
  IFS=',' read -r -a items <<<"\$DIRECT_IP_CIDRS"
  for cidr in "\${items[@]}"; do
    cidr="\${cidr#"\${cidr%%[![:space:]]*}"}"
    cidr="\${cidr%"\${cidr##*[![:space:]]}"}"
    [[ -z "\$cidr" ]] && continue
    if [[ -n "\$GW" ]]; then
      if ! sudo ip route replace "\$cidr" via "\$GW" dev "\$DEV"; then
        echo "[!] Failed to add direct route: \$cidr" >&2
      fi
    else
      if ! sudo ip route replace "\$cidr" dev "\$DEV"; then
        echo "[!] Failed to add direct route: \$cidr" >&2
      fi
    fi
  done
}

del_direct_routes() {
  local cidr
  IFS=',' read -r -a items <<<"\$DIRECT_IP_CIDRS"
  for cidr in "\${items[@]}"; do
    cidr="\${cidr#"\${cidr%%[![:space:]]*}"}"
    cidr="\${cidr%"\${cidr##*[![:space:]]}"}"
    [[ -z "\$cidr" ]] && continue
    sudo ip route del "\$cidr" 2>/dev/null || true
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
  set_direct_routes

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
  del_direct_routes

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
DIRECT_IP_CIDRS="$DIRECT_IP_CIDRS_CSV"

is_wsl() {
  grep -qi microsoft /proc/version 2>/dev/null
}

guess_wsl_gw() {
  local dev="\$1"
  local cidr
  cidr="\$(ip -o -4 route show dev "\$dev" 2>/dev/null | awk '/proto kernel/ {print \$1; exit}')"
  if [[ -z "\$cidr" ]]; then
    return 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "\$cidr" <<'PY'
import ipaddress
import sys

cidr = sys.argv[1]
try:
    net = ipaddress.ip_network(cidr, strict=False)
    gw = net.network_address + 1
    print(gw)
except Exception:
    pass
PY
  else
    return 1
  fi
}

resolve_base_route() {
  local dev gw
  dev="$DEV"
  gw="$GW"
  if [[ -z "$dev" || "$dev" =~ ^tun[0-9]+$ || ! -e "/sys/class/net/$dev" ]]; then
    dev="$(ip -o -4 route show default 2>/dev/null | awk '$0 !~ / dev tun[0-9]+/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
    if [[ -z "$dev" ]]; then
      dev="$(ip -o -4 addr show up 2>/dev/null | awk '{print $2}' | grep -v '^tun' | head -n1)"
    fi
  fi
  if [[ -z "$gw" ]]; then
    gw="$(ip -o -4 route show default 2>/dev/null | awk '$0 !~ / dev tun[0-9]+/ {for (i=1;i<=NF;i++) if ($i=="via") {print $(i+1); exit}}')"
  fi
  if [[ -z "$gw" && -n "$dev" ]] && is_wsl; then
    gw="$(guess_wsl_gw "$dev" || true)"
  fi
  DEV="$dev"
  GW="$gw"
}

is_running() {
  [[ -f "\$PID_FILE" ]] && kill -0 "\$(cat "\$PID_FILE")" 2>/dev/null
}

set_default_route() {
  resolve_base_route
  if [[ -z "\$DEV" ]]; then
    echo "[!] No base DEV found; skip default route restore" >&2
    return 0
  fi
  if [[ -n "\$GW" ]]; then
    sudo ip route replace default via "\$GW" dev "\$DEV" || {
      echo "[!] Failed to set default route via \$GW dev \$DEV" >&2
      return 0
    }
  else
    sudo ip route replace default dev "\$DEV" || {
      echo "[!] Failed to set default route dev \$DEV" >&2
      return 0
    }
  fi
}

set_bypass_route() {
  resolve_base_route
  if [[ -z "\$DEV" ]]; then
    echo "[!] No base DEV found; skip bypass route" >&2
    return 0
  fi
  if [[ -n "\$GW" ]]; then
    sudo ip route replace "\$SERVER_IP/32" via "\$GW" dev "\$DEV" || {
      echo "[!] Failed to add bypass route for \$SERVER_IP" >&2
      return 0
    }
  else
    sudo ip route replace "\$SERVER_IP/32" dev "\$DEV" || {
      echo "[!] Failed to add bypass route for \$SERVER_IP" >&2
      return 0
    }
  fi
}

set_direct_routes() {
  local cidr
  IFS=',' read -r -a items <<<"\$DIRECT_IP_CIDRS"
  for cidr in "\${items[@]}"; do
    cidr="\${cidr#"\${cidr%%[![:space:]]*}"}"
    cidr="\${cidr%"\${cidr##*[![:space:]]}"}"
    [[ -z "\$cidr" ]] && continue
    if [[ -n "\$GW" ]]; then
      if ! sudo ip route replace "\$cidr" via "\$GW" dev "\$DEV"; then
        echo "[!] Failed to add direct route: \$cidr" >&2
      fi
    else
      if ! sudo ip route replace "\$cidr" dev "\$DEV"; then
        echo "[!] Failed to add direct route: \$cidr" >&2
      fi
    fi
  done
}

del_direct_routes() {
  local cidr
  IFS=',' read -r -a items <<<"\$DIRECT_IP_CIDRS"
  for cidr in "\${items[@]}"; do
    cidr="\${cidr#"\${cidr%%[![:space:]]*}"}"
    cidr="\${cidr%"\${cidr##*[![:space:]]}"}"
    [[ -z "\$cidr" ]] && continue
    sudo ip route del "\$cidr" 2>/dev/null || true
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
  set_direct_routes

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
  del_direct_routes

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
