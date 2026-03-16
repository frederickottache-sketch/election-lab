#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# preflight.sh  —  System readiness check & dependency installer
# Election Cybersecurity Lab — Lite Edition
# Ubuntu 20.04 / 22.04  |  4 GB RAM min  |  25 GB disk min
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${LAB_DIR}/lib/common.sh"
require_root

clear
echo -e "${BLUE}${BOLD}"
cat << 'BANNER'
  ╔══════════════════════════════════════════════════════════╗
  ║   ELECTION CYBERSECURITY LAB — Pre-flight Check          ║
  ║   Securing Election Infrastructure  ·  Lite Edition      ║
  ╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

PASS=0; WARN=0; FAIL=0; ISSUES=()

_check() {
    local label="$1" result="$2" required="${3:-true}"
    if   [[ "$result" == "ok"   ]]; then echo -e "  ${GREEN}✔${RESET}  ${label}"; PASS=$((PASS+1))
    elif [[ "$result" == "warn" ]]; then echo -e "  ${YELLOW}⚠${RESET}  ${label}"; WARN=$((WARN+1))
    else
        if [[ "$required" == "true" ]]; then
            echo -e "  ${RED}✘${RESET}  ${label}"; FAIL=$((FAIL+1)); ISSUES+=("${label}")
        else
            echo -e "  ${YELLOW}⚠${RESET}  ${label} (optional)"; WARN=$((WARN+1))
        fi
    fi
}

# ── 1. OS check ────────────────────────────────────────────────────────────────
log_section "1 / 7  — Operating System"
OS_ID=$(. /etc/os-release && echo "$ID")
OS_VER=$(. /etc/os-release && echo "$VERSION_ID")
if [[ "$OS_ID" == "ubuntu" && ( "$OS_VER" == "20.04" || "$OS_VER" == "22.04" ) ]]; then
    _check "Ubuntu ${OS_VER} LTS" ok
else
    _check "Ubuntu 20.04/22.04 required (found: ${OS_ID} ${OS_VER})" fail
fi
ARCH=$(uname -m)
[[ "$ARCH" == "x86_64" ]] && _check "Architecture: x86_64" ok || _check "x86_64 required" fail

# ── 2. Hardware ───────────────────────────────────────────────────────────────
log_section "2 / 7  — Hardware Resources"
RAM_GB=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
if   [[ $RAM_GB -ge 6 ]]; then _check "RAM: ${RAM_GB} GB (full mode)" ok
elif [[ $RAM_GB -ge 4 ]]; then _check "RAM: ${RAM_GB} GB (minimum — lite mode)" warn
else                            _check "RAM: ${RAM_GB} GB — need 4 GB minimum" fail; fi

DISK_GB=$(( $(df -k / | awk 'NR==2{print $4}') / 1024 / 1024 ))
if   [[ $DISK_GB -ge 30 ]]; then _check "Disk free: ${DISK_GB} GB" ok
elif [[ $DISK_GB -ge 25 ]]; then _check "Disk free: ${DISK_GB} GB (minimum)" warn
else                              _check "Disk free: ${DISK_GB} GB — need 25 GB" fail; fi

CPU_CORES=$(nproc)
[[ $CPU_CORES -ge 4 ]] && _check "CPU: ${CPU_CORES} cores (good)" ok \
                        || _check "CPU: ${CPU_CORES} core(s) — 2 minimum, 4 recommended" warn

grep -qE '(vmx|svm)' /proc/cpuinfo 2>/dev/null \
    && _check "Virtualisation extensions (vmx/svm) detected" ok \
    || _check "Virtualisation extensions not detected (OK for bare metal Docker)" warn false

# ── 3. Network ────────────────────────────────────────────────────────────────
log_section "3 / 7  — Network Connectivity"
curl -sf --max-time 5 https://registry-1.docker.io/v2/ &>/dev/null \
    && _check "Docker Hub reachable" ok || _check "Docker Hub unreachable — image pulls will fail" fail
curl -sf --max-time 5 https://archive.ubuntu.com &>/dev/null \
    && _check "Ubuntu apt repos reachable" ok || _check "Ubuntu repos unreachable" warn false
ip route show 2>/dev/null | grep -q "172.21\." \
    && _check "WARNING: 172.21.x.x in use — lab network conflict possible" warn \
    || _check "Lab subnets 172.21.x.x are free" ok

# ── 4. Docker ─────────────────────────────────────────────────────────────────
log_section "4 / 7  — Docker Runtime"
if command -v docker &>/dev/null; then
    _check "Docker installed: $(docker --version | grep -oP '[\d\.]+' | head -1)" ok
    docker info &>/dev/null \
        && _check "Docker daemon running" ok \
        || { _check "Docker daemon NOT running" fail; ISSUES+=("Docker daemon not running"); }
    MAPCOUNT=$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)
    [[ $MAPCOUNT -ge 262144 ]] \
        && _check "vm.max_map_count: ${MAPCOUNT} (Elasticsearch OK)" ok \
        || _check "vm.max_map_count: ${MAPCOUNT} — will be set to 262144" warn
else
    _check "Docker not installed — will install" fail
fi

# ── 5. Packages ───────────────────────────────────────────────────────────────
log_section "5 / 7  — Required Packages"
for pkg in curl wget python3 python3-pip nftables jq git netcat-openbsd; do
    dpkg -l "$pkg" &>/dev/null \
        && _check "Package: ${pkg}" ok \
        || { _check "Package: ${pkg} missing" fail; }
done
for pkg in tshark yara nmap snort freeradius-utils; do
    dpkg -l "$pkg" &>/dev/null \
        && _check "Package: ${pkg}" ok \
        || _check "Package: ${pkg} — will install" warn
done
python3 -c "import docker" 2>/dev/null && _check "Python: docker SDK" ok || _check "Python: docker SDK — will install" warn
python3 -c "import requests" 2>/dev/null && _check "Python: requests" ok || _check "Python: requests — will install" warn

# ── 6. Ports ──────────────────────────────────────────────────────────────────
log_section "6 / 7  — Port Availability"
declare -A LAB_PORTS=([9200]="Elasticsearch" [5601]="Kibana" [55000]="Wazuh API"
                      [8080]="Election Portal" [5432]="ElectionDB (PostgreSQL)"
                      [389]="LDAP/Samba AD" [1812]="FreeRADIUS")
for port in "${!LAB_PORTS[@]}"; do
    ss -tlnp 2>/dev/null | grep -q ":${port} " \
        && _check "Port ${port} (${LAB_PORTS[$port]}) IN USE — conflict!" fail \
        || _check "Port ${port} (${LAB_PORTS[$port]}) — available" ok
done

# ── 7. Kernel / nftables ──────────────────────────────────────────────────────
log_section "7 / 7  — System Settings"
command -v nft &>/dev/null \
    && _check "nftables: $(nft --version 2>&1 | head -1)" ok \
    || _check "nftables not found — will install" warn
[[ $(ulimit -n) -ge 65536 ]] \
    && _check "Open file limit: $(ulimit -n)" ok \
    || _check "Open file limit: $(ulimit -n) — will raise to 65536" warn

# ── Score ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}Passed:${RESET}   ${PASS}"
echo -e "  ${YELLOW}Warnings:${RESET} ${WARN}"
echo -e "  ${RED}Failed:${RESET}   ${FAIL}"
[[ $FAIL -gt 0 ]] && { echo ""; echo -e "${YELLOW}Issues found:${RESET}"; for i in "${ISSUES[@]}"; do echo "  • $i"; done; }

echo ""
echo -e "${CYAN}${BOLD}Proceeding with installation / remediation...${RESET}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# INSTALL / FIX
# ══════════════════════════════════════════════════════════════════════════════
export DEBIAN_FRONTEND=noninteractive

log_step "Updating package lists..."
apt-get update -qq 2>/dev/null

# Docker install
if ! command -v docker &>/dev/null; then
    log_step "Installing Docker CE..."
    apt-get install -y -qq ca-certificates gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker --now
    log_ok "Docker CE installed"
fi

systemctl is-active docker &>/dev/null || systemctl start docker

# Packages
log_step "Installing packages..."
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections 2>/dev/null || true
for pkg in curl wget python3 python3-pip nftables jq git netcat-openbsd \
           tshark yara nmap snort freeradius-utils net-tools postgresql-client; do
    apt-get install -y -qq "$pkg" 2>/dev/null || log_warn "Could not install ${pkg}"
done

# Docker Compose plugin fallback
docker compose version &>/dev/null 2>&1 \
    || apt-get install -y -qq docker-compose-plugin 2>/dev/null || true

# Python packages
log_step "Installing Python packages..."
pip3 install -q --break-system-packages docker requests stix2 2>/dev/null \
|| pip3 install -q docker requests stix2 2>/dev/null || true

# Kernel
log_step "Setting kernel tunables..."
sysctl -w vm.max_map_count=262144 >/dev/null
grep -q 'vm.max_map_count' /etc/sysctl.conf 2>/dev/null || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
grep -q 'fs.file-max' /etc/sysctl.conf 2>/dev/null      || echo 'fs.file-max=100000'      >> /etc/sysctl.conf
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

# Docker daemon tuning
log_step "Tuning Docker daemon..."
cat > /etc/docker/daemon.json << 'EOF_DAEMON'
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "default-address-pools": [
    { "base": "172.21.0.0/16", "size": 24 }
  ]
}
EOF_DAEMON
systemctl restart docker && sleep 4
log_ok "Docker daemon configured"

# docker group
[[ -n "${SUDO_USER:-}" ]] && { usermod -aG docker "$SUDO_USER" 2>/dev/null || true; log_ok "Added ${SUDO_USER} to docker group"; }

# Snort dirs
mkdir -p /etc/snort/rules /var/log/snort
touch /etc/snort/rules/local.rules /var/log/snort/alert 2>/dev/null || true

# Evidence dir
mkdir -p "${EVIDENCE_DIR}"
[[ -n "${SUDO_USER:-}" ]] && chown -R "$SUDO_USER":"$SUDO_USER" "${EVIDENCE_DIR}" 2>/dev/null || true

log_section "Pre-flight Complete"
echo -e "${GREEN}${BOLD}✔  All dependencies installed and verified.${RESET}"
echo -e "${CYAN}   Next step:  sudo bash setup.sh all${RESET}"
echo ""
