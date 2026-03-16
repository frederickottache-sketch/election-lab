#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# lib/common.sh  —  Shared variables, colours, logging helpers
# Election Cybersecurity Lab — Lite Edition
# ──────────────────────────────────────────────────────────────────────────────

# ── Colour codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m';  YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[1;34m';   BOLD='\033[1m';  RESET='\033[0m'

# ── Lab identity ──────────────────────────────────────────────────────────────
LAB_NAME="Election Cybersecurity Lab"
LAB_VERSION="1.0.0"
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_DIR="${HOME}/election_evidence"
LOG_FILE="${LAB_DIR}/lab.log"

# ── Docker network names & subnets ────────────────────────────────────────────
NET_DMZ="lab-election-dmz"
NET_INT="lab-election-int"
NET_MGMT="lab-election-mgmt"

SUBNET_DMZ="172.21.10.0/24"
SUBNET_INT="172.21.20.0/24"
SUBNET_MGMT="172.21.30.0/24"

GW_DMZ="172.21.10.1"
GW_INT="172.21.20.1"
GW_MGMT="172.21.30.1"

# ── Container IPs ─────────────────────────────────────────────────────────────
IP_PORTAL="172.21.10.10"        # Election portal (nginx)
IP_ELECTIONDB="172.21.20.10"    # Simulated voter-reg DB (PostgreSQL)
IP_SAMBA="172.21.20.20"         # Samba AD / LDAP
IP_RADIUS="172.21.20.21"        # FreeRADIUS
IP_ELASTIC="172.21.30.10"       # Elasticsearch
IP_KIBANA="172.21.30.11"        # Kibana
IP_WAZUH="172.21.30.12"         # Wazuh manager

# ── Container names ───────────────────────────────────────────────────────────
CTR_PORTAL="lab-election-portal"
CTR_ELECTIONDB="lab-election-db"
CTR_SAMBA="lab-election-samba"
CTR_RADIUS="lab-election-radius"
CTR_ELASTIC="lab-election-elastic"
CTR_KIBANA="lab-election-kibana"
CTR_WAZUH="lab-election-wazuh"

# ── Credentials ───────────────────────────────────────────────────────────────
AD_DOMAIN="election.local"
AD_REALM="ELECTION.LOCAL"
AD_ADMINPASS='El3ct10n@Admin2024!'
RADIUS_SECRET='R@dius$ecret2024'
DB_PASS='VoterDB@2024!'
ELASTIC_PASS='Elastic@2024!'

# ── Logging helpers ───────────────────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[INFO]${RESET}  $*" | tee -a "${LOG_FILE}"; }
log_ok()      { echo -e "${GREEN}[OK]${RESET}    $*" | tee -a "${LOG_FILE}"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*" | tee -a "${LOG_FILE}"; }
log_error()   { echo -e "${RED}[ERROR]${RESET} $*" | tee -a "${LOG_FILE}"; }
log_section() { echo -e "\n${BLUE}${BOLD}══════════════════════════════════════════${RESET}" | tee -a "${LOG_FILE}"
                echo -e "${BLUE}${BOLD}  $*${RESET}" | tee -a "${LOG_FILE}"
                echo -e "${BLUE}${BOLD}══════════════════════════════════════════${RESET}\n" | tee -a "${LOG_FILE}"; }
log_step()    { echo -e "${BOLD}  ▶  $*${RESET}" | tee -a "${LOG_FILE}"; }

# ── Requirement checks ────────────────────────────────────────────────────────
require_root() {
    [[ $EUID -eq 0 ]] || { log_error "This script must be run as root (sudo)."; exit 1; }
}

require_docker() {
    command -v docker &>/dev/null || { log_error "Docker not found. Run: sudo bash preflight.sh"; exit 1; }
    docker info &>/dev/null       || { log_error "Docker daemon not running. Run: sudo systemctl start docker"; exit 1; }
}

# ── Container helpers ─────────────────────────────────────────────────────────
container_running() { docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${1}$"; }

wait_for_container() {
    local name="$1" max="${2:-60}" n=0
    while ! container_running "$name"; do
        sleep 2; n=$((n+2))
        [[ $n -ge $max ]] && { log_error "Timeout waiting for container $name"; return 1; }
        echo -n "."
    done
    echo ""
    log_ok "Container ${name} is running"
}

wait_for_http() {
    local url="$1" max="${2:-90}" n=0
    log_info "Waiting for ${url}..."
    while ! curl -sf --max-time 3 "$url" &>/dev/null; do
        sleep 3; n=$((n+3))
        [[ $n -ge $max ]] && { log_warn "Timeout waiting for ${url} (may still be starting)"; return 1; }
        echo -n "."
    done
    echo ""
    log_ok "${url} is responding"
}

wait_for_port() {
    local host="$1" port="$2" max="${3:-90}" n=0
    log_info "Waiting for ${host}:${port}..."
    while ! nc -z "$host" "$port" 2>/dev/null; do
        sleep 3; n=$((n+3))
        [[ $n -ge $max ]] && { log_warn "Timeout waiting for ${host}:${port}"; return 1; }
        echo -n "."
    done
    echo ""
    log_ok "${host}:${port} is open"
}

# ── Evidence collection helper ────────────────────────────────────────────────
collect_evidence() {
    local tag="$1" content="$2"
    mkdir -p "${EVIDENCE_DIR}"
    local fname="${EVIDENCE_DIR}/${tag}_$(date +%Y%m%d_%H%M%S).txt"
    echo "$content" > "$fname"
    log_ok "Evidence saved: ${fname}"
}
