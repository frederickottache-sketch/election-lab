#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# sessions/session_evidence.sh
# Collect all election cybersecurity compliance evidence artefacts
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${LAB_DIR}/lib/common.sh"

log_section "Evidence Collection — Election Cybersecurity Compliance"

TS=$(date +%Y%m%d_%H%M%S)
mkdir -p "${EVIDENCE_DIR}"

# ── 1. Network configuration evidence ────────────────────────────────────────
log_step "Collecting network evidence..."
{
    echo "=== Network Configuration Evidence ==="
    echo "Collected: $(date -u)"
    echo ""
    echo "--- Docker Networks ---"
    docker network ls --filter "name=lab-election" --format "{{.ID}}\t{{.Name}}\t{{.Driver}}" 2>/dev/null || echo "Docker unavailable"
    echo ""
    echo "--- nftables Rules ---"
    nft list table inet lab_election 2>/dev/null || nft list ruleset 2>/dev/null | head -50 || echo "No nftables rules"
    echo ""
    echo "--- Container IPs ---"
    docker ps --filter "name=lab-election" --format "{{.Names}}" 2>/dev/null | while read c; do
        ip=$(docker inspect "$c" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null)
        echo "  $c  →  $ip"
    done
} > "${EVIDENCE_DIR}/network_evidence_${TS}.txt"
log_ok "Network evidence: network_evidence_${TS}.txt"

# ── 2. SIEM indices ───────────────────────────────────────────────────────────
log_step "Collecting SIEM evidence..."
{
    echo "=== SIEM Evidence ==="
    echo "Collected: $(date -u)"
    echo ""
    echo "--- Elasticsearch Indices ---"
    curl -sf "http://localhost:9200/_cat/indices?v" 2>/dev/null || echo "Elasticsearch unavailable"
    echo ""
    echo "--- Event Count ---"
    curl -sf "http://localhost:9200/election-security-events/_count" 2>/dev/null || echo "N/A"
    echo ""
    echo "--- Latest 5 Security Events ---"
    curl -sf "http://localhost:9200/election-security-events/_search?size=5&sort=timestamp:desc" \
        2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    for h in d.get('hits',{}).get('hits',[]):
        s=h['_source']
        print(f\"  [{s.get('severity','?'):8s}] {s.get('event_type','?'):20s} {s.get('message','')[:60]}\")
except: print('No events yet')
" 2>/dev/null || echo "N/A"
} > "${EVIDENCE_DIR}/siem_evidence_${TS}.txt"
log_ok "SIEM evidence: siem_evidence_${TS}.txt"

# ── 3. IDS / Snort evidence ───────────────────────────────────────────────────
log_step "Collecting IDS evidence..."
{
    echo "=== IDS Evidence ==="
    echo "Collected: $(date -u)"
    echo ""
    echo "--- Snort Rules ---"
    cat /etc/snort/rules/election.rules 2>/dev/null || echo "No Snort rules found"
    echo ""
    echo "--- Snort Alert Log (last 20 lines) ---"
    tail -20 /var/log/snort/alert 2>/dev/null || echo "No alerts yet"
} > "${EVIDENCE_DIR}/ids_evidence_${TS}.txt"
log_ok "IDS evidence: ids_evidence_${TS}.txt"

# ── 4. Threat intelligence evidence ──────────────────────────────────────────
log_step "Collecting threat intelligence evidence..."
{
    echo "=== Threat Intelligence Evidence ==="
    echo "Collected: $(date -u)"
    echo ""
    echo "--- IOC Store ---"
    python3 /opt/election-lab/threat-intel/ioc_store.py list 2>/dev/null || echo "IOC store not available"
    echo ""
    echo "--- STIX 2.1 Export ---"
    python3 /opt/election-lab/threat-intel/ioc_store.py export 2>/dev/null || echo "N/A"
    [[ -f /tmp/election_iocs_stix2.json ]] && {
        echo ""
        echo "--- STIX Bundle Summary ---"
        python3 -c "
import json
with open('/tmp/election_iocs_stix2.json') as f:
    b=json.load(f)
print(f'Bundle ID: {b[\"id\"]}')
print(f'Indicators: {len(b[\"objects\"])}')
for o in b['objects'][:3]:
    print(f'  {o[\"id\"]}  {o[\"name\"][:60]}')
print('  ... (see /tmp/election_iocs_stix2.json for full export)')
" 2>/dev/null
    }
} > "${EVIDENCE_DIR}/threat_intel_evidence_${TS}.txt"
log_ok "Threat intel evidence: threat_intel_evidence_${TS}.txt"

# ── 5. Forensics / chain of custody ──────────────────────────────────────────
log_step "Collecting forensics evidence..."
{
    echo "=== Forensics & Chain of Custody Evidence ==="
    echo "Collected: $(date -u)"
    echo ""
    echo "--- Chain of Custody Log ---"
    cat /forensics/evidence/chain_of_custody.json 2>/dev/null | python3 -c "
import json,sys
try:
    records=json.load(sys.stdin)
    for r in records:
        print(f\"  [{r.get('timestamp','?')}]  {r.get('action','?'):15s}  {r.get('target','?')}\")
except: print('No custody records yet')
" 2>/dev/null || echo "No chain of custody records yet"
    echo ""
    echo "--- Forensics Files ---"
    find /forensics -type f 2>/dev/null | head -20 || echo "No forensics files yet"
} > "${EVIDENCE_DIR}/forensics_evidence_${TS}.txt"
log_ok "Forensics evidence: forensics_evidence_${TS}.txt"

# ── 6. IAM evidence ───────────────────────────────────────────────────────────
log_step "Collecting IAM evidence..."
{
    echo "=== IAM Evidence ==="
    echo "Collected: $(date -u)"
    echo ""
    echo "--- Samba/LDAP Container Status ---"
    docker inspect lab-election-samba --format "Name: {{.Name}}\nStatus: {{.State.Status}}\nIP: {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" 2>/dev/null || echo "Samba container not running"
    echo ""
    echo "--- FreeRADIUS Container Status ---"
    docker inspect lab-election-radius --format "Name: {{.Name}}\nStatus: {{.State.Status}}" 2>/dev/null || echo "RADIUS container not running"
    echo ""
    echo "--- RADIUS Test Users Configured ---"
    echo "  jclerk    — County Clerk"
    echo "  jit       — IT Administrator"
    echo "  raudit    — Election Auditor"
    echo ""
    echo "  Test: radtest jclerk Clerk@2024! 127.0.0.1 0 'R@dius\$ecret2024'"
} > "${EVIDENCE_DIR}/iam_evidence_${TS}.txt"
log_ok "IAM evidence: iam_evidence_${TS}.txt"

# ── 7. Legal / notification readiness ─────────────────────────────────────────
log_step "Collecting legal & comms evidence..."
{
    echo "=== Legal & Communication Readiness Evidence ==="
    echo "Collected: $(date -u)"
    echo ""
    echo "--- Templates Available ---"
    ls -la /opt/election-lab/legal/notifications/ 2>/dev/null || echo "Templates not yet created"
    ls -la /opt/election-lab/legal/comms/ 2>/dev/null || echo ""
    echo ""
    echo "--- Compliance Check (now as incident time) ---"
    python3 /opt/election-lab/legal/check_compliance.py \
        --incident-date "$(date -u +%Y-%m-%dT%H:%M:%S)" --state DEFAULT 2>/dev/null || echo "Compliance checker not yet installed"
} > "${EVIDENCE_DIR}/legal_evidence_${TS}.txt"
log_ok "Legal evidence: legal_evidence_${TS}.txt"

# ── 8. Full running services snapshot ────────────────────────────────────────
log_step "Collecting running services snapshot..."
{
    echo "=== Running Services Snapshot ==="
    echo "Collected: $(date -u)"
    echo ""
    echo "--- Docker Containers ---"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | grep -E "lab-election|NAMES" || echo "No containers"
    echo ""
    echo "--- Systemd Election Services ---"
    systemctl status election-monitor 2>/dev/null | head -10 || echo "election-monitor: not installed"
    systemctl status snort-to-es 2>/dev/null | head -10 || echo "snort-to-es: not installed"
    echo ""
    echo "--- Memory Usage ---"
    free -h
    echo ""
    echo "--- Disk Usage ---"
    df -h / | awk 'NR==2'
} > "${EVIDENCE_DIR}/running_services_${TS}.txt"
log_ok "Running services: running_services_${TS}.txt"

# ── Summary ────────────────────────────────────────────────────────────────────
log_section "Evidence Collection Complete"
echo -e "  ${BOLD}Evidence directory:${RESET} ${EVIDENCE_DIR}"
echo ""
echo -e "  ${BOLD}Files collected:${RESET}"
ls -1 "${EVIDENCE_DIR}" | while read f; do
    echo -e "    ${GREEN}✔${RESET}  ${f}"
done
echo ""
echo -e "  ${CYAN}NIST SP 800-61 Compliance Mapping:${RESET}"
echo -e "    Preparation:   network_evidence, ids_evidence, threat_intel_evidence"
echo -e "    Detection:     siem_evidence, ids_evidence"
echo -e "    Containment:   forensics_evidence (chain of custody)"
echo -e "    Recovery:      running_services (post-restore verification)"
echo -e "    Post-Incident: legal_evidence (notification templates & compliance)"
echo ""
