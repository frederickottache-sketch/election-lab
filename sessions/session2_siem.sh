#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# sessions/session2_siem.sh
# Session 2 — SIEM & Logging: Elasticsearch + Kibana + Wazuh agent
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${LAB_DIR}/lib/common.sh"
require_root; require_docker

log_section "Session 2 — SIEM: Elasticsearch + Kibana + Wazuh"

# Ensure vm.max_map_count is set (required for Elasticsearch)
sysctl -w vm.max_map_count=262144 >/dev/null

# ── Elasticsearch ──────────────────────────────────────────────────────────────
log_step "Deploying Elasticsearch 8..."
docker rm -f "$CTR_ELASTIC" 2>/dev/null || true

docker run -d \
    --name "$CTR_ELASTIC" \
    --network "$NET_MGMT" \
    --ip "$IP_ELASTIC" \
    -p 9200:9200 \
    --memory 900m \
    -e "discovery.type=single-node" \
    -e "xpack.security.enabled=false" \
    -e "xpack.security.http.ssl.enabled=false" \
    -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
    -e "cluster.name=election-lab-cluster" \
    -e "node.name=election-siem-01" \
    --ulimit nofile=65536:65536 \
    --restart unless-stopped \
    elasticsearch:8.11.0
log_ok "Elasticsearch container started — waiting for it to be healthy..."
wait_for_http "http://localhost:9200" 120

# ── Create election indices & mappings ────────────────────────────────────────
log_step "Creating Elasticsearch indices..."
sleep 5

# Election security events index
curl -sf -X PUT "http://localhost:9200/election-security-events" \
    -H "Content-Type: application/json" \
    -d '{
      "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
      "mappings": {
        "properties": {
          "timestamp":  { "type": "date" },
          "event_type": { "type": "keyword" },
          "source_ip":  { "type": "ip" },
          "user":       { "type": "keyword" },
          "severity":   { "type": "keyword" },
          "message":    { "type": "text" },
          "mitre_tactic": { "type": "keyword" },
          "mitre_technique": { "type": "keyword" }
        }
      }
    }' >/dev/null && log_ok "Index election-security-events created"

# Voter DB audit log index
curl -sf -X PUT "http://localhost:9200/election-db-audit" \
    -H "Content-Type: application/json" \
    -d '{
      "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
      "mappings": {
        "properties": {
          "timestamp":    { "type": "date" },
          "query_type":   { "type": "keyword" },
          "rows_accessed":{ "type": "integer" },
          "user":         { "type": "keyword" },
          "source_ip":    { "type": "ip" }
        }
      }
    }' >/dev/null && log_ok "Index election-db-audit created"

# Seed sample security events
python3 - << 'PYEOF'
import json, urllib.request, datetime, random

events = [
    {"event_type":"AUTH_FAILURE","source_ip":"10.0.40.10","user":"unknown",
     "severity":"HIGH","message":"Failed SSH login attempt to ElectionDB server",
     "mitre_tactic":"Initial Access","mitre_technique":"T1110 Brute Force"},
    {"event_type":"PORT_SCAN","source_ip":"10.0.40.10","user":None,
     "severity":"MEDIUM","message":"Nmap port scan detected against 172.21.20.10",
     "mitre_tactic":"Reconnaissance","mitre_technique":"T1595 Active Scanning"},
    {"event_type":"BULK_QUERY","source_ip":"172.21.20.50","user":"analyst1",
     "severity":"HIGH","message":"Unusual bulk SELECT on voters table — 4000 rows accessed",
     "mitre_tactic":"Collection","mitre_technique":"T1005 Data from Local System"},
    {"event_type":"FIM_ALERT","source_ip":"172.21.20.10","user":"root",
     "severity":"CRITICAL","message":"voter_export.sh created in /tmp — file integrity alert",
     "mitre_tactic":"Exfiltration","mitre_technique":"T1041 Exfiltration Over C2"},
    {"event_type":"AUTH_SUCCESS","source_ip":"172.21.20.50","user":"jclerk",
     "severity":"INFO","message":"Normal login to election management console",
     "mitre_tactic":None,"mitre_technique":None},
]
base = datetime.datetime(2024, 11, 5, 8, 0, 0)
for i, ev in enumerate(events):
    ev["timestamp"] = (base + datetime.timedelta(minutes=i*23)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = json.dumps(ev).encode()
    req = urllib.request.Request("http://localhost:9200/election-security-events/_doc",
          data=data, headers={"Content-Type":"application/json"}, method="POST")
    urllib.request.urlopen(req)
print("Sample election security events seeded")
PYEOF

# ── Kibana ────────────────────────────────────────────────────────────────────
log_step "Deploying Kibana..."
docker rm -f "$CTR_KIBANA" 2>/dev/null || true

docker run -d \
    --name "$CTR_KIBANA" \
    --network "$NET_MGMT" \
    --ip "$IP_KIBANA" \
    -p 5601:5601 \
    --memory 800m \
    -e "ELASTICSEARCH_HOSTS=http://${IP_ELASTIC}:9200" \
    -e "SERVER_NAME=election-kibana" \
    -e "TELEMETRY_ENABLED=false" \
    -e "XPACK_SECURITY_ENABLED=false" \
    -e "NODE_OPTIONS=--max-old-space-size=600" \
    --restart unless-stopped \
    kibana:8.11.0
log_ok "Kibana container started — waiting..."
wait_for_http "http://localhost:5601/api/status" 360
# After wait_for_http for Kibana
log_step "Waiting for Kibana to become fully available..."
for i in $(seq 1 30); do
   STATUS=$(curl -sf http://localhost:5601/api/status 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',{}).get('overall',{}).get('level',''))" 2>/dev/null)
   if [ "$STATUS" = "available" ]; then
      log_ok "Kibana is fully available"
      break
   fi
   log_info "Kibana status: ${STATUS:-initializing} (attempt $i/30)..."
   sleep 10
done
# Wait and poll manually
until curl -sf http://localhost:5601/api/status | grep -1 '"level":"available"'; do
   echo "Still waiting...$(date)"
   sleep 15
done
echo "Kibana is ready! Open http://localhost:5601"

# ── Import Kibana saved objects (index pattern) ───────────────────────────────
log_step "Configuring Kibana index patterns..."
sleep 10
curl -sf -X POST "http://localhost:5601/api/saved_objects/index-pattern/election-security-*" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    -d '{"attributes":{"title":"election-security-*","timeFieldName":"timestamp"}}' \
    >/dev/null 2>&1 && log_ok "Kibana index pattern created" || log_warn "Index pattern — will create on first login"

# ── Wazuh agent (host-based IDS) ──────────────────────────────────────────────
# ── Local log monitor (Python-based fallback / supplement) ───────────────────
_setup_log_monitor() {
    log_step "Setting up local election log monitor..."
    mkdir -p /opt/election-lab/monitor /var/log/election-lab

    cat > /opt/election-lab/monitor/election_monitor.py << 'PYEOF2'
#!/usr/bin/env python3
"""
Election Log Monitor — sends alerts to Elasticsearch
Watches: /var/log/auth.log, /var/log/syslog, custom election logs
"""
import os, re, json, time, urllib.request, datetime, subprocess

ES_URL = "http://localhost:9200"
INDEX  = "election-security-events"
WATCH  = ["/var/log/auth.log", "/var/log/syslog"]
POLL   = 5  # seconds

RULES = [
    {"pattern": r"Failed password",      "severity": "HIGH",     "event_type": "AUTH_FAILURE",   "tactic": "Initial Access",    "technique": "T1110"},
    {"pattern": r"Invalid user",         "severity": "HIGH",     "event_type": "AUTH_FAILURE",   "tactic": "Initial Access",    "technique": "T1110"},
    {"pattern": r"Accepted publickey",   "severity": "INFO",     "event_type": "AUTH_SUCCESS",   "tactic": None,                "technique": None},
    {"pattern": r"useradd|usermod",      "severity": "MEDIUM",   "event_type": "USER_MGMT",      "tactic": "Persistence",       "technique": "T1136"},
    {"pattern": r"sudo.*COMMAND",        "severity": "MEDIUM",   "event_type": "PRIV_ESCALATION","tactic": "Privilege Escalation","technique": "T1548"},
    {"pattern": r"ELECTION_ALERT",       "severity": "CRITICAL", "event_type": "ELECTION_EVENT", "tactic": "Impact",            "technique": "T1485"},
]

def send_event(ev):
    try:
        data = json.dumps(ev).encode()
        req  = urllib.request.Request(f"{ES_URL}/{INDEX}/_doc",
               data=data, headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[WARN] ES send failed: {e}")

def tail_file(path, pos):
    try:
        with open(path) as f:
            f.seek(pos)
            lines = f.readlines()
            return f.tell(), lines
    except Exception:
        return pos, []

positions = {f: os.path.getsize(f) if os.path.exists(f) else 0 for f in WATCH}

print(f"[Election Monitor] Watching: {WATCH}")
while True:
    for fpath in WATCH:
        pos, lines = tail_file(fpath, positions.get(fpath, 0))
        positions[fpath] = pos
        for line in lines:
            for rule in RULES:
                if re.search(rule["pattern"], line, re.I):
                    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                    send_event({
                        "timestamp":      datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "event_type":     rule["event_type"],
                        "severity":       rule["severity"],
                        "source_ip":      ip_match.group(1) if ip_match else "127.0.0.1",
                        "message":        line.strip(),
                        "mitre_tactic":   rule["tactic"],
                        "mitre_technique":rule["technique"],
                        "source_file":    fpath,
                    })
    time.sleep(POLL)
PYEOF2
    chmod +x /opt/election-lab/monitor/election_monitor.py

    # Systemd unit
    cat > /etc/systemd/system/election-monitor.service << 'SYSD'
[Unit]
Description=Election Security Log Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/election-lab/monitor/election_monitor.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/election-lab/monitor.log
StandardError=append:/var/log/election-lab/monitor.log

[Install]
WantedBy=multi-user.target
SYSD
    systemctl daemon-reload
    systemctl enable election-monitor --now 2>/dev/null || true
    log_ok "Election log monitor service started"
}



log_step "Setting up Wazuh IDS rules for election monitoring..."

# Install Wazuh agent if available; else use ossec-hids as lightweight alternative
if ! command -v wazuh-agent &>/dev/null && ! command -v ossec-control &>/dev/null; then
    log_step "Installing Wazuh agent (lightweight)..."
    # Add Wazuh repo
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH 2>/dev/null \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list 2>/dev/null || true
    apt-get update -qq 2>/dev/null
    WAZUH_MANAGER=localhost apt-get install -y -qq wazuh-agent 2>/dev/null || {
        log_warn "Wazuh agent install failed — using local log monitoring fallback"
        _setup_log_monitor
    }
else
    log_ok "Wazuh/OSSEC already present"
fi

# Always set up the log monitor (works alongside Wazuh)
_setup_log_monitor

# ── Collect evidence ──────────────────────────────────────────────────────────
log_step "Collecting SIEM evidence..."
{
    echo "=== Election Lab SIEM Evidence ==="
    echo "Date: $(date -u)"
    echo ""
    echo "=== Elasticsearch Indices ==="
    curl -sf "http://localhost:9200/_cat/indices?v" 2>/dev/null
    echo ""
    echo "=== Sample Events ==="
    curl -sf "http://localhost:9200/election-security-events/_search?pretty&size=3" 2>/dev/null
    echo ""
    echo "=== Running Services ==="
    docker ps --format "{{.Names}}\t{{.Status}}" | grep lab-election
} > "${EVIDENCE_DIR}/siem_config_$(date +%Y%m%d_%H%M%S).txt"

log_section "Session 2 Complete"
echo -e "  ${GREEN}✔${RESET}  Elasticsearch:  http://localhost:9200"
echo -e "  ${GREEN}✔${RESET}  Kibana:         http://localhost:5601"
echo -e "  ${GREEN}✔${RESET}  Election log monitor: /opt/election-lab/monitor/"
echo ""
log_section "Session 2 Exercise"
echo -e "${YELLOW} Exercise commands:${RESET}"
echo -e "${BOLD} Exercise 2.1:${RESET}"
echo -e "${CYAN}curl http://localhost:9200/_cat/indices?v${RESET}"
echo ""
echo -e "${BOLD} Exercise 2.2:${RESET}"
echo -e "${CYAN}curl 'http://localhost:9200/election-security-events/_search?pretty'${RESET}"
echo ""
echo -e "${BOLD} Exercise 2.3:${RESET}"
echo -e "${CYAN}sudo tail -f /var/log/election-lab/monitor.log${RESET}"
echo ""
echo "  # Then open Kibana: http://localhost:5601"
echo ""
echo ""
