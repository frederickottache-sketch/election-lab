#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# sessions/session3_ids.sh
# Session 3 — Incident Detection: Snort IDS + Threat Intelligence (MISP-lite)
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${LAB_DIR}/lib/common.sh"
require_root; require_docker

log_section "Session 3 — Incident Detection: Snort IDS + Threat Intelligence"

# ── Step 1: Election-specific Snort rules ────────────────────────────────────
log_step "Writing election-specific Snort detection rules..."
mkdir -p /etc/snort/rules /var/log/snort
touch /var/log/snort/alert

cat > /etc/snort/rules/election.rules << 'SNORTRULES'
# ──────────────────────────────────────────────────────────────────────────────
# Election Cybersecurity Lab — Custom Snort Rules
# ──────────────────────────────────────────────────────────────────────────────

# Rule 1: Port scan against ElectionDB
alert tcp any any -> 172.21.20.10 any \
    (msg:"ELECTION RECON: Port scan against ElectionDB"; \
     flags:S; detection_filter: track by_src,count 20,seconds 10; \
     sid:9000001; rev:1; classtype:bad-unknown;)

# Rule 2: Bulk database query (many short connections)
alert tcp any any -> 172.21.20.10 5432 \
    (msg:"ELECTION DB: High-frequency DB connection — potential bulk exfil"; \
     detection_filter: track by_src,count 50,seconds 60; \
     sid:9000002; rev:1; classtype:policy-violation;)

# Rule 3: Known C2 beacon pattern (periodic HTTP to external)
alert tcp 172.21.0.0/16 any -> any 80 \
    (msg:"ELECTION C2: Possible outbound C2 beacon from election network"; \
     content:"User-Agent: Mozilla/4.0"; \
     detection_filter: track by_src,count 5,seconds 120; \
     sid:9000003; rev:1; classtype:trojan-activity;)

# Rule 4: DMZ attempting to reach Internal (Zero-Trust violation)
alert ip 172.21.10.0/24 any -> 172.21.20.0/24 any \
    (msg:"ELECTION ZT-VIOLATION: DMZ attempting to reach Internal segment"; \
     sid:9000004; rev:1; classtype:policy-violation;)

# Rule 5: SSH brute force
alert tcp any any -> 172.21.20.10 22 \
    (msg:"ELECTION AUTH: SSH brute-force detected against ElectionDB"; \
     flags:S; detection_filter: track by_src,count 5,seconds 60; \
     sid:9000005; rev:1; classtype:bad-unknown;)

# Rule 6: After-hours database access (rough pattern — alerts all connections off-peak)
alert tcp any any -> 172.21.20.10 5432 \
    (msg:"ELECTION POLICY: Database access — verify if within operating hours"; \
     detection_filter: track by_src,count 1,seconds 3600; \
     sid:9000006; rev:1; classtype:policy-violation;)

# Rule 7: SQL injection pattern in HTTP to portal
alert tcp any any -> 172.21.10.10 80 \
    (msg:"ELECTION SQLI: Possible SQL injection attempt on election portal"; \
     content:"UNION SELECT"; nocase; \
     sid:9000007; rev:1; classtype:web-application-attack;)

# Rule 8: Voter data keyword in exfiltration attempt
alert tcp 172.21.0.0/16 any -> !172.21.0.0/16 any \
    (msg:"ELECTION EXFIL: Voter data keyword detected in outbound traffic"; \
     content:"voter_id"; \
     sid:9000008; rev:1; classtype:policy-violation;)
SNORTRULES
log_ok "Election Snort rules written: /etc/snort/rules/election.rules"

# ── Step 2: Write Snort config ────────────────────────────────────────────────
log_step "Configuring Snort..."

# Get the internal bridge interface
INTERNAL_IFACE=$(ip link show 2>/dev/null \
    | grep -E "br-(int|lab-election-int|election-int)" \
    | awk '{print $2}' | tr -d ':' | head -1)
[[ -z "$INTERNAL_IFACE" ]] && INTERNAL_IFACE="any"
log_info "Snort will monitor interface: ${INTERNAL_IFACE}"

cat > /etc/snort/snort.conf << SNORTCONF
# Election Lab Snort Configuration
include /etc/snort/classification.config
var HOME_NET 172.21.0.0/16
var EXTERNAL_NET !\$HOME_NET
var ELECTION_DB 172.21.20.10
var ELECTION_DMZ 172.21.10.0/24
var ELECTION_MGMT 172.21.30.0/24

# Decoder
config disable_decode_alerts
config disable_tcpopt_experimental_alerts

# Output — fast alert format for easy parsing
output alert_fast: /var/log/snort/alert
output log_tcpdump: /var/log/snort/election.pcap

# Include election rules
include /etc/snort/rules/election.rules
SNORTCONF

# Validate config (non-fatal — snort may not be fully installed)
if command -v snort &>/dev/null; then
    snort -T -c /etc/snort/snort.conf -i "$INTERNAL_IFACE" 2>/dev/null \
        && log_ok "Snort config validated" \
        || log_warn "Snort config validation — check manually: snort -T -c /etc/snort/snort.conf"
fi

# ── Step 3: Snort alert forwarder to Elasticsearch ────────────────────────────
log_step "Setting up Snort-to-Elasticsearch alert forwarder..."
mkdir -p /opt/election-lab/ids

cat > /opt/election-lab/ids/snort_to_es.py << 'PYEOF'
#!/usr/bin/env python3
"""
Snort Alert → Elasticsearch Forwarder
Tails /var/log/snort/alert and ships parsed alerts to ES
"""
import os, re, json, time, urllib.request, datetime

ES_URL    = "http://localhost:9200"
INDEX     = "election-security-events"
ALERT_LOG = "/var/log/snort/alert"

# Snort fast-alert format: MM/DD-HH:MM:SS.uuuuuu  [**] [sid:X:Y] msg [**] ...
PATTERN = re.compile(
    r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2})\.\d+\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]'
    r'.*?(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s+->\s+(\d+\.\d+\.\d+\.\d+)(?::(\d+))?'
)

SEVERITY_MAP = {
    "RECON": "MEDIUM", "AUTH": "HIGH", "DB": "HIGH",
    "C2": "CRITICAL", "ZT-VIOLATION": "HIGH", "SQLI": "HIGH",
    "EXFIL": "CRITICAL", "POLICY": "MEDIUM"
}

def parse_alert(line):
    m = PATTERN.search(line)
    if not m: return None
    msg = m.group(3).strip()
    sev = "MEDIUM"
    for k, v in SEVERITY_MAP.items():
        if k in msg.upper():
            sev = v; break
    return {
        "timestamp":  datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "IDS_ALERT",
        "severity":   sev,
        "message":    msg,
        "source_ip":  m.group(4),
        "source_port":m.group(5),
        "dest_ip":    m.group(6),
        "dest_port":  m.group(7),
        "snort_sid":  m.group(2),
        "source_file":"snort",
    }

def send(ev):
    try:
        data = json.dumps(ev).encode()
        req  = urllib.request.Request(f"{ES_URL}/{INDEX}/_doc",
               data=data, headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[WARN] {e}")

print(f"[Snort→ES] Tailing {ALERT_LOG}")
pos = os.path.getsize(ALERT_LOG) if os.path.exists(ALERT_LOG) else 0
while True:
    try:
        with open(ALERT_LOG) as f:
            f.seek(pos)
            for line in f:
                ev = parse_alert(line)
                if ev:
                    send(ev)
                    print(f"[ALERT] {ev['severity']}: {ev['message']}")
            pos = f.tell()
    except Exception as e:
        print(f"[WARN] {e}")
    time.sleep(3)
PYEOF
chmod +x /opt/election-lab/ids/snort_to_es.py

# Systemd service
cat > /etc/systemd/system/snort-to-es.service << 'SYSD'
[Unit]
Description=Snort Alert Forwarder to Elasticsearch
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/election-lab/ids/snort_to_es.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/election-lab/snort-forwarder.log
StandardError=append:/var/log/election-lab/snort-forwarder.log

[Install]
WantedBy=multi-user.target
SYSD
mkdir -p /var/log/election-lab
systemctl daemon-reload
systemctl enable snort-to-es --now 2>/dev/null || true
log_ok "Snort-to-ES forwarder service started"

# ── Step 4: MISP-lite threat intel store ──────────────────────────────────────
log_step "Setting up MISP-lite local IOC store..."
# Full MISP requires 2 GB+ RAM — we use a lightweight Python IOC store + feed parser
mkdir -p /opt/election-lab/threat-intel

cat > /opt/election-lab/threat-intel/ioc_store.py << 'PYEOF2'
#!/usr/bin/env python3
"""
MISP-lite: Local IOC store for election security lab
Provides: IOC ingestion, search, STIX 2.1 export, feed simulation
"""
import json, os, datetime, argparse, urllib.request

STORE_DIR  = "/opt/election-lab/threat-intel/iocs"
FEEDS_DIR  = "/opt/election-lab/threat-intel/feeds"
ES_URL     = "http://localhost:9200"
IOC_INDEX  = "election-threat-intel"
os.makedirs(STORE_DIR, exist_ok=True)
os.makedirs(FEEDS_DIR, exist_ok=True)

# ── Seed election-relevant IOCs ───────────────────────────────────────────────
SEED_IOCS = [
    {"type":"ip-dst",    "value":"185.220.101.45",  "tags":["APT","election","C2"],         "tlp":"WHITE", "confidence":85},
    {"type":"ip-dst",    "value":"91.108.4.220",    "tags":["DDoS","election","botnet"],     "tlp":"WHITE", "confidence":70},
    {"type":"domain",    "value":"vote-check.ru",   "tags":["phishing","election","lure"],   "tlp":"WHITE", "confidence":90},
    {"type":"domain",    "value":"myvoterinfo.xyz",  "tags":["phishing","credential-theft"], "tlp":"WHITE", "confidence":88},
    {"type":"md5",       "value":"d41d8cd98f00b204e9800998ecf8427e",
                         "tags":["ransomware","election-targeted"],                           "tlp":"GREEN", "confidence":75},
    {"type":"url",       "value":"http://185.220.101.45/c2/beacon",
                         "tags":["C2","election","APT"],                                      "tlp":"GREEN", "confidence":92},
    {"type":"email",     "value":"admin@election-update.com",
                         "tags":["phishing","spearphish","election-official"],                "tlp":"WHITE", "confidence":80},
    {"type":"filename",  "value":"voter_export_tool.exe",
                         "tags":["malware","data-theft","election"],                          "tlp":"GREEN", "confidence":78},
]

def save_ioc(ioc):
    ioc["id"]        = f"ioc-{len(os.listdir(STORE_DIR))+1:04d}"
    ioc["created"]   = datetime.datetime.utcnow().isoformat()
    ioc["source"]    = ioc.get("source", "local")
    fpath = os.path.join(STORE_DIR, f"{ioc['id']}.json")
    with open(fpath, "w") as f:
        json.dump(ioc, f, indent=2)
    # Also index in ES
    try:
        data = json.dumps({"timestamp": ioc["created"], "ioc_type": ioc["type"],
                           "ioc_value": ioc["value"], "tags": ",".join(ioc.get("tags",[])),
                           "confidence": ioc.get("confidence", 50), "tlp": ioc.get("tlp","WHITE")}).encode()
        req  = urllib.request.Request(f"{ES_URL}/{IOC_INDEX}/_doc",
               data=data, headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass
    return ioc["id"]

def load_all():
    iocs = []
    for fname in sorted(os.listdir(STORE_DIR)):
        if fname.endswith(".json"):
            with open(os.path.join(STORE_DIR, fname)) as f:
                iocs.append(json.load(f))
    return iocs

def search_iocs(value):
    return [i for i in load_all() if value.lower() in i.get("value","").lower()
            or value.lower() in ",".join(i.get("tags",[])).lower()]

def export_stix2():
    iocs = load_all()
    bundle = {
        "type": "bundle",
        "id":   f"bundle--election-lab-{datetime.date.today()}",
        "spec_version": "2.1",
        "objects": []
    }
    for ioc in iocs:
        pattern = f"[{ioc['type']} = '{ioc['value']}']"
        if ioc["type"] == "ip-dst":
            pattern = f"[ipv4-addr:value = '{ioc['value']}']"
        elif ioc["type"] == "domain":
            pattern = f"[domain-name:value = '{ioc['value']}']"
        elif ioc["type"] == "url":
            pattern = f"[url:value = '{ioc['value']}']"
        elif ioc["type"] == "md5":
            pattern = f"[file:hashes.MD5 = '{ioc['value']}']"
        bundle["objects"].append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc['id']}",
            "created": ioc["created"],
            "modified": ioc["created"],
            "name": f"Election IOC: {ioc['type']} {ioc['value']}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc["created"],
            "labels": ioc.get("tags", []),
        })
    return bundle

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MISP-lite IOC Store")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("seed", help="Seed election IOCs")
    p_add = sub.add_parser("add",  help="Add IOC: --type ip-dst --value x --tags a,b")
    p_add.add_argument("--type");  p_add.add_argument("--value")
    p_add.add_argument("--tags", default="");  p_add.add_argument("--tlp", default="WHITE")
    p_srch = sub.add_parser("search", help="Search IOCs"); p_srch.add_argument("value")
    sub.add_parser("list",   help="List all IOCs")
    sub.add_parser("export", help="Export STIX 2.1 bundle")
    args = parser.parse_args()

    if args.cmd == "seed":
        for ioc in SEED_IOCS:
            iid = save_ioc(dict(ioc))
            print(f"  Seeded: {iid}  {ioc['type']}  {ioc['value']}")
        print(f"\nSeeded {len(SEED_IOCS)} election IOCs")

    elif args.cmd == "add":
        iid = save_ioc({"type":args.type, "value":args.value,
                        "tags":args.tags.split(",") if args.tags else [],
                        "tlp":args.tlp, "source":"manual"})
        print(f"Added IOC: {iid}")

    elif args.cmd == "search":
        results = search_iocs(args.value)
        if results:
            for r in results:
                print(f"  [{r['id']}]  {r['type']:12s}  {r['value']}  tags={r.get('tags',[])}  confidence={r.get('confidence','?')}")
        else:
            print("  No matching IOCs found")

    elif args.cmd == "list":
        for r in load_all():
            print(f"  [{r['id']}]  {r['type']:12s}  {r['value']}")

    elif args.cmd == "export":
        bundle = export_stix2()
        out = "/tmp/election_iocs_stix2.json"
        with open(out, "w") as f:
            json.dump(bundle, f, indent=2)
        print(f"STIX 2.1 bundle exported: {out}  ({len(bundle['objects'])} indicators)")

    else:
        parser.print_help()
PYEOF2
chmod +x /opt/election-lab/threat-intel/ioc_store.py

# Seed IOCs
python3 /opt/election-lab/threat-intel/ioc_store.py seed
log_ok "Election IOC store seeded"

# Optionally show the count
IOC_COUNT=$(curl -sf "http://localhost:9200/election-iocs/_count" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "?")
log_ok "Election IOC store seeded with ${IOC_COUNT} indicators"

# Create Elasticsearch index for IOCs
curl -sf -X PUT "http://localhost:9200/election-threat-intel" \
    -H "Content-Type: application/json" \
    -d '{"settings":{"number_of_shards":1,"number_of_replicas":0}}' \
    >/dev/null 2>&1 || true

# ── Collect evidence ──────────────────────────────────────────────────────────
{
    echo "=== Election Lab IDS Evidence ==="
    echo "Date: $(date -u)"
    echo ""
    echo "=== Snort Rules ==="
    cat /etc/snort/rules/election.rules
    echo ""
    echo "=== IOC Store ==="
    python3 /opt/election-lab/threat-intel/ioc_store.py list
} > "${EVIDENCE_DIR}/ids_config_$(date +%Y%m%d_%H%M%S).txt"

log_section "Session 3 Complete"
echo -e "  ${GREEN}✔${RESET}  Snort rules:          /etc/snort/rules/election.rules"
echo -e "  ${GREEN}✔${RESET}  Alert log:            /var/log/snort/alert"
echo -e "  ${GREEN}✔${RESET}  Alert forwarder:      systemctl status snort-to-es"
echo -e "  ${GREEN}✔${RESET}  IOC store:            /opt/election-lab/threat-intel/"
echo ""
echo -e "${YELLOW}Exercise commands:${RESET}"
echo "  sudo snort -A console -c /etc/snort/snort.conf -i ${INTERNAL_IFACE}    # live mode"
echo "  python3 /opt/election-lab/threat-intel/ioc_store.py search election"
echo "  python3 /opt/election-lab/threat-intel/ioc_store.py export"
echo "  cat /var/log/snort/alert"
echo ""
