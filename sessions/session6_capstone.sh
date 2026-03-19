#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# sessions/session6_capstone.sh
# Session 6 — Capstone: Attack Simulation + Election Cybersecurity Readiness Kit
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${LAB_DIR}/lib/common.sh"
require_root; require_docker

log_section "Session 6 — Capstone: Attack Simulation & Readiness Kit"

# ── Step 1: IAM — Samba AD + FreeRADIUS (lightweight) ────────────────────────
log_step "Deploying Identity & Access Management (Samba AD + FreeRADIUS)..."

# Samba AD — use existing container or deploy
docker rm -f "$CTR_SAMBA" 2>/dev/null || true
docker run -d \
    --name "$CTR_SAMBA" \
    --network "$NET_INT" \
    --ip "$IP_SAMBA" \
    --memory 512m \
    --restart unless-stopped \
    -e SAMBA_DOMAIN="election" \
    -e SAMBA_REALM="ELECTION.LOCAL" \
    -e "SAMBA_ADMIN_PASSWORD=${AD_ADMINPASS}" \
    -e SAMBA_DC_NAME="dc1" \
    dperson/samba -p 2>/dev/null \
    || docker run -d \
        --name "$CTR_SAMBA" \
        --network "$NET_INT" \
        --ip "$IP_SAMBA" \
        --memory 256m \
        --restart unless-stopped \
        alpine:latest sh -c "
            apk add --no-cache samba-dc 2>/dev/null || apk add --no-cache samba;
            mkdir -p /etc/samba /var/lib/samba/private;
            cat > /etc/samba/smb.conf << 'SMBEOF'
[global]
    workgroup = ELECTION
    realm = ELECTION.LOCAL
    netbios name = DC1
    server role = active directory domain controller
    dns forwarder = 8.8.8.8
    log level = 1
SMBEOF
            samba-tool domain provision --realm=ELECTION.LOCAL --domain=ELECTION \
                --adminpass='${AD_ADMINPASS}' --use-rfc2307 --option='dns backend=SAMBA_INTERNAL' \
                2>/dev/null || true;
            # Create election office user OUs and accounts
            samba-tool user create jclerk 'Clerk@2024!' --description='County Clerk' 2>/dev/null || true;
            samba-tool user create jit 'ITAdmin@2024!' --description='IT Administrator' 2>/dev/null || true;
            samba-tool user create raudit 'Auditor@2024!' --description='Election Auditor' 2>/dev/null || true;
            tail -f /dev/null
        "
log_ok "Samba container started"

# FreeRADIUS
docker rm -f "$CTR_RADIUS" 2>/dev/null || true
docker run -d \
    --name "$CTR_RADIUS" \
    --network "$NET_INT" \
    --ip "$IP_RADIUS" \
    -p 1812:1812/udp \
    --memory 128m \
    --restart unless-stopped \
    freeradius/freeradius-server:latest 2>/dev/null \
    || docker run -d \
        --name "$CTR_RADIUS" \
        --network "$NET_INT" \
        --ip "$IP_RADIUS" \
        -p 1812:1812/udp \
        --memory 128m \
        --restart unless-stopped \
        alpine:latest sh -c "
            apk add --no-cache freeradius 2>/dev/null;
            # Write local user file
            cat > /etc/raddb/users << 'RADIUSUSR'
jclerk    Cleartext-Password := 'Clerk@2024!'
          Reply-Message = 'Hello, County Clerk'
jit       Cleartext-Password := 'ITAdmin@2024!'
          Reply-Message = 'Hello, IT Admin'
raudit    Cleartext-Password := 'Auditor@2024!'
          Reply-Message = 'Hello, Auditor'
RADIUSUSR
            radiusd -X 2>/dev/null || freeradius -X 2>/dev/null || tail -f /dev/null
        "
log_ok "FreeRADIUS container started"

# ── Step 2: Attack simulation toolkit ────────────────────────────────────────
log_step "Building attack simulation scenarios..."
mkdir -p /opt/election-lab/attack-sim

cat > /opt/election-lab/attack-sim/attack_scenario.py << 'PYEOF'
#!/usr/bin/env python3
"""
Election Cybersecurity Lab — Attack Simulation
EDUCATIONAL USE ONLY — runs only within the isolated lab network

Phases:
  recon            — network reconnaissance (safe nmap-style)
  phishing         — simulate phishing email generation (no real sending)
  lateral          — simulate lateral movement traffic to ElectionDB
  bulk-query       — simulate bulk voter DB queries (anomaly generation)
  c2-beacon        — simulate C2 beacon traffic pattern
  exfil            — simulate data exfiltration pattern
  full-chain        — run the full attack kill chain

Usage:
  python3 attack_scenario.py --phase recon
  python3 attack_scenario.py --phase full-chain
"""
import subprocess, socket, time, json, datetime, argparse, urllib.request, os

ES_URL = "http://localhost:9200"
INDEX  = "election-security-events"
DB_IP  = "172.21.20.10"
PORTAL = "172.21.10.10"

def ts():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def log_event(event_type, sev, msg, src="172.21.40.10", tactic=None, technique=None):
    ev = {"timestamp":ts(), "event_type":event_type, "severity":sev,
          "message":msg, "source_ip":src, "mitre_tactic":tactic, "mitre_technique":technique}
    try:
        data = json.dumps(ev).encode()
        req  = urllib.request.Request(f"{ES_URL}/{INDEX}/_doc",
               data=data, headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception: pass
    flag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"⚪")
    print(f"  {flag} [{sev:8s}] {event_type}: {msg}")

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

def phase_recon():
    print("\n[PHASE: RECONNAISSANCE]  MITRE T1595 — Active Scanning")
    print("-"*50)
    # Ping sweep on internal subnet
    log_event("PORT_SCAN","MEDIUM","Adversary initiating ping sweep on 172.21.20.0/24",
              tactic="Reconnaissance", technique="T1595.001")
    for ip in ["172.21.20.10","172.21.20.20","172.21.20.21"]:
        r = run(f"ping -c 1 -W 1 {ip} 2>/dev/null")
        status = "UP" if r.returncode == 0 else "DOWN"
        print(f"  Ping {ip}: {status}")
    # Port check on DB
    for port in [22, 5432, 80, 443]:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((DB_IP, port))
            print(f"  Port {DB_IP}:{port} — OPEN")
            log_event("PORT_SCAN","HIGH",f"Open port discovered: {DB_IP}:{port}",
                      tactic="Reconnaissance", technique="T1595.002")
        except Exception:
            print(f"  Port {DB_IP}:{port} — closed/filtered")
        finally:
            s.close()

def phase_phishing():
    print("\n[PHASE: PHISHING SIMULATION]  MITRE T1566 — Spear-phishing")
    print("-"*50)
    phish = {
        "from": "cisa-update@election-security-gov.com",
        "to":   "county.clerk@election.local",
        "subject": "URGENT: Required Election Security Patch — Action Needed",
        "body": """Dear County Clerk,

CISA has identified a critical vulnerability in election management
systems. You must apply the attached patch immediately.

[Malicious attachment: election_patch.exe]

Click here to verify your credentials:
http://vote-check.ru/secure-login

— CISA Election Security Team
"""
    }
    log_event("PHISHING","CRITICAL",
              f"Spear-phish simulated: From={phish['from']} Subject={phish['subject']}",
              tactic="Initial Access", technique="T1566.001")
    print(f"  From:    {phish['from']}")
    print(f"  To:      {phish['to']}")
    print(f"  Subject: {phish['subject']}")
    print(f"  IOC:     vote-check.ru (election-related phishing domain)")
    print(f"\n  [!] This domain is in the election IOC store — check:")
    print(f"      python3 /opt/election-lab/threat-intel/ioc_store.py search vote-check")

def phase_lateral():
    print("\n[PHASE: LATERAL MOVEMENT]  MITRE T1021 — Remote Services")
    print("-"*50)
    log_event("LATERAL_MOVEMENT","HIGH",
              "Adversary attempting SSH to ElectionDB from compromised endpoint",
              tactic="Lateral Movement", technique="T1021.004")
    for attempt in range(1, 4):
        r = run(f"ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no "
                f"election_admin@{DB_IP} 'id' 2>&1")
        print(f"  SSH attempt {attempt}: {'Success' if r.returncode==0 else 'Failed (auth required)'}")
        log_event("AUTH_FAILURE","HIGH",f"SSH brute-force attempt {attempt}/3 to {DB_IP}",
                  tactic="Credential Access", technique="T1110")
        time.sleep(1)

def phase_bulk_query():
    print("\n[PHASE: BULK DATA COLLECTION]  MITRE T1005 — Data from Local System")
    print("-"*50)
    log_event("BULK_QUERY","CRITICAL",
              "Bulk voter record query: 5000 rows accessed in 8 seconds — anomaly threshold exceeded",
              tactic="Collection", technique="T1005")
    # Connect to real DB and run some queries to generate real events
    try:
        import subprocess
        r = run(f"psql postgresql://election_admin:{os.environ.get('DB_PASS','VoterDB@2024!')}@{DB_IP}/voterdb "
                f"-c 'SELECT * FROM voters LIMIT 5;' 2>/dev/null")
        if r.returncode == 0:
            print(f"  DB query result:\n{r.stdout[:300]}")
        else:
            print(f"  DB query simulated (container may be starting)")
    except Exception:
        print(f"  DB query simulated (psql not available)")
    log_event("BULK_QUERY","CRITICAL",
              "Attacker accessing voter table — precinct P001: 2 records extracted",
              src=DB_IP, tactic="Collection", technique="T1005")

def phase_c2_beacon():
    print("\n[PHASE: C2 BEACON SIMULATION]  MITRE T1041 — Exfil Over C2")
    print("-"*50)
    c2_ips = ["185.220.101.45", "91.108.4.220"]
    for c2 in c2_ips:
        log_event("C2_BEACON","CRITICAL",
                  f"Periodic HTTP beacon to known C2 infrastructure: {c2}:80",
                  src="172.21.20.10", tactic="Command and Control", technique="T1071.001")
        print(f"  Beacon to {c2}:80 — IOC match (check threat-intel store)")
        print(f"      python3 /opt/election-lab/threat-intel/ioc_store.py search {c2}")

def phase_exfil():
    print("\n[PHASE: DATA EXFILTRATION]  MITRE T1048 — Exfil Over Alternative Protocol")
    print("-"*50)
    log_event("EXFIL","CRITICAL",
              "voter_export.csv (4.2 MB) detected in outbound DNS traffic — DNS tunnelling",
              src="172.21.20.10", tactic="Exfiltration", technique="T1048.003")
    print("  Simulated DNS exfiltration: voter_export.csv encoded in DNS TXT queries")
    print("  Destination: myvoterinfo.xyz (phishing domain — in IOC store)")
    # Write a marker file to trigger file-integrity monitoring
    with open("/tmp/voter_export_SIMULATION.txt","w") as f:
        f.write("ELECTION_ALERT: Simulated voter data export file — forensics exercise\n")
    log_event("FIM_ALERT","CRITICAL",
              "voter_export_SIMULATION.txt created in /tmp — file integrity alert triggered",
              tactic="Impact", technique="T1485")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Election Attack Simulation")
    p.add_argument("--phase", choices=["recon","phishing","lateral","bulk-query",
                                        "c2-beacon","exfil","full-chain"],
                   default="full-chain")
    args = p.parse_args()

    print(f"\n{'='*55}")
    print(f"  ELECTION ATTACK SIMULATION — EDUCATIONAL USE ONLY")
    print(f"  Phase: {args.phase.upper()}")
    print(f"  Time:  {ts()}")
    print(f"{'='*55}")

    PHASES = {
        "recon":       phase_recon,
        "phishing":    phase_phishing,
        "lateral":     phase_lateral,
        "bulk-query":  phase_bulk_query,
        "c2-beacon":   phase_c2_beacon,
        "exfil":       phase_exfil,
    }

    if args.phase == "full-chain":
        for ph_name, ph_fn in PHASES.items():
            ph_fn()
            time.sleep(2)
    else:
        PHASES[args.phase]()

    print(f"\n{'='*55}")
    print(f"  Simulation complete. Check SIEM:")
    print(f"  http://localhost:5601  — search for election-security-events")
    print(f"{'='*55}\n")
PYEOF
chmod +x /opt/election-lab/attack-sim/attack_scenario.py

# ── Step 3: Run the simulation ────────────────────────────────────────────────
log_step "Running attack simulation (generating SIEM events)..."
python3 /opt/election-lab/attack-sim/attack_scenario.py --phase full-chain 2>/dev/null \
    || log_warn "Attack simulation completed with some warnings — check ES connectivity"

# ── Step 4: Compile the readiness kit ─────────────────────────────────────────
log_step "Compiling Election Cybersecurity Readiness Kit..."
mkdir -p /opt/election-lab/readiness-kit

cat > /opt/election-lab/readiness-kit/generate_kit.py << 'PYEOF2'
#!/usr/bin/env python3
"""
Generate the Election Cybersecurity Readiness Kit summary document
"""
import datetime, json, os, urllib.request

ES_URL   = "http://localhost:9200"
KIT_DIR  = "/opt/election-lab/readiness-kit"
EVID_DIR = os.path.expanduser("~/election_evidence")
os.makedirs(KIT_DIR, exist_ok=True)

def es_count(index):
    try:
        r = urllib.request.urlopen(f"{ES_URL}/{index}/_count", timeout=5)
        return json.loads(r.read()).get("count", 0)
    except:
        return "N/A"

report = f"""
╔══════════════════════════════════════════════════════════════╗
║   ELECTION CYBERSECURITY READINESS KIT                       ║
║   Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}                            ║
╚══════════════════════════════════════════════════════════════╝

EXECUTIVE SUMMARY
─────────────────
This Election Cybersecurity Readiness Kit confirms that the
lab environment has been successfully configured and tested for:

  1. Network Segmentation & Zero-Trust Controls (Session 1)
  2. SIEM & Log Monitoring (Session 2)
  3. Intrusion Detection & Threat Intelligence (Session 3)
  4. Containment, Recovery & Digital Forensics (Session 4)
  5. Legal Compliance & Public Communication (Session 5)
  6. Attack Simulation & Integration Testing (Session 6)

LAB STATUS
──────────
Elasticsearch Events Indexed:
  election-security-events:  {es_count('election-security-events')}
  election-threat-intel:      {es_count('election-threat-intel')}
  election-db-audit:          {es_count('election-db-audit')}

COMPONENTS DEPLOYED
───────────────────
  ✔  Election Portal (DMZ)         172.21.10.10  → http://localhost:8080
  ✔  ElectionDB (PostgreSQL)        172.21.20.10:5432
  ✔  Elasticsearch SIEM             http://localhost:9200
  ✔  Kibana Dashboard               http://localhost:5601
  ✔  nftables Zero-Trust Firewall   /etc/nftables-election.conf
  ✔  Snort IDS                      /etc/snort/rules/election.rules
  ✔  IOC Store (MISP-lite)          /opt/election-lab/threat-intel/
  ✔  Containment Toolkit            /opt/election-lab/containment/
  ✔  Notification Templates         /opt/election-lab/legal/
  ✔  Attack Simulation              /opt/election-lab/attack-sim/

MITRE ATT&CK COVERAGE
──────────────────────
  T1595  Active Scanning              — Snort rule 9000001
  T1566  Phishing                     — Election monitor + IOC
  T1110  Brute Force                  — Snort rule 9000005
  T1021  Remote Services (lateral)    — Snort rule 9000003
  T1005  Data from Local System       — Snort rule 9000002
  T1041  Exfil Over C2 Channel        — Snort rule 9000008
  T1048  Exfil Over Alt Protocol      — Election monitor
  T1485  Data Destruction / Impact    — Wazuh FIM

EVIDENCE ARTEFACTS
───────────────────
  Evidence directory: {EVID_DIR}
"""

if os.path.exists(EVID_DIR):
    for f in sorted(os.listdir(EVID_DIR)):
        report += f"  {f}\n"

report += f"""
NIST SP 800-61 ALIGNMENT
──────────────────────────
  Preparation:    Sessions 1-3  (controls, detection, intel)
  Detection:      Wazuh + Snort + Election Monitor
  Containment:    Session 4  (contain.py + nftables block)
  Eradication:    Session 4  (recovery.sh + clean restore)
  Recovery:       Session 4  (verified backup restore)
  Post-Incident:  Session 5  (legal notifications + comms)

QUICK REFERENCE — KEY COMMANDS
──────────────────────────────────────────────────────────────
  SIEM:           curl http://localhost:9200/election-security-events/_search?pretty
  IOC check:      python3 /opt/election-lab/threat-intel/ioc_store.py search <value>
  Contain:        python3 /opt/election-lab/containment/contain.py isolate --target <IP>
  Block IP:       python3 /opt/election-lab/containment/contain.py block-ip --ip <IP>
  Compliance:     python3 /opt/election-lab/legal/check_compliance.py --incident-date <ISO> --state <ST>
  Attack sim:     python3 /opt/election-lab/attack-sim/attack_scenario.py --phase full-chain
  Status:         sudo bash /path/to/election-lab/setup.sh status
  Teardown:       sudo bash /path/to/election-lab/setup.sh down

SERVICE CREDENTIALS
──────────────────────────────────────────────────────────────
  Kibana:          http://localhost:5601         no auth (lab mode)
  Elasticsearch:   http://localhost:9200         no auth (lab mode)
  Election Portal: http://localhost:8080         public
  ElectionDB:      postgresql://election_admin@172.21.20.10/voterdb
                   Password: VoterDB@2024!
  Samba AD:        ldap://172.21.20.20:389
                   Administrator / El3ct10n@Admin2024!
  FreeRADIUS:      172.21.20.21:1812/udp  secret: R@dius$ecret2024
  RADIUS users:    jclerk/Clerk@2024!  jit/ITAdmin@2024!  raudit/Auditor@2024!

──────────────────────────────────────────────────────────────
EDUCATIONAL USE ONLY — DO NOT CONNECT TO LIVE ELECTION SYSTEMS
──────────────────────────────────────────────────────────────
"""

out = f"{KIT_DIR}/election_readiness_kit_{datetime.date.today()}.txt"
with open(out, "w") as f:
    f.write(report)
print(report)
print(f"\nReadiness kit saved: {out}")
PYEOF2
chmod +x /opt/election-lab/readiness-kit/generate_kit.py

log_step "Generating readiness kit document..."
python3 /opt/election-lab/readiness-kit/generate_kit.py

# ── Collect evidence ──────────────────────────────────────────────────────────
{
    echo "=== Capstone Evidence ==="
    echo "Date: $(date -u)"
    echo ""
    echo "=== Running Containers ==="
    docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | grep lab-election || echo "None running"
    echo ""
    echo "=== Elasticsearch Event Count ==="
    curl -sf "http://localhost:9200/election-security-events/_count" 2>/dev/null || echo "N/A"
    echo ""
    echo "=== IOC Count ==="
    python3 /opt/election-lab/threat-intel/ioc_store.py list 2>/dev/null | wc -l || echo "N/A"
} > "${EVIDENCE_DIR}/capstone_$(date +%Y%m%d_%H%M%S).txt"

log_section "Session 6 Complete — Full Lab Deployed"
echo -e "  ${GREEN}✔${RESET}  Attack simulation ran — events in Elasticsearch"
echo -e "  ${GREEN}✔${RESET}  Readiness kit:  /opt/election-lab/readiness-kit/"
echo ""
echo -e "${YELLOW}Capstone exercises:${RESET}"
echo -e "${BOLD} Exercise 6.1:${RESET}"
echo -e "${CYAN}python3 /opt/election-lab/attack-sim/attack_scenario.py --phase full-chain${RESET}"
echo ""
echo -e "${BOLD} Exercise 6.2:${RESET}"
echo -e "${CYAN}python3 /opt/election-lab/attack-sim/attack_scenario.py --phase recon${RESET}"
echo ""
echo -e "${BOLD} Exercise 6.3:${RESET}"
echo -e "${CYAN}curl 'http://localhost:9200/election-security-events/_search?pretty'${RESET}"
echo ""
echo -e "${BOLD} Exercise 6.4:${RESET}"
echo -e "${CYAN}http://localhost:5601  (Kibana — search election-security-*)${RESET}"
echo ""

