# 🗳️ Election Cybersecurity Lab — Lite Edition
### Single-VM · Docker-Based · NIST SP 800-61 & MITRE ATT&CK
**Optimised for 4 GB RAM / 25 GB storage**

---

## Quick Start

```bash
# Step 0
sudo apt-get update && sudo apt-get upgrade

# Step 1 — Run preflight checks (installs all dependencies)
sudo bash preflight.sh

# Step 2 — Deploy the full lab
sudo bash setup.sh all

# Step 3 — Check status
sudo bash setup.sh status
```

---

## Pre-flight Requirements

| Requirement | Minimum | Recommended | Notes |
|---|---|---|---|
| OS | Ubuntu 20.04 / 22.04 LTS | Ubuntu 22.04 LTS | Single VM or bare metal |
| RAM | 4 GB | 6 GB | Elasticsearch needs 512 MB heap |
| Disk | 25 GB free | 40 GB | Docker images ~10 GB |
| CPU | 2 cores | 4 cores | VT-x/AMD-V for best performance |
| Internet | Required | Required | Docker Hub + apt repos |

The `preflight.sh` script automatically installs and verifies:
- `docker-ce`, `docker-compose-plugin`
- `tshark`, `nmap`, `snort`, `nftables`, `yara`
- `freeradius-utils`, `netcat-openbsd`, `jq`, `python3-pip`
- Python packages: `docker`, `requests`, `stix2`
- Kernel tunables: `vm.max_map_count=262144`
- Docker daemon: `overlay2` storage, log limits

---

## Architecture

```
┌─────────────── Ubuntu Host VM (4 GB RAM) ──────────────────────┐
│                                                                   │
│  ┌── lab-election-dmz  (172.21.10.0/24) ──────────────────┐     │
│  │  lab-election-portal  (nginx:alpine)    128 MB          │     │
│  └─────────────────────────────────────────────────────────┘     │
│                     ↕  nftables Zero-Trust                        │
│  ┌── lab-election-int  (172.21.20.0/24) ──────────────────┐      │
│  │  lab-election-db      (PostgreSQL 15)   256 MB          │      │
│  │  lab-election-samba   (Samba 4 AD)      512 MB          │      │
│  │  lab-election-radius  (FreeRADIUS)      128 MB          │      │
│  └─────────────────────────────────────────────────────────┘      │
│                     ↕  nftables Zero-Trust                        │
│  ┌── lab-election-mgmt (172.21.30.0/24) ──────────────────┐      │
│  │  lab-election-elastic (ES 8)            900 MB          │      │
│  │  lab-election-kibana  (Kibana 8)        512 MB          │      │
│  └─────────────────────────────────────────────────────────┘      │
│                                                                   │
│  Host tools: Snort IDS · YARA · nftables · tshark · Volatility   │
│  RAM budget: ~2.5 GB containers + ~1.5 GB OS/Docker              │
└───────────────────────────────────────────────────────────────────┘
```

---

## Module Commands

```bash
sudo bash setup.sh preflight   # Install all dependencies
sudo bash setup.sh network     # Session 1 — Docker networks + Zero-Trust firewall
sudo bash setup.sh siem        # Session 2 — Elasticsearch + Kibana + log monitor
sudo bash setup.sh ids         # Session 3 — Snort IDS + IOC store (MISP-lite)
sudo bash setup.sh forensics   # Session 4 — Containment toolkit + forensics
sudo bash setup.sh legal       # Session 5 — Notification templates + compliance checker
sudo bash setup.sh capstone    # Session 6 — Attack simulation + Readiness Kit
sudo bash setup.sh evidence    # Collect all compliance artefacts
sudo bash setup.sh status      # Show running services + memory + URLs
sudo bash setup.sh down        # Stop all containers (keep volumes)
sudo bash setup.sh clean       # Full teardown including volumes + nftables
```

---

## Session Exercises

### Session 1 — Network Segmentation & Zero-Trust
```bash
# Verify nftables Zero-Trust rules are active
echo -e "${BOLD} Exercise 1.1 - Verify Zero-Trust rules:${NC}
echo -e " ${CYAN}sudo nft list table inet lab_election${NC}"
echo ""

# DMZ → Internal MUST FAIL (Zero-Trust enforced)
docker exec lab-election-portal ping -c 3 172.21.20.10

# Host → Portal MUST SUCCEED
curl http://localhost:8080

# Watch Zero-Trust firewall drop events
sudo journalctl -kf | grep LAB_DROP
```

### Session 2 — SIEM & Incident Detection
```bash
# Check Elasticsearch indices
curl http://localhost:9200/_cat/indices?v

# View security events
curl 'http://localhost:9200/election-security-events/_search?pretty&size=5'

# Watch live election log monitor
sudo tail -f /var/log/election-lab/monitor.log

# Open Kibana SIEM dashboard
# Browser: http://localhost:5601
```

### Session 3 — IDS & Threat Intelligence
```bash
# Run Snort in live console mode on the internal bridge
sudo snort -A console -c /etc/snort/snort.conf -i any

# Check IOC store
python3 /opt/election-lab/threat-intel/ioc_store.py list
python3 /opt/election-lab/threat-intel/ioc_store.py search election

# Add a new IOC
python3 /opt/election-lab/threat-intel/ioc_store.py add \
    --type ip-dst --value 1.2.3.4 --tags "APT,c2" --tlp GREEN

# Export STIX 2.1 bundle
python3 /opt/election-lab/threat-intel/ioc_store.py export

# View Snort alert log
sudo tail -f /var/log/snort/alert
```

### Session 4 — Containment & Forensics
```bash
# Isolate a compromised VM
python3 /opt/election-lab/containment/contain.py isolate --target 172.21.20.10

# Block an attacker IP
python3 /opt/election-lab/containment/contain.py block-ip --ip 172.21.40.10

# Create forensic snapshot of a container
python3 /opt/election-lab/containment/contain.py snapshot --container lab-election-db

# View chain of custody log
python3 /opt/election-lab/containment/contain.py status

# Run recovery playbook
sudo bash /opt/election-lab/containment/recovery.sh all

# Forensics quick reference
bash /opt/election-lab/containment/mem_forensics.sh
```

### Session 5 — Legal & Communications
```bash
# Check notification deadlines from incident time
python3 /opt/election-lab/legal/check_compliance.py \
    --incident-date 2024-11-05T14:32:00 --state TX

# View notification templates
cat /opt/election-lab/legal/notifications/voter_notification.txt
cat /opt/election-lab/legal/notifications/cisa_report.txt
cat /opt/election-lab/legal/comms/press_release.txt
```

### Session 6 — Attack Simulation & Capstone
```bash
# Run the full election attack kill chain
python3 /opt/election-lab/attack-sim/attack_scenario.py --phase full-chain

# Run individual phases
python3 /opt/election-lab/attack-sim/attack_scenario.py --phase recon
python3 /opt/election-lab/attack-sim/attack_scenario.py --phase phishing
python3 /opt/election-lab/attack-sim/attack_scenario.py --phase lateral
python3 /opt/election-lab/attack-sim/attack_scenario.py --phase bulk-query
python3 /opt/election-lab/attack-sim/attack_scenario.py --phase c2-beacon
python3 /opt/election-lab/attack-sim/attack_scenario.py --phase exfil

# Generate Readiness Kit
python3 /opt/election-lab/readiness-kit/generate_kit.py

# Test RADIUS authentication
radtest jclerk 'Clerk@2024!' 127.0.0.1 0 'R@dius$ecret2024'
```

---

## Service Credentials

| Service | URL | Credentials |
|---|---|---|
| Kibana | http://localhost:5601 | no auth (lab mode) |
| Elasticsearch | http://localhost:9200 | no auth (lab mode) |
| Election Portal | http://localhost:8080 | public |
| Wazuh API | http://localhost:55000 | see Wazuh docs |
| ElectionDB | postgresql://172.21.20.10:5432/voterdb | election_admin / VoterDB@2024! |
| Samba AD | ldap://172.21.20.20:389 | Administrator / El3ct10n@Admin2024! |
| FreeRADIUS | 127.0.0.1:1812/udp | secret: R@dius$ecret2024 |

**RADIUS test users:**
| Username | Password | Role |
|---|---|---|
| jclerk | Clerk@2024! | County Clerk |
| jit | ITAdmin@2024! | IT Administrator |
| raudit | Auditor@2024! | Election Auditor |

---

## NIST SP 800-61 Compliance Matrix

| Phase | Control | Tool | Session | Evidence File |
|---|---|---|---|---|
| Preparation | Network Segmentation | Docker + nftables | Session 1 | network_evidence_*.txt |
| Preparation | Access Control | Samba AD + FreeRADIUS | Session 6 | iam_evidence_*.txt |
| Detection | SIEM Logging | Elasticsearch + Kibana | Session 2 | siem_evidence_*.txt |
| Detection | Intrusion Detection | Snort IDS | Session 3 | ids_evidence_*.txt |
| Detection | Threat Intelligence | IOC Store (MISP-lite) | Session 3 | threat_intel_evidence_*.txt |
| Containment | Incident Isolation | contain.py + nftables | Session 4 | forensics_evidence_*.txt |
| Eradication | Root Cause Removal | Forensic analysis | Session 4 | forensics_evidence_*.txt |
| Recovery | System Restore | recovery.sh | Session 4 | running_services_*.txt |
| Post-Incident | Legal Compliance | Notification templates | Session 5 | legal_evidence_*.txt |
| Post-Incident | Public Communication | Comms templates | Session 5 | legal_evidence_*.txt |

Evidence collected in: `~/election_evidence/`

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection Tool | Session |
|---|---|---|---|
| Reconnaissance | T1595 Active Scanning | Snort rule 9000001 | Session 3 |
| Initial Access | T1566 Phishing | IOC store + log monitor | Sessions 2-3 |
| Credential Access | T1110 Brute Force | Snort rule 9000005 | Session 3 |
| Lateral Movement | T1021 Remote Services | Snort rule 9000003 | Session 3 |
| Collection | T1005 Local Data | Snort rule 9000002 | Session 3 |
| C&C | T1071 Application Protocol | Snort rule 9000003 | Session 3 |
| Exfiltration | T1048 Alt Protocol | Election log monitor | Session 2 |
| Impact | T1485 Data Destruction | File integrity check | Session 4 |

---

## Teardown

```bash
# Stop everything (keeps volumes)
sudo bash setup.sh down

# Full clean including volumes + nftables rules
sudo bash setup.sh clean
```

---

## File Layout

```
election-lab/
├── README.md
├── setup.sh                         ← Main entry point
├── preflight.sh                     ← Dependency checker + installer
├── lib/
│   └── common.sh                    ← Shared variables, colours, helpers
└── sessions/
    ├── session1_network.sh          ← Docker VLANs + nftables Zero-Trust
    ├── session2_siem.sh             ← Elasticsearch + Kibana + log monitor
    ├── session3_ids.sh              ← Snort IDS + IOC store (MISP-lite)
    ├── session4_forensics.sh        ← Containment toolkit + forensics
    ├── session5_legal.sh            ← Notification templates + compliance
    ├── session6_capstone.sh         ← Attack simulation + Readiness Kit
    └── session_evidence.sh          ← Collect all compliance artefacts
```

---

*For educational use only. Do not connect to live election systems, production voter databases, or the public internet beyond what is required for package installations.*
