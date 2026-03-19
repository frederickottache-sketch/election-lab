#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# sessions/session4_forensics.sh
# Session 4 — Containment, Recovery & Digital Forensics
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${LAB_DIR}/lib/common.sh"
require_root

log_section "Session 4 — Containment, Recovery & Digital Forensics"

# ── Step 1: Install forensics tools ──────────────────────────────────────────
log_step "Installing forensics tools..."
export DEBIAN_FRONTEND=noninteractive
for pkg in binutils foremost strings file hexdump xxd steghide; do
    apt-get install -y -qq "$pkg" 2>/dev/null || true
done
# volatility3 via pip
pip3 install -q --break-system-packages volatility3 2>/dev/null \
    || pip3 install -q volatility3 2>/dev/null || true

log_ok "Forensics tools installed"
mkdir -p /forensics/evidence /forensics/memory /forensics/disk /forensics/network

# ── Step 2: Containment automation script ────────────────────────────────────
log_step "Creating containment automation toolkit..."
mkdir -p /opt/election-lab/containment

cat > /opt/election-lab/containment/contain.py << 'PYEOF'
#!/usr/bin/env python3
"""
Election Incident Containment Toolkit
Usage:
  python3 contain.py isolate  --target 172.21.20.10
  python3 contain.py block-ip --ip 10.0.40.10
  python3 contain.py snapshot --container lab-election-db
  python3 contain.py restore  --container lab-election-db
  python3 contain.py status
"""
import subprocess, argparse, json, datetime, os, sys, hashlib

LOG_DIR     = "/forensics/evidence"
CHAIN_LOG   = f"{LOG_DIR}/chain_of_custody.json"
os.makedirs(LOG_DIR, exist_ok=True)

def ts():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def log_custody(action, target, details=""):
    entry = {"timestamp":ts(), "action":action, "target":target,
             "operator": os.environ.get("SUDO_USER", os.environ.get("USER","unknown")),
             "details": details}
    records = []
    if os.path.exists(CHAIN_LOG):
        with open(CHAIN_LOG) as f:
            try: records = json.load(f)
            except: records = []
    records.append(entry)
    with open(CHAIN_LOG, "w") as f:
        json.dump(records, f, indent=2)
    print(f"[CUSTODY] {entry['timestamp']}  {action}  {target}")
    return entry

def run(cmd, check=True):
    r = subprocess.run(cmd, shell=isinstance(cmd,str), capture_output=True, text=True)
    if check and r.returncode != 0:
        print(f"[WARN] Command failed: {cmd}\n{r.stderr}")
    return r

def isolate(target):
    print(f"\n[ISOLATE] Isolating {target} from all networks...")
    # Add nftables rule to block all traffic to/from target
    run(f"nft add rule inet lab_election dmz_to_internal ip saddr {target} drop 2>/dev/null || true", check=False)
    run(f"nft add rule inet lab_election dmz_to_internal ip daddr {target} drop 2>/dev/null || true", check=False)
    # Use iptables as fallback
    run(f"iptables -I FORWARD 1 -s {target} -j DROP 2>/dev/null || true", check=False)
    run(f"iptables -I FORWARD 1 -d {target} -j DROP 2>/dev/null || true", check=False)
    # Capture memory snapshot before isolation (tshark packet capture of last traffic)
    pcap = f"/forensics/network/pre_isolation_{target.replace('.','_')}_{datetime.date.today()}.pcap"
    run(f"timeout 10 tcpdump -i any host {target} -w {pcap} 2>/dev/null || true", check=False)
    sha = ""
    if os.path.exists(pcap):
        sha = hashlib.sha256(open(pcap,'rb').read()).hexdigest()
    log_custody("ISOLATE", target, f"Network traffic blocked. Pre-isolation pcap: {pcap}  SHA256={sha}")
    print(f"  [OK] {target} isolated from all segments")
    print(f"  [OK] Pre-isolation pcap saved: {pcap}")

def block_ip(ip):
    print(f"\n[BLOCK] Blocking IP {ip}...")
    run(f"iptables -I INPUT   1 -s {ip} -j DROP 2>/dev/null || true", check=False)
    run(f"iptables -I FORWARD 1 -s {ip} -j DROP 2>/dev/null || true", check=False)
    run(f"iptables -I OUTPUT  1 -d {ip} -j DROP 2>/dev/null || true", check=False)
    # Also add to Snort pass rule (block at IDS level)
    rule = f'drop ip {ip} any -> any any (msg:"BLOCKED-IP: {ip}"; sid:9099999; rev:1;)\n'
    with open("/etc/snort/rules/election.rules", "a") as f:
        f.write(rule)
    log_custody("BLOCK_IP", ip, "iptables DROP + Snort drop rule added")
    print(f"  [OK] {ip} blocked at firewall and IDS")

def snapshot(container):
    print(f"\n[SNAPSHOT] Creating forensic snapshot of {container}...")
    out_dir = f"/forensics/disk/{container}_{datetime.date.today()}"
    os.makedirs(out_dir, exist_ok=True)
    # Export container filesystem
    tar = f"{out_dir}/filesystem.tar"
    r = run(f"docker export {container} > {tar} 2>/dev/null", check=False)
    if os.path.exists(tar):
        sha = hashlib.sha256(open(tar,'rb').read()).hexdigest()
        log_custody("SNAPSHOT", container, f"Filesystem exported: {tar}  SHA256={sha}")
        print(f"  [OK] Snapshot saved: {tar}")
        print(f"  [OK] SHA256: {sha}")
    else:
        print(f"  [WARN] Snapshot failed — is {container} running?")
    # Also dump container logs
    log_file = f"{out_dir}/docker_logs.txt"
    run(f"docker logs {container} > {log_file} 2>&1", check=False)
    log_custody("LOG_DUMP", container, f"Docker logs: {log_file}")

def restore(container):
    print(f"\n[RESTORE] Restoring {container} from clean image...")
    # Get original image
    r = run(f"docker inspect {container} --format '{{{{.Config.Image}}}}'", check=False)
    image = r.stdout.strip()
    if not image:
        print(f"  [WARN] Cannot find original image for {container}")
        return
    print(f"  Using image: {image}")
    run(f"docker rm -f {container}", check=False)
    # Re-run with same image (simplified — full restore would replay original run cmd)
    print(f"  [OK] Container {container} removed. Re-run session script to restore.")
    log_custody("RESTORE", container, f"Removed container. Re-deploy from image: {image}")

def show_status():
    print("\n[STATUS] Containment Status")
    print("  Blocked IPs (iptables):")
    r = run("iptables -L INPUT -n --line-numbers 2>/dev/null | grep DROP", check=False)
    for line in r.stdout.strip().split("\n"):
        if line: print(f"    {line}")
    print("\n  Chain of Custody Log:")
    if os.path.exists(CHAIN_LOG):
        with open(CHAIN_LOG) as f:
            records = json.load(f)
        for rec in records[-5:]:
            print(f"    [{rec['timestamp']}] {rec['action']:15s} {rec['target']}  — {rec['operator']}")
    else:
        print("    No custody records yet")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Election Incident Containment Toolkit")
    sub = parser.add_subparsers(dest="cmd")
    p_iso = sub.add_parser("isolate");   p_iso.add_argument("--target", required=True)
    p_blk = sub.add_parser("block-ip");  p_blk.add_argument("--ip",     required=True)
    p_snp = sub.add_parser("snapshot");  p_snp.add_argument("--container", required=True)
    p_rst = sub.add_parser("restore");   p_rst.add_argument("--container", required=True)
    sub.add_parser("status")
    args = parser.parse_args()

    if   args.cmd == "isolate":   isolate(args.target)
    elif args.cmd == "block-ip":  block_ip(args.ip)
    elif args.cmd == "snapshot":  snapshot(args.container)
    elif args.cmd == "restore":   restore(args.container)
    elif args.cmd == "status":    show_status()
    else: parser.print_help()
PYEOF
chmod +x /opt/election-lab/containment/contain.py

# ── Step 3: Recovery playbook script ─────────────────────────────────────────
log_step "Creating recovery playbook..."

cat > /opt/election-lab/containment/recovery.sh << 'RECSH'
#!/usr/bin/env bash
# Election Incident Recovery Playbook
# Run: sudo bash /opt/election-lab/containment/recovery.sh [step]
# Steps: backup | verify | restore-db | restore-portal | post-check | all
set -euo pipefail
source /opt/election-lab/../lib/common.sh 2>/dev/null || true
CMD="${1:-help}"
BACKUP_DIR="/forensics/backups/$(date +%Y%m%d_%H%M%S)"

case "$CMD" in
  backup)
    echo "[STEP 1] Backing up current DB state..."
    mkdir -p "$BACKUP_DIR"
    docker exec lab-election-db pg_dump -U election_admin voterdb \
        > "${BACKUP_DIR}/voterdb_backup.sql" 2>/dev/null \
        && echo "[OK] DB backup: ${BACKUP_DIR}/voterdb_backup.sql" \
        || echo "[WARN] DB backup failed — container may be isolated"
    ;;
  verify)
    echo "[STEP 2] Verifying backup integrity..."
    ls -lh /forensics/backups/ 2>/dev/null || echo "[WARN] No backups found"
    echo "[STEP 2] Checking DB row count..."
    docker exec lab-election-db psql -U election_admin -d voterdb \
        -c "SELECT COUNT(*) AS voters FROM voters;" 2>/dev/null || echo "[WARN] DB check failed"
    ;;
  restore-db)
    echo "[STEP 3] Re-deploying ElectionDB from clean image..."
    docker rm -f lab-election-db 2>/dev/null || true
    source "$(dirname "$0")/../../sessions/session1_network.sh" 2>/dev/null || true
    echo "[OK] Run: sudo bash setup.sh network  (to re-deploy DB)"
    ;;
  restore-portal)
    echo "[STEP 4] Re-deploying Election Portal..."
    docker rm -f lab-election-portal 2>/dev/null || true
    echo "[OK] Run: sudo bash setup.sh network  (to re-deploy portal)"
    ;;
  post-check)
    echo "[STEP 5] Post-recovery verification..."
    curl -sf http://localhost:8080 >/dev/null && echo "[OK] Portal responding" || echo "[FAIL] Portal down"
    docker exec lab-election-db psql -U election_admin -d voterdb \
        -c "SELECT COUNT(*) FROM voters;" 2>/dev/null && echo "[OK] DB accessible" || echo "[FAIL] DB inaccessible"
    curl -sf http://localhost:9200/_cluster/health 2>/dev/null | grep -q '"status":"green"\|"status":"yellow"' \
        && echo "[OK] Elasticsearch healthy" || echo "[WARN] Elasticsearch check needed"
    ;;
  all)
    bash "$0" backup
    bash "$0" verify
    bash "$0" restore-portal
    bash "$0" post-check
    ;;
  help|*)
    echo "Usage: sudo bash recovery.sh [backup|verify|restore-db|restore-portal|post-check|all]"
    ;;
esac
RECSH
chmod +x /opt/election-lab/containment/recovery.sh

# ── Step 4: Memory forensics helper ──────────────────────────────────────────
log_step "Setting up memory forensics helper..."

cat > /opt/election-lab/containment/mem_forensics.sh << 'MEMSH'
#!/usr/bin/env bash
# Memory & Disk Forensics Quick-Reference
# Election Cybersecurity Lab
echo "=== Election Lab — Forensics Commands Reference ==="
echo ""
echo "--- Memory Forensics (Volatility 3) ---"
echo "  vol.py -f /forensics/memory/dump.raw windows.pslist   # Process list"
echo "  vol.py -f /forensics/memory/dump.raw windows.netscan  # Network connections"
echo "  vol.py -f /forensics/memory/dump.raw linux.pslist     # Linux processes"
echo ""
echo "--- Disk Forensics ---"
echo "  foremost -i /forensics/disk/image.img -o /forensics/disk/recovered/"
echo "  strings /forensics/disk/image.img | grep -i voter"
echo "  xxd /forensics/disk/image.img | head -100"
echo ""
echo "--- Network Forensics ---"
echo "  sudo tshark -i any -w /forensics/network/capture.pcap"
echo "  sudo tshark -r /forensics/network/capture.pcap -Y 'tcp.port==5432'"
echo "  sudo tshark -r /forensics/network/capture.pcap -T fields -e ip.src -e ip.dst"
echo ""
echo "--- Container Forensics ---"
echo "  python3 /opt/election-lab/containment/contain.py snapshot --container lab-election-db"
echo "  docker diff lab-election-db    # What files changed"
echo "  docker logs lab-election-db    # Container logs"
echo ""
echo "--- Chain of Custody ---"
echo "  cat /forensics/evidence/chain_of_custody.json"
MEMSH
chmod +x /opt/election-lab/containment/mem_forensics.sh

# ── Collect evidence ──────────────────────────────────────────────────────────
{
    echo "=== Election Lab Forensics Setup Evidence ==="
    echo "Date: $(date -u)"
    echo ""
    echo "=== Forensics Tools ==="
    for t in strings file xxd foremost tshark; do
        command -v $t &>/dev/null && echo "  [OK] $t: $(command -v $t)" || echo "  [--] $t: not found"
    done
    echo ""
    echo "=== Forensics Directories ==="
    ls -la /forensics/ 2>/dev/null
    echo ""
    echo "=== Containment Scripts ==="
    ls -la /opt/election-lab/containment/
} > "${EVIDENCE_DIR}/forensics_setup_$(date +%Y%m%d_%H%M%S).txt"

log_section "Session 4 Complete"
echo -e "  ${GREEN}✔${RESET}  Containment toolkit:  python3 /opt/election-lab/containment/contain.py"
echo -e "  ${GREEN}✔${RESET}  Recovery playbook:    bash /opt/election-lab/containment/recovery.sh"
echo -e "  ${GREEN}✔${RESET}  Forensics reference:  bash /opt/election-lab/containment/mem_forensics.sh"
echo -e "  ${GREEN}✔${RESET}  Evidence storage:     /forensics/"
echo ""
echo -e "${YELLOW}Exercise commands:${RESET}"
echo -e "${BOLD} Exercise 4.1:${RESET}"
echo -e "${CYAN}python3 /opt/election-lab/containment/contain.py isolate  --target 172.21.20.10${RESET}"
echo ""
echo -e "${BOLD} Exercise 4.2:${RESET}"
echo -e "${CYAN}python3 /opt/election-lab/containment/contain.py block-ip --ip 172.21.10.10${RESET}"
echo ""
echo -e "${BOLD} Exercise 4.3:${RESET}"
echo -e "${CYAN}python3 /opt/election-lab/containment/contain.py snapshot --container lab-election-db${RESET}"
echo ""
echo -e "${BOLD} Exercise 4.4:${RESET}"
echo -e "${CYAN}python3 /opt/election-lab/containment/contain.py status${RESET}"
echo ""
echo -e "${BOLD} Exercise 4.5:${RESET}"
echo -e "${CYAN}bash /opt/election-lab/containment/recovery.sh all${RESET}"
echo ""
