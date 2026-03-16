#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# setup.sh  —  Main entry point for the Election Cybersecurity Lab
# Usage: sudo bash setup.sh [command]
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${LAB_DIR}/lib/common.sh"

CMD="${1:-help}"

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    cat << EOF
${BLUE}${BOLD}
  ╔══════════════════════════════════════════════════════════╗
  ║   ELECTION CYBERSECURITY LAB — Setup                     ║
  ║   Securing Election Infrastructure  ·  Lite Edition      ║
  ╚══════════════════════════════════════════════════════════╝
${RESET}
  ${BOLD}Usage:${RESET}  sudo bash setup.sh [command]

  ${BOLD}Commands:${RESET}
    ${CYAN}all${RESET}          Deploy the full lab (Sessions 1-6 in order)
    ${CYAN}preflight${RESET}    Install all dependencies (same as preflight.sh)
    ${CYAN}network${RESET}      Session 1 — Docker networks + nftables Zero-Trust
    ${CYAN}siem${RESET}         Session 2 — Elasticsearch + Kibana + Wazuh
    ${CYAN}ids${RESET}          Session 3 — Snort IDS + MISP lite
    ${CYAN}forensics${RESET}    Session 4 — Containment + forensics tools
    ${CYAN}legal${RESET}        Session 5 — Notification templates + comms package
    ${CYAN}capstone${RESET}     Session 6 — Attack simulation + readiness kit
    ${CYAN}evidence${RESET}     Collect compliance evidence artefacts
    ${CYAN}status${RESET}       Show all running services + memory
    ${CYAN}down${RESET}         Stop and remove all containers (keeps volumes)
    ${CYAN}clean${RESET}        Full teardown including volumes
    ${CYAN}help${RESET}         Show this message

  ${BOLD}Examples:${RESET}
    sudo bash setup.sh all
    sudo bash setup.sh status
    sudo bash setup.sh down

EOF
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "$CMD" in
    all)
        require_root
        require_docker
        log_section "Deploying Full Election Cybersecurity Lab"
        bash "${LAB_DIR}/sessions/session1_network.sh"
        bash "${LAB_DIR}/sessions/session2_siem.sh"
        bash "${LAB_DIR}/sessions/session3_ids.sh"
        bash "${LAB_DIR}/sessions/session4_forensics.sh"
        bash "${LAB_DIR}/sessions/session5_legal.sh"
        bash "${LAB_DIR}/sessions/session6_capstone.sh"
        bash "${LAB_DIR}/sessions/session_evidence.sh"
        log_section "Full Lab Deployment Complete"
        bash "${LAB_DIR}/setup.sh" status
        ;;
    preflight)
        bash "${LAB_DIR}/preflight.sh"
        ;;
    network)
        require_root; require_docker
        bash "${LAB_DIR}/sessions/session1_network.sh"
        ;;
    siem)
        require_root; require_docker
        bash "${LAB_DIR}/sessions/session2_siem.sh"
        ;;
    ids)
        require_root; require_docker
        bash "${LAB_DIR}/sessions/session3_ids.sh"
        ;;
    forensics)
        require_root; require_docker
        bash "${LAB_DIR}/sessions/session4_forensics.sh"
        ;;
    legal)
        bash "${LAB_DIR}/sessions/session5_legal.sh"
        ;;
    capstone)
        require_root; require_docker
        bash "${LAB_DIR}/sessions/session6_capstone.sh"
        ;;
    evidence)
        bash "${LAB_DIR}/sessions/session_evidence.sh"
        ;;
    status)
        require_docker
        log_section "Election Lab — Service Status"

        echo -e "${BOLD}Docker Containers:${RESET}"
        docker ps --format "  {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null \
            | grep "lab-election" \
            | while IFS=$'\t' read -r name status ports; do
                if echo "$status" | grep -q "Up"; then
                    echo -e "  ${GREEN}●${RESET}  ${name}  |  ${status}  |  ${ports}"
                else
                    echo -e "  ${RED}●${RESET}  ${name}  |  ${status}"
                fi
              done || echo -e "  ${YELLOW}No election lab containers running${RESET}"

        echo ""
        echo -e "${BOLD}Docker Networks:${RESET}"
        for net in "$NET_DMZ" "$NET_INT" "$NET_MGMT"; do
            docker network ls --format "{{.Name}}" 2>/dev/null | grep -q "^${net}$" \
                && echo -e "  ${GREEN}●${RESET}  ${net} — exists" \
                || echo -e "  ${RED}●${RESET}  ${net} — MISSING"
        done

        echo ""
        echo -e "${BOLD}Memory Usage:${RESET}"
        free -h | awk 'NR==2{printf "  Total: %s  |  Used: %s  |  Free: %s\n", $2, $3, $4}'
        docker stats --no-stream --format "  {{.Name}}\t{{.MemUsage}}" 2>/dev/null \
            | grep "lab-election" | head -20 || true

        echo ""
        echo -e "${BOLD}Quick Access URLs:${RESET}"
        echo -e "  ${CYAN}Kibana:${RESET}           http://localhost:5601"
        echo -e "  ${CYAN}Elasticsearch:${RESET}    http://localhost:9200"
        echo -e "  ${CYAN}Election Portal:${RESET}  http://localhost:8080"
        echo -e "  ${CYAN}Wazuh API:${RESET}        http://localhost:55000"
        echo ""
        echo -e "  ${BOLD}Evidence dir:${RESET}     ${EVIDENCE_DIR}"
        echo ""
        ;;
    down)
        require_docker
        log_section "Stopping Election Lab"
        docker ps -a --format "{{.Names}}" 2>/dev/null \
            | grep "^lab-election" \
            | xargs -r docker rm -f
        log_ok "All election lab containers stopped"
        ;;
    clean)
        require_docker
        log_section "Full Teardown — Removing All Lab Resources"
        docker ps -a --format "{{.Names}}" 2>/dev/null \
            | grep "^lab-election" \
            | xargs -r docker rm -f 2>/dev/null || true
        docker volume ls --format "{{.Name}}" 2>/dev/null \
            | grep "^lab-election" \
            | xargs -r docker volume rm 2>/dev/null || true
        for net in "$NET_DMZ" "$NET_INT" "$NET_MGMT"; do
            docker network rm "$net" 2>/dev/null || true
        done
        # Remove nftables rules
        nft delete table inet lab_election 2>/dev/null || true
        log_ok "Full teardown complete"
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        log_error "Unknown command: ${CMD}"
        usage
        exit 1
        ;;
esac
