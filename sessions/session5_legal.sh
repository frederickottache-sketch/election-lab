#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# sessions/session5_legal.sh
# Session 5 — Legal, Ethical & Public Communication Procedures
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${LAB_DIR}/lib/common.sh"

log_section "Session 5 — Legal, Ethical & Public Communication"

# ── Step 1: Notification templates ───────────────────────────────────────────
log_step "Generating breach notification templates..."
mkdir -p /opt/election-lab/legal/notifications /opt/election-lab/legal/comms

# Voter notification
cat > /opt/election-lab/legal/notifications/voter_notification.txt << 'EOF'
════════════════════════════════════════════════════════════════
IMPORTANT NOTICE REGARDING YOUR VOTER REGISTRATION INFORMATION
                  [DRAFT — FILL IN BEFORE SENDING]
════════════════════════════════════════════════════════════════

Date: [INCIDENT_DATE]
From: Office of the County Clerk — [COUNTY_NAME] County
Re:   Data Security Incident Affecting Voter Registration Records

Dear Registered Voter,

We are writing to inform you of a security incident that may have
affected your voter registration information.

WHAT HAPPENED:
On [INCIDENT_DATE], our security team detected [BRIEF_DESCRIPTION].
The incident affected systems containing voter registration records
including [DATA_TYPES_AFFECTED].

WHAT INFORMATION WAS INVOLVED:
[ ] Name
[ ] Date of birth
[ ] Registered address
[ ] Party affiliation
[ ] No financial or Social Security information was involved

WHAT WE ARE DOING:
• Engaged law enforcement (FBI Cyber Division) immediately
• Isolated affected systems and preserved forensic evidence
• Restored systems from verified clean backups
• Engaged cybersecurity firm [FIRM_NAME] for incident response
• Reported to CISA and State Election Director within 1 hour

WHAT YOU CAN DO:
• Monitor your voter registration status at [STATE_PORTAL_URL]
• Report any suspicious activity to [COUNTY_CLERK_EMAIL]
• Call our dedicated incident hotline: [HOTLINE_NUMBER]

For more information, visit: [COUNTY_WEBSITE]/security-notice
Or contact: [COUNTY_CLERK_EMAIL] | [COUNTY_PHONE]

Sincerely,
[COUNTY_CLERK_NAME]
County Clerk — [COUNTY_NAME] County
────────────────────────────────────────────────────────────────
[TEMPLATE VERSION 1.0 — Election Cybersecurity Lab]
EOF

# State director brief
cat > /opt/election-lab/legal/notifications/state_director_brief.txt << 'EOF'
════════════════════════════════════════════════════════════════
URGENT: CYBER INCIDENT REPORT — [COUNTY_NAME] COUNTY
FOR: State Election Director
CLASSIFICATION: SENSITIVE — ELECTION SECURITY
════════════════════════════════════════════════════════════════

Reporting Official:  [COUNTY_CLERK_NAME], County Clerk
Report Date/Time:    [TIMESTAMP_UTC] UTC
Incident Ref:        INC-[YEAR]-[SEQUENTIAL_NUMBER]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Incident Type:        [RANSOMWARE / DATA BREACH / DDoS / INTRUSION]
Systems Affected:     [LIST_AFFECTED_SYSTEMS]
Voters Affected:      [NUMBER] (estimated)
Election Impact:      [ ] None  [ ] Minor  [ ] SIGNIFICANT
Current Status:       [ ] Ongoing  [ ] Contained  [ ] Resolved

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TIMELINE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[HH:MM]  Initial detection: [HOW_DETECTED]
[HH:MM]  IRT notified
[HH:MM]  Affected systems isolated
[HH:MM]  CISA notified (CISA 24/7: 1-888-282-0870)
[HH:MM]  FBI Cyber notified
[HH:MM]  This report filed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMMEDIATE ACTIONS TAKEN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ ] Affected systems isolated from network
[ ] Forensic evidence preserved (chain of custody maintained)
[ ] Backup systems activated
[ ] Law enforcement notified
[ ] Incident Response Team activated
[ ] Public communication prepared (pending legal review)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUPPORT REQUESTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ ] CISA CISA Cybersecurity Advisory
[ ] State IT assistance
[ ] Additional forensic resources
[ ] Public messaging coordination
[ ] Legal counsel guidance

Next update: [NEXT_UPDATE_TIME]
Contact:     [IRT_LEAD_NAME] — [IRT_LEAD_PHONE] — [IRT_LEAD_EMAIL]
────────────────────────────────────────────────────────────────
[TEMPLATE VERSION 1.0 — Election Cybersecurity Lab]
EOF

# CISA report template
cat > /opt/election-lab/legal/notifications/cisa_report.txt << 'EOF'
════════════════════════════════════════════════════════════════
CISA CYBER INCIDENT REPORT
CIRCIA Mandatory Reporting — Election Infrastructure
════════════════════════════════════════════════════════════════

Report to: CISA 24/7 Operations Center
Phone:     1-888-282-0870
Web:       https://www.cisa.gov/report

Reporting Entity:    [COUNTY_NAME] County Board of Elections
Contact Name:        [IRT_LEAD_NAME]
Contact Email:       [IRT_LEAD_EMAIL]
Contact Phone:       [IRT_LEAD_PHONE]

Incident Date/Time:  [TIMESTAMP_UTC] UTC
Report Date/Time:    [REPORT_TIMESTAMP_UTC] UTC

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INCIDENT DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Category:    [ ] Ransomware  [ ] Data Breach  [ ] DDoS
             [ ] Unauthorized Access  [ ] Supply Chain  [ ] Other

Description: [DETAILED_INCIDENT_DESCRIPTION]

Systems:     [AFFECTED_SYSTEMS_AND_FUNCTION]
Network:     [ ] Air-gapped  [ ] Connected to state network  [ ] Internet-connected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INDICATORS OF COMPROMISE (IOCs)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IP Addresses:  [ATTACKER_IPs]
Domains:       [MALICIOUS_DOMAINS]
File Hashes:   [MD5/SHA256_OF_MALICIOUS_FILES]
Email:         [PHISH_EMAIL_ADDRESSES]

STIX 2.1 bundle attached: [ ] Yes  [ ] No

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMPACT ASSESSMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Voter Records Exposed:  [NUMBER]
Election Operations:    [ ] Unaffected  [ ] Degraded  [ ] Halted
Data Integrity:         [ ] Confirmed intact  [ ] Unknown  [ ] Compromised
────────────────────────────────────────────────────────────────
[TEMPLATE VERSION 1.0 — Election Cybersecurity Lab]
EOF

# Press release template
cat > /opt/election-lab/legal/comms/press_release.txt << 'EOF'
════════════════════════════════════════════════════════════════
FOR IMMEDIATE RELEASE                          [DATE]
════════════════════════════════════════════════════════════════

[COUNTY_NAME] COUNTY ELECTION OFFICE ADDRESSES CYBER SECURITY INCIDENT

[CITY, STATE] — The [COUNTY_NAME] County Election Office today announced
that it detected and responded to a cybersecurity incident affecting
[AFFECTED_SYSTEMS] on [INCIDENT_DATE].

"The integrity of our election systems and the security of voter
information are our highest priorities," said [COUNTY_CLERK_NAME],
County Clerk. "Upon detecting this incident, we immediately activated
our cybersecurity response plan, isolated affected systems, and
engaged federal law enforcement and cybersecurity experts."

KEY FACTS:
  • What:    [BRIEF_DESCRIPTION_NO_SENSITIVE_DETAILS]
  • When:    Detected on [INCIDENT_DATE] at [TIME]
  • Impact:  [ACCURATE_IMPACT_STATEMENT]
  • Status:  [CURRENT_STATUS — e.g., "Systems have been restored"]

ELECTION INTEGRITY:
[COUNTY_NAME] County confirms that [SPECIFIC_ASSURANCE — e.g., "voter
registration data has been restored from verified clean backups and
the integrity of our election records has been confirmed."]

WHAT VOTERS SHOULD DO:
  • Check your registration: [STATE_PORTAL_URL]
  • Call our hotline: [HOTLINE_NUMBER]
  • Report suspicious emails: [REPORT_EMAIL]

The [COUNTY_NAME] County Election Office is working with CISA, the FBI,
and [STATE_AGENCY] to investigate this incident fully.

###

MEDIA CONTACT:
[SPOKESPERSON_NAME]
[TITLE]
[PHONE] | [EMAIL]
[WEBSITE]
────────────────────────────────────────────────────────────────
[TEMPLATE VERSION 1.0 — Election Cybersecurity Lab]
EOF

# Social media template
cat > /opt/election-lab/legal/comms/social_media.txt << 'EOF'
════════════════════════════════════════════════════════════════
SOCIAL MEDIA STATEMENT TEMPLATES
════════════════════════════════════════════════════════════════

--- Twitter/X (under 280 characters) ---
STATEMENT 1 (Initial):
"We are aware of a security incident affecting our systems.
Our team is working around the clock to protect voter data.
We are cooperating with @CISAgov and law enforcement.
More info: [URL] #ElectionSecurity"

STATEMENT 2 (Update):
"UPDATE [DATE]: Systems restored. Voter registration data confirmed
intact. Election operations continue normally. Full statement: [URL]"

STATEMENT 3 (Reassurance):
"Your vote is secure. Our election systems include multiple
independent verification layers. Statement: [URL] #VoterSecurity"

--- Facebook / Longer format ---
[COUNTY NAME] Election Office — Important Update

We want to be transparent with our community about a cybersecurity
incident we detected on [DATE]. [2-3 sentence description].

Your voter registration status is: [STATUS].
To verify your registration: [LINK]
Questions: [PHONE] | [EMAIL]

We are committed to maintaining your trust and the integrity
of every election.
────────────────────────────────────────────────────────────────
[TEMPLATE VERSION 1.0 — Election Cybersecurity Lab]
EOF

log_ok "Notification and communication templates created"

# ── Step 2: Notification timeline checker ────────────────────────────────────
log_step "Creating notification compliance checker..."

cat > /opt/election-lab/legal/check_compliance.py << 'PYEOF'
#!/usr/bin/env python3
"""
Election Breach Notification Compliance Checker
Checks notification timelines against state and federal requirements.
Usage:
  python3 check_compliance.py --incident-date 2024-11-05T14:32:00
  python3 check_compliance.py --incident-date 2024-11-05T14:32:00 --state TX
"""
import argparse, datetime, json

REQUIREMENTS = {
    "FEDERAL": {
        "CISA (CIRCIA)": {
            "hours": 72, "recipient": "CISA Operations Center",
            "contact": "1-888-282-0870 / cisa.gov/report",
            "template": "cisa_report.txt"
        },
        "FBI Cyber Division": {
            "hours": 72, "recipient": "FBI IC3 / Cyber Division",
            "contact": "ic3.gov or local FBI field office",
            "template": None
        },
        "EAC Notification": {
            "hours": 24, "recipient": "Election Assistance Commission",
            "contact": "eac.gov",
            "template": None
        },
    },
    "COMMON_STATES": {
        "CA": {"hours": 72,  "law": "CA Civil Code 1798.82"},
        "TX": {"hours": 60,  "law": "TX Bus & Commerce Code 521.053"},
        "FL": {"hours": 30,  "law": "FL Statute 501.171"},
        "NY": {"hours": 72,  "law": "NY SHIELD Act"},
        "PA": {"hours": 0,   "law": "PA Breach of Personal Info Act (no set deadline — 'expedient')"},
        "GA": {"hours": 0,   "law": "GA Code 10-1-912 (no set deadline — 'in the most expedient time')"},
        "AZ": {"hours": 45*24, "law": "AZ Rev Stat 18-552 (45 days)"},
        "MI": {"hours": 0,   "law": "MI Identity Theft Protection Act (no set deadline)"},
        "WI": {"hours": 0,   "law": "WI Statute 134.98 (no set deadline)"},
        "DEFAULT": {"hours": 72, "law": "State law — verify your state's exact requirement"},
    }
}

def check(incident_str, state=None):
    try:
        incident_dt = datetime.datetime.fromisoformat(incident_str.replace("Z",""))
    except ValueError:
        print(f"[ERROR] Invalid date format. Use ISO 8601: 2024-11-05T14:32:00")
        return

    now = datetime.datetime.utcnow()
    elapsed_h = (now - incident_dt).total_seconds() / 3600

    print(f"\n{'='*60}")
    print(f"  NOTIFICATION COMPLIANCE CHECK")
    print(f"  Incident:   {incident_dt.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Now:        {now.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Elapsed:    {elapsed_h:.1f} hours")
    print(f"{'='*60}")

    print("\n  FEDERAL REQUIREMENTS:")
    for org, req in REQUIREMENTS["FEDERAL"].items():
        deadline_h = req["hours"]
        deadline_dt = incident_dt + datetime.timedelta(hours=deadline_h)
        remaining = deadline_h - elapsed_h
        if remaining > 0:
            status = f"DUE IN {remaining:.1f}h  (by {deadline_dt.strftime('%Y-%m-%d %H:%M UTC')})"
            flag = "⏰"
        else:
            status = f"OVERDUE by {abs(remaining):.1f}h"
            flag = "❌"
        print(f"    {flag}  {org:<30s}  {status}")
        if req.get("contact"):
            print(f"        Contact: {req['contact']}")

    state = (state or "DEFAULT").upper()
    state_req = REQUIREMENTS["COMMON_STATES"].get(state, REQUIREMENTS["COMMON_STATES"]["DEFAULT"])
    print(f"\n  STATE REQUIREMENT ({state}):")
    if state_req["hours"] == 0:
        print(f"    ℹ️   {state_req['law']}")
        print(f"         No fixed deadline — notify as soon as practicable")
    else:
        deadline_h = state_req["hours"]
        deadline_dt = incident_dt + datetime.timedelta(hours=deadline_h)
        remaining = deadline_h - elapsed_h
        if remaining > 0:
            print(f"    ⏰  {state_req['law']}")
            print(f"         DUE IN {remaining:.1f}h  (by {deadline_dt.strftime('%Y-%m-%d %H:%M UTC')})")
        else:
            print(f"    ❌  {state_req['law']}")
            print(f"         OVERDUE by {abs(remaining):.1f}h")

    print(f"\n  TEMPLATES AVAILABLE:")
    import os
    tmpl_dir = os.path.dirname(os.path.abspath(__file__)) + "/notifications"
    if os.path.exists(tmpl_dir):
        for f in os.listdir(tmpl_dir):
            if f.endswith(".txt"):
                print(f"    /opt/election-lab/legal/notifications/{f}")
    print("")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--incident-date", required=True, help="ISO 8601 datetime of incident")
    p.add_argument("--state", default="DEFAULT", help="US state code (e.g. TX, CA, FL)")
    a = p.parse_args()
    check(a.incident_date, a.state)
PYEOF
chmod +x /opt/election-lab/legal/check_compliance.py

# ── Collect evidence ──────────────────────────────────────────────────────────
{
    echo "=== Election Lab Legal & Comms Evidence ==="
    echo "Date: $(date -u)"
    echo ""
    echo "=== Templates Created ==="
    ls -la /opt/election-lab/legal/notifications/
    ls -la /opt/election-lab/legal/comms/
    echo ""
    echo "=== Compliance Checker ==="
    python3 /opt/election-lab/legal/check_compliance.py \
        --incident-date "$(date -u +%Y-%m-%dT%H:%M:%S)" --state DEFAULT 2>/dev/null || true
} > "${EVIDENCE_DIR}/legal_comms_$(date +%Y%m%d_%H%M%S).txt"

log_section "Session 5 Complete"
echo -e "  ${GREEN}✔${RESET}  Voter notification:  /opt/election-lab/legal/notifications/voter_notification.txt"
echo -e "  ${GREEN}✔${RESET}  State director brief: notifications/state_director_brief.txt"
echo -e "  ${GREEN}✔${RESET}  CISA report:         notifications/cisa_report.txt"
echo -e "  ${GREEN}✔${RESET}  Press release:       /opt/election-lab/legal/comms/press_release.txt"
echo -e "  ${GREEN}✔${RESET}  Social media:        /opt/election-lab/legal/comms/social_media.txt"
echo ""
echo -e "${YELLOW}Exercise commands:${RESET}"
echo -e "${BOLD} Exercise 5.1:${RESET}"
echo -e "${CYAN}python3 /opt/election-lab/legal/check_compliance.py --incident-date 2024-11-05T14:32:00 --state TX${RESET}"
echo ""
echo -e "${BOLD} Exercise 5.2:${RESET}"
echo -e "${CYAN}cat /opt/election-lab/legal/notifications/voter_notification.txt${RESET}"
echo ""
echo -e "${BOLD} Exercise 5.3:${RESET}"
echo -e "${CYAN}cat /opt/election-lab/legal/comms/press_release.txt${RESET}"
echo ""

