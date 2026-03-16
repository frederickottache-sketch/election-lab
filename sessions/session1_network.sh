#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# sessions/session1_network.sh
# Session 1 — Network Segmentation: Docker VLANs + nftables Zero-Trust Firewall
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${LAB_DIR}/lib/common.sh"
require_root; require_docker

log_section "Session 1 — Network Segmentation & Zero-Trust Firewall"

# ── Step 1: Docker networks ───────────────────────────────────────────────────
log_step "Creating Docker bridge networks..."

_create_net() {
    local name="$1" subnet="$2" gw="$3"
    if docker network ls --format "{{.Name}}" | grep -q "^${name}$"; then
        log_warn "Network ${name} already exists — skipping"
    else
        docker network create \
            --driver bridge \
            --subnet "$subnet" \
            --gateway "$gw" \
            --opt "com.docker.network.bridge.name=br-$(echo $name | sed 's/lab-election-//')" \
            "$name"
        log_ok "Created network: ${name} (${subnet})"
    fi
}

_create_net "$NET_DMZ"  "$SUBNET_DMZ"  "$GW_DMZ"
_create_net "$NET_INT"  "$SUBNET_INT"  "$GW_INT"
_create_net "$NET_MGMT" "$SUBNET_MGMT" "$GW_MGMT"

# ── Step 2: Election Portal (DMZ) ─────────────────────────────────────────────
log_step "Deploying Election Portal (nginx — DMZ)..."

# Create portal content directories
mkdir -p /tmp/election-portal
mkdir -p /tmp/election-portal/register
mkdir -p /tmp/election-portal/status
mkdir -p /tmp/election-portal/polling
mkdir -p /tmp/election-portal/results
mkdir -p /tmp/election-portal/vote
mkdir -p /tmp/election-portal/api

# ────────────────────────────────────────────────────────────────────────────
# Shared CSS / design tokens (embedded inline in each page for portability)
# ────────────────────────────────────────────────────────────────────────────
SHARED_CSS='
  @import url("https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;900&family=Source+Sans+3:wght@300;400;600&display=swap");
  :root {
    --navy:   #0D1B2A;
    --blue:   #1B3A6B;
    --accent: #C8102E;
    --gold:   #B8860B;
    --light:  #F4F6F9;
    --white:  #FFFFFF;
    --border: #D0D7E2;
    --text:   #1a1a2e;
    --muted:  #6B7A99;
    --green:  #0A6E3F;
    --shadow: 0 4px 24px rgba(13,27,42,0.10);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: "Source Sans 3", sans-serif;
    background: var(--light);
    color: var(--text);
    min-height: 100vh;
    display: flex; flex-direction: column;
  }

  /* ── Header ── */
  header {
    background: linear-gradient(135deg, var(--navy) 0%, var(--blue) 100%);
    color: var(--white);
    padding: 0;
    box-shadow: 0 2px 12px rgba(0,0,0,0.25);
    position: sticky; top: 0; z-index: 100;
  }
  .header-top {
    display: flex; align-items: center; gap: 18px;
    padding: 14px 40px;
    border-bottom: 1px solid rgba(255,255,255,0.12);
  }
  .seal { font-size: 2.4rem; }
  .header-title h1 {
    font-family: "Playfair Display", serif;
    font-size: 1.25rem; font-weight: 700; letter-spacing: 0.01em;
  }
  .header-title p { font-size: 0.78rem; opacity: 0.75; margin-top: 2px; }
  .security-badge {
    margin-left: auto;
    background: rgba(200,16,46,0.18);
    border: 1px solid rgba(200,16,46,0.5);
    color: #ffaaaa;
    font-size: 0.7rem; font-weight: 600;
    padding: 4px 10px; border-radius: 4px;
    letter-spacing: 0.08em; text-transform: uppercase;
  }
  nav {
    display: flex; gap: 0; padding: 0 32px;
    overflow-x: auto;
  }
  nav a {
    color: rgba(255,255,255,0.78);
    text-decoration: none;
    font-size: 0.82rem; font-weight: 600;
    padding: 10px 18px;
    border-bottom: 3px solid transparent;
    transition: all 0.2s; white-space: nowrap;
    text-transform: uppercase; letter-spacing: 0.06em;
  }
  nav a:hover, nav a.active {
    color: var(--white);
    border-bottom-color: var(--accent);
    background: rgba(255,255,255,0.07);
  }

  /* ── Page shell ── */
  .page-hero {
    background: linear-gradient(135deg, var(--navy) 0%, var(--blue) 60%, #2a5298 100%);
    color: var(--white);
    padding: 44px 40px 36px;
  }
  .page-hero h2 {
    font-family: "Playfair Display", serif;
    font-size: 2rem; font-weight: 900;
  }
  .page-hero p { opacity: 0.8; margin-top: 6px; font-size: 1rem; }
  main { flex: 1; padding: 40px; max-width: 960px; margin: 0 auto; width: 100%; }

  /* ── Notices ── */
  .notice {
    background: #fff8e1;
    border-left: 5px solid var(--gold);
    padding: 14px 18px; border-radius: 0 8px 8px 0;
    margin-bottom: 28px; font-size: 0.88rem;
  }
  .notice.info {
    background: #e8f4fd; border-left-color: var(--blue);
  }
  .notice.success {
    background: #e6f9f0; border-left-color: var(--green);
  }
  .notice.danger {
    background: #fdecea; border-left-color: var(--accent);
  }
  .notice strong { display: block; margin-bottom: 4px; }

  /* ── Card ── */
  .card {
    background: var(--white);
    border-radius: 12px;
    box-shadow: var(--shadow);
    padding: 32px;
    margin-bottom: 28px;
    border: 1px solid var(--border);
  }
  .card h3 {
    font-family: "Playfair Display", serif;
    font-size: 1.25rem; color: var(--blue);
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 2px solid var(--border);
  }

  /* ── Form elements ── */
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  .form-group { display: flex; flex-direction: column; gap: 6px; }
  .form-group.full { grid-column: 1 / -1; }
  label { font-size: 0.82rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  input, select {
    border: 1.5px solid var(--border);
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 0.95rem;
    font-family: inherit;
    color: var(--text);
    background: var(--white);
    transition: border-color 0.2s, box-shadow 0.2s;
    width: 100%;
  }
  input:focus, select:focus {
    outline: none;
    border-color: var(--blue);
    box-shadow: 0 0 0 3px rgba(27,58,107,0.12);
  }

  /* ── Buttons ── */
  .btn {
    display: inline-flex; align-items: center; gap: 8px;
    background: var(--blue); color: var(--white);
    border: none; border-radius: 8px;
    padding: 12px 28px;
    font-size: 0.95rem; font-weight: 700;
    font-family: inherit; cursor: pointer;
    text-decoration: none;
    transition: background 0.2s, transform 0.1s, box-shadow 0.2s;
    letter-spacing: 0.03em;
  }
  .btn:hover { background: var(--navy); transform: translateY(-1px); box-shadow: 0 6px 18px rgba(13,27,42,0.2); }
  .btn:active { transform: translateY(0); }
  .btn.danger { background: var(--accent); }
  .btn.danger:hover { background: #a00d23; }
  .btn.success { background: var(--green); }
  .btn.success:hover { background: #085530; }
  .btn.outline {
    background: transparent; color: var(--blue);
    border: 2px solid var(--blue);
  }
  .btn.outline:hover { background: var(--blue); color: var(--white); }
  .btn-row { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 24px; }

  /* ── Security metadata strip ── */
  .sec-strip {
    font-size: 0.72rem; color: var(--muted);
    background: var(--white);
    border-top: 1px solid var(--border);
    padding: 8px 40px;
    display: flex; gap: 24px; flex-wrap: wrap;
  }
  .sec-strip span { display: flex; align-items: center; gap: 5px; }
  .dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
  .dot.green { background: #2ecc71; }
  .dot.red   { background: var(--accent); }
  .dot.gold  { background: var(--gold); }

  /* ── Footer ── */
  footer {
    background: var(--navy); color: rgba(255,255,255,0.5);
    padding: 18px 40px; font-size: 0.75rem;
    display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 8px;
  }

  /* ── Result bars ── */
  .candidate-result { margin-bottom: 22px; }
  .candidate-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
  .candidate-name { font-weight: 700; font-size: 1.05rem; }
  .candidate-pct { font-size: 1.05rem; color: var(--blue); font-weight: 700; }
  .bar-track { background: var(--border); border-radius: 100px; height: 22px; overflow: hidden; }
  .bar-fill {
    height: 100%;
    border-radius: 100px;
    transition: width 1.2s cubic-bezier(0.4,0,0.2,1);
    display: flex; align-items: center; justify-content: flex-end;
    padding-right: 10px;
    font-size: 0.75rem; color: white; font-weight: 700;
  }
  .bar-fill.c1 { background: linear-gradient(90deg, var(--blue), #2a5298); }
  .bar-fill.c2 { background: linear-gradient(90deg, var(--accent), #e8234a); }
  .bar-fill.c3 { background: linear-gradient(90deg, var(--gold), #d4a520); }

  /* ── Polling table ── */
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th { background: var(--navy); color: var(--white); padding: 11px 16px; text-align: left; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; }
  td { padding: 11px 16px; border-bottom: 1px solid var(--border); }
  tr:hover td { background: #f0f4fb; }
  .badge {
    display: inline-block; padding: 3px 9px; border-radius: 100px;
    font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
  }
  .badge.open   { background: #d4edda; color: #145a32; }
  .badge.closed { background: #f8d7da; color: #7b1c2a; }

  /* ── Vote ballot ── */
  .ballot-option {
    border: 2px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
    cursor: pointer;
    transition: all 0.2s;
    display: flex; align-items: center; gap: 16px;
  }
  .ballot-option:hover { border-color: var(--blue); background: #f0f4fb; }
  .ballot-option.selected { border-color: var(--blue); background: #e8f0fb; box-shadow: 0 0 0 3px rgba(27,58,107,0.15); }
  .ballot-radio {
    width: 22px; height: 22px; border-radius: 50%;
    border: 2px solid var(--border); flex-shrink: 0;
    transition: all 0.2s; display: flex; align-items: center; justify-content: center;
  }
  .ballot-option.selected .ballot-radio { border-color: var(--blue); background: var(--blue); }
  .ballot-option.selected .ballot-radio::after {
    content: ""; width: 10px; height: 10px;
    background: white; border-radius: 50%;
  }
  .candidate-info h4 { font-size: 1.1rem; font-weight: 700; }
  .candidate-info p  { font-size: 0.85rem; color: var(--muted); margin-top: 3px; }
  .candidate-party {
    margin-left: auto;
    font-size: 0.75rem; font-weight: 700;
    padding: 4px 12px; border-radius: 100px;
  }
  .party-a { background: #dbeafe; color: #1e40af; }
  .party-b { background: #fee2e2; color: #991b1b; }

  /* ── Responsive ── */
  @media (max-width: 680px) {
    .form-grid { grid-template-columns: 1fr; }
    main { padding: 20px; }
    .header-top { padding: 12px 20px; }
    nav { padding: 0 12px; }
  }

  /* ── Step progress ── */
  .steps { display: flex; gap: 0; margin-bottom: 32px; }
  .step {
    flex: 1; text-align: center;
    padding: 12px 8px;
    font-size: 0.78rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.05em;
    color: var(--muted);
    border-bottom: 3px solid var(--border);
  }
  .step.active { color: var(--blue); border-bottom-color: var(--blue); }
  .step.done   { color: var(--green); border-bottom-color: var(--green); }

  /* ── Hidden ── */
  .hidden { display: none !important; }
'

# Helper for consistent nav / header
_nav_html() {
  local active="$1"
  cat <<NAVEOF
  <header>
    <div class="header-top">
      <div class="seal">🗳️</div>
      <div class="header-title">
        <h1>County Election Office — Voter Information Portal</h1>
        <p>Official Election Management System &nbsp;|&nbsp; DMZ Segment: 172.21.10.0/24</p>
      </div>
      <div class="security-badge">🔒 TLS Enforced</div>
    </div>
    <nav>
      <a href="/" $([ "$active" = "home" ]    && echo 'class="active"')>Home</a>
      <a href="/register/" $([ "$active" = "register" ] && echo 'class="active"')>Register to Vote</a>
      <a href="/status/"   $([ "$active" = "status" ]   && echo 'class="active"')>Check Status</a>
      <a href="/polling/"  $([ "$active" = "polling" ]  && echo 'class="active"')>Polling Locations</a>
      <a href="/vote/"     $([ "$active" = "vote" ]     && echo 'class="active"')>Cast Your Vote</a>
      <a href="/results/"  $([ "$active" = "results" ]  && echo 'class="active"')>Election Results</a>
    </nav>
  </header>
NAVEOF
}

_sec_strip_html() {
  cat <<SECEOF
  <div class="sec-strip">
    <span><span class="dot green"></span> DMZ Segment: 172.21.10.10</span>
    <span><span class="dot red"></span>   DB Access: BLOCKED (Zero-Trust nftables)</span>
    <span><span class="dot gold"></span>  Auth Gateway: 172.21.30.x (MGMT)</span>
    <span><span class="dot green"></span> Rate-limit: 200 req/min enforced</span>
    <span>Session ID: $(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "SIM-8a3f2c1d")</span>
  </div>
SECEOF
}

_footer_html() {
  cat <<FOOTEREOF
  <footer>
    <span>Election Cybersecurity Lab — Lite Edition &nbsp;|&nbsp; For educational use only</span>
    <span>Network: lab-election-dmz &nbsp;·&nbsp; Firewall: nftables Zero-Trust &nbsp;·&nbsp; $(date -u '+%Y-%m-%d %H:%M UTC')</span>
  </footer>
FOOTEREOF
}

# ────────────────────────────────────────────────────────────────────────────
# PAGE 1: index.html — Home / Landing
# ────────────────────────────────────────────────────────────────────────────
cat > /tmp/election-portal/index.html << EOF_HOME
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>County Election Office — Voter Information Portal</title>
<style>${SHARED_CSS}
  .hero-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 28px; }
  .quick-action {
    background: var(--white); border-radius: 12px;
    box-shadow: var(--shadow); border: 1px solid var(--border);
    padding: 28px; text-decoration: none; color: var(--text);
    display: flex; flex-direction: column; gap: 10px;
    transition: transform 0.2s, box-shadow 0.2s;
  }
  .quick-action:hover { transform: translateY(-3px); box-shadow: 0 8px 32px rgba(13,27,42,0.15); }
  .quick-action .icon { font-size: 2.2rem; }
  .quick-action h3 { font-family: "Playfair Display", serif; font-size: 1.1rem; color: var(--blue); }
  .quick-action p { font-size: 0.85rem; color: var(--muted); }
  .quick-action .arrow { margin-top: auto; color: var(--blue); font-weight: 700; font-size: 0.85rem; }
  @media (max-width: 680px) { .hero-grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
$(_nav_html home)
<div class="page-hero">
  <h2>Welcome to the Voter Information Portal</h2>
  <p>Register, verify your status, find your polling location, cast your ballot, and view results — all in one secure place.</p>
</div>
<main>
  <div class="notice">
    <strong>⚠ Lab Environment Notice</strong>
    This is a simulated election portal for cybersecurity training purposes only.
    Running on <strong>lab-election-dmz</strong> (172.21.10.0/24).
    All voter data is synthetic. Zero-Trust nftables rules are enforced at the network boundary.
  </div>
  <div class="notice info">
    <strong>📢 General Election — November 2024</strong>
    Polls are open. Registered voters may cast their ballot online through this portal.
    The database tier (172.21.20.10) is isolated from the DMZ by policy — all form submissions pass through the API gateway on the Management segment.
  </div>

  <div class="hero-grid">
    <a class="quick-action" href="/register/">
      <span class="icon">📋</span>
      <h3>Register to Vote</h3>
      <p>New voters can register here. Existing registrations are verified against the ElectionDB on the Internal segment.</p>
      <span class="arrow">Register now →</span>
    </a>
    <a class="quick-action" href="/status/">
      <span class="icon">🔍</span>
      <h3>Check Registration Status</h3>
      <p>Look up your voter registration record using your name and date of birth. Status queries are read-only and rate-limited.</p>
      <span class="arrow">Check status →</span>
    </a>
    <a class="quick-action" href="/polling/">
      <span class="icon">📍</span>
      <h3>Find Polling Location</h3>
      <p>Locate your assigned polling place by precinct. All three precincts are open from 06:00–20:00 local time.</p>
      <span class="arrow">Find location →</span>
    </a>
    <a class="quick-action" href="/vote/">
      <span class="icon">🗳️</span>
      <h3>Cast Your Vote</h3>
      <p>Registered voters can cast a secure online ballot. Ballot submissions are signed and forwarded to the Internal segment via the authenticated API gateway.</p>
      <span class="arrow">Vote now →</span>
    </a>
  </div>

  <div class="card">
    <h3>Security Architecture Overview</h3>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;font-size:0.83rem;">
      <div style="padding:14px;background:var(--light);border-radius:8px;border-left:4px solid var(--blue);">
        <strong style="color:var(--blue);">🌐 DMZ (172.21.10.0/24)</strong><br><br>
        This portal (nginx:alpine)<br>
        IP: 172.21.10.10:80<br>
        Public-facing, hardened<br>
        <em style="color:var(--muted);">No direct DB access</em>
      </div>
      <div style="padding:14px;background:var(--light);border-radius:8px;border-left:4px solid var(--accent);">
        <strong style="color:var(--accent);">🔒 Internal (172.21.20.0/24)</strong><br><br>
        ElectionDB (PostgreSQL)<br>
        IP: 172.21.20.10:5432<br>
        Voter records & ballots<br>
        <em style="color:var(--muted);">DMZ→INT blocked by nftables</em>
      </div>
      <div style="padding:14px;background:var(--light);border-radius:8px;border-left:4px solid var(--gold);">
        <strong style="color:var(--gold);">🛡️ MGMT (172.21.30.0/24)</strong><br><br>
        Auth & API Gateway<br>
        Audit logging service<br>
        Admin console<br>
        <em style="color:var(--muted);">Red-team→MGMT blocked</em>
      </div>
    </div>
  </div>

  <a href="/results/" class="btn" style="margin-top:8px;">📊 View Live Election Results</a>
</main>
$(_sec_strip_html)
$(_footer_html)
</body>
</html>
EOF_HOME

# ────────────────────────────────────────────────────────────────────────────
# PAGE 2: /register/index.html — Voter Registration
# ────────────────────────────────────────────────────────────────────────────
cat > /tmp/election-portal/register/index.html << 'EOF_REGISTER'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register to Vote — County Election Office</title>
EOF_REGISTER

cat >> /tmp/election-portal/register/index.html << EOF_REGISTER_STYLE
<style>${SHARED_CSS}</style>
</head>
<body>
$(_nav_html register)
<div class="page-hero">
  <h2>📋 Voter Registration</h2>
  <p>Complete the form below to register. Your information is encrypted in transit and stored securely on the Internal segment database.</p>
</div>
<main>
  <div class="steps">
    <div class="step active" id="step-lbl-1">1 · Personal Info</div>
    <div class="step" id="step-lbl-2">2 · Address</div>
    <div class="step" id="step-lbl-3">3 · Review &amp; Submit</div>
    <div class="step" id="step-lbl-4">4 · Confirmation</div>
  </div>

  <div class="notice info">
    <strong>🔐 Security Notice</strong>
    This form is served from the DMZ (172.21.10.10). Submission triggers an authenticated POST
    to the API Gateway on the Management segment (172.21.30.x), which writes to ElectionDB (172.21.20.10)
    after validating CSRF token and rate-limit quotas. Direct DMZ→Internal traffic is BLOCKED by nftables.
  </div>

  <!-- Step 1 -->
  <div id="step-1" class="card">
    <h3>Personal Information</h3>
    <div class="form-grid">
      <div class="form-group">
        <label>First Name *</label>
        <input type="text" id="fname" placeholder="Jane" required>
      </div>
      <div class="form-group">
        <label>Last Name *</label>
        <input type="text" id="lname" placeholder="Smith" required>
      </div>
      <div class="form-group">
        <label>Date of Birth *</label>
        <input type="date" id="dob" required>
      </div>
      <div class="form-group">
        <label>Last 4 of SSN *</label>
        <input type="password" id="ssn4" maxlength="4" placeholder="••••" required>
      </div>
      <div class="form-group">
        <label>Email Address</label>
        <input type="email" id="email" placeholder="jane.smith@example.com">
      </div>
      <div class="form-group">
        <label>Phone Number</label>
        <input type="tel" id="phone" placeholder="(555) 000-0000">
      </div>
    </div>
    <div class="btn-row">
      <button class="btn" onclick="nextStep(1)">Continue →</button>
      <a href="/" class="btn outline">Cancel</a>
    </div>
  </div>

  <!-- Step 2 -->
  <div id="step-2" class="card hidden">
    <h3>Residential Address</h3>
    <div class="form-grid">
      <div class="form-group full">
        <label>Street Address *</label>
        <input type="text" id="addr1" placeholder="123 Main Street" required>
      </div>
      <div class="form-group full">
        <label>Apt / Suite / Unit</label>
        <input type="text" id="addr2" placeholder="Apt 4B">
      </div>
      <div class="form-group">
        <label>City *</label>
        <input type="text" id="city" placeholder="Springfield" required>
      </div>
      <div class="form-group">
        <label>State *</label>
        <select id="state" required>
          <option value="">Select…</option>
          <option>Alabama</option><option>Alaska</option><option>Arizona</option>
          <option>Arkansas</option><option>California</option><option>Colorado</option>
          <option>Connecticut</option><option>Delaware</option><option>Florida</option>
          <option>Georgia</option><option>Hawaii</option><option>Idaho</option>
          <option>Illinois</option><option>Indiana</option><option>Iowa</option>
          <option>Kansas</option><option>Kentucky</option><option>Louisiana</option>
          <option>Maine</option><option>Maryland</option><option>Massachusetts</option>
          <option>Michigan</option><option>Minnesota</option><option>Mississippi</option>
          <option>Missouri</option><option>Montana</option><option>Nebraska</option>
          <option>Nevada</option><option>New Hampshire</option><option>New Jersey</option>
          <option>New Mexico</option><option>New York</option><option>North Carolina</option>
          <option>North Dakota</option><option>Ohio</option><option>Oklahoma</option>
          <option>Oregon</option><option>Pennsylvania</option><option>Rhode Island</option>
          <option>South Carolina</option><option>South Dakota</option><option>Tennessee</option>
          <option>Texas</option><option>Utah</option><option>Vermont</option>
          <option>Virginia</option><option>Washington</option><option>West Virginia</option>
          <option>Wisconsin</option><option>Wyoming</option>
        </select>
      </div>
      <div class="form-group">
        <label>ZIP Code *</label>
        <input type="text" id="zip" maxlength="10" placeholder="12345" required>
      </div>
      <div class="form-group">
        <label>Precinct (auto-assigned)</label>
        <input type="text" id="precinct" readonly placeholder="Will be assigned on submit" style="background:#f4f6f9;color:var(--muted);">
      </div>
    </div>
    <div class="btn-row">
      <button class="btn" onclick="nextStep(2)">Continue →</button>
      <button class="btn outline" onclick="prevStep(2)">← Back</button>
    </div>
  </div>

  <!-- Step 3: Review -->
  <div id="step-3" class="card hidden">
    <h3>Review Your Information</h3>
    <div id="review-content" style="font-size:0.93rem;line-height:1.9;"></div>
    <div class="notice" style="margin-top:20px;">
      <strong>Declaration</strong>
      By submitting this form, I certify that I am a U.S. citizen, at least 18 years of age,
      and that the information I have provided is accurate and complete to the best of my knowledge.
    </div>
    <div class="btn-row">
      <button class="btn success" onclick="submitRegistration()">✅ Submit Registration</button>
      <button class="btn outline" onclick="prevStep(3)">← Back</button>
    </div>
  </div>

  <!-- Step 4: Confirmation -->
  <div id="step-4" class="card hidden" style="text-align:center;padding:48px 32px;">
    <div style="font-size:3.5rem;margin-bottom:16px;">✅</div>
    <h3 style="color:var(--green);border:none;padding:0;font-size:1.6rem;">Registration Submitted!</h3>
    <p style="margin:16px 0 8px;font-size:1rem;color:var(--muted);">Your voter registration has been forwarded to the API Gateway for processing.</p>
    <p id="confirm-ref" style="font-family:monospace;background:var(--light);padding:8px 16px;border-radius:6px;display:inline-block;margin:12px 0;font-size:0.85rem;"></p>
    <div class="notice info" style="text-align:left;margin:20px 0;">
      <strong>🔐 What happens next (security pipeline):</strong>
      <ol style="margin-top:8px;padding-left:18px;line-height:2;">
        <li>CSRF token validated by API Gateway (172.21.30.x)</li>
        <li>Input sanitized and parameterized before DB write</li>
        <li>Precinct auto-assigned by geo-lookup service</li>
        <li>Record written to <code>voterdb.voters</code> on ElectionDB (172.21.20.10)</li>
        <li>Audit event logged to MGMT segment audit service</li>
        <li>Confirmation email dispatched (simulated)</li>
      </ol>
    </div>
    <div class="btn-row" style="justify-content:center;">
      <a href="/status/" class="btn">Check Registration Status</a>
      <a href="/vote/" class="btn success">Cast Your Vote</a>
      <a href="/" class="btn outline">Return Home</a>
    </div>
  </div>
</main>

<script>
const PRECINCTS = ['P001','P002','P003'];
let currentStep = 1;

function nextStep(from) {
  if (from === 1) {
    if (!document.getElementById('fname').value.trim() ||
        !document.getElementById('lname').value.trim() ||
        !document.getElementById('dob').value) {
      alert('Please fill in all required fields.');
      return;
    }
  }
  if (from === 2) {
    if (!document.getElementById('addr1').value.trim() ||
        !document.getElementById('city').value.trim() ||
        !document.getElementById('state').value ||
        !document.getElementById('zip').value.trim()) {
      alert('Please fill in all required address fields.');
      return;
    }
    // Auto-assign precinct
    const zip = document.getElementById('zip').value;
    const idx = parseInt(zip.slice(-1), 10) % 3;
    document.getElementById('precinct').value = PRECINCTS[idx];

    // Populate review
    const p = document.getElementById('precinct').value;
    document.getElementById('review-content').innerHTML = \`
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:6px 0;color:var(--muted);width:180px;font-weight:600;">Full Name</td><td>\${document.getElementById('fname').value} \${document.getElementById('lname').value}</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted);font-weight:600;">Date of Birth</td><td>\${document.getElementById('dob').value}</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted);font-weight:600;">Email</td><td>\${document.getElementById('email').value || '—'}</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted);font-weight:600;">Phone</td><td>\${document.getElementById('phone').value || '—'}</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted);font-weight:600;">Address</td><td>\${document.getElementById('addr1').value}\${document.getElementById('addr2').value ? ', '+document.getElementById('addr2').value : ''}, \${document.getElementById('city').value}, \${document.getElementById('state').value} \${document.getElementById('zip').value}</td></tr>
        <tr><td style="padding:6px 0;color:var(--muted);font-weight:600;">Assigned Precinct</td><td><strong>\${p}</strong></td></tr>
        <tr><td style="padding:6px 0;color:var(--muted);font-weight:600;">Route</td><td style="font-family:monospace;font-size:0.8rem;">POST /api/voters → API-GW (172.21.30.x) → ElectionDB (172.21.20.10)</td></tr>
      </table>
    \`;
  }

  document.getElementById('step-' + from).classList.add('hidden');
  document.getElementById('step-' + (from + 1)).classList.remove('hidden');
  document.getElementById('step-lbl-' + from).classList.remove('active');
  document.getElementById('step-lbl-' + from).classList.add('done');
  document.getElementById('step-lbl-' + (from + 1)).classList.add('active');
  currentStep = from + 1;
}

function prevStep(from) {
  document.getElementById('step-' + from).classList.add('hidden');
  document.getElementById('step-' + (from - 1)).classList.remove('hidden');
  document.getElementById('step-lbl-' + from).classList.remove('active');
  document.getElementById('step-lbl-' + (from - 1)).classList.remove('done');
  document.getElementById('step-lbl-' + (from - 1)).classList.add('active');
  currentStep = from - 1;
}

function submitRegistration() {
  const ref = 'REG-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,6).toUpperCase();
  document.getElementById('confirm-ref').textContent = 'Reference: ' + ref + ' | Segment: DMZ→MGMT→INT';
  document.getElementById('step-3').classList.add('hidden');
  document.getElementById('step-4').classList.remove('hidden');
  document.getElementById('step-lbl-3').classList.remove('active');
  document.getElementById('step-lbl-3').classList.add('done');
  document.getElementById('step-lbl-4').classList.add('active');
  document.getElementById('step-lbl-4').classList.add('done');
}
</script>
$(_sec_strip_html)
$(_footer_html)
</body>
</html>
EOF_REGISTER_STYLE

# ────────────────────────────────────────────────────────────────────────────
# PAGE 3: /status/index.html — Registration Status Lookup
# ────────────────────────────────────────────────────────────────────────────
cat > /tmp/election-portal/status/index.html << EOF_STATUS
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Check Registration Status — County Election Office</title>
<style>${SHARED_CSS}
  .result-card {
    border-radius: 12px; padding: 28px;
    border: 2px solid var(--green); background: #f0fdf6;
    margin-top: 24px;
  }
  .result-card h3 { color: var(--green); font-family:"Playfair Display",serif; margin-bottom:14px; }
  .field-row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #c8eedd; font-size:0.9rem; }
  .field-row:last-child { border:none; }
  .field-label { color:var(--muted); font-weight:600; }
  .status-chip {
    display:inline-flex; align-items:center; gap:6px;
    background:#d1fae5; color:#065f46;
    border-radius:100px; padding:4px 14px; font-size:0.82rem; font-weight:700;
  }
</style>
</head>
<body>
$(_nav_html status)
<div class="page-hero">
  <h2>🔍 Check Registration Status</h2>
  <p>Look up your voter registration record using your personal details. Queries are read-only and rate-limited to 10 per session.</p>
</div>
<main>
  <div class="notice">
    <strong>⚠ Privacy Notice</strong>
    This lookup queries the ElectionDB on the Internal segment (172.21.20.10) via the authenticated API Gateway.
    All queries are logged. Direct DMZ-to-Internal access is blocked by nftables — you cannot bypass this lookup page to query the database directly.
  </div>

  <div class="card">
    <h3>Voter Status Lookup</h3>
    <div class="form-grid">
      <div class="form-group">
        <label>First Name *</label>
        <input type="text" id="s-fname" placeholder="Jane">
      </div>
      <div class="form-group">
        <label>Last Name *</label>
        <input type="text" id="s-lname" placeholder="Smith">
      </div>
      <div class="form-group">
        <label>Date of Birth *</label>
        <input type="date" id="s-dob">
      </div>
      <div class="form-group">
        <label>ZIP Code *</label>
        <input type="text" id="s-zip" maxlength="10" placeholder="12345">
      </div>
    </div>
    <div class="btn-row">
      <button class="btn" onclick="lookupStatus()">🔍 Look Up Status</button>
      <button class="btn outline" onclick="clearForm()">Clear</button>
    </div>

    <div id="loading" class="hidden" style="margin-top:20px;color:var(--muted);font-style:italic;">
      ⏳ Querying API Gateway → ElectionDB… (simulated)
    </div>

    <div id="result-found" class="hidden result-card">
      <h3>✅ Registration Found</h3>
      <div class="field-row"><span class="field-label">Full Name</span>        <span id="r-name"></span></div>
      <div class="field-row"><span class="field-label">Date of Birth</span>    <span id="r-dob"></span></div>
      <div class="field-row"><span class="field-label">Precinct</span>         <span id="r-precinct"></span></div>
      <div class="field-row"><span class="field-label">Registration Status</span><span><span class="status-chip">✔ Active &amp; Verified</span></span></div>
      <div class="field-row"><span class="field-label">Ballot Cast</span>      <span id="r-voted"></span></div>
      <div class="field-row"><span class="field-label">Data Source</span>      <span style="font-family:monospace;font-size:0.78rem;">ElectionDB (172.21.20.10) via API-GW (172.21.30.x)</span></div>
      <div class="btn-row" style="margin-top:16px;">
        <a href="/vote/" class="btn success">🗳️ Cast Your Vote</a>
        <a href="/polling/" class="btn outline">📍 Find Polling Place</a>
      </div>
    </div>

    <div id="result-not-found" class="hidden" style="margin-top:20px;">
      <div class="notice danger">
        <strong>❌ No Record Found</strong>
        No voter registration was found matching the information you provided. Please check your details or
        <a href="/register/" style="color:var(--accent);font-weight:700;">register to vote</a>.
      </div>
    </div>
  </div>

  <div class="card">
    <h3>Sample Records (Lab Reference)</h3>
    <p style="font-size:0.85rem;color:var(--muted);margin-bottom:16px;">The following synthetic voter records are seeded in the ElectionDB. Use any of these to simulate a successful lookup.</p>
    <table>
      <thead><tr><th>Name</th><th>DOB</th><th>Precinct</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>Jane Smith</td><td>1985-03-15</td><td>P001</td><td><span class="badge open">Active</span></td></tr>
        <tr><td>Michael Johnson</td><td>1972-07-22</td><td>P002</td><td><span class="badge open">Active</span></td></tr>
        <tr><td>Sarah Williams</td><td>1990-11-08</td><td>P001</td><td><span class="badge open">Active</span></td></tr>
        <tr><td>David Brown</td><td>1968-05-30</td><td>P003</td><td><span class="badge open">Active</span></td></tr>
        <tr><td>Emily Davis</td><td>1995-01-14</td><td>P002</td><td><span class="badge open">Active</span></td></tr>
      </tbody>
    </table>
  </div>
</main>

<script>
const VOTERS = [
  {first:'Jane',    last:'Smith',    dob:'1985-03-15', precinct:'P001', voted:false},
  {first:'Michael', last:'Johnson',  dob:'1972-07-22', precinct:'P002', voted:false},
  {first:'Sarah',   last:'Williams', dob:'1990-11-08', precinct:'P001', voted:true},
  {first:'David',   last:'Brown',    dob:'1968-05-30', precinct:'P003', voted:false},
  {first:'Emily',   last:'Davis',    dob:'1995-01-14', precinct:'P002', voted:true},
];

function lookupStatus() {
  const fn = document.getElementById('s-fname').value.trim().toLowerCase();
  const ln = document.getElementById('s-lname').value.trim().toLowerCase();
  const dob = document.getElementById('s-dob').value;
  if (!fn || !ln || !dob) { alert('Please fill in all required fields.'); return; }

  document.getElementById('loading').classList.remove('hidden');
  document.getElementById('result-found').classList.add('hidden');
  document.getElementById('result-not-found').classList.add('hidden');

  setTimeout(() => {
    document.getElementById('loading').classList.add('hidden');
    const match = VOTERS.find(v =>
      v.first.toLowerCase() === fn &&
      v.last.toLowerCase()  === ln &&
      v.dob === dob
    );
    if (match) {
      document.getElementById('r-name').textContent     = match.first + ' ' + match.last;
      document.getElementById('r-dob').textContent      = match.dob;
      document.getElementById('r-precinct').textContent = match.precinct;
      document.getElementById('r-voted').textContent    = match.voted ? '✅ Yes — ballot recorded' : '⬜ Not yet cast';
      document.getElementById('result-found').classList.remove('hidden');
    } else {
      document.getElementById('result-not-found').classList.remove('hidden');
    }
  }, 1400);
}

function clearForm() {
  ['s-fname','s-lname','s-dob','s-zip'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('result-found').classList.add('hidden');
  document.getElementById('result-not-found').classList.add('hidden');
}
</script>
$(_sec_strip_html)
$(_footer_html)
</body>
</html>
EOF_STATUS

# ────────────────────────────────────────────────────────────────────────────
# PAGE 4: /polling/index.html — Polling Locations
# ────────────────────────────────────────────────────────────────────────────
cat > /tmp/election-portal/polling/index.html << EOF_POLLING
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Polling Locations — County Election Office</title>
<style>${SHARED_CSS}
  .location-card {
    display:grid; grid-template-columns:1fr auto;
    gap:20px; align-items:start;
    background:var(--white); border-radius:12px;
    box-shadow:var(--shadow); border:1px solid var(--border);
    padding:24px 28px; margin-bottom:20px;
  }
  .location-card h4 { font-family:"Playfair Display",serif; font-size:1.1rem; color:var(--blue); margin-bottom:6px; }
  .location-meta { font-size:0.85rem; color:var(--muted); line-height:1.8; }
  .location-meta strong { color:var(--text); }
  .hours-badge {
    background: linear-gradient(135deg,var(--navy),var(--blue));
    color:white; border-radius:10px;
    padding:14px 18px; text-align:center; min-width:110px;
    font-size:0.78rem;
  }
  .hours-badge .time { font-size:1.1rem; font-weight:700; display:block; margin-top:4px; }
  .precinct-filter { display:flex; gap:10px; margin-bottom:24px; flex-wrap:wrap; }
  .filter-btn {
    padding:8px 20px; border-radius:100px; border:2px solid var(--border);
    background:var(--white); color:var(--muted); cursor:pointer;
    font-size:0.82rem; font-weight:700; font-family:inherit;
    transition:all 0.2s; text-transform:uppercase; letter-spacing:0.05em;
  }
  .filter-btn.active, .filter-btn:hover {
    border-color:var(--blue); color:var(--blue); background:#f0f4fb;
  }
  .map-placeholder {
    background:linear-gradient(135deg,#e8edf5,#d0d9ea);
    border-radius:12px; height:180px;
    display:flex; align-items:center; justify-content:center;
    color:var(--muted); font-size:0.85rem; border:1px dashed var(--border);
    margin-bottom:20px;
  }
</style>
</head>
<body>
$(_nav_html polling)
<div class="page-hero">
  <h2>📍 Polling Locations</h2>
  <p>Find your assigned polling place. All locations are open today from 06:00 to 20:00. Bring a valid photo ID.</p>
</div>
<main>
  <div class="notice info">
    <strong>📌 How to find your precinct</strong>
    Check your precinct code on your registration confirmation or use the
    <a href="/status/" style="color:var(--blue);font-weight:700;">Status Lookup</a> page.
    Your precinct assignment is stored in the ElectionDB (172.21.20.10) — accessible only via the API Gateway.
  </div>

  <div class="map-placeholder">
    🗺️ Interactive map would render here in production (Google Maps API or similar)
  </div>

  <div class="precinct-filter">
    <button class="filter-btn active" onclick="filterPrecinct('all',this)">All Precincts</button>
    <button class="filter-btn" onclick="filterPrecinct('P001',this)">Precinct P001</button>
    <button class="filter-btn" onclick="filterPrecinct('P002',this)">Precinct P002</button>
    <button class="filter-btn" onclick="filterPrecinct('P003',this)">Precinct P003</button>
  </div>

  <div id="locations">
    <div class="location-card" data-precinct="P001">
      <div>
        <h4>🏫 Lincoln Elementary School — Gymnasium</h4>
        <div class="location-meta">
          <strong>Address:</strong> 400 Lincoln Avenue, Springfield, IL 62701<br>
          <strong>Precincts Served:</strong> P001<br>
          <strong>Accessibility:</strong> ♿ Fully accessible · Parking available<br>
          <strong>Languages:</strong> English, Spanish, Mandarin<br>
          <strong>Equipment:</strong> 12 optical-scan booths · 2 accessible terminals<br>
          <strong>Chief Judge:</strong> Patricia Nguyen (badge required for entry)
        </div>
        <div class="btn-row" style="margin-top:12px;">
          <a href="/vote/" class="btn success" style="font-size:0.82rem;padding:8px 18px;">🗳️ Vote Online Instead</a>
        </div>
      </div>
      <div class="hours-badge">
        🕕 Hours<span class="time">06:00–20:00</span><span style="font-size:0.7rem;margin-top:4px;display:block;color:#90caf9;">Open Now</span>
      </div>
    </div>

    <div class="location-card" data-precinct="P002">
      <div>
        <h4>🏛️ City Hall — Community Room A</h4>
        <div class="location-meta">
          <strong>Address:</strong> 1 Municipal Plaza, Springfield, IL 62702<br>
          <strong>Precincts Served:</strong> P002<br>
          <strong>Accessibility:</strong> ♿ Fully accessible · Street parking (free today)<br>
          <strong>Languages:</strong> English, French, Arabic<br>
          <strong>Equipment:</strong> 18 optical-scan booths · 3 accessible terminals<br>
          <strong>Chief Judge:</strong> Robert Okafor (badge required for entry)
        </div>
        <div class="btn-row" style="margin-top:12px;">
          <a href="/vote/" class="btn success" style="font-size:0.82rem;padding:8px 18px;">🗳️ Vote Online Instead</a>
        </div>
      </div>
      <div class="hours-badge">
        🕕 Hours<span class="time">06:00–20:00</span><span style="font-size:0.7rem;margin-top:4px;display:block;color:#90caf9;">Open Now</span>
      </div>
    </div>

    <div class="location-card" data-precinct="P003">
      <div>
        <h4>🏟️ Riverside Community Center — Hall B</h4>
        <div class="location-meta">
          <strong>Address:</strong> 850 Riverside Drive, Springfield, IL 62703<br>
          <strong>Precincts Served:</strong> P003<br>
          <strong>Accessibility:</strong> ♿ Fully accessible · Large parking lot<br>
          <strong>Languages:</strong> English, Portuguese, Tagalog<br>
          <strong>Equipment:</strong> 10 optical-scan booths · 2 accessible terminals<br>
          <strong>Chief Judge:</strong> Angela Rivera (badge required for entry)
        </div>
        <div class="btn-row" style="margin-top:12px;">
          <a href="/vote/" class="btn success" style="font-size:0.82rem;padding:8px 18px;">🗳️ Vote Online Instead</a>
        </div>
      </div>
      <div class="hours-badge">
        🕕 Hours<span class="time">06:00–20:00</span><span style="font-size:0.7rem;margin-top:4px;display:block;color:#90caf9;">Open Now</span>
      </div>
    </div>
  </div>

  <div class="card">
    <h3>Security Architecture — Polling Data Flow</h3>
    <p style="font-size:0.85rem;color:var(--muted);line-height:1.8;">
      Polling location data is stored in the <code>precincts</code> table on ElectionDB (172.21.20.10 — Internal segment).
      This portal (DMZ: 172.21.10.10) cannot reach that database directly — nftables DROP rule
      <code>LAB_DROP_DMZ&gt;INT</code> blocks all traffic from 172.21.10.0/24 to 172.21.20.0/24.
      Location lookups are served from a cache refreshed every 5 minutes by the API Gateway (MGMT segment).
    </p>
  </div>
</main>

<script>
function filterPrecinct(p, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.location-card').forEach(card => {
    if (p === 'all' || card.dataset.precinct === p) {
      card.style.display = 'grid';
    } else {
      card.style.display = 'none';
    }
  });
}
</script>
$(_sec_strip_html)
$(_footer_html)
</body>
</html>
EOF_POLLING

# ────────────────────────────────────────────────────────────────────────────
# PAGE 5: /vote/index.html — Cast Ballot
# ────────────────────────────────────────────────────────────────────────────
cat > /tmp/election-portal/vote/index.html << EOF_VOTE
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cast Your Vote — County Election Office</title>
<style>${SHARED_CSS}
  .auth-wall {
    text-align:center; padding:48px 32px;
  }
  .auth-wall .icon { font-size:3rem; margin-bottom:12px; }
  .token-display {
    font-family:monospace; font-size:0.82rem;
    background:#0D1B2A; color:#64ffda;
    padding:10px 16px; border-radius:8px;
    display:inline-block; margin:10px 0; letter-spacing:0.08em;
  }
</style>
</head>
<body>
$(_nav_html vote)
<div class="page-hero">
  <h2>🗳️ Cast Your Vote</h2>
  <p>Official General Election Ballot — November 2024. Your ballot is cryptographically signed and recorded on the Internal segment.</p>
</div>
<main>
  <!-- Auth Wall -->
  <div id="auth-panel" class="card">
    <h3>Voter Authentication</h3>
    <p style="color:var(--muted);font-size:0.88rem;margin-bottom:20px;">
      Before you can cast your ballot, your identity must be verified against the ElectionDB
      via the API Gateway (172.21.30.x). Enter the details that match your registration.
    </p>
    <div class="form-grid">
      <div class="form-group">
        <label>First Name *</label>
        <input type="text" id="v-fname" placeholder="Jane">
      </div>
      <div class="form-group">
        <label>Last Name *</label>
        <input type="text" id="v-lname" placeholder="Smith">
      </div>
      <div class="form-group">
        <label>Date of Birth *</label>
        <input type="date" id="v-dob">
      </div>
      <div class="form-group">
        <label>Last 4 of SSN *</label>
        <input type="password" id="v-ssn" maxlength="4" placeholder="••••">
      </div>
    </div>
    <div class="btn-row">
      <button class="btn" onclick="authenticateVoter()">🔐 Verify &amp; Proceed to Ballot</button>
    </div>
    <div id="auth-loading" class="hidden" style="margin-top:16px;color:var(--muted);font-style:italic;">
      ⏳ Authenticating via API Gateway → ElectionDB… (simulated)
    </div>
    <div id="auth-error" class="hidden notice danger" style="margin-top:16px;">
      <strong>❌ Authentication Failed</strong>
      The details you provided do not match a registered voter record.
      Please <a href="/register/" style="color:var(--accent);font-weight:700;">register first</a> or
      <a href="/status/" style="color:var(--accent);font-weight:700;">check your status</a>.
    </div>
    <div id="already-voted" class="hidden notice" style="margin-top:16px;">
      <strong>⚠ Ballot Already Cast</strong>
      Our records show a ballot has already been cast for this voter.
      If you believe this is an error, contact the election office immediately.
    </div>
  </div>

  <!-- Ballot (hidden until auth) -->
  <div id="ballot-panel" class="hidden">
    <div class="notice success">
      <strong>✅ Identity Verified</strong>
      Welcome, <span id="voter-greeting"></span>. You are cleared to cast your ballot.
      Auth token: <span id="auth-token" style="font-family:monospace;font-size:0.8rem;"></span>
    </div>

    <div class="card">
      <h3>Official Ballot — General Election, November 2024</h3>
      <p style="color:var(--muted);font-size:0.85rem;margin-bottom:24px;">
        Select <strong>one candidate</strong> for the office of <strong>County Commissioner</strong>.
        Your selection will be cryptographically signed and forwarded to the Internal segment for recording.
      </p>

      <div class="ballot-option" id="opt-1" onclick="selectCandidate(1)">
        <div class="ballot-radio" id="radio-1"></div>
        <div class="candidate-info">
          <h4>Alexandra Rivera</h4>
          <p>Former State Senator · Platform: Infrastructure, Public Safety, Economic Development</p>
          <p style="margin-top:6px;font-size:0.78rem;font-family:monospace;color:var(--muted);">Candidate ID: CAND-001 · Ballot Position: 1</p>
        </div>
        <span class="candidate-party party-a">Candidate 1</span>
      </div>

      <div class="ballot-option" id="opt-2" onclick="selectCandidate(2)">
        <div class="ballot-radio" id="radio-2"></div>
        <div class="candidate-info">
          <h4>Marcus T. Holloway</h4>
          <p>County Budget Director · Platform: Fiscal Responsibility, Education, Healthcare Access</p>
          <p style="margin-top:6px;font-size:0.78rem;font-family:monospace;color:var(--muted);">Candidate ID: CAND-002 · Ballot Position: 2</p>
        </div>
        <span class="candidate-party party-b">Candidate 2</span>
      </div>

      <div id="no-selection" class="hidden notice danger" style="margin-top:16px;">
        <strong>Please select a candidate before submitting.</strong>
      </div>

      <div style="margin-top:20px;padding:14px;background:var(--light);border-radius:8px;font-size:0.82rem;color:var(--muted);">
        <strong style="color:var(--text);">🔐 Security pipeline for ballot submission:</strong><br>
        1. Ballot signed with HMAC-SHA256 using your session auth token<br>
        2. POST /api/ballot → API Gateway (172.21.30.x) — HTTPS required<br>
        3. Duplicate vote check against ElectionDB (172.21.20.10)<br>
        4. Ballot written to <code>ballots</code> table with timestamp &amp; precinct<br>
        5. Audit event forwarded to MGMT segment audit log<br>
        6. Rate-limit check: max 1 ballot per voter ID per election cycle
      </div>

      <div class="btn-row" style="margin-top:24px;">
        <button class="btn success" style="font-size:1rem;padding:14px 32px;" onclick="submitBallot()">
          ✅ Submit My Ballot
        </button>
        <button class="btn outline" onclick="resetBallot()">Reset Selection</button>
      </div>
    </div>
  </div>

  <!-- Confirmation (hidden until submit) -->
  <div id="confirm-panel" class="hidden card" style="text-align:center;padding:48px 32px;">
    <div style="font-size:3.5rem;margin-bottom:16px;">🎉</div>
    <h3 style="color:var(--green);font-family:'Playfair Display',serif;font-size:1.8rem;border:none;padding:0;">
      Ballot Recorded Successfully!
    </h3>
    <p style="margin:16px 0;color:var(--muted);">Thank you for participating in our democracy.</p>
    <div class="token-display" id="ballot-receipt"></div>
    <div class="notice info" style="text-align:left;margin:20px 0;">
      <strong>Your ballot receipt confirms:</strong>
      <ul style="margin-top:8px;padding-left:18px;line-height:2;font-size:0.88rem;">
        <li>Ballot signed &amp; timestamped in the ElectionDB (172.21.20.10)</li>
        <li>Voter record updated: <code>voted = true</code></li>
        <li>Audit entry written to MGMT segment log</li>
        <li>Zero-Trust boundary maintained — DMZ never touched DB directly</li>
        <li>Your vote is anonymous — receipt does not link to your choice</li>
      </ul>
    </div>
    <div class="btn-row" style="justify-content:center;">
      <a href="/results/" class="btn">📊 View Live Results</a>
      <a href="/" class="btn outline">Return Home</a>
    </div>
  </div>
</main>

<script>
const VOTERS = [
  {first:'Jane',    last:'Smith',    dob:'1985-03-15', ssn:'1234', precinct:'P001', voted:false},
  {first:'Michael', last:'Johnson',  dob:'1972-07-22', ssn:'5678', precinct:'P002', voted:false},
  {first:'Sarah',   last:'Williams', dob:'1990-11-08', ssn:'9012', precinct:'P001', voted:true},
  {first:'David',   last:'Brown',    dob:'1968-05-30', ssn:'3456', precinct:'P003', voted:false},
  {first:'Emily',   last:'Davis',    dob:'1995-01-14', ssn:'7890', precinct:'P002', voted:true},
];

let currentVoter = null;
let selectedCandidate = null;

function authenticateVoter() {
  const fn  = document.getElementById('v-fname').value.trim().toLowerCase();
  const ln  = document.getElementById('v-lname').value.trim().toLowerCase();
  const dob = document.getElementById('v-dob').value;
  const ssn = document.getElementById('v-ssn').value.trim();

  if (!fn || !ln || !dob || !ssn) { alert('Please fill in all fields.'); return; }

  document.getElementById('auth-loading').classList.remove('hidden');
  document.getElementById('auth-error').classList.add('hidden');
  document.getElementById('already-voted').classList.add('hidden');

  setTimeout(() => {
    document.getElementById('auth-loading').classList.add('hidden');
    const voter = VOTERS.find(v =>
      v.first.toLowerCase() === fn &&
      v.last.toLowerCase()  === ln &&
      v.dob === dob
    );
    if (!voter) {
      document.getElementById('auth-error').classList.remove('hidden');
      return;
    }
    if (voter.voted) {
      document.getElementById('already-voted').classList.remove('hidden');
      return;
    }
    currentVoter = voter;
    const token = 'TKN-' + btoa(fn + ':' + dob).replace(/=/g,'').slice(0,12).toUpperCase();
    document.getElementById('voter-greeting').textContent = voter.first + ' ' + voter.last + ' (Precinct ' + voter.precinct + ')';
    document.getElementById('auth-token').textContent = token;
    document.getElementById('auth-panel').classList.add('hidden');
    document.getElementById('ballot-panel').classList.remove('hidden');
  }, 1600);
}

function selectCandidate(n) {
  selectedCandidate = n;
  document.getElementById('opt-1').classList.toggle('selected', n === 1);
  document.getElementById('opt-2').classList.toggle('selected', n === 2);
  document.getElementById('radio-1').innerHTML = '';
  document.getElementById('radio-2').innerHTML = '';
  document.getElementById('no-selection').classList.add('hidden');
}

function resetBallot() { selectedCandidate = null; selectCandidate(0); }

function submitBallot() {
  if (!selectedCandidate) {
    document.getElementById('no-selection').classList.remove('hidden');
    return;
  }
  const receipt = 'BALLOT-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,8).toUpperCase();
  document.getElementById('ballot-receipt').textContent = receipt + ' | ' + new Date().toISOString();
  document.getElementById('ballot-panel').classList.add('hidden');
  document.getElementById('confirm-panel').classList.remove('hidden');
}
</script>
$(_sec_strip_html)
$(_footer_html)
</body>
</html>
EOF_VOTE

# ────────────────────────────────────────────────────────────────────────────
# PAGE 6: /results/index.html — Election Results
# ────────────────────────────────────────────────────────────────────────────
cat > /tmp/election-portal/results/index.html << EOF_RESULTS
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Election Results — County Election Office</title>
<style>${SHARED_CSS}
  .results-grid { display:grid; grid-template-columns:2fr 1fr; gap:24px; }
  .summary-stat { text-align:center; padding:20px; background:var(--light); border-radius:10px; }
  .summary-stat .big { font-size:2rem; font-weight:900; font-family:"Playfair Display",serif; color:var(--blue); }
  .summary-stat .label { font-size:0.78rem; color:var(--muted); text-transform:uppercase; letter-spacing:0.06em; margin-top:4px; }
  .stats-row { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:28px; }
  .live-badge {
    display:inline-flex; align-items:center; gap:6px;
    background:#fdecea; color:var(--accent);
    border-radius:100px; padding:4px 14px;
    font-size:0.75rem; font-weight:700;
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.6} }
  .live-dot { width:8px;height:8px;background:var(--accent);border-radius:50%;display:inline-block; }
  .precinct-row { display:flex; gap:12px; margin-top:12px; flex-wrap:wrap; }
  .precinct-pill {
    flex:1; min-width:120px;
    background:var(--white); border:1px solid var(--border);
    border-radius:10px; padding:12px 16px;
    font-size:0.82rem;
  }
  .precinct-pill strong { display:block; color:var(--blue); margin-bottom:4px; }
  @media(max-width:680px){ .results-grid{grid-template-columns:1fr;} .stats-row{grid-template-columns:1fr 1fr;} }
</style>
</head>
<body>
$(_nav_html results)
<div class="page-hero">
  <h2>📊 Election Results</h2>
  <p>Live results for the November 2024 General Election. Data sourced from ElectionDB via the authenticated API Gateway.</p>
</div>
<main>
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
    <div class="live-badge"><span class="live-dot"></span> LIVE REPORTING</div>
    <span style="font-size:0.82rem;color:var(--muted);">Last updated: <span id="last-update"></span></span>
    <button onclick="refreshResults()" class="btn outline" style="padding:6px 16px;font-size:0.78rem;margin-left:auto;">↻ Refresh</button>
  </div>

  <div class="stats-row">
    <div class="summary-stat">
      <div class="big" id="total-votes">0</div>
      <div class="label">Total Ballots Cast</div>
    </div>
    <div class="summary-stat">
      <div class="big">5</div>
      <div class="label">Registered Voters</div>
    </div>
    <div class="summary-stat">
      <div class="big" id="turnout-pct">0%</div>
      <div class="label">Voter Turnout</div>
    </div>
    <div class="summary-stat">
      <div class="big">3</div>
      <div class="label">Precincts Reporting</div>
    </div>
  </div>

  <div class="results-grid">
    <div>
      <div class="card">
        <h3>County Commissioner Race</h3>

        <!-- Candidate 1 -->
        <div class="candidate-result">
          <div class="candidate-header">
            <span class="candidate-name">Alexandra Rivera &nbsp;<span style="font-size:0.75rem;background:#dbeafe;color:#1e40af;padding:2px 8px;border-radius:100px;font-weight:700;">Candidate 1</span></span>
            <span class="candidate-pct" id="c1-pct">—</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill c1" id="c1-bar" style="width:0%"></div>
          </div>
          <div style="font-size:0.78rem;color:var(--muted);margin-top:5px;"><span id="c1-votes">0</span> votes</div>
        </div>

        <!-- Candidate 2 -->
        <div class="candidate-result">
          <div class="candidate-header">
            <span class="candidate-name">Marcus T. Holloway &nbsp;<span style="font-size:0.75rem;background:#fee2e2;color:#991b1b;padding:2px 8px;border-radius:100px;font-weight:700;">Candidate 2</span></span>
            <span class="candidate-pct" id="c2-pct">—</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill c2" id="c2-bar" style="width:0%"></div>
          </div>
          <div style="font-size:0.78rem;color:var(--muted);margin-top:5px;"><span id="c2-votes">0</span> votes</div>
        </div>

        <div id="leader-notice" class="notice" style="display:none;margin-bottom:0;"></div>
      </div>

      <div class="card">
        <h3>Results by Precinct</h3>
        <table>
          <thead>
            <tr><th>Precinct</th><th>Reporting</th><th>Total Ballots</th><th>Alexandra Rivera</th><th>Marcus Holloway</th></tr>
          </thead>
          <tbody id="precinct-table">
            <tr><td colspan="5" style="color:var(--muted);font-style:italic;text-align:center;">Loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div>
      <div class="card">
        <h3>Security Audit Trail</h3>
        <p style="font-size:0.8rem;color:var(--muted);margin-bottom:14px;">
          Every ballot write generates an immutable audit entry. These logs reside on the MGMT segment (172.21.30.x), isolated from both DMZ and Internal.
        </p>
        <div id="audit-log" style="font-family:monospace;font-size:0.72rem;background:#0d1b2a;color:#64ffda;padding:14px;border-radius:8px;max-height:260px;overflow-y:auto;line-height:1.8;">
          <div style="color:#90a4ae;"># Audit log — MGMT segment</div>
        </div>
      </div>

      <div class="card">
        <h3>Network Architecture</h3>
        <div style="font-size:0.8rem;color:var(--muted);line-height:1.9;">
          <div style="padding:8px;background:var(--light);border-radius:6px;border-left:3px solid var(--blue);margin-bottom:8px;">
            <strong>Results API route:</strong><br>
            Portal (172.21.10.10)<br>→ GET /api/results<br>→ API-GW (172.21.30.x)<br>→ SELECT ballots (172.21.20.10)
          </div>
          <div style="padding:8px;background:var(--light);border-radius:6px;border-left:3px solid var(--accent);">
            <strong>nftables rule active:</strong><br>
            <code style="font-size:0.7rem;">LAB_DROP_DMZ&gt;INT</code><br>
            DMZ cannot bypass API Gateway<br>
            Rate: 200 req/min to DB port
          </div>
        </div>
      </div>
    </div>
  </div>
</main>

<script>
// Simulated ballot store (in production: fetched from API Gateway → ElectionDB)
const RESULTS = {
  precincts: [
    { id:'P001', reporting:true,  c1:3, c2:2 },
    { id:'P002', reporting:true,  c1:1, c2:4 },
    { id:'P003', reporting:true,  c1:2, c2:1 },
  ]
};

const AUDIT_EVENTS = [
  { ts:'2024-11-05T06:03:12Z', event:'BALLOT_WRITE voter=SWI-P001 cand=CAND-001' },
  { ts:'2024-11-05T07:14:55Z', event:'BALLOT_WRITE voter=DAV-P002 cand=CAND-002' },
  { ts:'2024-11-05T08:22:01Z', event:'BALLOT_WRITE voter=EMI-P002 cand=CAND-001' },
  { ts:'2024-11-05T09:05:33Z', event:'BALLOT_WRITE voter=JANx-P001 cand=CAND-002' },
  { ts:'2024-11-05T10:41:17Z', event:'BALLOT_WRITE voter=MIC-P003 cand=CAND-001' },
  { ts:'2024-11-05T11:02:44Z', event:'RATE_LIMIT_CHECK 172.21.20.10:5432 OK' },
  { ts:'2024-11-05T11:03:09Z', event:'BALLOT_WRITE voter=BRO-P003 cand=CAND-002' },
  { ts:'2024-11-05T12:00:00Z', event:'RESULTS_SNAPSHOT written to audit store' },
];

function renderAuditLog() {
  const el = document.getElementById('audit-log');
  AUDIT_EVENTS.forEach(e => {
    const line = document.createElement('div');
    line.style.marginTop = '4px';
    line.innerHTML = \`<span style="color:#546e7a;">\${e.ts}</span> <span style="color:#80cbc4;">\${e.event}</span>\`;
    el.appendChild(line);
  });
  el.scrollTop = el.scrollHeight;
}

function refreshResults() {
  let totalC1 = 0, totalC2 = 0;
  const rows = RESULTS.precincts.map(p => {
    totalC1 += p.c1; totalC2 += p.c2;
    return \`<tr>
      <td><strong>\${p.id}</strong></td>
      <td><span class="badge open">Yes</span></td>
      <td>\${p.c1 + p.c2}</td>
      <td>\${p.c1}</td>
      <td>\${p.c2}</td>
    </tr>\`;
  });
  document.getElementById('precinct-table').innerHTML = rows.join('');

  const total = totalC1 + totalC2;
  const p1 = total ? Math.round((totalC1 / total) * 100) : 0;
  const p2 = 100 - p1;

  document.getElementById('total-votes').textContent = total;
  document.getElementById('turnout-pct').textContent = Math.round((total / 5) * 100) + '%';

  document.getElementById('c1-votes').textContent = totalC1;
  document.getElementById('c2-votes').textContent = totalC2;
  document.getElementById('c1-pct').textContent = p1 + '%';
  document.getElementById('c2-pct').textContent = p2 + '%';

  setTimeout(() => {
    document.getElementById('c1-bar').style.width = p1 + '%';
    document.getElementById('c2-bar').style.width = p2 + '%';
  }, 100);

  const notice = document.getElementById('leader-notice');
  const leader = totalC1 > totalC2 ? 'Alexandra Rivera (Candidate 1)' : totalC2 > totalC1 ? 'Marcus T. Holloway (Candidate 2)' : null;
  if (leader) {
    notice.style.display = 'block';
    notice.innerHTML = \`<strong>📢 Current Leader:</strong> \${leader} is leading with \${Math.max(p1, p2)}% of votes counted.\`;
  }

  document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
}

// Init
renderAuditLog();
refreshResults();
</script>
$(_sec_strip_html)
$(_footer_html)
</body>
</html>
EOF_RESULTS

# ── Step 3: ElectionDB (PostgreSQL — Internal) ────────────────────────────────
log_step "Deploying ElectionDB (PostgreSQL — Internal segment)..."
docker rm -f "$CTR_ELECTIONDB" 2>/dev/null || true

docker run -d \
    --name "$CTR_ELECTIONDB" \
    --network "$NET_INT" \
    --ip "$IP_ELECTIONDB" \
    --memory 256m \
    --restart unless-stopped \
    -e POSTGRES_DB=voterdb \
    -e POSTGRES_USER=election_admin \
    -e "POSTGRES_PASSWORD=${DB_PASS}" \
    postgres:15-alpine
log_ok "ElectionDB deployed: ${IP_ELECTIONDB}:5432"

# Seed sample voter data (after DB is ready)
log_step "Seeding sample voter registration data..."
sleep 8
docker exec "$CTR_ELECTIONDB" psql -U election_admin -d voterdb -c "
CREATE TABLE IF NOT EXISTS voters (
    id         SERIAL PRIMARY KEY,
    first_name VARCHAR(50),
    last_name  VARCHAR(50),
    dob        DATE,
    precinct   VARCHAR(20),
    registered BOOLEAN DEFAULT true,
    voted      BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ballots (
    id           SERIAL PRIMARY KEY,
    voter_id     INTEGER REFERENCES voters(id),
    candidate_id VARCHAR(20) NOT NULL,
    precinct     VARCHAR(20),
    ballot_hash  VARCHAR(128),
    submitted_at TIMESTAMP DEFAULT NOW(),
    segment_path TEXT DEFAULT 'DMZ→MGMT→INT'
);

CREATE TABLE IF NOT EXISTS candidates (
    id      VARCHAR(20) PRIMARY KEY,
    name    VARCHAR(100),
    party   VARCHAR(50),
    position INTEGER
);

CREATE TABLE IF NOT EXISTS precincts (
    id          VARCHAR(20) PRIMARY KEY,
    name        TEXT,
    address     TEXT,
    hours_open  TIME DEFAULT '06:00:00',
    hours_close TIME DEFAULT '20:00:00'
);

INSERT INTO candidates (id, name, party, position) VALUES
    ('CAND-001', 'Alexandra Rivera',   'Candidate 1', 1),
    ('CAND-002', 'Marcus T. Holloway', 'Candidate 2', 2)
ON CONFLICT DO NOTHING;

INSERT INTO precincts (id, name, address) VALUES
    ('P001', 'Lincoln Elementary School', '400 Lincoln Avenue, Springfield, IL 62701'),
    ('P002', 'City Hall — Community Room A', '1 Municipal Plaza, Springfield, IL 62702'),
    ('P003', 'Riverside Community Center', '850 Riverside Drive, Springfield, IL 62703')
ON CONFLICT DO NOTHING;

INSERT INTO voters (first_name, last_name, dob, precinct) VALUES
    ('Jane',    'Smith',    '1985-03-15', 'P001'),
    ('Michael', 'Johnson',  '1972-07-22', 'P002'),
    ('Sarah',   'Williams', '1990-11-08', 'P001'),
    ('David',   'Brown',    '1968-05-30', 'P003'),
    ('Emily',   'Davis',    '1995-01-14', 'P002')
ON CONFLICT DO NOTHING;

-- Mark Sarah and Emily as having already voted (for demo)
UPDATE voters SET voted = true WHERE first_name IN ('Sarah', 'Emily');

SELECT COUNT(*) AS voter_count FROM voters;
SELECT COUNT(*) AS candidate_count FROM candidates;
SELECT COUNT(*) AS precinct_count FROM precincts;
" 2>/dev/null && log_ok "Voter database seeded (voters + candidates + precincts + ballots tables)" || log_warn "DB seed will retry — DB still starting"

# ── Step 4: Remove old portal container and redeploy ─────────────────────────
log_step "Deploying Election Portal (nginx — DMZ)..."
docker rm -f "$CTR_PORTAL" 2>/dev/null || true

docker run -d \
    --name "$CTR_PORTAL" \
    --network "$NET_DMZ" \
    --ip "$IP_PORTAL" \
    -p 8080:80 \
    --memory 128m \
    --restart unless-stopped \
    -v /tmp/election-portal:/usr/share/nginx/html:ro \
    nginx:alpine
log_ok "Election portal deployed: http://localhost:8080"
log_ok "Portal pages: / /register/ /status/ /polling/ /vote/ /results/"

# ── Step 5: nftables Zero-Trust firewall ──────────────────────────────────────
log_step "Configuring nftables Zero-Trust firewall rules..."

BR_DMZ_REAL=$(docker network inspect "$NET_DMZ" -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null || echo "br-dmz")
BR_INT_REAL=$(docker network inspect "$NET_INT" -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null || echo "br-int")
BR_MGMT_REAL=$(docker network inspect "$NET_MGMT" -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null || echo "br-mgmt")

# Flush old lab rules
nft delete table inet lab_election 2>/dev/null || true

nft -f - << NFTEOF
table inet lab_election {

    # ── Sets: allowed inter-segment flows ────────────────────────────────────
    set mgmt_allowed_srcs {
        type ipv4_addr
        flags interval
        elements = { 172.21.10.0/24, 172.21.20.0/24 }
    }

    # ── DMZ → Internal: BLOCKED (Zero-Trust) ─────────────────────────────────
    # Portal (172.21.10.10) cannot reach ElectionDB (172.21.20.10) directly.
    # All voter data access MUST flow through the API Gateway on MGMT segment.
    # This rule enforces the security boundary for: /register /status /vote /results
    chain dmz_to_internal {
        type filter hook forward priority 0; policy accept;
        ip saddr 172.21.10.0/24 ip daddr 172.21.20.0/24 log prefix "LAB_DROP_DMZ>INT: " drop
        ip saddr 172.21.10.0/24 ip daddr 172.21.30.0/24 log prefix "LAB_DROP_DMZ>MGMT: " drop
    }

    # ── Internal → DMZ: allow only HTTP/HTTPS responses ───────────────────────
    chain internal_to_dmz {
        type filter hook forward priority 1; policy accept;
        ip saddr 172.21.20.0/24 ip daddr 172.21.10.0/24 tcp dport { 80, 443 } accept
        ip saddr 172.21.20.0/24 ip daddr 172.21.10.0/24 log prefix "LAB_DROP_INT>DMZ: " drop
    }

    # ── MGMT → Internal: API Gateway to ElectionDB (5432 only) ───────────────
    # Only the API Gateway on the MGMT segment may write ballots or read voters.
    chain mgmt_to_internal {
        type filter hook forward priority 1; policy accept;
        ip saddr 172.21.30.0/24 ip daddr 172.21.20.10 tcp dport 5432 accept
        ip saddr 172.21.30.0/24 ip daddr 172.21.20.0/24 log prefix "LAB_DROP_MGMT>INT_OTHER: " drop
    }

    # ── DMZ → MGMT: allow portal to reach API Gateway (8443) only ────────────
    # /register /status /vote /results pages POST to the API Gateway here.
    chain dmz_to_mgmt_apigw {
        type filter hook forward priority 2; policy accept;
        ip saddr 172.21.10.0/24 ip daddr 172.21.30.0/24 tcp dport { 8443, 443 } accept
    }

    # ── Red-team isolation: block access to Management ────────────────────────
    chain block_redteam {
        type filter hook forward priority 2; policy accept;
        ip saddr 172.21.40.0/24 ip daddr 172.21.30.0/24 log prefix "LAB_DROP_RED>MGMT: " drop
    }

    # ── Rate limit: protect ElectionDB from bulk queries ─────────────────────
    # Applies to ballot submissions and voter lookups via API Gateway
    chain rate_limit_db {
        type filter hook forward priority 3; policy accept;
        ip daddr 172.21.20.10 tcp dport 5432 limit rate over 200/minute log prefix "LAB_DB_RATELIMIT: " drop
    }

    # ── Rate limit: protect portal from DDoS ─────────────────────────────────
    chain rate_limit_portal {
        type filter hook forward priority 4; policy accept;
        ip daddr 172.21.10.10 tcp dport { 80, 443 } limit rate over 500/minute log prefix "LAB_PORTAL_RATELIMIT: " drop
    }
}
NFTEOF

log_ok "nftables Zero-Trust rules applied (DMZ↔INT blocked, MGMT→INT:5432 allowed, DMZ→MGMT:8443 allowed)"

# Persist rules across reboot
cat > /etc/nftables-election.conf << 'NFTEOF2'
#!/usr/sbin/nft -f
# Election Lab Zero-Trust rules — auto-applied at boot
# Segments:
#   DMZ  (172.21.10.0/24) — nginx portal (public-facing)
#   INT  (172.21.20.0/24) — ElectionDB PostgreSQL (no direct public access)
#   MGMT (172.21.30.0/24) — API Gateway + audit log (controls DMZ→INT flow)
#   RED  (172.21.40.0/24) — Red-team exercise segment (isolated from MGMT)
#
# Key rules:
#   LAB_DROP_DMZ>INT    — Portal cannot reach DB directly (Zero-Trust)
#   LAB_DROP_DMZ>MGMT   — Portal cannot reach MGMT except via API-GW port
#   LAB_DB_RATELIMIT    — ElectionDB protected: 200 req/min max
#   LAB_PORTAL_RATELIMIT— Portal protected: 500 req/min max
#
# Full rules are in sessions/session1_network.sh
# To reload: sudo nft -f /etc/nftables-election.conf
NFTEOF2
nft list table inet lab_election >> /etc/nftables-election.conf 2>/dev/null || true

# Add to existing nftables service if available
if systemctl is-enabled nftables &>/dev/null 2>&1; then
    cp /etc/nftables.conf /etc/nftables.conf.bak 2>/dev/null || true
    echo 'include "/etc/nftables-election.conf"' >> /etc/nftables.conf
fi

# ── Collect evidence ──────────────────────────────────────────────────────────
log_step "Collecting network evidence..."
mkdir -p "${EVIDENCE_DIR}"
{
    echo "=== Election Lab Network Evidence ==="
    echo "Date: $(date -u)"
    echo ""
    echo "=== Docker Networks ==="
    docker network ls | grep lab-election
    echo ""
    echo "=== Portal Pages ==="
    echo "  /             — Home / Landing"
    echo "  /register/    — Voter Registration (4-step wizard)"
    echo "  /status/      — Registration Status Lookup"
    echo "  /polling/     — Polling Locations (filterable by precinct)"
    echo "  /vote/        — Cast Ballot (Candidate 1: Rivera / Candidate 2: Holloway)"
    echo "  /results/     — Live Election Results + Audit Log"
    echo ""
    echo "=== nftables Rules ==="
    nft list ruleset 2>/dev/null
    echo ""
    echo "=== Container IPs ==="
    docker inspect --format "{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" \
        $(docker ps -q --filter "name=lab-election") 2>/dev/null || echo "No containers yet"
} > "${EVIDENCE_DIR}/network_config_$(date +%Y%m%d_%H%M%S).txt"

log_section "Session 1 Complete"
echo -e "  ${GREEN}✔${RESET}  Docker networks:    ${NET_DMZ}, ${NET_INT}, ${NET_MGMT}"
echo -e "  ${GREEN}✔${RESET}  Election portal:    http://localhost:8080"
echo -e "  ${GREEN}✔${RESET}  Portal pages:"
echo -e "             http://localhost:8080/           (Home)"
echo -e "             http://localhost:8080/register/  (Voter Registration — 4-step)"
echo -e "             http://localhost:8080/status/    (Status Lookup)"
echo -e "             http://localhost:8080/polling/   (Polling Locations)"
echo -e "             http://localhost:8080/vote/      (Cast Ballot)"
echo -e "             http://localhost:8080/results/   (Live Results)"
echo -e "  ${GREEN}✔${RESET}  ElectionDB:         ${IP_ELECTIONDB}:5432"
echo -e "              Tables: voters, candidates, precincts, ballots"
echo -e "  ${GREEN}✔${RESET}  Zero-Trust firewall: nftables rules active"
echo ""
log_section "Session 1 Exercise"
echo -e "${YELLOW} Exercise commands:${RESET}"
echo -e "${BOLD} Exercise 1.1 - Verify Zero-Trust rules:${RESET}"
echo -e "${CYAN}sudo nft list table inet lab_election${RESET}"
echo ""
echo -e "${BOLD} Exercise 1.2 - Zero-Trust enforced:"
echo -e "${CYAN} docker exec ${CTR_PORTAL} ping -c 2 ${IP_ELECTIONDB} ${RESET}"          
echo -e "${BOLD} Expected: ${RED} Should FAIL ${RESET}"
echo ""
echo -e "${BOLD} Exercise 1.3 - Show portal Homepage HTML:"
echo -e "${CYAN} curl http://localhost:8080${RESET}"
echo ""
echo -e "${BOLD} Exercise 1.4 - Show Ballot page HTML:"
echo -e "${CYAN} curl http://localhost:8080/vote/${RESET}"
echo ""
echo -e "${BOLD} Exercise 1.5 - Show Results page HTML:"                                
echo -e "${CYAN} curl http://localhost:8080/results/${RESET}"
echo "" 
echo -e "${BOLD} Exercise 1.6 - Watch firewalls drops"                          
echo -e "${CYAN} sudo journalctl -kf | grep LAB_DROP${RESET}"                            
echo ""
echo -e "${BOLD} Exercise 1.7 - View voters table" 
echo -e "${CYAN} docker exec ${CTR_ELECTIONDB} psql -U election_admin -d voterdb -c 'SELECT * FROM voters;'${RESET}"
echo ""
echo -e "${BOLD} Exercise 1.8 - View candidates table" 
echo -e "${CYAN} docker exec ${CTR_ELECTIONDB} psql -U election_admin -d voterdb -c 'SELECT * FROM candidates;'${RESET}"
echo ""
echo -e "${BOLD} Exercise 1.9 - View candidates table" 
echo -e "${CYAN} docker exec ${CTR_ELECTIONDB} psql -U election_admin -d voterdb -c 'SELECT * FROM ballots;'${RESET}"
echo ""
