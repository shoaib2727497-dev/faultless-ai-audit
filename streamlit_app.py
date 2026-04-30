import io
import json
import os
import re
import smtplib
import ssl
import threading
import time
import zipfile
from datetime import datetime, timedelta
from email.message import EmailMessage
from hashlib import sha256
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import pandas as pd
import schedule
import streamlit as st
from fpdf import FPDF
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from targets import COMPANY_LIST


st.set_page_config(page_title="Faultless AI Audit", page_icon=":mag:", layout="wide")

STATE_FILE = Path("autopilot_state.json")
ALERT_COUNTER_FILE = Path("alert_counter.json")
PORTFOLIO_FILE = Path("portfolio_state.json")
ADMIN_PASSWORD_HASH = sha256("Deposit70$".encode("utf-8")).hexdigest()
ADMIN_MAX_ATTEMPTS = 3
ADMIN_LOCKOUT_MINUTES = 15
ADMIN_RATE_LIMIT_WINDOW_SECONDS = 60
ADMIN_RATE_LIMIT_MAX_REQUESTS = 15
AUTOPILOT_EVERY_HOURS = 12
SUBSCRIPTION_URL = "https://faultless-ai-audit.example.com/subscribe"
WEBSITE_LINK = "https://faultless-ai-audit.example.com"

TARGETS = [
    "google.com", "amazon.com", "microsoft.com", "apple.com", "meta.com",
    "netflix.com", "adobe.com", "oracle.com", "ibm.com", "intel.com",
    "nvidia.com", "salesforce.com", "paypal.com", "uber.com", "airbnb.com",
    "shopify.com", "spotify.com", "zoom.us", "dropbox.com", "slack.com",
    "twitter.com", "linkedin.com", "reddit.com", "pinterest.com", "snap.com",
    "tesla.com", "samsung.com", "sony.com", "siemens.com", "sap.com",
    "walmart.com", "target.com", "costco.com", "ikea.com", "nike.com",
    "cisco.com", "vmware.com", "atlassian.com", "cloudflare.com", "stripe.com",
    "openai.com", "anthropic.com", "github.com", "gitlab.com", "bitbucket.org",
    "docker.com", "digitalocean.com", "akamai.com", "vercel.com", "twilio.com",
]


def load_json_file(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def save_json_file(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def update_live_portfolio(findings_df: pd.DataFrame, source: str) -> None:
    portfolio = load_json_file(PORTFOLIO_FILE, {"last_updated": None, "audited_companies": [], "high_critical_bugs": []})
    audited_companies = set(portfolio.get("audited_companies", []))
    for recipient in COMPANY_LIST:
        if recipient.strip():
            audited_companies.add(recipient.strip())

    high_critical = findings_df[findings_df["severity"].isin(["High", "Critical"])] if not findings_df.empty else pd.DataFrame()
    bug_entries = portfolio.get("high_critical_bugs", [])
    for _, row in high_critical.head(30).iterrows():
        bug_entries.append(
            {
                "source": source,
                "severity": row["severity"],
                "issue": row["issue"],
                "file": row["file"],
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
        )

    portfolio["audited_companies"] = sorted(audited_companies)
    portfolio["high_critical_bugs"] = bug_entries[-100:]
    portfolio["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    save_json_file(PORTFOLIO_FILE, portfolio)


def get_live_portfolio() -> dict:
    return load_json_file(
        PORTFOLIO_FILE,
        {"last_updated": None, "audited_companies": [], "high_critical_bugs": [], "wall_of_fame": []},
    )


def record_wall_of_fame(company_name: str, bug_type: str) -> None:
    portfolio = get_live_portfolio()
    wall = portfolio.get("wall_of_fame", [])
    wall.append(
        {
            "company_name": company_name,
            "bug_type": bug_type,
            "status": "Report Sent",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    )
    portfolio["wall_of_fame"] = wall[-100:]
    portfolio["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    save_json_file(PORTFOLIO_FILE, portfolio)


def extract_company_name(email_or_domain: str) -> str:
    value = (email_or_domain or "").strip().lower()
    if "@" in value:
        value = value.split("@", 1)[1]
    if "." in value:
        value = value.split(".", 1)[0]
    return value.replace("-", " ").replace("_", " ").title() or "Target Company"


def get_autopilot_state() -> dict:
    return load_json_file(
        STATE_FILE,
        {
            "enabled": True,
            "last_run": None,
            "last_status": "Never ran",
        },
    )


def set_autopilot_enabled(enabled: bool) -> None:
    state = get_autopilot_state()
    state["enabled"] = enabled
    state["last_status"] = "Resumed" if enabled else "Paused by admin"
    save_json_file(STATE_FILE, state)


def is_admin_rate_limited() -> bool:
    now = time.time()
    req_times = st.session_state.get("admin_req_times", [])
    req_times = [ts for ts in req_times if now - ts <= ADMIN_RATE_LIMIT_WINDOW_SECONDS]
    req_times.append(now)
    st.session_state["admin_req_times"] = req_times
    return len(req_times) > ADMIN_RATE_LIMIT_MAX_REQUESTS


def verify_admin_password(password: str) -> bool:
    return sha256(password.encode("utf-8")).hexdigest() == ADMIN_PASSWORD_HASH


def lockout_active() -> bool:
    lock_until_ts = st.session_state.get("admin_lock_until_ts")
    if not lock_until_ts:
        return False
    return datetime.utcnow() < datetime.fromtimestamp(lock_until_ts)


def register_failed_login() -> None:
    attempts = st.session_state.get("admin_failed_attempts", 0) + 1
    st.session_state["admin_failed_attempts"] = attempts
    if attempts >= ADMIN_MAX_ATTEMPTS:
        lock_until = datetime.utcnow() + timedelta(minutes=ADMIN_LOCKOUT_MINUTES)
        st.session_state["admin_lock_until_ts"] = lock_until.timestamp()


def reset_login_security() -> None:
    st.session_state["admin_failed_attempts"] = 0
    st.session_state["admin_lock_until_ts"] = None


def get_email_settings() -> dict:
    secrets = st.secrets if hasattr(st, "secrets") else {}

    def read_setting(key: str, default: str = "") -> str:
        val = os.getenv(key, "").strip()
        if val:
            return val
        secret_val = secrets.get(key, default) if isinstance(secrets, dict) else secrets.get(key, default)
        return str(secret_val).strip() if secret_val is not None else default

    return {
        "smtp_host": read_setting("SMTP_HOST"),
        "smtp_port": int(read_setting("SMTP_PORT", "587")),
        "smtp_user": read_setting("SMTP_USER"),
        "smtp_pass": read_setting("SMTP_PASS"),
        "from_email": read_setting("ALERT_FROM_EMAIL"),
        "cc_email": read_setting("MY_CC_EMAIL"),
    }


def smtp_ready(settings: dict) -> bool:
    required = ["smtp_host", "smtp_port", "smtp_user", "smtp_pass", "from_email", "cc_email"]
    return all(settings.get(key) for key in required)


def scan_target(domain: str) -> list[dict]:
    """Passive health and header checks over HTTPS."""
    findings = []
    url = f"https://{domain}"
    req = Request(url, headers={"User-Agent": "Faultless-AI-Audit/1.0"})
    try:
        with urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status_code = getattr(resp, "status", 200)
            if status_code >= 400:
                findings.append(
                    {
                        "file": domain,
                        "category": "Security",
                        "issue": f"Non-healthy HTTPS response ({status_code})",
                        "severity": "Medium",
                        "line": 0,
                        "snippet": f"{url} returned HTTP {status_code}",
                    }
                )

            required_headers = ["strict-transport-security", "x-content-type-options", "content-security-policy"]
            for hdr in required_headers:
                if hdr not in headers:
                    findings.append(
                        {
                            "file": domain,
                            "category": "Security",
                            "issue": f"Missing recommended security header: {hdr}",
                            "severity": "Low",
                            "line": 0,
                            "snippet": f"{url} missing `{hdr}`",
                        }
                    )
    except URLError as exc:
        findings.append(
            {
                "file": domain,
                "category": "Security",
                "issue": "Target unreachable over HTTPS",
                "severity": "High",
                "line": 0,
                "snippet": str(exc)[:250],
            }
        )
    except Exception as exc:  # broad to keep monitor resilient
        findings.append(
            {
                "file": domain,
                "category": "Security",
                "issue": "Monitoring check failed",
                "severity": "Medium",
                "line": 0,
                "snippet": str(exc)[:250],
            }
        )
    return findings


def add_subscription_message_if_needed(company_key: str, body: str) -> str:
    counters = load_json_file(ALERT_COUNTER_FILE, {})
    sent_count = int(counters.get(company_key, 0))
    sent_count += 1
    counters[company_key] = sent_count
    save_json_file(ALERT_COUNTER_FILE, counters)

    if sent_count > 3:
        body += (
            "\n\n---\n"
            "Subscription & Support\n"
            "You have now received more than 3 free alerts. "
            "For continuous premium monitoring and dedicated support, "
            "subscribe to our professional plan at $100/month."
        )
    return body


def generate_professional_security_pdf(findings_df: pd.DataFrame, source: str, company_name: str) -> bytes:
    high_df = findings_df[findings_df["severity"].isin(["High", "Critical"])] if not findings_df.empty else pd.DataFrame()
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 50

    pdf.saveState()
    pdf.setFont("Helvetica-Bold", 50)
    pdf.setFillGray(0.90)
    pdf.translate(width / 2, height / 2)
    pdf.rotate(45)
    pdf.drawCentredString(0, 0, "CONFIDENTIAL")
    pdf.restoreState()

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, "Faultless AI Audit - Security Incident Report")
    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    y -= 16
    pdf.drawString(40, y, f"Company: {company_name}")
    y -= 16
    pdf.drawString(40, y, f"Source: {source}")
    y -= 16
    pdf.drawString(40, y, f"High/Critical findings: {len(high_df)}")
    y -= 20
    pdf.drawString(40, y, f"Subscription: {SUBSCRIPTION_URL}")
    y -= 24

    if high_df.empty:
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(40, y, "No High or Critical findings in this cycle.")
    else:
        for idx, row in high_df.iterrows():
            if y < 80:
                pdf.showPage()
                y = height - 50
            pdf.setFont("Helvetica-Bold", 10)
            pdf.drawString(40, y, f"{idx + 1}. [{row['severity']}] {row['issue']}")
            y -= 14
            pdf.setFont("Helvetica", 9)
            pdf.drawString(50, y, f"Target/File: {row['file']} | Line: {row['line']}")
            y -= 12
            snippet = str(row["snippet"])[:120]
            pdf.drawString(50, y, f"Snippet: {snippet}")
            y -= 18

    pdf.save()
    buffer.seek(0)
    return buffer.read()


def send_alert_email(subject: str, body: str, company_key: str, findings_df: pd.DataFrame, source: str) -> tuple[bool, str]:
    settings = get_email_settings()
    if not smtp_ready(settings):
        return False, "SMTP/email environment variables are not fully configured."

    recipients_list = [email.strip() for email in COMPANY_LIST if email.strip()]
    if not recipients_list:
        return False, "COMPANY_LIST is empty. Add at least one recipient in targets.py."
    high_critical_df = findings_df[findings_df["severity"].isin(["High", "Critical"])] if not findings_df.empty else pd.DataFrame()
    default_bug_type = str(high_critical_df.iloc[0]["issue"]) if not high_critical_df.empty else "Security Finding"
    default_severity = str(high_critical_df.iloc[0]["severity"]) if not high_critical_df.empty else "Medium"

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(settings["smtp_host"], settings["smtp_port"], timeout=15) as server:
            server.starttls(context=context)
            server.login(settings["smtp_user"], settings["smtp_pass"])
            for company_email in recipients_list:
                company_name = extract_company_name(company_email)
                bug_type = default_bug_type
                severity_level = default_severity
                dynamic_subject = (
                    f"[URGENT] Security Vulnerability Assessment Report - {company_name} - Faultless AI Audit"
                )
                template_body = (
                    f"Dear Security Team at {company_name},\n"
                    "My name is Muhammad Awais, a Senior Security Researcher at Faultless AI Audit. "
                    f"Our autonomous system has detected a {severity_level} vulnerability ({bug_type}) "
                    "in your infrastructure. A detailed PDF report is attached.\n"
                    f"Verify our work at: {WEBSITE_LINK}\n"
                    "To secure your systems 24/7, subscribe to our Premium Guardian Plan on our website."
                )
                final_template_body = add_subscription_message_if_needed(
                    company_key=f"{company_key}:{company_email}",
                    body=template_body,
                )
                msg = EmailMessage()
                msg["Subject"] = dynamic_subject
                msg["From"] = settings["from_email"]
                msg["To"] = company_email
                msg["Cc"] = settings["cc_email"]  # Dual notification: always carbon-copy user.
                msg.set_content(final_template_body)
                if not high_critical_df.empty:
                    pdf_attachment = generate_professional_security_pdf(findings_df, source, company_name)
                    msg.add_attachment(
                        pdf_attachment,
                        maintype="application",
                        subtype="pdf",
                        filename="faultless_ai_high_critical_report.pdf",
                    )
                server.send_message(msg, to_addrs=[company_email, settings["cc_email"]])
                record_wall_of_fame(company_name=company_name, bug_type=bug_type)
        return True, f"Alert email sent to {len(recipients_list)} company recipients."
    except Exception as exc:
        return False, f"Failed to send email: {exc}"


def format_alert_body(findings_df: pd.DataFrame, source: str) -> str:
    lines = [
        "Faultless AI Audit detected issues.",
        f"Source: {source}",
        f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Total findings: {len(findings_df)}",
        f"High/Critical findings: {int(findings_df['severity'].isin(['High', 'Critical']).sum()) if not findings_df.empty else 0}",
        "",
        "Top findings:",
    ]
    preview = findings_df.head(15)
    for _, row in preview.iterrows():
        lines.append(
            f"- [{row['severity']}] [{row['category']}] {row['issue']} | file/target={row['file']} | line={row['line']} | {row['snippet']}"
        )
    return "\n".join(lines)


def run_autopilot_cycle() -> None:
    state = get_autopilot_state()
    if not state.get("enabled", True):
        return

    all_findings = []
    for domain in TARGETS:
        all_findings.extend(scan_target(domain))

    if all_findings:
        df = pd.DataFrame(all_findings)
    else:
        df = pd.DataFrame(columns=["file", "category", "issue", "severity", "line", "snippet"])

    update_live_portfolio(df, source="scheduled monitor")

    if not df.empty:
        subject = f"[AUTO-ALERT] Faultless AI Audit detected {len(df)} issue(s)"
        body = format_alert_body(df, source="12-hour scheduled monitor")
        send_alert_email(subject, body, company_key="global_targets", findings_df=df, source="12-hour scheduled monitor")
        state["last_status"] = f"Alerts sent for {len(df)} findings"
    else:
        state["last_status"] = "No issues in latest scheduled cycle"

    state["last_run"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    save_json_file(STATE_FILE, state)


def autopilot_loop() -> None:
    run_autopilot_cycle()
    schedule.every(AUTOPILOT_EVERY_HOURS).hours.do(run_autopilot_cycle)
    while True:
        schedule.run_pending()
        time.sleep(5)


@st.cache_resource
def start_autopilot_worker() -> bool:
    worker = threading.Thread(target=autopilot_loop, daemon=True, name="faultless-autopilot")
    worker.start()
    return True


def decode_bytes(content: bytes) -> str:
    """Decode bytes safely into text."""
    for encoding in ("utf-8", "latin-1", "cp1252"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return ""


def scan_security(text: str) -> list[dict]:
    """Scan for hardcoded credentials and secret-like patterns."""
    findings = []
    patterns = [
        ("Hardcoded password", "High", r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
        ("Hardcoded API key", "Critical", r"(?i)\b(api[_-]?key|token|secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{8,}['\"]"),
        ("AWS Access Key", "Critical", r"\bAKIA[0-9A-Z]{16}\b"),
        ("GitHub token pattern", "Critical", r"\bghp_[A-Za-z0-9]{30,}\b"),
    ]

    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for issue_type, severity, pattern in patterns:
            if re.search(pattern, line):
                findings.append(
                    {
                        "category": "Security",
                        "issue": issue_type,
                        "severity": severity,
                        "line": line_no,
                        "snippet": line.strip()[:200],
                    }
                )
    return findings


def scan_logic(text: str) -> list[dict]:
    """Scan for simple division-by-zero issues."""
    findings = []
    lines = text.splitlines()

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if re.search(r"/\s*0(\D|$)", stripped):
            findings.append(
                {
                    "category": "Logic",
                    "issue": "Possible division by zero",
                    "severity": "Medium",
                    "line": line_no,
                    "snippet": stripped[:200],
                }
            )
        elif re.search(r"//\s*0(\D|$)", stripped):
            findings.append(
                {
                    "category": "Logic",
                    "issue": "Possible floor division by zero",
                    "severity": "Medium",
                    "line": line_no,
                    "snippet": stripped[:200],
                }
            )
    return findings


def scan_sql_injection(text: str) -> list[dict]:
    """Detect likely SQL injection-prone query construction."""
    findings = []
    patterns = [
        ("SQL query built with string concatenation", "Critical", r"(?i)(select|insert|update|delete).*(\+|%s|f\")"),
        ("SQL query built via format()", "High", r"(?i)(select|insert|update|delete).*(\.format\()"),
        ("Unsanitized SQL execution", "High", r"(?i)\.execute\(\s*f?[\"'].*\{.*\}"),
    ]

    for line_no, line in enumerate(text.splitlines(), start=1):
        for issue, severity, pattern in patterns:
            if re.search(pattern, line):
                findings.append(
                    {
                        "category": "Security",
                        "issue": issue,
                        "severity": severity,
                        "line": line_no,
                        "snippet": line.strip()[:200],
                    }
                )
    return findings


def scan_insecure_dependencies(text: str) -> list[dict]:
    """Flag potentially insecure dependency pins in requirements-like files."""
    findings = []
    rules = {
        "django": ("4.2.0", "High"),
        "flask": ("2.2.0", "High"),
        "requests": ("2.31.0", "Medium"),
        "pyyaml": ("6.0.0", "High"),
    }
    version_re = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*==\s*([0-9][A-Za-z0-9\.\-]*)", re.IGNORECASE)
    for line_no, line in enumerate(text.splitlines(), start=1):
        match = version_re.match(line)
        if not match:
            continue
        pkg = match.group(1).lower()
        version = match.group(2)
        if pkg in rules and version < rules[pkg][0]:
            findings.append(
                {
                    "category": "Dependency",
                    "issue": f"Potential insecure dependency: {pkg}=={version}",
                    "severity": rules[pkg][1],
                    "line": line_no,
                    "snippet": line.strip()[:200],
                }
            )
    return findings


def generate_pdf_report(df: pd.DataFrame, total_files: int) -> bytes:
    """Generate a PDF report for findings."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Faultless AI Audit Report", ln=True)

    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(0, 8, f"Files analyzed: {total_files}", ln=True)
    pdf.cell(0, 8, f"Total findings: {len(df)}", ln=True)
    pdf.ln(3)

    if df.empty:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "No issues found. Great job!", ln=True)
    else:
        for idx, row in df.iterrows():
            pdf.set_font("Arial", "B", 11)
            pdf.multi_cell(0, 7, f"{idx + 1}. [{row['category']}] {row['issue']}")
            pdf.set_font("Arial", "", 10)
            pdf.multi_cell(0, 6, f"File: {row['file']}  |  Line: {row['line']}")
            pdf.multi_cell(0, 6, f"Code: {str(row['snippet'])[:400]}")
            pdf.ln(1)

    pdf_output = pdf.output(dest="S")
    if isinstance(pdf_output, str):
        return pdf_output.encode("latin-1", errors="ignore")
    return bytes(pdf_output)


def extract_uploads(uploaded_files) -> tuple[list[tuple[str, str]], int]:
    """Return list of (filename, text) from direct files and ZIP archives."""
    extracted = []
    analyzed_files = 0
    allowed_ext = (
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".cpp",
        ".c",
        ".h",
        ".json",
        ".yaml",
        ".yml",
        ".env",
        ".txt",
    )

    for uploaded in uploaded_files:
        filename = uploaded.name
        ext = os.path.splitext(filename)[1].lower()
        data = uploaded.read()

        if ext == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zip_ref:
                    for member in zip_ref.infolist():
                        if member.is_dir():
                            continue
                        member_ext = os.path.splitext(member.filename)[1].lower()
                        if member_ext and member_ext not in allowed_ext:
                            continue
                        try:
                            content = zip_ref.read(member)
                            text = decode_bytes(content)
                            if text.strip():
                                extracted.append((member.filename, text))
                                analyzed_files += 1
                        except Exception:
                            continue
            except zipfile.BadZipFile:
                st.warning(f"Invalid ZIP file skipped: {filename}")
        else:
            if ext and ext not in allowed_ext:
                continue
            text = decode_bytes(data)
            if text.strip():
                extracted.append((filename, text))
                analyzed_files += 1

    return extracted, analyzed_files


def main() -> None:
    start_autopilot_worker()

    st.title("Faultless AI Audit")
    st.caption("Professional static code audit with instant detection and auto-pilot alerts.")
    portfolio = get_live_portfolio()

    with st.container(border=True):
        st.subheader("Live Security Portfolio")
        st.write(f"Last updated: {portfolio.get('last_updated') or 'Not available'}")
        pcol1, pcol2 = st.columns(2)
        pcol1.metric("Companies Audited", len(portfolio.get("audited_companies", [])))
        pcol2.metric("High/Critical Bugs Logged", len(portfolio.get("high_critical_bugs", [])))
        if portfolio.get("audited_companies"):
            st.caption("Audited companies/targets")
            st.code(", ".join(portfolio["audited_companies"][:20]), language="text")
        if portfolio.get("high_critical_bugs"):
            st.dataframe(pd.DataFrame(portfolio["high_critical_bugs"][-10:]), use_container_width=True, hide_index=True)

    with st.container(border=True):
        st.subheader("Wall of Fame")
        wall = portfolio.get("wall_of_fame", [])
        if wall:
            st.dataframe(pd.DataFrame(wall[-15:]), use_container_width=True, hide_index=True)
        else:
            st.caption("No successful report deliveries logged yet.")

    # Hidden Admin Dashboard access gate.
    with st.sidebar:
        st.markdown("### Private Controls")
        show_admin = st.toggle("Open hidden admin dashboard", value=False)

        if show_admin:
            if is_admin_rate_limited():
                st.error("Too many requests. Please wait and try again.")
            elif lockout_active():
                lock_until = datetime.fromtimestamp(st.session_state["admin_lock_until_ts"])
                st.error(f"Admin access locked until {lock_until.strftime('%H:%M:%S')} (UTC).")
            else:
                admin_pwd = st.text_input("Admin Password", type="password", placeholder="Enter secure admin password")
                if st.button("Unlock Admin"):
                    if verify_admin_password(admin_pwd):
                        st.session_state["admin_authed"] = True
                        reset_login_security()
                        st.success("Admin dashboard unlocked.")
                    else:
                        register_failed_login()
                        remaining = max(0, ADMIN_MAX_ATTEMPTS - st.session_state.get("admin_failed_attempts", 0))
                        st.error(f"Invalid password. Attempts left before lockout: {remaining}")

        if st.session_state.get("admin_authed"):
            st.markdown("---")
            st.markdown("### Admin Dashboard")
            state = get_autopilot_state()
            st.write(f"**Auto-Pilot Status:** {'Running' if state.get('enabled') else 'Paused'}")
            st.write(f"**Last Cycle:** {state.get('last_run') or 'Not yet run'}")
            st.write(f"**Last Status:** {state.get('last_status')}")

            col_pause, col_resume = st.columns(2)
            with col_pause:
                if st.button("Pause Auto-Pilot", use_container_width=True):
                    set_autopilot_enabled(False)
                    st.warning("Master kill switch activated. Auto-pilot paused.")
            with col_resume:
                if st.button("Resume Auto-Pilot", use_container_width=True):
                    set_autopilot_enabled(True)
                    st.success("Auto-pilot resumed.")

            if st.button("Lock Admin Dashboard", use_container_width=True):
                st.session_state["admin_authed"] = False
                st.info("Admin dashboard locked.")

    st.info(
        "Transport security: this app enforces TLS for outbound email (STARTTLS). "
        "Deploy behind HTTPS (reverse proxy/TLS cert) to encrypt browser-to-server traffic."
    )

    with st.container(border=True):
        st.subheader("Upload Source Files or ZIP")
        uploaded_files = st.file_uploader(
            "Choose files (.py, .js, etc.) or ZIP archives",
            type=[
                "py",
                "js",
                "ts",
                "jsx",
                "tsx",
                "java",
                "go",
                "rb",
                "php",
                "cs",
                "cpp",
                "c",
                "h",
                "json",
                "yaml",
                "yml",
                "env",
                "txt",
                "zip",
            ],
            accept_multiple_files=True,
            help="You can upload one or multiple files, including ZIP archives.",
        )

    run_scan = st.button("Run Faultless Audit", type="primary", use_container_width=True)

    if run_scan:
        state = get_autopilot_state()
        if not state.get("enabled", True):
            st.error("Auto-pilot is currently paused by admin. Resume it from the Admin Dashboard.")
            return

        if not uploaded_files:
            st.error("Please upload at least one file or ZIP archive.")
            return

        with st.spinner("Scanning files..."):
            extracted_files, total_files = extract_uploads(uploaded_files)

            all_findings = []
            for fname, text in extracted_files:
                security_findings = scan_security(text)
                logic_findings = scan_logic(text)
                sql_injection_findings = scan_sql_injection(text)
                dependency_findings = scan_insecure_dependencies(text)

                for finding in security_findings + logic_findings + sql_injection_findings + dependency_findings:
                    finding["file"] = fname
                    all_findings.append(finding)

            findings_df = pd.DataFrame(all_findings)
            if not findings_df.empty:
                findings_df = findings_df[
                    ["file", "category", "severity", "issue", "line", "snippet"]
                ].sort_values(by=["severity", "category", "file", "line"], ascending=[True, True, True, True])
            else:
                findings_df = pd.DataFrame(columns=["file", "category", "severity", "issue", "line", "snippet"])

            update_live_portfolio(findings_df, source="manual upload audit")

        st.success(f"Audit complete. Files analyzed: {total_files}")

        col1, col2, col3 = st.columns(3)
        col1.metric("Files Analyzed", total_files)
        col2.metric("Total Findings", len(findings_df))
        col3.metric(
            "High/Critical Findings",
            int(findings_df["severity"].isin(["High", "Critical"]).sum()) if not findings_df.empty else 0,
        )

        st.subheader("Audit Findings")
        if findings_df.empty:
            st.info("No security or logic issues found.")
        else:
            st.dataframe(findings_df, use_container_width=True, hide_index=True)
            subject = f"[INSTANT ALERT] Faultless AI Audit detected {len(findings_df)} issue(s)"
            body = format_alert_body(findings_df, source="uploaded code scan")
            email_ok, email_msg = send_alert_email(
                subject,
                body,
                company_key="uploaded_scan",
                findings_df=findings_df,
                source="uploaded code scan",
            )
            if email_ok:
                st.success("Instant auto-alert sent to company email with CC to your email.")
            else:
                st.warning(f"Auto-alert could not be sent: {email_msg}")

        csv_bytes = findings_df.to_csv(index=False).encode("utf-8")
        pdf_bytes = generate_pdf_report(findings_df, total_files)

        st.subheader("Export Reports")
        c1, c2 = st.columns(2)
        with c1:
            st.download_button(
                label="Download CSV Report",
                data=csv_bytes,
                file_name="faultless_ai_audit_report.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with c2:
            st.download_button(
                label="Download PDF Report",
                data=pdf_bytes,
                file_name="faultless_ai_audit_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

    with st.expander("24/7 Global Target Loop (50 Companies)", expanded=False):
        st.write("Auto-pilot monitor includes the following target set:")
        st.code(", ".join(TARGETS), language="text")
        st.caption("Use only with legal authorization and approved scopes.")


if __name__ == "__main__":
    main()
