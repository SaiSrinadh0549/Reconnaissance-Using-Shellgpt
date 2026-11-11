import ipaddress, json, platform, re, shutil, socket, ssl, subprocess
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import urljoin, urlparse
from xml.sax.saxutils import escape

import requests
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted

st.set_page_config(page_title="ShellGPT Security Lab", page_icon="🛡️", layout="centered")
st.title("🛡️ ShellGPT Security Lab")
st.caption("Seven cybersecurity footprinting demonstrations")
st.info("Use only domains and systems you own or are explicitly authorized to assess.")

for key, default in [("latest_result", None), ("last_scan", None)]:
    if key not in st.session_state:
        st.session_state[key] = default

target = st.text_input("Target domain", placeholder="your-owned-domain.example")
authorized = st.checkbox("I am authorized to assess this domain.")
activities = [
    "1. Email Footprinting",
    "2. Social Footprinting (Privacy Assessment)",
    "3. Website Footprinting",
    "4. Wordlist Demonstration (Local Text)",
    "5. Traceroute",
    "6. Website Structure Inventory",
    "7. Automated Footprinting",
    "AI Report Explanation",
]
activity = st.selectbox("Choose an activity", activities)

# ---------------- Validation and DNS ----------------
def validate_domain(value):
    domain = value.strip().lower().rstrip(".")
    if not domain or any(x in domain for x in ["://", "/", "@", " "]):
        raise ValueError("Enter a domain only, such as example.com.")
    try:
        ipaddress.ip_address(domain)
        raise ValueError("Enter a DNS domain, not an IP address.")
    except ValueError as exc:
        if str(exc).startswith("Enter a DNS domain"):
            raise
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid domain name.")
    pattern = r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
    if not re.fullmatch(pattern, domain):
        raise ValueError("Invalid domain format.")
    return domain


def resolve_public(domain):
    addresses = sorted({x[4][0] for x in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)})
    if not addresses:
        raise RuntimeError("The domain did not resolve.")
    if any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise RuntimeError("The domain resolves to a private, loopback, or reserved IP address.")
    return addresses


def dig_record(domain, record_type):
    dig = shutil.which("dig")
    if not dig:
        return ["dig not installed. Install dnsutils."]
    try:
        p = subprocess.run([dig, "+time=3", "+tries=1", "+short", domain, record_type],
                           capture_output=True, text=True, timeout=8, shell=False)
        return [line.strip() for line in p.stdout.splitlines() if line.strip()]
    except subprocess.TimeoutExpired:
        return ["DNS query timed out."]


def dns_report(domain):
    return {record: dig_record(domain, record) for record in ["A", "AAAA", "MX", "NS", "TXT"]}

# ---------------- Activity 1: Email footprinting ----------------
def email_footprinting(domain):
    txt = dig_record(domain, "TXT")
    dmarc_txt = dig_record("_dmarc." + domain, "TXT")
    spf = [x for x in txt if "v=spf1" in x.lower()]
    dmarc = [x for x in dmarc_txt if "v=dmarc1" in x.lower()]
    return {
        "Domain": domain,
        "MX Records": dig_record(domain, "MX"),
        "SPF Records": spf or ["No SPF record detected in returned TXT records."],
        "DMARC Records": dmarc or ["No DMARC record detected."],
        "Note": "Email-domain configuration only; no personal email addresses are harvested."
    }

# ---------------- Activity 3: Website footprinting ----------------
def http_tls_analysis(domain):
    report = {}
    try:
        response = requests.get("https://" + domain, timeout=12, allow_redirects=True,
                                headers={"User-Agent": "ShellGPT-Security-Lab/3.0"}, stream=True)
        report["Final URL"] = response.url
        report["HTTP Status"] = response.status_code
        report["Redirect Count"] = len(response.history)
        keys = ["server", "content-type", "strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options", "referrer-policy"]
        report["HTTP Headers"] = {k: response.headers.get(k, "Not present") for k in keys}
        response.close()
    except requests.RequestException as exc:
        report["HTTP Error"] = str(exc)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                report["TLS Version"] = tls.version()
                report["Cipher"] = tls.cipher()[0] if tls.cipher() else "Unknown"
                report["Certificate Expiry"] = cert.get("notAfter", "Unknown")
    except Exception as exc:
        report["TLS Error"] = str(exc)
    return report


def whois_analysis(domain):
    whois = shutil.which("whois")
    if not whois:
        return {"Error": "WHOIS not installed. Run sudo apt install whois."}
    try:
        p = subprocess.run([whois, domain], capture_output=True, text=True, timeout=20, shell=False)
        raw = p.stdout or p.stderr
        # Best-effort redaction of common contact fields; review before sharing.
        raw = re.sub(r"(?im)^.*(?:email|e-mail|phone|fax|street|address|registrant name|admin name|tech name|person):.*$",
                     "[redacted personal contact field]", raw)
        return {"WHOIS Output (common contact fields redacted)": raw[:12000]}
    except subprocess.TimeoutExpired:
        return {"Error": "WHOIS query timed out."}

# ---------------- Activity 4: Local text vocabulary analysis ----------------
def local_text_analysis(upload):
    if upload is None:
        return {"Error": "Upload a text file you own."}
    raw = upload.getvalue()
    if len(raw) > 1_000_000:
        return {"Error": "Please upload a text file smaller than 1 MB."}
    content = raw.decode("utf-8", errors="replace").lower()
    words = re.findall(r"\b[a-zA-Z][a-zA-Z0-9_-]{2,}\b", content)
    counts = Counter(words)
    return {
        "File Name": upload.name,
        "Total Word Count": len(words),
        "Unique Terms": len(counts),
        "Most Frequent Terms": counts.most_common(30),
        "Purpose": "Vocabulary analysis only; no password-attack wordlist is generated."
    }

# ---------------- Activity 5: Traceroute ----------------
def traceroute_analysis(domain):
    if platform.system() == "Windows":
        command = ["tracert", "-d", "-h", "12", "-w", "1000", domain]
    else:
        tool = shutil.which("traceroute") or shutil.which("tracepath")
        if not tool:
            return {"Error": "Install traceroute using sudo apt install traceroute."}
        command = [tool, "-m", "12", domain] if tool.endswith("tracepath") else [tool, "-m", "12", "-w", "1", domain]
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=35, shell=False)
        return {"Exit Code": p.returncode, "Output": (p.stdout + "\n" + p.stderr).strip() or "No output returned."}
    except subprocess.TimeoutExpired:
        return {"Error": "Traceroute timed out."}

# ---------------- Activity 6: Website structure inventory ----------------
def website_structure_inventory(domain):
    base = "https://" + domain
    headers = {"User-Agent": "ShellGPT-Security-Lab/3.0"}
    report = {}
    for path in ["/robots.txt", "/sitemap.xml"]:
        try:
            r = requests.get(urljoin(base, path), headers=headers, timeout=10, allow_redirects=True)
            report[path] = {"HTTP Status": r.status_code, "Final URL": r.url,
                            "Content Preview": r.text[:3000] if r.status_code == 200 else ""}
        except requests.RequestException as exc:
            report[path] = {"Error": str(exc)}
    try:
        r = requests.get(base, headers=headers, timeout=10, allow_redirects=True)
        links = []
        for href in re.findall(r"href=[\"']([^\"'#]+)[\"']", r.text, flags=re.I):
            link = urljoin(r.url, href)
            parsed = urlparse(link)
            if parsed.scheme in ("http", "https") and parsed.netloc == domain and link not in links:
                links.append(link)
            if len(links) >= 40:
                break
        report["Same-Domain Homepage Links"] = links
    except requests.RequestException as exc:
        report["Homepage Link Error"] = str(exc)
    report["Scope Note"] = "Metadata and link inventory only; no website cloning or bulk downloading."
    return report

# ---------------- Activity 7: Automated footprinting ----------------
def automated_footprinting(domain, addresses):
    return {
        "Target": domain,
        "Resolved IP Addresses": addresses,
        "DNS Records": dns_report(domain),
        "Email Domain Configuration": email_footprinting(domain),
        "HTTP and TLS Analysis": http_tls_analysis(domain),
        "WHOIS Information": whois_analysis(domain),
        "Generated UTC": datetime.now(timezone.utc).isoformat()
    }

# ---------------- ShellGPT analysis ----------------
def shellgpt_analysis(scan_record):
    sgpt = shutil.which("sgpt")
    if not sgpt:
        return {"Error": "ShellGPT CLI was not found in PATH."}
    prompt = (
        "You are a careful cybersecurity report analyst. Analyze the supplied authorized assessment results. "
        "Use only the evidence provided. Separate confirmed observations from unknowns and potential risks. "
        "Do not invent vulnerabilities or suggest exploitation. Provide defensive recommendations and clear Markdown headings.\n\n"
        + json.dumps(scan_record, indent=2, ensure_ascii=False)[:12000]
    )
    try:
        p = subprocess.run([sgpt, prompt], capture_output=True, text=True, timeout=75, shell=False)
        if p.returncode != 0:
            return {"Error": p.stderr.strip() or "ShellGPT returned an error."}
        return {"ShellGPT Analysis": p.stdout.strip()}
    except subprocess.TimeoutExpired:
        return {"Error": "ShellGPT request timed out."}

# ---------------- PDF report generation ----------------
def create_pdf_report(record):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
                            topMargin=19*mm, bottomMargin=19*mm,
                            title="ShellGPT Security Assessment Report", author="ShellGPT Security Lab")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                                 fontSize=19, leading=23, textColor=colors.HexColor("#12345A"),
                                 alignment=TA_CENTER, spaceAfter=7)
    subtitle_style = ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=9,
                                    textColor=colors.HexColor("#64748B"), alignment=TA_CENTER, spaceAfter=18)
    heading_style = ParagraphStyle("ReportHeading", parent=styles["Heading2"], fontName="Helvetica-Bold",
                                   fontSize=12, leading=15, textColor=colors.HexColor("#087E9B"),
                                   spaceBefore=12, spaceAfter=7)
    body_style = ParagraphStyle("ReportBody", parent=styles["BodyText"], fontName="Helvetica",
                                fontSize=9, leading=13, spaceAfter=6, wordWrap="CJK")
    code_style = ParagraphStyle("ReportCode", parent=styles["Code"], fontName="Courier",
                                fontSize=7, leading=9, leftIndent=4, rightIndent=4,
                                wordWrap="CJK", spaceAfter=2)
    story = [Paragraph("SHELLGPT SECURITY LAB", title_style),
             Paragraph("Cybersecurity Footprinting Assessment Report", subtitle_style),
             Paragraph("Assessment Information", heading_style)]
    metadata = [
        ["Project", "ShellGPT Security Lab"],
        ["Activity", str(record.get("Activity", "N/A"))],
        ["Target", str(record.get("Target", "N/A"))],
        ["Date and Time (UTC)", str(record.get("Time UTC", "N/A"))]
    ]
    table_data = [[Paragraph("<b>" + escape(str(row[0])) + "</b>", body_style),
                   Paragraph(escape(str(row[1])), body_style)] for row in metadata]
    table = Table(table_data, colWidths=[45*mm, 120*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#E8F1F8")),
        ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 7), ("RIGHTPADDING", (0,0), (-1,-1), 7),
        ("TOPPADDING", (0,0), (-1,-1), 7), ("BOTTOMPADDING", (0,0), (-1,-1), 7)
    ]))
    story.extend([table, Paragraph("Assessment Results", heading_style)])
    result = record.get("Result", {})
    if record.get("Activity") == "AI Report Explanation":
        analysis = result.get("ShellGPT Analysis")
        if analysis:
            for line in analysis.splitlines():
                line = line.strip()
                if not line:
                    story.append(Spacer(1, 4))
                elif line.startswith("#"):
                    story.append(Paragraph(escape(line.lstrip("#").strip()), heading_style))
                elif line.startswith(("- ", "* ")):
                    story.append(Paragraph("• " + escape(line[2:]), body_style))
                else:
                    story.append(Paragraph(escape(line), body_style))
        else:
            story.append(Paragraph(escape(str(result.get("Error", "No AI analysis available."))), body_style))
    else:
        result_text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
        story.append(Preformatted(result_text, code_style, maxLineLength=100))
    story.extend([
        Spacer(1, 12),
        Paragraph("Conclusion", heading_style),
        Paragraph("This report records observations returned by ShellGPT Security Lab. These observations are not, by themselves, proof of a vulnerability. Verify findings before making security conclusions.", body_style),
        Spacer(1, 8),
        Paragraph("<b>Disclaimer:</b> Generated for educational and authorized cybersecurity assessment purposes only.", body_style)
    ])
    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(18*mm, 10*mm, "ShellGPT Security Lab | Educational Use")
        canvas.drawRightString(A4[0]-18*mm, 10*mm, f"Page {document.page}")
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    buffer.seek(0)
    return buffer.getvalue()

# ---------------- Activity-specific inputs ----------------
uploaded_file = None
if activity == "4. Wordlist Demonstration (Local Text)":
    uploaded_file = st.file_uploader("Upload your own text file", type=["txt"])

if activity == "2. Social Footprinting (Privacy Assessment)":
    account_label = st.text_input("Your own account label (optional)")
    privacy_checks = ["Profile visibility reviewed", "Public contact details reviewed",
                      "Username reuse reviewed by account owner", "MFA enabled where available",
                      "Account recovery options reviewed"]
    completed_checks = [x for x in privacy_checks if st.checkbox(x, key="privacy_" + x)]
else:
    account_label, privacy_checks, completed_checks = "", [], []

# ---------------- Run and clear controls ----------------
run_col, clear_col = st.columns(2)
with run_col:
    run_clicked = st.button("Run Activity", type="primary", use_container_width=True)
with clear_col:
    clear_clicked = st.button("Clear Results", use_container_width=True)

if clear_clicked:
    st.session_state.latest_result = None
    st.session_state.last_scan = None
    st.rerun()

# ---------------- Execute selected activity ----------------
if run_clicked:
    if activity == "4. Wordlist Demonstration (Local Text)":
        result = local_text_analysis(uploaded_file)
        record = {"Activity": activity, "Target": uploaded_file.name if uploaded_file else "Local text file",
                  "Result": result, "Time UTC": datetime.now(timezone.utc).isoformat()}
        st.session_state.last_scan = record
        st.session_state.latest_result = record

    elif activity == "2. Social Footprinting (Privacy Assessment)":
        result = {"Account Label": account_label or "My account", "Completed Checks": completed_checks,
                  "Remaining Checks": [x for x in privacy_checks if x not in completed_checks],
                  "Note": "Self-assessment only; no personal account enumeration was performed."}
        record = {"Activity": activity, "Target": account_label or "Self-assessment",
                  "Result": result, "Time UTC": datetime.now(timezone.utc).isoformat()}
        st.session_state.last_scan = record
        st.session_state.latest_result = record

    elif activity == "AI Report Explanation":
        if not st.session_state.last_scan:
            st.error("Run another activity before requesting AI analysis.")
        else:
            with st.spinner("ShellGPT is analyzing the latest result..."):
                record = {"Activity": activity, "Target": st.session_state.last_scan["Target"],
                          "Result": shellgpt_analysis(st.session_state.last_scan),
                          "Time UTC": datetime.now(timezone.utc).isoformat()}
                st.session_state.latest_result = record

    elif not authorized:
        st.error("Confirm that you are authorized to assess this domain.")
    elif not target.strip():
        st.error("Enter your authorized target domain.")
    else:
        try:
            domain = validate_domain(target)
            addresses = resolve_public(domain)
            with st.spinner("Running activity..."):
                if activity == "1. Email Footprinting":
                    result = email_footprinting(domain)
                elif activity == "3. Website Footprinting":
                    result = {"DNS Records": dns_report(domain), "HTTP and TLS": http_tls_analysis(domain),
                              "WHOIS": whois_analysis(domain)}
                elif activity == "5. Traceroute":
                    result = traceroute_analysis(domain)
                elif activity == "6. Website Structure Inventory":
                    result = website_structure_inventory(domain)
                elif activity == "7. Automated Footprinting":
                    result = automated_footprinting(domain, addresses)
                else:
                    result = {"Error": "Unknown activity selected."}
                record = {"Activity": activity, "Target": domain, "Resolved IP Addresses": addresses,
                          "Result": result, "Time UTC": datetime.now(timezone.utc).isoformat()}
                st.session_state.last_scan = record
                st.session_state.latest_result = record
        except Exception as exc:
            st.error(str(exc))

# ---------------- Latest result and PDF download ----------------
if st.session_state.latest_result:
    st.divider()
    st.subheader("Latest Result")
    record = st.session_state.latest_result
    st.write("**Activity:**", record["Activity"])
    st.write("**Target:**", record["Target"])
    st.write("**Time (UTC):**", record["Time UTC"])
    if record["Activity"] == "AI Report Explanation":
        analysis = record["Result"].get("ShellGPT Analysis")
        if analysis:
            st.markdown(analysis)
        else:
            st.error(record["Result"].get("Error", "AI analysis failed."))
    else:
        st.json(record["Result"])
    try:
        pdf_bytes = create_pdf_report(record)
        st.download_button("Download PDF Report", data=pdf_bytes,
                           file_name="ShellGPT_Security_Report.pdf", mime="application/pdf",
                           use_container_width=True)
    except Exception as exc:
        st.error(f"Could not generate PDF report: {exc}")
else:
    st.info("No results yet. Select an activity and click Run Activity.")

st.divider()
st.caption("ShellGPT Security Lab | Educational Use | Authorized Assessment Only")
