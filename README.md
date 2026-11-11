# ShellGPT Security Lab — PDF Edition

## Included activities
1. Email Footprinting: MX, SPF and DMARC configuration.
2. Social Footprinting: self-assessment privacy checklist.
3. Website Footprinting: DNS, HTTP/TLS and WHOIS.
4. Wordlist Demonstration: vocabulary analysis of a text file you own.
5. Traceroute: bounded route discovery.
6. Website Structure Inventory: robots.txt, sitemap.xml and same-domain homepage links.
7. Automated Footprinting: combines DNS, email configuration, HTTP/TLS and WHOIS.
8. AI Report Explanation: uses your existing `sgpt PROMPT` CLI syntax.

Every activity provides a downloadable PDF report.

## Kali Linux installation

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip dnsutils whois traceroute unzip -y
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
which sgpt
sgpt --help
streamlit run app.py
```

Open the local URL printed by Streamlit, normally http://localhost:8501.

Use only systems you own or are explicitly authorized to assess. WHOIS contact-field redaction is best-effort; review reports before sharing. Keep API keys out of source files and GitHub.
