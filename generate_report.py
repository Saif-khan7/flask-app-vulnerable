import json
import pdfkit

# Load JSON files
with open('bandit-report.json') as bandit_file:
    bandit_data = json.load(bandit_file)

with open('safety-report.json') as safety_file:
    safety_data = json.load(safety_file)

with open('semgrep-report.json') as semgrep_file:
    semgrep_data = json.load(semgrep_file)

# Create HTML content for the PDF
html_out = "<h1>Security Scan Report</h1>"

# Bandit Report
html_out += "<h2>Bandit Report</h2>"
if bandit_data.get("results"):
    html_out += "<table border='1'><tr><th>Severity</th><th>Issue</th><th>File</th><th>Line</th></tr>"
    for result in bandit_data["results"]:
        html_out += f"<tr><td>{result['issue_severity']}</td><td>{result['issue_text']}</td><td>{result['filename']}</td><td>{result['line_number']}</td></tr>"
    html_out += "</table>"
else:
    html_out += "<p>No issues found by Bandit.</p>"

# Safety Report
html_out += "<h2>Safety Report</h2>"
if safety_data.get("vulnerabilities"):
    html_out += "<table border='1'><tr><th>Package</th><th>Vulnerability</th><th>Severity</th></tr>"
    for vulnerability in safety_data["vulnerabilities"]:
        html_out += f"<tr><td>{vulnerability['package_name']}</td><td>{vulnerability['vulnerability']}</td><td>{vulnerability['severity']}</td></tr>"
    html_out += "</table>"
else:
    html_out += "<p>No vulnerabilities found by Safety.</p>"

# Semgrep Report
html_out += "<h2>Semgrep Report</h2>"
if semgrep_data.get("results"):
    html_out += "<table border='1'><tr><th>Severity</th><th>Message</th><th>File</th><th>Line</th></tr>"
    for result in semgrep_data["results"]:
        html_out += f"<tr><td>{result['severity']}</td><td>{result['extra']['message']}</td><td>{result['path']}</td><td>{result['start']['line']}</td></tr>"
    html_out += "</table>"
else:
    html_out += "<p>No issues found by Semgrep.</p>"

# Output PDF file name
pdf_file = "Security_Scan_Report.pdf"

# Generate PDF
pdfkit.from_string(html_out, pdf_file)

print(f"PDF report generated: {pdf_file}")
