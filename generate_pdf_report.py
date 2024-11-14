import json
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet

def create_pdf(report_data, output_filename):
    doc = SimpleDocTemplate(output_filename, pagesize=LETTER)
    elements = []
    styles = getSampleStyleSheet()

    # Title
    elements.append(Paragraph('Security Scan Report', styles['Title']))
    elements.append(Spacer(1, 12))

    # For each tool's report
    for tool_name, findings in report_data.items():
        elements.append(Paragraph(f'{tool_name} Findings', styles['Heading2']))
        elements.append(Spacer(1, 12))

        if findings['rows']:
            data = [findings['headers']] + findings['rows']
            table = Table(data, repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.gray),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.black),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 24))
        else:
            elements.append(Paragraph('No issues found.', styles['Normal']))
            elements.append(Spacer(1, 24))

        # Add a page break between reports
        elements.append(PageBreak())

    doc.build(elements)

def parse_bandit_report(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    findings = data.get('results', [])
    report = {'headers': ['Severity', 'Issue', 'File', 'Line'], 'rows': []}
    for issue in findings:
        severity = issue.get('issue_severity', 'UNKNOWN')
        issue_text = issue.get('issue_text', '')
        file_path = issue.get('filename', 'N/A')
        line_number = issue.get('line_number', 'N/A')
        report['rows'].append([severity, issue_text, file_path, line_number])
    return report

def parse_safety_report(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    findings = data.get('vulnerabilities', [])
    report = {'headers': ['Package', 'Vulnerability', 'Severity'], 'rows': []}
    for vuln in findings:
        package_name = vuln.get('package_name', 'N/A')
        advisory = vuln.get('advisory', '')
        severity = vuln.get('severity', 'N/A')
        report['rows'].append([package_name, advisory, severity])
    return report

def parse_semgrep_report(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    findings = data.get('results', [])
    report = {'headers': ['Severity', 'Message', 'File', 'Line'], 'rows': []}
    for issue in findings:
        severity = issue.get('extra', {}).get('severity', 'UNKNOWN')
        message = issue.get('extra', {}).get('message', '')
        file_path = issue.get('path', 'N/A')
        line_number = issue.get('start', {}).get('line', 'N/A')
        report['rows'].append([severity, message, file_path, line_number])
    return report

def main():
    report_data = {}

    # Parse Bandit report
    bandit_report = parse_bandit_report('bandit-report.json')
    report_data['Bandit'] = bandit_report

    # Parse Safety report
    safety_report = parse_safety_report('safety-report.json')
    report_data['Safety'] = safety_report

    # Parse Semgrep report
    semgrep_report = parse_semgrep_report('semgrep-report.json')
    report_data['Semgrep'] = semgrep_report

    # Generate PDF
    create_pdf(report_data, 'security_report.pdf')

if __name__ == '__main__':
    main()
