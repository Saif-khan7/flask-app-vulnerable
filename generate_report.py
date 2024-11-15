import json
import os
from reportlab.lib.pagesizes import LETTER, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from datetime import datetime

def load_json(file_path):
    """
    Load and return JSON data from a file.
    """
    if not os.path.exists(file_path):
        print(f"Warning: {file_path} does not exist.")
        return None
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {file_path}: {e}")
        return None

def parse_bandit_report(bandit_data):
    """
    Parse Bandit JSON report and return a list of issues.
    """
    if not bandit_data or 'results' not in bandit_data:
        return []
    issues = []
    for issue in bandit_data['results']:
        issues.append([
            issue.get('issue_severity', 'N/A'),
            issue.get('issue_text', 'N/A'),
            issue.get('filename', 'N/A'),
            issue.get('line_number', 'N/A')
        ])
    return issues

def parse_semgrep_report(semgrep_data):
    """
    Parse Semgrep JSON report and return a list of issues.
    """
    if not semgrep_data or 'results' not in semgrep_data:
        return []
    issues = []
    for issue in semgrep_data['results']:
        issues.append([
            issue.get('extra', {}).get('severity', 'N/A'),
            issue.get('message', 'N/A'),
            issue.get('path', 'N/A'),
            issue.get('start', {}).get('line', 'N/A')
        ])
    return issues

def parse_pylint_report(pylint_data):
    """
    Parse Pylint JSON report and return a list of issues.
    """
    if not pylint_data:
        return []
    issues = []
    for issue in pylint_data:
        issues.append([
            issue.get('type', 'N/A'),
            issue.get('message', 'N/A'),
            issue.get('module', 'N/A'),
            issue.get('line', 'N/A')
        ])
    return issues

def create_pdf_report(bandit_issues, semgrep_issues, pylint_issues, output_file='security_report.pdf'):
    """
    Create a PDF report summarizing the security findings.
    """
    doc = SimpleDocTemplate(
        output_file,
        pagesize=LETTER,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=18,
    )
    elements = []

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CenterTitle', alignment=1, fontSize=18, spaceAfter=20))
    styles.add(ParagraphStyle(name='Heading', fontSize=14, spaceAfter=10, textColor=colors.darkblue))
    
    # Modify the existing 'Normal' style instead of adding a new one
    styles['Normal'].fontSize = 10
    styles['Normal'].spaceAfter = 10

    # Title
    elements.append(Paragraph("🛡️ Security Scan Report", styles['CenterTitle']))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Bandit Findings
    elements.append(Paragraph("🔒 Bandit Findings", styles['Heading']))
    if bandit_issues:
        table_data = [["Severity", "Issue", "File", "Line"]]
        table_data += bandit_issues

        table = Table(table_data, colWidths=[60, 250, 150, 40])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No issues found by Bandit.", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Semgrep Findings
    elements.append(Paragraph("🔍 Semgrep Findings", styles['Heading']))
    if semgrep_issues:
        table_data = [["Severity", "Message", "File", "Line"]]
        table_data += semgrep_issues

        table = Table(table_data, colWidths=[60, 250, 150, 40])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No issues found by Semgrep.", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Pylint Findings
    elements.append(Paragraph("🐍 Pylint Findings", styles['Heading']))
    if pylint_issues:
        table_data = [["Type", "Message", "Module", "Line"]]
        table_data += pylint_issues

        table = Table(table_data, colWidths=[60, 250, 150, 40])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No issues found by Pylint.", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Build PDF
    doc.build(elements)
    print(f"PDF report generated successfully: {output_file}")

def main():
    # Define file paths
    bandit_file = 'bandit-report.json'
    semgrep_file = 'semgrep-report.json'
    pylint_file = 'pylint-report.json'

    # Load JSON reports
    bandit_data = load_json(bandit_file)
    semgrep_data = load_json(semgrep_file)
    pylint_data = load_json(pylint_file)

    # Parse reports
    bandit_issues = parse_bandit_report(bandit_data)
    semgrep_issues = parse_semgrep_report(semgrep_data)
    pylint_issues = parse_pylint_report(pylint_data)

    # Create PDF report
    create_pdf_report(bandit_issues, semgrep_issues, pylint_issues)

if __name__ == "__main__":
    main()
