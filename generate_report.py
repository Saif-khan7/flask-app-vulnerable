import json
import os
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

# Define the paths to your JSON reports
REPORTS_DIR = 'artifacts'  # Adjust this path if your artifacts are stored elsewhere
OUTPUT_DIR = 'reports'
TEMPLATE_DIR = 'templates'

# Ensure the output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Initialize Jinja2 environment
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
template = env.get_template('report_template.html')

# Function to load a JSON file
def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

# Function to process Semgrep report
def process_semgrep(report):
    tool = {
        'name': 'Semgrep',
        'headers': ['Check ID', 'Severity', 'Message', 'File', 'Line'],
        'columns': ['check_id', 'severity', 'message', 'path', 'start_line'],
        'results': [],
        'errors': []
    }
    if 'errors' in report:
        for error in report['errors']:
            tool['errors'].append(error['message'])
    
    for result in report.get('results', []):
        tool['results'].append({
            'check_id': result.get('check_id', ''),
            'severity': result.get('severity', ''),
            'message': result.get('extra', {}).get('message', ''),
            'path': result.get('path', ''),
            'start_line': result.get('start', {}).get('line', '')
        })
    return tool

# Function to process Bandit report
def process_bandit(report):
    tool = {
        'name': 'Bandit',
        'headers': ['Issue Severity', 'Issue', 'File', 'Line'],
        'columns': ['issue_severity', 'issue_text', 'filename', 'line_number'],
        'results': [],
        'errors': []
    }
    for issue in report.get('results', []):
        tool['results'].append({
            'issue_severity': issue.get('issue_severity', ''),
            'issue_text': issue.get('issue_text', ''),
            'filename': issue.get('filename', ''),
            'line_number': issue.get('line_number', '')
        })
    return tool

# Function to process Pylint report
def process_pylint(report):
    tool = {
        'name': 'Pylint',
        'headers': ['Type', 'Message', 'Module', 'Line'],
        'columns': ['type', 'message', 'module', 'line'],
        'results': [],
        'errors': []
    }
    for issue in report:
        tool['results'].append({
            'type': issue.get('type', ''),
            'message': issue.get('message', ''),
            'module': issue.get('module', ''),
            'line': issue.get('line', '')
        })
    return tool

# Function to process Safety report
def process_safety(report):
    tool = {
        'name': 'Safety',
        'headers': ['Package', 'Vulnerability', 'Severity'],
        'columns': ['package_name', 'advisory', 'severity'],
        'results': [],
        'errors': []
    }
    for vuln in report.get('vulnerabilities', []):
        tool['results'].append({
            'package_name': vuln.get('package_name', ''),
            'advisory': vuln.get('advisory', ''),
            'severity': vuln.get('severity', '')
        })
    return tool

# Add more processing functions for other tools if needed

def main():
    tools = []

    # Process Semgrep Report
    semgrep_path = os.path.join(REPORTS_DIR, 'semgrep-report.json')
    if os.path.exists(semgrep_path):
        semgrep_report = load_json(semgrep_path)
        tools.append(process_semgrep(semgrep_report))
    else:
        print(f"Semgrep report not found at {semgrep_path}")

    # Process Bandit Report
    bandit_path = os.path.join(REPORTS_DIR, 'bandit-report.json')
    if os.path.exists(bandit_path):
        bandit_report = load_json(bandit_path)
        tools.append(process_bandit(bandit_report))
    else:
        print(f"Bandit report not found at {bandit_path}")

    # Process Pylint Report
    pylint_path = os.path.join(REPORTS_DIR, 'pylint-report.json')
    if os.path.exists(pylint_path):
        pylint_report = load_json(pylint_path)
        tools.append(process_pylint(pylint_report))
    else:
        print(f"Pylint report not found at {pylint_path}")

    # Process Safety Report
    safety_path = os.path.join(REPORTS_DIR, 'safety-report.json')
    if os.path.exists(safety_path):
        safety_report = load_json(safety_path)
        tools.append(process_safety(safety_report))
    else:
        print(f"Safety report not found at {safety_path}")

    # Add more tool processing as needed

    # Render HTML using the template
    html_out = template.render(tools=tools)

    # Write the HTML to a file (optional)
    html_file = os.path.join(OUTPUT_DIR, 'security_report.html')
    with open(html_file, 'w') as f:
        f.write(html_out)
    print(f"HTML report generated at {html_file}")

    # Convert HTML to PDF
    pdf_file = os.path.join(OUTPUT_DIR, 'security_report.pdf')
    HTML(string=html_out).write_pdf(pdf_file)
    print(f"PDF report generated at {pdf_file}")

if __name__ == '__main__':
    main()
