import json
import os
import pdfkit

# Define the paths to your JSON reports
REPORTS_DIR = 'artifacts'  # Adjust this path if your artifacts are stored elsewhere
OUTPUT_DIR = 'reports'
TEMPLATE_DIR = 'templates'

# Ensure the output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Function to load a JSON file
def load_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: {file_path} not found.")
        return {}
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {file_path}: {e}")
        return {}

# Function to process Semgrep report
def process_semgrep(report):
    tool = {
        'name': 'Semgrep',
        'headers': ['Check ID', 'Severity', 'Message', 'File', 'Line'],
        'columns': ['check_id', 'severity', 'message', 'path', 'line'],
        'results': [],
        'errors': []
    }
    if 'errors' in report:
        for error in report['errors']:
            tool['errors'].append(error.get('message', 'No error message provided.'))
    
    for result in report.get('results', []):
        severity = result.get('extra', {}).get('severity', 'N/A')
        message = result.get('extra', {}).get('message', 'No message provided.')
        path = result.get('path', 'N/A')
        line = result.get('start', {}).get('line', 'N/A')
        check_id = result.get('check_id', 'N/A')
        
        tool['results'].append({
            'check_id': check_id,
            'severity': severity,
            'message': message,
            'path': path,
            'line': line
        })
    return tool

# Function to process Bandit report
def process_bandit(report):
    tool = {
        'name': 'Bandit',
        'headers': ['Severity', 'Issue', 'File', 'Line'],
        'columns': ['issue_severity', 'issue_text', 'filename', 'line_number'],
        'results': [],
        'errors': []
    }
    for issue in report.get('results', []):
        severity = issue.get('issue_severity', 'N/A')
        issue_text = issue.get('issue_text', 'No issue text provided.')
        filename = issue.get('filename', 'N/A')
        line_number = issue.get('line_number', 'N/A')
        
        tool['results'].append({
            'issue_severity': severity,
            'issue_text': issue_text,
            'filename': filename,
            'line_number': line_number
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
        issue_type = issue.get('type', 'N/A')
        message = issue.get('message', 'No message provided.')
        module = issue.get('module', 'N/A')
        line = issue.get('line', 'N/A')
        
        tool['results'].append({
            'type': issue_type,
            'message': message,
            'module': module,
            'line': line
        })
    return tool

# Function to process Safety report
def process_safety(report):
    tool = {
        'name': 'Safety',
        'headers': ['Package', 'Vulnerability', 'Severity'],
        'columns': ['package_name', 'vulnerability', 'severity'],
        'results': [],
        'errors': []
    }
    for vuln in report.get('vulnerabilities', []):
        package_name = vuln.get('package_name', 'N/A')
        vulnerability = vuln.get('advisory', 'No advisory provided.')
        severity = vuln.get('severity', 'N/A')
        
        tool['results'].append({
            'package_name': package_name,
            'vulnerability': vulnerability,
            'severity': severity
        })
    return tool

def main():
    tools = []

    # Process Semgrep Report
    semgrep_path = os.path.join(REPORTS_DIR, 'semgrep-report.json')
    semgrep_report = load_json(semgrep_path)
    if semgrep_report:
        tools.append(process_semgrep(semgrep_report))
    
    # Process Bandit Report
    bandit_path = os.path.join(REPORTS_DIR, 'bandit-report.json')
    bandit_report = load_json(bandit_path)
    if bandit_report:
        tools.append(process_bandit(bandit_report))
    
    # Process Pylint Report
    pylint_path = os.path.join(REPORTS_DIR, 'pylint-report.json')
    pylint_report = load_json(pylint_path)
    if pylint_report:
        tools.append(process_pylint(pylint_report))
    
    # Process Safety Report
    safety_path = os.path.join(REPORTS_DIR, 'safety-report.json')
    safety_report = load_json(safety_path)
    if safety_report:
        tools.append(process_safety(safety_report))
    
    if not tools:
        print("No reports found to generate PDF.")
        return

    # Create HTML content for the PDF
    html_out = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Security Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { text-align: center; }
            h2 { color: #2F4F4F; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            th, td { border: 1px solid #dddddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            .ERROR { background-color: #f8d7da; }
            .WARNING { background-color: #fff3cd; }
            .info { background-color: #d1ecf1; }
        </style>
    </head>
    <body>
        <h1>🛡️ Security Scan Report</h1>
    """

    for tool in tools:
        html_out += f"<h2>{tool['name']} Report</h2>"
        
        # Display errors if any
        if tool['errors']:
            html_out += "<h3>Errors</h3><ul>"
            for error in tool['errors']:
                html_out += f"<li>{error}</li>"
            html_out += "</ul>"
        
        # Display results in a table
        if tool['results']:
            html_out += "<table>"
            html_out += "<thead><tr>"
            for header in tool['headers']:
                html_out += f"<th>{header}</th>"
            html_out += "</tr></thead><tbody>"
            
            for result in tool['results']:
                # Determine the row class based on severity for color coding
                severity = result.get('severity') or result.get('type') or 'info'
                row_class = severity.upper()
                html_out += f"<tr class='{row_class}'>"
                
                for column in tool['columns']:
                    cell = result.get(column, 'N/A')
                    html_out += f"<td>{cell}</td>"
                html_out += "</tr>"
            
            html_out += "</tbody></table>"
        else:
            html_out += f"<p>No issues found by {tool['name']}.</p>"
    
    html_out += """
    </body>
    </html>
    """

    # Output PDF file name
    pdf_file = os.path.join(OUTPUT_DIR, "Security_Scan_Report.pdf")

    try:
        # Generate PDF using pdfkit
        pdfkit.from_string(html_out, pdf_file)
        print(f"PDF report generated successfully: {pdf_file}")
    except Exception as e:
        print(f"An error occurred while generating the PDF: {e}")

if __name__ == '__main__':
    main()
