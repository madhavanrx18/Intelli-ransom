import requests
import time
import json
from fpdf import FPDF

# Your VirusTotal API key
API_KEY = 'enter your api key here'

# VirusTotal base URL for file analysis
BASE_URL = 'https://www.virustotal.com/api/v3/'

# Upload a file to VirusTotal for dynamic analysis
def submit_file(file_path):
    url = f"{BASE_URL}files"
    headers = {
        "x-apikey": API_KEY
    }
    
    # Open the file in binary mode
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(url, headers=headers, files=files)
    
    if response.status_code == 200:
        file_id = response.json().get('data', {}).get('id')
        print(f"File submitted successfully, ID: {file_id}")
        return file_id
    else:
        print(f"Error submitting file: {response.status_code}, {response.text}")
        return None

# Retrieve the analysis report
def get_analysis_report(file_id):
    url = f"{BASE_URL}analyses/{file_id}"
    headers = {
        "x-apikey": API_KEY
    }
    
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            analysis_status = response.json().get('data', {}).get('attributes', {}).get('status')
            if analysis_status == 'completed':
                print("Analysis completed!")
                return response.json()  # Return the complete analysis report
            else:
                print("Analysis in progress... waiting for completion.")
        else:
            print(f"Error retrieving report: {response.status_code}, {response.text}")
        
        time.sleep(30)  # Wait for 30 seconds before polling again

# Check for ransomware-related behaviors in the report
def check_ransomware_behaviors(report):
    ransomware_indicators = []

    if 'data' in report and 'attributes' in report['data']:
        attributes = report['data']['attributes']

        # 1. Check for file encryption activity in sandbox behavior
        if 'sandbox_verdicts' in attributes:
            for verdict in attributes['sandbox_verdicts']:
                if any(keyword in verdict['category'].lower() for keyword in ['encryption', 'ransomware']):
                    ransomware_indicators.append(f"Sandbox verdict: {verdict['category']}")

        # 2. Check for suspicious file modifications (e.g., ransom notes)
        if 'extracted_files' in attributes:
            for file in attributes['extracted_files']:
                if any(keyword in file['name'].lower() for keyword in ['readme', 'decrypt', 'ransom']):
                    ransomware_indicators.append(f"Potential ransom note found: {file['name']}")

        # 3. Check for suspicious network activity (e.g., communication with C2 servers)
        if 'network' in attributes:
            network_activity = attributes['network']
            # DNS requests
            if 'dns' in network_activity:
                for dns in network_activity['dns']:
                    if any(keyword in dns.get('hostname', '').lower() for keyword in ['ransom', 'c2']):
                        ransomware_indicators.append(f"Suspicious DNS activity: {dns['hostname']}")
            # HTTP requests
            if 'http' in network_activity:
                for http in network_activity['http']:
                    if 'ransom' in http.get('url', '').lower():
                        ransomware_indicators.append(f"Suspicious HTTP request: {http['url']}")

        # 4. Check for suspicious registry modifications
        if 'behavior' in attributes and 'registry_keys' in attributes['behavior']:
            for registry_change in attributes['behavior']['registry_keys']:
                if any(keyword in registry_change['key'].lower() for keyword in ['run', 'disable', 'no_recovery', 'no_backup']):
                    ransomware_indicators.append(f"Suspicious registry modification: {registry_change['key']}")

        # 5. Check for process injection and suspicious processes
        if 'processes' in attributes:
            for process in attributes['processes']:
                if 'inject' in process['name'].lower():
                    ransomware_indicators.append(f"Suspicious process injection found: {process['name']}")
                if 'cmd.exe' in process['name'].lower() or 'powershell.exe' in process['name'].lower():
                    ransomware_indicators.append(f"Suspicious process spawning: {process['name']}")

        # 6. Check for mass file renaming/deletion
        if 'file_actions' in attributes:
            for action in attributes['file_actions']:
                if 'rename' in action['action'].lower() or 'delete' in action['action'].lower():
                    ransomware_indicators.append(f"Mass file renaming/deletion detected: {action['path']}")

        # 7. Look for ransomware-related YARA rule matches
        if 'crowdsourced_yara_results' in attributes:
            for yara_rule in attributes['crowdsourced_yara_results']:
                if 'ransom' in yara_rule['rule_name'].lower():
                    ransomware_indicators.append(f"YARA rule matched: {yara_rule['rule_name']}")

        # 8. Check for encrypted file extensions
        if 'names' in attributes:
            for file_name in attributes['names']:
                if any(file_name.endswith(ext) for ext in ['.locked', '.crypt', '.enc', '.ransom']):
                    ransomware_indicators.append(f"File with ransomware extension found: {file_name}")

    return ransomware_indicators

# Generate styled PDF report
def generate_pdf_report(file_id, report, indicators):
    pdf = FPDF()
    pdf.add_page()

    # Subtitle for Ransomware Indicators
    pdf.set_text_color(0, 0, 0)  # Reset text color to black
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, "Ransomware Indicators:", ln=True)
    pdf.set_font("Arial", '', 12)
    
    if indicators:
        pdf.set_text_color(255, 0, 0)  # Red color for ransomware indicators
        for indicator in indicators:
            pdf.multi_cell(0, 10, indicator)
    else:
        pdf.set_text_color(0, 128, 0)  # Green color for no threats found
        pdf.cell(200, 10, "No ransomware-related behaviors found.", ln=True)

    # Full Report Parsing and Formatting
    pdf.add_page()
    pdf.set_text_color(0, 0, 0)  # Reset to black text for the rest of the report
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, "Full VirusTotal Report:", ln=True)
    pdf.set_font("Arial", '', 10)

    # Recursively format the JSON data for better readability
    def format_json_data(data, indent=0):
        for key, value in data.items():
            if isinstance(value, dict):
                pdf.set_font("Arial", 'B', 10)
                pdf.multi_cell(0, 10, "  " * indent + str(key) + ":")
                format_json_data(value, indent + 1)
            elif isinstance(value, list):
                pdf.set_font("Arial", 'B', 10)
                pdf.multi_cell(0, 10, "  " * indent + str(key) + ":")
                for item in value:
                    if isinstance(item, dict):
                        format_json_data(item, indent + 1)
                    else:
                        pdf.set_font("Arial", '', 10)
                        pdf.multi_cell(0, 10, "  " * (indent + 1) + str(item))
            else:
                pdf.set_font("Arial", '', 10)
                pdf.multi_cell(0, 10, "  " * indent + f"{key}: {value}")

    # Parse and format JSON report
    format_json_data(report['data'])

    # Save the PDF to a file
    pdf_output_path = f"virustotal_report_{file_id}.pdf"
    pdf.output(pdf_output_path)
    print(f"PDF report saved to: {pdf_output_path}")
    return pdf_output_path

# Example usage
if __name__ == "__main__":
    # Submit a file for analysis (replace 'sample_file.exe' with your file)
    file_path = r"D:\MediaCreationTool_22H2.exe"
    file_id = submit_file(file_path)

    if file_id:
        # Get the dynamic analysis report
        report = get_analysis_report(file_id)

        # Check for ransomware-related behaviors in the report
        if report:
            ransomware_indicators = check_ransomware_behaviors(report)

            # Generate a styled PDF report
            generate_pdf_report(file_id, report, ransomware_indicators)
