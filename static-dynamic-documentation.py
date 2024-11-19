import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import pefile
import re
import math
import requests
import yara
import time
import json
from fpdf import FPDF
import threading
import os

# VirusTotal API key (replace with your actual key)
API_KEY = 'dddb032813a57d0742adf6d7f471c197759ec83a2bfd7a9e143e3ecf3da023f4'

# VirusTotal base URL for file analysis
BASE_URL = 'https://www.virustotal.com/api/v3/'

class RansomwareAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Ransomware Analyzer")
        master.geometry("600x400")

        self.file_path = tk.StringVar()

        # Centered File selection
        file_frame = tk.Frame(master)
        file_frame.pack(pady=10)

        tk.Label(file_frame, text="Select file to analyze:").pack()
        file_entry_frame = tk.Frame(file_frame)
        file_entry_frame.pack()

        tk.Entry(file_entry_frame, textvariable=self.file_path, width=50).pack(side=tk.LEFT, padx=10)
        tk.Button(file_entry_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT)

        # Analysis buttons centered below file selection
        button_frame = tk.Frame(master)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Run Static Analysis", command=self.run_static_analysis).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Run Dynamic Analysis", command=self.run_dynamic_analysis).pack(side=tk.LEFT, padx=5)

        # Results display
        self.result_text = tk.Text(master, height=10, width=70)
        self.result_text.pack(pady=10)

        # Progress bar
        self.progress = ttk.Progressbar(master, length=400, mode='indeterminate')
        self.progress.pack(pady=10)

        # View report button at the bottom
        self.view_report_button = tk.Button(master, text="View Full Report", command=self.view_report, state=tk.DISABLED)
        self.view_report_button.pack(pady=10)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        self.file_path.set(filename)

    def run_static_analysis(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file first.")
            return

        self.progress.start()
        threading.Thread(target=self._run_static_analysis, daemon=True).start()

    def _run_static_analysis(self):
        try:
            result = ransomware_static_analysis(self.file_path.get())
            self.master.after(0, self._update_result, result)
        finally:
            self.master.after(0, self.progress.stop)

    def run_dynamic_analysis(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file first.")
            return

        self.progress.start()
        threading.Thread(target=self._run_dynamic_analysis, daemon=True).start()

    def _run_dynamic_analysis(self):
        try:
            file_id = submit_file(self.file_path.get())
            if file_id:
                report = get_analysis_report(file_id)
                if report:
                    ransomware_indicators = check_ransomware_behaviors(report)
                    result = "Dynamic analysis completed"
                    pdf_path = generate_pdf_report(file_id, report, ransomware_indicators)
                    self.master.after(0, self._update_result, result)
                    self.master.after(0, self.view_report_button.config, {'state': tk.NORMAL})
                else:
                    self.master.after(0, self._update_result, "Failed to retrieve analysis report.")
            else:
                self.master.after(0, self._update_result, "Failed to submit file for analysis.")
        finally:
            self.master.after(0, self.progress.stop)

    def _update_result(self, result):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)

    def view_report(self):
        report_file = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if report_file:
            os.startfile(report_file)

# Static Analysis Functions
def compute_hash(file_path, algorithm='sha256'):
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def check_file_format(file_path):
    with open(file_path, 'rb') as file:
        magic_number = file.read(2)
    return magic_number == b'MZ'

def check_hash_virustotal(file_hash):
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response.get('positives', 0) > 0:
            return f"VirusTotal Detection: {json_response['positives']}/{json_response['total']} engines detected malware."
        else:
            return "VirusTotal: No malware detected."
    elif response.status_code == 403:
        return "Error querying VirusTotal: Forbidden (403). Possible reasons: Invalid API key or rate limit exceeded."
    else:
        return f"Error querying VirusTotal: {response.status_code}"

def pe_header_analysis(file_path):
    if check_file_format(file_path):
        try:
            pe = pefile.PE(file_path)
            suspicious_imports = [
    "IMAGE_DOS_HEADER", "IMAGE_NT_HEADERS", "IMAGE_FILE_EXECUTABLE_IMAGE", 
    "IMAGE_FILE_DLL", "IMAGE_FILE_RELOCS_STRIPPED", "IMAGE_FILE_MACHINE_I386", 
    "IMAGE_FILE_MACHINE_AMD64", "IMAGE_OPTIONAL_HEADER", 
    "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", 
    "IMAGE_DIRECTORY_ENTRY_SECURITY", "IMAGE_SECTION_HEADER", 
    ".text", ".data", ".rdata", ".bss", ".rsrc", 
    ".reloc", "BaseOfCode", "BaseOfData", "EntryPoint", 
    "VirtualSize", "Characteristics", "Subsystem", 
    "DllCharacteristics", "Magic", "MajorSubsystemVersion", 
    "MinorSubsystemVersion", "SizeOfImage", "CheckSum", 
    "SizeOfHeaders", "Import Address Table", "Export Table", 
    "Resource Table", "Exception Table", "TLS Table", 
    "IMAGE_FILE_MACHINE_ARM", "IMAGE_FILE_MACHINE_ARM64", 
    "IMAGE_SCN_CNT_CODE", "IMAGE_SCN_CNT_INITIALIZED_DATA", 
    "IMAGE_SCN_CNT_UNINITIALIZED_DATA", "IMAGE_SCN_MEM_EXECUTE", 
    "IMAGE_SCN_MEM_READ", "IMAGE_SCN_MEM_WRITE"
]
            detected_imports = [imp.name.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports if imp.name and imp.name.decode() in suspicious_imports]
            return f"Suspicious API calls found: {', '.join(detected_imports)}" if detected_imports else "No suspicious API calls detected."
        except Exception as e:
            return f"Error inspecting PE headers: {e}"
    else:
        return "File is not a valid PE file. Skipping PE header analysis."

def extract_strings(file_path, min_length=4):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        
        ascii_strings = re.findall(rb'[\x20-\x7E]{%d,}' % min_length, data)
        unicode_strings = re.findall(rb'(?:[\x20-\x7E][\x00]){%d,}' % min_length, data)
        
        all_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings] + \
                      [s.decode('utf-16', errors='ignore') for s in unicode_strings]
        
        suspicious_indicators = [
    "ransom", "decrypt", "encrypt", "bitcoin", "wallet", "payment", 
    "AES", "RSA", "DES", "key", "locked", "pay", "restore", 
    "private key", "public key", "command and control", "decryptor", 
    "shadow", "backup", "readme", "help", "instructions", 
    "WannaCry", "Cerber", "Locky", "Ryuk", "CryptoLocker", 
    "GandCrab", "Sodinokibi", "TeslaCrypt", "STOP Djvu"
]
        detected_suspicious_strings = [s for s in all_strings if any(indicator in s.lower() for indicator in suspicious_indicators)]
        
        return f"Suspicious strings found: {', '.join(detected_suspicious_strings[:10])}" if detected_suspicious_strings else "No suspicious strings found."
    except Exception as e:
        return f"Error extracting strings: {e}"

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy

def file_entropy(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        entropy = calculate_entropy(data)
        return f"File entropy: {entropy:.2f}"
    except Exception as e:
        return f"Error calculating entropy: {e}"

def yara_scan(file_path):
    try:
        rules = yara.compile(source="""
        rule Ransomware_Family_Detection {
    meta:
        description = "Detects multiple ransomware families: WannaCry, Locky, CryptoLocker, REvil, Ryuk"
        author = "YARA rule example"
        date = "2024-10-20"
        version = "1.0"
        
    strings:
        // WannaCry
        $wannacry_1 = "WannaDecryptor" wide
        $wannacry_2 = "WannaCry" wide
        $wannacry_3 = "WNcry@2ol7" wide

        // Locky
        $locky_ext = ".locky" nocase
        $locky_str = "the installation of software must be authorized by the administrator"

        // CryptoLocker
        $cryptolocker_note = "Your personal files are encrypted!"
        $cryptolocker_name = "CryptoLocker" nocase
        $cryptolocker_rsa = "BEGIN PUBLIC KEY" ascii

        // REvil/Sodinokibi
        $revil_ext = ".sodinokibi" nocase
        $revil_msg = "REvil"
        $revil_key = "-----BEGIN REvil PRIVATE KEY-----" ascii

        // Ryuk
        $ryuk_note = "RyukReadMe" wide
        $ryuk_str1 = "Ryuk" wide
        $ryuk_key = "-----BEGIN PRIVATE KEY-----"

    condition:
        (uint16(0) == 0x5A4D) and // PE file
        filesize < 10MB and (
            // WannaCry conditions
            all of ($wannacry_*) or
            // Locky conditions
            ($locky_ext or $locky_str) or
            // CryptoLocker conditions
            ($cryptolocker_note or $cryptolocker_name or $cryptolocker_rsa) or
            // REvil conditions
            ($revil_ext or $revil_msg or $revil_key) or
            // Ryuk conditions
            ($ryuk_note or $ryuk_str1 or $ryuk_key)
        )
}
        """)
        matches = rules.match(file_path)
        return f"YARA detected potential ransomware: {', '.join(match.rule for match in matches)}" if matches else "No ransomware patterns detected by YARA."
    except Exception as e:
        return f"Error in YARA scanning: {e}"

def ransomware_static_analysis(file_path):
    results = []
    results.append(f"File Hash (SHA-256): {compute_hash(file_path)}")
    results.append(check_hash_virustotal(compute_hash(file_path)))
    results.append(pe_header_analysis(file_path))
    results.append(extract_strings(file_path))
    results.append(file_entropy(file_path))
    results.append(yara_scan(file_path))
    
    return "\n".join(results)

# Dynamic Analysis Functions
def submit_file(file_path):
    url = f"{BASE_URL}files"
    headers = {"x-apikey": API_KEY}
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json().get('data', {}).get('id')
    else:
        return None

def get_analysis_report(file_id):
    url = f"{BASE_URL}analyses/{file_id}"
    headers = {"x-apikey": API_KEY}
    for _ in range(10):  # Try for 5 minutes (10 * 30 seconds)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            analysis_status = response.json().get('data', {}).get('attributes', {}).get('status')
            if analysis_status == 'completed':
                return response.json()
        time.sleep(30)
    return None

def check_ransomware_behaviors(report):
    ransomware_indicators = []
    
    if 'data' in report and 'attributes' in report['data']:
        attributes = report['data']['attributes']

        # Check for sandbox verdicts related to ransomware behavior
        if 'sandbox_verdicts' in attributes:
            for verdict in attributes['sandbox_verdicts'].values():
                # Look for additional categories related to ransomware
                if any(word in verdict.get('category', '').lower() for word in ['ransomware', 'file encryptor', 'filecoder', 'cryptolocker', 'locky']):
                    ransomware_indicators.append(f"Sandbox verdict: {verdict['category']} - {verdict['description']}")
                # Also look for malicious behavior tags in sandbox verdicts
                if 'tags' in verdict and any(tag in verdict['tags'] for tag in ['ransom', 'extortion', 'encrypt', 'crypt', 'crypto']):
                    ransomware_indicators.append(f"Malicious sandbox behavior tag: {verdict['tags']}")
                    
      
        #check for suspicous memory usage
        if 'memory_usage' in attributes:
            for process in attributes['memory_usage']:
                # Check for high memory usage (above a defined threshold)
                if process['usage'] > 100000000:  # Example threshold of 100MB
                    ransomware_indicators.append(f"Suspiciously high memory usage by: {process['name']} ({process['usage']} bytes)")

                # Check for memory injection into other processes
                if 'injected_into' in process:
                    ransomware_indicators.append(f"Memory injection detected: {process['name']} into {process['injected_into']}")

                # Check for suspicious memory protection flags (e.g., indicating code execution)
                if 'protection_flags' in process:
                    if any(flag in process['protection_flags'].lower() for flag in ['execute_readwrite', 'execute']):
                        ransomware_indicators.append(f"Suspicious memory protection flags: {process['protection_flags']} in {process['name']}")

        #check for mutex
        
        if 'mutexes' in attributes:
            for mutex in attributes['mutexes']:
                # Check for mutexes containing suspicious keywords
                if any(keyword in mutex['name'].lower() for keyword in ['lock', 'crypt', 'ransom', 'sync']):
                    ransomware_indicators.append(f"Suspicious mutex detected: {mutex['name']}")

                # Detect known ransomware-related mutex patterns (e.g., mutexes created to prevent multiple instances)
                if re.search(r'ransomware_\d+', mutex['name'].lower()):
                    ransomware_indicators.append(f"Known ransomware mutex pattern: {mutex['name']}")

                # Check for mutexes created by critical system processes to ensure ransomware is active
                if 'critical_process' in mutex.get('owner', '').lower():
                    ransomware_indicators.append(f"Mutex owned by critical process: {mutex['owner']}")

        # Check for potential ransom notes in dropped files
        if 'files' in attributes:
            for file in attributes['files']:
                if any(keyword in file['name'].lower() for keyword in ['readme', 'decrypt', 'ransom', 'help', 'instructions']):
                    ransomware_indicators.append(f"Potential ransom note found: {file['name']}")
                # Additional suspicious file extensions for encrypted files
                if file['name'].lower().endswith(('.locked', '.encrypted', '.enc', '.crypt', '.cry', '.aes', '.id-', '.pay', '.dark')):
                    ransomware_indicators.append(f"Suspicious file extension: {file['name']}")
                # Check for specific patterns in ransom note filenames
                if any(pattern in file['name'].lower() for pattern in ['!readme!', 'help', '-decrypt-', 'restore_files']):
                    ransomware_indicators.append(f"Ransom note pattern detected: {file['name']}")
                # File extension checks for ransomware-encrypted files
                if file['name'].lower().endswith(('.crypted', '.crypted1', '.crypted2', '.locky', '.tesla', '.cerber', '.zepto', '.mamba', '.gandcrab', '.stop', '.djvu')):
                    ransomware_indicators.append(f"Known ransomware file extension: {file['name']}")

        # Check for registry modifications indicating persistence or disabling security
        if 'registry_keys' in attributes:
            for key in attributes['registry_keys']:
                if any(keyword in key['path'].lower() for keyword in ['run', 'autorun', 'disable', 'backup', 'restore', 'security', 'safe', 'antivirus']):
                    ransomware_indicators.append(f"Suspicious registry key modification: {key['path']}")
                # Additional checks for ransomware targeting specific registry locations
                if any(specific_key in key['path'].lower() for specific_key in ['microsoft\\windows\\currentversion\\run', 'runonce', 'runservices']):
                    ransomware_indicators.append(f"Possible ransomware persistence mechanism: {key['path']}")

        # Check for network activity related to command and control (C2) servers
        if 'network_activity' in attributes:
            for activity in attributes['network_activity']:
                if any(keyword in activity['domain'].lower() for keyword in ['.onion', 'tor', 'darkweb', 'c2', 'ransom', 'decrypt']):
                    ransomware_indicators.append(f"Suspicious network activity: {activity['domain']}")
                # Check for suspicious IP ranges or protocols (often used in ransomware)
                if any(ip in activity['ip_address'] for ip in ['10.', '192.168.', '172.']):
                    ransomware_indicators.append(f"Internal network IPs used in suspicious activity: {activity['ip_address']}")
                if 'protocol' in activity and activity['protocol'].lower() in ['ftp', 'smb', 'rdp']:
                    ransomware_indicators.append(f"Suspicious protocol usage: {activity['protocol']} - {activity['ip_address']}")

        # Check for deletion of shadow copies or backup services
        if 'processes' in attributes:
            for process in attributes['processes']:
                if any(command in process['command_line'].lower() for command in ['vssadmin', 'delete', 'shadow', 'wbadmin']):
                    ransomware_indicators.append(f"Potential shadow copy deletion command: {process['command_line']}")
                # Additional processes and commands typically used in ransomware
                if any(command in process['command_line'].lower() for command in ['bcdedit', 'disable', 'safeboot', 'schtasks', 'taskkill']):
                    ransomware_indicators.append(f"Suspicious command for disabling services or scheduled tasks: {process['command_line']}")
                # Look for process names commonly associated with ransomware
                if any(process_name in process['name'].lower() for process_name in ['rundll32.exe', 'powershell.exe', 'wscript.exe']):
                    ransomware_indicators.append(f"Potential malicious process: {process['name']}")

    return ransomware_indicators


def generate_pdf_report(file_id, report, indicators):
    pdf = FPDF()
    pdf.add_page()

    # Subtitle for Ransomware Indicators
    pdf.set_text_color(0, 0, 0)  # Reset text color to black
    pdf.set_font("Arial", 'B', 12)
    pdf.set_font("Arial", '', 12)

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
if __name__ == "__main__":
    root = tk.Tk()
    app = RansomwareAnalyzerGUI(root)
    root.mainloop()
