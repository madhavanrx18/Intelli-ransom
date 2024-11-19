## Architecture diagram
![image](https://github.com/user-attachments/assets/2c10aa82-0374-477b-a7b8-69089bd07768)
## Ransomware Analyzer GUI

This Python project provides a **Ransomware Analyzer GUI** using the `Tkinter` library. The tool enables users to perform **static and dynamic analysis** on suspicious files to detect potential ransomware.

### Features

- **File Selection:** Browse and select files for analysis.
- **Static Analysis:**
    - Calculate file hash (SHA-256) and check VirusTotal for detections.
    - Analyze PE headers for suspicious imports.
    - Extract suspicious strings using pattern matching.
    - Calculate file entropy to detect obfuscation.
    - Perform YARA-based ransomware signature detection.
- **Dynamic Analysis:**
    - Submit the file to VirusTotal for behavioral analysis.
    - Monitor suspicious behaviors such as encryption, shadow copy deletion, mutex creation, and network activity.
- **Progress Indicator:** Shows the progress of ongoing tasks.
- **PDF Report Generation:** Generates a detailed PDF report based on the analysis results.

### How It Works

1. Select a file using the **Browse** button.
2. Click **Run Static Analysis** to perform a detailed examination of the file's structure and characteristics.
3. Click **Run Dynamic Analysis** to submit the file to VirusTotal and analyze its behavior in a sandbox environment.
4. View the results in the GUI or save them as a PDF report.

### Dependencies

- `Tkinter` for the GUI
- `requests` for API communication
- `pefile` for PE header analysis
- `yara` for pattern matching
- `FPDF` for PDF report generation
- `hashlib`, `re`, `math`, `threading`, and other standard libraries

### Setup

1. Clone the repository.
2. Install the required dependencies:
    
    ```
    pip install pefile yara-python fpdf requests
    ```
    
3. Replace the placeholder `API_KEY` with your VirusTotal API key.
4. Run the script:
    
    ```
    python ransomware_analyzer.py
    ```
    

### Note

Ensure that you have a valid VirusTotal API key to perform dynamic analysis. API rate limits may apply.

This tool is intended for educational and research purposes only. Use responsibly.
