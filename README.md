# Security Audit Report Generator for Windows

## Description
The **Security Audit Report Generator for Windows** is a Python-based tool designed to perform automated security audits on Windows servers. It evaluates various security configurations, detects insecure services, and generates detailed reports with recommendations for improvements. This tool is especially useful for system administrators, security consultants, and audit teams.

---
## Warning
This tool should only be used for authorized security audits. Unauthorized use may violate laws and regulations. Always obtain explicit permission before running this tool.

---
## Features
- **Firewall Analysis**:
  - Checks if the Windows Firewall is enabled and lists existing rules.
- **Service Analysis**:
  - Detects unnecessary or insecure services like Telnet or FTP.
- **RDP Security Checks**:
  - Verifies if Remote Desktop Protocol (RDP) is enabled and ensures Network Level Authentication (NLA) is configured.
- **Password Policy Checks**:
  - Evaluates password length, complexity, and lockout policies.
- **Windows Update Status**:
  - Checks for pending updates to ensure the system is up-to-date.
- **Disk Usage and Permissions**:
  - Reports disk usage and highlights potential issues with critical folder permissions.
- **SMB Protocol Configuration**:
  - Detects whether SMBv1 (an insecure protocol) is disabled.
- **Administrator Accounts**:
  - Lists all accounts in the Administrators group for review.
- **BitLocker Configuration**:
  - Verifies if BitLocker encryption is enabled for system drives.
- **Windows Defender Status**:
  - Checks if Windows Defender is enabled, real-time protection is active, and antivirus definitions are updated.
- **PowerShell Execution Policies**:
  - Ensures secure execution policies are in place to block unsigned scripts.
- **TLS/SSL Configuration**:
  - Verifies that secure versions of TLS (1.2 and 1.3) are enabled.
- **USB Restrictions**:
  - Ensures USB storage devices are restricted to prevent unauthorized access.
- **AppLocker Policies**:
  - Checks if AppLocker is configured to block unauthorized applications.

---

## Requirements
- Python 3.8 or higher
- Administrative privileges on the target system
- Install the required dependencies:
  ```bash
  pip install paramiko
  ```

---

## Usage
1. Clone this repository:
   ```bash
   git clone https://github.com/diegomessiah/security-audit-report-generator.git
   cd security-audit-report-generator
   ```

2. Run the script with administrative privileges:
   ```bash
   python security_audit_report_windows_baseline.py
   ```

3. The script will generate a detailed report in the current directory with a filename like:
   ```
   security_audit_report_windows_YYYYMMDD_HHMMSS.txt
   ```

---

## Example Report
```plaintext
Security Audit Report - 2025-04-13 22:30:14
==================================================
Firewall Configuration:
- Firewall is enabled for the following profiles:
 Name  Enabled
 ----- -------
 Domain   True
 Private  True
 Public   True

Running Services:
DisplayName                Status
-------------------------- -------
Windows Update             Running

RDP (Remote Desktop Protocol) Configuration:
- Warning: RDP is enabled. Disable it if not needed.
- Network Level Authentication (NLA) is enabled for RDP.

Password Policies:
- Minimum password length: 8
- Password complexity: Enabled

Windows Update Status:
- Pending updates:
Security Update KB5005565

Disk Usage and Permissions:
Name   UsedGB Free
C:      120   80

SMB Configuration:
- SMBv1 is disabled (good practice).

Administrators Group Members:
Administrator
JohnDoe
==================================================
```

---

## Customization
- **Adding Checks**: Extend the script to add more security checks as needed.
- **Integration**: Integrate the script with your CI/CD pipelines or monitoring tools for regular audits.

---

## License
This project is licensed under the [MIT License](LICENSE).

---

## Contributions
Contributions are welcome! Feel free to submit a pull request or open an issue to improve the script or add new features.

---

## Author
**Diego Messiah**
- GitHub: [diegomessiah](https://github.com/diegomessiah)
