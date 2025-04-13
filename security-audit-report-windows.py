import os
import subprocess
from datetime import datetime

# Security Audit Report Generator for Windows
# Description: Generates a comprehensive security audit report for Windows servers.

class SecurityAuditWindows:
    def __init__(self):
        self.report = []

    def run_command(self, command):
        """Execute a PowerShell command and return its output."""
        try:
            result = subprocess.check_output(["powershell", "-Command", command], text=True)
            return result.strip()
        except subprocess.CalledProcessError as e:
            return f"Error executing command: {e}"

    def check_firewall(self):
        """Analyze firewall configurations."""
        self.report.append("Firewall Configuration:")
        firewall_status = self.run_command("Get-NetFirewallProfile | Select-Object Name, Enabled")
        if "True" in firewall_status:
            self.report.append("- Firewall is enabled for the following profiles:")
            self.report.append(firewall_status)
        else:
            self.report.append("- Warning: Firewall is disabled for all profiles. Enable it for better security.")

        self.report.append("\nFirewall Rules:")
        firewall_rules = self.run_command("Get-NetFirewallRule | Select-Object DisplayName, Direction, Action")
        self.report.append(firewall_rules if firewall_rules else "- No firewall rules found.")

    def check_services(self):
        """Detect unnecessary or insecure services."""
        self.report.append("\nRunning Services:")
        running_services = self.run_command("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object DisplayName, Status")
        self.report.append(running_services if running_services else "- No running services found.")

        insecure_services = ["Telnet", "FTP"]
        for service in insecure_services:
            status = self.run_command(f"Get-Service -Name {service} -ErrorAction SilentlyContinue | Select-Object Status")
            if "Running" in status:
                self.report.append(f"- Warning: {service} service is running. Consider disabling it.")

    def check_rdp_security(self):
        """Check RDP (Remote Desktop Protocol) security settings."""
        self.report.append("\nRDP (Remote Desktop Protocol) Configuration:")
        rdp_status = self.run_command("(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections")
        if rdp_status == "1":
            self.report.append("- RDP is disabled (good practice).")
        else:
            self.report.append("- Warning: RDP is enabled. Disable it if not needed.")

        nla_status = self.run_command("(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication")
        if nla_status == "1":
            self.report.append("- Network Level Authentication (NLA) is enabled for RDP.")
        else:
            self.report.append("- Warning: NLA is not enabled for RDP. Enable it for better security.")

    def check_password_policies(self):
        """Check password policies."""
        self.report.append("\nPassword Policies:")
        min_length = self.run_command("net accounts | findstr /C:\"Minimum password length\"")
        complexity = self.run_command("net accounts | findstr /C:\"Password complexity\"")
        self.report.append(f"- {min_length}")
        self.report.append(f"- {complexity}")

    def check_windows_updates(self):
        """Check for pending Windows updates."""
        self.report.append("\nWindows Update Status:")
        updates = self.run_command("Get-WindowsUpdate | Select-Object Title, KBArticle")
        if updates:
            self.report.append("- Pending updates:")
            self.report.append(updates)
        else:
            self.report.append("- The system is up to date.")

    def check_disk_usage(self):
        """Check disk usage and permissions."""
        self.report.append("\nDisk Usage and Permissions:")
        disk_usage = self.run_command("Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free, @{Name='UsedGB';Expression={[math]::Round($_.Used/1GB,2)}}")
        self.report.append(disk_usage if disk_usage else "- Could not retrieve disk usage information.")

    def check_smb_configuration(self):
        """Check SMB protocol settings."""
        self.report.append("\nSMB Configuration:")
        smb_status = self.run_command("Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
        if "Enabled" in smb_status:
            self.report.append("- Warning: SMBv1 is enabled. Consider disabling it as it is insecure.")
        else:
            self.report.append("- SMBv1 is disabled (good practice).")

    def check_admin_users(self):
        """List users in the Administrators group."""
        self.report.append("\nAdministrators Group Members:")
        admins = self.run_command("net localgroup Administrators")
        self.report.append(admins if admins else "- Could not retrieve administrators group members.")

    def generate_report(self):
        """Generate a detailed security audit report."""
        self.report.append(f"Security Audit Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.report.append("=" * 50)
        self.check_firewall()
        self.check_services()
        self.check_rdp_security()
        self.check_password_policies()
        self.check_windows_updates()
        self.check_disk_usage()
        self.check_smb_configuration()
        self.check_admin_users()
        self.report.append("=" * 50)

        # Save the report to a file
        report_path = f"security_audit_report_windows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_path, "w") as report_file:
            report_file.write("\n".join(self.report))

        print(f"Security audit report generated: {report_path}")


if __name__ == "__main__":
    print("Starting Security Audit on Windows...")
    audit = SecurityAuditWindows()
    audit.generate_report()
    print("Audit completed.")
