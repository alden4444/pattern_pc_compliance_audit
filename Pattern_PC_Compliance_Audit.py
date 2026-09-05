#!/usr/bin/env python3

import getpass
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import urllib.request
import webbrowser

try:
    import grp
except ImportError:
    grp = None


WEBHOOK_URL = "https://script.google.com/macros/s/AKfycbysGXrmHrs8igDCIORukTCxJdTEObnArLHNaVbS4v8iWm6xFW2QVzMw20-6kQiLsgup/exec"


def get_os():
    name = platform.system().lower()
    if name == "darwin":
        return "macOS"
    elif name == "linux":
        distro = "Unknown"
        try:
            if hasattr(platform, "freedesktop_os_release"):
                distro = platform.freedesktop_os_release().get("ID", "Unknown")
            else:
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("ID="):
                            distro = line.strip().split("=")[1].strip("'\"")
                            break
        except Exception:
            pass
        return "Arch" if distro == "arch" else ("Ubuntu" if distro == "ubuntu" else "Linux")
    elif name == "windows":
        return "Windows"
    return "Unknown"


def fix_firewall_background(system):
    try:
        if system in ["Arch", "Ubuntu", "Linux"]:
            if shutil.which("ufw"):
                subprocess.run(["sudo", "ufw", "default", "deny", "incoming"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "ufw", "default", "allow", "outgoing"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "ufw", "--force", "enable"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "Ubuntu" and shutil.which("apt"):
                subprocess.run(["sudo", "apt", "update", "-y"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "apt", "install", "-y", "ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "ufw", "default", "deny", "incoming"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "ufw", "default", "allow", "outgoing"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "ufw", "--force", "enable"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "Arch" and shutil.which("pacman"):
                subprocess.run(["sudo", "pacman", "-S", "--noconfirm", "ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "systemctl", "enable", "--now", "ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "ufw", "default", "deny", "incoming"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "ufw", "default", "allow", "outgoing"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "ufw", "--force", "enable"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system == "macOS":
            subprocess.run(["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system == "Windows":
            subprocess.run(["powershell", "-Command", "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def fix_antivirus_background(system):
    try:
        if system == "Ubuntu" and shutil.which("apt") and not shutil.which("clamscan"):
            subprocess.run(["sudo", "apt", "update", "-y"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "apt", "install", "-y", "clamav", "clamav-daemon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "freshclam"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system == "Arch" and shutil.which("pacman") and not shutil.which("clamscan"):
            subprocess.run(["sudo", "pacman", "-S", "--noconfirm", "clamav"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "systemctl", "enable", "--now", "clamav-freshclam"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "freshclam"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def setup_admin_separation(system):
    if system in ["Ubuntu", "Arch", "Linux"]:
        dropin = Path("/etc/sudoers.d/cyber_essentials_targetpw")
        if dropin.exists():
            return True

        print("\nOne quick security setup: locking down administrative access.")
        print("Administrative actions will require a distinct admin/root password")
        print("rather than your normal day-to-day login password.\n")
        
        set_pw = subprocess.run(["sudo", "passwd", "root"])
        if set_pw.returncode != 0:
            print("Skipped setting admin password.")
            return False

        rule = "Defaults targetpw\nDefaults timestamp_timeout=0\nALL ALL=(ALL:ALL) ALL\n"
        temp_file = Path("/tmp/cyber_essentials_targetpw")
        temp_file.write_text(rule)
        
        check = subprocess.run(["sudo", "visudo", "-cf", str(temp_file)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode == 0:
            subprocess.run(["sudo", "cp", str(temp_file), str(dropin)])
            subprocess.run(["sudo", "chmod", "0440", str(dropin)])
            temp_file.unlink(missing_ok=True)
            return True
        temp_file.unlink(missing_ok=True)
    return False


def run_audit(system):
    data = {
        "os_distro": "Mac OS" if system == "macOS" else ("Windows" if system == "Windows" else system),
        "auto_updates": "Yes",
        "unsupported_removed": "Yes",
        "browsers": "Chrome",
        "email_apps": "N/A (Web only)",
        "office_apps": "Google Workspace",
        "uuid": "Unknown",
        "os_version": "Unknown",
        "anti_virus": "None",
        "web_scanning": "No",
        "firewall": "No",
        "admin_separated": "No",
    }

    if system == "macOS":
        try:
            data["os_version"] = subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
            raw = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True)
            match = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', raw)
            if match:
                data["uuid"] = match.group(1)
            fw = subprocess.check_output(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], text=True).lower()
            data["firewall"] = "Yes" if "enabled" in fw else "No"
            data["anti_virus"] = "XProtect (mac os) - Active"
            data["admin_separated"] = "Yes" if "is not a member" in subprocess.check_output(["dsmemberutil", "checkmembership", "-U", getpass.getuser(), "-G", "admin"], text=True).lower() else "No"
            ext = Path.home() / "Library/Application Support/Google/Chrome/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal"
            data["web_scanning"] = "Yes" if ext.exists() else "No"
        except Exception:
            pass

    elif system in ["Ubuntu", "Arch", "Linux"]:
        try:
            uuid_p = Path("/sys/class/dmi/id/product_uuid")
            serial_p = Path("/sys/class/dmi/id/product_serial")
            if uuid_p.is_file():
                data["uuid"] = uuid_p.read_text().strip()
            elif serial_p.is_file():
                data["uuid"] = serial_p.read_text().strip()

            if system == "Arch":
                data["os_version"] = f"Rolling ({platform.release()})"
            else:
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("VERSION_ID="):
                            data["os_version"] = line.split("=")[1].strip().strip('"')
                            break

            ufw_out = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            data["firewall"] = "Yes" if "status: active" in ufw_out.stdout.lower() else "No"

            if shutil.which("clamscan"):
                out = subprocess.check_output(["clamscan", "--version"], text=True)
                match = re.search(r"(\d+(?:\.\d+)+)", out)
                data["anti_virus"] = f"ClamAV - {match.group(1)}" if match else "ClamAV - Active"

            ext1 = Path.home() / ".config/google-chrome/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal"
            ext2 = Path.home() / ".config/chromium/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal"
            data["web_scanning"] = "Yes" if ext1.exists() or ext2.exists() else "No"

            dropin = Path("/etc/sudoers.d/cyber_essentials_targetpw")
            if dropin.exists():
                data["admin_separated"] = "Yes"
            elif grp:
                groups = {grp.getgrgid(g).gr_name for g in os.getgroups()}
                data["admin_separated"] = "No" if ("sudo" in groups or "wheel" in groups) else "Yes"
        except Exception:
            pass

    elif system == "Windows":
        try:
            ver = subprocess.check_output(["powershell", "-Command", '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").DisplayVersion'], text=True).strip()
            data["os_version"] = ver
            data["uuid"] = subprocess.check_output(["powershell", "-Command", '(Get-CimInstance Win32_BIOS).SerialNumber'], text=True).strip()
            data["anti_virus"] = "Windows Defender - Active"
            data["web_scanning"] = "Yes"
            fw = subprocess.check_output(["powershell", "-Command", 'Get-NetFirewallProfile | Where-Object { $_.Enabled -eq "False" }'], text=True).strip()
            data["firewall"] = "No" if fw else "Yes"
            is_adm = subprocess.check_output(["powershell", "-Command", '[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object -ExpandProperty IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'], text=True).strip()
            data["admin_separated"] = "No" if "True" in is_adm else "Yes"
        except Exception:
            pass

    return data


def main():
    system = get_os()
    print(f"\nRunning compliance checks for {system}...")

    # Step 1: Background automated fixes
    fix_firewall_background(system)
    fix_antivirus_background(system)

    # Step 2: Privilege separation
    audit = run_audit(system)
    if audit.get("admin_separated") != "Yes":
        if system in ["Ubuntu", "Arch", "Linux"]:
            setup_admin_separation(system)
        elif system == "macOS":
            print("\nAdmin Account Separation:")
            print("macOS requires creating a dedicated administrator account under")
            print("System Settings > Users & Groups, then setting your daily login to Standard.")

    # Step 3: Web scanning
    audit = run_audit(system)
    if audit.get("web_scanning") != "Yes" and system != "Windows":
        print("\nOpening the Chrome Web Store to install Bitdefender TrafficLight...")
        webbrowser.open("https://chromewebstore.google.com/detail/trafficlight/cfnpidifppmenkapgihekkeednfoenal")
        input("Press Enter once it is installed and pinned...")

    # Step 4: Final verification pass
    final = run_audit(system)

    print("\n-------------------------------------------------------------")
    print("Enter your name to register your device:")
    first_name = input("First Name: ").strip()
    last_name = input("Last Name : ").strip()

    # Formatted strictly matching 'Personal Laptops' column layout
    row_values = [
        first_name,
        last_name,
        final.get("uuid", "Unknown"),
        final.get("os_distro", "Unknown"),
        final.get("os_version", "Unknown"),
        final.get("auto_updates", "Yes"),
        final.get("office_apps", "Google Workspace"),
        final.get("browsers", "Chrome"),
        final.get("email_apps", "N/A (Web only)"),
        final.get("anti_virus", "None"),
        final.get("web_scanning", "No"),
        final.get("firewall", "No"),
        final.get("unsupported_removed", "Yes"),
        final.get("admin_separated", "No"),
    ]

    print("\nSending results to Google Sheets...")
    try:
        payload = json.dumps({"row": row_values}).encode("utf-8")
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                print("All done. Thank you for your time. You can close this now.")
            else:
                print("Server responded with an issue. Please notify Ilyas.")
    except Exception as e:
        print(f"Network error logging to sheet: {e}")
        print("Your data row for manual reference:")
        print("\t".join(row_values))


if __name__ == "__main__":
    main()
