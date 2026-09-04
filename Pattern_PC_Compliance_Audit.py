#!/usr/bin/env python3

import getpass
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess

try:
    import grp
except ImportError:
    grp = None


def get_os():
    os_name = platform.system().lower()
    if os_name == "darwin":
        return "macOS"

    elif os_name == "linux":
        distro = "Unknown"
        try:
            if hasattr(platform, "freedesktop_os_release"):
                distro = platform.freedesktop_os_release().get("ID", "Unknown")
            else:
                with open("/etc/os-release", "r") as f:
                    for line in f:
                        if line.startswith("ID="):
                            distro = line.strip().split("=")[1].strip("'\"")
                            break
        except Exception:
            pass

        if distro == "arch":
            return "Arch"
        elif distro == "ubuntu":
            return "Ubuntu"
        else:
            return "Unknown"

    elif os_name == "windows":
        return "Windows"

    else:
        return "Unknown"


def macos():
    data = {
        "os_distro": "macOS",
        "auto_updates": "Yes",
        "unsupported_removed": "Yes",
    }

    try:
        data["os_version"] = subprocess.check_output(
            ["sw_vers", "-productVersion"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        data["os_version"] = "Unknown"

    try:
        raw_ioreg = subprocess.check_output(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        match = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', raw_ioreg)
        data["uuid"] = match.group(1) if match else "Unknown"
    except Exception:
        data["uuid"] = "Unknown"

    def get_app_version(app_path):
        plist_candidates = [
            Path(app_path) / "Contents" / "Info.plist",
            Path(app_path) / "Contents" / "Resources" / "Info.plist",
            Path(app_path) / "Resources" / "Info.plist",
            Path(app_path) / "Info.plist",
        ]
        for plist_path in plist_candidates:
            if plist_path.is_file():
                try:
                    with open(plist_path, "rb") as fp:
                        plist = plistlib.load(fp)
                        return plist.get("CFBundleShortVersionString") or plist.get(
                            "CFBundleVersion", "Unknown"
                        )
                except Exception:
                    return "Unknown"
        return None

    browser_paths = {
        "Chrome": "/Applications/Google Chrome.app",
        "Firefox": "/Applications/Firefox.app",
        "Safari": "/System/Applications/Safari.app",
        "Brave": "/Applications/Brave Browser.app",
    }
    found_browsers = []
    for name, path in browser_paths.items():
        version = get_app_version(path)
        if version:
            found_browsers.append(f"{name} {version}")
    data["browsers"] = ", ".join(found_browsers) if found_browsers else "None detected"

    found_email = []
    if Path("/System/Applications/Mail.app").exists():
        found_email.append(f"Apple Mail (macOS {data.get('os_version', 'Unknown')})")
    outlook_ver = get_app_version("/Applications/Microsoft Outlook.app")
    if outlook_ver:
        found_email.append(f"Outlook {outlook_ver}")
    data["email_apps"] = ", ".join(found_email) if found_email else "N/A (Web only)"

    found_office = []
    word_ver = get_app_version("/Applications/Microsoft Word.app")
    if word_ver:
        found_office.append(f"MS Word ({word_ver})")
    libre_ver = get_app_version("/Applications/LibreOffice.app")
    if libre_ver:
        found_office.append(f"LibreOffice ({libre_ver})")
    data["office_apps"] = ", ".join(found_office) if found_office else "N/A (Web only)"

    xp_ver = get_app_version("/Library/Apple/System/Library/CoreServices/XProtect.bundle")
    if not xp_ver or xp_ver == "Unknown":
        data["anti_virus"] = "macOS XProtect (Active)"
    else:
        data["anti_virus"] = f"macOS XProtect ({xp_ver})"

    chrome_ext = (
        Path.home()
        / "Library/Application Support/Google/Chrome/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal"
    )
    data["web_scanning"] = (
        "Yes (Bitdefender TrafficLight)"
        if chrome_ext.exists()
        else "No (Extension missing)"
    )

    try:
        fw_out = subprocess.check_output(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).lower()
        if "enabled" in fw_out:
            data["firewall"] = "Yes (Enabled)"
        elif "disabled" in fw_out:
            data["firewall"] = "No (Disabled)"
        else:
            data["firewall"] = "Unknown"
    except Exception:
        data["firewall"] = "Unknown"

    try:
        current_user = getpass.getuser()
        check = subprocess.run(
            ["dsmemberutil", "checkmembership", "-U", current_user, "-G", "admin"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        output = check.stdout.lower()
        if "is not a member" in output:
            data["admin_separated"] = "Yes"
        elif "is a member" in output:
            data["admin_separated"] = f"FAIL (User '{current_user}' has admin privileges)"
        else:
            data["admin_separated"] = "Manual check required"
    except Exception:
        data["admin_separated"] = "Manual check required"

    return data


def arch():
    data = {
        "os_distro": "Arch Linux",
        "auto_updates": "Yes",
        "unsupported_removed": "Yes",
    }

    data["os_version"] = f"Rolling ({platform.release()})"

    uuid_path = Path("/sys/class/dmi/id/product_uuid")
    serial_path = Path("/sys/class/dmi/id/product_serial")

    try:
        if uuid_path.is_file():
            data["uuid"] = uuid_path.read_text().strip()
        elif serial_path.is_file():
            data["uuid"] = serial_path.read_text().strip()
        else:
            data["uuid"] = "Unknown"
    except Exception:
        data["uuid"] = "Unknown"

    def get_bin_version(binary_name):
        path = shutil.which(binary_name)
        if not path:
            return None
        try:
            out = subprocess.check_output(
                [path, "--version"], text=True, stderr=subprocess.DEVNULL
            )
            match = re.search(r"(\d+(?:\.\d+)+)", out)
            return match.group(1) if match else "Installed"
        except Exception:
            try:
                pkg_out = subprocess.check_output(
                    ["pacman", "-Q", binary_name],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
                match = re.search(r"(\d+(?:\.\d+)+)", pkg_out)
                return match.group(1) if match else "Unknown"
            except Exception:
                return "Unknown"

    browser_targets = [
        ("Chrome", "google-chrome-stable"),
        ("Chrome", "google-chrome"),
        ("Chromium", "chromium"),
        ("Firefox", "firefox"),
        ("Brave", "brave-bin"),
        ("Brave", "brave"),
    ]

    found_browsers = []
    seen_browsers = set()

    for display_name, bin_name in browser_targets:
        if display_name in seen_browsers:
            continue
        ver = get_bin_version(bin_name)
        if ver:
            found_browsers.append(f"{display_name} {ver}")
            seen_browsers.add(display_name)

    data["browsers"] = (
        ", ".join(found_browsers) if found_browsers else "None detected"
    )

    found_emails = []
    tb_ver = get_bin_version("thunderbird")
    if tb_ver:
        found_emails.append(f"Thunderbird {tb_ver}")
    data["email_apps"] = (
        ", ".join(found_emails) if found_emails else "N/A (Web only)"
    )

    found_office = []
    lo_ver = get_bin_version("libreoffice")
    if lo_ver:
        found_office.append(f"LibreOffice {lo_ver}")
    data["office_apps"] = (
        ", ".join(found_office) if found_office else "N/A (Web only)"
    )

    clam_ver = get_bin_version("clamscan")
    if clam_ver:
        data["anti_virus"] = f"ClamAV {clam_ver}"
    elif Path("/opt/bitdefender-security-tools").exists():
        data["anti_virus"] = "Bitdefender Endpoint"
    else:
        data["anti_virus"] = "None"

    chrome_ext = (
        Path.home()
        / ".config/google-chrome/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal"
    )
    chromium_ext = (
        Path.home()
        / ".config/chromium/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal"
    )

    if chrome_ext.exists() or chromium_ext.exists():
        data["web_scanning"] = "Yes (Bitdefender TrafficLight)"
    else:
        data["web_scanning"] = "No (Extension missing)"

    try:
        res = subprocess.run(
            ["systemctl", "is-active", "ufw"],
            capture_output=True,
            text=True,
        )
        if "active" in res.stdout.strip().lower():
            data["firewall"] = "Yes (Enabled)"
        else:
            ufw_out = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
            )
            if "status: active" in ufw_out.stdout.lower():
                data["firewall"] = "Yes (Enabled)"
            else:
                data["firewall"] = "No (Disabled)"
    except Exception:
        data["firewall"] = "Unknown"

    try:
        current_user = getpass.getuser()
        if grp:
            user_groups = {grp.getgrgid(g).gr_name for g in os.getgroups()}
            if "wheel" in user_groups or "sudo" in user_groups:
                data["admin_separated"] = (
                    f"FAIL (User '{current_user}' has sudo/wheel privileges)"
                )
            else:
                data["admin_separated"] = "Yes"
        else:
            data["admin_separated"] = "Manual check required"
    except Exception:
        data["admin_separated"] = "Manual check required"

    return data


def ubuntu():
    data = {
        "os_distro": "Ubuntu",
        "auto_updates": "Yes",
        "unsupported_removed": "Yes",
    }

    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_ID="):
                    data["os_version"] = line.split("=")[1].strip().strip('"')
                    break
    except Exception:
        data["os_version"] = "Unknown"

    uuid_path = Path("/sys/class/dmi/id/product_uuid")
    serial_path = Path("/sys/class/dmi/id/product_serial")
    try:
        if uuid_path.is_file():
            data["uuid"] = uuid_path.read_text().strip()
        elif serial_path.is_file():
            data["uuid"] = serial_path.read_text().strip()
        else:
            data["uuid"] = "Unknown"
    except Exception:
        data["uuid"] = "Unknown"

    def get_bin_version(binary_name, pkg_name=None):
        if not pkg_name:
            pkg_name = binary_name
        path = shutil.which(binary_name)
        if path:
            try:
                out = subprocess.check_output(
                    [path, "--version"], text=True, stderr=subprocess.DEVNULL
                )
                match = re.search(r"(\d+(?:\.\d+)+)", out)
                if match:
                    return match.group(1)
            except Exception:
                pass
        try:
            pkg_out = subprocess.check_output(
                ["dpkg-query", "-W", "-f=${Version}", pkg_name],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            if pkg_out:
                return pkg_out.strip()
        except Exception:
            return None
        return None

    browser_targets = [
        ("Chrome", "google-chrome", "google-chrome-stable"),
        ("Chromium", "chromium-browser", "chromium-browser"),
        ("Firefox", "firefox", "firefox"),
        ("Brave", "brave", "brave-browser"),
    ]
    found_browsers = []
    for disp, bin_name, pkg in browser_targets:
        ver = get_bin_version(bin_name, pkg)
        if ver:
            found_browsers.append(f"{disp} {ver}")
    data["browsers"] = ", ".join(found_browsers) if found_browsers else "None detected"

    tb_ver = get_bin_version("thunderbird")
    data["email_apps"] = f"Thunderbird {tb_ver}" if tb_ver else "N/A (Web only)"

    lo_ver = get_bin_version("libreoffice", "libreoffice-core")
    data["office_apps"] = f"LibreOffice {lo_ver}" if lo_ver else "N/A (Web only)"

    clam_ver = get_bin_version("clamscan", "clamav")
    if clam_ver:
        data["anti_virus"] = f"ClamAV {clam_ver}"
    elif Path("/opt/bitdefender-security-tools").exists():
        data["anti_virus"] = "Bitdefender Endpoint"
    else:
        data["anti_virus"] = "None"

    chrome_ext = (
        Path.home()
        / ".config/google-chrome/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal"
    )
    chromium_ext = (
        Path.home()
        / ".config/chromium/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal"
    )
    if chrome_ext.exists() or chromium_ext.exists():
        data["web_scanning"] = "Yes (Bitdefender TrafficLight)"
    else:
        data["web_scanning"] = "No (Extension missing)"

    try:
        ufw_out = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        if "status: active" in ufw_out.stdout.lower():
            data["firewall"] = "Yes (Enabled)"
        else:
            data["firewall"] = "No (Disabled)"
    except Exception:
        data["firewall"] = "Unknown"

    try:
        current_user = getpass.getuser()
        if grp:
            user_groups = {grp.getgrgid(g).gr_name for g in os.getgroups()}
            if "sudo" in user_groups:
                data["admin_separated"] = (
                    f"FAIL (User '{current_user}' has sudo privileges)"
                )
            else:
                data["admin_separated"] = "Yes"
        else:
            data["admin_separated"] = "Manual check required"
    except Exception:
        data["admin_separated"] = "Manual check required"

    return data


def windows():
    data = {
        "os_distro": "Windows",
        "auto_updates": "Yes",
        "unsupported_removed": "Yes",
    }

    try:
        cmd_os = '(Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").DisplayVersion'
        ver = subprocess.check_output(
            ["powershell", "-Command", cmd_os],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        name_cmd = "(Get-CimInstance Win32_OperatingSystem).Caption"
        name = subprocess.check_output(
            ["powershell", "-Command", name_cmd],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        data["os_version"] = f"{name.replace('Microsoft ', '')} {ver}"
    except Exception:
        data["os_version"] = "Unknown"

    try:
        cmd_uuid = "(Get-CimInstance Win32_BIOS).SerialNumber"
        data["uuid"] = subprocess.check_output(
            ["powershell", "-Command", cmd_uuid],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        data["uuid"] = "Unknown"

    def get_ps_version(path):
        try:
            cmd = f'(Get-Item "{path}").VersionInfo.ProductVersion'
            return subprocess.check_output(
                ["powershell", "-Command", cmd],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            return None

    browser_paths = {
        "Chrome": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "Firefox": r"C:\Program Files\Mozilla Firefox\firefox.exe",
        "Brave": r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        "Edge": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    }
    found_browsers = []
    for name, path in browser_paths.items():
        if Path(path).exists():
            ver = get_ps_version(path)
            if ver:
                found_browsers.append(f"{name} {ver}")
    data["browsers"] = ", ".join(found_browsers) if found_browsers else "None detected"

    found_emails = []
    outlook_path = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
    if Path(outlook_path).exists():
        over = get_ps_version(outlook_path)
        found_emails.append(f"Outlook Build {over}")
    data["email_apps"] = ", ".join(found_emails) if found_emails else "N/A (Web only)"

    found_office = []
    word_path = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    if Path(word_path).exists():
        wover = get_ps_version(word_path)
        found_office.append(f"MS Word {wover}")
    data["office_apps"] = ", ".join(found_office) if found_office else "N/A (Web only)"

    try:
        cmd_av = "(Get-AppxPackage Microsoft.SecHealthUI).Version"
        av_ver = subprocess.check_output(
            ["powershell", "-Command", cmd_av],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        data["anti_virus"] = f"Windows Defender - {av_ver}"
    except Exception:
        data["anti_virus"] = "None"

    data["web_scanning"] = "Yes (Windows Defender SmartScreen)"

    try:
        cmd_fw = 'Get-NetFirewallProfile | Where-Object { $_.Enabled -eq "False" }'
        fw_out = subprocess.check_output(
            ["powershell", "-Command", cmd_fw],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        data["firewall"] = "No (Disabled)" if fw_out else "Yes (Enabled)"
    except Exception:
        data["firewall"] = "Unknown"

    try:
        current_user = getpass.getuser()
        cmd_admin = "[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object -ExpandProperty IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        is_admin = subprocess.check_output(
            ["powershell", "-Command", cmd_admin],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if "True" in is_admin:
            data["admin_separated"] = f"FAIL (User '{current_user}' has admin privileges)"
        else:
            data["admin_separated"] = "Yes"
    except Exception:
        data["admin_separated"] = "Manual check required"

    return data

def setup_firewall(system):
    print("\n[!] Firewall is disabled. Attempting automatic remediation...")
    if system in ["Arch", "Ubuntu"]:
        script_path = Path(__file__).parent / "setup_firewall.sh"
        if script_path.is_file():
            try:
                subprocess.run(["sudo", str(script_path)], check=True)
            except Exception as e:
                print(f"[!] Failed to run setup_firewall.sh: {e}")
        else:
            print(f"[!] {script_path} not found.")
    elif system == "macOS":
        print("[+] Enabling macOS Application Firewall...")
        try:
            subprocess.run(
                ["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"],
                check=True
            )
        except Exception as e:
            print(f"[!] Failed to enable macOS firewall: {e}")
    elif system == "Windows":
        print("[+] Enabling Windows Defender Firewall across all profiles...")
        try:
            subprocess.run(
                ["powershell", "-Command", "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"],
                check=True
            )
        except Exception as e:
            print(f"[!] Failed to enable Windows firewall: {e}")

def report(results, system):
    print("\n" + "=" * 65)
    print("           COMPLIANCE REPORT")
    print("=" * 65)

    # 1. Firewall Status
    fw_pass = "Yes" in results.get("firewall", "")
    print(f"[{'PASS' if fw_pass else 'FAIL'}] Firewall Protection: {results.get('firewall')}")

    # 2. Web Threat Filtering
    web_pass = "Yes" in results.get("web_scanning", "")
    print(f"[{'PASS' if web_pass else 'FAIL'}] Website Threat Scanning: {results.get('web_scanning')}")

    # 3. Privilege Separation
    admin_pass = results.get("admin_separated") == "Yes"
    print(f"[{'PASS' if admin_pass else 'FAIL'}] Admin Account Separation: {results.get('admin_separated')}")

    # 4. Anti-Virus
    av_pass = results.get("anti_virus") not in ["None", "Unknown"]
    print(f"[{'PASS' if av_pass else 'FAIL'}] Anti-Virus Software: {results.get('anti_virus')}")

    print("=" * 65)

    # Guidance for remaining manual items
    if not (fw_pass and web_pass and admin_pass and av_pass):
        print("\nACTION ITEMS REQUIRED TO COMPLETE COMPLIANCE:")

        if not fw_pass:
            print("\n• Firewall Setup (Step 4 in Laptop Policy):")
            if system == "macOS":
                print("  Go to System Settings > Network > Firewall, turn On, and set incoming to deny.")
            elif system == "Windows":
                print("  Open Settings (Win + I) > Privacy & security > Windows Security > Firewall & network protection.")
                print("  Turn On Domain, Private, and Public network profiles.")
            else:
                print("  Run: sudo ./setup_firewall.sh")
            print("  Note: If any inbound ports are opened, log them in 'Firewall Exceptions & Justifications'.")

        if not web_pass:
            print("\n• Website Scanning (Step 3 in Laptop Policy):")
            if system == "Windows":
                print("  Enable SmartScreen under Windows Security > App & browser control > Reputation-based protection.")
            else:
                print("  Install the Bitdefender TrafficLight Chrome extension:")
                print("  https://chromewebstore.google.com/detail/trafficlight/cfnpidifppmenkapgihekkeednfoenal")
                print("  Confirm it is active and shows 'This page is safe' with a green checkmark.")

        if not admin_pass:
            print("\n• Admin Account Separation (Step 5 in Laptop Policy):")
            if system == "Ubuntu":
                print("  1. Create a separate admin: sudo adduser <name>-admin && sudo adduser <name>-admin sudo")
                print("  2. Remove standard user:   sudo deluser <name> sudo")
                print("  (Or configure root password elevation via 'sudo visudo' with 'Defaults targetpw').")
            elif system == "Arch":
                print("  1. Create a separate admin: sudo useradd -m -G wheel <name>-admin && sudo passwd <name>-admin")
                print("  2. Remove standard user:   sudo gpasswd -d <name> wheel")
            elif system == "macOS":
                print("  1. System Settings > Users & Groups: Create a new Administrator account.")
                print("  2. Demote your daily account to 'Standard'. Disable automatic login.")
            elif system == "Windows":
                print("  1. Create a separate local identity (e.g., <name>-admin) and add to Administrators.")
                print("  2. Demote your daily account to Standard User.")

        if not av_pass:
            print("\n• Anti-Virus Missing:")
            print("  Install an active anti-malware package (e.g., ClamAV for Linux, Defender for Windows).")

    print("\nFINAL STEP:")
    print("Copy the raw compliance table values into your row on the IT Device Tracking Sheet.")
    print("Ensure your lock screen requires a PIN/password of at least 6 characters and locks on inactivity.")
    print("=" * 65 + "\n")

def main():
    system = get_os()
    print(f"Detected Platform: {system}\n")

    if system == "Arch":
        audit_fn = arch
    elif system == "macOS":
        audit_fn = macos
    elif system == "Ubuntu":
        audit_fn = ubuntu
    elif system == "Windows":
        audit_fn = windows
    else:
        print(f"Unsupported OS: {system}")
        return

    results = audit_fn()

    if "No" in results.get("firewall", ""):
        setup_firewall(system)
        results = audit_fn()

    print("=" * 65)
    print(f"RAW AUDIT DATA FOR TRACKER ({system})")
    print("=" * 65)
    for key, value in results.items():
        print(f"{key.ljust(24)}: {value}")
    print("=" * 65)

    report(results, system)

if __name__ == "__main__":
    main()
