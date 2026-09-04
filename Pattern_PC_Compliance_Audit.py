#!/usr/bin/env python3

import platform
import sys
import os
import plistlib
import subprocess
import getpass
import grp
from pathlib import Path
import re
import shutil

def get_os():
    os_name = platform.system().lower()
    if os_name == "darwin":
        return "macOS"

    elif os_name == "linux":
        distro = "Unknown"
        try:
            if hassattr(platform, "freedesktop_os_release"):
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
        "auto_updates": "Yes (Drata Enforced)",
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
        plist_path = Path(app_path) / "Contents" / "Info.plist"
        if plist_path.is_file():
            try:
                with open(plist_path, "rb") as fp:
                    plist = plistlib.load(fp)
                    return plist.get("CFBundleShortVersionString", "Unknown")
            except Exception:
                return "Unknown"
        return None

    browser_paths = {
        "Chrome": "/Applications/Google Chrome.app",
        "Firefox": "/Applications/Firefox.app",
        "Safari": "/System/Applications/Safari.app",
        "Brave": "/Applications/Brave Browser.app",
    ~ via 🐍 v3.14.7 
❯ ./Pattern_PC_Compliance_Audit.py
/home/alden/./Pattern_PC_Compliance_Audit.py:171: SyntaxWarning: 'str' object is not callable; perhaps you missed a comma?
  data["os_version"] = f"Rolling" ({platform.release()})
Traceback (most recent call last):
  File "/home/alden/./Pattern_PC_Compliance_Audit.py", line 187, in <module>
    arch()
    ~~~~^^
  File "/home/alden/./Pattern_PC_Compliance_Audit.py", line 171, in arch
    data["os_version"] = f"Rolling" ({platform.release()})
                         ~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^
TypeError: 'str' object is not callable}

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
        if "is a member" in check.stdout.lower():
            data["admin_separated"] = (
                f"FAIL (User \"{current_user}\" has admin privileges)"
            )
        else:
            data["admin_separated"] = "Yes"
    except Exception:
        data["admin_separated"] = "Manual check required"

    return data

def arch():
    data = {
            "os_distro": "Arch Linux",
            "auto_updates": "Yes (Drata Enforced)",
            "unsupported_removed": "Yes"
            }

    data["os_version"] = f"Rolling ({platform.release()})"

    uuid_path = Path("/sys/class/dmi/id/product_uuid")
    serial_path = Path("/sys/class/dmi/product_serial")

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
            out = subprocess.check.output(
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
            text=True
        )
        if "active" in res.stdout.strip().lower():
            data["firewall"] = "Yes (Enabled)"
        else:
            ufw_out = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True
            )
            if "status: active" in ufw_out.stdout.lower():
                data["firewall"] = "Yes (Enabled)"
            else:
                data["firewall"] = "No (Disabled)"
    except Exception:
        data["firewall"] = "Unknown"
