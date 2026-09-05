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

try:
    import pwd
except ImportError:
    pwd = None


WEBHOOK_URL = "https://script.google.com/macros/s/AKfycbysGXrmHrs8igDCIORukTCxJdTEObnArLHNaVbS4v8iWm6xFW2QVzMw20-6kQiLsgup/exec"


def get_real_home():
    """
    Return the invoking user's home directory, even when run under sudo.
    Falls back to Path.home() if we can't resolve a real user.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and pwd:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    home_env = os.environ.get("HOME")
    if home_env and sudo_user:
        return Path(home_env)
    return Path.home()


def open_url_safely(url):
    """
    Open URLs under the original desktop user context to avoid root sandbox errors.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and shutil.which("su"):
        try:
            subprocess.Popen(
                ["su", "-", sudo_user, "-c", f"xdg-open '{url}'"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return
        except Exception:
            pass
    webbrowser.open(url)


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


def _run(cmd, timeout=45, env=None):
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


_APT_NONINTERACTIVE = ["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"]


def disable_competing_linux_firewalls():
    if shutil.which("firewall-cmd") or shutil.which("firewalld"):
        _run(["sudo", "systemctl", "stop", "firewalld"], timeout=30)
        _run(["sudo", "systemctl", "disable", "firewalld"], timeout=30)
        _run(["sudo", "systemctl", "mask", "firewalld"], timeout=30)


def allow_ssh_before_enabling_ufw():
    _run(["sudo", "ufw", "allow", "OpenSSH"], timeout=30)
    _run(["sudo", "ufw", "allow", "22/tcp"], timeout=30)


def ufw_is_correctly_configured():
    if not shutil.which("ufw"):
        return False
    try:
        out = subprocess.check_output(
            ["sudo", "ufw", "status", "verbose"], text=True, stderr=subprocess.DEVNULL, timeout=30
        ).lower()
    except Exception:
        return False
    return (
        "status: active" in out
        and "deny (incoming)" in out
        and "allow (outgoing)" in out
    )


def fix_firewall_background(system):
    try:
        if system in ["Arch", "Ubuntu", "Linux"]:
            disable_competing_linux_firewalls()

            if not shutil.which("ufw"):
                if system == "Ubuntu" and shutil.which("apt"):
                    _run(_APT_NONINTERACTIVE + ["apt", "update", "-y"], timeout=120)
                    _run(_APT_NONINTERACTIVE + ["apt", "install", "-y", "ufw"], timeout=120)
                elif system == "Arch" and shutil.which("pacman"):
                    _run(["sudo", "pacman", "-S", "--noconfirm", "ufw"], timeout=120)
                    _run(["sudo", "systemctl", "enable", "ufw"], timeout=30)

            if shutil.which("ufw") and not ufw_is_correctly_configured():
                allow_ssh_before_enabling_ufw()
                _run(["sudo", "ufw", "default", "deny", "incoming"], timeout=30)
                _run(["sudo", "ufw", "default", "allow", "outgoing"], timeout=30)
                _run(["sudo", "ufw", "--force", "enable"], timeout=30)
        elif system == "macOS":
            _run(["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"], timeout=30)
        elif system == "Windows":
            _run(["powershell", "-Command", "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"], timeout=30)
    except Exception:
        pass


def fix_antivirus_background(system):
    try:
        if system == "Ubuntu" and shutil.which("apt") and not shutil.which("clamscan"):
            _run(_APT_NONINTERACTIVE + ["apt", "update", "-y"], timeout=120)
            _run(_APT_NONINTERACTIVE + ["apt", "install", "-y", "clamav", "clamav-daemon"], timeout=180)
            _run(["sudo", "freshclam"], timeout=60)
        elif system == "Arch" and shutil.which("pacman") and not shutil.which("clamscan"):
            _run(["sudo", "pacman", "-S", "--noconfirm", "clamav"], timeout=120)
            _run(["sudo", "systemctl", "enable", "--now", "clamav-freshclam"], timeout=30)
            _run(["sudo", "freshclam"], timeout=60)
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

        rule = "Defaults targetpw\nDefaults timestamp_timeout=0\n%sudo ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) ALL\n"
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


def get_linux_bin_version(binary_name):
    path = shutil.which(binary_name)
    if path:
        try:
            out = subprocess.check_output([path, "--version"], text=True, stderr=subprocess.DEVNULL)
            match = re.search(r"(\d+(?:\.\d+)+)", out)
            if match:
                return match.group(1)
        except Exception:
            pass
    return None


def find_firefox_profile_dirs(home):
    profile_dirs = []
    candidates = [
        home / ".mozilla/firefox",
        home / "Library/Application Support/Firefox",
        home / "AppData/Roaming/Mozilla/Firefox",
    ]
    for base in candidates:
        ini_path = base / "profiles.ini"
        if not ini_path.is_file():
            continue
        try:
            current_path = None
            is_relative = True
            for line in ini_path.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("Path="):
                    current_path = line.split("=", 1)[1]
                elif line.startswith("IsRelative="):
                    is_relative = line.split("=", 1)[1] == "1"
                elif line.startswith("[") and current_path:
                    p = (base / current_path) if is_relative else Path(current_path)
                    if p.is_dir():
                        profile_dirs.append(p)
                    current_path = None
                    is_relative = True
            if current_path:
                p = (base / current_path) if is_relative else Path(current_path)
                if p.is_dir():
                    profile_dirs.append(p)
        except Exception:
            continue
    return profile_dirs


def firefox_has_trafficlight(home):
    for profile_dir in find_firefox_profile_dirs(home):
        ext_json = profile_dir / "extensions.json"
        if not ext_json.is_file():
            continue
        try:
            data = json.loads(ext_json.read_text(errors="ignore"))
        except Exception:
            continue
        for addon in data.get("addons", []):
            blob = json.dumps(addon).lower()
            if "trafficlight" in blob and "bitdefender" in blob:
                return True
    return False


def run_audit(system):
    home = get_real_home()

    data = {
        "os_distro": "Mac OS" if system == "macOS" else ("Windows" if system == "Windows" else system),
        "auto_updates": "Yes",
        "unsupported_removed": "Yes",
        "browsers": "None detected",
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
            
            check_user = os.environ.get("SUDO_USER") or getpass.getuser()
            check = subprocess.run(["dsmemberutil", "checkmembership", "-U", check_user, "-G", "admin"], capture_output=True, text=True)
            data["admin_separated"] = "Yes" if "is not a member" in check.stdout.lower() else "No"

            chrome_ext_found = any(home.glob("Library/Application Support/Google/Chrome/*/Extensions/cfnpidifppmenkapgihekkeednfoenal"))
            ff_found = firefox_has_trafficlight(home)
            data["web_scanning"] = "Yes" if (chrome_ext_found or ff_found) else "No"
        except Exception:
            pass

    elif system in ["Ubuntu", "Arch", "Linux"]:
        try:
            uuid_proc = subprocess.run(["sudo", "cat", "/sys/class/dmi/id/product_uuid"], capture_output=True, text=True, timeout=3)
            val = uuid_proc.stdout.strip()
            if not val or "denied" in val.lower():
                serial_proc = subprocess.run(["sudo", "cat", "/sys/class/dmi/id/product_serial"], capture_output=True, text=True, timeout=3)
                val = serial_proc.stdout.strip()
            if (not val or "denied" in val.lower()) and shutil.which("dmidecode"):
                dmi_proc = subprocess.run(["sudo", "dmidecode", "-s", "system-uuid"], capture_output=True, text=True, timeout=3)
                val = dmi_proc.stdout.strip()
            if not val or "denied" in val.lower():
                mid = Path("/etc/machine-id")
                if mid.is_file():
                    val = mid.read_text().strip()
            data["uuid"] = val if val else "Unknown"
        except Exception:
            data["uuid"] = "Unknown"

        if system == "Arch":
            data["os_version"] = f"Rolling ({platform.release()})"
        else:
            try:
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("VERSION_ID="):
                            data["os_version"] = line.split("=")[1].strip().strip('"')
                            break
            except Exception:
                pass

        linux_browsers = {
            "Chrome": "google-chrome-stable",
            "Chromium": "chromium",
            "Firefox": "firefox",
            "Brave": "brave"
        }
        found_browsers = []
        for bname, bbin in linux_browsers.items():
            ver = get_linux_bin_version(bbin)
            if not ver and bname == "Chrome":
                ver = get_linux_bin_version("google-chrome")
            if not ver and bname == "Firefox":
                for alt in ["firefox-nightly", "firefox-trunk", "firefox-esr", "firefox-developer-edition"]:
                    ver = get_linux_bin_version(alt)
                    if ver:
                        bname = "Firefox Nightly" if alt == "firefox-nightly" else bname
                        break
            if ver:
                found_browsers.append(f"{bname} {ver}")

        if found_browsers:
            data["browsers"] = ", ".join(found_browsers)

        data["firewall"] = "Yes" if ufw_is_correctly_configured() else "No"

        if shutil.which("clamscan"):
            out = subprocess.check_output(["clamscan", "--version"], text=True)
            match = re.search(r"(\d+(?:\.\d+)+)", out)
            data["anti_virus"] = f"ClamAV - {match.group(1)}" if match else "ClamAV - Active"

        ext_id = "cfnpidifppmenkapgihekkeednfoenal"
        candidate_roots = [
            home / ".config/google-chrome",
            home / ".config/chromium",
            home / ".config/BraveSoftware/Brave-Browser"
        ]

        ext_found = False
        for root in candidate_roots:
            if root.is_dir():
                if any(root.glob(f"*/Extensions/{ext_id}")):
                    ext_found = True
                    break

        if not ext_found:
            ext_found = firefox_has_trafficlight(home)

        data["web_scanning"] = "Yes" if ext_found else "No"

        dropin = Path("/etc/sudoers.d/cyber_essentials_targetpw")
        if dropin.exists():
            data["admin_separated"] = "Yes"
        elif grp:
            check_user = os.environ.get("SUDO_USER") or getpass.getuser()
            try:
                groups = [g.gr_name for g in grp.getgrall() if check_user in g.gr_mem]
                data["admin_separated"] = "No" if ("sudo" in groups or "wheel" in groups) else "Yes"
            except Exception:
                data["admin_separated"] = "No"

    elif system == "Windows":
        try:
            ver = subprocess.check_output(["powershell", "-Command", '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").DisplayVersion'], text=True).strip()
            data["os_version"] = ver
            data["uuid"] = subprocess.check_output(["powershell", "-Command", '(Get-CimInstance Win32_BIOS).SerialNumber'], text=True).strip()
            data["anti_virus"] = "Windows Defender - Active"
            data["web_scanning"] = "Yes"
            data["browsers"] = "Chrome"
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

    fix_firewall_background(system)
    fix_antivirus_background(system)

    audit = run_audit(system)
    if audit.get("admin_separated") != "Yes":
        if system in ["Ubuntu", "Arch", "Linux"]:
            if setup_admin_separation(system):
                audit = run_audit(system)
        elif system == "macOS":
            print("\nAdmin Account Separation:")
            print("macOS requires creating a dedicated administrator account under")
            print("System Settings > Users & Groups, then setting your daily login to Standard.")

    audit = run_audit(system)
    if audit.get("web_scanning") != "Yes" and system != "Windows":
        print("\nWebsite Threat Scanning:")
        print("Opening extension store to install Bitdefender TrafficLight...")
        open_url_safely("https://chromewebstore.google.com/detail/trafficlight/cfnpidifppmenkapgihekkeednfoenal")
        input("Press Enter once it is installed and pinned...")

    final = run_audit(system)

    print("\n-------------------------------------------------------------")
    print("Enter your name to register your device:")
    first_name = input("First Name: ").strip()
    last_name = input("Last Name : ").strip()

    row_values = [
        first_name,
        last_name,
        final.get("uuid", "Unknown"),
        final.get("os_distro", "Unknown"),
        final.get("os_version", "Unknown"),
        final.get("auto_updates", "Yes"),
        final.get("office_apps", "Google Workspace"),
        final.get("browsers", "None detected"),
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
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 200:
                print("All done. Your machine has been logged into the tracker. Thank you!")
            else:
                print("Server responded with an issue. Please notify IT.")
    except Exception as e:
        print(f"Network error logging to sheet: {e}")
        print("Your data row for manual reference:")
        print("\t".join(row_values))


if __name__ == "__main__":
    main()
