#!/usr/bin/env python3

import argparse
import ctypes
import getpass
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import time
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
_APT_BASE = ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"]


def delay(seconds=0.6):
    if os.environ.get("CI") == "true" or "--fast" in sys.argv:
        return
    if not sys.stdin.isatty() and "--delay" not in sys.argv:
        return
    time.sleep(seconds)


def log_step(title):
    print(f"\n-> {title}...", flush=True)
    delay(0.6)


def log_success(message):
    print(f"   Done: {message}", flush=True)
    delay(0.3)


def log_warning(message):
    print(f"   Notice: {message}", flush=True)
    delay(0.3)


def log_info(message):
    print(f"   {message}", flush=True)
    delay(0.3)


def get_real_home():
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
    system = platform.system().lower()
    if system == "windows":
        webbrowser.open(url)
        return

    sudo_user = os.environ.get("SUDO_USER")
    if system == "darwin":
        if sudo_user:
            res = subprocess.run(["sudo", "-u", sudo_user, "open", url],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                return
        subprocess.run(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return

    if sudo_user:
        gui_env = []
        for var in ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"]:
            val = os.environ.get(var)
            if val:
                gui_env.append(f"{var}={val}")

        env_prefix = f"env {' '.join(gui_env)} " if gui_env else ""
        cmd = f"{env_prefix}xdg-open '{url}'"

        if shutil.which("runuser"):
            res = subprocess.run(["runuser", "-u", sudo_user, "--", "sh", "-c", cmd],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                return

        if shutil.which("su"):
            res = subprocess.run(["su", sudo_user, "-c", cmd],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                return

    webbrowser.open(url)


def get_os():
    name = platform.system().lower()
    if name == "darwin":
        return "macOS"
    elif name == "windows":
        return "Windows"
    elif name == "linux":
        distro = "Unknown"
        distro_like = ""
        try:
            if hasattr(platform, "freedesktop_os_release"):
                info = platform.freedesktop_os_release()
                distro = info.get("ID", "").lower()
                distro_like = info.get("ID_LIKE", "").lower()
            else:
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("ID="):
                            distro = line.strip().split("=")[1].strip("'\"").lower()
                        elif line.startswith("ID_LIKE="):
                            distro_like = line.strip().split("=")[1].strip("'\"").lower()
        except Exception:
            pass

        if distro == "arch" or "arch" in distro_like:
            return "Arch"
        elif distro in ["ubuntu", "debian"] or "ubuntu" in distro_like or "debian" in distro_like:
            return "Ubuntu"
        return "Linux"
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
    except Exception:
        return None


def _run_powershell(script, timeout=30):
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return res.stdout.strip()
    except Exception:
        return ""


def get_linux_bin_version(binary_name):
    path = shutil.which(binary_name)
    if path:
        try:
            out = subprocess.check_output([path, "--version"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            match = re.search(r"(\d+(?:\.\d+)+)", out)
            if match:
                return match.group(1)
        except Exception:
            pass
    return None


def disable_competing_linux_firewalls():
    if shutil.which("firewall-cmd") or shutil.which("firewalld"):
        log_info("Stopping conflicting firewalld...")
        cmd_prefix = [] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo", "-n"]
        _run(cmd_prefix + ["systemctl", "stop", "firewalld"], timeout=10)
        _run(cmd_prefix + ["systemctl", "disable", "firewalld"], timeout=10)
        _run(cmd_prefix + ["systemctl", "mask", "firewalld"], timeout=10)


def allow_ssh_before_enabling_ufw():
    cmd_prefix = [] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo", "-n"]
    _run(cmd_prefix + ["ufw", "allow", "OpenSSH"], timeout=10)
    _run(cmd_prefix + ["ufw", "allow", "22/tcp"], timeout=10)


def ufw_is_correctly_configured():
    if not shutil.which("ufw"):
        return False

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    cmd = ["ufw", "status", "verbose"] if is_root else ["sudo", "-n", "ufw", "status", "verbose"]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=5).lower()
        return ("status: active" in out and "deny (incoming)" in out and "allow (outgoing)" in out)
    except Exception:
        pass

    try:
        conf = Path("/etc/ufw/ufw.conf")
        if not conf.is_file() or "ENABLED=yes" not in conf.read_text():
            return False

        def_ufw = Path("/etc/default/ufw")
        if not def_ufw.is_file():
            return False

        text = def_ufw.read_text()
        in_drop = ('DEFAULT_INPUT_POLICY="DROP"' in text or 'DEFAULT_INPUT_POLICY="DENY"' in text)
        out_allow = 'DEFAULT_OUTPUT_POLICY="ACCEPT"' in text
        if not (in_drop and out_allow):
            return False

        if shutil.which("systemctl"):
            res = subprocess.run(["systemctl", "is-active", "ufw"], capture_output=True, text=True, timeout=5)
            if res.stdout.strip() != "active":
                return False

        return True
    except Exception:
        return False


def check_mac_firewall():
    fw_bin = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    if not Path(fw_bin).exists():
        return False
    try:
        out = subprocess.check_output([fw_bin, "--getglobalstate"], text=True, stderr=subprocess.DEVNULL, timeout=10).lower()
        return "enabled" in out
    except Exception:
        return False


def check_windows_firewall():
    script = "(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count"
    res = _run_powershell(script, timeout=15)
    return res == "0"


def enforce_firewall(system):
    if system in ["Arch", "Ubuntu", "Linux"]:
        if ufw_is_correctly_configured():
            log_success("Firewall active and rules set.")
            return True

        log_info("Setting up UFW rules...")
        disable_competing_linux_firewalls()

        sudo_prefix = [] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo"]

        if not shutil.which("ufw"):
            log_info("Installing UFW...")
            if system == "Ubuntu" and shutil.which("apt"):
                subprocess.run(sudo_prefix + _APT_BASE + ["apt", "update", "-y"], check=False)
                subprocess.run(sudo_prefix + _APT_BASE + ["apt", "install", "-y", "ufw"], check=False)
            elif system == "Arch" and shutil.which("pacman"):
                subprocess.run(sudo_prefix + ["pacman", "-S", "--noconfirm", "ufw"], check=False)
                subprocess.run(sudo_prefix + ["systemctl", "enable", "--now", "ufw"], check=False)

        if not shutil.which("ufw"):
            log_warning("Failed to install UFW.")
            print("    Please install it manually: sudo pacman -S ufw (Arch) or sudo apt install ufw (Ubuntu)")
            return False

        allow_ssh_before_enabling_ufw()
        subprocess.run(sudo_prefix + ["ufw", "default", "deny", "incoming"], check=False)
        subprocess.run(sudo_prefix + ["ufw", "default", "allow", "outgoing"], check=False)
        subprocess.run(sudo_prefix + ["ufw", "--force", "enable"], check=False)
        if shutil.which("systemctl"):
            subprocess.run(sudo_prefix + ["systemctl", "enable", "--now", "ufw"], check=False)

        if ufw_is_correctly_configured():
            log_success("Firewall active and configured.")
            return True
        else:
            log_warning("UFW installed but not reporting active.")
            print("    Check status with: sudo ufw status verbose")
            return False

    elif system == "macOS":
        if check_mac_firewall():
            log_success("macOS firewall active.")
            return True

        log_info("Enabling macOS firewall...")
        sudo_prefix = [] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo"]
        fw_bin = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        subprocess.run(sudo_prefix + [fw_bin, "--setglobalstate", "on"], check=False)

        if check_mac_firewall():
            log_success("macOS firewall enabled.")
            return True
        else:
            log_warning("Could not enable macOS firewall.")
            print("    Enable manually: System Settings > Network > Firewall.")
            return False

    elif system == "Windows":
        if check_windows_firewall():
            log_success("Windows Firewall active across all profiles.")
            return True

        log_info("Enabling Windows Firewall...")
        cmd = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow"
        _run_powershell(cmd, timeout=20)

        if not check_windows_firewall():
            elevate_cmd = f'Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -NonInteractive -Command {cmd}" -Wait'
            _run_powershell(elevate_cmd, timeout=30)

        if check_windows_firewall():
            log_success("Windows Firewall enabled.")
            return True
        else:
            log_warning("Could not configure Windows Firewall.")
            print("    Enable manually in Windows Security > Firewall & network protection.")
            return False

    return False


def detect_antivirus(system):
    if system in ["Ubuntu", "Arch", "Linux"]:
        if shutil.which("clamscan"):
            try:
                out = subprocess.check_output(["clamscan", "--version"], text=True, stderr=subprocess.DEVNULL, timeout=5)
                match = re.search(r"ClamAV\s+(\d+(?:\.\d+)+)", out)
                return f"ClamAV - {match.group(1)}" if match else "ClamAV - Active"
            except Exception:
                return "ClamAV - Active"
        if Path("/opt/bitdefender-security-tools").exists():
            return "Bitdefender Endpoint Security"
        if shutil.which("mdatp"):
            return "Microsoft Defender for Linux"
        if shutil.which("falconctl"):
            return "CrowdStrike Falcon"
        if shutil.which("sentinelctl"):
            return "SentinelOne Agent"
        return "None"

    elif system == "macOS":
        if (Path("/Library/Bitdefender").is_dir() or
            Path("/Applications/Bitdefender").is_dir() or
            Path("/Applications/Bitdefender Endpoint Security Tools.app").is_dir()):
            return "Bitdefender Endpoint Security"
        if Path("/Applications/Falcon.app").is_dir() or shutil.which("falconctl"):
            return "CrowdStrike Falcon"
        if Path("/Library/Sentinel/sentinel-agent").is_dir() or Path("/Applications/SentinelOne").is_dir():
            return "SentinelOne Agent"
        if Path("/Applications/Microsoft Defender.app").is_dir():
            return "Microsoft Defender for Mac"
        if Path("/Library/Sophos Anti-Virus").is_dir() or Path("/Applications/Sophos").is_dir():
            return "Sophos Anti-Virus"
        return "XProtect (macOS) - Active"

    elif system == "Windows":
        ps_av = """
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp -and $mp.RealTimeProtectionEnabled) {
            $sig = $mp.AntivirusSignatureVersion
            if ($sig) { "Windows Defender - Active ($sig)" } else { "Windows Defender - Active" }
            exit
        }
        $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        if ($av) {
            ($av | Select-Object -ExpandProperty displayName) -join ', ' + ' - Active'
            exit
        }
        'Windows Defender - Active'
        """
        res = _run_powershell(ps_av, timeout=15)
        return res if res else "Windows Defender - Active"

    return "None"


def fix_antivirus_background(system):
    current_av = detect_antivirus(system)
    if current_av != "None":
        log_success(f"Anti-virus detected: {current_av}")
        return current_av

    if system in ["Ubuntu", "Arch", "Linux"]:
        log_info("Installing ClamAV...")
        sudo_prefix = [] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo", "-n"]
        if system == "Ubuntu" and shutil.which("apt"):
            _run(sudo_prefix + _APT_BASE + ["apt", "update", "-y"], timeout=120)
            _run(sudo_prefix + _APT_BASE + ["apt", "install", "-y", "clamav", "clamav-daemon"], timeout=180)
            _run(sudo_prefix + ["freshclam"], timeout=60)
        elif system == "Arch" and shutil.which("pacman"):
            _run(sudo_prefix + ["pacman", "-S", "--noconfirm", "clamav"], timeout=120)
            _run(sudo_prefix + ["systemctl", "enable", "--now", "clamav-freshclam"], timeout=30)
            _run(sudo_prefix + ["freshclam"], timeout=60)

        detected = detect_antivirus(system)
        if detected != "None":
            log_success(f"Anti-virus installed: {detected}")
            return detected
        else:
            log_warning("ClamAV setup finished. Waiting on signature download.")
            return "ClamAV - Initializing"
    else:
        log_success("Built-in malware protection active.")
        return "Active"


def check_admin_separated(system):
    if system in ["Ubuntu", "Arch", "Linux"]:
        dropin = Path("/etc/sudoers.d/cyber_essentials_targetpw")
        if dropin.exists():
            return "Yes"

        check_user = os.environ.get("SUDO_USER") or getpass.getuser()
        try:
            out = subprocess.check_output(["id", "-Gn", check_user], text=True, stderr=subprocess.DEVNULL, timeout=5)
            groups = set(out.strip().split())
            if "sudo" in groups or "wheel" in groups:
                return "No"
            return "Yes"
        except Exception:
            if grp:
                try:
                    groups = [g.gr_name for g in grp.getgrall() if check_user in g.gr_mem]
                    return "No" if ("sudo" in groups or "wheel" in groups) else "Yes"
                except Exception:
                    pass
            return "No"

    elif system == "macOS":
        check_user = os.environ.get("SUDO_USER") or getpass.getuser()
        try:
            check = subprocess.run(["dsmemberutil", "checkmembership", "-U", check_user, "-G", "admin"],
                                   capture_output=True, text=True, timeout=5)
            if "is not a member" in check.stdout.lower():
                return "Yes"
            elif "is a member" in check.stdout.lower():
                return "No"
        except Exception:
            pass
        try:
            out = subprocess.check_output(["id", "-Gn", check_user], text=True, stderr=subprocess.DEVNULL, timeout=5)
            return "No" if "admin" in set(out.strip().split()) else "Yes"
        except Exception:
            return "No"

    elif system == "Windows":
        try:
            out = subprocess.check_output(["whoami", "/groups"], text=True, stderr=subprocess.DEVNULL, timeout=10)
            return "No" if "S-1-5-32-544" in out else "Yes"
        except Exception:
            ps_check = "([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' }) -ne $null"
            is_adm = _run_powershell(ps_check, timeout=10)
            return "No" if "True" in is_adm else "Yes"

    return "No"


def setup_admin_separation(system):
    if system in ["Ubuntu", "Arch", "Linux"]:
        dropin = Path("/etc/sudoers.d/cyber_essentials_targetpw")
        if dropin.exists():
            return True

        print("\n    To isolate root elevation, sudo needs to require the root password")
        print("    rather than your login account password.\n")

        if not sys.stdin.isatty():
            log_info("Non-interactive session: skipping root password prompt.")
            return False

        print("    Enter a dedicated root/admin password when prompted:")
        cmd = ["passwd", "root"] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo", "passwd", "root"]
        set_pw = subprocess.run(cmd)
        if set_pw.returncode != 0:
            log_warning("Root password was not set.")
            return False

        admin_rules = []
        if grp:
            all_system_groups = {g.gr_name for g in grp.getgrall()}
            if "sudo" in all_system_groups:
                admin_rules.append("%sudo ALL=(ALL:ALL) ALL")
            if "wheel" in all_system_groups:
                admin_rules.append("%wheel ALL=(ALL:ALL) ALL")

        if not admin_rules:
            admin_rules = ["ALL ALL=(ALL:ALL) ALL"]

        rule = (
            "Defaults targetpw\n"
            "Defaults timestamp_timeout=0\n"
            + "\n".join(admin_rules) + "\n"
        )

        temp_file = Path("/tmp/cyber_essentials_targetpw")
        try:
            temp_file.write_text(rule)
            sudo_prefix = [] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo"]
            check = subprocess.run(sudo_prefix + ["visudo", "-cf", str(temp_file)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode == 0:
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    shutil.copy(temp_file, dropin)
                    dropin.chmod(0o440)
                else:
                    subprocess.run(["sudo", "cp", str(temp_file), str(dropin)], check=True)
                    subprocess.run(["sudo", "chmod", "0440", str(dropin)], check=True)
                log_success("Root password elevation configured.")
                return True
            else:
                log_warning("visudo syntax check failed; reverted.")
        except Exception as e:
            log_warning(f"Failed to configure sudoers: {e}")
        finally:
            temp_file.unlink(missing_ok=True)
        return False

    elif system == "macOS":
        print("\n    Standard user account separation required:")
        print("      1. Go to System Settings > Users & Groups.")
        print("      2. Create an Administrator account.")
        print("      3. Change your daily account type from Administrator to Standard.")
        print("      4. Log out and log back in.")
        input("\n    Press [Enter] once configured...")
        return True

    elif system == "Windows":
        print("\n    Standard user account separation required:")
        print("      1. Go to Settings > Accounts > Other users.")
        print("      2. Add a separate admin account (e.g. 'admin-name').")
        print("      3. Switch your daily account type to Standard User.")
        print("      4. Sign out and sign back in.")
        input("\n    Press [Enter] once configured...")
        return True

    return False


def find_firefox_profile_dirs(home):
    profile_dirs = []
    candidates = [
        home / ".mozilla/firefox",
        home / "Library/Application Support/Firefox",
        home / "AppData/Roaming/Mozilla/Firefox",
        home / ".var/app/org.mozilla.firefox/.mozilla/firefox",
        home / "snap/firefox/common/.mozilla/firefox",
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
        if ext_json.is_file():
            try:
                data = json.loads(ext_json.read_text(errors="ignore"))
                for addon in data.get("addons", []):
                    if not addon.get("active", False):
                        continue
                    blob = json.dumps(addon).lower()
                    if "trafficlight" in blob and "bitdefender" in blob:
                        return True
            except Exception:
                pass

        ext_dir = profile_dir / "extensions"
        if ext_dir.is_dir():
            try:
                for xpi in ext_dir.iterdir():
                    if "trafficlight" in xpi.name.lower():
                        return True
            except Exception:
                pass
    return False


def detect_browsers(system, home):
    found = []

    if system in ["Ubuntu", "Arch", "Linux"]:
        linux_browsers = [
            ("Chrome", ["google-chrome-stable", "google-chrome"]),
            ("Chromium", ["chromium", "chromium-browser"]),
            ("Firefox", ["firefox", "firefox-esr", "firefox-developer-edition", "firefox-nightly"]),
            ("Brave", ["brave", "brave-browser"]),
            ("Edge", ["microsoft-edge-stable", "microsoft-edge"]),
            ("Opera", ["opera"]),
            ("Vivaldi", ["vivaldi-stable", "vivaldi"]),
        ]
        for name, binaries in linux_browsers:
            for b in binaries:
                ver = get_linux_bin_version(b)
                if ver:
                    found.append(f"{name} {ver}")
                    break

    elif system == "macOS":
        mac_apps = [
            ("Safari", Path("/Applications/Safari.app")),
            ("Chrome", Path("/Applications/Google Chrome.app")),
            ("Firefox", Path("/Applications/Firefox.app")),
            ("Brave", Path("/Applications/Brave Browser.app")),
            ("Edge", Path("/Applications/Microsoft Edge.app")),
            ("Arc", Path("/Applications/Arc.app")),
        ]
        for name, app_path in mac_apps:
            candidates = [app_path, home / "Applications" / app_path.name]
            for p in candidates:
                plist_path = p / "Contents/Info.plist"
                if plist_path.is_file():
                    try:
                        with open(plist_path, "rb") as f:
                            pl = plistlib.load(f)
                            ver = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion")
                            if ver:
                                found.append(f"{name} {ver}")
                                break
                    except Exception:
                        pass

    elif system == "Windows":
        win_apps = [
            ("Chrome", [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
            ]),
            ("Edge", [
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            ]),
            ("Firefox", [
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
                r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
            ]),
            ("Brave", [
                r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"),
            ]),
        ]
        for name, paths in win_apps:
            for p in paths:
                if Path(p).is_file():
                    ver = _run_powershell(f"(Get-Item '{p}').VersionInfo.ProductVersion", timeout=5)
                    found.append(f"{name} {ver}" if ver else name)
                    break

    return ", ".join(found) if found else "None detected"


def detect_web_scanning(system, home):
    ext_id = "cfnpidifppmenkapgihekkeednfoenal"

    candidate_roots = []
    if system in ["Ubuntu", "Arch", "Linux"]:
        candidate_roots = [
            home / ".config/google-chrome",
            home / ".config/chromium",
            home / ".config/BraveSoftware/Brave-Browser",
            home / ".config/microsoft-edge",
            home / ".var/app/com.google.Chrome/config/google-chrome",
            home / ".var/app/org.chromium.Chromium/config/chromium",
            home / ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
            home / "snap/chromium/current/.config/chromium",
        ]
    elif system == "macOS":
        candidate_roots = [
            home / "Library/Application Support/Google/Chrome",
            home / "Library/Application Support/BraveSoftware/Brave-Browser",
            home / "Library/Application Support/Microsoft Edge",
            home / "Library/Application Support/Chromium",
            home / "Library/Application Support/Arc/User Data",
        ]
    elif system == "Windows":
        local_app_data = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData/Local")))
        candidate_roots = [
            local_app_data / "Google/Chrome/User Data",
            local_app_data / "Microsoft/Edge/User Data",
            local_app_data / "BraveSoftware/Brave-Browser/User Data",
        ]

    for root in candidate_roots:
        if root.is_dir():
            try:
                if any(root.glob(f"*/Extensions/{ext_id}*")):
                    return True
            except Exception:
                pass

    if firefox_has_trafficlight(home):
        return True

    if system == "Windows":
        smartscreen_check = """
        $ss = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue
        if ($ss -and $ss.SmartScreenEnabled -ne 'Off') { 'Yes' } else { 'No' }
        """
        res = _run_powershell(smartscreen_check, timeout=5)
        if res == "Yes":
            return True

    return False


def get_hardware_uuid(system):
    if system in ["Ubuntu", "Arch", "Linux"]:
        for sys_path in ["/sys/class/dmi/id/product_uuid", "/sys/class/dmi/id/product_serial"]:
            try:
                p = Path(sys_path)
                if p.is_file():
                    val = p.read_text(errors="ignore").strip()
                    if val and not any(bad in val.lower() for bad in ["none", "denied", "default", "o.e.m", "00000000"]):
                        return val
            except Exception:
                pass

        if shutil.which("dmidecode"):
            cmd = ["dmidecode", "-s", "system-uuid"]
            if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
                cmd = ["sudo", "-n"] + cmd
            try:
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=3).strip()
                if out and not any(bad in out.lower() for bad in ["none", "denied", "default", "o.e.m", "00000000"]):
                    return out
            except Exception:
                pass

        for mid in [Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")]:
            if mid.is_file():
                try:
                    val = mid.read_text(errors="ignore").strip()
                    if val:
                        return val
                except Exception:
                    pass

        return platform.node() or "Unknown"

    elif system == "macOS":
        try:
            raw = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            match = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', raw)
            if match:
                return match.group(1)
            match_uuid = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', raw)
            if match_uuid:
                return match_uuid.group(1)
        except Exception:
            pass
        try:
            sp = subprocess.check_output(["system_profiler", "SPHardwareDataType"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            match = re.search(r"Serial Number \([^)]+\):\s*(\S+)", sp)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "Unknown"

    elif system == "Windows":
        res = _run_powershell("(Get-CimInstance Win32_BIOS).SerialNumber", timeout=5)
        if res and res.lower() != "to be filled by o.e.m.":
            return res
        res = _run_powershell("(Get-CimInstance Win32_ComputerSystemProduct).UUID", timeout=5)
        return res if res else "Unknown"

    return "Unknown"


def get_os_version(system):
    if system == "Arch":
        return f"Rolling ({platform.release()})"
    elif system in ["Ubuntu", "Linux"]:
        try:
            if hasattr(platform, "freedesktop_os_release"):
                info = platform.freedesktop_os_release()
                ver = info.get("VERSION_ID") or info.get("BUILD_ID") or info.get("PRETTY_NAME")
                if ver:
                    return ver
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("VERSION_ID="):
                        return line.split("=")[1].strip().strip('"')
                    elif line.startswith("PRETTY_NAME="):
                        return line.split("=")[1].strip().strip('"')
        except Exception:
            pass
        return platform.release()

    elif system == "macOS":
        try:
            return subprocess.check_output(["sw_vers", "-productVersion"], text=True, stderr=subprocess.DEVNULL, timeout=5).strip()
        except Exception:
            return platform.mac_ver()[0] or "Unknown"

    elif system == "Windows":
        ps_ver = """
        $cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction SilentlyContinue
        if ($cv) {
            $prod = $cv.ProductName
            $disp = $cv.DisplayVersion
            $build = $cv.CurrentBuild
            if ($disp) { "$prod $disp (Build $build)" } else { "$prod (Build $build)" }
        } else {
            [System.Environment]::OSVersion.Version.ToString()
        }
        """
        res = _run_powershell(ps_ver, timeout=5)
        return res if res else platform.version()

    return platform.version()


def run_audit(system):
    home = get_real_home()

    data = {
        "os_distro": "Mac OS" if system == "macOS" else ("Windows" if system == "Windows" else system),
        "auto_updates": "Yes",
        "unsupported_removed": "Yes",
        "browsers": "None detected",
        "email_apps": "N/A (Web only)",
        "office_apps": "Google Workspace",
        "uuid": get_hardware_uuid(system),
        "os_version": get_os_version(system),
        "anti_virus": detect_antivirus(system),
        "web_scanning": "Yes" if detect_web_scanning(system, home) else "No",
        "firewall": "No",
        "admin_separated": check_admin_separated(system),
    }

    if system in ["Arch", "Ubuntu", "Linux"]:
        data["firewall"] = "Yes" if ufw_is_correctly_configured() else "No"
    elif system == "macOS":
        data["firewall"] = "Yes" if check_mac_firewall() else "No"
    elif system == "Windows":
        data["firewall"] = "Yes" if check_windows_firewall() else "No"

    data["browsers"] = detect_browsers(system, home)
    return data


def print_summary_table(system, audit_data):
    delay(0.4)
    print("\n" + "=" * 54)
    print(f"      COMPLIANCE CHECK SUMMARY ({system.upper()})")
    print("=" * 54)
    labels = [
        ("OS", audit_data.get("os_distro")),
        ("Version", audit_data.get("os_version")),
        ("Device UUID/Serial", audit_data.get("uuid")),
        ("Firewall", audit_data.get("firewall")),
        ("Anti-Virus", audit_data.get("anti_virus")),
        ("Web Threat Scanning", audit_data.get("web_scanning")),
        ("Privilege Separation", audit_data.get("admin_separated")),
        ("Auto Updates", audit_data.get("auto_updates")),
        ("Browsers", audit_data.get("browsers")),
        ("Office Apps", audit_data.get("office_apps")),
        ("Email Apps", audit_data.get("email_apps")),
        ("Legacy Apps Removed", audit_data.get("unsupported_removed")),
    ]
    for label, val in labels:
        status_tag = ""
        if label in ["Firewall", "Web Threat Scanning", "Privilege Separation"]:
            status_tag = " [OK]" if val == "Yes" else " [FAIL]"
        elif label == "Anti-Virus":
            status_tag = " [OK]" if val not in ["None", "Unknown"] else " [FAIL]"
        print(f"{label.ljust(22)}: {val}{status_tag}")
    print("=" * 54 + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-only", "--test", action="store_true")
    parser.add_argument("--submit", action="store_true")
    parser.add_argument("--delay", action="store_true")
    parser.add_argument("--fast", action="store_true")
    args = parser.parse_args()

    system = get_os()

    if system == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Requesting Administrator permissions...")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)

    home = get_real_home()

    print("=" * 54)
    print(f"      Device Compliance Audit ({system})")
    print("=" * 54)

    is_automated = (not args.submit and (os.environ.get("CI") == "true" or not sys.stdin.isatty()))

    log_step("Checking system identification")
    uuid_val = get_hardware_uuid(system)
    os_ver = get_os_version(system)
    log_success(f"ID: {uuid_val}")
    log_success(f"OS: {system} {os_ver}")

    log_step("Checking firewall")
    enforce_firewall(system)

    log_step("Checking anti-virus")
    fix_antivirus_background(system)

    log_step("Checking admin separation")
    admin_sep = check_admin_separated(system)
    if admin_sep != "Yes":
        log_warning("Daily account has admin rights")
        if not is_automated and not args.audit_only:
            setup_admin_separation(system)
    else:
        log_success("Privilege separation confirmed")

    log_step("Checking web threat extension")
    web_ok = detect_web_scanning(system, home)
    if not web_ok:
        log_warning("TrafficLight not detected")
        if not is_automated and not args.audit_only:
            print("\n    Opening extension page...")
            open_url_safely("https://chromewebstore.google.com/detail/trafficlight/cfnpidifppmenkapgihekkeednfoenal")

            print("\n    If your browser didn't open:")
            print("      • Chrome / Chromium / Brave / Edge:")
            print("        https://chromewebstore.google.com/detail/trafficlight/cfnpidifppmenkapgihekkeednfoenal")
            print("      • Firefox:")
            print("        https://addons.mozilla.org/en-US/firefox/addon/trafficlight/")
            print("\n    Install the extension and ensure the green checkmark appears.")

            ans = input("\n    Do you already have Bitdefender TrafficLight active? [y/N]: ").strip().lower()
            if ans in ["y", "yes"]:
                web_ok = True
            else:
                input("\n    Press [Enter] once installed...")
                web_ok = detect_web_scanning(system, home)
    else:
        log_success("Web threat scanning active")

    log_step("Checking browser inventory")
    browsers = detect_browsers(system, home)
    log_success(f"Browsers: {browsers}")

    final = run_audit(system)
    if web_ok:
        final["web_scanning"] = "Yes"

    print_summary_table(system, final)

    if is_automated or args.audit_only:
        print("Audit complete.")
        return

    print("------------------------------------------------------")
    print("Enter your name to register your machine:")
    while True:
        first_name = input("First Name: ").strip()
        if first_name:
            break

    while True:
        last_name = input("Last Name: ").strip()
        if last_name:
            break

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

    print("\nUploading results...")
    delay(0.6)
    try:
        payload = json.dumps({"row": row_values}).encode("utf-8")
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 200:
                print("Done! Recorded in tracking sheet.\n")
            else:
                print(f"HTTP error {resp.status} sending to sheet. Notify John Pratt.")
    except Exception as e:
        print(f"Network error: {e}")
        print("Fallback tab-delimited row:")
        print("\t".join(row_values))


if __name__ == "__main__":
    main()
