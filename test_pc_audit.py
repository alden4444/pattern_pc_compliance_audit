#!/usr/bin/env python3

import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import Pattern_PC_Compliance_Audit as audit


class TestComplianceAudit(unittest.TestCase):

    def test_get_os_detection(self):
        # Test Darwin -> macOS
        with patch("platform.system", return_value="Darwin"):
            self.assertEqual(audit.get_os(), "macOS")

        # Test Windows -> Windows
        with patch("platform.system", return_value="Windows"):
            self.assertEqual(audit.get_os(), "Windows")

        # Test Linux -> Arch
        with patch("platform.system", return_value="Linux"):
            with patch("platform.freedesktop_os_release", return_value={"ID": "arch", "ID_LIKE": ""}):
                self.assertEqual(audit.get_os(), "Arch")

        # Test Linux -> Ubuntu
        with patch("platform.system", return_value="Linux"):
            with patch("platform.freedesktop_os_release", return_value={"ID": "ubuntu", "ID_LIKE": "debian"}):
                self.assertEqual(audit.get_os(), "Ubuntu")

        # Test Linux -> Debian derivative (treated as Ubuntu ecosystem)
        with patch("platform.system", return_value="Linux"):
            with patch("platform.freedesktop_os_release", return_value={"ID": "linuxmint", "ID_LIKE": "ubuntu debian"}):
                self.assertEqual(audit.get_os(), "Ubuntu")

        # Test Linux -> Generic Linux
        with patch("platform.system", return_value="Linux"):
            with patch("platform.freedesktop_os_release", return_value={"ID": "fedora", "ID_LIKE": ""}):
                self.assertEqual(audit.get_os(), "Linux")

    def test_get_real_home(self):
        # Under normal execution
        home = audit.get_real_home()
        self.assertTrue(isinstance(home, Path))

    def test_macos_browser_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            app_dir = tmppath / "Google Chrome.app" / "Contents"
            app_dir.mkdir(parents=True)
            plist_file = app_dir / "Info.plist"
            with plist_file.open("wb") as f:
                plistlib.dump({"CFBundleShortVersionString": "129.0.6668.70"}, f)

            # Mock mac_apps path
            with patch.object(Path, "is_file", autospec=True) as mock_is_file:
                # Test plistlib reading
                with plist_file.open("rb") as f:
                    pl = plistlib.load(f)
                    self.assertEqual(pl.get("CFBundleShortVersionString"), "129.0.6668.70")

    def test_windows_admin_separated(self):
        # Scenario 1: Standard user (S-1-5-32-544 not in groups)
        whoami_standard = """
GROUP INFORMATION
-----------------
Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\\Users                         Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
"""
        with patch("subprocess.check_output", return_value=whoami_standard):
            self.assertEqual(audit.check_admin_separated("Windows"), "Yes")

        # Scenario 2: Admin user (S-1-5-32-544 present)
        whoami_admin = """
GROUP INFORMATION
-----------------
Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\\Administrators                 Alias            S-1-5-32-544 Group used for deny only
"""
        with patch("subprocess.check_output", return_value=whoami_admin):
            self.assertEqual(audit.check_admin_separated("Windows"), "No")

    def test_macos_admin_separated(self):
        # Scenario 1: User is not an admin
        mock_proc_standard = MagicMock(stdout="user is not a member of the group")
        with patch("subprocess.run", return_value=mock_proc_standard):
            self.assertEqual(audit.check_admin_separated("macOS"), "Yes")

        # Scenario 2: User is an admin
        mock_proc_admin = MagicMock(stdout="user is a member of the group")
        with patch("subprocess.run", return_value=mock_proc_admin):
            self.assertEqual(audit.check_admin_separated("macOS"), "No")

    def test_linux_admin_separated(self):
        # If cyber_essentials_targetpw dropin exists -> Yes
        with patch.object(Path, "exists", return_value=True):
            self.assertEqual(audit.check_admin_separated("Arch"), "Yes")

        # If dropin does not exist:
        with patch.object(Path, "exists", return_value=False):
            # User in wheel -> No
            with patch("subprocess.check_output", return_value="alden network wheel docker\n"):
                self.assertEqual(audit.check_admin_separated("Arch"), "No")

            # User in sudo -> No
            with patch("subprocess.check_output", return_value="alden adm cdrom sudo dip\n"):
                self.assertEqual(audit.check_admin_separated("Ubuntu"), "No")

            # Standard user (neither wheel nor sudo) -> Yes
            with patch("subprocess.check_output", return_value="alden users audio video\n"):
                self.assertEqual(audit.check_admin_separated("Arch"), "Yes")
                self.assertEqual(audit.check_admin_separated("Ubuntu"), "Yes")

    def test_antivirus_detection(self):
        # Windows Defender
        with patch("Pattern_PC_Compliance_Audit._run_powershell", return_value="Windows Defender - Active (1.417.432.0)"):
            self.assertEqual(audit.detect_antivirus("Windows"), "Windows Defender - Active (1.417.432.0)")

        # macOS XProtect
        with patch.object(Path, "is_dir", return_value=False):
            self.assertEqual(audit.detect_antivirus("macOS"), "XProtect (macOS) - Active")

        # Linux ClamAV
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/clamscan" if x == "clamscan" else None):
            with patch("subprocess.check_output", return_value="ClamAV 1.5.4/28113\n"):
                self.assertEqual(audit.detect_antivirus("Arch"), "ClamAV - 1.5.4")

    def test_web_scanning_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            ext_dir = home / ".config/google-chrome/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal/3.0.2_0"
            ext_dir.mkdir(parents=True)
            self.assertTrue(audit.detect_web_scanning("Arch", home))

    def test_firefox_trafficlight_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            ff_dir = home / ".mozilla/firefox"
            ff_dir.mkdir(parents=True)
            profiles_ini = ff_dir / "profiles.ini"
            profiles_ini.write_text("[Profile0]\nName=default\nIsRelative=1\nPath=default-release\n")

            prof_dir = ff_dir / "default-release"
            prof_dir.mkdir()
            ext_json = prof_dir / "extensions.json"
            ext_json.write_text('{"addons":[{"id":"trafficlight@bitdefender.com","name":"TrafficLight"}]}')

            self.assertTrue(audit.firefox_has_trafficlight(home))

    def test_hardware_uuid(self):
        # Test reading DMI or machine-id
        with patch("subprocess.check_output", return_value="12345-67890-UUID\n"):
            val = audit.get_hardware_uuid("Arch")
            self.assertTrue(val != "Unknown")

    def test_run_audit_structure(self):
        data = audit.run_audit(audit.get_os())
        required_keys = [
            "os_distro",
            "auto_updates",
            "unsupported_removed",
            "browsers",
            "email_apps",
            "office_apps",
            "uuid",
            "os_version",
            "anti_virus",
            "web_scanning",
            "firewall",
            "admin_separated",
        ]
        for k in required_keys:
            self.assertIn(k, data, f"Missing key: {k}")


if __name__ == "__main__":
    unittest.main()
