#!/usr/bin/env python3

import platform
import sys
import os
import plistlib
import subprocess
import getpass
import grp
from pathlib import Path

def get_os():
    os_name = platform.system().lower()

    if os_name == 'darwin':
        return 'macos'

    elif os_name == 'linux':
        distro = platform.freedesktop_os_release().get('ID')

        if distro == 'arch':
            return 'arch'

        elif distro == 'ubuntu':
            return 'ubuntu'

        else:
            return 'unknown'

    elif os_name == 'windows':
        return 'windows'

    else:
        return 'unknown'

def macos():
    data = {
            "os_distro": "macOS",
            "auto_updates": "Yes (Drata Enforced)",
            "unsupported_removed": "Yes"
            }

    try:
        data["os_version"] = subprocess.check_output(
            ["sw_vers", "-productVersion"], 
            text=True
        ).strip()
    except Exception:
        data["os_version"] = "Unknown"

    try:
        raw_ioreg = subprocess.check_output(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], 
            text=True
        )
        serial = "Unknown"
        for line in raw_ioreg.splitlines():
            if "IOPlatformSerialNumber" in line:
                serial = line.split('"')[-2]
                break
        data["uuid"] = serial
    except Exception:
        data["uuid"] = "Unknown"
