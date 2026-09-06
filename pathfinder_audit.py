#!/usr/bin/env python3

import platform
import subprocess
import json

def get_data():
    data = {
            "node": platform.node(),
            "release": platform.release(),
            "machine_id": "unknown",
            "distro": "unknown"
            }

    try:
        with open("/etc/machine-id") as f:
            data["machine_id"] = f.read().strip()
    except Exception:
        pass

    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("NAME="):
                    data["distro"] = line.strip().split("=")[1].strip('"\'')
    except Exception:
        pass

    return data

def get_interfaces():
    raw = subprocess.check_output(["ip", "-j", "addr"], text=True)
    data = json.loads(raw)

    interfaces = []

    for iface in data:
        name = iface.get("ifname", "unknown")
        ips = []

        for addr in iface.get("addr_info", []):
            if addr.get("family") == "inet":
                ips.append(addr.get("local"))

        interfaces.append({"name": name, "ips": ips})

    return interfaces

def get_open_ports():
    ports = []
    
    raw = subprocess.check_output(["ss", "-tulnH"], text=True)
    
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            protocol = parts[0]
            socket = parts[4]
            ip, port = socket.rsplit(":", 1)

            is_exposed = ip in ["0.0.0.0", "::", "*"]
            ports.append({
                            "proto": protocol,
                            "ip": ip,
                            "port": port,
                            "exposed": is_exposed
                        })

    return ports

def main():
    report = {
        "identity": get_data(),
        "interfaces": get_interfaces(),
        "open_ports": get_open_ports()
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
