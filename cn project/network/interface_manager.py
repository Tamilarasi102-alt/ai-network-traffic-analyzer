"""
Network Interface Manager.
Discovers, queries, and validates local network adapters using psutil and cross-referencing Scapy.
"""
import os
import socket
import logging
from typing import List, Dict, Any, Optional
import psutil

logger = logging.getLogger(__name__)


class InterfaceManager:
    """Manages discovery and inspection of local network interfaces."""

    @staticmethod
    def check_npcap_status() -> Dict[str, Any]:
        """Check if Npcap driver files exist and whether capture permission is available."""
        installed = (
            os.path.exists(r"C:\Windows\System32\Npcap") or
            os.path.exists(r"C:\Windows\System32\drivers\npcap.sys")
        )
        permission_granted = False
        message = ""
        if installed:
            try:
                import scapy.all as scapy
                # Check if physical interfaces are exposed to Scapy in this process
                ifaces = getattr(scapy.conf, "ifaces", {})
                physical_count = len([k for k, v in ifaces.items() if "loopback" not in str(v).lower()])
                if physical_count > 0:
                    permission_granted = True
                    message = "Npcap driver is installed and capture permission is active."
                else:
                    permission_granted = False
                    message = (
                        "Npcap is installed in Admin-Only Mode. "
                        "Deep packet protocol capture requires running Python as Administrator. "
                        "OS network throughput (Mbps) and packet rates (PPS) continue normally via psutil."
                    )
            except Exception as e:
                permission_granted = False
                message = f"Scapy query returned: {e}"
        else:
            message = "Npcap driver is not detected. Download from https://npcap.com/#download for raw packet capture."

        return {
            "installed": installed,
            "permission_granted": permission_granted,
            "message": message
        }

    @staticmethod
    def get_interfaces() -> List[Dict[str, Any]]:
        """
        Discovers all available network interfaces on the system.
        Returns a list of structured interface descriptor dictionaries.
        """
        interfaces: List[Dict[str, Any]] = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        io_counters = psutil.net_io_counters(pernic=True)

        for name, stat in stats.items():
            is_up = bool(stat.isup)
            speed = stat.speed if stat.speed > 0 else None
            
            # Extract IPv4 and MAC
            ipv4_addr = None
            mac_addr = None
            if name in addrs:
                for snic in addrs[name]:
                    if snic.family == socket.AF_INET:
                        ipv4_addr = snic.address
                    elif getattr(snic, "family", None) == getattr(psutil, "AF_LINK", -1):
                        mac_addr = snic.address

            # Check if has active traffic
            has_traffic = False
            if name in io_counters:
                nic_io = io_counters[name]
                if nic_io.bytes_recv > 0 or nic_io.bytes_sent > 0:
                    has_traffic = True

            # Classify adapter type
            name_lower = name.lower()
            if any(term in name_lower for term in ("wi-fi", "wifi", "wireless", "wlan")):
                adapter_type = "Wi-Fi"
            elif any(term in name_lower for term in ("ethernet", "eth", "lan", "gigabit")):
                adapter_type = "Ethernet"
            elif "loopback" in name_lower:
                adapter_type = "Loopback"
            else:
                adapter_type = "Other/Virtual"

            # Determine suitability as default recommendation
            is_loopback = adapter_type == "Loopback" or (ipv4_addr and ipv4_addr.startswith("127."))
            is_recommended = (
                is_up and
                not is_loopback and
                ipv4_addr is not None and
                not ipv4_addr.startswith("169.254")  # Not APIPA / unassigned
            )

            status_text = "UP" if is_up else "DOWN"
            speed_text = f"{speed} Mbps" if speed else "Speed Unknown"
            display_name = f"[{adapter_type}] {name} ({status_text} | {speed_text})"
            if ipv4_addr:
                display_name += f" - {ipv4_addr}"

            interfaces.append({
                "name": name,
                "display_name": display_name,
                "adapter_type": adapter_type,
                "is_up": is_up,
                "speed_mbps": speed,
                "ipv4_address": ipv4_addr or "Unassigned",
                "mac_address": mac_addr or "Unknown",
                "has_traffic": has_traffic,
                "is_loopback": is_loopback,
                "is_recommended": is_recommended
            })

        # Sort so recommended interfaces appear first, followed by active interfaces
        interfaces.sort(key=lambda x: (x["is_recommended"], x["is_up"], x["has_traffic"]), reverse=True)
        return interfaces

    @classmethod
    def get_recommended_interface(cls) -> Optional[str]:
        """Returns the best default interface name available, or None if none found."""
        ifaces = cls.get_interfaces()
        for iface in ifaces:
            if iface["is_recommended"]:
                return iface["name"]
        for iface in ifaces:
            if iface["is_up"]:
                return iface["name"]
        return ifaces[0]["name"] if ifaces else None

    @classmethod
    def validate_interface(cls, name: str) -> bool:
        """Checks whether the specified interface name exists in psutil."""
        if not name:
            return False
        return name in psutil.net_if_stats()

    @classmethod
    def get_interface_speed(cls, name: str) -> Optional[float]:
        """Gets the link speed in Mbps if reported by the OS driver."""
        stats = psutil.net_if_stats()
        if name in stats and stats[name].speed > 0:
            return float(stats[name].speed)
        return None
