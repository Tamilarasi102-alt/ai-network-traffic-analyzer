"""
Safe Background Packet Capture using Scapy.
Aggregates protocol distribution, flow counts, and packet lengths in memory with store=False.
Gracefully handles Windows Npcap permissions and unavailable devices.
"""
import logging
import threading
from typing import Dict, Any, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Attempt to import Scapy
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    scapy = None


class PacketCaptureWorker:
    """
    Background worker that runs Scapy sniffer on a designated network interface.
    Aggregates only packet metadata (layer types, length, flows).
    Never stores payloads, credentials, or raw packets.
    """

    def __init__(self, interface_name: str):
        self.interface_name = interface_name
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Operational status
        self.status = "Idle"
        self.scapy_available = SCAPY_AVAILABLE
        self.is_degraded = False
        self.error_message: Optional[str] = None

        # Metadata accumulators for the current measurement window
        self._packet_count = 0
        self._total_bytes = 0
        self._tcp_count = 0
        self._udp_count = 0
        self._icmp_count = 0
        self._other_count = 0
        self._flows: Set[Tuple[str, str, int, int, str]] = set()

    def _resolve_scapy_interface(self) -> Optional[Any]:
        """
        Resolve friendly Windows interface name to Scapy capture interface.
        """
        if not SCAPY_AVAILABLE:
            return None

        try:
            # Check if direct name matches
            if hasattr(scapy, "conf") and hasattr(scapy.conf, "ifaces"):
                for dev_key, iface_obj in scapy.conf.ifaces.items():
                    if iface_obj.name == self.interface_name or iface_obj.description == self.interface_name:
                        return dev_key

            # Fallback to get_windows_if_list
            from scapy.arch.windows import get_windows_if_list
            for w in get_windows_if_list():
                if w.get("name") == self.interface_name:
                    guid = w.get("guid")
                    return f"\\Device\\NPF_{guid}"
        except Exception as e:
            logger.debug("Failed resolving Scapy interface for %s: %s", self.interface_name, e)

        return self.interface_name

    def _process_packet(self, pkt):
        """
        Callback executed for each captured packet.
        Aggregates metadata only in memory; stores zero payload.
        """
        pkt_len = len(pkt)
        proto_name = "OTHER"
        flow = None

        try:
            if pkt.haslayer(TCP):
                proto_name = "TCP"
                tcp_layer = pkt.getlayer(TCP)
                src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "")
                dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "")
                flow = (src, dst, getattr(tcp_layer, "sport", 0), getattr(tcp_layer, "dport", 0), "TCP")
            elif pkt.haslayer(UDP):
                proto_name = "UDP"
                udp_layer = pkt.getlayer(UDP)
                src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "")
                dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "")
                flow = (src, dst, getattr(udp_layer, "sport", 0), getattr(udp_layer, "dport", 0), "UDP")
            elif pkt.haslayer(ICMP):
                proto_name = "ICMP"
                src = pkt[IP].src if pkt.haslayer(IP) else ""
                dst = pkt[IP].dst if pkt.haslayer(IP) else ""
                flow = (src, dst, 0, 0, "ICMP")
            else:
                proto_name = "OTHER"
        except Exception:
            proto_name = "OTHER"

        with self._lock:
            self._packet_count += 1
            self._total_bytes += pkt_len
            if proto_name == "TCP":
                self._tcp_count += 1
            elif proto_name == "UDP":
                self._udp_count += 1
            elif proto_name == "ICMP":
                self._icmp_count += 1
            else:
                self._other_count += 1

            if flow and len(self._flows) < 3000:
                self._flows.add(flow)

    def _sniff_loop(self):
        """Background loop executing scapy.sniff."""
        scapy_iface = self._resolve_scapy_interface()
        logger.info("Starting Scapy packet capture worker on interface: %s (scapy device: %s)", self.interface_name, scapy_iface)

        try:
            # Test if sniffing is permitted
            scapy.sniff(
                iface=scapy_iface,
                store=False,
                prn=self._process_packet,
                stop_filter=lambda p: self._stop_event.is_set(),
                timeout=None
            )
            self.status = "Stopped"
        except (OSError, ValueError) as err:
            self.is_degraded = True
            err_str = str(err)
            if any(term in err_str.lower() for term in ("permission", "admin", "not found", "access is denied")):
                self.status = "Admin Permission Required"
                self.error_message = (
                    "Windows Npcap driver is in Admin-Only Mode. "
                    "Deep packet protocol capture requires running Python as Administrator. "
                    "OS-level throughput, PPS, and bandwidth utilization continue normally via psutil."
                )
            else:
                self.status = "Capture Device Error"
                self.error_message = f"Scapy capture error on '{self.interface_name}': {err_str}"
            logger.warning("Scapy capture restricted: %s", self.error_message)
        except Exception as e:
            self.is_degraded = True
            err_str = str(e)
            if any(term in err_str.lower() for term in ("permission", "admin", "not found", "access is denied")):
                self.status = "Admin Permission Required"
                self.error_message = (
                    "Windows Npcap driver is in Admin-Only Mode. "
                    "Deep packet protocol capture requires running Python as Administrator. "
                    "OS-level throughput, PPS, and bandwidth utilization continue normally via psutil."
                )
            else:
                self.status = "Capture Unavailable"
                self.error_message = f"Scapy sniff exception: {type(e).__name__}: {err_str}"
            logger.warning("Scapy capture error: %s", self.error_message)
        finally:
            self.is_running = False

    def start(self) -> bool:
        """Start the background packet sniffer."""
        if self.is_running:
            return True

        self._stop_event.clear()
        self.is_degraded = False
        self.error_message = None

        if not SCAPY_AVAILABLE:
            self.is_degraded = True
            self.status = "Scapy Library Not Installed"
            self.error_message = "Scapy is not installed. Protocol breakdowns unavailable."
            return False

        self.is_running = True
        self.status = "Running"
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True, name="ScapySnifferThread")
        self._thread.start()
        return True

    def stop(self):
        """Cleanly stop the background packet sniffer."""
        if not self.is_running:
            return

        self._stop_event.set()
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self.status = "Stopped"

    def snapshot_and_reset(self) -> Dict[str, Any]:
        """
        Thread-safely returns the current window's accumulated metadata and resets counters.
        """
        with self._lock:
            pkts = self._packet_count
            tot_bytes = self._total_bytes
            tcps = self._tcp_count
            udps = self._udp_count
            icmps = self._icmp_count
            others = self._other_count
            flow_count = len(self._flows)

            # Reset accumulators for the next window
            self._packet_count = 0
            self._total_bytes = 0
            self._tcp_count = 0
            self._udp_count = 0
            self._icmp_count = 0
            self._other_count = 0
            self._flows.clear()

        # Compute proportions
        if pkts > 0:
            tcp_ratio = round(tcps / pkts, 4)
            udp_ratio = round(udps / pkts, 4)
            icmp_ratio = round(icmps / pkts, 4)
            other_ratio = round(others / pkts, 4)
            avg_size = round(tot_bytes / pkts, 1)
        else:
            tcp_ratio = 0.0
            udp_ratio = 0.0
            icmp_ratio = 0.0
            other_ratio = 0.0
            avg_size = 0.0

        return {
            "scapy_packets": pkts,
            "scapy_bytes": tot_bytes,
            "avg_packet_size": avg_size,
            "tcp_count": tcps,
            "udp_count": udps,
            "icmp_count": icmps,
            "other_count": others,
            "tcp_ratio": tcp_ratio,
            "udp_ratio": udp_ratio,
            "icmp_ratio": icmp_ratio,
            "other_ratio": other_ratio,
            "unique_flows": flow_count,
            "scapy_status": self.status,
            "scapy_degraded": self.is_degraded,
            "scapy_message": self.error_message
        }

    def feed_mock_packet(self, proto: str, length: int, flow: Optional[Tuple] = None):
        """Helper for unit tests to verify aggregation without live network capture."""
        with self._lock:
            self._packet_count += 1
            self._total_bytes += length
            if proto.upper() == "TCP":
                self._tcp_count += 1
            elif proto.upper() == "UDP":
                self._udp_count += 1
            elif proto.upper() == "ICMP":
                self._icmp_count += 1
            else:
                self._other_count += 1

            if flow:
                self._flows.add(flow)
