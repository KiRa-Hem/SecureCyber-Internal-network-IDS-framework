import threading
import queue
import time
import json
import logging
import os
import sys
from typing import Dict, Any, Optional, List
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.http import HTTP
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet

from app.config import settings
from app.cache import cache_manager
from app.metrics import metrics_collector
try:
    from scapy.arch import get_if_list
except Exception:  # pragma: no cover - optional dependency path
    get_if_list = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self, interface="auto", capture_filter="tcp or udp"):
        self.interface = interface
        self.capture_filter = capture_filter
        self.packet_queue = queue.Queue()
        self.running = False
        self.capture_thread = None
        self.processing_thread = None
        self.packet_callbacks = []
        self.interface_label = None
        
        # Windows-specific settings
        self.is_windows = os.name == 'nt'
        self._select_interface()

    def _select_interface(self):
        """Resolve the capture interface when running in auto mode."""
        if self.interface != "auto":
            if self.is_windows:
                self.interface_label = self.interface
            return

        if self.is_windows:
            try:
                interfaces = self._windows_interfaces()
                best = self._select_best_windows_interface(interfaces)
                if best:
                    self.interface = best.get("guid") or best.get("name") or "Ethernet"
                    self.interface_label = best.get("name") or best.get("description") or self.interface
                else:
                    logger.warning("No suitable interface found, using Ethernet")
                    self.interface = "Ethernet"
                    self.interface_label = "Ethernet"
            except ImportError:
                logger.error("Scapy Windows modules not available. Make sure Npcap is installed correctly.")
            return

        if get_if_list is None:
            logger.warning("Scapy interface discovery unavailable; using eth0")
            self.interface = "eth0"
            return

        try:
            interfaces = get_if_list()
            for iface in interfaces:
                if iface not in ['lo', 'Loopback']:
                    self.interface = iface
                    break
            if self.interface == "auto":
                logger.warning("No suitable interface found, using eth0")
                self.interface = "eth0"
        except Exception as exc:
            logger.error("Error selecting interface: %s", exc)
            self.interface = "eth0"
        
    def start_capture(self):
        """Start packet capture in a separate thread."""
        if self.running:
            logger.warning("Packet capture already running")
            return
        
        # Check if running on Windows and if Npcap is available
        if self.is_windows:
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                if not interfaces:
                    logger.error("No network interfaces found. Make sure Npcap is installed with WinPcap API-compatible Mode.")
                    return
            except ImportError:
                logger.error("Scapy Windows modules not available. Make sure Npcap is installed correctly.")
                return
        
        self.running = True
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._process_packets)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        logger.info(f"Packet capture started on interface {self.interface}")
    
    def stop_capture(self):
        """Stop packet capture."""
        if not self.running:
            return
        
        self.running = False
        
        # Wait for threads to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=1)
        
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=1)
        
        logger.info("Packet capture stopped")
    
    def _capture_packets(self):
        """Capture packets using Scapy."""
        try:
            # Auto-select interface
            if self.interface == "auto":
                if self.is_windows:
                    interfaces = self._windows_interfaces()
                    best = self._select_best_windows_interface(interfaces)
                    if best:
                        self.interface = best.get("guid") or best.get("name") or "Ethernet"
                        self.interface_label = best.get("name") or best.get("description") or self.interface
                    if not self.interface or self.interface == "auto":
                        logger.warning("No suitable interface found, using Ethernet")
                        self.interface = "Ethernet"
                        self.interface_label = "Ethernet"
                else:
                    from scapy.arch import get_if_list
                    interfaces = get_if_list()
                    
                    # Find a suitable interface
                    for iface in interfaces:
                        if iface not in ['lo', 'Loopback']:
                            self.interface = iface
                            break
                    
                    if self.interface == "auto":
                        logger.warning("No suitable interface found, using eth0")
                        self.interface = "eth0"
            else:
                self._select_interface()
            
            label = self.interface_label or self.interface
            logger.info(f"Capturing on interface {label} with filter '{self.capture_filter}'")
            
            # For Windows, we need to use a different approach
            if self.is_windows:
                # On Windows, we need to use the Windows-specific capture method
                pcap_iface = self._resolve_windows_pcap_iface(self.interface)
                if pcap_iface:
                    sniff(
                        iface=pcap_iface,
                        filter=self.capture_filter,
                        prn=self._packet_callback,
                        stop_filter=lambda x: not self.running,
                        store=False
                    )
                else:
                    logger.error(f"Could not resolve Windows adapter for interface {self.interface}")
                    self.running = False
            else:
                # Unix-like systems
                sniff(
                    iface=self.interface,
                    filter=self.capture_filter,
                    prn=self._packet_callback,
                    stop_filter=lambda x: not self.running,
                    store=False
                )
            
        except PermissionError:
            logger.error("Permission denied. Try running as Administrator.")
            self.running = False
        except Exception as e:
            logger.error(f"Error capturing packets: {e}")
            self.running = False
    
    def _packet_callback(self, packet):
        """Callback for each captured packet."""
        try:
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                self.packet_queue.put(packet_info)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Extract relevant information from a packet."""
        try:
            info = {
                'timestamp': time.time(),
                'size': len(packet)
            }
            
            # Extract IP layer
            if IP in packet:
                info['src_ip'] = packet[IP].src
                info['dst_ip'] = packet[IP].dst
                info['protocol'] = packet[IP].proto
                
                # Extract transport layer
                if TCP in packet:
                    info['src_port'] = packet[TCP].sport
                    info['dst_port'] = packet[TCP].dport
                    info['flags'] = packet[TCP].flags
                    info['protocol_name'] = 'TCP'
                elif UDP in packet:
                    info['src_port'] = packet[UDP].sport
                    info['dst_port'] = packet[UDP].dport
                    info['protocol_name'] = 'UDP'
                elif ICMP in packet:
                    info['protocol_name'] = 'ICMP'
                
                # Extract payload
                if Raw in packet:
                    payload_bytes = bytes(packet[Raw].payload)
                    payload_sample = payload_bytes[:512]
                    info['payload_hex'] = payload_sample.hex()
                    info['payload'] = self._decode_payload(payload_sample)
                    
                    # Try to decode as HTTP
                    if info['protocol_name'] == 'TCP' and info['dst_port'] in [80, 443, 8080]:
                        try:
                            http_payload = info['payload']
                            if 'HTTP' in http_payload:
                                info['http_method'] = self._extract_http_method(http_payload)
                                info['http_host'] = self._extract_http_host(http_payload)
                                info['http_path'] = self._extract_http_path(http_payload)
                        except:
                            pass
            
            return info
            
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _extract_http_method(self, payload: str) -> Optional[str]:
        """Extract HTTP method from payload."""
        try:
            lines = payload.split('\r\n')
            if lines:
                first_line = lines[0]
                parts = first_line.split(' ')
                if parts and parts[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']:
                    return parts[0]
        except:
            pass
        return None

    @staticmethod
    def _decode_payload(payload: bytes) -> str:
        """Decode payload bytes into best-effort text for signature matching."""
        if not payload:
            return ""
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            return payload.decode("latin-1", errors="ignore")

    def _windows_interfaces(self):
        from scapy.arch.windows import get_windows_if_list
        return get_windows_if_list()

    def _select_best_windows_interface(self, interfaces):
        if not interfaces:
            return None

        def is_link_local(ip: str) -> bool:
            return ip.startswith("169.254.") or ip.startswith("127.")

        def score(iface):
            name = (iface.get("name") or "").lower()
            desc = (iface.get("description") or "").lower()
            mac = iface.get("mac") or ""
            ips = iface.get("ips") or []
            ipv4s = [ip for ip in ips if ip.count(".") == 3]
            has_ipv4 = any(ipv4s) and any(not is_link_local(ip) for ip in ipv4s)
            prefer_name = name in {"wi-fi", "wifi", "ethernet", "ethernet 2"}
            is_virtual = any(
                key in desc
                for key in (
                    "virtual",
                    "vmware",
                    "wintun",
                    "npcap packet driver",
                    "wfp",
                    "wan miniport",
                    "tunnel",
                    "wi-fi direct",
                    "loopback",
                )
            )
            is_virtual = is_virtual or name.startswith("local area connection*")
            return (
                int(not is_virtual),
                int(has_ipv4),
                int(bool(mac)),
                int(prefer_name),
                len(ipv4s),
            )

        candidates = sorted(interfaces, key=score, reverse=True)
        return candidates[0] if candidates else None

    def _resolve_windows_pcap_iface(self, interface: str) -> Optional[str]:
        if not interface:
            return None
        if interface.startswith("\\\\Device\\\\NPF_"):
            return interface
        if interface.startswith("{") and interface.endswith("}"):
            return f"\\\\Device\\\\NPF_{interface}"

        interfaces = self._windows_interfaces()
        target = interface.lower()
        for iface in interfaces:
            if (iface.get("name") or "").lower() == target or (iface.get("description") or "").lower() == target:
                guid = iface.get("guid")
                if guid:
                    return f"\\\\Device\\\\NPF_{guid}"
        return None
    
    def _extract_http_host(self, payload: str) -> Optional[str]:
        """Extract HTTP Host header from payload."""
        try:
            lines = payload.split('\r\n')
            for line in lines:
                if line.startswith('Host: '):
                    return line.split(': ')[1].strip()
        except:
            pass
        return None
    
    def _extract_http_path(self, payload: str) -> Optional[str]:
        """Extract HTTP path from payload."""
        try:
            lines = payload.split('\r\n')
            if lines:
                first_line = lines[0]
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    return parts[1]
        except:
            pass
        return None
    
    def _process_packets(self):
        """Process captured packets."""
        while self.running or not self.packet_queue.empty():
            try:
                # Get packet from queue with timeout
                packet_info = self.packet_queue.get(timeout=1)
                
                # Update metrics
                metrics_collector.record_packet()
                
                # Process packet through detectors
                self._process_through_detectors(packet_info)
                
                # Call registered callbacks
                for callback in self.packet_callbacks:
                    try:
                        callback(packet_info)
                    except Exception as e:
                        logger.error(f"Error in packet callback: {e}")
                
            except queue.Empty:
                if not self.running:
                    break
                continue
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
    
    def _process_through_detectors(self, packet_info: Dict[str, Any]):
        """Process packet through all detectors."""
        # This would be implemented to call the actual detectors
        # For now, we'll just cache the packet for demo purposes
        pass
    
    def add_packet_callback(self, callback):
        """Add a callback to be called for each processed packet."""
        self.packet_callbacks.append(callback)
    
    def get_interface_help(self):
        """Get help text for interface configuration."""
        help_text = """
Packet Capture Interface Configuration
====================================

Windows:
1. Npcap must be installed with 'WinPcap API-compatible Mode'
2. Run the application as Administrator for packet capture
3. To list available interfaces, run:
   python -c "from scapy.arch.windows import get_windows_if_list; print([i['name'] for i in get_windows_if_list()])"
4. Common interface names: 'Ethernet', 'Wi-Fi', 'Local Area Connection'

Linux/macOS:
1. To capture on a specific interface: sudo python -m app.main
2. To set capabilities for non-root capture: sudo setcap cap_net_raw+ep $(readlink -f $(which python))
3. List available interfaces: python -c "from scapy.arch import get_if_list; print(get_if_list())"

Demo Mode:
If you don't have permissions or want to test without real capture:
1. Set ENABLE_PACKET_CAPTURE=false in .env
2. The system will use simulated traffic instead
"""
        return help_text
