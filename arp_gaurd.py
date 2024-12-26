#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import time
from collections import defaultdict
import threading
import logging
from datetime import datetime
import json
import ipaddress
import signal
import sqlite3
from pathlib import Path
import yaml

class ARPGuard:
    def __init__(self, interface, config_path=None):
        self.interface = interface
        self.mac_ip_mappings = defaultdict(set)
        self.suspicious_activity = []
        self.lock = threading.Lock()
        self.is_running = True
        self.packet_stats = defaultdict(int)
        
        # Load configuration
        self.config = self.load_config(config_path)
        
        # Initialize database
        self.db_path = Path(self.config.get('database_path', 'arp_guard.db'))
        self.init_database()
        
        # Configure logging
        self._setup_logging()

    def load_config(self, config_path):
        """Load configuration from YAML file."""
        default_config = {
            'network_range': '192.168.1.0/24',
            'scan_interval': 300,
            'database_path': 'arp_guard.db',
            'trusted_macs': [],
            'log_level': 'INFO',
            'log_file': 'arp_guard.log',
            'alert_threshold': 5
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config

    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config['log_level'].upper())
        log_format = '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(self.config['log_file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def init_database(self):
        """Initialize SQLite database for storage."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS arp_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    mac_address TEXT,
                    ip_address TEXT,
                    description TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS mac_ip_history (
                    mac_address TEXT,
                    ip_address TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    PRIMARY KEY (mac_address, ip_address)
                )
            ''')

    def store_event(self, event_type, mac_address, ip_address, description):
        """Store security event in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'INSERT INTO arp_events (timestamp, event_type, mac_address, ip_address, description) '
                'VALUES (datetime("now"), ?, ?, ?, ?)',
                (event_type, mac_address, ip_address, description)
            )

    def update_mac_ip_history(self, mac_address, ip_address):
        """Update MAC-IP mapping history."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO mac_ip_history (mac_address, ip_address, first_seen, last_seen)
                VALUES (?, ?, datetime("now"), datetime("now"))
                ON CONFLICT(mac_address, ip_address) 
                DO UPDATE SET last_seen = datetime("now")
            ''', (mac_address, ip_address))

    def get_original_mappings(self):
        """Get the original MAC-IP mappings on the network"""
        try:
            network = ipaddress.ip_network(self.config['network_range'])
            for subnet in network.subnets(new_prefix=network.max_prefixlen):
                arp_request = scapy.ARP(pdst=str(subnet.network_address))
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                
                answered_list = scapy.srp(
                    arp_request_broadcast,
                    timeout=1,
                    verbose=False,
                    retry=2
                )[0]

                for element in answered_list:
                    ip = element[1].psrc
                    mac = element[1].hwsrc
                    with self.lock:
                        self.mac_ip_mappings[mac].add(ip)
                        self.update_mac_ip_history(mac, ip)
                        self.logger.info(f"Original mapping: {mac} -> {ip}")
                
                time.sleep(0.1)  # Prevent flooding the network
                
        except Exception as e:
            self.logger.error(f"Error during network scanning: {str(e)}")

    def is_trusted_mac(self, mac_address):
        """Check if a MAC address is in the trusted list."""
        return mac_address in self.config['trusted_macs']

    def analyze_packet(self, packet):
        """Analyze ARP packets for potential spoofing with enhanced detection."""
        if not packet.haslayer(scapy.ARP):
            return

        try:
            arp = packet[scapy.ARP]
            if arp.op != 2:  # Not an ARP reply
                return

            self.packet_stats['total_packets'] += 1
            
            real_mac = packet[scapy.Ether].src
            claimed_mac = arp.hwsrc
            claimed_ip = arp.psrc
            target_ip = arp.pdst

            # Skip trusted MAC addresses
            if self.is_trusted_mac(claimed_mac):
                return

            suspicious_activity = []

            # Check for MAC address inconsistencies
            if real_mac != claimed_mac:
                suspicious_activity.append(f"MAC address mismatch: {real_mac} vs {claimed_mac}")
                self.packet_stats['mac_mismatches'] += 1

            # Check for new MAC-IP mappings
            with self.lock:
                for mac, ips in self.mac_ip_mappings.items():
                    if claimed_ip in ips and mac != claimed_mac:
                        suspicious_activity.append(
                            f"IP {claimed_ip} claimed by new MAC {claimed_mac} (originally {mac})"
                        )
                        self.packet_stats['ip_conflicts'] += 1

                # Check for rapid IP changes
                if len(self.mac_ip_mappings[claimed_mac]) >= self.config['alert_threshold']:
                    suspicious_activity.append(
                        f"MAC {claimed_mac} associated with multiple IPs: {self.mac_ip_mappings[claimed_mac]}"
                    )
                    self.packet_stats['multiple_ip_warnings'] += 1

                # Update mappings
                self.mac_ip_mappings[claimed_mac].add(claimed_ip)
                self.update_mac_ip_history(claimed_mac, claimed_ip)

            # Record suspicious activities
            for activity in suspicious_activity:
                self._record_suspicious_activity(activity)
                self.store_event("SUSPICIOUS", claimed_mac, claimed_ip, activity)

        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            self.packet_stats['errors'] += 1

    def _record_suspicious_activity(self, message):
        """Record suspicious activity with enhanced logging."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.lock:
            self.suspicious_activity.append(f"{timestamp} - {message}")
            self.logger.warning(message)

    def generate_report(self, format='text'):
        """Generate a detailed security report in multiple formats."""
        with self.lock:
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'mac_ip_mappings': {
                    mac: list(ips) for mac, ip in self.mac_ip_mappings.items()
                },
                'suspicious_activity': self.suspicious_activity,
                'packet_stats': dict(self.packet_stats)
            }

        if format == 'json':
            return json.dumps(report_data, indent=2)
        else:
            report = "\nARP Guard Security Report\n"
            report += "=" * 50 + "\n"
            report += f"Generated at: {report_data['timestamp']}\n\n"
            
            report += "Packet Statistics:\n"
            for stat, value in report_data['packet_stats'].items():
                report += f"  {stat}: {value}\n"
            
            report += "\nCurrent MAC-IP Mappings:\n"
            for mac, ips in report_data['mac_ip_mappings'].items():
                report += f"{mac}: {', '.join(ips)}\n"
            
            report += "\nSuspicious Activity Log:\n"
            for activity in report_data['suspicious_activity']:
                report += f"{activity}\n"
            
            return report

    def start_monitoring(self):
        """Start monitoring ARP traffic with graceful shutdown."""
        self.logger.info(f"Starting ARP monitoring on interface {self.interface}")
        self.get_original_mappings()
        
        try:
            scapy.sniff(
                iface=self.interface,
                store=False,
                prn=self.analyze_packet,
                filter="arp",
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            self.logger.error(f"Error during packet capture: {str(e)}")

    def stop_monitoring(self):
        """Gracefully stop monitoring."""
        self.is_running = False
        self.logger.info("Stopping ARP monitoring...")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global arp_guard
    if arp_guard:
        arp_guard.stop_monitoring()

def main():
    parser = argparse.ArgumentParser(description='ARP Guard - Enhanced ARP Spoofing Detection Tool')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to monitor')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-t', '--time', type=int, default=0, help='Monitoring duration in seconds (0 for continuous)')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text', help='Report format')
    args = parser.parse_args()

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    global arp_guard
    arp_guard = ARPGuard(args.interface, args.config)
    
    # Start monitoring in a separate thread
    monitor_thread = threading.Thread(target=arp_guard.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()

    try:
        if args.time > 0:
            time.sleep(args.time)
        else:
            while arp_guard.is_running:
                time.sleep(arp_guard.config['scan_interval'])
                print(arp_guard.generate_report(args.format))
    except KeyboardInterrupt:
        pass
    finally:
        arp_guard.stop_monitoring()
        print("\nGenerating final report...")
        print(arp_guard.generate_report(args.format))
        print("ARP Guard monitoring stopped.")

if __name__ == "__main__":
    main()
