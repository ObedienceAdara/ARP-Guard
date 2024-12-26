
# ARPGuard - Enhanced ARP Spoofing Detection Tool

`ARPGuard` is a robust Python tool designed to detect and mitigate ARP spoofing attacks on your network. It combines network scanning, packet analysis, and advanced logging to help secure your environment against potential threats.

## Features

- **Real-time ARP Traffic Monitoring:** Detect ARP spoofing and anomalies as they happen.
- **MAC-IP Mapping:** Maintains a historical record of MAC-IP associations.
- **Suspicious Activity Logging:** Tracks and logs ARP-related threats for detailed analysis.
- **Customizable Configuration:** Supports user-defined network ranges, trusted MAC addresses, and logging levels.
- **SQLite Database Integration:** Persistent storage of ARP events and history.
- **Detailed Reporting:** Generate security reports in text or JSON format.

---

## Installation

### Prerequisites
- Python 3.8 or newer
- Required libraries (install via pip):
  ```bash
  pip install scapy pyyaml
  ```

### Clone the Repository
```bash
git clone https://github.com/obedienceadara/arp_guard.git
cd arp_guard
```

---

## Configuration

### Config File
Update the `config.yaml` file to suit your network environment. Example:
```yaml
network_range: "192.168.1.0/24"
scan_interval: 300
database_path: "arp_guard.db"
trusted_macs:
  - "00:11:22:33:44:55"
log_level: "INFO"
log_file: "arp_guard.log"
alert_threshold: 5
```

---

## Usage

### Basic Command
Run the script with the required options:
```bash
python3 arp_guard.py -i <network_interface>
```

### Options
- `-i, --interface` (required): Specify the network interface to monitor.
- `-c, --config`: Path to the configuration file (default: `config.yaml`).
- `-t, --time`: Duration to monitor (in seconds). Default is continuous monitoring.
- `-f, --format`: Report format (`text` or `json`).

Example:
```bash
python3 arp_guard.py -i eth0 -c config.yaml -t 600 -f json
```

---

## Features Overview

### Start Monitoring
ARPGuard scans your network to establish baseline MAC-IP mappings and begins monitoring ARP traffic:
```bash
python3 arp_guard.py -i eth0
```

### Reporting
View activity reports in real-time:
```bash
python3 arp_guard.py -i eth0 -f text
```

### Database
All events and historical MAC-IP mappings are stored in a SQLite database (`arp_guard.db`).

---

## Handling Shutdown
Press `CTRL+C` to gracefully stop monitoring and generate a final report.

---

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes and open a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contact

For any inquiries, please contact [obedienceadara@gmail.com](mailto:obedienceadara@gmail.com).

Happy Monitoring! 🚀

NOTE: This README was generated with the help of AI
```
