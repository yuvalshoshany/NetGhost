---

# ShadowPcap

Lightweight, streaming PCAP IP extractor for malware and network-forensics practice — built with **dpkt**. ShadowPcap reads PCAP files, extracts all unique IPv4 and IPv6 addresses (source and destination), optionally filters out private addresses, and outputs results for analysis.

---

## Features

* Streaming PCAP parsing using **dpkt** for low memory usage
* Extracts both IPv4 and IPv6 addresses
* Optional filtering to exclude private (RFC1918) addresses
* Outputs results to console, CSV, or JSON
* Handles malformed packets gracefully
* Lightweight and easy to modify for classroom or lab exercises

---

## Getting Started

### Prerequisites

* Python 3.8 or higher
* `dpkt` Python library

Install dependencies using pip:

```
pip install dpkt
```

> Tip: Run ShadowPcap inside a sandbox or isolated VM when working with PCAPs that may contain malicious traffic.

---

## Usage

1. Place your PCAP file in the project directory.
2. Run ShadowPcap to extract IPs and print to the console.
3. Optionally, exclude private addresses using the `--no-private` option.
4. Output can be saved to CSV or JSON for further analysis by specifying the `--output` option and an output file path.

---

## Example Workflow

* Extract all IPs and display them in the terminal
* Exclude private IPs if needed
* Save the results to CSV or JSON for reporting or sharing

---

## Sample Data Sources

Use publicly available PCAPs for testing and learning:

* **Malware-Traffic-Analysis**: curated exercises and PCAPs
* **Wireshark SampleCaptures**: official protocol examples
* **Netresec PCAP Repository**: malware and network traffic datasets
* **Security Onion Community Datasets**: intrusion detection datasets

> **Important:** Treat PCAPs as potentially dangerous if they contain payloads. Analyze them only in a sandbox or isolated VM. Do not execute binaries extracted from PCAPs on your host machine.

---

## Contributing

Contributions and improvements are welcome. Possible contributions include:

* Adding filters for ports, protocols, or time windows
* Supporting additional PCAP formats such as pcapng
* Integrating with command-line tools like `tshark` for large captures
* Adding GUI or web dashboard support for classroom demos

---

## License

This project is licensed under the **MIT License**. See `LICENSE` for details.

---

## Acknowledgements

* **dpkt** — for fast and lightweight PCAP parsing
* Malware analysis exercises and public PCAP datasets that enable safe learning
