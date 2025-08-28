# NetMapper — Network Scanner (C + GTK3)

NetMapper scans your local IPv4 network to discover live hosts and displays information for each device:

- IP address
- Hostname (reverse DNS if available)
- MAC address (from `/proc/net/arp`)
- Open common TCP ports

It is written in C with a GTK3 GUI. The tool performs a ping sweep, reads the ARP table, and does a quick TCP connect scan.  

> **Disclaimer:** Run only on networks you own or have explicit permission to test. Misuse may be illegal.

---

## Features

- Auto-detects your primary IPv4 network and subnet
- Ping sweep to find live hosts
- Reads MAC addresses from the ARP table
- Quick TCP port scan on common ports
- GUI table showing all discovered devices
- Concurrent scanning with configurable thread count

---

## Requirements (Linux)

- Linux desktop (tested on Ubuntu/Debian)
- GTK3 development libraries
- build-essential (gcc, make)

Install dependencies:

```bash
sudo apt update
sudo apt install build-essential libgtk-3-dev pkg-config
```

### Usage

```bash
make                                                         
sudo bin/netmapper
```
