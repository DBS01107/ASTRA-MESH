# Scanner Installation Guide

## Missing Tools & Wordlists

### 1. Install SSLyze (SSL/TLS Scanner)
```bash
sudo apt update
sudo apt install -y python3-pip
pip3 install sslyze
```

### 2. Install Wordlists for DIRB/FFUF
```bash
# Install dirb (includes wordlists)
sudo apt install -y dirb

# Or download wordlists manually
sudo mkdir -p /usr/share/wordlists/dirb
sudo wget https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -O /usr/share/wordlists/dirb/common.txt
```

### 3. Install Additional Security Scanners
```bash
# Wapiti (Web Application Scanner)
sudo apt install -y wapiti

# Skipfish (Web Application Security Scanner)
sudo apt install -y skipfish

# Enum4linux (SMB Enumeration)
sudo apt install -y enum4linux

# WPScan (WordPress Scanner)
sudo gem install wpscan

# JoomScan (Joomla Scanner)
git clone https://github.com/OWASP/joomscan.git /opt/joomscan
sudo ln -s /opt/joomscan/joomscan.pl /usr/local/bin/joomscan
```

### 4. Fix Nmap Root Privileges
For advanced Nmap scans (SYN scan, OS detection):
```bash
# Option 1: Run server with sudo (NOT RECOMMENDED for production)
sudo PYTHONPATH=. /home/sadist/ASTRA/.venv/bin/python orchestrator/server.py

# Option 2: Give nmap capabilities (SAFER)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

### 5. SQLMap (Already installed but verify)
```bash
# Install if missing
sudo apt install -y sqlmap
```

### 6. SearchSploit (ExploitDB CLI)
```bash
# Install ExploitDB package (includes searchsploit)
sudo apt install -y exploitdb
```

## Quick Install All
```bash
# Install all tools at once
sudo apt update && sudo apt install -y \
    dirb \
    wapiti \
    skipfish \
    enum4linux \
    exploitdb \
    sqlmap \
    nikto \
    whatweb

# Python-based tools
pip3 install sslyze

# Set nmap capabilities
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

## Verify Installation
```bash
# Check which tools are available
which nmap nikto dirb ffuf sqlmap wpscan sslyze enum4linux wapiti skipfish searchsploit
```

## Notes
- Most tools require **root/sudo** for installation
- Some tools (like nmap advanced features) need elevated privileges to run
- WPScan and JoomScan are optional - only needed for WordPress/Joomla targets
- The orchestrator will skip tools that aren't installed
