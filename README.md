# Cybersecurity Portfolio

A comprehensive collection of cybersecurity tools and scripts for penetration testing, reconnaissance, and security research.

## ⚠️ **DISCLAIMER**
These tools are for **EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**. 
- Only use against systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- User assumes all responsibility for proper usage

## 🛠️ **Tools Overview**

### 🔍 **Reconnaissance**
- **Andromalius Recon** - Production-ready automated Phase 1 reconnaissance for bug bounty hunting
  - Location: `tools/ars-goetia/recon/`
  - Features: Subdomain enumeration, technology detection, live host discovery

### 🌐 **Web Security**
- **PHP Web Shells** - Simple shells for penetration testing
  - Basic Shell: `tools/web-security/php-web-shells/basic_shell.php`
  - Image Header Shell: `tools/web-security/php-web-shells/img_header_shell.php`
- **Orobas** - Command injection exploit for OverTheWire Natas16
  - Location: `tools/python/web-security/natas16/orobas.py`

### 🔐 **Cryptography**
- **XOR Key Recovery** - Tool for analyzing XOR-encrypted data
  - Location: `tools/cryptography/XORkey_recovery.py`
  - Use case: Breaking weak XOR encryption

## 🚀 **Quick Start**

### Prerequisites
```bash
# Python dependencies
pip install requests dnspython

# System tools (Linux/macOS)
sudo apt-get install subfinder amass nmap
```

### Usage Examples
```bash
# Run reconnaissance
cd tools/ars-goetia/recon/
python3 andromalius_recon.py -t example.com -o ./results

# Use command injection tool
cd tools/python/web-security/natas16/
python3 orobas.py
```

## 📁 **Directory Structure**
```
cybersecurity-portfolio/
├── tools/
│   ├── ars-goetia/
│   │   └── recon/           # Reconnaissance tools
│   ├── cryptography/        # Cryptographic analysis tools
│   ├── python/
│   │   └── web-security/    # Python web security tools
│   └── web-security/
│       └── php-web-shells/  # PHP penetration testing shells
└── README.md
```

## 🤝 **Contributing**
1. Follow responsible disclosure practices
2. Test tools only on authorized targets
3. Document all tools with proper usage examples
4. Include security warnings where appropriate

## 📜 **License**
Educational use only. See individual tool headers for specific licensing information.