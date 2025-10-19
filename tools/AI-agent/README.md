# SecureAgent v2.0.0 - Production-Grade AI Pentesting Assistant

A secure, auditable, and professional AI-powered pentesting automation tool that uses natural language to orchestrate security testing tools.

## 🎯 Overview

SecureAgent is designed for professional penetration testers, bug bounty hunters, and security researchers who need an intelligent assistant to help automate security testing workflows while maintaining strict authorization controls and comprehensive audit logging.

## ✨ Key Features

- **🤖 AI-Powered Tool Orchestration**: Use natural language to execute complex pentesting workflows
- **🔒 Mandatory Authorization System**: Enforces scope authorization before any scanning
- **📋 Comprehensive Audit Logging**: JSONL format logs for compliance and forensics
- **🛡️ Shell Injection Prevention**: Secure command execution without `shell=True`
- **📊 Structured Result Storage**: JSON-formatted results with metadata
- **🆓 100% Free**: Uses Groq's API (14,400+ requests/day free tier)

## 🚀 Quick Start

### Prerequisites

- Linux system (Kali, Debian, Ubuntu, or Arch)
- Python 3.9+
- sudo access for installing tools
- Internet connection

### Installation

1. **Install Python dependencies:**
```bash
pip install langchain langchain-groq langchain-community pydantic
```

2. **Download the agent:**
```bash
mkdir -p ~/bin
# Copy agent.py to ~/bin/secureagent
chmod +x ~/bin/secureagent
```

3. **Add to PATH:**
```bash
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

4. **Get your free Groq API key:**
   - Visit https://console.groq.com
   - Sign up (no credit card required)
   - Create an API key
   - Save it for first run

5. **First run:**
```bash
secureagent "hello"
# You'll be prompted to enter your API key
```

## 📚 Usage Examples

### Basic Scanning
```bash
# Authorize scope and scan
secureagent "set scope to 192.168.1.100 and scan with nmap"

# Web vulnerability scanning
secureagent "scan 192.168.1.100 for web vulnerabilities"
```

### Tool Management
```bash
# Get tool recommendations
secureagent "what tools should I use for web application testing?"

# Install a tool
secureagent "install nikto"

# List all available tools
secureagent --list-tools
```

### Advanced Workflows
```bash
# Multi-step enumeration
secureagent "set scope to example.com, enumerate subdomains, then scan each with nmap"

# OSINT gathering
secureagent "gather information about example.com using theharvester"
```

### Informational Commands
```bash
# View authorized scopes
secureagent --list-scopes

# View audit log
secureagent --audit-log

# View help
secureagent --help
```

## 🔧 Supported Tools

SecureAgent includes 18+ pentesting tools across multiple categories:

### Scanning
- nmap - Network scanner
- masscan - Fast TCP port scanner
- rustscan - Modern fast port scanner

### Web Application Testing
- nikto - Web server vulnerability scanner
- sqlmap - SQL injection tool
- gobuster - Directory/file brute-forcing
- ffuf - Fast web fuzzer
- whatweb - Web technology fingerprinting
- wpscan - WordPress vulnerability scanner

### Password Attacks
- hydra - Network logon cracker
- john - John the Ripper
- hashcat - Advanced password recovery

### OSINT
- theharvester - Email/subdomain harvester
- dnsenum - DNS enumeration
- dnsrecon - DNS reconnaissance

### Network Analysis
- wireshark/tshark - Protocol analyzer
- tcpdump - Packet capture

### Exploitation
- metasploit-framework
- searchsploit - Exploit database

## 🔒 Security Features

### 1. Authorization System
- SHA256 scope hashing for unique identification
- Persistent authorization storage
- Interactive authorization prompts
- Explicit user confirmation required

### 2. Shell Injection Prevention
- Uses `shell=False` for all subprocess calls
- Command validation for dangerous characters
- Argument list parsing (never string concatenation)
- Tool existence verification

### 3. Audit Logging
- JSONL format for easy parsing
- Logs all commands, installations, and authorizations
- Includes exit codes, duration, and scope information
- SIEM integration ready

### 4. Input Validation
- Pydantic models for type safety
- IP/CIDR/domain format validation
- Automatic validation before execution

### 5. Secure Credential Management
- Environment variable support
- Config file with 600 permissions
- Never logged or displayed
- Rotation-friendly design

## 📁 Directory Structure

After installation, SecureAgent creates:

```
~/.secureagent/
├── config.json              # API key (600 permissions)
├── authorized_scopes.json   # Authorized targets
├── audit.jsonl             # Audit log
├── logs/                   # Execution logs
│   └── agent_YYYYMMDD_HHMMSS.log
└── results/                # Scan results
    └── {scope_hash}_{timestamp}.json
```

## ⚖️ Legal & Ethical Use

**⚠️ CRITICAL WARNING**: Unauthorized network scanning is ILLEGAL in most jurisdictions.

### Legal Use Cases ONLY:
✅ Your own systems and networks  
✅ Systems with explicit written authorization  
✅ Bug bounty programs (within scope)  
✅ Authorized penetration testing contracts  
✅ Security research labs (HackTheBox, TryHackMe)  
✅ Educational environments with permission  

### NEVER scan:
❌ Systems without written permission  
❌ Neighbors' networks  
❌ Production systems without authorization  
❌ Any target outside your authorized scope  

**Penalties for unauthorized scanning include criminal prosecution, fines, and imprisonment.**

## 🛠️ Advanced Configuration

### Custom Config Directory
```bash
secureagent --config-dir ~/projects/client-pentest/.secureagent "scan target"
```

### Environment Variables
```bash
export GROQ_API_KEY="gsk_your_key_here"
export SECUREAGENT_MODEL="llama-3.3-70b-versatile"
```

### Alternative AI Models
- `llama-3.3-70b-versatile` (default, best)
- `llama-3.1-70b-versatile` (good fallback)
- `llama-3.1-8b-instant` (faster, less capable)
- `mixtral-8x7b-32768` (alternative architecture)

## 🐛 Troubleshooting

### Command not found
```bash
export PATH="$HOME/bin:$PATH"
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
```

### Missing dependencies
```bash
pip install --upgrade langchain langchain-groq langchain-community pydantic
```

### API key issues
```bash
# Check current config
cat ~/.secureagent/config.json

# Or use environment variable
export GROQ_API_KEY="gsk_your_actual_key"
```

### View logs for debugging
```bash
tail -f ~/.secureagent/logs/agent_*.log
```

## 📊 Architecture

```
┌─────────────────┐
│   CLI Interface │
└────────┬────────┘
         │
┌────────▼────────┐
│  SecureAgent    │
└────────┬────────┘
         │
    ┌────┴────┬──────────┬────────────┐
    │         │          │            │
┌───▼──┐ ┌───▼───┐ ┌────▼────┐ ┌────▼─────┐
│Security│ │Tool   │ │Secure   │ │Agent     │
│Manager│ │Manager│ │Executor │ │Tools     │
└───────┘ └───────┘ └─────────┘ └──────────┘
         │
    ┌────▼────┐
    │ Groq LLM│
    └─────────┘
```

## 📖 Documentation

- **UsageGuide.txt**: Complete installation and usage guide
- **agent.py**: Main Python script with inline documentation
- **README.md**: This file

## 🤝 Contributing

This is a portfolio project. Feel free to fork and adapt for your own use, but please:
- Always maintain the authorization system
- Never remove security features
- Use responsibly and legally

## 📄 License

MIT License - See code header for details

## ⚡ Version History

**v2.0.0** (Current)
- Production-grade security features
- Modular architecture
- Comprehensive audit logging
- Shell injection prevention
- Modern LangChain integration

## 🔗 Resources

- Groq API: https://console.groq.com
- LangChain Docs: https://python.langchain.com/docs/
- Kali Linux: https://www.kali.org/
- HackTheBox: https://hackthebox.eu
- TryHackMe: https://tryhackme.com

---

**Remember**: With great power comes great responsibility. Always obtain proper authorization before scanning any systems.
