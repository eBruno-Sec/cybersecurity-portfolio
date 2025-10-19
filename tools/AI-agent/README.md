

```markdown
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
- sudo access for installing pentesting tools
- Internet connection
- Git (optional, for cloning the repo)

### Complete Installation (Copy-Paste Commands)

**Step 1: Create and activate virtual environment**
```bash
python3 -m venv ~/secureagent-env
source ~/secureagent-env/bin/activate
```

**Step 2: Install Python dependencies with compatible versions**
```bash
pip install --upgrade pip
pip install langchain==0.1.0 langchain-groq langchain-community pydantic
```

**Step 3: Download SecureAgent from GitHub**
```bash
mkdir -p ~/bin
curl -o ~/bin/secureagent https://raw.githubusercontent.com/eBruno-Sec/cybersecurity-portfolio/main/tools/AI-agent/agent.py
chmod +x ~/bin/secureagent
```

**Step 4: Add to PATH (for Zsh - Kali default)**
```bash
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**For Bash users (Ubuntu/Debian), use this instead:**
```bash
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Step 5: Verify installation**
```bash
which secureagent
```

Expected output: `/home/kali/bin/secureagent` (or `/home/yourusername/bin/secureagent`)

**Step 6: Get your FREE Groq API key**

1. Visit: https://console.groq.com
2. Click "Sign Up" (free, no credit card required)
3. After login, go to "API Keys" in the left sidebar
4. Click "Create API Key"
5. Copy the key (starts with `gsk_`)
6. **SAVE IT** - you'll need it in the next step

**Step 7: First run and API key setup**
```bash
secureagent "hello"
```

You'll be prompted to enter your Groq API key. Paste it when asked.

---

### Important: Using SecureAgent in New Terminal Sessions

**Every time you open a new terminal**, you must activate the virtual environment first:

```bash
source ~/secureagent-env/bin/activate
secureagent "your command here"
```

**Optional: Create a convenient alias** (add to `~/.zshrc` or `~/.bashrc`):
```bash
echo 'alias secureagent="source ~/secureagent-env/bin/activate && secureagent"' >> ~/.zshrc
source ~/.zshrc
```

Now you can just type `secureagent` without manually activating the environment each time.

---

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

# Password attack simulation (authorized targets only!)
secureagent "set scope to 192.168.1.50, then simulate SSH brute force with hydra using rockyou.txt"
```

### Informational Commands
```bash
# View authorized scopes
secureagent --list-scopes

# View audit log
secureagent --audit-log

# List all available tools
secureagent --list-tools

# View help
secureagent --help
```

## 🔧 Supported Tools

SecureAgent includes 18+ pentesting tools across multiple categories:

### Scanning
- **nmap** - Network scanner and security auditing tool
- **masscan** - Fast TCP port scanner
- **rustscan** - Modern fast port scanner

### Web Application Testing
- **nikto** - Web server vulnerability scanner
- **sqlmap** - Automatic SQL injection and database takeover tool
- **gobuster** - Directory/file & DNS brute-forcing tool
- **ffuf** - Fast web fuzzer
- **whatweb** - Web technology fingerprinting
- **wpscan** - WordPress vulnerability scanner

### Password Attacks
- **hydra** - Network logon cracker
- **john** - John the Ripper password cracker
- **hashcat** - Advanced password recovery

### OSINT (Open Source Intelligence)
- **theharvester** - Email, subdomain and people names harvester
- **dnsenum** - DNS enumeration tool
- **dnsrecon** - DNS reconnaissance tool

### Network Analysis
- **wireshark/tshark** - Network protocol analyzer
- **tcpdump** - Packet capture tool

### Exploitation
- **metasploit-framework** - Penetration testing framework
- **searchsploit** - Exploit database search tool

## 🔒 Security Features

### 1. Mandatory Authorization System
- **SHA256 scope hashing** for unique target identification
- **Persistent authorization storage** survives reboots
- **Interactive authorization prompts** before first scan
- **Explicit user confirmation** required for new scopes

Example workflow:
```bash
$ secureagent "set scope to 192.168.1.100 and scan with nmap"

⚠️  AUTHORIZATION REQUIRED
Targets: 192.168.1.100

Do you have authorization to scan these targets? (yes/no): yes
Authorization note: Home lab testing
✅ Scope authorized and saved
```

### 2. Shell Injection Prevention
- Uses `shell=False` for **all** subprocess calls
- Command validation for dangerous characters (`;`, `&&`, `||`, `|`, etc.)
- Argument list parsing (never string concatenation)
- Tool existence verification before execution

### 3. Comprehensive Audit Logging
- **JSONL format** for easy parsing with jq, grep, or Python
- Logs all commands, installations, and authorizations
- Includes exit codes, duration, and scope information
- **SIEM integration ready** for enterprise compliance

Example audit entry:
```json
{
  "timestamp": "2025-01-18T14:30:45.123456",
  "event_type": "command_executed",
  "data": {
    "command": "nmap -sV -sC 192.168.1.100",
    "exit_code": 0,
    "duration": 12.34,
    "scope_hash": "a1b2c3d4e5f6a7b8"
  }
}
```

### 4. Input Validation & Type Safety
- **Pydantic models** for type validation
- IP/CIDR/domain format checking
- Automatic validation before execution
- Prevents malformed inputs

### 5. Secure Credential Management
- Environment variable support (`GROQ_API_KEY`)
- Config file with **600 permissions** (owner read/write only)
- Never logged or displayed in output
- Rotation-friendly design

## 📁 Directory Structure

After first run, SecureAgent creates:

```
~/.secureagent/
├── config.json              # API key and settings (600 permissions)
├── authorized_scopes.json   # Authorized scanning targets
├── audit.jsonl             # Audit log (JSONL format)
├── logs/                   # Detailed execution logs
│   └── agent_20250118_143022.log
└── results/                # Structured scan results
    └── a1b2c3d4e5f6_20250118_143045.json
```

## ⚖️ Legal & Ethical Use

### ⚠️ CRITICAL WARNING

**Unauthorized computer network scanning is ILLEGAL in most jurisdictions** under laws such as:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Cybercrime Convention - European Union
- Similar laws worldwide

**Penalties include:**
- Criminal prosecution
- Civil lawsuits
- Fines up to millions of dollars
- Prison sentences
- Permanent criminal record

### ✅ Legal Use Cases ONLY

- Your own systems and networks
- Systems with **explicit written authorization**
- Bug bounty programs (**within defined scope**)
- Authorized penetration testing contracts
- Security research labs (HackTheBox, TryHackMe, etc.)
- Educational environments with permission
- Internal corporate security assessments

### ❌ NEVER Scan

- Systems without written permission
- Neighbors' WiFi networks
- Production systems without authorization
- Any target outside your authorized scope
- "Testing" websites without permission

**SecureAgent requires authorization before scanning. This is a security feature, not a limitation.**

## 🛠️ Advanced Configuration

### Custom Configuration Directory

Use project-specific configurations:

```bash
secureagent --config-dir ~/projects/client-pentest/.secureagent "scan target"
```

Useful for:
- Multiple clients with separate authorizations
- Team collaboration (shared config in Git repo)
- Compliance requirements (separate audit logs per project)

### Environment Variables

```bash
# Set in ~/.zshrc or ~/.bashrc for persistence
export GROQ_API_KEY="gsk_your_key_here"
export SECUREAGENT_MODEL="llama-3.3-70b-versatile"
```

### Alternative AI Models

- `llama-3.3-70b-versatile` (default, best performance)
- `llama-3.1-70b-versatile` (good fallback)
- `llama-3.1-8b-instant` (faster, less capable)
- `mixtral-8x7b-32768` (alternative architecture)

To use a different model:
```bash
secureagent --model llama-3.1-8b-instant "your task"
```

## 🐛 Troubleshooting

### "externally-managed-environment" error

**Cause**: Kali Linux, Debian 12+, and Ubuntu 23.04+ prevent system-wide pip installs.

**Solution**: Use virtual environment (already covered in installation steps above).

### "command not found: secureagent"

**Cause**: `~/bin` not in PATH

**Solution**:
```bash
# Temporary fix (current session only)
export PATH="$HOME/bin:$PATH"

# Permanent fix
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### "No module named 'langchain'" or Import Errors

**Cause**: Virtual environment not activated or wrong LangChain version

**Solution**:
```bash
# Activate virtual environment
source ~/secureagent-env/bin/activate

# Reinstall with correct versions
pip uninstall -y langchain langchain-groq langchain-community langchain-core
pip install langchain==0.1.0 langchain-groq langchain-community pydantic
```

### "Error code: 401 - Invalid API key"

**Cause**: Wrong API key or typo

**Solution**:
```bash
# Check current config
cat ~/.secureagent/config.json

# Update API key manually
nano ~/.secureagent/config.json
# Change "groq_api_key" value

# Or use environment variable
export GROQ_API_KEY="gsk_your_actual_key_here"
```

### "Error code: 400 - model decommissioned"

**Cause**: Model name changed or deprecated

**Solution**:
```bash
# Try alternative model
secureagent --model llama-3.1-70b-versatile "your task"

# Or set permanently
export SECUREAGENT_MODEL="llama-3.1-70b-versatile"

# Check available models at: https://console.groq.com/docs/models
```

### Virtual Environment Not Activating

**Cause**: `python3-venv` not installed

**Solution**:
```bash
# Install venv module
sudo apt update
sudo apt install python3-venv

# Recreate virtual environment
rm -rf ~/secureagent-env
python3 -m venv ~/secureagent-env
source ~/secureagent-env/bin/activate

# Reinstall dependencies
pip install langchain==0.1.0 langchain-groq langchain-community pydantic
```

### View Logs for Debugging

```bash
# Find latest log file
ls -lt ~/.secureagent/logs/

# View in real-time
tail -f ~/.secureagent/logs/agent_*.log

# Search for errors
grep -i error ~/.secureagent/logs/agent_*.log
```

## 📊 Architecture Overview

```
                    ┌─────────────────┐
                    │   CLI Interface │
                    │   (argparse)    │
                    └────────┬────────┘
                             │
                  ┌──────────▼──────────┐
                  │    SecureAgent      │
                  │ (Main Orchestrator) │
                  └──────────┬──────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
┌────────▼────────┐ ┌────────▼────────┐ ┌───────▼────────┐
│ SecurityManager │ │  ToolManager    │ │ SecureExecutor │
│  - Scope auth   │ │  - Install      │ │  - Validation  │
│  - Audit log    │ │  - Verify       │ │  - Execution   │
│  - Results      │ │  - Recommend    │ │  - Safety      │
└─────────────────┘ └─────────────────┘ └────────────────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
                   ┌─────────▼─────────┐
                   │   AgentTools      │
                   │ (LangChain Tools) │
                   └─────────┬─────────┘
                             │
                   ┌─────────▼─────────┐
                   │  LangChain Agent  │
                   │  (ReAct Pattern)  │
                   └─────────┬─────────┘
                             │
                   ┌─────────▼─────────┐
                   │     Groq LLM      │
                   │ (llama-3.3-70b)   │
                   └───────────────────┘
```

### Component Responsibilities

**SecurityManager**
- Load/save authorized scopes
- Verify target authorization
- Write audit logs (JSONL)
- Save structured results (JSON)

**ToolManager**
- Check if tools are installed
- Install tools from registry
- Verify tool functionality
- Recommend tools based on keywords

**SecureExecutor**
- Set and validate scanning scope
- Validate command safety
- Execute commands (shell=False)
- Enforce interactive approval
- Handle timeouts and errors

**AgentTools**
- Bridge between AI and system functions
- Expose tools to LangChain agent
- Convert AI decisions to function calls

**SecureAgent**
- Initialize all components
- Create LangChain agent executor
- Orchestrate task execution
- Handle errors and interrupts

## 📖 Documentation Files

- **README.md** (this file) - Quick start and overview
- **UsageGuide.txt** - Comprehensive installation and usage guide
- **agent.py** - Main Python script with inline documentation

## 🤝 Contributing

This is a portfolio project demonstrating secure AI-powered automation. Feel free to fork and adapt for your own use, but please:

- **Always maintain the authorization system**
- **Never remove security features**
- **Use responsibly and legally**
- Follow responsible disclosure for any vulnerabilities found

## 📄 License

MIT License - See code header for details

## ⚡ Version History

### v2.0.0 (Current)
- Production-grade security features
- Modular architecture with separate managers
- Comprehensive audit logging (JSONL format)
- Shell injection prevention (shell=False)
- Modern LangChain integration
- Pydantic models for type safety
- Interactive authorization system
- Structured result storage

### Key Improvements Over v1.0
- ❌ OLD: `shell=True` → ✅ NEW: `shell=False` (injection-proof)
- ❌ OLD: No authorization → ✅ NEW: Mandatory scope authorization
- ❌ OLD: Hardcoded API key → ✅ NEW: Secure config file + env vars
- ❌ OLD: No audit trail → ✅ NEW: Comprehensive JSONL logging
- ❌ OLD: Silent errors → ✅ NEW: Full logging with rotation
- ❌ OLD: String validation → ✅ NEW: Pydantic type validation

## 🔗 Useful Resources

- **Groq Console**: https://console.groq.com
- **Groq API Docs**: https://console.groq.com/docs
- **LangChain Docs**: https://python.langchain.com/docs/
- **Kali Linux**: https://www.kali.org/
- **Kali Python Guide**: https://www.kali.org/docs/general-use/python3-external-packages/
- **HackTheBox** (Legal Practice): https://hackthebox.eu
- **TryHackMe** (Legal Practice): https://tryhackme.com
- **OWASP WebGoat** (Legal Practice): https://owasp.org/www-project-webgoat/

## 💡 Example Workflows

### Scenario 1: Basic Network Reconnaissance
```bash
# Set scope
secureagent "set scope to 192.168.1.0/24"

# Discover live hosts
secureagent "scan the network for live hosts using nmap"

# Detailed scan on discovered hosts
secureagent "perform detailed scan on 192.168.1.100 with service detection"
```

### Scenario 2: Web Application Testing
```bash
# Set scope
secureagent "set scope to example.com"

# Reconnaissance
secureagent "enumerate subdomains for example.com using dnsenum"

# Web scanning
secureagent "scan example.com with nikto and whatweb"

# Directory enumeration
secureagent "use gobuster to find hidden directories on example.com"
```

### Scenario 3: OSINT Gathering
```bash
# Email harvesting
secureagent "use theharvester to gather emails for example.com"

# DNS enumeration
secureagent "enumerate DNS records for example.com using dnsrecon"

# Subdomain discovery
secureagent "find subdomains of example.com"
```

## 🎓 Learning Path

If you're new to penetration testing, here's a suggested learning path:

1. **Learn the basics**: TryHackMe "Complete Beginner" path
2. **Practice legally**: HackTheBox free tier
3. **Understand tools**: Read man pages (`man nmap`, `man nikto`, etc.)
4. **Get certified**: Consider CEH, OSCP, or GPEN
5. **Use SecureAgent**: As an assistant, not a replacement for knowledge

## ⚠️ Final Reminder

**SecureAgent is a powerful tool. Use it responsibly.**

- Always obtain written authorization
- Stay within your authorized scope
- Report vulnerabilities responsibly
- Maintain detailed documentation
- Follow your local laws and regulations

**Unauthorized hacking is a crime. Don't be a criminal. Be a professional.**

---

**Version**: 2.0.0  
**Last Updated**: January 2025  
**Author**: Portfolio Project by eBruno-Sec  
**Repository**: https://github.com/eBruno-Sec/cybersecurity-portfolio

For issues or questions, please refer to the troubleshooting section or check the logs at `~/.secureagent/logs/`
```
