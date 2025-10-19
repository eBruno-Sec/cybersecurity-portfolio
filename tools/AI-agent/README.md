# AI Cybersecurity Agent

An AI-powered pentesting assistant that recommends, installs, and executes Kali Linux security tools using natural language commands.

## Features

- **AI-Powered Tool Recommendations**: Automatically suggests the best security tools for your task
- **Auto-Installation**: Install Kali Linux tools with confirmation prompts
- **Safe Command Execution**: Review and edit commands before execution
- **38+ Security Tools**: Supports popular tools like nmap, metasploit, burpsuite, sqlmap, and more
- **Interactive Workflow**: Confirm, edit, or cancel operations before execution

## Prerequisites

- **Operating System**: Kali Linux or Debian-based Linux distribution
- **Python**: Python 3.8 or higher
- **API Key**: Groq API key (free at [console.groq.com](https://console.groq.com))
- **Internet Connection**: Required for API calls and tool installations

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/eBruno-Sec/cybersecurity-portfolio.git
cd cybersecurity-portfolio/tools/AI-agent
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or install globally:

```bash
sudo pip install -r requirements.txt
```

### 3. Configure API Key

Edit `agent.py` and replace the placeholder API key with your Groq API key:

```python
llm = ChatGroq(api_key="YOUR_GROQ_API_KEY_HERE", model="llama-3.3-70b-versatile", temperature=0)
```

To get a free Groq API key:
1. Visit [console.groq.com](https://console.groq.com)
2. Sign up for a free account
3. Navigate to API Keys section
4. Generate a new API key

### 4. Make the Script Executable

```bash
chmod +x agent.py
```

### 5. (Optional) Add to PATH

For system-wide access:

```bash
sudo cp agent.py /usr/local/bin/agent
```

## Usage

### Basic Syntax

```bash
./agent.py 'your task description'
```

Or if installed to PATH:

```bash
agent 'your task description'
```

### Example Commands

**Network Scanning:**
```bash
./agent.py 'scan network 192.168.1.0/24 for open ports'
```

**Web Application Testing:**
```bash
./agent.py 'scan website example.com for vulnerabilities'
```

**Password Cracking:**
```bash
./agent.py 'crack password hash using john the ripper'
```

**SQL Injection Testing:**
```bash
./agent.py 'test http://example.com/login for SQL injection'
```

**Subdomain Enumeration:**
```bash
./agent.py 'find subdomains for example.com'
```

**Tool Installation:**
```bash
./agent.py 'install nmap'
```

**Tool Recommendations:**
```bash
./agent.py 'what tools should I use for web application pentesting?'
```

## Interactive Prompts

The agent provides interactive prompts for safety:

- **Execute? (y/n/e)**:
  - `y` - Execute the command
  - `n` - Cancel the operation
  - `e` - Edit the command before execution

- **Install tool? (y/n)**:
  - `y` - Proceed with installation
  - `n` - Cancel installation

## Supported Tools

The agent supports 38+ security tools including:

| Category | Tools |
|----------|-------|
| **Network Scanning** | nmap, masscan, amass |
| **Web Testing** | nikto, burpsuite, ffuf, gobuster, nuclei |
| **Password Cracking** | john, hashcat, hydra |
| **Exploitation** | metasploit, msfvenom, searchsploit |
| **SMB/AD Testing** | enum4linux, crackmapexec, bloodhound |
| **DNS Enumeration** | dnsenum, dnsrecon, fierce, subfinder |
| **OSINT** | theharvester, maltego, spiderfoot, shodan |
| **Wireless** | aircrack-ng |
| **Network Analysis** | wireshark, tcpdump |

## Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only.

- Always obtain proper authorization before testing systems
- Use only in controlled environments or with explicit permission
- Review all commands before execution
- Keep your API key secure and never commit it to version control
- The tool requires user confirmation before executing commands

## Troubleshooting

### Command Not Found

If you get "command not found" errors:

```bash
# Ensure the script is executable
chmod +x agent.py

# Or run with python
python3 agent.py 'your task'
```

### API Key Errors

If you see authentication errors:
- Verify your Groq API key is correct
- Check your internet connection
- Ensure the API key is not expired

### Tool Installation Failures

If tools fail to install:
```bash
# Update package lists
sudo apt update

# Install specific tool manually
sudo apt install <tool-name>
```

### Permission Errors

Some tools require root privileges:
```bash
sudo ./agent.py 'your task'
```

## Technical Details

- **AI Model**: Llama 3.3 70B via Groq API
- **Framework**: LangChain with ZERO_SHOT_REACT agent
- **Max Iterations**: 5 (prevents infinite loops)
- **Timeout**: 600 seconds for command execution, 300 seconds for installations

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is part of the [eBruno-Sec Cybersecurity Portfolio](https://github.com/eBruno-Sec/cybersecurity-portfolio).

## Disclaimer

This tool is for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of this tool.

## Author

**eBruno-Sec**
- GitHub: [@eBruno-Sec](https://github.com/eBruno-Sec)
- Portfolio: [cybersecurity-portfolio](https://github.com/eBruno-Sec/cybersecurity-portfolio)

## Acknowledgments

- Powered by [Groq](https://groq.com) and Llama 3.3
- Built with [LangChain](https://langchain.com)
- Designed for [Kali Linux](https://www.kali.org) security tools
