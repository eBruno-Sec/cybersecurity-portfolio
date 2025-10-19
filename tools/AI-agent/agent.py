
#!/usr/bin/env python3
import sys, subprocess, os, shutil, warnings
warnings.filterwarnings('ignore')
os.environ['LANGCHAIN_TRACING'] = 'false'
from langchain_groq import ChatGroq
from langchain.agents import initialize_agent, AgentType, Tool

llm = ChatGroq(api_key="gsk_###############################", model="llama-3.3-70b-versatile", temperature=0)

KALI_TOOLS = {
    "nmap": "Network scanner - apt install nmap",
    "masscan": "Fast port scanner - apt install masscan", 
    "nikto": "Web vulnerability scanner - apt install nikto",
    "sqlmap": "SQL injection tool - apt install sqlmap",
    "metasploit": "Exploitation framework - apt install metasploit-framework",
    "hydra": "Password cracker - apt install hydra",
    "john": "Password cracker - apt install john",
    "hashcat": "Advanced password recovery - apt install hashcat",
    "gobuster": "Directory/DNS bruteforce - apt install gobuster",
    "ffuf": "Web fuzzer - apt install ffuf",
    "enum4linux": "SMB enumeration - apt install enum4linux",
    "smbclient": "SMB client - apt install smbclient",
    "crackmapexec": "Network pentesting - apt install crackmapexec",
    "responder": "LLMNR/NBT-NS poisoner - apt install responder",
    "bloodhound": "AD attack paths - apt install bloodhound",
    "burpsuite": "Web proxy - apt install burpsuite",
    "wireshark": "Network analyzer - apt install wireshark",
    "tcpdump": "Packet capture - apt install tcpdump",
    "aircrack-ng": "WiFi security - apt install aircrack-ng",
    "wpscan": "WordPress scanner - apt install wpscan",
    "exploitdb": "Exploit database - apt install exploitdb",
    "searchsploit": "Exploit search - apt install exploitdb",
    "msfvenom": "Payload generator - apt install metasploit-framework",
    "nuclei": "Vulnerability scanner - go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "subfinder": "Subdomain discovery - go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "HTTP toolkit - go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "amass": "Network mapping - apt install amass",
    "recon-ng": "Reconnaissance framework - apt install recon-ng",
    "theharvester": "OSINT gathering - apt install theharvester",
    "maltego": "OSINT analysis - apt install maltego",
    "spiderfoot": "OSINT automation - apt install spiderfoot",
    "shodan": "Internet device search - pip install shodan",
    "fierce": "DNS scanner - apt install fierce",
    "dnsenum": "DNS enumeration - apt install dnsenum",
    "dnsrecon": "DNS reconnaissance - apt install dnsrecon",
    "whatweb": "Web fingerprinting - apt install whatweb",
    "wafw00f": "WAF detection - apt install wafw00f",
    "commix": "Command injection - apt install commix",
}

def check_tool_installed(tool):
    return shutil.which(tool) is not None

def recommend_tools(task_description):
    recommendations = []
    task_lower = task_description.lower()
    
    if any(word in task_lower for word in ["scan", "port", "network", "host"]):
        recommendations.extend(["nmap", "masscan"])
    if any(word in task_lower for word in ["web", "http", "website", "url"]):
        recommendations.extend(["nikto", "nuclei", "ffuf", "gobuster", "whatweb"])
    if any(word in task_lower for word in ["password", "crack", "brute"]):
        recommendations.extend(["hydra", "john", "hashcat"])
    if any(word in task_lower for word in ["sql", "injection", "sqli"]):
        recommendations.extend(["sqlmap"])
    if any(word in task_lower for word in ["exploit", "metasploit", "vulnerability"]):
        recommendations.extend(["metasploit", "searchsploit"])
    if any(word in task_lower for word in ["smb", "windows", "domain"]):
        recommendations.extend(["enum4linux", "crackmapexec"])
    if any(word in task_lower for word in ["subdomain", "dns", "domain"]):
        recommendations.extend(["subfinder", "amass", "dnsenum", "fierce"])
    if any(word in task_lower for word in ["directory", "content", "fuzzing"]):
        recommendations.extend(["gobuster", "ffuf"])
    
    result = "\n=== RECOMMENDED TOOLS ===\n"
    for tool in set(recommendations[:5]):
        installed = "✓" if check_tool_installed(tool) else "✗"
        result += f"{installed} {tool}\n"
    return result

def auto_install_tool(tool_name):
    if tool_name not in KALI_TOOLS:
        return f"Unknown tool: {tool_name}"
    if check_tool_installed(tool_name):
        return f"{tool_name} already installed"
    install_cmd = KALI_TOOLS[tool_name]
    print(f"Installing {tool_name}...")
    if input(f"Install {tool_name}? (y/n): ").lower() != 'y':
        return "Cancelled"
    try:
        result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True, timeout=300)
        return f"✓ Installed" if result.returncode == 0 else f"✗ Failed"
    except Exception as e:
        return f"✗ Error: {e}"

def safe_exec(cmd):
    print(f"\nCommand: {cmd}")
    response = input("Execute? (y/n/e): ").lower()
    if response == 'e':
        edited = input(f"Edit [{cmd}]: ") or cmd
        return safe_exec(edited)
    elif response != 'y':
        return "Cancelled"
    print(f"\n▶ Executing...\n")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        output = result.stdout + result.stderr
        print(output)
        return output if output else "Done"
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as e:
        return f"Error: {e}"

tools = [
    Tool(name="recommend_tools", func=recommend_tools, description="Recommend pentesting tools for a task"),
    Tool(name="install_tool", func=auto_install_tool, description="Install a Kali tool by name"),
    Tool(name="execute_command", func=safe_exec, description="Execute shell command with approval"),
    Tool(name="read_file", func=lambda x: open(x).read() if os.path.exists(x) else f"Not found: {x}", description="Read file contents"),
]

agent = initialize_agent(
    tools, llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=False,
    max_iterations=5,
    handle_parsing_errors=True
)

if len(sys.argv) < 2:
    print("Usage: agent 'your task'")
    sys.exit(1)

try:
    result = agent.run(' '.join(sys.argv[1:]))
    print(f"\n{result}")
except KeyboardInterrupt:
    print("\nInterrupted")
except Exception as e:
    print(f"Error: {e}")
                                                                                                                            
┌──(secureagent-env)─(kali㉿kali)-[~/Desktop]
└─$ 
