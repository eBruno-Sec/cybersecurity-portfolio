#!/usr/bin/env python3
"""
SecureAgent - Production-Grade AI Pentesting Assistant
Version: 2.0.0
License: MIT
Author: Security-First AI Agent


A secure, auditable, and professional AI-powered pentesting automation tool.
"""


import sys
import subprocess
import os
import json
import shutil
import argparse
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


# Suppress warnings but log them
import warnings
import logging


# Configure logging FIRST
LOG_DIR = Path.home() / ".secureagent" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecureAgent")


# Suppress third-party warnings after logging is configured
warnings.filterwarnings('ignore', category=DeprecationWarning)
os.environ['LANGCHAIN_TRACING_V2'] = 'false'


try:
    from langchain_groq import ChatGroq
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain.tools import Tool
    from langchain_core.prompts import PromptTemplate
    from pydantic import BaseModel, Field, validator
except ImportError as e:
    logger.error(f"Missing required library: {e}")
    print("\n❌ Missing dependencies. Install with:")
    print("pip install langchain langchain-groq langchain-community pydantic")
    sys.exit(1)




# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================


class ToolCategory(Enum):
    RECON = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    PASSWORD = "password_attack"
    WEB = "web_application"
    NETWORK = "network_analysis"
    OSINT = "osint"




@dataclass
class ToolDefinition:
    """Structured tool definition with security metadata"""
    name: str
    category: ToolCategory
    description: str
    install_command: List[str]  # Argument list, NOT shell string
    requires_sudo: bool = False
    package_manager: str = "apt"
    verification_command: List[str] = None
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['category'] = self.category.value
        return data




class ScanScope(BaseModel):
    """Validated scanning scope with authorization tracking"""
    targets: List[str] = Field(..., min_items=1)
    authorized: bool = Field(default=False)
    authorization_note: Optional[str] = None
    scope_hash: Optional[str] = None
    
    @validator('targets')
    def validate_targets(cls, v):
        """Ensure targets are valid IP/domain formats"""
        import ipaddress
        for target in v:
            # Try IP validation
            try:
                ipaddress.ip_address(target)
                continue
            except ValueError:
                pass
            
            # Try CIDR notation
            try:
                ipaddress.ip_network(target, strict=False)
                continue
            except ValueError:
                pass
            
            # Try domain validation (basic)
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', target):
                raise ValueError(f"Invalid target format: {target}")
        
        return v
    
    def calculate_hash(self) -> str:
        """Generate unique hash for this scope"""
        scope_str = ",".join(sorted(self.targets))
        return hashlib.sha256(scope_str.encode()).hexdigest()[:16]
    
    def model_post_init(self, __context):
        """Calculate hash after initialization"""
        if not self.scope_hash:
            self.scope_hash = self.calculate_hash()




@dataclass
class ExecutionResult:
    """Structured execution result with metadata"""
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    timestamp: datetime
    duration_seconds: float
    scope_hash: Optional[str] = None
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['command'] = ' '.join(self.command)  # For display only
        return data
    
    def success(self) -> bool:
        return self.exit_code == 0




# ============================================================================
# TOOL REGISTRY - Comprehensive and Structured
# ============================================================================


TOOL_REGISTRY: Dict[str, ToolDefinition] = {
    # Reconnaissance
    "nmap": ToolDefinition(
        name="nmap",
        category=ToolCategory.SCANNING,
        description="Network scanner and security auditing tool",
        install_command=["apt", "install", "-y", "nmap"],
        requires_sudo=True,
        verification_command=["nmap", "--version"]
    ),
    "masscan": ToolDefinition(
        name="masscan",
        category=ToolCategory.SCANNING,
        description="Fast TCP port scanner",
        install_command=["apt", "install", "-y", "masscan"],
        requires_sudo=True,
        verification_command=["masscan", "--version"]
    ),
    "rustscan": ToolDefinition(
        name="rustscan",
        category=ToolCategory.SCANNING,
        description="Modern fast port scanner",
        install_command=["apt", "install", "-y", "rustscan"],
        requires_sudo=True,
        verification_command=["rustscan", "--version"]
    ),
    
    # Web Application Testing
    "nikto": ToolDefinition(
        name="nikto",
        category=ToolCategory.WEB,
        description="Web server vulnerability scanner",
        install_command=["apt", "install", "-y", "nikto"],
        requires_sudo=True,
        verification_command=["nikto", "-Version"]
    ),
    "sqlmap": ToolDefinition(
        name="sqlmap",
        category=ToolCategory.WEB,
        description="Automatic SQL injection and database takeover tool",
        install_command=["apt", "install", "-y", "sqlmap"],
        requires_sudo=True,
        verification_command=["sqlmap", "--version"]
    ),
    "gobuster": ToolDefinition(
        name="gobuster",
        category=ToolCategory.WEB,
        description="Directory/file & DNS brute-forcing tool",
        install_command=["apt", "install", "-y", "gobuster"],
        requires_sudo=True,
        verification_command=["gobuster", "version"]
    ),
    "ffuf": ToolDefinition(
        name="ffuf",
        category=ToolCategory.WEB,
        description="Fast web fuzzer",
        install_command=["apt", "install", "-y", "ffuf"],
        requires_sudo=True,
        verification_command=["ffuf", "-V"]
    ),
    "whatweb": ToolDefinition(
        name="whatweb",
        category=ToolCategory.WEB,
        description="Web technology fingerprinting",
        install_command=["apt", "install", "-y", "whatweb"],
        requires_sudo=True,
        verification_command=["whatweb", "--version"]
    ),
    "wpscan": ToolDefinition(
        name="wpscan",
        category=ToolCategory.WEB,
        description="WordPress vulnerability scanner",
        install_command=["apt", "install", "-y", "wpscan"],
        requires_sudo=True,
        verification_command=["wpscan", "--version"]
    ),
    
    # Password Attacks
    "hydra": ToolDefinition(
        name="hydra",
        category=ToolCategory.PASSWORD,
        description="Network logon cracker",
        install_command=["apt", "install", "-y", "hydra"],
        requires_sudo=True,
        verification_command=["hydra", "-h"]
    ),
    "john": ToolDefinition(
        name="john",
        category=ToolCategory.PASSWORD,
        description="John the Ripper password cracker",
        install_command=["apt", "install", "-y", "john"],
        requires_sudo=True,
        verification_command=["john", "--list=build-info"]
    ),
    "hashcat": ToolDefinition(
        name="hashcat",
        category=ToolCategory.PASSWORD,
        description="Advanced password recovery",
        install_command=["apt", "install", "-y", "hashcat"],
        requires_sudo=True,
        verification_command=["hashcat", "--version"]
    ),
    
    # Network Analysis
    "wireshark": ToolDefinition(
        name="wireshark",
        category=ToolCategory.NETWORK,
        description="Network protocol analyzer",
        install_command=["apt", "install", "-y", "wireshark"],
        requires_sudo=True,
        verification_command=["tshark", "--version"]
    ),
    "tcpdump": ToolDefinition(
        name="tcpdump",
        category=ToolCategory.NETWORK,
        description="Packet capture tool",
        install_command=["apt", "install", "-y", "tcpdump"],
        requires_sudo=True,
        verification_command=["tcpdump", "--version"]
    ),
    
    # OSINT
    "theharvester": ToolDefinition(
        name="theharvester",
        category=ToolCategory.OSINT,
        description="E-mail, subdomain and people names harvester",
        install_command=["apt", "install", "-y", "theharvester"],
        requires_sudo=True,
        verification_command=["theharvester", "--help"]
    ),
    "dnsenum": ToolDefinition(
        name="dnsenum",
        category=ToolCategory.OSINT,
        description="DNS enumeration tool",
        install_command=["apt", "install", "-y", "dnsenum"],
        requires_sudo=True,
        verification_command=["dnsenum", "--help"]
    ),
    "dnsrecon": ToolDefinition(
        name="dnsrecon",
        category=ToolCategory.OSINT,
        description="DNS reconnaissance tool",
        install_command=["apt", "install", "-y", "dnsrecon"],
        requires_sudo=True,
        verification_command=["dnsrecon", "--help"]
    ),
    
    # Exploitation
    "metasploit-framework": ToolDefinition(
        name="msfconsole",
        category=ToolCategory.EXPLOITATION,
        description="Metasploit Framework",
        install_command=["apt", "install", "-y", "metasploit-framework"],
        requires_sudo=True,
        verification_command=["msfconsole", "-v"]
    ),
    "searchsploit": ToolDefinition(
        name="searchsploit",
        category=ToolCategory.EXPLOITATION,
        description="Exploit database search tool",
        install_command=["apt", "install", "-y", "exploitdb"],
        requires_sudo=True,
        verification_command=["searchsploit", "--help"]
    ),
}




# ============================================================================
# SECURITY MANAGER
# ============================================================================


class SecurityManager:
    """Handles authorization, validation, and audit logging"""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.auth_file = config_dir / "authorized_scopes.json"
        self.audit_file = config_dir / "audit.jsonl"
        self.results_dir = config_dir / "results"
        
        # Ensure directories exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Security Manager initialized. Config: {self.config_dir}")
    
    def load_authorized_scopes(self) -> List[ScanScope]:
        """Load previously authorized scopes"""
        if not self.auth_file.exists():
            return []
        
        try:
            with open(self.auth_file, 'r') as f:
                data = json.load(f)
                return [ScanScope(**scope) for scope in data]
        except Exception as e:
            logger.error(f"Failed to load authorized scopes: {e}")
            return []
    
    def save_authorized_scope(self, scope: ScanScope):
        """Save an authorized scope"""
        scopes = self.load_authorized_scopes()
        
        # Check if already exists
        for existing in scopes:
            if existing.scope_hash == scope.scope_hash:
                logger.info(f"Scope {scope.scope_hash} already authorized")
                return
        
        scopes.append(scope)
        
        with open(self.auth_file, 'w') as f:
            json.dump([s.dict() for s in scopes], f, indent=2)
        
        logger.info(f"Saved authorized scope: {scope.scope_hash}")
    
    def is_scope_authorized(self, targets: List[str]) -> Tuple[bool, Optional[str]]:
        """Check if targets are in authorized scope"""
        test_scope = ScanScope(targets=targets, authorized=True)
        test_hash = test_scope.scope_hash
        
        authorized_scopes = self.load_authorized_scopes()
        
        for scope in authorized_scopes:
            if scope.scope_hash == test_hash and scope.authorized:
                return True, scope.authorization_note
        
        return False, None
    
    def authorize_scope_interactive(self, targets: List[str]) -> ScanScope:
        """Interactive authorization for new scope"""
        print("\n" + "="*70)
        print("⚠️  AUTHORIZATION REQUIRED")
        print("="*70)
        print(f"\nTargets: {', '.join(targets)}")
        print("\nYou are about to authorize scanning of these targets.")
        print("This authorization will be saved for future use.")
        print("\n⚠️  WARNING: Only scan systems you own or have written permission to test!")
        print("\nUnauthorized scanning is ILLEGAL and unethical.")
        
        response = input("\nDo you have authorization to scan these targets? (yes/no): ").strip().lower()
        
        if response != "yes":
            logger.warning("User declined authorization")
            raise PermissionError("Scanning not authorized by user")
        
        note = input("Authorization note (e.g., 'Company pentest 2025-Q1'): ").strip()
        
        scope = ScanScope(
            targets=targets,
            authorized=True,
            authorization_note=note or "User authorized via CLI"
        )
        
        self.save_authorized_scope(scope)
        
        print(f"\n✅ Scope authorized and saved (hash: {scope.scope_hash})")
        logger.info(f"New scope authorized: {scope.scope_hash} - {scope.authorization_note}")
        
        return scope
    
    def audit_log(self, event_type: str, data: Dict[str, Any]):
        """Append to audit log (JSONL format)"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "data": data
        }
        
        with open(self.audit_file, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        
        logger.debug(f"Audit: {event_type}")
    
    def save_result(self, result: ExecutionResult):
        """Save execution result to structured file"""
        timestamp = result.timestamp.strftime("%Y%m%d_%H%M%S")
        scope = result.scope_hash or "unknown"
        filename = self.results_dir / f"{scope}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        
        logger.info(f"Result saved: {filename}")




# ============================================================================
# TOOL MANAGER
# ============================================================================


class ToolManager:
    """Manages tool installation and verification"""
    
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
    
    def is_installed(self, tool_name: str) -> bool:
        """Check if tool is installed via which"""
        return shutil.which(tool_name) is not None
    
    def verify_tool(self, tool_def: ToolDefinition) -> bool:
        """Verify tool is installed and working"""
        if not tool_def.verification_command:
            return self.is_installed(tool_def.name)
        
        try:
            result = subprocess.run(
                tool_def.verification_command,
                capture_output=True,
                timeout=5,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def install_tool(self, tool_name: str, interactive: bool = True) -> bool:
        """Install a tool from registry"""
        if tool_name not in TOOL_REGISTRY:
            logger.error(f"Unknown tool: {tool_name}")
            return False
        
        tool_def = TOOL_REGISTRY[tool_name]
        
        # Check if already installed
        if self.verify_tool(tool_def):
            print(f"✓ {tool_name} is already installed")
            return True
        
        # Interactive confirmation
        if interactive:
            print(f"\n📦 Installing {tool_name}")
            print(f"   Category: {tool_def.category.value}")
            print(f"   Description: {tool_def.description}")
            print(f"   Command: {' '.join(tool_def.install_command)}")
            
            if tool_def.requires_sudo:
                print("   ⚠️  Requires sudo privileges")
            
            response = input("\nProceed with installation? (y/n): ").strip().lower()
            if response != 'y':
                logger.info(f"User cancelled installation of {tool_name}")
                return False
        
        # Execute installation
        try:
            print(f"\n▶ Installing {tool_name}...")
            
            cmd = tool_def.install_command
            if tool_def.requires_sudo and os.geteuid() != 0:
                cmd = ["sudo"] + cmd
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=300,
                text=True
            )
            
            if result.returncode == 0:
                print(f"✅ {tool_name} installed successfully")
                self.security_manager.audit_log("tool_installed", {
                    "tool": tool_name,
                    "success": True
                })
                return True
            else:
                print(f"❌ Installation failed")
                print(f"Error: {result.stderr}")
                logger.error(f"Failed to install {tool_name}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"❌ Installation timed out (300s)")
            return False
        except Exception as e:
            print(f"❌ Installation error: {e}")
            logger.error(f"Exception installing {tool_name}: {e}")
            return False
    
    def recommend_tools(self, task_description: str) -> List[str]:
        """Recommend tools based on task keywords"""
        task_lower = task_description.lower()
        recommendations = []
        
        keyword_map = {
            ToolCategory.SCANNING: ["scan", "port", "network", "host", "discovery"],
            ToolCategory.WEB: ["web", "http", "website", "url", "application"],
            ToolCategory.PASSWORD: ["password", "crack", "brute", "hash"],
            ToolCategory.OSINT: ["subdomain", "dns", "domain", "osint", "reconnaissance"],
            ToolCategory.EXPLOITATION: ["exploit", "vulnerability", "cve", "metasploit"],
        }
        
        for category, keywords in keyword_map.items():
            if any(kw in task_lower for kw in keywords):
                category_tools = [
                    name for name, tool in TOOL_REGISTRY.items()
                    if tool.category == category
                ]
                recommendations.extend(category_tools[:3])  # Top 3 per category
        
        return list(dict.fromkeys(recommendations))[:5]  # Remove duplicates, max 5




# ============================================================================
# SECURE COMMAND EXECUTOR
# ============================================================================


class SecureExecutor:
    """Executes commands safely with validation and logging"""
    
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
        self.current_scope: Optional[ScanScope] = None
    
    def set_scope(self, targets: List[str]):
        """Set and validate current scanning scope"""
        # Check authorization
        is_auth, note = self.security_manager.is_scope_authorized(targets)
        
        if is_auth:
            self.current_scope = ScanScope(
                targets=targets,
                authorized=True,
                authorization_note=note
            )
            logger.info(f"Scope set to authorized targets: {targets}")
        else:
            # Request authorization
            self.current_scope = self.security_manager.authorize_scope_interactive(targets)
    
    def validate_command(self, command: List[str]) -> Tuple[bool, str]:
        """Validate command safety"""
        if not command:
            return False, "Empty command"
        
        # Check for shell injection patterns
        dangerous_patterns = [';', '&&', '||', '|', '`', '$', '>', '<', '\n']
        for arg in command:
            for pattern in dangerous_patterns:
                if pattern in arg:
                    return False, f"Potentially dangerous pattern detected: {pattern}"
        
        # Validate tool exists
        if not shutil.which(command[0]):
            return False, f"Command not found: {command[0]}"
        
        return True, "OK"
    
    def execute_safe(self, command: List[str], timeout: int = 600, interactive: bool = True) -> ExecutionResult:
        """Execute command with safety checks"""
        
        # Validate command
        is_valid, reason = self.validate_command(command)
        if not is_valid:
            logger.error(f"Command validation failed: {reason}")
            raise ValueError(f"Invalid command: {reason}")
        
        # Display and confirm
        if interactive:
            print(f"\n{'='*70}")
            print("COMMAND EXECUTION")
            print(f"{'='*70}")
            print(f"Command: {' '.join(command)}")
            print(f"Timeout: {timeout}s")
            if self.current_scope:
                print(f"Scope: {', '.join(self.current_scope.targets)}")
            
            response = input("\nExecute this command? (y/n/e): ").strip().lower()
            
            if response == 'e':
                edited = input(f"Edit command [{' '.join(command)}]: ").strip()
                if edited:
                    command = edited.split()
                    return self.execute_safe(command, timeout, interactive=True)
            elif response != 'y':
                logger.info("User cancelled execution")
                raise InterruptedError("User cancelled execution")
        
        # Execute
        print(f"\n▶ Executing...")
        start_time = datetime.now()
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout,
                text=True,
                shell=False  # CRITICAL: No shell=True
            )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Create result object
            exec_result = ExecutionResult(
                command=command,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                timestamp=start_time,
                duration_seconds=duration,
                scope_hash=self.current_scope.scope_hash if self.current_scope else None
            )
            
            # Display output
            if result.stdout:
                print("\n--- STDOUT ---")
                print(result.stdout)
            
            if result.stderr:
                print("\n--- STDERR ---")
                print(result.stderr)
            
            print(f"\n✓ Completed in {duration:.2f}s (exit code: {result.returncode})")
            
            # Save and audit
            self.security_manager.save_result(exec_result)
            self.security_manager.audit_log("command_executed", {
                "command": ' '.join(command),
                "exit_code": result.returncode,
                "duration": duration,
                "scope_hash": self.current_scope.scope_hash if self.current_scope else None
            })
            
            return exec_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s")
            print(f"\n❌ Command timed out after {timeout}s")
            raise TimeoutError(f"Command exceeded {timeout}s timeout")
        
        except Exception as e:
            logger.error(f"Execution error: {e}")
            print(f"\n❌ Execution error: {e}")
            raise




# ============================================================================
# AI AGENT TOOLS
# ============================================================================


class AgentTools:
    """LangChain-compatible tools for AI agent"""
    
    def __init__(self, tool_manager: ToolManager, executor: SecureExecutor):
        self.tool_manager = tool_manager
        self.executor = executor
    
    def recommend_tools_func(self, task: str) -> str:
        """Recommend appropriate tools for a pentesting task"""
        recommendations = self.tool_manager.recommend_tools(task)
        
        if not recommendations:
            return "No specific tool recommendations for this task."
        
        output = "\n=== RECOMMENDED TOOLS ===\n"
        for tool_name in recommendations:
            installed = "✓" if self.tool_manager.is_installed(tool_name) else "✗"
            tool_def = TOOL_REGISTRY.get(tool_name)
            desc = tool_def.description if tool_def else "Unknown"
            output += f"{installed} {tool_name}: {desc}\n"
        
        return output
    
    def install_tool_func(self, tool_name: str) -> str:
        """Install a pentesting tool"""
        success = self.tool_manager.install_tool(tool_name, interactive=True)
        return f"✓ {tool_name} installed" if success else f"✗ Failed to install {tool_name}"
    
    def execute_command_func(self, command_str: str) -> str:
        """Execute a shell command with safety checks"""
        command_list = command_str.split()
        
        try:
            result = self.executor.execute_safe(command_list, interactive=True)
            return result.stdout if result.stdout else "Command completed successfully"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def set_scope_func(self, targets: str) -> str:
        """Set scanning scope with authorization"""
        target_list = [t.strip() for t in targets.split(",")]
        
        try:
            self.executor.set_scope(target_list)
            return f"✓ Scope set and authorized: {', '.join(target_list)}"
        except Exception as e:
            return f"✗ Failed to set scope: {str(e)}"
    
    def get_langchain_tools(self) -> List[Tool]:
        """Return list of LangChain Tool objects"""
        return [
            Tool(
                name="recommend_tools",
                func=self.recommend_tools_func,
                description="Recommend appropriate pentesting tools for a given task. Input should be a task description."
            ),
            Tool(
                name="install_tool",
                func=self.install_tool_func,
                description="Install a pentesting tool by name. Input should be the exact tool name (e.g., 'nmap', 'nikto')."
            ),
            Tool(
                name="execute_command",
                func=self.execute_command_func,
                description="Execute a shell command with safety checks and user approval. Input should be the complete command as a string."
            ),
            Tool(
                name="set_scope",
                func=self.set_scope_func,
                description="Set and authorize the scanning scope. Input should be comma-separated list of targets (IPs or domains)."
            ),
        ]




# ============================================================================
# AI AGENT
# ============================================================================


class SecureAgent:
    """Main AI agent orchestrator"""
    
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        # Initialize components
        config_dir = Path.home() / ".secureagent"
        self.security_manager = SecurityManager(config_dir)
        self.tool_manager = ToolManager(self.security_manager)
        self.executor = SecureExecutor(self.security_manager)
        self.agent_tools = AgentTools(self.tool_manager, self.executor)
        
        # Initialize LLM
        try:
            self.llm = ChatGroq(
                api_key=api_key,
                model=model,
                temperature=0
            )
            logger.info(f"AI model initialized: {model}")
        except Exception as e:
            logger.error(f"Failed to initialize AI model: {e}")
            raise
        
        # Create agent
        self._create_agent()
    
    def _create_agent(self):
        """Create LangChain agent with custom prompt"""
        
        tools = self.agent_tools.get_langchain_tools()
        
        template = """You are a professional penetration testing assistant. You help security professionals conduct authorized security assessments.


CRITICAL RULES:
1. ALWAYS use set_scope FIRST before any scanning/testing commands
2. NEVER execute commands on unauthorized targets
3. Recommend appropriate tools before suggesting complex commands
4. Explain what each command does before execution
5. Prioritize safety and proper authorization


Available tools:
{tools}


Tool Names: {tool_names}


When answering:
1. Think step-by-step
2. Use tools appropriately
3. Explain your reasoning
4. Request user confirmation for critical actions


Question: {input}


Thought: {agent_scratchpad}"""
        
        prompt = PromptTemplate.from_template(template)
        
        # Create ReAct agent
        agent = create_react_agent(
            llm=self.llm,
            tools=tools,
            prompt=prompt
        )
        
        # Create executor
        self.agent_executor = AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=True,
            max_iterations=10,
            handle_parsing_errors=True,
            return_intermediate_steps=False
        )
        
        logger.info("Agent executor created successfully")
    
    def run(self, task: str) -> str:
        """Execute a task via AI agent"""
        logger.info(f"Task requested: {task}")
        
        try:
            result = self.agent_executor.invoke({"input": task})
            output = result.get("output", "No output generated")
            
            logger.info("Task completed successfully")
            return output
            
        except KeyboardInterrupt:
            logger.warning("Task interrupted by user")
            return "\n⚠️ Task interrupted by user"
        
        except Exception as e:
            logger.error(f"Task execution failed: {e}")
            return f"\n❌ Error: {str(e)}"




# ============================================================================
# CLI INTERFACE
# ============================================================================


def setup_argparse() -> argparse.ArgumentParser:
    """Configure command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="SecureAgent - Production-Grade AI Pentesting Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Set scope and scan
  secureagent "set scope to 192.168.1.1 and scan it with nmap"
  
  # Install and use tool
  secureagent "install nikto and scan example.com"
  
  # Get recommendations
  secureagent "what tools should I use for web application testing?"
  
  # View authorized scopes
  secureagent --list-scopes
  
  # View audit log
  secureagent --audit-log
  
Environment Variables:
  GROQ_API_KEY    Your Groq API key (required if not in config)
  SECUREAGENT_MODEL    AI model to use (default: llama-3.3-70b-versatile)
        """
    )
    
    parser.add_argument(
        "task",
        nargs="*",
        help="Pentesting task in natural language"
    )
    
    parser.add_argument(
        "--list-scopes",
        action="store_true",
        help="List all authorized scanning scopes"
    )
    
    parser.add_argument(
        "--audit-log",
        action="store_true",
        help="Display audit log"
    )
    
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List all available tools"
    )
    
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=Path.home() / ".secureagent",
        help="Configuration directory (default: ~/.secureagent)"
    )
    
    parser.add_argument(
        "--model",
        type=str,
        help="AI model to use (overrides SECUREAGENT_MODEL)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="SecureAgent 2.0.0"
    )
    
    return parser




def list_authorized_scopes(config_dir: Path):
    """Display all authorized scopes"""
    sec_manager = SecurityManager(config_dir)
    scopes = sec_manager.load_authorized_scopes()
    
    if not scopes:
        print("\n📋 No authorized scopes found.")
        print("   Use the agent to authorize new scopes interactively.")
        return
    
    print(f"\n📋 Authorized Scanning Scopes ({len(scopes)} total):\n")
    print(f"{'Hash':<18} {'Targets':<40} {'Note':<30}")
    print("-" * 90)
    
    for scope in scopes:
        targets_str = ", ".join(scope.targets[:2])
        if len(scope.targets) > 2:
            targets_str += f" (+{len(scope.targets)-2} more)"
        
        note = scope.authorization_note or "No note"
        print(f"{scope.scope_hash:<18} {targets_str:<40} {note:<30}")




def display_audit_log(config_dir: Path, limit: int = 50):
    """Display recent audit log entries"""
    sec_manager = SecurityManager(config_dir)
    
    if not sec_manager.audit_file.exists():
        print("\n📋 No audit log found.")
        return
    
    print(f"\n📋 Audit Log (last {limit} entries):\n")
    
    entries = []
    with open(sec_manager.audit_file, 'r') as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except:
                continue
    
    # Show most recent entries
    for entry in entries[-limit:]:
        timestamp = entry.get("timestamp", "Unknown")
        event_type = entry.get("event_type", "unknown")
        data = entry.get("data", {})
        
        print(f"[{timestamp}] {event_type}")
        for key, value in data.items():
            print(f"  {key}: {value}")
        print()




def list_available_tools():
    """Display all tools in registry"""
    print(f"\n🔧 Available Tools ({len(TOOL_REGISTRY)} total):\n")
    
    # Group by category
    by_category = {}
    for name, tool in TOOL_REGISTRY.items():
        category = tool.category.value
        if category not in by_category:
            by_category[category] = []
        by_category[category].append((name, tool))
    
    for category in sorted(by_category.keys()):
        print(f"\n{category.upper()}:")
        print("-" * 60)
        
        for name, tool in sorted(by_category[category], key=lambda x: x[0]):
            installed = "✓" if shutil.which(name) else "✗"
            print(f"  {installed} {name:<20} {tool.description}")




def get_api_key() -> str:
    """Get Groq API key from environment or config file"""
    
    # Try environment variable first
    api_key = os.getenv("GROQ_API_KEY")
    if api_key:
        return api_key
    
    # Try config file
    config_file = Path.home() / ".secureagent" / "config.json"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                api_key = config.get("groq_api_key")
                if api_key:
                    return api_key
        except:
            pass
    
    # Interactive setup
    print("\n⚙️  First-time setup required")
    print("\nNo Groq API key found. You need a free API key from Groq.")
    print("\nSteps:")
    print("  1. Visit https://console.groq.com")
    print("  2. Sign up (free, no credit card)")
    print("  3. Go to API Keys → Create API Key")
    print("  4. Copy the key (starts with 'gsk_')")
    
    api_key = input("\nPaste your Groq API key: ").strip()
    
    if not api_key.startswith("gsk_"):
        print("\n❌ Invalid API key format. Should start with 'gsk_'")
        sys.exit(1)
    
    # Save to config
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config = {"groq_api_key": api_key}
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Secure the config file
    os.chmod(config_file, 0o600)
    
    print(f"\n✅ API key saved to {config_file}")
    print("   (File permissions set to 600 for security)")
    
    return api_key




def main():
    """Main entry point"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Handle informational commands
    if args.list_scopes:
        list_authorized_scopes(args.config_dir)
        return
    
    if args.audit_log:
        display_audit_log(args.config_dir)
        return
    
    if args.list_tools:
        list_available_tools()
        return
    
    # Require task for agent execution
    if not args.task:
        parser.print_help()
        print("\n❌ Error: No task provided")
        print("\nExamples:")
        print("  secureagent 'scan 192.168.1.1 with nmap'")
        print("  secureagent 'recommend tools for web testing'")
        sys.exit(1)
    
    task = " ".join(args.task)
    
    # Get API key
    try:
        api_key = get_api_key()
    except Exception as e:
        print(f"\n❌ Failed to get API key: {e}")
        sys.exit(1)
    
    # Get model
    model = args.model or os.getenv("SECUREAGENT_MODEL", "llama-3.3-70b-versatile")
    
    # Initialize and run agent
    try:
        print(f"\n🤖 SecureAgent v2.0.0")
        print(f"   Model: {model}")
        print(f"   Config: {args.config_dir}")
        print(f"   Logs: {LOG_FILE}")
        print()
        
        agent = SecureAgent(api_key=api_key, model=model)
        result = agent.run(task)
        
        print(f"\n{'='*70}")
        print("RESULT")
        print(f"{'='*70}")
        print(result)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        logger.exception("Fatal error")
        print(f"\n❌ Fatal error: {e}")
        print(f"\nCheck logs: {LOG_FILE}")
        sys.exit(1)




if __name__ == "__main__":
    main()
