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
    install_command: List[str]
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
            try:
                ipaddress.ip_address(target)
                continue
            except ValueError:
                pass
            
            try:
                ipaddress.ip_network(target, strict=False)
                continue
            except ValueError:
                pass
            
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
        data['command'] = ' '.join(self.command)
        return data
    
    def success(self) -> bool:
        return self.exit_code == 0


# ============================================================================
# TOOL REGISTRY
# ============================================================================

TOOL_REGISTRY: Dict[str, ToolDefinition] = {
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
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Security Manager initialized. Config: {self.config_dir}")
    
    def load_authorized_scopes(self) -> List[ScanScope]:
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
        scopes = self.load_authorized_scopes()
        
        for existing in scopes:
            if existing.scope_hash == scope.scope_hash:
                logger.info(f"Scope {scope.scope_hash} already authorized")
                return
        
        scopes.append(scope)
        
        with open(self.auth_file, 'w') as f:
            json.dump([s.dict() for s in scopes], f, indent=2)
        
        logger.info(f"Saved authorized scope: {scope.scope_hash}")
    
    def is_scope_authorized(self, targets: List[str]) -> Tuple[bool, Optional[str]]:
        test_scope = ScanScope(targets=targets, authorized=True)
        test_hash = test_scope.scope_hash
        
        authorized_scopes = self.load_authorized_scopes()
        
        for scope in authorized_scopes:
            if scope.scope_hash == test_hash and scope.authorized:
                return True, scope.authorization_note
        
        return False, None
    
    def authorize_scope_interactive(self, targets: List[str]) -> ScanScope:
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
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "data": data
        }
        
        with open(self.audit_file, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        
        logger.debug(f"Audit: {event_type}")
    
    def save_result(self, result: ExecutionResult):
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
        return shutil.which(tool_name) is not None
    
    def verify_tool(self, tool_def: ToolDefinition) -> bool:
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
        if tool_name not in TOOL_REGISTRY:
            logger.error(f"Unknown tool: {tool_name}")
            return False
        
        tool_def = TOOL_REGISTRY[tool_name]
        
        if self.verify_tool(tool_def):
            print(f"✓ {tool_name} is already installed")
            return True
        
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
                recommendations.extend(category_tools[:3])
        
        return list(dict.fromkeys(recommendations))[:5]


# ============================================================================
# SECURE COMMAND EXECUTOR
# ============================================================================

class SecureExecutor:
    """Executes commands safely with validation and logging"""
    
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
        self.current_scope: Optional[ScanScope] = None
    
    def set_scope(self, targets: List[str]):
        is_auth, note = self.security_manager.is_scope_authorized(targets)
        
        if is_auth:
            self.current_scope = ScanScope(
                targets=targets,
                authorized=True,
                authorization_note=note
            )
            logger.info(f"Scope set to authorized targets: {targets}")
        else:
            self.current_scope = self.security_manager.authorize_scope_interactive(targets)
    
    def validate_command(self, command: List[str]) -> Tuple[bool, str]:
        if not command:
            return False, "Empty command"
        
        dangerous_patterns = [';', '&&', '||', '|', '`', '$', '>', '<', '\n']
        for arg in command:
            for pattern in dangerous_patterns:
                if pattern in arg:
                    return False, f"Potentially dangerous pattern detected: {pattern}"
        
        if not shutil.which(command[0]):
            return False, f"Command not found: {command[0]}"
        
        return True, "OK"
    
    def execute_safe(self, command: List[str], timeout: int = 600, interactive: bool = True) -> ExecutionResult:
        is_valid, reason = self.validate_command(command)
        if not is_valid:
            logger.error(f"Command validation failed: {reason}")
            raise ValueError(f"Invalid command: {reason}")
        
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
        
        print(f"\n▶ Executing...")
        start_time = datetime.now()
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout,
                text=True,
                shell=False
            )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            exec_result = ExecutionResult(
                command=command,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                timestamp=start_time,
                duration_seconds=duration,
                scope_hash=self.current_scope.scope_hash if self.current_scope else None
            )
            
            if result.stdout:
                print("\n--- STDOUT ---")
                print(result.stdout)
            
            if result.stderr:
                print("\n--- STDERR ---")
                print(result.stderr)
            
            print(f"\n✓ Completed in {duration:.2f}s (exit code: {result.returncode})")
            
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
        success = self.tool_manager.install_tool(tool_name, interactive=True)
        return f"✓ {tool_name} installed" if success else f"✗ Failed to install {tool_name}"
    
    def execute_command_func(self, command_str: str) -> str:
        command_list = command_str.split()
        
        try:
            result = self.executor.execute_safe(command_list, interactive=True)
            return result.stdout if result.stdout else "Command completed successfully"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def set_scope_func(self, targets: str) -> str:
        target_list = [t.strip() for t in targets.split(",")]
        
        try:
            self.executor.set_scope(target_list)
            return f"✓ Scope set and authorized: {', '.join(target_list)}"
        except Exception as e:
            return f"✗ Failed to set scope: {str(e)}"
    
    def get_langchain_tools(self) -> List[Tool]:
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
        config_dir = Path.home() / ".secureagent"
        self.security_manager = SecurityManager(config_dir)
        self.tool_manager = ToolManager(self.security_manager)
        self.executor = SecureExecutor(self.security_manager)
        self.agent_tools = AgentTools(self.tool_manager, self.executor)
        
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
        
        self._create_agent()
    
    def _create_agent(self):
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
        
        agent = create_react_agent(
            llm=self.llm,
            tools=tools,
            prompt=prompt
        )
        
        self.agent_executor = AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=True,
            max_iterations=10,
            handle_parsing_errors=True,
            return_intermediate_steps=False
        )
