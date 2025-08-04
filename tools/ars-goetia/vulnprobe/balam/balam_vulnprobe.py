#!/usr/bin/env python3
"""
Balam Vulnerability Probe v2.0
Named after Balam: the demon who speaks truthfully of vulnerabilities, revealing both technical and business risk.

Advanced vulnerability assessment and deep analysis for bug bounty hunting.
Continues from Andromalius Phase 1 reconnaissance results.

Combines:
- gpt.txt: Exploitation automation (nmap, gobuster, nuclei, basic takeover)
- claude.txt: Advanced web/app/network, custom vuln logic, subdomain takeover, tech-specific checks
- gemini.txt: Fuzzing, parameter probing, known tech vulns, CORS/VCS checks, email harvesting, robust reporting

Usage:
    python3 balam_vulnprobe.txt -i ./andromalius_results -o ./balam_results
    python3 balam_vulnprobe.txt -i ./recon -o ./vuln_scan -T 30 --timeout 15

Prerequisites:
    • Run Andromalius Phase 1 first (Draft.txt)
    • Install required tools: nmap, nuclei, gobuster, ffuf, (optional: theHarvester)
    • Ensure proper permissions for port scanning
"""

import os
import sys
import json
import subprocess
import threading
import time
import requests
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote
import socket
import ssl
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ANSI Colors
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# ----------- Helper Functions -----------

def print_banner():
    banner = f"""
{Colors.BOLD}{Colors.RED}
██████╗  █████╗ ██╗      █████╗ ███╗   ███╗    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██║     ██╔══██╗████╗ ████║    ██║   ██║██║   ██║██║     ████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
██████╔╝███████║██║     ███████║██╔████╔██║    ██║   ██║██║   ██║██║     ██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
██╔══██╗██╔══██║██║     ██╔══██║██║╚██╔╝██║    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
██████╔╝██║  ██║███████╗██║  ██║██║ ╚═╝ ██║     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
{Colors.END}
{Colors.BOLD}{Colors.RED}      Demon of Truth & Future Sight - Advanced Vulnerability Assessment v2.0{Colors.END}
{Colors.YELLOW}Automates advanced post-recon probing and vulnerability analysis using Andromalius outputs.{Colors.END}
{Colors.BLUE}Disclaimer: Use only on targets you are authorized to test.{Colors.END}
{"-" * 90}
"""
    print(banner)

def check_tools(tools_list):
    missing_tools = []
    print(f"{Colors.BOLD}{Colors.BLUE}[*] Checking for required tools...{Colors.END}")
    for tool in tools_list:
        try:
            subprocess.run(['which', tool], check=True, capture_output=True, text=True)
            print(f"{Colors.GREEN}[+] {tool} found.{Colors.END}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_tools.append(tool)
            print(f"{Colors.RED}[-] {tool} not found. Please install it.{Colors.END}")
    if missing_tools:
        print(f"\n{Colors.RED}[!] Some required tools are missing: {', '.join(missing_tools)}{Colors.END}")
        print(f"{Colors.YELLOW}[!] Please install them before running the script.{Colors.END}")
        sys.exit(1)
    print(f"{Colors.BOLD}{Colors.GREEN}[*] All required tools found!{Colors.END}\n")

def run_command(cmd, outfile=None, shell=False, silent=False):
    try:
        if not silent:
            print(f"{Colors.BLUE}[*] Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}{Colors.END}")
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=600
        )
        if outfile and result.stdout.strip():
            with open(outfile, "w") as f:
                f.write(result.stdout)
        return result.stdout.strip() if result.returncode == 0 else ""
    except subprocess.TimeoutExpired:
        if not silent:
            print(f"{Colors.YELLOW}[!] Command timed out: {cmd}{Colors.END}")
        return ""
    except Exception as e:
        if not silent:
            print(f"{Colors.RED}[!] Command failed: {cmd} - {e}{Colors.END}")
        return ""

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

# ----------- Main Class -----------

class BalamVulnProbe:
    def __init__(self, input_dir, output_dir, threads=30, timeout=15):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.threads = threads
        self.timeout = timeout
        self.session = self._create_session()
        self.print_lock = threading.Lock()
        # Data storage
        self.live_hosts = []
        self.technologies = {}
        self.dns_info = {}
        self.whois_info = ""
        self.vulnerabilities = []
        self.ssl_issues = []
        self.directory_results = {}
        self.takeover_results = []
        self.harvested_emails = set()
        # Load phase 1 data
        self.load_andromalius_data()

    def _create_session(self):
        session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.verify = False
        session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; BalamProbe/2.0)'})
        return session

    def safe_print(self, message):
        with self.print_lock:
            print(message)

    def load_andromalius_data(self):
        self.safe_print(f"{Colors.BLUE}[*] Loading Andromalius reconnaissance data from {self.input_dir}...{Colors.END}")
        # live_hosts.json
        live_hosts_file = self.input_dir / "live_hosts.json"
        if live_hosts_file.exists():
            with open(live_hosts_file, "r") as f:
                self.live_hosts = json.load(f)
            self.safe_print(f"{Colors.GREEN}[+] Loaded {len(self.live_hosts)} live hosts{Colors.END}")
        # technologies.json
        tech_file = self.input_dir / "technologies.json"
        if tech_file.exists():
            with open(tech_file, "r") as f:
                self.technologies = json.load(f)
            self.safe_print(f"{Colors.GREEN}[+] Loaded technology fingerprints{Colors.END}")
        # dns_info.json
        dns_file = self.input_dir / "dns_info.json"
        if dns_file.exists():
            with open(dns_file, "r") as f:
                self.dns_info = json.load(f)
        # whois.txt
        whois_file = self.input_dir / "whois.txt"
        if whois_file.exists():
            with open(whois_file, "r") as f:
                self.whois_info = f.read()

        if not self.live_hosts:
            self.safe_print(f"{Colors.RED}[!] No live hosts found. Run Andromalius Phase 1 first.{Colors.END}")
            sys.exit(1)

    # ---------------------- Modules ----------------------

    def run_nmap(self):
        self.safe_print(f"{Colors.BLUE}[*] Running Nmap port scans...{Colors.END}")
        unique_ips = set()
        for host in self.live_hosts:
            hostname = urlparse(host['url']).hostname
            ip = resolve_ip(hostname)
            if ip:
                unique_ips.add(ip)
        if not unique_ips:
            self.safe_print(f"{Colors.YELLOW}[!] No IPs to scan{Colors.END}")
            return
        ips_file = self.output_dir / "target_ips.txt"
        with open(ips_file, "w") as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")
        nmap_cmd = [
            'nmap', '-sS', '-sV', '-O', '--top-ports', '1000',
            '-T3', '--open', '--version-intensity', '5',
            '-oA', str(self.output_dir / 'nmap_scan'),
            '-iL', str(ips_file)
        ]
        run_command(nmap_cmd, self.output_dir / "nmap_results.txt")
        self.safe_print(f"{Colors.GREEN}[+] Nmap scan complete{Colors.END}")

    def run_nmap_vuln(self):
        self.safe_print(f"{Colors.BLUE}[*] Running Nmap vuln script scan...{Colors.END}")
        ips_file = self.output_dir / "target_ips.txt"
        top_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080,8443"
        vuln_cmd = [
            'nmap', '--script', 'vuln', '-sV', '-p', top_ports,
            '-oA', str(self.output_dir / 'nmap_vulns'),
            '-iL', str(ips_file)
        ]
        run_command(vuln_cmd, self.output_dir / "nmap_vulns.txt")
        self.safe_print(f"{Colors.GREEN}[+] Nmap vuln scan complete{Colors.END}")

    def run_gobuster(self):
        self.safe_print(f"{Colors.BLUE}[*] Running Gobuster on web services...{Colors.END}")
        # Use common wordlist, override via env
        wordlist = os.getenv("FUZZ_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
        for host in self.live_hosts:
            url = host['url']
            hostname = urlparse(url).hostname
            output_file = self.output_dir / f"gobuster_{hostname}.txt"
            cmd = [
                "gobuster", "dir",
                "-u", url,
                "-w", wordlist,
                "-q", "-t", "20", "-o", str(output_file)
            ]
            run_command(cmd, output_file)
            self.safe_print(f"{Colors.GREEN}  ✓ Gobuster done: {url}{Colors.END}")

    def run_ffuf_fuzz(self):
        self.safe_print(f"{Colors.BLUE}[*] Running ffuf fuzzing on live hosts...{Colors.END}")
        wordlists = {
            "common": os.getenv("FUZZ_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/common.txt"),
            "api": os.getenv("API_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"),
            "backup": os.getenv("BACKUP_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/backups.txt")
        }
        ffuf_dir = self.output_dir / "ffuf_output"
        ffuf_dir.mkdir(exist_ok=True)
        for name, wordlist_path in wordlists.items():
            if not Path(wordlist_path).exists():
                self.safe_print(f"{Colors.YELLOW}[!] Wordlist not found: {wordlist_path}. Skipping {name} fuzzing.{Colors.END}")
                continue
            for host in self.live_hosts:
                fuzz_url = urljoin(host['url'], "FUZZ")
                out_file = ffuf_dir / f"{urlparse(host['url']).hostname}_{name}.txt"
                cmd = [
                    "ffuf", "-u", fuzz_url, "-w", wordlist_path,
                    "-mc", "200,204,301,302,307,401,403",
                    "-ac", "-recursion", "-recursion-depth", "1",
                    "-o", str(out_file), "-of", "csv", "-s"
                ]
                run_command(cmd, out_file)
                self.safe_print(f"{Colors.GREEN}  ✓ ffuf fuzzed: {fuzz_url} ({name}){Colors.END}")

    def run_nuclei(self):
        self.safe_print(f"{Colors.BLUE}[*] Running Nuclei vulnerability scans...{Colors.END}")
        urls_file = self.output_dir / "nuclei_targets.txt"
        with open(urls_file, 'w') as f:
            for host in self.live_hosts:
                f.write(f"{host['url']}\n")
        run_command(['nuclei', '-update-templates'], silent=True)
        nuclei_cmd = [
            'nuclei', '-l', str(urls_file),
            '-severity', 'low,medium,high,critical',
            '-o', str(self.output_dir / 'nuclei_results.txt'),
            '-json-export', str(self.output_dir / 'nuclei_results.json'),
            '-rate-limit', '50'
        ]
        run_command(nuclei_cmd)
        self.safe_print(f"{Colors.GREEN}[+] Nuclei scan complete{Colors.END}")

    def ssl_analysis(self):
        self.safe_print(f"{Colors.BLUE}[*] SSL/TLS analysis...{Colors.END}")
        def check_ssl(url):
            try:
                parsed = urlparse(url)
                if parsed.scheme != 'https':
                    return None
                hostname = parsed.hostname
                port = parsed.port or 443
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        issues = []
                        if cipher and ('RC4' in cipher[0] or 'DES' in cipher[0]):
                            issues.append("Weak cipher detected")
                        import datetime
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.datetime.now()).days
                        if days_until_expiry < 30:
                            issues.append(f"Certificate expires in {days_until_expiry} days")
                        return {
                            'url': url,
                            'cipher': cipher,
                            'cert_subject': dict(x[0] for x in cert['subject']),
                            'cert_issuer': dict(x[0] for x in cert['issuer']),
                            'expires': cert['notAfter'],
                            'days_until_expiry': days_until_expiry,
                            'issues': issues
                        }
            except Exception as e:
                return {'url': url, 'error': str(e)}
        https_hosts = [h for h in self.live_hosts if h['url'].startswith('https://')]
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_ssl, host['url']): host for host in https_hosts}
            for future in as_completed(futures):
                result = future.result()
                if result and 'error' not in result:
                    self.ssl_issues.append(result)
                    if result.get('issues'):
                        self.safe_print(f"{Colors.YELLOW}    ⚠ {result['url']}: {', '.join(result['issues'])}{Colors.END}")
                    else:
                        self.safe_print(f"{Colors.GREEN}    ✓ {result['url']}{Colors.END}")
        with open(self.output_dir / "ssl_analysis.json", 'w') as f:
            json.dump(self.ssl_issues, f, indent=2)
        self.safe_print(f"{Colors.GREEN}[+] SSL/TLS analysis complete{Colors.END}")

    def custom_vuln_checks(self):
        self.safe_print(f"{Colors.BLUE}[*] Custom vulnerability checks...{Colors.END}")
        def check_host_vulns(host_info):
            url = host_info['url']
            findings = []
            try:
                # Common endpoints
                test_endpoints = [
                    '/.git/config', '/.env', '/config.php', '/phpinfo.php', '/admin', '/administrator',
                    '/wp-admin/', '/api/v1/', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
                    '/crossdomain.xml', '/clientaccesspolicy.xml'
                ]
                for endpoint in test_endpoints:
                    test_url = urljoin(url, endpoint)
                    try:
                        resp = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                        if resp.status_code == 200:
                            findings.append({
                                'type': 'exposed_file',
                                'severity': 'medium',
                                'url': test_url,
                                'status': resp.status_code,
                                'size': len(resp.content)
                            })
                    except:
                        pass
                # Directory traversal
                traversal_payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts']
                for payload in traversal_payloads:
                    test_url = f"{url}/{quote(payload)}"
                    try:
                        resp = self.session.get(test_url, timeout=5, verify=False)
                        if 'root:' in resp.text or 'localhost' in resp.text:
                            findings.append({
                                'type': 'directory_traversal',
                                'severity': 'high',
                                'url': test_url,
                                'payload': payload
                            })
                    except:
                        pass
                # SQLi (basic)
                sqli_payloads = ["'", '"', "1' OR '1'='1", "1\" OR \"1\"=\"1"]
                test_params = ['id', 'user', 'search', 'q', 'query']
                for param in test_params:
                    for payload in sqli_payloads:
                        test_url = f"{url}/?{param}={quote(payload)}"
                        try:
                            resp = self.session.get(test_url, timeout=5, verify=False)
                            if any(error in resp.text.lower() for error in ['sql syntax', 'mysql_fetch', 'ora-01756', 'syntax error']):
                                findings.append({
                                    'type': 'sql_injection',
                                    'severity': 'high',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload
                                })
                                break
                        except:
                            pass
                return findings
            except Exception:
                return []
        all_findings = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_host_vulns, host): host for host in self.live_hosts[:50]}
            for future in as_completed(futures):
                findings = future.result()
                if findings:
                    all_findings.extend(findings)
                    for finding in findings:
                        color = Colors.RED if finding['severity'] == 'high' else Colors.YELLOW
                        self.safe_print(f"{color}    ! {finding['type']}: {finding['url']}{Colors.END}")
        self.vulnerabilities.extend(all_findings)
        with open(self.output_dir / "custom_vulns.json", 'w') as f:
            json.dump(all_findings, f, indent=2)
        self.safe_print(f"{Colors.GREEN}[+] Custom vulnerability checks complete{Colors.END}")

    def subdomain_takeover_check(self):
        self.safe_print(f"{Colors.BLUE}[*] Checking for subdomain takeovers...{Colors.END}")
        takeover_signatures = {
            'github.io': ['There isn\'t a GitHub Pages site here'],
            'herokuapp.com': ['No such app'],
            'amazonaws.com': ['NoSuchBucket', 'The specified bucket does not exist'],
            'cloudfront.net': ['Bad Request: ERROR: The request could not be satisfied'],
            'azure.com': ['404 Web Site not found'],
            'bitbucket.io': ['Repository not found']
        }
        # From Phase 1 output
        subdomains_file = self.input_dir / "all_subdomains.txt"
        subdomains = []
        if subdomains_file.exists():
            with open(subdomains_file) as f:
                subdomains = [line.strip() for line in f if line.strip()]
        findings = []
        for sub in subdomains:
            try:
                cname = None
                if DNS_AVAILABLE:
                    answers = dns.resolver.resolve(sub, 'CNAME')
                    cname = str(answers[0]).lower()
                else:
                    try:
                        cname = socket.gethostbyname_ex(sub)[1][0] if socket.gethostbyname_ex(sub)[1] else None
                    except:
                        pass
                if cname:
                    for service, signatures in takeover_signatures.items():
                        if service in cname:
                            url = f"http://{sub}"
                            try:
                                resp = self.session.get(url, timeout=10, verify=False)
                                for signature in signatures:
                                    if signature in resp.text:
                                        findings.append({
                                            'hostname': sub,
                                            'cname': cname,
                                            'service': service,
                                            'signature': signature,
                                            'severity': 'critical'
                                        })
                                        self.safe_print(f"{Colors.RED}    🚨 POTENTIAL TAKEOVER: {sub} -> {cname}{Colors.END}")
                                        break
                            except:
                                pass
                            break
            except Exception:
                pass
        if findings:
            with open(self.output_dir / "subdomain_takeovers.json", 'w') as f:
                json.dump(findings, f, indent=2)
            self.vulnerabilities.extend(findings)
        self.takeover_results = findings
        self.safe_print(f"{Colors.GREEN}[+] Subdomain takeover check complete{Colors.END}")

    def tech_specific_checks(self):
        self.safe_print(f"{Colors.BLUE}[*] Technology-specific vulnerability checks...{Colors.END}")
        tech_findings = []
        for url, techs in self.technologies.items():
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            for tech in techs:
                tech_lower = tech.lower()
                # WordPress
                if 'wordpress' in tech_lower:
                    wp_endpoints = [
                        '/wp-admin/admin-ajax.php', '/wp-content/debug.log', '/wp-config.php.bak',
                        '/wp-json/wp/v2/users', '/?rest_route=/wp/v2/users'
                    ]
                    for endpoint in wp_endpoints:
                        test_url = base_url + endpoint
                        try:
                            resp = self.session.get(test_url, timeout=5, verify=False)
                            if resp.status_code == 200:
                                tech_findings.append({
                                    'type': 'wordpress_exposure',
                                    'url': test_url,
                                    'endpoint': endpoint,
                                    'severity': 'medium'
                                })
                                self.safe_print(f"{Colors.YELLOW}    ⚠ WordPress exposure: {test_url}{Colors.END}")
                        except:
                            pass
                # Drupal
                elif 'drupal' in tech_lower:
                    drupal_endpoints = [
                        '/CHANGELOG.txt', '/README.txt', '/user/register', '/admin/reports/status'
                    ]
                    for endpoint in drupal_endpoints:
                        test_url = base_url + endpoint
                        try:
                            resp = self.session.get(test_url, timeout=5, verify=False)
                            if resp.status_code == 200:
                                tech_findings.append({
                                    'type': 'drupal_exposure',
                                    'url': test_url,
                                    'endpoint': endpoint,
                                    'severity': 'low'
                                })
                        except:
                            pass
                # PHP
                elif 'php' in tech_lower:
                    php_endpoints = [
                        '/phpinfo.php', '/info.php', '/test.php', '/config.php.bak'
                    ]
                    for endpoint in php_endpoints:
                        test_url = base_url + endpoint
                        try:
                            resp = self.session.get(test_url, timeout=5, verify=False)
                            if resp.status_code == 200 and 'phpinfo()' in resp.text:
                                tech_findings.append({
                                    'type': 'phpinfo_exposure',
                                    'url': test_url,
                                    'severity': 'high'
                                })
                                self.safe_print(f"{Colors.RED}    🚨 PHPInfo exposure: {test_url}{Colors.END}")
                        except:
                            pass
        self.vulnerabilities.extend(tech_findings)
        with open(self.output_dir / "tech_specific_vulns.json", 'w') as f:
            json.dump(tech_findings, f, indent=2)
        self.safe_print(f"{Colors.GREEN}[+] Technology-specific checks complete{Colors.END}")

    def check_cors(self):
        self.safe_print(f"{Colors.BLUE}[*] Checking for CORS misconfigurations...{Colors.END}")
        output_file = self.output_dir / "cors_results.txt"
        with open(output_file, 'w') as f_out:
            for host_info in self.live_hosts:
                url = host_info['url']
                test_origins = ["null", "https://evil.com", f"https://sub.evil.{urlparse(url).hostname}"]
                for origin in test_origins:
                    try:
                        headers = {'Origin': origin}
                        response = self.session.options(url, headers=headers, timeout=self.timeout)
                        if 'Access-Control-Allow-Origin' in response.headers:
                            acao = response.headers['Access-Control-Allow-Origin']
                            f_out.write(f"URL: {url}, Origin: {origin}, ACAO: {acao}\n")
                            if acao == "*" or (origin != "null" and acao == origin):
                                self.vulnerabilities.append({
                                    "type": "cors_misconfig",
                                    "url": url,
                                    "origin": origin,
                                    "ACAO": acao,
                                    "severity": "medium"
                                })
                                self.safe_print(f"{Colors.YELLOW}    ⚠ CORS misconfiguration: {url} allows '{acao}' for '{origin}'{Colors.END}")
                        else:
                            f_out.write(f"URL: {url}, Origin: {origin}, No ACAO header.\n")
                    except Exception as e:
                        f_out.write(f"URL: {url}, Origin: {origin}, Error: {e}\n")
        self.safe_print(f"{Colors.GREEN}[+] CORS check complete{Colors.END}")

    def check_exposed_vcs(self):
        self.safe_print(f"{Colors.BLUE}[*] Checking for exposed VCS (.git/.svn)...{Colors.END}")
        vcs_paths = [".git/HEAD", ".git/config", ".svn/entries"]
        output_file = self.output_dir / "exposed_vcs_results.txt"
        with open(output_file, 'w') as f_out:
            for host_info in self.live_hosts:
                base_url = host_info['url']
                for path in vcs_paths:
                    test_url = urljoin(base_url, path)
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        if response.status_code == 200 and len(response.content) > 0:
                            f_out.write(f"URL: {test_url}, Status: {response.status_code}, Content-Length: {len(response.content)}\n")
                            self.vulnerabilities.append({
                                "type": "exposed_vcs",
                                "url": test_url,
                                "severity": "high"
                            })
                            self.safe_print(f"{Colors.RED}    ! Exposed VCS: {test_url}{Colors.END}")
                    except Exception as e:
                        f_out.write(f"URL: {test_url}, Error: {e}\n")
        self.safe_print(f"{Colors.GREEN}[+] Exposed VCS check complete{Colors.END}")

    def check_known_tech_vulnerabilities(self):
        self.safe_print(f"{Colors.BLUE}[*] Checking for known technology vulnerabilities...{Colors.END}")
        output_file = self.output_dir / "known_tech_vulnerabilities.txt"
        with open(output_file, 'w') as f_out:
            for url, tech_list in self.technologies.items():
                f_out.write(f"--- Checking {url} ---\n")
                if not tech_list:
                    f_out.write("No technologies identified.\n\n")
                    continue
                f_out.write(f"Identified Technologies: {', '.join(tech_list)}\n")
                for tech in tech_list:
                    # WordPress
                    if "WordPress" in tech:
                        f_out.write("  - Checking for WordPress common paths...\n")
                        wp_paths = ["/wp-admin/", "/wp-login.php", "/xmlrpc.php"]
                        for path in wp_paths:
                            test_url = urljoin(url, path)
                            try:
                                response = self.session.get(test_url, timeout=self.timeout)
                                if response.status_code == 200:
                                    self.vulnerabilities.append({
                                        "type": "wp_common_path",
                                        "url": test_url,
                                        "severity": "low"
                                    })
                            except Exception:
                                pass
                    elif "Apache" in tech or "Nginx" in tech:
                        f_out.write("  - Checking for Apache/Nginx misconfigurations...\n")
                        test_url = urljoin(url, "/test/")
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            if response.status_code == 200 and ("Index of /" in response.text or "Directory Listing" in response.text):
                                self.vulnerabilities.append({
                                    "type": "dir_listing_enabled",
                                    "url": test_url,
                                    "severity": "medium"
                                })
                        except Exception:
                            pass
                f_out.write("\n")
        self.safe_print(f"{Colors.GREEN}[+] Known technology vulnerability checks complete{Colors.END}")

    def check_common_params(self):
        self.safe_print(f"{Colors.BLUE}[*] Probing common URL parameters...{Colors.END}")
        common_params = [
            "next", "url", "redirect", "dest", "continue", "return", "data", "file", "image", "src",
            "id", "q", "query", "search", "name", "callback", "jsonp"
        ]
        payloads = {
            "open_redirect": "https://evil.com",
            "xss_basic": "<script>alert(document.domain)</script>",
            "sqli_basic": "' OR 1=1--",
            "ssrf_basic": "http://127.0.0.1:80",
            "lfi_basic": "../../../etc/passwd"
        }
        output_file = self.output_dir / "parameter_probe_results.txt"
        with open(output_file, 'w') as f_out:
            for host_info in self.live_hosts:
                base_url = host_info['url']
                for param in common_params:
                    for p_type, payload in payloads.items():
                        test_url = f"{base_url}?{param}={payload}"
                        try:
                            response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                            f_out.write(f"URL: {test_url}\nStatus: {response.status_code}\n")
                            if response.status_code in [301, 302, 307, 308] and 'Location' in response.headers:
                                if payload in response.headers['Location']:
                                    self.vulnerabilities.append({
                                        "type": "open_redirect",
                                        "url": test_url,
                                        "parameter": param,
                                        "severity": "medium"
                                    })
                            if p_type == "xss_basic" and payload.replace("<script>", "").replace("</script>", "") in response.text:
                                self.vulnerabilities.append({
                                    "type": "reflected_xss",
                                    "url": test_url,
                                    "parameter": param,
                                    "severity": "low"
                                })
                            if p_type == "sqli_basic" and ("syntax" in response.text.lower() or "mysql" in response.text.lower() or "sql" in response.text.lower()):
                                self.vulnerabilities.append({
                                    "type": "sqli_error",
                                    "url": test_url,
                                    "parameter": param,
                                    "severity": "medium"
                                })
                            if p_type == "ssrf_basic" and response.status_code == 200 and "root:x" in response.text.lower():
                                self.vulnerabilities.append({
                                    "type": "lfi",
                                    "url": test_url,
                                    "parameter": param,
                                    "severity": "high"
                                })
                        except Exception as e:
                            f_out.write(f"URL: {test_url}\nError: {e}\n")
        self.safe_print(f"{Colors.GREEN}[+] Common parameter probing complete{Colors.END}")

    def harvest_emails(self):
        self.safe_print(f"{Colors.BLUE}[*] Harvesting emails from WHOIS and open sources...{Colors.END}")
        output_file = self.output_dir / "harvested_emails.txt"
        found_emails = set()
        import re
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        if self.whois_info:
            emails_from_whois = re.findall(email_pattern, self.whois_info)
            found_emails.update(emails_from_whois)
        try:
            subprocess.run(['which', 'theHarvester'], check=True, capture_output=True, text=True)
            main_domain = self.dns_info.get('target', '').replace('*.', '')
            if main_domain:
                harvester_cmd = ["theHarvester", "-d", main_domain, "-b", "google,linkedin,twitter", "-f", str(self.output_dir / "theharvester_results.xml")]
                run_command(harvester_cmd)
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(self.output_dir / "theharvester_results.xml")
                    root = tree.getroot()
                    for email_elem in root.findall('.//email'):
                        if email_elem.text:
                            found_emails.add(email_elem.text.strip())
                except Exception as e:
                    self.safe_print(f"{Colors.YELLOW}[!] Error parsing theHarvester XML: {e}{Colors.END}")
            else:
                self.safe_print(f"{Colors.YELLOW}[!] Main domain not found in DNS info. Cannot run theHarvester.{Colors.END}")
        except Exception:
            self.safe_print(f"{Colors.YELLOW}[!] 'theHarvester' tool not found or not in PATH. Skipping theHarvester.{Colors.END}")
        if found_emails:
            with open(output_file, 'w') as f:
                for email in sorted(list(found_emails)):
                    f.write(f"{email}\n")
            self.safe_print(f"{Colors.GREEN}[+] Found {len(found_emails)} emails. See {output_file}{Colors.END}")
        else:
            self.safe_print(f"{Colors.YELLOW}[!] No emails harvested.{Colors.END}")
        self.harvested_emails = found_emails

    # ---------------------- Reporting ----------------------

    def generate_report(self):
        self.safe_print(f"{Colors.BLUE}[*] Generating Phase 2 report...{Colors.END}")
        critical_vulns = [v for v in self.vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in self.vulnerabilities if v.get('severity') == 'high']
        medium_vulns = [v for v in self.vulnerabilities if v.get('severity') == 'medium']
        low_vulns = [v for v in self.vulnerabilities if v.get('severity') == 'low']
        ssl_critical = [s for s in self.ssl_issues if s.get('issues')]
        report = f"""
{Colors.BOLD}{Colors.RED}BALAM VULNERABILITY PROBE - DEEP ANALYSIS REPORT{Colors.END}
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
{"="*90}

{Colors.BOLD}🎯 EXECUTIVE SUMMARY{Colors.END}
• Hosts Analyzed: {len(self.live_hosts)}
• Total Vulnerabilities: {len(self.vulnerabilities)}
• Critical: {len(critical_vulns)} | High: {len(high_vulns)} | Medium: {len(medium_vulns)} | Low: {len(low_vulns)}
• SSL/TLS Issues: {len(ssl_critical)}
• Directory Scans: {len(self.directory_results)}

{Colors.BOLD}🚨 CRITICAL FINDINGS{Colors.END}
"""
        for vuln in critical_vulns[:10]:
            report += f"• {vuln.get('type', 'Unknown').upper()}: {vuln.get('url', vuln.get('hostname', 'N/A'))}\n"
        report += f"""
{Colors.BOLD}⚠️  HIGH SEVERITY FINDINGS{Colors.END}
"""
        for vuln in high_vulns[:15]:
            report += f"• {vuln.get('type', 'Unknown').upper()}: {vuln.get('url', vuln.get('hostname', 'N/A'))}\n"
        report += f"""
{Colors.BOLD}🔧 TOOLS USED{Colors.END}
• Nmap (port scanning & vulnerability detection)
• Gobuster/FFUF (directory bruteforcing)
• Nuclei (vulnerability scanning)
• Custom vulnerability checks
• SSL/TLS analysis
• Subdomain takeover detection
• CORS/VCS checks
• Parameter probing
• Email harvesting

{Colors.BOLD}📁 GENERATED FILES{Colors.END}
"""
        files = list(self.output_dir.glob('*'))
        for file in sorted(files):
            if file.is_file():
                size = file.stat().st_size
                report += f"• {file.name} ({size} bytes)\n"
        report += f"""
{Colors.BOLD}🎯 PRIORITY TARGETS FOR MANUAL TESTING{Colors.END}
"""
        priority_targets = []
        for vuln in critical_vulns + high_vulns:
            if vuln.get('url'):
                priority_targets.append(vuln['url'])
            elif vuln.get('hostname'):
                priority_targets.append(vuln['hostname'])
        priority_targets = list(set(priority_targets))[:10]
        for target in priority_targets:
            report += f"• {target}\n"
        report += f"""
{Colors.BOLD}💡 NEXT STEPS{Colors.END}
1. Manual verification of critical/high findings
2. Exploit development for confirmed vulnerabilities
3. Privilege escalation testing on compromised systems
4. Data exfiltration proof of concepts
5. Business logic testing
6. Authentication bypass attempts
7. Session management testing

{Colors.BOLD}🔍 MANUAL TESTING CHECKLIST{Colors.END}
[ ] SQL Injection (manual payloads)
[ ] Cross-Site Scripting (XSS)
[ ] Cross-Site Request Forgery (CSRF)
[ ] Authentication bypass
[ ] Authorization flaws
[ ] Business logic vulnerabilities
[ ] File upload vulnerabilities
[ ] Local/Remote File Inclusion
[ ] Server-Side Request Forgery (SSRF)
[ ] XML External Entity (XXE)
[ ] Insecure Direct Object References
[ ] Security misconfigurations

{Colors.BOLD}📊 VULNERABILITY BREAKDOWN{Colors.END}
"""
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vtype = vuln.get('type', 'unknown')
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        for vtype, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            report += f"• {vtype.replace('_', ' ').title()}: {count}\n"
        report += f"""
{Colors.BOLD}🛡️  REMEDIATION PRIORITIES{Colors.END}
1. Fix critical vulnerabilities immediately
2. Patch high-severity findings within 48 hours
3. Address medium-severity issues within 1 week
4. Review and harden SSL/TLS configurations
5. Implement proper access controls
6. Remove exposed sensitive files
7. Update vulnerable software components

{Colors.BOLD}⚠️  IMPORTANT NOTES{Colors.END}
• This is an automated analysis - manual verification required
• Some findings may be false positives
• Test in a controlled environment first
• Follow responsible disclosure practices
• Document all findings with proof of concepts
• Ensure proper authorization before testing

{Colors.BOLD}📈 BUG BOUNTY TIPS{Colors.END}
• Focus on critical/high severity findings first
• Chain vulnerabilities for maximum impact
• Look for business logic flaws in custom applications
• Test authentication and authorization thoroughly
• Check for subdomain takeovers (easy wins)
• Verify all findings before reporting
• Write clear, detailed reports with PoCs
"""
        import re
        clean_report = re.sub(r'\x1b\[[0-9;]*m', '', report)
        with open(self.output_dir / "BALAM_VULNERABILITY_REPORT.txt", 'w') as f:
            f.write(clean_report)
        print(report)
        with open(self.output_dir / "all_vulnerabilities.json", 'w') as f:
            json.dump({
                'critical': critical_vulns,
                'high': high_vulns,
                'medium': medium_vulns,
                'low': low_vulns,
                'summary': {
                    'total': len(self.vulnerabilities),
                    'critical': len(critical_vulns),
                    'high': len(high_vulns),
                    'medium': len(medium_vulns),
                    'low': len(low_vulns)
                }
            }, f, indent=2)

    # ---------------------- Runner ----------------------

    def run_balam_probe(self):
        start_time = time.time()
        print_banner()
        try:
            # PHASE A: Network Scanning & Service Fingerprinting
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{Colors.CYAN}🔍 PHASE A: NETWORK RECONNAISSANCE{Colors.END}")
            self.run_nmap()
            self.run_nmap_vuln()
            # PHASE B: Web/App Assessment
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{Colors.CYAN}🌐 PHASE B: WEB APPLICATION ASSESSMENT{Colors.END}")
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(self.run_gobuster),
                    executor.submit(self.run_ffuf_fuzz),
                    executor.submit(self.run_nuclei),
                    executor.submit(self.ssl_analysis)
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.safe_print(f"{Colors.RED}[!] Error in web assessment: {e}{Colors.END}")
            # PHASE C: Vulnerability Discovery
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{Colors.CYAN}🎯 PHASE C: VULNERABILITY DISCOVERY{Colors.END}")
            with ThreadPoolExecutor(max_workers=6) as executor:
                futures = [
                    executor.submit(self.custom_vuln_checks),
                    executor.submit(self.subdomain_takeover_check),
                    executor.submit(self.tech_specific_checks),
                    executor.submit(self.check_cors),
                    executor.submit(self.check_exposed_vcs),
                    executor.submit(self.check_known_tech_vulnerabilities),
                    executor.submit(self.check_common_params),
                    executor.submit(self.harvest_emails)
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.safe_print(f"{Colors.RED}[!] Error in vulnerability discovery: {e}{Colors.END}")
            # Generate final report
            self.generate_report()
            elapsed = time.time() - start_time
            print(f"\n{Colors.BOLD}{Colors.GREEN}🏁 BALAM VULNERABILITY PROBE COMPLETE{Colors.END}")
            print(f"{Colors.CYAN}⏱️  Total time: {elapsed:.2f} seconds{Colors.END}")
            print(f"{Colors.CYAN}📁 Results: {self.output_dir}{Colors.END}")
            print(f"{Colors.CYAN}🚨 Vulnerabilities: {len(self.vulnerabilities)}{Colors.END}")
            critical_count = len([v for v in self.vulnerabilities if v.get('severity') == 'critical'])
            high_count = len([v for v in self.vulnerabilities if v.get('severity') == 'high'])
            if critical_count > 0:
                print(f"{Colors.BOLD}{Colors.RED}⚠️  {critical_count} CRITICAL vulnerabilities revealed by Balam!{Colors.END}")
            if high_count > 0:
                print(f"{Colors.BOLD}{Colors.YELLOW}⚠️  {high_count} HIGH severity vulnerabilities discovered!{Colors.END}")
            print(f"\n{Colors.BOLD}{Colors.PURPLE}💀 Balam has spoken the truth of vulnerabilities. Ready for exploitation!{Colors.END}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Balam vulnerability probe interrupted by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Fatal error in Balam probe: {e}{Colors.END}")
            import traceback
            traceback.print_exc()

# ---------------------- Main ----------------------

def main():
    parser = argparse.ArgumentParser(
        description="Balam Vulnerability Probe - Advanced Vulnerability Assessment (Phase 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 balam_vulnprobe.txt -i ./andromalius_results -o ./balam_results
  python3 balam_vulnprobe.txt -i ./recon -o ./vuln_scan -T 30 --timeout 15

Probing Tips:
  • Always verify automated findings manually.
  • Be aware of WAF/IDS/IPS and adjust scan speed/techniques.
  • Focus on high-impact vulnerabilities after initial scans.
        """
    )
    parser.add_argument("-i", "--input", required=True, help="Input directory from Andromalius reconnaissance")
    parser.add_argument("-o", "--output", required=True, help="Output directory for Balam vulnerability results")
    parser.add_argument("-T", "--threads", type=int, default=30, help="Number of threads (default: 30)")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds (default: 15)")
    args = parser.parse_args()
    # Tool check
    required_tools = ['nmap', 'nuclei', 'gobuster', 'ffuf']
    check_tools(required_tools)
    # Validate input directory
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"{Colors.RED}❌ Input directory does not exist: {args.input}{Colors.END}")
        sys.exit(1)
    if not (input_path / "live_hosts.json").exists():
        print(f"{Colors.RED}❌ live_hosts.json not found. Run Andromalius reconnaissance first.{Colors.END}")
        sys.exit(1)
    # Run Balam vulnerability probe
    probe = BalamVulnProbe(args.input, args.output, args.threads, args.timeout)
    probe.run_balam_probe()

if __name__ == "__main__":
    main()
