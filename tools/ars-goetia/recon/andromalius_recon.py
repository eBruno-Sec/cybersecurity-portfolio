#!/usr/bin/env python3
"""
Andromalius Reconnaissance Script v2.0
Named after the demon of secrets and surveillance from Ars Goetia

Production-ready automated Phase 1 reconnaissance for bug bounty hunting
"""

import os
import sys
import subprocess
import json
import requests
import time
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from pathlib import Path
import socket
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings for reconnaissance
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

class AndromaliusRecon:
    def __init__(self, target, output_dir, threads=50, timeout=10):
        self.target = target.replace('*.', '').replace('*', '').lower()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.threads = threads
        self.timeout = timeout
        self.subdomains = set()
        self.live_hosts = []
        self.technologies = {}
        self.session = self._create_session()
        
        # Thread-safe printing
        self.print_lock = threading.Lock()
        
    def _create_session(self):
        """Create a requests session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def safe_print(self, message):
        """Thread-safe printing"""
        with self.print_lock:
            print(message)

    def banner(self):
        banner = f"""{Colors.BOLD}{Colors.PURPLE}
 █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗     ██╗██╗   ██╗███████╗
██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║     ██║██║   ██║██╔════╝
███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██╔████╔██║███████║██║     ██║██║   ██║███████╗
██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║╚██╔╝██║██╔══██║██║     ██║██║   ██║╚════██║
██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║███████╗██║╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚══════╝
{Colors.END}
{Colors.BOLD}{Colors.CYAN}                Demon of Secrets & Surveillance - Phase 1 Recon v2.0{Colors.END}
{Colors.YELLOW}[🎯] Target: {self.target}{Colors.END}
{Colors.YELLOW}[📁] Output: {self.output_dir}{Colors.END}
{Colors.YELLOW}[🧵] Threads: {self.threads}{Colors.END}
{Colors.YELLOW}[⏱️ ] Timeout: {self.timeout}s{Colors.END}
{"-" * 80}
"""
        print(banner)

    def run_tool(self, cmd, output_file=None, silent=False):
        """Execute external tool safely"""
        try:
            if not silent:
                self.safe_print(f"{Colors.BLUE}[*] Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}{Colors.END}")
            
            result = subprocess.run(
                cmd,
                shell=isinstance(cmd, str),
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if output_file and result.stdout.strip():
                with open(self.output_dir / output_file, 'w') as f:
                    f.write(result.stdout)
            
            return result.stdout.strip() if result.returncode == 0 else ""
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            if not silent:
                self.safe_print(f"{Colors.RED}[!] Tool failed or not installed: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}{Colors.END}")
            return ""

    def crt_sh_search(self):
        """Query Certificate Transparency logs"""
        self.safe_print(f"{Colors.BLUE}[*] Querying Certificate Transparency...{Colors.END}")
        try:
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            }
            
            response = self.session.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                ct_subs = set()
                
                for cert in data:
                    name_value = cert.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip().lower()
                        if (domain.endswith(f".{self.target}") or domain == self.target) and not domain.startswith('*'):
                            ct_subs.add(domain)
                
                # Save results
                with open(self.output_dir / "crt_sh.txt", 'w') as f:
                    for sub in sorted(ct_subs):
                        f.write(f"{sub}\n")
                
                self.subdomains.update(ct_subs)
                self.safe_print(f"{Colors.GREEN}[+] Certificate Transparency: {len(ct_subs)} subdomains{Colors.END}")
                return ct_subs
                
        except Exception as e:
            self.safe_print(f"{Colors.RED}[!] crt.sh error: {e}{Colors.END}")
        return set()

    def subfinder_enum(self):
        """Run subfinder for passive enumeration"""
        self.safe_print(f"{Colors.BLUE}[*] Running subfinder...{Colors.END}")
        result = self.run_tool(['subfinder', '-d', self.target, '-all', '-silent'], 'subfinder.txt')
        
        if result:
            subs = set(line.strip() for line in result.split('\n') if line.strip())
            self.subdomains.update(subs)
            self.safe_print(f"{Colors.GREEN}[+] Subfinder: {len(subs)} subdomains{Colors.END}")
            return subs
        return set()

    def amass_enum(self):
        """Run amass passive enumeration"""
        self.safe_print(f"{Colors.BLUE}[*] Running amass passive...{Colors.END}")
        result = self.run_tool(['amass', 'enum', '-passive', '-d', self.target, '-silent'], 'amass.txt')
        
        if result:
            subs = set(line.strip() for line in result.split('\n') if line.strip())
            self.subdomains.update(subs)
            self.safe_print(f"{Colors.GREEN}[+] Amass: {len(subs)} subdomains{Colors.END}")
            return subs
        return set()

    def dns_bruteforce(self):
        """Fast DNS brute forcing with threading"""
        self.safe_print(f"{Colors.BLUE}[*] DNS brute forcing...{Colors.END}")
        
        # Extended wordlist for better coverage
        common_subs = [
            "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
            "cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile", "imap", "test",
            "staging", "stage", "dev", "development", "prod", "production", "api", "app",
            "blog", "forum", "shop", "store", "admin", "administrator", "root", "server",
            "web", "secure", "vpn", "remote", "access", "portal", "gateway", "firewall",
            "mail2", "email", "webdisk", "mysql", "sql", "db", "database", "backup",
            "old", "new", "demo", "beta", "alpha", "internal", "intranet", "extranet",
            "cdn", "static", "media", "img", "images", "upload", "download", "files",
            "support", "help", "docs", "wiki", "kb", "faq", "status", "monitoring",
            "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence", "redmine"
        ]
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in common_subs}
            found_subs = set()
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subs.add(result)
                    self.safe_print(f"{Colors.GREEN}    ✓ {result}{Colors.END}")
        
        if found_subs:
            with open(self.output_dir / "dns_bruteforce.txt", 'w') as f:
                for sub in sorted(found_subs):
                    f.write(f"{sub}\n")
            
            self.subdomains.update(found_subs)
            self.safe_print(f"{Colors.GREEN}[+] DNS Brute Force: {len(found_subs)} subdomains{Colors.END}")
        
        return found_subs

    def check_http_status(self, url):
        """Check HTTP status of a URL"""
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; AndromaliusRecon/2.0)'}
            )
            
            tech_headers = {
                'Server': response.headers.get('Server', ''),
                'X-Powered-By': response.headers.get('X-Powered-By', ''),
                'X-Generator': response.headers.get('X-Generator', ''),
                'X-Framework': response.headers.get('X-Framework', ''),
            }
            
            return {
                'url': url,
                'status': response.status_code,
                'title': self.extract_title(response.text),
                'content_length': len(response.content),
                'redirect': response.url if response.url != url else None,
                'tech_headers': {k: v for k, v in tech_headers.items() if v}
            }
            
        except Exception:
            return None

    def extract_title(self, html):
        """Extract title from HTML"""
        try:
            import re
            match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            return match.group(1).strip() if match else ""
        except:
            return ""

    def live_host_detection(self):
        """Multi-threaded live host detection"""
        if not self.subdomains:
            self.safe_print(f"{Colors.YELLOW}[!] No subdomains to check{Colors.END}")
            return
        
        self.safe_print(f"{Colors.BLUE}[*] Checking {len(self.subdomains)} subdomains for HTTP/HTTPS...{Colors.END}")
        
        urls_to_check = []
        for subdomain in self.subdomains:
            urls_to_check.extend([f"https://{subdomain}", f"http://{subdomain}"])
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_http_status, url): url for url in urls_to_check}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.live_hosts.append(result)
                    status_color = Colors.GREEN if result['status'] < 400 else Colors.YELLOW
                    self.safe_print(f"{status_color}    ✓ {result['url']} [{result['status']}] {result['title'][:50]}{Colors.END}")
        
        # Save live hosts
        with open(self.output_dir / "live_hosts.json", 'w') as f:
            json.dump(self.live_hosts, f, indent=2)
        
        with open(self.output_dir / "live_hosts.txt", 'w') as f:
            for host in self.live_hosts:
                f.write(f"{host['url']} [{host['status']}]\n")
        
        self.safe_print(f"{Colors.GREEN}[+] Live hosts: {len(self.live_hosts)}{Colors.END}")

    def technology_detection(self):
        """Advanced technology detection"""
        if not self.live_hosts:
            self.safe_print(f"{Colors.YELLOW}[!] No live hosts to fingerprint{Colors.END}")
            return
        
        self.safe_print(f"{Colors.BLUE}[*] Fingerprinting technologies...{Colors.END}")
        
        # Run whatweb if available
        self.run_tool(['whatweb', '--color=never', '--no-errors', '-a', '3'] + 
                     [host['url'] for host in self.live_hosts[:20]], 'whatweb.txt')
        
        # Technology patterns
        tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', '/sites/default/', 'Drupal.settings'],
            'Joomla': ['joomla', '/media/jui/', 'option=com_'],
            'Apache': ['Apache/', 'Server: Apache'],
            'Nginx': ['nginx/', 'Server: nginx'],
            'IIS': ['Server: Microsoft-IIS', 'X-Powered-By: ASP.NET'],
            'PHP': ['X-Powered-By: PHP', '.php'],
            'ASP.NET': ['X-Powered-By: ASP.NET', '__VIEWSTATE'],
            'Laravel': ['laravel_session', 'X-Powered-By: PHP'],
            'React': ['react', '_next/', '__NEXT_DATA__'],
            'Angular': ['angular', 'ng-version'],
            'Vue.js': ['vue.js', '__VUE__']
        }
        
        for host_info in self.live_hosts:
            url = host_info['url']
            techs = []
            
            # Check headers
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if any(pattern.lower() in str(v).lower() for v in host_info.get('tech_headers', {}).values()):
                        techs.append(tech)
                        break
            
            self.technologies[url] = list(set(techs))
        
        # Save technology results
        with open(self.output_dir / "technologies.json", 'w') as f:
            json.dump(self.technologies, f, indent=2)
        
        self.safe_print(f"{Colors.GREEN}[+] Technology fingerprinting complete{Colors.END}")

    def dns_enumeration(self):
        """Comprehensive DNS enumeration"""
        self.safe_print(f"{Colors.BLUE}[*] DNS enumeration...{Colors.END}")
        
        dns_info = {'target': self.target, 'records': {}}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR']
        
        if DNS_AVAILABLE:
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, record_type)
                    dns_info['records'][record_type] = [str(r) for r in answers]
                except:
                    dns_info['records'][record_type] = []
        else:
            try:
                ip = socket.gethostbyname(self.target)
                dns_info['records']['A'] = [ip]
            except:
                dns_info['records']['A'] = []
        
        # Try zone transfer
        if 'NS' in dns_info['records']:
            for ns in dns_info['records']['NS']:
                zone_transfer = self.run_tool(['dig', 'axfr', f'@{ns}', self.target], silent=True)
                if zone_transfer and 'Transfer failed' not in zone_transfer:
                    dns_info['zone_transfer'] = {ns: zone_transfer}
                    self.safe_print(f"{Colors.GREEN}[+] Zone transfer successful: {ns}{Colors.END}")
        
        with open(self.output_dir / "dns_info.json", 'w') as f:
            json.dump(dns_info, f, indent=2)
        
        self.safe_print(f"{Colors.GREEN}[+] DNS enumeration complete{Colors.END}")

    def whois_lookup(self):
        """WHOIS information gathering"""
        self.safe_print(f"{Colors.BLUE}[*] WHOIS lookup...{Colors.END}")
        whois_result = self.run_tool(['whois', self.target], 'whois.txt')
        if whois_result:
            self.safe_print(f"{Colors.GREEN}[+] WHOIS information saved{Colors.END}")

    def github_dorking(self):
        """GitHub intelligence gathering"""
        self.safe_print(f"{Colors.BLUE}[*] GitHub intelligence...{Colors.END}")
        
        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            self.safe_print(f"{Colors.YELLOW}[!] Set GITHUB_TOKEN for GitHub dorking{Colors.END}")
            return
        
        dorks = [
            f'"{self.target}" password',
            f'"{self.target}" api_key OR apikey',
            f'"{self.target}" secret',
            f'"{self.target}" token',
            f'"{self.target}" config.json',
            f'"{self.target}" .env',
            f'site:{self.target} password',
            f'site:{self.target} key'
        ]
        
        github_results = {}
        headers = {'Authorization': f'token {github_token}'}
        
        for dork in dorks:
            try:
                url = f"https://api.github.com/search/code?q={dork}"
                response = self.session.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    github_results[dork] = {
                        'total_count': data.get('total_count', 0),
                        'items': [item.get('html_url', '') for item in data.get('items', [])[:5]]
                    }
                time.sleep(2)  # Rate limiting
            except Exception as e:
                github_results[dork] = {'error': str(e)}
        
        with open(self.output_dir / "github_intelligence.json", 'w') as f:
            json.dump(github_results, f, indent=2)
        
        self.safe_print(f"{Colors.GREEN}[+] GitHub intelligence complete{Colors.END}")

    def generate_report(self):
        """Generate comprehensive report"""
        self.safe_print(f"{Colors.BLUE}[*] Generating report...{Colors.END}")
        
        # Statistics
        unique_ips = set()
        status_codes = {}
        interesting_titles = []
        
        for host in self.live_hosts:
            try:
                ip = socket.gethostbyname(urlparse(host['url']).hostname)
                unique_ips.add(ip)
            except:
                pass
            
            status = host['status']
            status_codes[status] = status_codes.get(status, 0) + 1
            
            title = host['title']
            if any(keyword in title.lower() for keyword in ['admin', 'login', 'dashboard', 'panel', 'test', 'dev']):
                interesting_titles.append(f"{host['url']} - {title}")
        
        report = f"""
{Colors.BOLD}{Colors.PURPLE}ANDROMALIUS RECONNAISSANCE REPORT{Colors.END}
Target: {self.target}
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
{"="*80}

{Colors.BOLD}📊 STATISTICS{Colors.END}
• Total Subdomains: {len(self.subdomains)}
• Live Hosts: {len(self.live_hosts)}
• Unique IPs: {len(unique_ips)}
• Status Code Distribution: {dict(sorted(status_codes.items()))}

{Colors.BOLD}🔍 KEY FINDINGS{Colors.END}
• Subdomains saved to: all_subdomains.txt
• Live hosts: live_hosts.json
• Technologies: technologies.json
• DNS records: dns_info.json
• WHOIS info: whois.txt

{Colors.BOLD}🎯 INTERESTING TARGETS{Colors.END}
"""
        
        for title in interesting_titles[:10]:
            report += f"• {title}\n"
        
        report += f"""
{Colors.BOLD}🚀 NEXT STEPS{Colors.END}
1. Port scanning (nmap -sS -sV -O target_ips.txt)
2. Directory brute forcing (gobuster/ffuf)
3. Vulnerability scanning (nuclei/nessus)
4. Manual testing of interesting endpoints
5. Check for subdomain takeovers
6. Analyze technology stack for known CVEs

{Colors.BOLD}📁 FILES GENERATED{Colors.END}
"""
        
        files = list(self.output_dir.glob('*'))
        for file in sorted(files):
            if file.is_file():
                size = file.stat().st_size
                report += f"• {file.name} ({size} bytes)\n"
        
        report += f"""
{Colors.BOLD}💡 TACTICAL INSIGHTS{Colors.END}
"Recon is your foundation and filter: the broader your data, the more valuable bugs you can spot.
But recon also narrows the hunt: out of {len(self.subdomains)} subdomains, maybe 2 are legacy goldmines.
You're looking for forgotten, overlooked, or misconfigured assets."

{Colors.BOLD}⚠️  REMEMBER{Colors.END}
• Use slow scanning (-T1) if IDS/IPS is suspected
• Rotate user agents and IP addresses for large targets
• Check for rate limiting and adapt accordingly
• Document everything for reporting
"""
        
        with open(self.output_dir / "RECON_REPORT.txt", 'w') as f:
            # Remove ANSI codes for file
            import re
            clean_report = re.sub(r'\x1b\[[0-9;]*m', '', report)
            f.write(clean_report)
        
        print(report)
        
        # Save all subdomains
        with open(self.output_dir / "all_subdomains.txt", 'w') as f:
            for sub in sorted(self.subdomains):
                f.write(f"{sub}\n")

    def run_recon(self):
        """Execute full reconnaissance workflow"""
        start_time = time.time()
        self.banner()
        
        try:
            # Phase 1: Passive Enumeration
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{Colors.CYAN}🔍 PHASE 1: PASSIVE ENUMERATION{Colors.END}")
            self.subdomains.add(self.target)  # Add main domain
            
            # Run passive enumeration methods concurrently
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(self.crt_sh_search),
                    executor.submit(self.subfinder_enum),
                    executor.submit(self.amass_enum),
                    executor.submit(self.dns_bruteforce)
                ]
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.safe_print(f"{Colors.RED}[!] Error in enumeration: {e}{Colors.END}")
            
            # Phase 2: Active Enumeration
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{Colors.CYAN}🌐 PHASE 2: ACTIVE ENUMERATION{Colors.END}")
            self.live_host_detection()
            
            # Phase 3: Intelligence Gathering
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{Colors.CYAN}🔧 PHASE 3: INTELLIGENCE GATHERING{Colors.END}")
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(self.technology_detection),
                    executor.submit(self.dns_enumeration),
                    executor.submit(self.whois_lookup),
                    executor.submit(self.github_dorking)
                ]
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.safe_print(f"{Colors.RED}[!] Error in intelligence gathering: {e}{Colors.END}")
            
            # Generate final report
            self.generate_report()
            
            elapsed = time.time() - start_time
            print(f"\n{Colors.BOLD}{Colors.GREEN}🏁 RECONNAISSANCE COMPLETE{Colors.END}")
            print(f"{Colors.CYAN}⏱️  Total time: {elapsed:.2f} seconds{Colors.END}")
            print(f"{Colors.CYAN}📁 Results: {self.output_dir}{Colors.END}")
            print(f"{Colors.CYAN}📊 Subdomains: {len(self.subdomains)} | Live: {len(self.live_hosts)}{Colors.END}")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Reconnaissance interrupted by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Fatal error: {e}{Colors.END}")
            import traceback
            traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(
        description="Andromalius v2.0 - Production Bug Bounty Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 andromalius_recon.py -t example.com -o ./results
  python3 andromalius_recon.py -t target.com -o ./recon -T 100 --timeout 15
  
Environment Variables:
  GITHUB_TOKEN - GitHub API token for dorking
  
Bug Bounty Tips:
  • Start with subdomains, they often have less security
  • Look for staging/dev/test environments
  • Check for subdomain takeovers
  • Focus on forgotten or misconfigured assets
        """
    )
    
    parser.add_argument("-t", "--target", required=True, 
                       help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", required=True,
                       help="Output directory for results")
    parser.add_argument("-T", "--threads", type=int, default=50,
                       help="Number of threads (default: 50)")
    parser.add_argument("--timeout", type=int, default=10,
                       help="HTTP timeout in seconds (default: 10)")
    
    # Interactive mode fallback
    if len(sys.argv) == 1:
        print(f"{Colors.BOLD}{Colors.PURPLE}🎯 ANDROMALIUS v2.0 - Interactive Mode{Colors.END}")
        target = input("Target domain: ").strip()
        if not target:
            print(f"{Colors.RED}❌ Target required{Colors.END}")
            sys.exit(1)
        
        output = input("Output directory [./recon]: ").strip() or "./recon"
        
        # Create args object
        args = argparse.Namespace(
            target=target,
            output=output,
            threads=50,
            timeout=10
        )
    else:
        args = parser.parse_args()
    
    # Validate target
    if not args.target or '/' in args.target:
        print(f"{Colors.RED}❌ Invalid target. Use domain only (e.g., example.com){Colors.END}")
        sys.exit(1)
    
    # Run reconnaissance
    recon = AndromaliusRecon(args.target, args.output, args.threads, args.timeout)
    recon.run_recon()

if __name__ == "__main__":
    main()
