#!/usr/bin/env python3
"""
Subdomain Enumeration Tool
Advanced subdomain discovery and DNS analysis tool
Discovers subdomains through multiple techniques and analyzes DNS configurations
"""

import socket
import threading
import argparse
import json
import sys
from datetime import datetime
import concurrent.futures
import urllib.request
import urllib.error
import ssl
import re

class SubdomainEnumerator:
    def __init__(self, domain, threads=50):
        self.domain = domain
        self.threads = threads
        self.subdomains = set()
        self.valid_subdomains = {}
        self.dns_records = {}
        
        # Common subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'forum', 'm', 'imap',
            'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'www1', 'email', 'img', 'www3', 'help',
            'shop', 'api', 'apps', 'secure', 'sip', 'mail1', 'mobile', 'remote', 'code',
            'stage', 'stats', 'web', 'img1', 'img2', 'img3', 'css', 'js', 'mail3', 'mail4',
            'mail5', 'video', 'www4', 'www5', 'img4', 'beta', 'vps', 'server', 'uploads',
            'app', 'portal', 'demo', 'support', 'cdn', 'static', 'media', 'images',
            'login', 'manage', 'dashboard', 'control', 'panel', 'ssl', 'secure',
            'payment', 'payments', 'shop', 'store', 'cart', 'order', 'orders',
            'track', 'tracking', 'follow', 'subscribe', 'newsletter', 'promo',
            'deals', 'offer', 'offers', 'sale', 'sales', 'buy', 'purchase'
        ]
        
        # Technology-specific subdomains
        self.tech_subdomains = [
            'git', 'svn', 'jenkins', 'ci', 'build', 'repo', 'repository',
            'docker', 'k8s', 'kubernetes', 'rancher', 'grafana', 'kibana',
            'elasticsearch', 'redis', 'mongo', 'db', 'database', 'mysql',
            'postgres', 'influx', 'prometheus', 'alertmanager', 'nagios',
            'zabbix', 'cacti', 'munin', 'sensu', 'check_mk'
        ]
        
        # Cloud service subdomains
        self.cloud_subdomains = [
            'aws', 'azure', 'gcp', 'cloud', 's3', 'storage', 'backup',
            'cdn', 'edge', 'cache', 'proxy', 'lb', 'balancer'
        ]
        
        # Security-related subdomains
        self.security_subdomains = [
            'vpn', 'firewall', 'fw', 'proxy', 'gateway', 'router',
            'switch', 'access', 'auth', 'sso', 'ldap', 'ad', 'radius'
        ]
    
    def dns_lookup(self, subdomain):
        """Perform DNS lookup for a subdomain"""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            # Get A records
            ip_addresses = socket.gethostbyname_ex(full_domain)[2]
            
            if ip_addresses:
                self.subdomains.add(subdomain)
                self.valid_subdomains[subdomain] = {
                    'domain': full_domain,
                    'ips': ip_addresses,
                    'status': 'active'
                }
                
                # Try to get additional DNS records
                self.get_dns_records(full_domain)
                
                print(f"[+] Found: {full_domain} -> {', '.join(ip_addresses)}")
                return True
                
        except socket.gaierror:
            pass
        except Exception as e:
            pass
        
        return False
    
    def get_dns_records(self, domain):
        """Get various DNS records for a domain"""
        try:
            import dns.resolver
            
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
            dns_info = {}
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[record_type] = [str(record) for record in answers]
                except:
                    pass
            
            if dns_info:
                self.dns_records[domain] = dns_info
                
        except ImportError:
            # dnspython not available, skip detailed DNS records
            pass
        except Exception as e:
            pass
    
    def check_web_service(self, subdomain):
        """Check if subdomain has a web service running"""
        full_domain = f"{subdomain}.{self.domain}"
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{full_domain}"
                
                # Create request with timeout
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'SubdomainEnumerator/1.0')
                
                # Handle SSL for HTTPS
                if protocol == 'https':
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    response = urllib.request.urlopen(req, timeout=5, context=ctx)
                else:
                    response = urllib.request.urlopen(req, timeout=5)
                
                # Get response info
                status_code = response.getcode()
                headers = dict(response.headers)
                
                # Update subdomain info
                if subdomain in self.valid_subdomains:
                    if 'web_services' not in self.valid_subdomains[subdomain]:
                        self.valid_subdomains[subdomain]['web_services'] = []
                    
                    self.valid_subdomains[subdomain]['web_services'].append({
                        'protocol': protocol,
                        'status_code': status_code,
                        'server': headers.get('Server', 'Unknown'),
                        'title': self.extract_title(response.read().decode('utf-8', errors='ignore'))
                    })
                
                return True
                
            except urllib.error.HTTPError as e:
                # Still a valid web service, just returned an error
                if subdomain in self.valid_subdomains:
                    if 'web_services' not in self.valid_subdomains[subdomain]:
                        self.valid_subdomains[subdomain]['web_services'] = []
                    
                    self.valid_subdomains[subdomain]['web_services'].append({
                        'protocol': protocol,
                        'status_code': e.code,
                        'server': 'Unknown',
                        'title': 'Error Page'
                    })
                return True
                
            except Exception:
                continue
        
        return False
    
    def extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()[:100]  # Limit title length
        except:
            pass
        return 'No Title'
    
    def brute_force_subdomains(self, wordlist=None):
        """Brute force subdomains using wordlist"""
        print(f"[*] Starting subdomain enumeration for {self.domain}")
        
        if wordlist is None:
            wordlist = self.common_subdomains + self.tech_subdomains + self.cloud_subdomains + self.security_subdomains
        
        print(f"[*] Testing {len(wordlist)} potential subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.dns_lookup, wordlist)
    
    def certificate_transparency_search(self):
        """Search Certificate Transparency logs for subdomains"""
        print("[*] Searching Certificate Transparency logs...")
        
        try:
            # Query crt.sh for certificate transparency data
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'SubdomainEnumerator/1.0')
            
            response = urllib.request.urlopen(req, timeout=10)
            data = json.loads(response.read().decode())
            
            ct_subdomains = set()
            
            for cert in data:
                name_value = cert.get('name_value', '')
                
                # Parse multiple domains from certificate
                domains = name_value.split('\n')
                
                for domain in domains:
                    domain = domain.strip()
                    
                    # Skip wildcards and non-matching domains
                    if domain.startswith('*'):
                        domain = domain[2:]  # Remove *.
                    
                    if domain.endswith(f'.{self.domain}'):
                        subdomain = domain.replace(f'.{self.domain}', '')
                        if subdomain and '.' not in subdomain:  # Only first-level subdomains
                            ct_subdomains.add(subdomain)
            
            print(f"[*] Found {len(ct_subdomains)} subdomains in CT logs")
            
            # Verify CT subdomains
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.dns_lookup, ct_subdomains)
            
        except Exception as e:
            print(f"[-] Certificate Transparency search failed: {str(e)}")
    
    def analyze_subdomains(self):
        """Analyze discovered subdomains for web services"""
        print(f"[*] Analyzing {len(self.valid_subdomains)} discovered subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_web_service, self.valid_subdomains.keys())
    
    def check_zone_transfers(self):
        """Check for DNS zone transfer vulnerabilities"""
        print("[*] Checking for DNS zone transfer vulnerabilities...")
        
        try:
            # Get nameservers for the domain
            ns_records = socket.gethostbyname_ex(f"ns1.{self.domain}")[2]
            
            # This is a simplified check - in practice, you'd use dnspython
            # to perform actual zone transfer attempts
            print("[*] Zone transfer check requires dnspython library for full functionality")
            
        except Exception as e:
            print(f"[-] Zone transfer check failed: {str(e)}")
    
    def run_full_enumeration(self):
        """Run comprehensive subdomain enumeration"""
        print(f"[*] Starting comprehensive subdomain enumeration for {self.domain}")
        print("=" * 70)
        
        try:
            # Step 1: Brute force common subdomains
            self.brute_force_subdomains()
            
            # Step 2: Certificate Transparency search
            self.certificate_transparency_search()
            
            # Step 3: Analyze discovered subdomains
            if self.valid_subdomains:
                self.analyze_subdomains()
            
            # Step 4: Check for zone transfer vulnerabilities
            self.check_zone_transfers()
            
            print(f"\n[*] Enumeration completed. Found {len(self.valid_subdomains)} active subdomains")
            
        except Exception as e:
            print(f"[-] Error during enumeration: {str(e)}")
    
    def generate_report(self):
        """Generate comprehensive subdomain enumeration report"""
        web_services_count = len([s for s in self.valid_subdomains.values() 
                                if 'web_services' in s and s['web_services']])
        
        report = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'subdomains': self.valid_subdomains,
            'dns_records': self.dns_records,
            'summary': {
                'total_subdomains': len(self.valid_subdomains),
                'web_services': web_services_count,
                'unique_ips': len(set(ip for sub in self.valid_subdomains.values() 
                                    for ip in sub.get('ips', []))),
                'technologies_detected': self.analyze_technologies()
            }
        }
        
        return report
    
    def analyze_technologies(self):
        """Analyze technologies based on subdomain names and services"""
        technologies = set()
        
        tech_indicators = {
            'git': ['git', 'gitlab', 'github', 'bitbucket'],
            'ci_cd': ['jenkins', 'ci', 'build', 'travis', 'gitlab-ci'],
            'monitoring': ['grafana', 'kibana', 'nagios', 'zabbix', 'prometheus'],
            'cloud': ['aws', 'azure', 'gcp', 'cloud', 's3'],
            'cdn': ['cdn', 'static', 'media', 'assets', 'cache'],
            'mail': ['mail', 'smtp', 'pop', 'imap', 'webmail'],
            'vpn': ['vpn', 'remote', 'access'],
            'database': ['db', 'mysql', 'postgres', 'mongo', 'redis'],
            'web_services': ['api', 'service', 'ws', 'rest'],
            'admin': ['admin', 'manage', 'control', 'panel', 'cpanel']
        }
        
        for subdomain in self.valid_subdomains.keys():
            for tech, indicators in tech_indicators.items():
                if any(indicator in subdomain.lower() for indicator in indicators):
                    technologies.add(tech)
        
        return list(technologies)

def load_custom_wordlist(filename):
    """Load custom wordlist from file"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist file {filename} not found")
        return []
    except Exception as e:
        print(f"[-] Error loading wordlist: {str(e)}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("--no-ct", action="store_true", help="Skip Certificate Transparency search")
    parser.add_argument("--dns-only", action="store_true", help="Only perform DNS enumeration")
    
    args = parser.parse_args()
    
    # Validate domain
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$', args.domain):
        print(f"[-] Invalid domain format: {args.domain}")
        sys.exit(1)
    
    # Initialize enumerator
    enumerator = SubdomainEnumerator(args.domain, args.threads)
    
    try:
        # Load custom wordlist if provided
        if args.wordlist:
            custom_wordlist = load_custom_wordlist(args.wordlist)
            if custom_wordlist:
                enumerator.brute_force_subdomains(custom_wordlist)
            else:
                enumerator.brute_force_subdomains()
        else:
            if args.dns_only:
                enumerator.brute_force_subdomains()
            else:
                enumerator.run_full_enumeration()
        
        # Generate and display report
        report = enumerator.generate_report()
        
        print(f"\n[*] Subdomain Enumeration Report for {args.domain}")
        print("=" * 70)
        print(f"Total Subdomains Found: {report['summary']['total_subdomains']}")
        print(f"Web Services Detected: {report['summary']['web_services']}")
        print(f"Unique IP Addresses: {report['summary']['unique_ips']}")
        print(f"Technologies Detected: {', '.join(report['summary']['technologies_detected'])}")
        
        # Display discovered subdomains
        if report['subdomains']:
            print(f"\n[*] Discovered Subdomains:")
            for subdomain, info in report['subdomains'].items():
                full_domain = info['domain']
                ips = ', '.join(info['ips'])
                print(f"  {full_domain} -> {ips}")
                
                # Show web services if detected
                if 'web_services' in info:
                    for service in info['web_services']:
                        protocol = service['protocol'].upper()
                        status = service['status_code']
                        server = service['server']
                        title = service['title']
                        print(f"    [{protocol}] Status: {status}, Server: {server}")
                        if title != 'No Title':
                            print(f"    Title: {title}")
        
        # Save report if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[*] Report saved to {args.output}")
        
    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error during enumeration: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()