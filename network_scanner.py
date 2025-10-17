#!/usr/bin/env python3
"""
Network Security Scanner
A comprehensive port scanner and network vulnerability detector
Designed for cybersecurity professionals to assess network security posture
"""

import socket
import threading
import argparse
import json
import sys
from datetime import datetime
import concurrent.futures
import subprocess
import ipaddress

class NetworkScanner:
    def __init__(self, target, threads=100):
        self.target = target
        self.threads = threads
        self.open_ports = []
        self.services = {}
        self.vulnerabilities = []
        
    def port_scan(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                self.open_ports.append(port)
                service = self.get_service_info(port)
                self.services[port] = service
                print(f"[+] Port {port}: Open - {service}")
                
            sock.close()
        except Exception as e:
            pass
            
    def get_service_info(self, port):
        """Get service information for a port"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL",
            1433: "MSSQL", 6379: "Redis", 27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown")
    
    def banner_grab(self, port):
        """Grab service banners for fingerprinting"""
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((self.target, port))
            
            # Send basic HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return None
    
    def check_vulnerabilities(self):
        """Check for common vulnerabilities"""
        for port in self.open_ports:
            service = self.services.get(port, "Unknown")
            
            # Check for default/weak configurations
            if port == 21:  # FTP
                self.vulnerabilities.append({
                    "port": port,
                    "service": service,
                    "vulnerability": "FTP service detected - check for anonymous login",
                    "severity": "Medium"
                })
            
            elif port == 23:  # Telnet
                self.vulnerabilities.append({
                    "port": port,
                    "service": service,
                    "vulnerability": "Telnet service detected - unencrypted protocol",
                    "severity": "High"
                })
            
            elif port == 22:  # SSH
                banner = self.banner_grab(port)
                if banner and "SSH-1" in banner:
                    self.vulnerabilities.append({
                        "port": port,
                        "service": service,
                        "vulnerability": "SSH version 1 detected - vulnerable protocol",
                        "severity": "High"
                    })
            
            elif port in [80, 443]:  # Web services
                self.check_web_vulnerabilities(port)
    
    def check_web_vulnerabilities(self, port):
        """Check for web-specific vulnerabilities"""
        try:
            import requests
            protocol = "https" if port == 443 else "http"
            url = f"{protocol}://{self.target}:{port}"
            
            response = requests.get(url, timeout=5, verify=False)
            headers = response.headers
            
            # Check security headers
            security_headers = [
                'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy'
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.vulnerabilities.append({
                    "port": port,
                    "service": self.services.get(port),
                    "vulnerability": f"Missing security headers: {', '.join(missing_headers)}",
                    "severity": "Medium"
                })
            
            # Check server information disclosure
            if 'Server' in headers:
                self.vulnerabilities.append({
                    "port": port,
                    "service": self.services.get(port),
                    "vulnerability": f"Server information disclosure: {headers['Server']}",
                    "severity": "Low"
                })
                
        except ImportError:
            print("[-] requests library not available for web vulnerability checks")
        except Exception as e:
            pass
    
    def scan_range(self, start_port=1, end_port=1000):
        """Scan a range of ports"""
        print(f"[*] Scanning {self.target} for open ports ({start_port}-{end_port})...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.port_scan, range(start_port, end_port + 1))
        
        print(f"[*] Scan completed. Found {len(self.open_ports)} open ports")
        
        # Check for vulnerabilities
        if self.open_ports:
            print("[*] Checking for vulnerabilities...")
            self.check_vulnerabilities()
    
    def generate_report(self):
        """Generate a comprehensive security report"""
        report = {
            "target": self.target,
            "scan_date": datetime.now().isoformat(),
            "open_ports": self.open_ports,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "summary": {
                "total_open_ports": len(self.open_ports),
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical_issues": len([v for v in self.vulnerabilities if v.get("severity") == "High"])
            }
        }
        return report

def main():
    parser = argparse.ArgumentParser(description="Network Security Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (e.g., 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    
    args = parser.parse_args()
    
    # Parse port range
    if "-" in args.ports:
        start_port, end_port = map(int, args.ports.split("-"))
    else:
        start_port = end_port = int(args.ports)
    
    # Validate target
    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Error: Cannot resolve hostname {args.target}")
        sys.exit(1)
    
    # Initialize scanner
    scanner = NetworkScanner(args.target, args.threads)
    
    try:
        # Perform scan
        scanner.scan_range(start_port, end_port)
        
        # Generate report
        report = scanner.generate_report()
        
        # Display results
        print(f"\n[*] Security Assessment Report for {args.target}")
        print("=" * 50)
        print(f"Open Ports: {len(report['open_ports'])}")
        print(f"Vulnerabilities Found: {len(report['vulnerabilities'])}")
        print(f"Critical Issues: {report['summary']['critical_issues']}")
        
        if report['vulnerabilities']:
            print("\n[!] Vulnerabilities Detected:")
            for vuln in report['vulnerabilities']:
                print(f"  - Port {vuln['port']} ({vuln['service']}): {vuln['vulnerability']} [{vuln['severity']}]")
        
        # Save report if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[*] Report saved to {args.output}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error during scan: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()