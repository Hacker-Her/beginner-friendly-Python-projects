#!/usr/bin/env python3
"""
Web Application Security Tester
Comprehensive web application vulnerability scanner
Tests for OWASP Top 10 vulnerabilities and security misconfigurations
"""

import urllib.parse
import urllib.request
import ssl
import json
import argparse
import sys
from datetime import datetime
import re
import socket
from urllib.error import URLError, HTTPError

class WebSecurityTester:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        self.scan_results = {}
        
        # Common payloads for testing
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>"
        ]
        
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users;--",
            "' UNION SELECT null,null,null--",
            "admin'--",
            "' OR 'a'='a"
        ]
        
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
    def make_request(self, url, method='GET', data=None, headers=None):
        """Make HTTP request with error handling"""
        try:
            if headers is None:
                headers = {'User-Agent': 'SecurityTester/1.0'}
            
            if method == 'POST' and data:
                data = urllib.parse.urlencode(data).encode()
                req = urllib.request.Request(url, data=data, headers=headers)
            else:
                req = urllib.request.Request(url, headers=headers)
            
            # Create SSL context that doesn't verify certificates for testing
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            response = urllib.request.urlopen(req, context=ctx, timeout=10)
            return {
                'status_code': response.getcode(),
                'headers': dict(response.headers),
                'content': response.read().decode('utf-8', errors='ignore'),
                'url': response.geturl()
            }
        except HTTPError as e:
            return {
                'status_code': e.code,
                'headers': dict(e.headers) if hasattr(e, 'headers') else {},
                'content': e.read().decode('utf-8', errors='ignore') if hasattr(e, 'read') else '',
                'url': url,
                'error': str(e)
            }
        except Exception as e:
            return {
                'status_code': 0,
                'headers': {},
                'content': '',
                'url': url,
                'error': str(e)
            }
    
    def test_security_headers(self):
        """Test for missing security headers"""
        print("[*] Testing security headers...")
        
        response = self.make_request(self.target_url)
        headers = response.get('headers', {})
        
        required_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'XSS protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content injection protection',
            'Referrer-Policy': 'Information leakage protection'
        }
        
        missing_headers = []
        for header, description in required_headers.items():
            if header not in headers:
                missing_headers.append(header)
                self.vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'severity': 'Medium',
                    'description': f'Missing {header} header ({description})',
                    'location': self.target_url,
                    'recommendation': f'Add {header} header to prevent {description.lower()}'
                })
        
        # Check for information disclosure
        if 'Server' in headers:
            self.vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'description': f'Server header reveals: {headers["Server"]}',
                'location': self.target_url,
                'recommendation': 'Remove or obfuscate server information'
            })
        
        self.scan_results['security_headers'] = {
            'missing_headers': missing_headers,
            'present_headers': [h for h in required_headers.keys() if h in headers]
        }
    
    def test_xss_vulnerabilities(self, test_paths=None):
        """Test for Cross-Site Scripting vulnerabilities"""
        print("[*] Testing for XSS vulnerabilities...")
        
        if test_paths is None:
            test_paths = ['/', '/search', '/login', '/contact']
        
        xss_found = []
        
        for path in test_paths:
            test_url = self.target_url + path
            
            # Test reflected XSS in URL parameters
            for payload in self.xss_payloads:
                test_params = f'?q={urllib.parse.quote(payload)}&search={urllib.parse.quote(payload)}'
                response = self.make_request(test_url + test_params)
                
                if response['status_code'] == 200 and payload in response['content']:
                    xss_found.append({
                        'url': test_url + test_params,
                        'payload': payload,
                        'type': 'Reflected XSS'
                    })
                    self.vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': f'Reflected XSS vulnerability found',
                        'location': test_url,
                        'payload': payload,
                        'recommendation': 'Implement input validation and output encoding'
                    })
        
        self.scan_results['xss_tests'] = {
            'vulnerabilities_found': len(xss_found),
            'details': xss_found
        }
    
    def test_sql_injection(self, test_paths=None):
        """Test for SQL Injection vulnerabilities"""
        print("[*] Testing for SQL Injection vulnerabilities...")
        
        if test_paths is None:
            test_paths = ['/', '/login', '/search', '/user']
        
        sql_errors = [
            'mysql_fetch_array()',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'java.sql.SQLException',
            'PostgreSQL.*ERROR',
            'Warning.*mysql_.*',
            'valid MySQL result',
            'MySQLSyntaxErrorException'
        ]
        
        sqli_found = []
        
        for path in test_paths:
            test_url = self.target_url + path
            
            for payload in self.sql_payloads:
                # Test GET parameters
                test_params = f'?id={urllib.parse.quote(payload)}&user={urllib.parse.quote(payload)}'
                response = self.make_request(test_url + test_params)
                
                # Check for SQL error messages
                for error_pattern in sql_errors:
                    if re.search(error_pattern, response['content'], re.IGNORECASE):
                        sqli_found.append({
                            'url': test_url + test_params,
                            'payload': payload,
                            'error': error_pattern
                        })
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'Critical',
                            'description': f'SQL Injection vulnerability detected',
                            'location': test_url,
                            'payload': payload,
                            'evidence': error_pattern,
                            'recommendation': 'Use parameterized queries and input validation'
                        })
                        break
        
        self.scan_results['sql_injection'] = {
            'vulnerabilities_found': len(sqli_found),
            'details': sqli_found
        }
    
    def test_directory_traversal(self, test_paths=None):
        """Test for Directory Traversal vulnerabilities"""
        print("[*] Testing for Directory Traversal vulnerabilities...")
        
        if test_paths is None:
            test_paths = ['/download', '/file', '/image', '/doc']
        
        traversal_found = []
        sensitive_files = ['root:', 'bin/bash', '[boot loader]', 'Windows Registry']
        
        for path in test_paths:
            test_url = self.target_url + path
            
            for payload in self.path_traversal_payloads:
                test_params = f'?file={urllib.parse.quote(payload)}&path={urllib.parse.quote(payload)}'
                response = self.make_request(test_url + test_params)
                
                # Check for sensitive file contents
                for file_content in sensitive_files:
                    if file_content in response['content']:
                        traversal_found.append({
                            'url': test_url + test_params,
                            'payload': payload,
                            'evidence': file_content
                        })
                        self.vulnerabilities.append({
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'description': f'Directory traversal vulnerability detected',
                            'location': test_url,
                            'payload': payload,
                            'evidence': file_content,
                            'recommendation': 'Implement proper input validation and file access controls'
                        })
                        break
        
        self.scan_results['directory_traversal'] = {
            'vulnerabilities_found': len(traversal_found),
            'details': traversal_found
        }
    
    def test_sensitive_files(self):
        """Test for sensitive file exposure"""
        print("[*] Testing for sensitive file exposure...")
        
        sensitive_files = [
            '/robots.txt',
            '/.htaccess',
            '/web.config',
            '/config.php',
            '/wp-config.php',
            '/.env',
            '/backup.sql',
            '/database.sql',
            '/.git/config',
            '/admin',
            '/phpmyadmin',
            '/test',
            '/debug'
        ]
        
        exposed_files = []
        
        for file_path in sensitive_files:
            response = self.make_request(self.target_url + file_path)
            
            if response['status_code'] == 200:
                exposed_files.append(file_path)
                severity = 'Critical' if any(x in file_path for x in ['.env', 'config', '.git']) else 'Medium'
                
                self.vulnerabilities.append({
                    'type': 'Sensitive File Exposure',
                    'severity': severity,
                    'description': f'Sensitive file exposed: {file_path}',
                    'location': self.target_url + file_path,
                    'recommendation': 'Remove or restrict access to sensitive files'
                })
        
        self.scan_results['sensitive_files'] = {
            'exposed_files': exposed_files,
            'total_found': len(exposed_files)
        }
    
    def run_full_scan(self):
        """Run comprehensive security scan"""
        print(f"[*] Starting security scan of {self.target_url}")
        print("=" * 60)
        
        try:
            self.test_security_headers()
            self.test_xss_vulnerabilities()
            self.test_sql_injection()
            self.test_directory_traversal()
            self.test_sensitive_files()
            
            print(f"\n[*] Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            print(f"[-] Error during scan: {str(e)}")
    
    def generate_report(self):
        """Generate comprehensive security report"""
        critical_count = len([v for v in self.vulnerabilities if v['severity'] == 'Critical'])
        high_count = len([v for v in self.vulnerabilities if v['severity'] == 'High'])
        medium_count = len([v for v in self.vulnerabilities if v['severity'] == 'Medium'])
        low_count = len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
        
        report = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'scan_results': self.scan_results,
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count,
                'risk_score': (critical_count * 10) + (high_count * 7) + (medium_count * 4) + (low_count * 1)
            }
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(description="Web Application Security Tester")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("--headers-only", action="store_true", help="Test only security headers")
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    # Initialize tester
    tester = WebSecurityTester(args.url)
    
    try:
        if args.headers_only:
            tester.test_security_headers()
        else:
            tester.run_full_scan()
        
        # Generate and display report
        report = tester.generate_report()
        
        print(f"\n[*] Security Assessment Report for {args.url}")
        print("=" * 60)
        print(f"Total Vulnerabilities: {report['summary']['total_vulnerabilities']}")
        print(f"Critical: {report['summary']['critical']}")
        print(f"High: {report['summary']['high']}")
        print(f"Medium: {report['summary']['medium']}")
        print(f"Low: {report['summary']['low']}")
        print(f"Risk Score: {report['summary']['risk_score']}")
        
        if report['vulnerabilities']:
            print("\n[!] Vulnerabilities Found:")
            for vuln in report['vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
                if 'location' in vuln:
                    print(f"    Location: {vuln['location']}")
                if 'recommendation' in vuln:
                    print(f"    Fix: {vuln['recommendation']}")
                print()
        
        # Save report if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[*] Report saved to {args.output}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error during scan: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()