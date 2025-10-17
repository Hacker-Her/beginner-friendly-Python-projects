#!/usr/bin/env python3
"""
SSL/TLS Security Analyzer
Comprehensive SSL certificate and TLS configuration security tester
Analyzes cipher suites, certificate validity, and TLS vulnerabilities
"""

import ssl
import socket
import json
import argparse
import sys
from datetime import datetime, timezone
import hashlib
import urllib.parse

class SSLTLSAnalyzer:
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        self.vulnerabilities = []
        self.certificate_info = {}
        self.cipher_info = {}
        self.protocol_info = {}
        
    def get_ssl_context(self, protocol=None):
        """Create SSL context for different protocols"""
        if protocol:
            context = ssl.SSLContext(protocol)
        else:
            context = ssl.create_default_context()
        
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    
    def analyze_certificate(self):
        """Analyze SSL certificate details"""
        print("[*] Analyzing SSL certificate...")
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    # Extract certificate information
                    self.certificate_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'signature_algorithm': cert.get('signatureAlgorithm'),
                        'san': cert.get('subjectAltName', []),
                        'fingerprint_sha256': hashlib.sha256(cert_der).hexdigest()
                    }
                    
                    # Check certificate validity
                    self._check_certificate_validity(cert)
                    
                    # Check certificate security
                    self._check_certificate_security(cert)
                    
        except socket.timeout:
            self.vulnerabilities.append({
                'type': 'Connection Timeout',
                'severity': 'Medium',
                'description': 'SSL connection timeout - server may be unreachable',
                'recommendation': 'Verify server accessibility and SSL configuration'
            })
        except ssl.SSLError as e:
            self.vulnerabilities.append({
                'type': 'SSL Connection Error',
                'severity': 'High',
                'description': f'SSL connection failed: {str(e)}',
                'recommendation': 'Check SSL configuration and certificate validity'
            })
        except Exception as e:
            print(f"[-] Certificate analysis error: {str(e)}")
    
    def _check_certificate_validity(self, cert):
        """Check certificate validity dates"""
        try:
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.now()
            
            # Check if certificate is expired
            if now > not_after:
                self.vulnerabilities.append({
                    'type': 'Expired Certificate',
                    'severity': 'Critical',
                    'description': f'Certificate expired on {cert["notAfter"]}',
                    'recommendation': 'Renew SSL certificate immediately'
                })
            
            # Check if certificate is not yet valid
            elif now < not_before:
                self.vulnerabilities.append({
                    'type': 'Certificate Not Yet Valid',
                    'severity': 'High',
                    'description': f'Certificate not valid until {cert["notBefore"]}',
                    'recommendation': 'Check system clock and certificate validity period'
                })
            
            # Check if certificate expires soon (within 30 days)
            else:
                days_until_expiry = (not_after - now).days
                if days_until_expiry <= 30:
                    self.vulnerabilities.append({
                        'type': 'Certificate Expiring Soon',
                        'severity': 'Medium',
                        'description': f'Certificate expires in {days_until_expiry} days',
                        'recommendation': 'Plan certificate renewal'
                    })
                    
        except Exception as e:
            print(f"[-] Error checking certificate validity: {str(e)}")
    
    def _check_certificate_security(self, cert):
        """Check certificate security parameters"""
        
        # Check key length (if available in certificate info)
        subject = dict(x[0] for x in cert.get('subject', []))
        
        # Check for wildcard certificates
        if 'commonName' in subject and subject['commonName'].startswith('*'):
            self.vulnerabilities.append({
                'type': 'Wildcard Certificate',
                'severity': 'Low',
                'description': 'Wildcard certificate detected',
                'recommendation': 'Consider using specific certificates for better security'
            })
        
        # Check signature algorithm
        sig_alg = cert.get('signatureAlgorithm', '').lower()
        if 'md5' in sig_alg:
            self.vulnerabilities.append({
                'type': 'Weak Signature Algorithm',
                'severity': 'High',
                'description': 'Certificate uses MD5 signature algorithm',
                'recommendation': 'Replace certificate with SHA-256 or stronger signature'
            })
        elif 'sha1' in sig_alg:
            self.vulnerabilities.append({
                'type': 'Weak Signature Algorithm',
                'severity': 'Medium',
                'description': 'Certificate uses SHA-1 signature algorithm',
                'recommendation': 'Consider upgrading to SHA-256 signature'
            })
    
    def analyze_protocols(self):
        """Analyze supported SSL/TLS protocols"""
        print("[*] Analyzing SSL/TLS protocols...")
        
        protocols_to_test = [
            ('SSLv2', getattr(ssl, 'PROTOCOL_SSLv2', None)),
            ('SSLv3', getattr(ssl, 'PROTOCOL_SSLv3', None)),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
        ]
        
        # Add TLSv1.3 if available
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            protocols_to_test.append(('TLSv1.3', ssl.PROTOCOL_TLSv1_3))
        
        supported_protocols = []
        
        for protocol_name, protocol_const in protocols_to_test:
            if protocol_const is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        supported_protocols.append(protocol_name)
                        
            except (ssl.SSLError, socket.error, OSError):
                # Protocol not supported or connection failed
                pass
            except Exception as e:
                print(f"[-] Error testing {protocol_name}: {str(e)}")
        
        self.protocol_info['supported'] = supported_protocols
        
        # Check for insecure protocols
        insecure_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0']
        for protocol in supported_protocols:
            if protocol in insecure_protocols:
                severity = 'Critical' if protocol in ['SSLv2', 'SSLv3'] else 'High'
                self.vulnerabilities.append({
                    'type': 'Insecure Protocol',
                    'severity': severity,
                    'description': f'{protocol} is supported (insecure)',
                    'recommendation': f'Disable {protocol} and use TLS 1.2 or higher'
                })
        
        # Check if only secure protocols are supported
        if not any(p in supported_protocols for p in ['TLSv1.2', 'TLSv1.3']):
            self.vulnerabilities.append({
                'type': 'No Secure Protocols',
                'severity': 'Critical',
                'description': 'No secure TLS protocols (1.2+) detected',
                'recommendation': 'Enable TLS 1.2 and TLS 1.3 support'
            })
    
    def analyze_cipher_suites(self):
        """Analyze supported cipher suites"""
        print("[*] Analyzing cipher suites...")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        self.cipher_info = {
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        }
                        
                        # Check for weak ciphers
                        cipher_name = cipher[0].upper()
                        
                        # Check for weak encryption
                        if any(weak in cipher_name for weak in ['DES', 'RC4', 'MD5']):
                            self.vulnerabilities.append({
                                'type': 'Weak Cipher Suite',
                                'severity': 'High',
                                'description': f'Weak cipher detected: {cipher[0]}',
                                'recommendation': 'Use strong cipher suites (AES, ChaCha20)'
                            })
                        
                        # Check for anonymous ciphers
                        if 'ADH' in cipher_name or 'AECDH' in cipher_name:
                            self.vulnerabilities.append({
                                'type': 'Anonymous Cipher',
                                'severity': 'Critical',
                                'description': f'Anonymous cipher detected: {cipher[0]}',
                                'recommendation': 'Disable anonymous cipher suites'
                            })
                        
                        # Check key length
                        if cipher[2] < 128:
                            self.vulnerabilities.append({
                                'type': 'Weak Key Length',
                                'severity': 'High',
                                'description': f'Weak key length: {cipher[2]} bits',
                                'recommendation': 'Use cipher suites with 256-bit keys'
                            })
                            
        except Exception as e:
            print(f"[-] Cipher analysis error: {str(e)}")
    
    def check_vulnerabilities(self):
        """Check for known SSL/TLS vulnerabilities"""
        print("[*] Checking for known vulnerabilities...")
        
        # Test for POODLE (SSLv3)
        if 'SSLv3' in self.protocol_info.get('supported', []):
            self.vulnerabilities.append({
                'type': 'POODLE Vulnerability',
                'severity': 'High',
                'description': 'SSLv3 support makes server vulnerable to POODLE attack',
                'recommendation': 'Disable SSLv3 support'
            })
        
        # Test for BEAST (TLS 1.0 with CBC ciphers)
        if 'TLSv1.0' in self.protocol_info.get('supported', []):
            cipher_name = self.cipher_info.get('name', '')
            if 'CBC' in cipher_name.upper():
                self.vulnerabilities.append({
                    'type': 'BEAST Vulnerability',
                    'severity': 'Medium',
                    'description': 'TLS 1.0 with CBC ciphers vulnerable to BEAST attack',
                    'recommendation': 'Disable TLS 1.0 or use non-CBC cipher suites'
                })
    
    def run_full_analysis(self):
        """Run comprehensive SSL/TLS analysis"""
        print(f"[*] Starting SSL/TLS analysis of {self.hostname}:{self.port}")
        print("=" * 60)
        
        try:
            self.analyze_certificate()
            self.analyze_protocols()
            self.analyze_cipher_suites()
            self.check_vulnerabilities()
            
            print(f"\n[*] Analysis completed. Found {len(self.vulnerabilities)} issues")
            
        except Exception as e:
            print(f"[-] Error during analysis: {str(e)}")
    
    def generate_report(self):
        """Generate comprehensive SSL/TLS security report"""
        critical_count = len([v for v in self.vulnerabilities if v['severity'] == 'Critical'])
        high_count = len([v for v in self.vulnerabilities if v['severity'] == 'High'])
        medium_count = len([v for v in self.vulnerabilities if v['severity'] == 'Medium'])
        low_count = len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
        
        report = {
            'target': f"{self.hostname}:{self.port}",
            'scan_date': datetime.now().isoformat(),
            'certificate_info': self.certificate_info,
            'protocol_info': self.protocol_info,
            'cipher_info': self.cipher_info,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total_issues': len(self.vulnerabilities),
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count,
                'ssl_grade': self._calculate_ssl_grade()
            }
        }
        
        return report
    
    def _calculate_ssl_grade(self):
        """Calculate SSL security grade"""
        critical_count = len([v for v in self.vulnerabilities if v['severity'] == 'Critical'])
        high_count = len([v for v in self.vulnerabilities if v['severity'] == 'High'])
        medium_count = len([v for v in self.vulnerabilities if v['severity'] == 'Medium'])
        
        if critical_count > 0:
            return 'F'
        elif high_count > 2:
            return 'D'
        elif high_count > 0:
            return 'C'
        elif medium_count > 3:
            return 'B'
        elif medium_count > 0:
            return 'A-'
        else:
            return 'A+'

def main():
    parser = argparse.ArgumentParser(description="SSL/TLS Security Analyzer")
    parser.add_argument("hostname", help="Target hostname to analyze")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("--cert-only", action="store_true", help="Analyze certificate only")
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = SSLTLSAnalyzer(args.hostname, args.port)
    
    try:
        if args.cert_only:
            analyzer.analyze_certificate()
        else:
            analyzer.run_full_analysis()
        
        # Generate and display report
        report = analyzer.generate_report()
        
        print(f"\n[*] SSL/TLS Security Report for {args.hostname}:{args.port}")
        print("=" * 60)
        print(f"SSL Grade: {report['summary']['ssl_grade']}")
        print(f"Total Issues: {report['summary']['total_issues']}")
        print(f"Critical: {report['summary']['critical']}")
        print(f"High: {report['summary']['high']}")
        print(f"Medium: {report['summary']['medium']}")
        print(f"Low: {report['summary']['low']}")
        
        # Display certificate info
        if report['certificate_info']:
            cert_info = report['certificate_info']
            print(f"\n[*] Certificate Information:")
            print(f"Subject: {cert_info.get('subject', {}).get('commonName', 'N/A')}")
            print(f"Issuer: {cert_info.get('issuer', {}).get('organizationName', 'N/A')}")
            print(f"Valid From: {cert_info.get('not_before', 'N/A')}")
            print(f"Valid Until: {cert_info.get('not_after', 'N/A')}")
            print(f"Signature Algorithm: {cert_info.get('signature_algorithm', 'N/A')}")
        
        # Display protocol info
        if report['protocol_info']:
            protocols = report['protocol_info'].get('supported', [])
            print(f"\n[*] Supported Protocols: {', '.join(protocols) if protocols else 'None detected'}")
        
        # Display cipher info
        if report['cipher_info']:
            cipher = report['cipher_info']
            print(f"\n[*] Current Cipher: {cipher.get('name', 'N/A')} ({cipher.get('bits', 'N/A')} bits)")
        
        # Display vulnerabilities
        if report['vulnerabilities']:
            print(f"\n[!] Security Issues Found:")
            for vuln in report['vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
                print(f"    Recommendation: {vuln['recommendation']}")
                print()
        else:
            print(f"\n[+] No security issues detected!")
        
        # Save report if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[*] Report saved to {args.output}")
        
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error during analysis: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()