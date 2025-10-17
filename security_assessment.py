#!/usr/bin/env python3
"""
Main Security Assessment Orchestrator
Central command script to run comprehensive security assessments
"""

import argparse
import sys
import os
import json
from datetime import datetime
import subprocess

def run_command(command, description):
    """Run a command and return success status"""
    print(f"[*] {description}...")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print(f"[+] {description} completed successfully")
            return True
        else:
            print(f"[-] {description} failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print(f"[-] {description} timed out")
        return False
    except Exception as e:
        print(f"[-] Error in {description}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Comprehensive Security Assessment Orchestrator")
    parser.add_argument("target", help="Target domain/IP to assess")
    parser.add_argument("--output-dir", default="./security_results", 
                       help="Output directory for results")
    parser.add_argument("--scan-type", choices=['full', 'network', 'web', 'ssl', 'subdomain'], 
                       default='full', help="Type of scan to perform")
    parser.add_argument("--ports", default="1-1000", help="Port range for network scan")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads to use")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    print(f"🔒 Starting Security Assessment for {args.target}")
    print("=" * 60)
    
    scan_results = {}
    
    # Network scan
    if args.scan_type in ['full', 'network']:
        cmd = f"python3 network_scanner.py {args.target} --ports {args.ports} --threads {args.threads} --output {args.output_dir}/network_scan.json"
        scan_results['network'] = run_command(cmd, "Network Security Scan")
    
    # Web security test
    if args.scan_type in ['full', 'web']:
        cmd = f"python3 web_security_tester.py https://{args.target} --output {args.output_dir}/web_security.json"
        scan_results['web'] = run_command(cmd, "Web Application Security Test")
    
    # SSL/TLS analysis
    if args.scan_type in ['full', 'ssl']:
        cmd = f"python3 ssl_tls_analyzer.py {args.target} --output {args.output_dir}/ssl_analysis.json"
        scan_results['ssl'] = run_command(cmd, "SSL/TLS Security Analysis")
    
    # Subdomain enumeration
    if args.scan_type in ['full', 'subdomain']:
        cmd = f"python3 subdomain_enumerator.py {args.target} --threads {args.threads} --output {args.output_dir}/subdomain_enum.json"
        scan_results['subdomain'] = run_command(cmd, "Subdomain Enumeration")
    
    # Generate comprehensive report
    print("[*] Generating comprehensive security report...")
    cmd = f"python3 security_report_generator.py --results-dir {args.output_dir} --output-html {args.output_dir}/security_report.html --output-json {args.output_dir}/security_report.json"
    report_success = run_command(cmd, "Report Generation")
    
    # Summary
    print(f"\n🔒 Security Assessment Summary")
    print("=" * 40)
    successful_scans = sum(scan_results.values())
    total_scans = len(scan_results)
    
    print(f"Target: {args.target}")
    print(f"Scan Type: {args.scan_type}")
    print(f"Successful Scans: {successful_scans}/{total_scans}")
    print(f"Report Generated: {'Yes' if report_success else 'No'}")
    print(f"Results Directory: {args.output_dir}")
    
    if report_success and os.path.exists(f"{args.output_dir}/security_report.json"):
        # Display quick summary from report
        try:
            with open(f"{args.output_dir}/security_report.json", 'r') as f:
                report_data = json.load(f)
                summary = report_data.get('executive_summary', {})
                print(f"\nRisk Level: {summary.get('risk_level', 'Unknown')}")
                print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
                breakdown = summary.get('severity_breakdown', {})
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    count = breakdown.get(severity, 0)
                    if count > 0:
                        print(f"  {severity}: {count}")
        except Exception as e:
            print(f"Could not read report summary: {str(e)}")
    
    print(f"\n[*] Assessment completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Exit with appropriate code
    if successful_scans == total_scans and report_success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()