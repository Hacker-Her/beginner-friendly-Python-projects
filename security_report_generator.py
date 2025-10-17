#!/usr/bin/env python3
"""
Security Report Generator
Comprehensive security reporting system that aggregates results from all security tools
Generates HTML, JSON, and PDF reports with executive summaries and technical details
"""

import json
import argparse
import sys
from datetime import datetime
import os
import subprocess
from pathlib import Path

class SecurityReportGenerator:
    def __init__(self):
        self.reports = {}
        self.consolidated_vulnerabilities = []
        self.executive_summary = {}
        
    def load_scan_results(self, results_dir):
        """Load scan results from JSON files"""
        print(f"[*] Loading scan results from {results_dir}")
        
        result_files = {
            'network_scan': 'network_scan.json',
            'web_security': 'web_security.json',
            'ssl_analysis': 'ssl_analysis.json',
            'subdomain_enum': 'subdomain_enum.json'
        }
        
        for scan_type, filename in result_files.items():
            filepath = os.path.join(results_dir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        self.reports[scan_type] = json.load(f)
                    print(f"[+] Loaded {scan_type} results")
                except Exception as e:
                    print(f"[-] Error loading {scan_type}: {str(e)}")
            else:
                print(f"[-] {filename} not found")
    
    def consolidate_vulnerabilities(self):
        """Consolidate vulnerabilities from all scans"""
        print("[*] Consolidating vulnerability data...")
        
        for scan_type, report in self.reports.items():
            if 'vulnerabilities' in report:
                for vuln in report['vulnerabilities']:
                    vuln['scan_type'] = scan_type
                    vuln['target'] = report.get('target', 'Unknown')
                    self.consolidated_vulnerabilities.append(vuln)
            elif scan_type == 'network_scan' and 'vulnerabilities' in report:
                for vuln in report['vulnerabilities']:
                    vuln['scan_type'] = scan_type
                    vuln['target'] = report.get('target', 'Unknown')
                    self.consolidated_vulnerabilities.append(vuln)
    
    def generate_executive_summary(self):
        """Generate executive summary with key metrics"""
        print("[*] Generating executive summary...")
        
        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in self.consolidated_vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score
        risk_score = (
            severity_counts['Critical'] * 10 +
            severity_counts['High'] * 7 +
            severity_counts['Medium'] * 4 +
            severity_counts['Low'] * 1
        )
        
        # Determine overall risk level
        if risk_score >= 50:
            risk_level = 'Critical'
        elif risk_score >= 30:
            risk_level = 'High'
        elif risk_score >= 15:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        # Get scan coverage
        scan_types = list(self.reports.keys())
        
        # Top vulnerabilities by type
        vuln_types = {}
        for vuln in self.consolidated_vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        top_vuln_types = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:5]
        
        self.executive_summary = {
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.consolidated_vulnerabilities),
            'severity_breakdown': severity_counts,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'scan_coverage': scan_types,
            'top_vulnerability_types': top_vuln_types,
            'targets_scanned': list(set(vuln.get('target', 'Unknown') for vuln in self.consolidated_vulnerabilities))
        }
    
    def generate_html_report(self, output_file):
        """Generate comprehensive HTML report"""
        print(f"[*] Generating HTML report: {output_file}")
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cybersecurity Assessment Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 10px; 
            box-shadow: 0 0 20px rgba(0,0,0,0.1); 
        }
        .header { 
            text-align: center; 
            margin-bottom: 40px; 
            border-bottom: 3px solid #007acc; 
            padding-bottom: 20px; 
        }
        .header h1 { 
            color: #333; 
            margin: 0; 
            font-size: 2.5em; 
        }
        .header p { 
            color: #666; 
            font-size: 1.2em; 
            margin: 10px 0 0 0; 
        }
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 40px; 
        }
        .summary-card { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 20px; 
            border-radius: 10px; 
            text-align: center; 
        }
        .summary-card h3 { 
            margin: 0 0 10px 0; 
            font-size: 1.8em; 
        }
        .summary-card p { 
            margin: 0; 
            font-size: 1.1em; 
            opacity: 0.9; 
        }
        .risk-level { 
            padding: 8px 16px; 
            border-radius: 20px; 
            font-weight: bold; 
            display: inline-block; 
            margin: 10px 0; 
        }
        .risk-critical { background-color: #dc3545; color: white; }
        .risk-high { background-color: #fd7e14; color: white; }
        .risk-medium { background-color: #ffc107; color: black; }
        .risk-low { background-color: #28a745; color: white; }
        .section { 
            margin-bottom: 40px; 
        }
        .section h2 { 
            color: #333; 
            border-left: 4px solid #007acc; 
            padding-left: 15px; 
            margin-bottom: 20px; 
        }
        .vulnerability { 
            background: #f8f9fa; 
            border-left: 4px solid #007acc; 
            padding: 15px; 
            margin-bottom: 15px; 
            border-radius: 5px; 
        }
        .vulnerability h4 { 
            margin: 0 0 10px 0; 
            color: #333; 
        }
        .severity { 
            padding: 4px 12px; 
            border-radius: 15px; 
            font-size: 0.8em; 
            font-weight: bold; 
            display: inline-block; 
            margin-right: 10px; 
        }
        .severity-critical { background-color: #dc3545; color: white; }
        .severity-high { background-color: #fd7e14; color: white; }
        .severity-medium { background-color: #ffc107; color: black; }
        .severity-low { background-color: #28a745; color: white; }
        .chart-container { 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            margin-bottom: 20px; 
            box-shadow: 0 2px 5px rgba(0,0,0,0.1); 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 12px; 
            text-align: left; 
        }
        th { 
            background-color: #f2f2f2; 
            font-weight: bold; 
        }
        .footer { 
            text-align: center; 
            margin-top: 40px; 
            padding-top: 20px; 
            border-top: 1px solid #ddd; 
            color: #666; 
        }
        .recommendation { 
            background-color: #e7f3ff; 
            border: 1px solid #b3d9ff; 
            padding: 10px; 
            border-radius: 5px; 
            margin-top: 10px; 
        }
        .target-info { 
            background-color: #f0f0f0; 
            padding: 8px 12px; 
            border-radius: 4px; 
            font-family: monospace; 
            font-size: 0.9em; 
            margin: 5px 0; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Cybersecurity Assessment Report</h1>
            <p>Comprehensive Security Analysis - Generated on {scan_date}</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>{total_vulnerabilities}</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="summary-card">
                <h3>{risk_score}</h3>
                <p>Risk Score</p>
            </div>
            <div class="summary-card">
                <h3>{targets_count}</h3>
                <p>Targets Scanned</p>
            </div>
            <div class="summary-card">
                <h3>{scan_types_count}</h3>
                <p>Scan Types</p>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Executive Summary</h2>
            <p><strong>Overall Risk Level:</strong> <span class="risk-level risk-{risk_level_lower}">{risk_level}</span></p>
            <p><strong>Assessment Date:</strong> {scan_date_formatted}</p>
            
            <div class="chart-container">
                <h3>Vulnerability Breakdown by Severity</h3>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                    {severity_table_rows}
                </table>
            </div>
            
            <div class="chart-container">
                <h3>Targets Assessed</h3>
                <ul>
                    {targets_list}
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Detailed Vulnerability Analysis</h2>
            {vulnerabilities_html}
        </div>
        
        <div class="section">
            <h2>📊 Scan Coverage</h2>
            <p>The following security assessments were performed:</p>
            <ul>
                {scan_coverage_list}
            </ul>
        </div>
        
        <div class="section">
            <h2>🛡️ Recommendations</h2>
            <div class="recommendation">
                <h4>Immediate Actions Required:</h4>
                <ul>
                    {immediate_recommendations}
                </ul>
            </div>
            
            <div class="recommendation">
                <h4>Long-term Security Improvements:</h4>
                <ul>
                    {longterm_recommendations}
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by Security Assessment Toolkit v1.0</p>
            <p>For questions about this report, contact your security team.</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Prepare template variables
        summary = self.executive_summary
        
        # Format scan date
        scan_date_formatted = datetime.fromisoformat(summary['scan_date'].replace('Z', '+00:00')).strftime('%B %d, %Y at %I:%M %p')
        
        # Generate severity table rows
        severity_table_rows = ""
        total_vulns = summary['total_vulnerabilities']
        for severity, count in summary['severity_breakdown'].items():
            if total_vulns > 0:
                percentage = (count / total_vulns) * 100
            else:
                percentage = 0
            severity_table_rows += f"""
                <tr>
                    <td><span class="severity severity-{severity.lower()}">{severity}</span></td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
            """
        
        # Generate targets list
        targets_list = ""
        for target in summary['targets_scanned']:
            targets_list += f"<li><code>{target}</code></li>"
        
        # Generate vulnerabilities HTML
        vulnerabilities_html = ""
        
        # Group vulnerabilities by severity
        vuln_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for vuln in self.consolidated_vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in vuln_by_severity:
                vuln_by_severity[severity].append(vuln)
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if vuln_by_severity[severity]:
                vulnerabilities_html += f"<h3>{severity} Severity Issues</h3>"
                for vuln in vuln_by_severity[severity]:
                    vulnerabilities_html += f"""
                    <div class="vulnerability">
                        <h4>
                            <span class="severity severity-{severity.lower()}">{severity}</span>
                            {vuln.get('type', 'Unknown Vulnerability')}
                        </h4>
                        <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                        <div class="target-info">Target: {vuln.get('target', 'Unknown')}</div>
                        <div class="target-info">Scan Type: {vuln.get('scan_type', 'Unknown').replace('_', ' ').title()}</div>
                        {f'<div class="recommendation"><strong>Recommendation:</strong> {vuln["recommendation"]}</div>' if vuln.get('recommendation') else ''}
                    </div>
                    """
        
        # Generate scan coverage list
        scan_coverage_list = ""
        scan_type_names = {
            'network_scan': 'Network Port Scanning',
            'web_security': 'Web Application Security Testing',
            'ssl_analysis': 'SSL/TLS Configuration Analysis',
            'subdomain_enum': 'Subdomain Enumeration'
        }
        
        for scan_type in summary['scan_coverage']:
            scan_name = scan_type_names.get(scan_type, scan_type.replace('_', ' ').title())
            scan_coverage_list += f"<li>✅ {scan_name}</li>"
        
        # Generate recommendations
        immediate_recommendations = ""
        longterm_recommendations = ""
        
        # Critical and High severity issues need immediate attention
        critical_high_count = summary['severity_breakdown']['Critical'] + summary['severity_breakdown']['High']
        
        if critical_high_count > 0:
            immediate_recommendations += f"<li>Address {critical_high_count} critical and high severity vulnerabilities immediately</li>"
        
        if summary['severity_breakdown']['Critical'] > 0:
            immediate_recommendations += "<li>Implement emergency security patches for critical vulnerabilities</li>"
        
        immediate_recommendations += "<li>Review and update security configurations</li>"
        immediate_recommendations += "<li>Implement network segmentation where possible</li>"
        
        longterm_recommendations += "<li>Establish regular security scanning schedule</li>"
        longterm_recommendations += "<li>Implement security awareness training</li>"
        longterm_recommendations += "<li>Deploy intrusion detection systems</li>"
        longterm_recommendations += "<li>Conduct regular penetration testing</li>"
        
        # Fill template
        html_content = html_template.format(
            scan_date=summary['scan_date'],
            scan_date_formatted=scan_date_formatted,
            total_vulnerabilities=summary['total_vulnerabilities'],
            risk_score=summary['risk_score'],
            risk_level=summary['risk_level'],
            risk_level_lower=summary['risk_level'].lower(),
            targets_count=len(summary['targets_scanned']),
            scan_types_count=len(summary['scan_coverage']),
            severity_table_rows=severity_table_rows,
            targets_list=targets_list,
            vulnerabilities_html=vulnerabilities_html,
            scan_coverage_list=scan_coverage_list,
            immediate_recommendations=immediate_recommendations,
            longterm_recommendations=longterm_recommendations
        )
        
        # Write HTML file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report generated: {output_file}")
    
    def generate_json_report(self, output_file):
        """Generate comprehensive JSON report"""
        print(f"[*] Generating JSON report: {output_file}")
        
        comprehensive_report = {
            'executive_summary': self.executive_summary,
            'detailed_results': self.reports,
            'consolidated_vulnerabilities': self.consolidated_vulnerabilities,
            'metadata': {
                'report_version': '1.0',
                'generator': 'Security Assessment Toolkit',
                'generated_at': datetime.now().isoformat()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(comprehensive_report, f, indent=2)
        
        print(f"[+] JSON report generated: {output_file}")
    
    def run_security_scans(self, target, output_dir):
        """Run all security scans and generate reports"""
        print(f"[*] Running comprehensive security scans for {target}")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        scan_commands = [
            {
                'name': 'Network Scan',
                'command': f'python3 network_scanner.py {target} -o {output_dir}/network_scan.json',
                'output': f'{output_dir}/network_scan.json'
            },
            {
                'name': 'Web Security Test',
                'command': f'python3 web_security_tester.py {target} -o {output_dir}/web_security.json',
                'output': f'{output_dir}/web_security.json'
            },
            {
                'name': 'SSL/TLS Analysis',
                'command': f'python3 ssl_tls_analyzer.py {target} -o {output_dir}/ssl_analysis.json',
                'output': f'{output_dir}/ssl_analysis.json'
            },
            {
                'name': 'Subdomain Enumeration',
                'command': f'python3 subdomain_enumerator.py {target} -o {output_dir}/subdomain_enum.json',
                'output': f'{output_dir}/subdomain_enum.json'
            }
        ]
        
        for scan in scan_commands:
            print(f"[*] Running {scan['name']}...")
            try:
                result = subprocess.run(scan['command'], shell=True, 
                                      capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    print(f"[+] {scan['name']} completed successfully")
                else:
                    print(f"[-] {scan['name']} failed: {result.stderr}")
            except subprocess.TimeoutExpired:
                print(f"[-] {scan['name']} timed out")
            except Exception as e:
                print(f"[-] Error running {scan['name']}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Security Report Generator")
    parser.add_argument("--target", help="Target to scan (for running scans)")
    parser.add_argument("--results-dir", default="./scan_results", 
                       help="Directory containing scan result JSON files")
    parser.add_argument("--output-html", help="Output HTML report file")
    parser.add_argument("--output-json", help="Output JSON report file")
    parser.add_argument("--run-scans", action="store_true", 
                       help="Run all security scans before generating report")
    
    args = parser.parse_args()
    
    if not any([args.output_html, args.output_json, args.run_scans]):
        print("[-] Please specify at least one output format or --run-scans")
        sys.exit(1)
    
    generator = SecurityReportGenerator()
    
    try:
        # Run scans if requested
        if args.run_scans:
            if not args.target:
                print("[-] Target required when --run-scans is specified")
                sys.exit(1)
            generator.run_security_scans(args.target, args.results_dir)
        
        # Load existing results
        generator.load_scan_results(args.results_dir)
        
        if not generator.reports:
            print("[-] No scan results found to generate report")
            sys.exit(1)
        
        # Process results
        generator.consolidate_vulnerabilities()
        generator.generate_executive_summary()
        
        # Generate reports
        if args.output_html:
            generator.generate_html_report(args.output_html)
        
        if args.output_json:
            generator.generate_json_report(args.output_json)
        
        # Display summary
        summary = generator.executive_summary
        print(f"\n[*] Security Assessment Summary")
        print("=" * 50)
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"Risk Level: {summary['risk_level']}")
        print(f"Risk Score: {summary['risk_score']}")
        print(f"Critical: {summary['severity_breakdown']['Critical']}")
        print(f"High: {summary['severity_breakdown']['High']}")
        print(f"Medium: {summary['severity_breakdown']['Medium']}")
        print(f"Low: {summary['severity_breakdown']['Low']}")
        
    except KeyboardInterrupt:
        print("\n[!] Report generation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error generating report: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()