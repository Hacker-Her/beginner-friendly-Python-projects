# 🔒 Cybersecurity Penetration Testing Toolkit

A comprehensive cybersecurity assessment toolkit designed for penetration testing and security analysis of web applications and network infrastructure. This toolkit is specifically designed for use with **riskcontrolnigeria.com** and can be automated through GitHub Actions for continuous security monitoring.

## 🚀 Features

### 🌐 Network Security Scanner (`network_scanner.py`)
- **Port scanning** with configurable ranges and threading
- **Service detection** and banner grabbing
- **Vulnerability identification** for common network services
- **Comprehensive reporting** with JSON output
- Supports scanning 1-65535 ports with intelligent timeout management

### 🌐 Web Application Security Tester (`web_security_tester.py`)
- **OWASP Top 10** vulnerability testing
- **Cross-Site Scripting (XSS)** detection
- **SQL Injection** testing with multiple payloads
- **Directory Traversal** vulnerability assessment
- **Security headers** analysis
- **Sensitive file exposure** detection
- Automated **risk scoring** and severity classification

### 🔐 SSL/TLS Security Analyzer (`ssl_tls_analyzer.py`)
- **Certificate validation** and expiry checking
- **Protocol security** analysis (SSL/TLS versions)
- **Cipher suite** strength evaluation
- **Known vulnerability** detection (POODLE, BEAST, etc.)
- **Security grading** system (A+ to F rating)
- **Certificate chain** analysis

### 🔍 Subdomain Enumeration Tool (`subdomain_enumerator.py`)
- **Brute force** subdomain discovery
- **Certificate Transparency** log mining
- **DNS record** analysis
- **Web service** detection on discovered subdomains
- **Technology stack** identification
- **Zone transfer** vulnerability testing

### 📊 Security Report Generator (`security_report_generator.py`)
- **Executive summary** generation
- **HTML reports** with visual dashboards
- **JSON exports** for automation
- **Risk scoring** and prioritization
- **Consolidated vulnerability** management
- **Compliance mapping**

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.11 or higher
- pip package manager
- Git (for cloning and version control)

### Quick Start

1. **Clone the repository:**
```bash
git clone https://github.com/Hacker-Her/beginner-friendly-Python-projects.git
cd beginner-friendly-Python-projects
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run individual security scans:**
```bash
# Network scan
python network_scanner.py riskcontrolnigeria.com --ports 1-1000 --output network_results.json

# Web security test
python web_security_tester.py https://riskcontrolnigeria.com --output web_results.json

# SSL/TLS analysis
python ssl_tls_analyzer.py riskcontrolnigeria.com --output ssl_results.json

# Subdomain enumeration
python subdomain_enumerator.py riskcontrolnigeria.com --output subdomain_results.json

# Generate comprehensive report
python security_report_generator.py --results-dir ./results --output-html report.html --output-json report.json
```

## 🤖 GitHub Actions Automation

This toolkit includes a comprehensive GitHub Actions workflow for **automated security testing**:

### Features:
- **Scheduled scanning** (daily at 2 AM UTC)
- **Manual trigger** with custom parameters
- **Multiple scan types** (full, network, web, ssl, subdomain)
- **Artifact management** with 30-day retention
- **Security alerting** for critical vulnerabilities
- **Executive reporting** in GitHub Actions summary

### Usage:

1. **Automated Daily Scans:**
   - Scans run automatically every day at 2 AM UTC
   - Results are uploaded as artifacts
   - Critical issues trigger workflow failures

2. **Manual Execution:**
   - Go to Actions tab in your GitHub repository
   - Select "🔒 Comprehensive Security Assessment"
   - Click "Run workflow"
   - Configure parameters:
     - **Target:** Domain/IP to scan (default: riskcontrolnigeria.com)
     - **Scan Type:** full, network, web, ssl, or subdomain
     - **Max Ports:** Maximum number of ports to scan (1-65535)

3. **Integration with Pull Requests:**
   - Automatically scans on push to main/develop branches
   - Validates security before merging changes

## 📋 Security Testing Methodology

### 1. **Network Assessment**
- Port scanning with service identification
- Banner grabbing for version detection
- Vulnerability mapping to CVE database
- Network topology discovery

### 2. **Web Application Testing**
- Input validation testing (XSS, SQLi)
- Authentication bypass attempts
- Session management analysis
- File upload security testing
- HTTP security headers validation

### 3. **SSL/TLS Security**
- Certificate validity and trust chain
- Supported protocol versions
- Cipher suite strength analysis
- Perfect Forward Secrecy validation
- HSTS and certificate pinning checks

### 4. **Information Gathering**
- Subdomain discovery and mapping
- DNS security configuration
- Technology stack fingerprinting
- Social engineering vector identification

## 🎯 Specific Use Cases for RiskControlNigeria.com

### Compliance Requirements
- **PCI DSS** scanning for payment processing systems
- **ISO 27001** security control validation
- **NIST Cybersecurity Framework** assessment
- **GDPR** data protection compliance checking

### Nigerian Financial Services
- **Central Bank of Nigeria (CBN)** cybersecurity guidelines compliance
- **NDPR** (Nigeria Data Protection Regulation) assessment
- **Financial sector** specific vulnerability testing
- **Regulatory reporting** automation

### Risk Management Focus
- **Risk scoring** aligned with financial industry standards
- **Executive dashboards** for C-level reporting
- **Compliance tracking** and audit trail generation
- **Incident response** automation triggers

## 📊 Report Examples

### Executive Summary
```
🔒 Security Assessment Summary
==============================
Target: riskcontrolnigeria.com
Risk Level: Medium
Risk Score: 23
Total Vulnerabilities: 8
- 🔴 Critical: 0
- 🟠 High: 2
- 🟡 Medium: 4
- 🟢 Low: 2
```

### Technical Findings
- Missing security headers (HSTS, CSP)
- Outdated SSL/TLS configuration
- Information disclosure vulnerabilities
- Subdomain security gaps

## 🔧 Configuration

### Environment Variables
```bash
export SECURITY_TARGET="riskcontrolnigeria.com"
export SCAN_THREADS="50"
export OUTPUT_FORMAT="json,html"
export ALERT_WEBHOOK_URL="https://hooks.slack.com/..."
```

### Configuration File (`config.ini`)
- Network scanner settings
- Web security test parameters
- SSL/TLS analysis options
- Reporting preferences
- GitHub Actions configuration

## 🚨 Security Alerts & Notifications

### Critical Issues
- **Immediate notification** via GitHub Actions
- **Workflow failure** on critical vulnerabilities
- **Executive summary** generation
- **Artifact upload** for forensic analysis

### Integration Options
- Slack notifications (configure webhook)
- Email alerts (SMTP configuration)
- SIEM integration (JSON exports)
- Ticketing system webhooks

## 📈 Continuous Monitoring

### Automated Scheduling
- **Daily scans** for production systems
- **Weekly comprehensive** assessments
- **Monthly compliance** reporting
- **Quarterly security** reviews

### Trend Analysis
- Vulnerability count tracking
- Risk score trending
- Compliance status monitoring
- Security posture improvement metrics

## 🛡️ Best Practices

### Responsible Disclosure
- Only scan systems you own or have permission to test
- Follow responsible disclosure protocols
- Document all findings with timestamps
- Coordinate with system administrators

### Legal Compliance
- Obtain proper authorization before scanning
- Follow local cybersecurity regulations
- Maintain audit logs of all activities
- Respect system performance and availability

## 🔄 Updates & Maintenance

### Regular Updates
- **Vulnerability signatures** updated monthly
- **Security rules** aligned with latest threats
- **Compliance standards** updated quarterly
- **Tool improvements** based on user feedback

### Version Control
- All security tools are version controlled
- Automated testing of tool updates
- Rollback capabilities for failed updates
- Change log maintenance

## 📞 Support & Contact

For questions, issues, or contributions:
- Create an issue in the GitHub repository
- Follow responsible disclosure for security findings
- Contact the security team for urgent vulnerabilities

## ⚖️ Legal Notice

This toolkit is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before conducting any security assessments. The authors are not responsible for any misuse of these tools.

---

**🔒 Stay Secure, Stay Compliant!**

*Built with ❤️ for the cybersecurity community*
