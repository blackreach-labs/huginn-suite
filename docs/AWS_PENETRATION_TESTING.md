# AWS Penetration Testing Suite

## Overview

The AWS Penetration Testing Suite is a comprehensive red team toolkit designed for authorized security assessments of AWS environments. It provides automated enumeration, vulnerability detection, privilege escalation, and exploitation capabilities specifically tailored for AWS cloud infrastructure.

## ⚠️ IMPORTANT DISCLAIMER

**AUTHORIZED TESTING ONLY**: This tool is designed for authorized penetration testing and security assessments. Only use this tool on AWS accounts and resources that you own or have explicit written permission to test. Unauthorized access to AWS resources is illegal and may result in criminal charges.

## Features

### 🔍 Enumeration Capabilities

#### IAM Enumeration
- **Users & Roles**: Enumerate all IAM users, roles, and their associated policies
- **Trust Relationships**: Analyze role trust policies for potential assumption paths
- **Permission Analysis**: Extract and analyze effective permissions from policies
- **Privilege Escalation Detection**: Identify dangerous permission combinations
- **Cross-Account Access**: Detect cross-account trust relationships

#### S3 Bucket Enumeration
- **Bucket Discovery**: Enumerate all accessible S3 buckets
- **Permission Testing**: Test read/write permissions on discovered buckets
- **Public Bucket Detection**: Identify publicly accessible buckets
- **Sensitive File Detection**: Scan for files containing sensitive information
- **ACL Analysis**: Analyze bucket and object ACLs for misconfigurations

#### EC2 Instance Enumeration
- **Instance Discovery**: Enumerate EC2 instances across all regions
- **Security Group Analysis**: Identify vulnerable security group rules
- **Public Instance Detection**: Find instances with public IP addresses
- **Snapshot Enumeration**: Discover EBS snapshots and check permissions
- **Key Pair Analysis**: Enumerate available key pairs

#### Lambda Function Enumeration
- **Function Discovery**: Enumerate Lambda functions across all regions
- **Environment Variable Analysis**: Check for secrets in environment variables
- **IAM Role Analysis**: Identify functions with high-privilege roles
- **Code Analysis**: Extract and analyze function code for vulnerabilities

#### Secrets Manager Enumeration
- **Secret Discovery**: Enumerate all secrets across regions
- **Access Testing**: Test access to discovered secrets
- **Value Extraction**: Extract accessible secret values
- **Cross-Service Analysis**: Identify secrets used by other services

### 💥 Exploitation Capabilities

#### Privilege Escalation
- **IAM PassRole Exploitation**: Exploit `iam:PassRole` + `lambda:CreateFunction` combinations
- **Policy Attachment**: Exploit `iam:AttachUserPolicy` and `iam:AttachRolePolicy`
- **Role Assumption**: Exploit misconfigured trust policies
- **Access Key Creation**: Exploit `iam:CreateAccessKey` for persistence

#### Data Exfiltration
- **S3 Data Extraction**: Download sensitive files from accessible buckets
- **Secrets Dumping**: Extract all accessible secrets from Secrets Manager
- **Lambda Code Extraction**: Download and analyze Lambda function code
- **Database Credential Harvesting**: Extract database credentials from various sources

#### Persistence Mechanisms
- **IAM Backdoor Creation**: Create hidden administrative users
- **Lambda Function Modification**: Inject backdoors into existing functions
- **Role Trust Policy Modification**: Modify trust policies for future access
- **CloudFormation Template Injection**: Hide backdoors in infrastructure code

#### Stealth Techniques
- **API Call Minimization**: Reduce CloudTrail noise through efficient API usage
- **Region Hopping**: Distribute activities across multiple regions
- **Service Account Impersonation**: Use service accounts to blend in
- **Timestamp Manipulation**: Space out activities to avoid detection

### 🛡️ Defense Evasion

#### CloudTrail Evasion
- **Log Gap Exploitation**: Target regions without CloudTrail enabled
- **Service-Specific Evasion**: Use services with limited logging
- **Bulk Operation Masking**: Hide malicious activities in legitimate bulk operations

#### Rate Limiting Bypass
- **Distributed Scanning**: Spread requests across multiple regions
- **Service Rotation**: Rotate between different AWS services
- **Throttling Detection**: Automatically adjust request rates

## Installation & Setup

### Prerequisites
```bash
pip install boto3 botocore
```

### AWS Credentials Configuration

#### Method 1: Access Keys
```python
# Direct credential input in the UI
Access Key ID: AKIA...
Secret Access Key: ...
Session Token: ... (optional)
```

#### Method 2: AWS Profile
```bash
# Configure AWS CLI profile
aws configure --profile pentest
```

#### Method 3: Instance Profile
```python
# Use EC2 instance profile (when running on EC2)
# No credentials needed - automatically detected
```

#### Method 4: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=... # optional
```

## Usage Guide

### 1. Configuration
1. Open the AWS Penetration Testing tab
2. Configure your AWS credentials using one of the methods above
3. Select your primary region
4. Test the connection to ensure credentials are valid

### 2. Enumeration
1. Select the enumeration modules you want to run:
   - ✅ IAM Enumeration (recommended)
   - ✅ S3 Bucket Enumeration
   - ✅ EC2 Instance Enumeration
   - ✅ Lambda Function Enumeration
   - ✅ Secrets Manager Enumeration

2. Choose scan options:
   - **All Regions**: Scan all AWS regions (comprehensive but slower)
   - **Stealth Mode**: Reduce API calls to minimize detection
   - **Save Evidence**: Automatically save evidence files

3. Click "Start Selected Scans" or use quick scan buttons

### 3. Results Analysis
1. Review the scan summary for high-level findings
2. Examine detailed findings for specific vulnerabilities
3. Check the privilege escalation paths section
4. Export results for further analysis

### 4. Exploitation (Advanced)
⚠️ **WARNING**: Only proceed if you have explicit authorization

1. Review identified privilege escalation paths
2. Select appropriate exploitation techniques
3. Execute exploits with caution
4. Document all activities for the assessment report

## Attack Scenarios

### Scenario 1: IAM Privilege Escalation
```
1. Enumerate IAM permissions
2. Identify user with iam:PassRole + lambda:CreateFunction
3. Create malicious Lambda function with high-privilege role
4. Execute function to create administrative backdoor
5. Use backdoor for further access
```

### Scenario 2: S3 Data Exfiltration
```
1. Enumerate S3 buckets
2. Identify publicly readable buckets
3. Scan for sensitive files (credentials, backups, etc.)
4. Download and analyze sensitive data
5. Document findings for report
```

### Scenario 3: Cross-Service Exploitation
```
1. Enumerate Lambda functions with secrets in environment variables
2. Extract database credentials from Lambda env vars
3. Use credentials to access RDS instances
4. Exfiltrate database contents
5. Establish persistence through database triggers
```

### Scenario 4: Metadata Service Exploitation
```
1. Identify web applications with SSRF vulnerabilities
2. Exploit SSRF to access EC2 metadata service
3. Extract IAM role credentials from metadata
4. Use stolen credentials for lateral movement
5. Escalate privileges through role assumption
```

## Red Team Techniques

### Information Gathering
- **OSINT Collection**: Gather public information about target AWS usage
- **DNS Enumeration**: Identify AWS-hosted services through DNS
- **Certificate Transparency**: Find AWS resources through SSL certificates
- **GitHub Reconnaissance**: Search for leaked AWS credentials in repositories

### Initial Access
- **Credential Stuffing**: Test common credentials against AWS services
- **Phishing**: Target employees with access to AWS credentials
- **Supply Chain**: Compromise third-party services with AWS access
- **Public Bucket Exploitation**: Find and exploit publicly accessible S3 buckets

### Persistence
- **IAM User Creation**: Create hidden administrative users
- **Lambda Backdoors**: Inject backdoors into existing Lambda functions
- **CloudFormation Persistence**: Hide backdoors in infrastructure templates
- **Cross-Account Access**: Establish access through cross-account roles

### Defense Evasion
- **CloudTrail Gaps**: Operate in regions without logging enabled
- **Service Account Usage**: Use service accounts to blend in with normal traffic
- **API Rate Management**: Spread activities to avoid rate limiting
- **Timestamp Spacing**: Space activities to avoid correlation

## Detection & Mitigation

### Detection Strategies
- **CloudTrail Analysis**: Monitor for unusual API patterns
- **GuardDuty Alerts**: Enable GuardDuty for threat detection
- **Config Rules**: Implement Config rules for compliance monitoring
- **Custom Monitoring**: Create custom CloudWatch alarms for suspicious activities

### Mitigation Techniques
- **Least Privilege**: Implement strict least-privilege access controls
- **MFA Enforcement**: Require MFA for all privileged operations
- **Cross-Account Isolation**: Use separate accounts for different environments
- **Regular Audits**: Conduct regular access reviews and permission audits

## Reporting

### Executive Summary
- High-level overview of findings
- Business impact assessment
- Risk prioritization matrix
- Recommended remediation timeline

### Technical Findings
- Detailed vulnerability descriptions
- Proof-of-concept evidence
- Exploitation steps
- Technical remediation guidance

### Evidence Collection
- Screenshots of successful exploits
- Log entries showing unauthorized access
- Extracted sensitive data samples
- Network traffic captures

## Legal & Ethical Considerations

### Authorization Requirements
- Written permission from system owner
- Clearly defined scope and limitations
- Emergency contact procedures
- Data handling agreements

### Responsible Disclosure
- Report findings to appropriate stakeholders
- Provide reasonable time for remediation
- Avoid public disclosure without permission
- Follow coordinated vulnerability disclosure practices

### Data Protection
- Minimize data collection to what's necessary
- Secure storage of collected evidence
- Proper disposal of sensitive information
- Compliance with applicable privacy laws

## Advanced Features

### Custom Exploitation Modules
```python
# Example custom exploitation module
class CustomAWSExploit:
    def __init__(self, session):
        self.session = session
    
    def exploit_custom_vulnerability(self):
        # Custom exploitation logic
        pass
```

### Integration with Other Tools
- **Pacu Integration**: Import/export findings to Pacu framework
- **ScoutSuite Integration**: Combine with ScoutSuite configuration assessment
- **Prowler Integration**: Enhance with Prowler compliance checks

### Automation & Orchestration
- **Scheduled Scans**: Automate regular security assessments
- **CI/CD Integration**: Include in deployment pipelines
- **Alert Integration**: Connect with SIEM and alerting systems

## Troubleshooting

### Common Issues
1. **Credential Errors**: Verify AWS credentials and permissions
2. **Rate Limiting**: Enable stealth mode or reduce scan scope
3. **Region Access**: Ensure target regions are enabled in AWS account
4. **Permission Denied**: Check IAM policies for required permissions

### Debug Mode
Enable debug logging for detailed troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

### Adding New Modules
1. Create new enumeration or exploitation class
2. Implement required interface methods
3. Add UI components for new functionality
4. Update documentation and tests

### Reporting Bugs
1. Provide detailed reproduction steps
2. Include relevant log files
3. Specify AWS service and region
4. Include tool version information

## Changelog

### Version 1.0.0
- Initial release with core enumeration capabilities
- IAM, S3, EC2, Lambda, and Secrets Manager support
- Basic exploitation framework
- Comprehensive reporting features

### Planned Features
- RDS enumeration and exploitation
- CloudFormation template analysis
- Container service (ECS/EKS) assessment
- Advanced persistence mechanisms
- Machine learning-based anomaly detection

## References

- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [OWASP Cloud Security Testing Guide](https://owasp.org/www-project-cloud-security-testing-guide/)
- [NIST Cloud Security Framework](https://www.nist.gov/cybersecurity/cloud-security)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)