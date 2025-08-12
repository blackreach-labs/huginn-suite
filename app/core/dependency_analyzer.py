import re
import json
import aiohttp
from typing import Dict, List, Optional

class DependencyAnalyzer:
    """Analyzes exposed dependency files for known vulnerabilities"""
    
    def __init__(self, session):
        self.session = session
        self.dependency_files = [
            'package.json', 'composer.json', 'requirements.txt', 'pom.xml',
            'Gemfile', 'go.mod', 'yarn.lock', 'package-lock.json'
        ]
    
    async def scan_dependencies(self, base_url: str) -> List[Dict]:
        """Scan for exposed dependency files and analyze vulnerabilities"""
        vulnerabilities = []
        
        for dep_file in self.dependency_files:
            try:
                async with self.session.get(f"{base_url}/{dep_file}") as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        vulns = await self._analyze_dependency_file(dep_file, content, base_url)
                        vulnerabilities.extend(vulns)
            except:
                continue
        
        return vulnerabilities
    
    async def _analyze_dependency_file(self, filename: str, content: str, url: str) -> List[Dict]:
        """Analyze dependency file for vulnerabilities"""
        vulnerabilities = []
        
        # Basic exposure vulnerability
        vulnerabilities.append({
            'type': 'Exposed Dependency File',
            'severity': 'Medium',
            'description': f'Dependency file exposed: {filename}',
            'url': f"{url}/{filename}",
            'cvss_score': 5.3,
            'remediation': 'Remove dependency files from web-accessible directories'
        })
        
        # Parse specific file types
        if filename == 'package.json':
            vulns = self._parse_package_json(content, url)
            vulnerabilities.extend(vulns)
        elif filename == 'requirements.txt':
            vulns = self._parse_requirements_txt(content, url)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _parse_package_json(self, content: str, url: str) -> List[Dict]:
        """Parse package.json for vulnerable dependencies"""
        vulnerabilities = []
        try:
            data = json.loads(content)
            dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            
            # Check for known vulnerable packages
            vulnerable_packages = {
                'lodash': ['<4.17.19', 'Prototype Pollution'],
                'express': ['<4.17.1', 'Directory Traversal'],
                'jquery': ['<3.5.0', 'XSS Vulnerability']
            }
            
            for pkg, version in dependencies.items():
                if pkg in vulnerable_packages:
                    vulnerabilities.append({
                        'type': 'Vulnerable Dependency',
                        'severity': 'High',
                        'description': f'Vulnerable package: {pkg}@{version} - {vulnerable_packages[pkg][1]}',
                        'cvss_score': 7.5,
                        'remediation': f'Update {pkg} to version {vulnerable_packages[pkg][0]} or higher'
                    })
        except:
            pass
        
        return vulnerabilities
    
    def _parse_requirements_txt(self, content: str, url: str) -> List[Dict]:
        """Parse requirements.txt for vulnerable Python packages"""
        vulnerabilities = []
        
        vulnerable_packages = {
            'django': ['<3.2.13', 'SQL Injection'],
            'flask': ['<2.0.3', 'Open Redirect'],
            'requests': ['<2.20.0', 'Certificate Validation']
        }
        
        for line in content.split('\n'):
            line = line.strip()
            if '==' in line:
                pkg, version = line.split('==')
                if pkg in vulnerable_packages:
                    vulnerabilities.append({
                        'type': 'Vulnerable Python Package',
                        'severity': 'High',
                        'description': f'Vulnerable package: {pkg}=={version} - {vulnerable_packages[pkg][1]}',
                        'cvss_score': 7.5,
                        'remediation': f'Update {pkg} to version {vulnerable_packages[pkg][0]} or higher'
                    })
        
        return vulnerabilities