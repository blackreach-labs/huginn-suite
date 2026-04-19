# app/core/tool_checker.py
import subprocess
import shutil
from typing import Dict, List, Tuple
from pathlib import Path

class ToolChecker:
    """Check availability of external security tools"""
    
    def __init__(self):
        self.tool_definitions = {
            'subfinder': {
                'command': 'subfinder',
                'check_args': ['-version'],
                'install_cmd': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                'description': 'ProjectDiscovery Subfinder - Fast passive subdomain enumeration',
                'category': 'subdomain_enum'
            },
            'amass': {
                'command': 'amass',
                'check_args': ['version'],
                'install_cmd': 'go install -v github.com/owasp-amass/amass/v4/...@master',
                'description': 'OWASP Amass - Network mapping and attack surface discovery',
                'category': 'subdomain_enum'
            },
            'bbot': {
                'command': 'bbot',
                'check_args': ['--version'],
                'install_cmd': 'pip install bbot',
                'description': 'BBOT - Recursive internet scanner for hackers',
                'category': 'subdomain_enum'
            },
            'nuclei': {
                'command': 'nuclei',
                'check_args': ['-version'],
                'install_cmd': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
                'description': 'ProjectDiscovery Nuclei - Vulnerability scanner',
                'category': 'vulnerability_scan'
            },
            'nmap': {
                'command': 'nmap',
                'check_args': ['--version'],
                'install_cmd': 'Install from https://nmap.org/download.html',
                'description': 'Nmap - Network discovery and security auditing',
                'category': 'port_scan'
            },
            'dig': {
                'command': 'dig',
                'check_args': ['-v'],
                'install_cmd': 'Install bind-utils (Linux) or bind (macOS)',
                'description': 'DNS lookup utility',
                'category': 'dns'
            }
        }
    
    def check_tool_availability(self, tool_name: str) -> Tuple[bool, str, str]:
        """
        Check if a specific tool is available
        
        Returns:
            Tuple of (is_available, version_info, error_message)
        """
        
        if tool_name not in self.tool_definitions:
            return False, "", f"Unknown tool: {tool_name}"
        
        tool_def = self.tool_definitions[tool_name]
        command = tool_def['command']
        check_args = tool_def['check_args']
        
        try:
            # First check if command exists in PATH
            if not shutil.which(command):
                return False, "", f"{command} not found in PATH"
            
            # Try to get version information
            result = subprocess.run(
                [command] + check_args,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Extract version from stdout or stderr
                version_output = result.stdout or result.stderr
                version_line = version_output.split('\n')[0] if version_output else "Unknown version"
                return True, version_line.strip(), ""
            else:
                return False, "", f"Command failed with return code {result.returncode}"
        
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except FileNotFoundError:
            return False, "", f"{command} not found"
        except Exception as e:
            return False, "", f"Error checking tool: {str(e)}"
    
    def check_category_tools(self, category: str) -> Dict[str, Tuple[bool, str, str]]:
        """Check all tools in a specific category"""
        
        results = {}
        for tool_name, tool_def in self.tool_definitions.items():
            if tool_def['category'] == category:
                results[tool_name] = self.check_tool_availability(tool_name)
        
        return results
    
    def check_all_tools(self) -> Dict[str, Tuple[bool, str, str]]:
        """Check availability of all defined tools"""
        
        results = {}
        for tool_name in self.tool_definitions.keys():
            results[tool_name] = self.check_tool_availability(tool_name)
        
        return results
    
    def get_install_instructions(self, tool_name: str) -> str:
        """Get installation instructions for a tool"""
        
        if tool_name not in self.tool_definitions:
            return f"Unknown tool: {tool_name}"
        
        return self.tool_definitions[tool_name]['install_cmd']
    
    def get_tool_description(self, tool_name: str) -> str:
        """Get description for a tool"""
        
        if tool_name not in self.tool_definitions:
            return f"Unknown tool: {tool_name}"
        
        return self.tool_definitions[tool_name]['description']
    
    def get_available_tools_by_category(self, category: str) -> List[str]:
        """Get list of available tools in a category"""
        
        available_tools = []
        category_results = self.check_category_tools(category)
        
        for tool_name, (is_available, _, _) in category_results.items():
            if is_available:
                available_tools.append(tool_name)
        
        return available_tools
    
    def generate_tool_report(self, category: str = None) -> str:
        """Generate a formatted report of tool availability"""
        
        if category:
            results = self.check_category_tools(category)
            title = f"Tool Availability Report - {category.title()}"
        else:
            results = self.check_all_tools()
            title = "Tool Availability Report - All Tools"
        
        report_lines = [
            "=" * len(title),
            title,
            "=" * len(title),
            ""
        ]
        
        # Group by category
        categories = {}
        for tool_name, (is_available, version, error) in results.items():
            tool_category = self.tool_definitions[tool_name]['category']
            if tool_category not in categories:
                categories[tool_category] = []
            
            categories[tool_category].append({
                'name': tool_name,
                'available': is_available,
                'version': version,
                'error': error,
                'description': self.tool_definitions[tool_name]['description'],
                'install_cmd': self.tool_definitions[tool_name]['install_cmd']
            })
        
        # Generate report by category
        for cat_name, tools in categories.items():
            report_lines.extend([
                f"{cat_name.upper().replace('_', ' ')}:",
                "-" * (len(cat_name) + 1)
            ])
            
            for tool in tools:
                status = "✅ AVAILABLE" if tool['available'] else "❌ NOT FOUND"
                report_lines.append(f"  {tool['name']}: {status}")
                
                if tool['available']:
                    report_lines.append(f"    Version: {tool['version']}")
                else:
                    report_lines.append(f"    Error: {tool['error']}")
                    report_lines.append(f"    Install: {tool['install_cmd']}")
                
                report_lines.append(f"    Description: {tool['description']}")
                report_lines.append("")
            
            report_lines.append("")
        
        return "\n".join(report_lines)

# Global instance
tool_checker = ToolChecker()