# app/core/passive_subdomain_worker.py
import subprocess
import json
import tempfile
import os
import threading
import time
from typing import Set, List, Dict, Callable, Optional
from pathlib import Path
import re
from dataclasses import dataclass, asdict
from PyQt6.QtCore import QObject, pyqtSignal, QThread
from app.core.tool_checker import tool_checker

@dataclass
class SubdomainResult:
    """Represents a discovered subdomain with metadata"""
    subdomain: str
    source: str
    ip_addresses: List[str] = None
    status_code: Optional[int] = None
    technologies: List[str] = None
    
    def __post_init__(self):
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.technologies is None:
            self.technologies = []

class PassiveSubdomainWorker(QThread):
    """Worker thread for passive subdomain enumeration using real tools"""
    
    # Signals
    progress_updated = pyqtSignal(str)
    subdomain_found = pyqtSignal(str, str)  # subdomain, source
    enumeration_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, target_domain: str, tools: List[str] = None, parent=None):
        super().__init__(parent)
        self.target_domain = target_domain
        self.tools = tools or ['subfinder', 'amass', 'bbot']
        self.discovered_subdomains = {}  # subdomain -> SubdomainResult
        self.stop_requested = False
        
        # Tool configurations
        self.tool_configs = {
            'subfinder': {
                'command': 'subfinder',
                'args': ['-d', self.target_domain, '-silent', '-o'],
                'timeout': 300,  # 5 minutes
                'description': 'ProjectDiscovery Subfinder - Fast passive aggregator'
            },
            'amass': {
                'command': 'amass',
                'args': ['enum', '-passive', '-d', self.target_domain, '-o'],
                'timeout': 600,  # 10 minutes
                'description': 'OWASP Amass - Deep intelligence gathering'
            },
            'bbot': {
                'command': 'bbot',
                'args': ['-t', self.target_domain, '-p', 'subdomain-enum', '-rf', 'passive', '-o'],
                'timeout': 900,  # 15 minutes
                'description': 'BBOT - Infrastructure correlation engine'
            }
        }
    
    def run(self):
        """Main execution thread"""
        try:
            self.progress_updated.emit(f"🚀 Starting passive subdomain enumeration for {self.target_domain}")
            self.progress_updated.emit("📋 Tools: Subfinder → Amass → BBOT (chained execution)")
            
            # Check tool availability
            available_tools = self._check_tool_availability()
            if not available_tools:
                self.error_occurred.emit("❌ No enumeration tools found. Please install subfinder, amass, or bbot")
                return
            
            self.progress_updated.emit(f"✅ Available tools: {', '.join(available_tools)}")
            
            # Execute tools in sequence (chaining approach)
            all_results = set()
            
            for tool in available_tools:
                if self.stop_requested:
                    break
                
                self.progress_updated.emit(f"🔍 Running {tool.upper()}...")
                results = self._run_tool(tool)
                
                if results:
                    new_subdomains = results - all_results
                    all_results.update(results)
                    
                    self.progress_updated.emit(f"✅ {tool.upper()}: Found {len(results)} subdomains ({len(new_subdomains)} new)")
                    
                    # Emit individual subdomain discoveries
                    for subdomain in new_subdomains:
                        self.subdomain_found.emit(subdomain, tool)
                else:
                    self.progress_updated.emit(f"⚠️ {tool.upper()}: No results or execution failed")
            
            # Final processing and validation
            if all_results:
                self.progress_updated.emit(f"🔄 Processing {len(all_results)} unique subdomains...")
                self._process_results(all_results)
            
            # Generate final statistics
            stats = self._generate_statistics()
            self.enumeration_completed.emit(stats)
            
        except Exception as e:
            self.error_occurred.emit(f"❌ Enumeration failed: {str(e)}")
    
    def _check_tool_availability(self) -> List[str]:
        """Check which enumeration tools are available using tool_checker"""
        available = []
        
        for tool in self.tools:
            if tool in ['subfinder', 'amass', 'bbot']:
                is_available, version, error = tool_checker.check_tool_availability(tool)
                if is_available:
                    available.append(tool)
                    self.progress_updated.emit(f"✅ {tool.upper()}: {version}")
                else:
                    self.progress_updated.emit(f"❌ {tool.upper()}: {error}")
                    self.progress_updated.emit(f"   Install: {tool_checker.get_install_instructions(tool)}")
        
        return available
    
    def _run_tool(self, tool: str) -> Set[str]:
        """Execute a specific enumeration tool"""
        
        if tool not in self.tool_configs:
            return set()
        
        config = self.tool_configs[tool]
        results = set()
        
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Build command
            cmd = [config['command']] + config['args'] + [temp_path]
            
            self.progress_updated.emit(f"⚡ Executing: {' '.join(cmd[:4])}... (timeout: {config['timeout']}s)")
            
            # Execute tool
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitor progress
            start_time = time.time()
            while process.poll() is None:
                if self.stop_requested:
                    process.terminate()
                    break
                
                elapsed = int(time.time() - start_time)
                if elapsed > config['timeout']:
                    process.terminate()
                    self.progress_updated.emit(f"⏰ {tool.upper()} timed out after {config['timeout']}s")
                    break
                
                # Update progress every 10 seconds
                if elapsed % 10 == 0 and elapsed > 0:
                    self.progress_updated.emit(f"🔄 {tool.upper()} running... ({elapsed}s elapsed)")
                
                time.sleep(1)
            
            # Read results from output file
            if os.path.exists(temp_path):
                try:
                    with open(temp_path, 'r') as f:
                        content = f.read().strip()
                    
                    if content:
                        # Parse tool-specific output
                        results = self._parse_tool_output(tool, content)
                    
                    # Clean up temp file
                    os.unlink(temp_path)
                    
                except Exception as e:
                    self.progress_updated.emit(f"⚠️ Error reading {tool} output: {str(e)}")
            
            # Also check stdout for some tools
            if process.stdout:
                stdout_content = process.stdout.read()
                if stdout_content:
                    stdout_results = self._parse_tool_output(tool, stdout_content)
                    results.update(stdout_results)
        
        except Exception as e:
            self.progress_updated.emit(f"❌ {tool.upper()} execution failed: {str(e)}")
        
        return results
    
    def _parse_tool_output(self, tool: str, content: str) -> Set[str]:
        """Parse tool-specific output formats"""
        
        results = set()
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if tool == 'subfinder':
                # Subfinder outputs one subdomain per line
                if self._is_valid_subdomain(line):
                    results.add(line.lower())
            
            elif tool == 'amass':
                # Amass can output various formats, extract domain from each line
                # Format: subdomain.domain.com [IP] [Source]
                parts = line.split()
                if parts and self._is_valid_subdomain(parts[0]):
                    results.add(parts[0].lower())
            
            elif tool == 'bbot':
                # BBOT outputs JSON or text format
                try:
                    # Try JSON parsing first
                    if line.startswith('{'):
                        data = json.loads(line)
                        if 'data' in data and 'DNS_NAME' in data.get('type', ''):
                            subdomain = data['data']
                            if self._is_valid_subdomain(subdomain):
                                results.add(subdomain.lower())
                    else:
                        # Fallback to text parsing
                        if self._is_valid_subdomain(line):
                            results.add(line.lower())
                except json.JSONDecodeError:
                    # Not JSON, treat as plain text
                    if self._is_valid_subdomain(line):
                        results.add(line.lower())
        
        return results
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate if string is a valid subdomain of target"""
        
        if not subdomain:
            return False
        
        # Must end with target domain
        if not (subdomain.endswith('.' + self.target_domain) or subdomain == self.target_domain):
            return False
        
        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
            return False
        
        # Check for wildcards or invalid patterns
        if '*' in subdomain or subdomain.startswith('.') or subdomain.endswith('.'):
            return False
        
        return True
    
    def _process_results(self, subdomains: Set[str]):
        """Process and enrich discovered subdomains"""
        
        for subdomain in subdomains:
            if subdomain not in self.discovered_subdomains:
                # Determine source (simplified - in real implementation, track per tool)
                source = "passive_enum"
                
                result = SubdomainResult(
                    subdomain=subdomain,
                    source=source
                )
                
                self.discovered_subdomains[subdomain] = result
        
        self.progress_updated.emit(f"✅ Processed {len(self.discovered_subdomains)} unique subdomains")
    
    def _generate_statistics(self) -> Dict:
        """Generate enumeration statistics"""
        
        total_subdomains = len(self.discovered_subdomains)
        
        # Count by source
        source_counts = {}
        for result in self.discovered_subdomains.values():
            source_counts[result.source] = source_counts.get(result.source, 0) + 1
        
        # Generate subdomain levels statistics
        level_counts = {}
        for subdomain in self.discovered_subdomains.keys():
            level = len(subdomain.split('.')) - len(self.target_domain.split('.'))
            level_counts[f"Level {level}"] = level_counts.get(f"Level {level}", 0) + 1
        
        stats = {
            'total_subdomains': total_subdomains,
            'target_domain': self.target_domain,
            'tools_used': self.tools,
            'source_breakdown': source_counts,
            'level_breakdown': level_counts,
            'subdomains': list(self.discovered_subdomains.keys()),
            'detailed_results': [asdict(result) for result in self.discovered_subdomains.values()]
        }
        
        return stats
    
    def stop(self):
        """Stop the enumeration process"""
        self.stop_requested = True
        self.progress_updated.emit("🛑 Stopping enumeration...")

class PassiveSubdomainEnumerator(QObject):
    """Main controller for passive subdomain enumeration"""
    
    # Signals
    progress_updated = pyqtSignal(str)
    enumeration_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.current_domain = None
    
    def start_enumeration(self, domain: str, tools: List[str] = None):
        """Start passive subdomain enumeration"""
        
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        
        self.current_domain = domain
        self.worker = PassiveSubdomainWorker(domain, tools)
        
        # Connect signals
        self.worker.progress_updated.connect(self.progress_updated.emit)
        self.worker.enumeration_completed.connect(self._on_enumeration_completed)
        self.worker.error_occurred.connect(self.error_occurred.emit)
        
        # Start worker
        self.worker.start()
    
    def stop_enumeration(self):
        """Stop current enumeration"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
    
    def _on_enumeration_completed(self, stats: Dict):
        """Handle enumeration completion"""
        self.enumeration_completed.emit(stats)
    
    def is_running(self) -> bool:
        """Check if enumeration is currently running"""
        return self.worker and self.worker.isRunning()

# Global instance
passive_subdomain_enumerator = PassiveSubdomainEnumerator()