"""
AV/Firewall Detection Utilities
Worker classes and utility functions for AV/Firewall detection
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from PyQt6.QtCore import QRunnable

from app.core.base_worker import WorkerSignals
from .av_firewall_scanner import av_firewall_scanner

logger = logging.getLogger(__name__)

class AVFirewallWorkerSignals(WorkerSignals):
    """Extended signals for AV/Firewall workers"""
    pass

class AVFirewallEnumWorker(QRunnable):
    """Worker for AV/Firewall detection tasks"""
    
    def __init__(self, target: str, scan_type: str = "waf", port: int = 80,
                 payload_type: str = "msfvenom", output_callback: Callable = None, 
                 results_callback: Callable = None):
        super().__init__()
        self.signals = AVFirewallWorkerSignals()
        self.target = target
        self.scan_type = scan_type
        self.port = port
        self.payload_type = payload_type
        self.output_callback = output_callback
        self.results_callback = results_callback
        self.is_running = True
        
    def run(self):
        """Execute AV/Firewall detection"""
        try:
            self.signals.progress_start.emit("Starting AV/Firewall detection...")
            
            if self.output_callback:
                self.output_callback(f"<p style='color: #00BFFF;'>Starting {self.scan_type.upper()} detection on {self.target}</p>")
            
            results = {}
            
            if self.scan_type == "waf":
                results = self._run_waf_detection()
            elif self.scan_type == "firewall":
                results = self._run_firewall_detection()
            elif self.scan_type == "evasion":
                results = self._run_evasion_test()
            elif self.scan_type == "payload":
                results = self._generate_av_payload()
            elif self.scan_type == "full":
                results = self._run_full_detection()
            
            if self.results_callback:
                self.results_callback(results)
                
            self.signals.finished.emit()
            
        except Exception as e:
            logger.error(f"AV/Firewall detection error: {e}")
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Error: {str(e)}</p>")
            self.signals.error.emit(str(e))
    
    def _run_waf_detection(self) -> Dict[str, Any]:
        """Run WAF detection"""
        if self.output_callback:
            self.output_callback(f"<p style='color: #FFD93D;'>Detecting Web Application Firewall on {self.target}:{self.port}...</p>")
        
        results = av_firewall_scanner.detect_waf(self.target, self.port)
        
        if results.get('error'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>WAF detection error: {results['error']}</p>")
            return results
        
        if results['waf_detected']:
            if self.output_callback:
                waf_type = results.get('waf_type', 'Unknown')
                self.output_callback(f"<p style='color: #FFA500;'>⚠ WAF Detected: {waf_type.upper()}</p>")
                
                if results.get('indicators'):
                    self.output_callback("<p style='color: #87CEEB;'>Detection Indicators:</p>")
                    for indicator in results['indicators']:
                        self.output_callback(f"<p style='margin-left: 20px; color: #FFD93D;'>• {indicator}</p>")
        else:
            if self.output_callback:
                self.output_callback("<p style='color: #6BCF7F;'>✓ No WAF detected</p>")
        
        return results
    
    def _run_firewall_detection(self) -> Dict[str, Any]:
        """Run firewall detection using nmap"""
        if self.output_callback:
            self.output_callback(f"<p style='color: #FFD93D;'>Detecting firewall on {self.target}...</p>")
        
        results = av_firewall_scanner.detect_firewall_nmap(self.target)
        
        if results.get('error'):
            if self.output_callback:
                if results['error'] == "nmap not available":
                    self.output_callback("<p style='color: #FFA500;'>⚠ nmap not available - install nmap for firewall detection</p>")
                    self.output_callback("<p style='color: #87CEEB;'>Install: apt-get install nmap (Linux) or download from nmap.org</p>")
                else:
                    self.output_callback(f"<p style='color: #FF6B6B;'>Firewall detection error: {results['error']}</p>")
            return results
        
        if results['firewall_detected']:
            if self.output_callback:
                self.output_callback("<p style='color: #FFA500;'>⚠ Firewall detected</p>")
                
                if results.get('filtered_ports'):
                    ports_str = ', '.join(results['filtered_ports'])
                    self.output_callback(f"<p style='color: #87CEEB;'>Filtered ports: {ports_str}</p>")
        else:
            if self.output_callback:
                self.output_callback("<p style='color: #6BCF7F;'>✓ No firewall detected</p>")
        
        # Display scan results
        if results.get('scan_techniques'):
            if self.output_callback:
                self.output_callback("<p style='color: #87CEEB;'>Scan Results:</p>")
                for technique, result in results['scan_techniques'].items():
                    if result and len(result) > 100:
                        preview = result[:100] + "..."
                    else:
                        preview = result or "No output"
                    self.output_callback(f"<p style='margin-left: 20px;'><b>{technique}:</b> {preview}</p>")
        
        return results
    
    def _run_evasion_test(self) -> Dict[str, Any]:
        """Run firewall evasion tests"""
        if self.output_callback:
            self.output_callback(f"<p style='color: #FFD93D;'>Testing firewall evasion techniques on {self.target}...</p>")
        
        results = av_firewall_scanner.firewall_evasion_scan(self.target)
        
        if results.get('error'):
            if self.output_callback:
                if results['error'] == "nmap not available":
                    self.output_callback("<p style='color: #FFA500;'>⚠ nmap not available - install nmap for evasion testing</p>")
                else:
                    self.output_callback(f"<p style='color: #FF6B6B;'>Evasion test error: {results['error']}</p>")
            return results
        
        if results.get('successful_techniques'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #6BCF7F;'>✓ Successful evasion techniques: {len(results['successful_techniques'])}</p>")
                for technique in results['successful_techniques']:
                    self.output_callback(f"<p style='margin-left: 20px; color: #6BCF7F;'>• {technique}</p>")
        else:
            if self.output_callback:
                self.output_callback("<p style='color: #FFA500;'>No successful evasion techniques found</p>")
        
        # Display all technique results
        if results.get('evasion_techniques'):
            if self.output_callback:
                self.output_callback("<p style='color: #87CEEB;'>Evasion Technique Results:</p>")
                for technique, result in results['evasion_techniques'].items():
                    status = "✓" if technique in results.get('successful_techniques', []) else "✗"
                    self.output_callback(f"<p style='margin-left: 20px;'>{status} <b>{technique}</b></p>")
        
        return results
    
    def _generate_av_payload(self) -> Dict[str, Any]:
        """Generate AV test payload"""
        if self.output_callback:
            self.output_callback(f"<p style='color: #FFD93D;'>Generating {self.payload_type} payload for AV testing...</p>")
        
        results = av_firewall_scanner.generate_av_test_payload(self.payload_type)
        
        if results.get('error'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Payload generation error: {results['error']}</p>")
            return results
        
        if self.output_callback:
            self.output_callback(f"<p style='color: #6BCF7F;'>✓ {self.payload_type.upper()} payload instructions generated</p>")
            
            if results.get('command'):
                self.output_callback("<p style='color: #87CEEB;'>Command:</p>")
                self.output_callback(f"<p style='margin-left: 20px; font-family: monospace; background: #1a1a1a; padding: 10px;'>{results['command']}</p>")
            
            if results.get('instructions'):
                self.output_callback("<p style='color: #87CEEB;'>Instructions:</p>")
                for instruction in results['instructions']:
                    self.output_callback(f"<p style='margin-left: 20px; color: #DCDCDC;'>{instruction}</p>")
            
            if results.get('virustotal_url'):
                self.output_callback(f"<p style='color: #87CEEB;'>VirusTotal URL: <a href='{results['virustotal_url']}' style='color: #64C8FF;'>{results['virustotal_url']}</a></p>")
        
        return results
    
    def _run_full_detection(self) -> Dict[str, Any]:
        """Run comprehensive AV/Firewall detection"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Running comprehensive AV/Firewall detection...</p>")
        
        all_results = {}
        
        # WAF detection
        waf_results = self._run_waf_detection()
        all_results['waf'] = waf_results
        
        # Firewall detection
        firewall_results = self._run_firewall_detection()
        all_results['firewall'] = firewall_results
        
        # Evasion testing (only if firewall detected)
        if firewall_results.get('firewall_detected'):
            evasion_results = self._run_evasion_test()
            all_results['evasion'] = evasion_results
        
        # Payload generation
        payload_results = self._generate_av_payload()
        all_results['payload'] = payload_results
        
        return all_results

def run_av_firewall_detection(target: str, scan_type: str = "waf", port: int = 80,
                             payload_type: str = "msfvenom", output_callback: Callable = None,
                             results_callback: Callable = None) -> AVFirewallEnumWorker:
    """Create and return AV/Firewall detection worker"""
    worker = AVFirewallEnumWorker(
        target=target,
        scan_type=scan_type,
        port=port,
        payload_type=payload_type,
        output_callback=output_callback,
        results_callback=results_callback
    )
    return worker

def get_nmap_evasion_techniques() -> Dict[str, str]:
    """Get nmap firewall evasion techniques"""
    return {
        "Fragmentation": "nmap -f <target>",
        "Decoy Scan": "nmap -D RND:10 <target>",
        "Source Port": "nmap --source-port 53 <target>",
        "Timing": "nmap -T1 <target>",
        "FIN Scan": "nmap -sF <target>",
        "NULL Scan": "nmap -sN <target>",
        "Xmas Scan": "nmap -sX <target>",
        "ACK Scan": "nmap -sA <target>",
        "Spoof MAC": "nmap --spoof-mac 0 <target>"
    }

def format_av_firewall_results(results: Dict[str, Any]) -> str:
    """Format AV/Firewall results for display"""
    if not results:
        return "No results available"
    
    output = []
    
    # WAF detection
    if 'waf_detected' in results:
        status = "Detected" if results['waf_detected'] else "Not Detected"
        output.append(f"WAF Status: {status}")
        if results.get('waf_type'):
            output.append(f"WAF Type: {results['waf_type']}")
    
    # Firewall detection
    if 'firewall_detected' in results:
        status = "Detected" if results['firewall_detected'] else "Not Detected"
        output.append(f"Firewall Status: {status}")
        if results.get('filtered_ports'):
            ports = ', '.join(results['filtered_ports'])
            output.append(f"Filtered Ports: {ports}")
    
    # Evasion techniques
    if 'successful_techniques' in results:
        count = len(results['successful_techniques'])
        output.append(f"Successful Evasion Techniques: {count}")
        for technique in results['successful_techniques'][:5]:
            output.append(f"  • {technique}")
    
    return '\n'.join(output)