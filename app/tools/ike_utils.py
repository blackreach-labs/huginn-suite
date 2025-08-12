"""
IKE Enumeration Utilities
Worker classes and utility functions for IKE enumeration
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from PyQt6.QtCore import QRunnable

from app.core.base_worker import WorkerSignals
from .ike_scanner import ike_scanner

logger = logging.getLogger(__name__)

class IKEWorkerSignals(WorkerSignals):
    """Extended signals for IKE workers"""
    pass

class IKEEnumWorker(QRunnable):
    """Worker for IKE enumeration tasks"""
    
    def __init__(self, target: str, scan_type: str = "basic", port: int = 500,
                 aggressive_mode: bool = True, output_callback: Callable = None, 
                 results_callback: Callable = None):
        super().__init__()
        self.signals = IKEWorkerSignals()
        self.target = target
        self.scan_type = scan_type
        self.port = port
        self.aggressive_mode = aggressive_mode
        self.output_callback = output_callback
        self.results_callback = results_callback
        self.is_running = True
        
    def run(self):
        """Execute IKE enumeration"""
        try:
            self.signals.progress_start.emit("Starting IKE enumeration...")
            
            if self.output_callback:
                self.output_callback(f"<p style='color: #00BFFF;'>Starting IKE enumeration on {self.target}:{self.port}</p>")
            
            results = {}
            
            if self.scan_type == "basic":
                results = self._run_basic_scan()
            elif self.scan_type == "detailed":
                results = self._run_detailed_scan()
            elif self.scan_type == "transforms":
                results = self._run_transforms_scan()
            elif self.scan_type == "full":
                results = self._run_full_scan()
            
            if self.results_callback:
                self.results_callback(results)
                
            self.signals.finished.emit()
            
        except Exception as e:
            logger.error(f"IKE enumeration error: {e}")
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Error: {str(e)}</p>")
            self.signals.error.emit(str(e))
    
    def _run_basic_scan(self) -> Dict[str, Any]:
        """Run basic IKE connectivity scan"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Testing IKE service connectivity...</p>")
        
        results = ike_scanner.scan_ike_basic(self.target, self.port)
        
        if not results.get('ike_scan_available'):
            if self.output_callback:
                self.output_callback("<p style='color: #FFA500;'>⚠ ike-scan tool not available - install ike-scan for IKE enumeration</p>")
                self.output_callback("<p style='color: #87CEEB;'>Install: apt-get install ike-scan (Linux) or brew install ike-scan (macOS)</p>")
        elif results['accessible']:
            if self.output_callback:
                self.output_callback(f"<p style='color: #6BCF7F;'>✓ IKE service potentially accessible on {self.target}:{self.port}</p>")
        else:
            if self.output_callback:
                error_msg = results.get('error', 'Service not accessible')
                self.output_callback(f"<p style='color: #FF6B6B;'>✗ IKE service not accessible: {error_msg}</p>")
        
        return results
    
    def _run_detailed_scan(self) -> Dict[str, Any]:
        """Run detailed IKE enumeration"""
        if self.output_callback:
            mode_text = "aggressive mode" if self.aggressive_mode else "main mode"
            self.output_callback(f"<p style='color: #FFD93D;'>Running detailed IKE scan ({mode_text})...</p>")
        
        results = ike_scanner.scan_ike_detailed(self.target, self.port, self.aggressive_mode)
        
        if not results.get('ike_scan_available'):
            if self.output_callback:
                self.output_callback("<p style='color: #FFA500;'>⚠ ike-scan tool not available</p>")
            return results
        
        if results.get('error'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Scan error: {results['error']}</p>")
            return results
        
        # Display results
        if results.get('handshake_type'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #87CEEB;'>Handshake Type: {results['handshake_type']}</p>")
        
        if results.get('transforms'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #87CEEB;'>Found {len(results['transforms'])} transforms:</p>")
                for transform in results['transforms']:
                    self.output_callback(f"<p style='margin-left: 20px;'>• {transform}</p>")
        
        if results.get('vendor_ids'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #87CEEB;'>Vendor IDs:</p>")
                for vid in results['vendor_ids']:
                    self.output_callback(f"<p style='margin-left: 20px;'>• {vid}</p>")
        
        if results.get('raw_output'):
            if self.output_callback:
                self.output_callback("<p style='color: #87CEEB;'>Raw ike-scan output:</p>")
                # Show first 500 chars of raw output
                raw_preview = results['raw_output'][:500] + "..." if len(results['raw_output']) > 500 else results['raw_output']
                self.output_callback(f"<p style='margin-left: 20px; font-family: monospace; font-size: 9pt;'>{raw_preview}</p>")
        
        return results
    
    def _run_transforms_scan(self) -> Dict[str, Any]:
        """Run IKE transforms enumeration"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Enumerating IKE transforms...</p>")
        
        results = ike_scanner.scan_ike_transforms(self.target, self.port)
        
        if results.get('transforms'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #6BCF7F;'>Found {len(results['transforms'])} supported transforms:</p>")
                for transform in results['transforms']:
                    self.output_callback(f"<p style='margin-left: 20px;'>• {transform}</p>")
        elif results.get('error'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Transform enumeration error: {results['error']}</p>")
        else:
            if self.output_callback:
                self.output_callback("<p style='color: #FFA500;'>No transforms detected</p>")
        
        return results
    
    def _run_full_scan(self) -> Dict[str, Any]:
        """Run comprehensive IKE enumeration"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Running comprehensive IKE enumeration...</p>")
        
        all_results = {}
        
        # Basic connectivity
        basic_results = self._run_basic_scan()
        all_results['basic'] = basic_results
        
        if not basic_results.get('ike_scan_available'):
            return all_results
        
        if basic_results.get('accessible'):
            # Detailed scan
            detailed_results = self._run_detailed_scan()
            all_results['detailed'] = detailed_results
            
            # Transform enumeration
            transform_results = self._run_transforms_scan()
            all_results['transforms'] = transform_results
        
        return all_results

def run_ike_enumeration(target: str, scan_type: str = "basic", port: int = 500,
                       aggressive_mode: bool = True, output_callback: Callable = None,
                       results_callback: Callable = None) -> IKEEnumWorker:
    """Create and return IKE enumeration worker"""
    worker = IKEEnumWorker(
        target=target,
        scan_type=scan_type,
        port=port,
        aggressive_mode=aggressive_mode,
        output_callback=output_callback,
        results_callback=results_callback
    )
    return worker

def get_ike_scan_commands() -> Dict[str, str]:
    """Get common ike-scan commands"""
    return {
        "Basic Scan": "ike-scan <target>",
        "Aggressive Mode": "ike-scan -M <target>",
        "Custom Port": "ike-scan --dport <port> <target>",
        "Transform Enum": "ike-scan --trans=1,2,3,4 <target>",
        "Verbose Output": "ike-scan -v <target>",
        "Show Backoff": "ike-scan --showbackoff <target>"
    }

def format_ike_results(results: Dict[str, Any]) -> str:
    """Format IKE results for display"""
    if not results:
        return "No results available"
    
    output = []
    
    # Basic info
    if 'accessible' in results:
        status = "✓ Accessible" if results['accessible'] else "✗ Not accessible"
        output.append(f"IKE Status: {status}")
    
    # Tool availability
    if 'ike_scan_available' in results:
        tool_status = "Available" if results['ike_scan_available'] else "Not Available"
        output.append(f"ike-scan Tool: {tool_status}")
    
    # Handshake type
    if results.get('handshake_type'):
        output.append(f"Handshake: {results['handshake_type']}")
    
    # Transforms
    if results.get('transforms'):
        output.append(f"\nTransforms ({len(results['transforms'])}):")
        for transform in results['transforms'][:10]:  # Limit output
            output.append(f"  • {transform}")
    
    # Vendor IDs
    if results.get('vendor_ids'):
        output.append(f"\nVendor IDs ({len(results['vendor_ids'])}):")
        for vid in results['vendor_ids'][:5]:
            output.append(f"  • {vid}")
    
    return '\n'.join(output)

def get_ipsec_config_info() -> Dict[str, str]:
    """Get IPSec configuration file information"""
    return {
        "ipsec.conf": "Main IPSec configuration file (/etc/ipsec.conf)",
        "ipsec.secrets": "IPSec secrets file (/etc/ipsec.secrets)",
        "strongswan.conf": "StrongSwan configuration (/etc/strongswan.conf)",
        "racoon.conf": "Racoon IKE daemon configuration (/etc/racoon/racoon.conf)"
    }