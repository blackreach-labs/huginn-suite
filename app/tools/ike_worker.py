# app/tools/ike_worker.py
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.tools.ike_scanner import ike_scanner
import logging

logger = logging.getLogger(__name__)

class IKEWorkerSignals(QObject):
    """Signals for IKE enumeration worker"""
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)
    error = pyqtSignal(str)

class IKEWorker(QRunnable):
    """IKE enumeration worker"""
    
    def __init__(self, target, port=500, scan_type="Basic Info", aggressive_mode=True):
        super().__init__()
        self.target = target
        self.port = int(port)
        self.scan_type = scan_type
        self.aggressive_mode = aggressive_mode
        self.signals = IKEWorkerSignals()
        self.is_running = True
    
    def run(self):
        """Execute IKE enumeration"""
        try:
            self.signals.output.emit(f"<p style='color: #00BFFF;'>[IKE SCAN] Starting {self.scan_type} on {self.target}:{self.port}</p><br>")
            
            results = {
                'target': self.target,
                'port': self.port,
                'scan_type': self.scan_type,
                'aggressive_mode': self.aggressive_mode,
                'ike_accessible': False,
                'transforms': [],
                'vendor_ids': [],
                'handshake_type': None,
                'error': None
            }
            
            if not self.is_running:
                return
            
            # Basic IKE service detection
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Testing IKE service accessibility...</p><br>")
            basic_results = ike_scanner.scan_ike_basic(self.target, self.port)
            
            if basic_results.get('error'):
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] {basic_results['error']}</p><br>")
                results['error'] = basic_results['error']
            else:
                results['ike_accessible'] = basic_results.get('accessible', False)
                results['ike_scan_available'] = basic_results.get('ike_scan_available', False)
                
                if results['ike_accessible']:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>IKE service accessible on port {self.port}</p><br>")
                else:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>IKE service may not be accessible on port {self.port}</p><br>")
            
            if not self.is_running:
                return
            
            # Detailed enumeration if ike-scan is available
            if results.get('ike_scan_available') and self.scan_type in ["Detailed Info", "Transform Enum"]:
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Running detailed IKE enumeration...</p><br>")
                
                if self.scan_type == "Transform Enum":
                    # Transform enumeration
                    transform_results = ike_scanner.scan_ike_transforms(self.target, self.port)
                    if transform_results.get('error'):
                        self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] Transform scan: {transform_results['error']}</p><br>")
                    else:
                        results['transforms'] = transform_results.get('transforms', [])
                        if results['transforms']:
                            self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(results['transforms'])} transforms:</p><br>")
                            for transform in results['transforms']:
                                self.signals.output.emit(f"<p style='color: #87CEEB;'>  - {transform}</p><br>")
                        else:
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>No transforms detected</p><br>")
                else:
                    # Detailed scan
                    detailed_results = ike_scanner.scan_ike_detailed(self.target, self.port, self.aggressive_mode)
                    if detailed_results.get('error'):
                        self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] Detailed scan: {detailed_results['error']}</p><br>")
                    else:
                        results.update({
                            'transforms': detailed_results.get('transforms', []),
                            'vendor_ids': detailed_results.get('vendor_ids', []),
                            'handshake_type': detailed_results.get('handshake_type'),
                            'raw_output': detailed_results.get('raw_output')
                        })
                        
                        # Display results
                        if results['handshake_type']:
                            self.signals.output.emit(f"<p style='color: #00FF41;'>Handshake Type: {results['handshake_type']}</p><br>")
                        
                        if results['transforms']:
                            self.signals.output.emit(f"<p style='color: #00FF41;'>Transforms ({len(results['transforms'])}):</p><br>")
                            for transform in results['transforms']:
                                self.signals.output.emit(f"<p style='color: #87CEEB;'>  - {transform}</p><br>")
                        
                        if results['vendor_ids']:
                            self.signals.output.emit(f"<p style='color: #00FF41;'>Vendor IDs ({len(results['vendor_ids'])}):</p><br>")
                            for vid in results['vendor_ids']:
                                self.signals.output.emit(f"<p style='color: #87CEEB;'>  - {vid}</p><br>")
            
            # Summary
            if results.get('ike_accessible'):
                self.signals.output.emit(f"<p style='color: #00FF41;'>[COMPLETE] IKE enumeration completed successfully</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>[COMPLETE] IKE enumeration completed with limited results</p><br>")
            
            self.signals.results.emit(results)
            
        except Exception as e:
            error_msg = f"IKE enumeration failed: {str(e)}"
            logger.error(error_msg)
            self.signals.error.emit(error_msg)
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] {error_msg}</p><br>")
        finally:
            self.signals.finished.emit()