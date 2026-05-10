# app/tools/av_worker.py
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.tools.av_firewall_scanner import av_firewall_scanner
import logging
from app.core.html_utils import h

logger = logging.getLogger(__name__)

class AVFirewallWorkerSignals(QObject):
    """Signals for AV/Firewall detection worker"""
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)
    error = pyqtSignal(str)

class AVFirewallWorker(QRunnable):
    """AV/Firewall detection worker"""
    
    def __init__(self, target, detection_type="WAF Detection", port=80):
        super().__init__()
        self.target = target
        self.detection_type = detection_type
        self.port = int(port)
        self.signals = AVFirewallWorkerSignals()
        self.is_running = True
    
    def run(self):
        """Execute AV/Firewall detection"""
        try:
            self.signals.output.emit(f"<p style='color: #00BFFF;'>[AV DETECTION] Starting {h(self.detection_type)} on {h(self.target)}</p><br>")
            
            results = {
                'target': self.target,
                'detection_type': self.detection_type,
                'port': self.port,
                'detections': [],
                'error': None
            }
            
            if not self.is_running:
                return
            
            if self.detection_type == "WAF Detection":
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Testing for Web Application Firewall...</p><br>")
                waf_results = av_firewall_scanner.detect_waf(self.target, self.port)
                
                if waf_results.get('error'):
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] {h(waf_results['error'])}</p><br>")
                    results['error'] = waf_results['error']
                else:
                    if waf_results.get('waf_detected'):
                        waf_type = waf_results.get('waf_type', 'Unknown')
                        self.signals.output.emit(f"<p style='color: #FF6B6B;'>WAF DETECTED: {h(waf_type)}</p><br>")
                        results['detections'].append({
                            'type': 'WAF',
                            'name': waf_type,
                            'indicators': waf_results.get('indicators', [])
                        })
                        
                        for indicator in waf_results.get('indicators', []):
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>  - {h(indicator)}</p><br>")
                    else:
                        self.signals.output.emit(f"<p style='color: #00FF41;'>No WAF detected</p><br>")
                
                results.update(waf_results)
            
            elif self.detection_type == "Firewall Detection":
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Testing for network firewall...</p><br>")
                fw_results = av_firewall_scanner.detect_firewall_nmap(self.target)
                
                if fw_results.get('error'):
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] {h(fw_results['error'])}</p><br>")
                    results['error'] = fw_results['error']
                else:
                    if fw_results.get('firewall_detected'):
                        self.signals.output.emit(f"<p style='color: #FF6B6B;'>FIREWALL DETECTED</p><br>")
                        filtered_ports = fw_results.get('filtered_ports', [])
                        if filtered_ports:
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>Filtered ports: {', '.join(filtered_ports)}</p><br>")
                        
                        results['detections'].append({
                            'type': 'Firewall',
                            'name': 'Network Firewall',
                            'filtered_ports': filtered_ports
                        })
                    else:
                        self.signals.output.emit(f"<p style='color: #00FF41;'>No firewall filtering detected</p><br>")
                
                results.update(fw_results)
            
            elif self.detection_type == "Evasion Testing":
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Testing firewall evasion techniques...</p><br>")
                evasion_results = av_firewall_scanner.firewall_evasion_scan(self.target)
                
                if evasion_results.get('error'):
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] {h(evasion_results['error'])}</p><br>")
                    results['error'] = evasion_results['error']
                else:
                    successful = evasion_results.get('successful_techniques', [])
                    if successful:
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Successful evasion techniques:</p><br>")
                        for technique in successful:
                            self.signals.output.emit(f"<p style='color: #87CEEB;'>  - {h(technique)}</p><br>")
                        
                        results['detections'].append({
                            'type': 'Evasion',
                            'successful_techniques': successful
                        })
                    else:
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>No successful evasion techniques found</p><br>")
                
                results.update(evasion_results)
            
            elif self.detection_type == "AV Payload Generation":
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Generating AV test payload...</p><br>")
                payload_results = av_firewall_scanner.generate_av_test_payload("msfvenom")
                
                if payload_results.get('error'):
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] {h(payload_results['error'])}</p><br>")
                    results['error'] = payload_results['error']
                else:
                    if payload_results.get('command'):
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Generated command:</p><br>")
                        self.signals.output.emit(f"<p style='color: #87CEEB;'>{h(payload_results['command'])}</p><br>")
                    
                    for instruction in payload_results.get('instructions', []):
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>{h(instruction)}</p><br>")
                    
                    results['detections'].append({
                        'type': 'Payload',
                        'command': payload_results.get('command'),
                        'instructions': payload_results.get('instructions', [])
                    })
                
                results.update(payload_results)
            
            # Summary
            detection_count = len(results.get('detections', []))
            if detection_count > 0:
                self.signals.output.emit(f"<p style='color: #00FF41;'>[COMPLETE] Detection completed - {h(detection_count)} findings</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>[COMPLETE] Detection completed - no security measures detected</p><br>")
            
            self.signals.results.emit(results)
            
        except Exception as e:
            error_msg = f"AV/Firewall detection failed: {str(e)}"
            logger.error(error_msg)
            self.signals.error.emit(error_msg)
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] {h(error_msg)}</p><br>")
        finally:
            self.signals.finished.emit()