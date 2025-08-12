import base64
import hashlib
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

@dataclass
class Evidence:
    """Evidence data structure"""
    vuln_id: str
    evidence_type: str  # 'request', 'response', 'screenshot', 'payload'
    data: str
    timestamp: float
    metadata: Dict[str, Any]

class EvidenceCollector:
    """Collects and manages vulnerability evidence"""
    
    def __init__(self):
        self.evidence_store: Dict[str, List[Evidence]] = {}
    
    def collect_request_evidence(self, vuln_id: str, method: str, url: str, 
                               headers: Dict, data: str = "") -> str:
        """Collect HTTP request evidence"""
        request_data = f"{method} {url}\n"
        for k, v in headers.items():
            request_data += f"{k}: {v}\n"
        if data:
            request_data += f"\n{data}"
        
        evidence = Evidence(
            vuln_id=vuln_id,
            evidence_type="request",
            data=base64.b64encode(request_data.encode()).decode(),
            timestamp=time.time(),
            metadata={"method": method, "url": url, "size": len(request_data)}
        )
        
        self._store_evidence(vuln_id, evidence)
        return evidence.data
    
    def collect_response_evidence(self, vuln_id: str, status_code: int, 
                                headers: Dict, content: str) -> str:
        """Collect HTTP response evidence"""
        response_data = f"HTTP/1.1 {status_code}\n"
        for k, v in headers.items():
            response_data += f"{k}: {v}\n"
        response_data += f"\n{content[:2000]}"  # Limit content size
        
        evidence = Evidence(
            vuln_id=vuln_id,
            evidence_type="response",
            data=base64.b64encode(response_data.encode()).decode(),
            timestamp=time.time(),
            metadata={"status_code": status_code, "size": len(content)}
        )
        
        self._store_evidence(vuln_id, evidence)
        return evidence.data
    
    def collect_payload_evidence(self, vuln_id: str, payload: str, 
                               context: str = "") -> str:
        """Collect payload evidence"""
        evidence = Evidence(
            vuln_id=vuln_id,
            evidence_type="payload",
            data=base64.b64encode(payload.encode()).decode(),
            timestamp=time.time(),
            metadata={"context": context, "payload_hash": hashlib.md5(payload.encode()).hexdigest()}
        )
        
        self._store_evidence(vuln_id, evidence)
        return evidence.data
    
    def get_evidence(self, vuln_id: str) -> List[Evidence]:
        """Get all evidence for vulnerability"""
        return self.evidence_store.get(vuln_id, [])
    
    def generate_evidence_report(self, vuln_id: str) -> Dict[str, Any]:
        """Generate evidence report for vulnerability"""
        evidence_list = self.get_evidence(vuln_id)
        if not evidence_list:
            return {}
        
        report = {
            "vulnerability_id": vuln_id,
            "evidence_count": len(evidence_list),
            "collected_at": min(e.timestamp for e in evidence_list),
            "evidence": []
        }
        
        for evidence in evidence_list:
            report["evidence"].append({
                "type": evidence.evidence_type,
                "data": evidence.data,
                "timestamp": evidence.timestamp,
                "metadata": evidence.metadata
            })
        
        return report
    
    def _store_evidence(self, vuln_id: str, evidence: Evidence):
        """Store evidence internally"""
        if vuln_id not in self.evidence_store:
            self.evidence_store[vuln_id] = []
        self.evidence_store[vuln_id].append(evidence)
    
    def _generate_vuln_id(self, vuln_type: str, target: str) -> str:
        """Generate unique vulnerability ID"""
        data = f"{vuln_type}_{target}_{time.time()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]