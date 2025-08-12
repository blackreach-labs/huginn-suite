# app/core/threat_intelligence.py
import requests
import json
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal

class ThreatIntelligence(QObject):
    """Manages threat intelligence feeds and IOC checking."""
    
    threat_data_updated = pyqtSignal(str, dict)
    
    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        self.timeout = 15
        self.feeds = {
            "abuse_ch": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "malware_domains": "https://mirror1.malwaredomains.com/files/justdomains",
            "phishing_army": "https://phishing.army/download/phishing_army_blocklist_extended.txt"
        }
        
    def check_ip_reputation(self, ip_address):
        """Check IP address against threat intelligence feeds."""
        results = {
            "ip": ip_address,
            "threats": [],
            "feeds_checked": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Check Abuse.ch Feodo Tracker
        try:
            response = self.session.get(self.feeds["abuse_ch"], timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                results["feeds_checked"].append("abuse_ch")
                
                for entry in data:
                    if entry.get("ip_address") == ip_address:
                        results["threats"].append({
                            "source": "Abuse.ch Feodo Tracker",
                            "type": "malware",
                            "description": f"Malware C&C server: {entry.get('malware', 'Unknown')}",
                            "first_seen": entry.get("first_seen"),
                            "last_seen": entry.get("last_seen")
                        })
        except Exception:
            pass
            
        self.threat_data_updated.emit("ip_reputation", results)
        return results
    
    def check_domain_reputation(self, domain):
        """Check domain against threat intelligence feeds."""
        results = {
            "domain": domain,
            "threats": [],
            "feeds_checked": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Check Malware Domains
        try:
            response = self.session.get(self.feeds["malware_domains"], timeout=self.timeout)
            if response.status_code == 200:
                domains = response.text.strip().split('\n')
                results["feeds_checked"].append("malware_domains")
                
                if domain in domains:
                    results["threats"].append({
                        "source": "Malware Domains",
                        "type": "malware",
                        "description": "Known malware hosting domain",
                        "severity": "high"
                    })
        except Exception:
            pass
            
        # Check Phishing Army
        try:
            response = self.session.get(self.feeds["phishing_army"], timeout=self.timeout)
            if response.status_code == 200:
                domains = response.text.strip().split('\n')
                results["feeds_checked"].append("phishing_army")
                
                if domain in domains:
                    results["threats"].append({
                        "source": "Phishing Army",
                        "type": "phishing",
                        "description": "Known phishing domain",
                        "severity": "high"
                    })
        except Exception:
            pass
            
        self.threat_data_updated.emit("domain_reputation", results)
        return results
    
    def get_ioc_summary(self, target):
        """Get comprehensive IOC summary for target."""
        if self._is_ip(target):
            return self.check_ip_reputation(target)
        else:
            return self.check_domain_reputation(target)
    
    def _is_ip(self, target):
        """Check if target is an IP address."""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, target))
    
    def get_feed_status(self):
        """Get status of threat intelligence feeds."""
        status = {}
        for feed_name, feed_url in self.feeds.items():
            try:
                response = self.session.head(feed_url, timeout=5)
                status[feed_name] = {
                    "status": "online" if response.status_code == 200 else "error",
                    "last_checked": datetime.now().isoformat()
                }
            except Exception:
                status[feed_name] = {
                    "status": "offline",
                    "last_checked": datetime.now().isoformat()
                }
        return status

# Global threat intelligence instance
threat_intelligence = ThreatIntelligence()