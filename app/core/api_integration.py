# app/core/api_integration.py
import requests
import json
from PyQt6.QtCore import QObject, pyqtSignal
from .secure_credential_manager import secure_credential_manager

class APIIntegration(QObject):
    """Handles external API integrations for enhanced functionality."""
    
    api_response = pyqtSignal(str, dict)
    
    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        self.timeout = 10
        
    def query_shodan(self, target, api_key=None):
        """Query Shodan API for host information."""
        if not api_key:
            # Try to get API key from secure credential manager
            credential = secure_credential_manager.get_credential("shodan")
            if credential and credential.api_key:
                api_key = credential.api_key
            else:
                return {"error": "Shodan API key required. Configure in credential manager."}
            
        try:
            url = f"https://api.shodan.io/shodan/host/{target}"
            params = {"key": api_key}
            response = self.session.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                result = {
                    "source": "Shodan",
                    "ip": data.get("ip_str"),
                    "ports": data.get("ports", []),
                    "services": [service.get("product", "Unknown") for service in data.get("data", [])],
                    "country": data.get("country_name"),
                    "org": data.get("org")
                }
                self.api_response.emit("shodan", result)
                return result
            else:
                return {"error": f"Shodan API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def query_virustotal(self, target, api_key=None):
        """Query VirusTotal API for domain reputation."""
        if not api_key:
            # Try to get API key from secure credential manager
            credential = secure_credential_manager.get_credential("virustotal")
            if credential and credential.api_key:
                api_key = credential.api_key
            else:
                return {"error": "VirusTotal API key required. Configure in credential manager."}
            
        try:
            import base64
            domain_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/domains/{domain_id}"
            headers = {"x-apikey": api_key}
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result = {
                    "source": "VirusTotal",
                    "domain": target,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0),
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0)
                }
                self.api_response.emit("virustotal", result)
                return result
            else:
                return {"error": f"VirusTotal API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def query_urlvoid(self, target):
        """Query URLVoid API for domain reputation (free tier)."""
        try:
            # Using public URLVoid service (limited)
            url = f"http://api.urlvoid.com/api1000/{target}/host/{target}/"
            response = self.session.get(url, timeout=self.timeout)
            
            result = {
                "source": "URLVoid",
                "domain": target,
                "status": "checked" if response.status_code == 200 else "error",
                "response_code": response.status_code
            }
            self.api_response.emit("urlvoid", result)
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def custom_api_request(self, url, method="GET", headers=None, data=None):
        """Make custom API request."""
        try:
            headers = headers or {}
            
            if method.upper() == "GET":
                response = self.session.get(url, headers=headers, timeout=self.timeout)
            elif method.upper() == "POST":
                response = self.session.post(url, headers=headers, json=data, timeout=self.timeout)
            else:
                return {"error": f"Unsupported method: {method}"}
            
            result = {
                "url": url,
                "method": method,
                "status_code": response.status_code,
                "response": response.text[:1000],  # Limit response size
                "success": 200 <= response.status_code < 300
            }
            
            try:
                result["json"] = response.json()
            except:
                pass
                
            self.api_response.emit("custom", result)
            return result
        except Exception as e:
            return {"error": str(e)}

# Global API integration instance
api_integration = APIIntegration()