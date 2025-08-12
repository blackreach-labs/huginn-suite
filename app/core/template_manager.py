# app/core/template_manager.py
import json
import os
from datetime import datetime
from typing import Dict, List

class TemplateManager:
    """Manage custom scan templates"""
    
    def __init__(self):
        self.templates_dir = "templates"
        os.makedirs(self.templates_dir, exist_ok=True)
        self.default_templates = self._create_default_templates()
        self._ensure_default_templates()
    
    def _create_default_templates(self) -> Dict:
        """Create default scan templates"""
        return {
            "Quick Web Scan": {
                "description": "Fast web application assessment",
                "tools": ["http_enum", "api_enum"],
                "settings": {
                    "rate_limit": {"enabled": True, "rps": 25, "threads": 100},
                    "proxy": {"enabled": False},
                    "export_formats": ["JSON", "PDF"]
                },
                "parameters": {
                    "http_enum": {"timeout": 3, "follow_redirects": False},
                    "api_enum": {"test_methods": ["GET", "POST", "PUT"]}
                }
            },
            "Stealth Recon": {
                "description": "Low-profile reconnaissance scan",
                "tools": ["dns_enum", "port_scan"],
                "settings": {
                    "rate_limit": {"enabled": True, "rps": 2, "threads": 10},
                    "proxy": {"enabled": False},
                    "export_formats": ["JSON", "Summary"]
                },
                "parameters": {
                    "dns_enum": {"record_types": ["A", "AAAA", "CNAME"]},
                    "port_scan": {"scan_type": "tcp_connect"}
                }
            },
            "Full Assessment": {
                "description": "Comprehensive security assessment",
                "tools": ["dns_enum", "port_scan", "http_enum", "api_enum"],
                "settings": {
                    "rate_limit": {"enabled": True, "rps": 10, "threads": 50},
                    "proxy": {"enabled": False},
                    "export_formats": ["PDF", "Summary", "Correlate"]
                },
                "parameters": {
                    "dns_enum": {"record_types": ["A", "AAAA", "CNAME", "MX", "TXT"]},
                    "port_scan": {"scan_type": "tcp_connect"},
                    "http_enum": {"timeout": 5, "follow_redirects": True},
                    "api_enum": {"test_methods": ["GET", "POST", "PUT", "DELETE"]}
                }
            }
        }
    
    def _ensure_default_templates(self):
        """Ensure default templates exist"""
        for name, template in self.default_templates.items():
            template_path = os.path.join(self.templates_dir, f"{name}.json")
            if not os.path.exists(template_path):
                self.save_template(name, template)
    
    def save_template(self, name: str, template: Dict) -> bool:
        """Save a scan template"""
        try:
            template['created'] = datetime.now().isoformat()
            template['version'] = "1.0"
            
            filename = f"{name}.json"
            filepath = os.path.join(self.templates_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(template, f, indent=2)
            
            return True
        except Exception:
            return False
    
    def load_template(self, name: str) -> Dict:
        """Load a scan template"""
        try:
            filename = f"{name}.json"
            filepath = os.path.join(self.templates_dir, filename)
            
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    
    def get_template_list(self) -> List[str]:
        """Get list of available templates"""
        templates = []
        if os.path.exists(self.templates_dir):
            for filename in os.listdir(self.templates_dir):
                if filename.endswith('.json'):
                    templates.append(filename[:-5])  # Remove .json extension
        return sorted(templates)
    
    def delete_template(self, name: str) -> bool:
        """Delete a scan template"""
        try:
            filename = f"{name}.json"
            filepath = os.path.join(self.templates_dir, filename)
            
            if os.path.exists(filepath):
                os.remove(filepath)
                return True
            return False
        except Exception:
            return False
    
    def create_template_from_current(self, name: str, description: str, current_settings: Dict) -> bool:
        """Create template from current scan settings"""
        template = {
            "description": description,
            "tools": current_settings.get("tools", []),
            "settings": current_settings.get("settings", {}),
            "parameters": current_settings.get("parameters", {})
        }
        
        return self.save_template(name, template)

# Global instance
template_manager = TemplateManager()