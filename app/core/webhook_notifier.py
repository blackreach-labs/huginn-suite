import json
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import aiohttp
from logging import info, error
from app.core.logger import logger

class WebhookNotifier:
    """Real-time webhook notifications for scan events"""
    
    def __init__(self):
        self.webhook_urls: List[str] = []
        self.notification_queue: List[Dict] = []
        self.enabled = False
    
    def set_webhook_url(self, url: str):
        """Set webhook URL for notifications"""
        if self._validate_url(url):
            self.webhook_urls = [url]
            self.enabled = True
            info(f"Webhook URL set: {url}")
    
    def add_webhook_url(self, url: str):
        """Add additional webhook URL"""
        if self._validate_url(url) and url not in self.webhook_urls:
            self.webhook_urls.append(url)
            self.enabled = True
    
    async def notify_scan_started(self, target: str, profile: str):
        """Notify scan start"""
        payload = {
            "event": "scan_started",
            "timestamp": time.time(),
            "data": {
                "target": target,
                "profile": profile,
                "message": f"🚀 Huginn scan started for {target} with {profile} profile"
            }
        }
        await self._send_notification(payload)
    
    async def notify_vulnerability_found(self, vuln: Dict[str, Any]):
        """Notify vulnerability discovery"""
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠", 
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "ℹ️"
        }
        
        emoji = severity_emoji.get(vuln.get("severity", "INFO"), "⚠️")
        payload = {
            "event": "vulnerability_found",
            "timestamp": time.time(),
            "data": {
                "severity": vuln.get("severity", "UNKNOWN"),
                "type": vuln.get("type", "Unknown"),
                "url": vuln.get("url", ""),
                "message": f"{emoji} {vuln.get('severity', 'UNKNOWN')}: {vuln.get('type', 'Unknown Vulnerability')}"
            }
        }
        await self._send_notification(payload)
    
    async def notify_scan_completed(self, target: str, vuln_count: int, duration: float):
        """Notify scan completion"""
        payload = {
            "event": "scan_completed",
            "timestamp": time.time(),
            "data": {
                "target": target,
                "vulnerabilities_found": vuln_count,
                "duration_seconds": duration,
                "message": f"✅ Scan completed for {target}: {vuln_count} vulnerabilities found in {duration:.1f}s"
            }
        }
        await self._send_notification(payload)
    
    async def notify_critical_finding(self, vuln: Dict[str, Any]):
        """Send immediate notification for critical findings"""
        payload = {
            "event": "critical_vulnerability",
            "timestamp": time.time(),
            "data": {
                "severity": "CRITICAL",
                "type": vuln.get("type", "Unknown"),
                "url": vuln.get("url", ""),
                "description": vuln.get("description", ""),
                "message": f"🚨 CRITICAL: {vuln.get('type', 'Unknown')} found at {vuln.get('url', 'unknown location')}"
            }
        }
        await self._send_notification(payload)
    
    def create_slack_payload(self, notification: Dict) -> Dict:
        """Convert notification to Slack format"""
        color_map = {
            "scan_started": "#36a64f",
            "vulnerability_found": "#ff9900", 
            "critical_vulnerability": "#ff0000",
            "scan_completed": "#36a64f"
        }
        
        return {
            "attachments": [{
                "color": color_map.get(notification["event"], "#cccccc"),
                "title": f"Huginn Scanner - {notification['event'].replace('_', ' ').title()}",
                "text": notification["data"]["message"],
                "timestamp": int(notification["timestamp"]),
                "fields": [
                    {"title": k.replace('_', ' ').title(), "value": str(v), "short": True}
                    for k, v in notification["data"].items() if k != "message"
                ]
            }]
        }
    
    async def _send_notification(self, payload: Dict):
        """Send notification to all webhook URLs"""
        if not self.enabled or not self.webhook_urls:
            return
        
        for url in self.webhook_urls:
            try:
                # Convert to Slack format if it's a Slack webhook
                if "slack.com" in url:
                    webhook_payload = self.create_slack_payload(payload)
                else:
                    webhook_payload = payload
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json=webhook_payload,
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        if response.status == 200:
                            info(f"Webhook notification sent successfully to {url}")
                        else:
                            error(f"Webhook notification failed: {response.status}")
            
            except Exception as e:
                error(f"Failed to send webhook notification to {url}: {e}")
    
    def _validate_url(self, url: str) -> bool:
        """Validate webhook URL"""
        try:
            parsed = urlparse(url)
            return parsed.scheme in ['http', 'https'] and parsed.netloc
        except Exception:
            return False