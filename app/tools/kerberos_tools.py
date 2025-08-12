#!/usr/bin/env python3
"""
Kerberos & Credential Assessment Tools
Non-destructive Kerberos enumeration and risk assessment
"""

import ldap3
import socket
import struct
import base64
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import hashlib
import binascii

@dataclass
class SPNInfo:
    user_dn: str
    sam_account: str
    spn: str
    encryption_types: List[str]
    last_password_set: Optional[str]
    risk_score: int

@dataclass
class ASREPUser:
    user_dn: str
    sam_account: str
    user_principal_name: str
    last_logon: Optional[str]
    risk_score: int

@dataclass
class KerberosTicket:
    ticket_type: str
    client_name: str
    service_name: str
    encryption_type: str
    ticket_data: bytes
    parsed_info: Dict[str, Any]

class KerberosTools:
    def __init__(self, domain: str, dc_ip: str = None):
        self.domain = domain
        self.dc_ip = dc_ip or domain
        self.connection = None
        
    def connect_ldap(self, username: str = None, password: str = None) -> bool:
        """Connect to LDAP for enumeration"""
        try:
            server = ldap3.Server(self.dc_ip, get_info=ldap3.ALL)
            
            if username and password:
                self.connection = ldap3.Connection(
                    server,
                    user=f"{self.domain}\\{username}",
                    password=password,
                    authentication=ldap3.NTLM
                )
            else:
                # Anonymous bind
                self.connection = ldap3.Connection(server)
            
            return self.connection.bind()
            
        except Exception as e:
            print(f"LDAP connection error: {e}")
            return False
    
    def enumerate_spns(self) -> List[SPNInfo]:
        """Enumerate Service Principal Names for Kerberoast detection"""
        if not self.connection:
            return []
        
        spn_users = []
        
        try:
            # Search for users with SPNs
            search_filter = '(&(objectClass=user)(servicePrincipalName=*))'
            attributes = [
                'sAMAccountName', 'servicePrincipalName', 'pwdLastSet',
                'msDS-SupportedEncryptionTypes', 'userAccountControl'
            ]
            
            base_dn = self.connection.server.info.other['defaultNamingContext'][0]
            
            self.connection.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=attributes
            )
            
            for entry in self.connection.entries:
                spns = entry.servicePrincipalName.value
                if isinstance(spns, str):
                    spns = [spns]
                
                # Get encryption types
                enc_types = self._parse_encryption_types(
                    entry['msDS-SupportedEncryptionTypes'].value
                )
                
                # Calculate risk score
                risk_score = self._calculate_spn_risk(entry, enc_types)
                
                for spn in spns:
                    spn_info = SPNInfo(
                        user_dn=str(entry.entry_dn),
                        sam_account=str(entry.sAMAccountName.value),
                        spn=spn,
                        encryption_types=enc_types,
                        last_password_set=str(entry.pwdLastSet.value) if entry.pwdLastSet.value else None,
                        risk_score=risk_score
                    )
                    spn_users.append(spn_info)
            
        except Exception as e:
            print(f"SPN enumeration error: {e}")
        
        return sorted(spn_users, key=lambda x: x.risk_score, reverse=True)
    
    def enumerate_asrep_users(self) -> List[ASREPUser]:
        """Enumerate users with pre-authentication disabled"""
        if not self.connection:
            return []
        
        asrep_users = []
        
        try:
            # Search for users with DONT_REQ_PREAUTH flag
            search_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
            attributes = [
                'sAMAccountName', 'userPrincipalName', 'lastLogon',
                'userAccountControl', 'pwdLastSet'
            ]
            
            base_dn = self.connection.server.info.other['defaultNamingContext'][0]
            
            self.connection.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=attributes
            )
            
            for entry in self.connection.entries:
                # Calculate risk score
                risk_score = self._calculate_asrep_risk(entry)
                
                asrep_user = ASREPUser(
                    user_dn=str(entry.entry_dn),
                    sam_account=str(entry.sAMAccountName.value),
                    user_principal_name=str(entry.userPrincipalName.value) if entry.userPrincipalName.value else "",
                    last_logon=str(entry.lastLogon.value) if entry.lastLogon.value else None,
                    risk_score=risk_score
                )
                asrep_users.append(asrep_user)
            
        except Exception as e:
            print(f"AS-REP enumeration error: {e}")
        
        return sorted(asrep_users, key=lambda x: x.risk_score, reverse=True)
    
    def analyze_kerberos_policy(self) -> Dict[str, Any]:
        """Analyze domain Kerberos policy"""
        if not self.connection:
            return {}
        
        policy_info = {}
        
        try:
            # Get domain policy
            base_dn = self.connection.server.info.other['defaultNamingContext'][0]
            
            self.connection.search(
                search_base=base_dn,
                search_filter='(objectClass=domain)',
                attributes=[
                    'maxTicketAge', 'maxRenewAge', 'lockoutDuration',
                    'lockoutThreshold', 'minPwdLength', 'pwdHistoryLength'
                ]
            )
            
            if self.connection.entries:
                entry = self.connection.entries[0]
                policy_info = {
                    'max_ticket_age': str(entry.maxTicketAge.value) if entry.maxTicketAge.value else "10 hours",
                    'max_renew_age': str(entry.maxRenewAge.value) if entry.maxRenewAge.value else "7 days",
                    'lockout_duration': str(entry.lockoutDuration.value) if entry.lockoutDuration.value else "30 minutes",
                    'lockout_threshold': str(entry.lockoutThreshold.value) if entry.lockoutThreshold.value else "0",
                    'min_password_length': str(entry.minPwdLength.value) if entry.minPwdLength.value else "7",
                    'password_history': str(entry.pwdHistoryLength.value) if entry.pwdHistoryLength.value else "24"
                }
            
            # Analyze policy weaknesses
            policy_info['weaknesses'] = self._analyze_policy_weaknesses(policy_info)
            
        except Exception as e:
            print(f"Policy analysis error: {e}")
        
        return policy_info
    
    def parse_ticket_file(self, ticket_path: str) -> List[KerberosTicket]:
        """Parse Kerberos ticket file (ccache or kirbi)"""
        tickets = []
        
        try:
            with open(ticket_path, 'rb') as f:
                ticket_data = f.read()
            
            # Determine file type by magic bytes
            if ticket_data.startswith(b'\x05\x04'):  # ccache
                tickets = self._parse_ccache(ticket_data)
            elif ticket_data.startswith(b'\x76'):  # kirbi
                tickets = self._parse_kirbi(ticket_data)
            else:
                # Try to parse as base64 encoded
                try:
                    decoded_data = base64.b64decode(ticket_data)
                    if decoded_data.startswith(b'\x76'):
                        tickets = self._parse_kirbi(decoded_data)
                except:
                    pass
            
        except Exception as e:
            print(f"Ticket parsing error: {e}")
        
        return tickets
    
    def generate_kerberoast_report(self, spn_users: List[SPNInfo]) -> Dict[str, Any]:
        """Generate Kerberoast assessment report"""
        report = {
            'summary': {
                'total_spn_users': len(spn_users),
                'high_risk_users': len([u for u in spn_users if u.risk_score >= 7]),
                'medium_risk_users': len([u for u in spn_users if 4 <= u.risk_score < 7]),
                'low_risk_users': len([u for u in spn_users if u.risk_score < 4])
            },
            'high_risk_targets': [
                {
                    'sam_account': user.sam_account,
                    'spn': user.spn,
                    'risk_score': user.risk_score,
                    'encryption_types': user.encryption_types,
                    'last_password_set': user.last_password_set
                }
                for user in spn_users if user.risk_score >= 7
            ],
            'recommendations': self._generate_kerberoast_recommendations(spn_users)
        }
        
        return report
    
    def generate_asrep_report(self, asrep_users: List[ASREPUser]) -> Dict[str, Any]:
        """Generate AS-REP Roasting assessment report"""
        report = {
            'summary': {
                'total_asrep_users': len(asrep_users),
                'high_risk_users': len([u for u in asrep_users if u.risk_score >= 7]),
                'active_users': len([u for u in asrep_users if u.last_logon])
            },
            'vulnerable_users': [
                {
                    'sam_account': user.sam_account,
                    'user_principal_name': user.user_principal_name,
                    'risk_score': user.risk_score,
                    'last_logon': user.last_logon
                }
                for user in asrep_users
            ],
            'recommendations': self._generate_asrep_recommendations(asrep_users)
        }
        
        return report
    
    def _parse_encryption_types(self, enc_types_value: Any) -> List[str]:
        """Parse supported encryption types"""
        if not enc_types_value:
            return ['RC4-HMAC']  # Default
        
        try:
            enc_types_int = int(enc_types_value)
            types = []
            
            if enc_types_int & 0x1:
                types.append('DES-CBC-CRC')
            if enc_types_int & 0x2:
                types.append('DES-CBC-MD5')
            if enc_types_int & 0x4:
                types.append('RC4-HMAC')
            if enc_types_int & 0x8:
                types.append('AES128-CTS-HMAC-SHA1-96')
            if enc_types_int & 0x10:
                types.append('AES256-CTS-HMAC-SHA1-96')
            
            return types if types else ['RC4-HMAC']
            
        except (ValueError, TypeError):
            return ['RC4-HMAC']
    
    def _calculate_spn_risk(self, entry: Any, enc_types: List[str]) -> int:
        """Calculate risk score for SPN user"""
        risk = 0
        
        # Base risk for having SPN
        risk += 3
        
        # Higher risk for weak encryption
        if 'RC4-HMAC' in enc_types and len(enc_types) == 1:
            risk += 3
        elif 'DES-CBC-CRC' in enc_types or 'DES-CBC-MD5' in enc_types:
            risk += 4
        
        # Check if user is privileged
        uac = entry.userAccountControl.value
        if uac and int(uac) & 0x2:  # Account disabled
            risk -= 2
        
        # Check account name for service indicators
        sam_account = str(entry.sAMAccountName.value).lower()
        if any(keyword in sam_account for keyword in ['svc', 'service', 'sql', 'iis']):
            risk += 2
        
        return max(0, min(10, risk))
    
    def _calculate_asrep_risk(self, entry: Any) -> int:
        """Calculate risk score for AS-REP user"""
        risk = 5  # Base risk for no pre-auth
        
        # Check if account is active
        if entry.lastLogon.value:
            try:
                # Recent logon increases risk
                last_logon = int(entry.lastLogon.value)
                if last_logon > 0:
                    risk += 2
            except (ValueError, TypeError):
                pass
        
        # Check if account is enabled
        uac = entry.userAccountControl.value
        if uac and int(uac) & 0x2:  # Account disabled
            risk -= 3
        
        return max(0, min(10, risk))
    
    def _analyze_policy_weaknesses(self, policy: Dict[str, Any]) -> List[str]:
        """Analyze Kerberos policy for weaknesses"""
        weaknesses = []
        
        try:
            # Check lockout threshold
            lockout_threshold = int(policy.get('lockout_threshold', '0'))
            if lockout_threshold == 0:
                weaknesses.append("No account lockout policy configured")
            elif lockout_threshold > 10:
                weaknesses.append("Account lockout threshold is too high")
            
            # Check minimum password length
            min_pwd_len = int(policy.get('min_password_length', '7'))
            if min_pwd_len < 8:
                weaknesses.append("Minimum password length is too short")
            
            # Check password history
            pwd_history = int(policy.get('password_history', '24'))
            if pwd_history < 12:
                weaknesses.append("Password history is insufficient")
                
        except (ValueError, TypeError):
            weaknesses.append("Unable to parse policy values")
        
        return weaknesses
    
    def _parse_ccache(self, data: bytes) -> List[KerberosTicket]:
        """Parse ccache ticket file"""
        tickets = []
        # Simplified ccache parsing - full implementation would be more complex
        try:
            # This is a placeholder - real ccache parsing requires detailed format knowledge
            ticket = KerberosTicket(
                ticket_type='TGT',
                client_name='unknown',
                service_name='krbtgt',
                encryption_type='unknown',
                ticket_data=data,
                parsed_info={'format': 'ccache', 'size': len(data)}
            )
            tickets.append(ticket)
        except Exception as e:
            print(f"ccache parsing error: {e}")
        
        return tickets
    
    def _parse_kirbi(self, data: bytes) -> List[KerberosTicket]:
        """Parse kirbi ticket file"""
        tickets = []
        # Simplified kirbi parsing - full implementation would be more complex
        try:
            # This is a placeholder - real kirbi parsing requires ASN.1 decoding
            ticket = KerberosTicket(
                ticket_type='TGS',
                client_name='unknown',
                service_name='unknown',
                encryption_type='unknown',
                ticket_data=data,
                parsed_info={'format': 'kirbi', 'size': len(data)}
            )
            tickets.append(ticket)
        except Exception as e:
            print(f"kirbi parsing error: {e}")
        
        return tickets
    
    def _generate_kerberoast_recommendations(self, spn_users: List[SPNInfo]) -> List[str]:
        """Generate Kerberoast mitigation recommendations"""
        recommendations = []
        
        if spn_users:
            recommendations.extend([
                "Use strong, complex passwords for service accounts (25+ characters)",
                "Enable AES encryption for Kerberos (disable RC4)",
                "Use Group Managed Service Accounts (gMSA) where possible",
                "Regularly rotate service account passwords",
                "Monitor for Kerberoast attacks in security logs (Event ID 4769)"
            ])
        
        high_risk_count = len([u for u in spn_users if u.risk_score >= 7])
        if high_risk_count > 0:
            recommendations.append(f"Immediately address {high_risk_count} high-risk service accounts")
        
        return recommendations
    
    def _generate_asrep_recommendations(self, asrep_users: List[ASREPUser]) -> List[str]:
        """Generate AS-REP Roasting mitigation recommendations"""
        recommendations = []
        
        if asrep_users:
            recommendations.extend([
                "Enable Kerberos pre-authentication for all user accounts",
                "Review accounts with pre-auth disabled for business justification",
                "Use strong passwords for accounts that must have pre-auth disabled",
                "Monitor for AS-REP roasting attacks in security logs (Event ID 4768)"
            ])
        
        active_count = len([u for u in asrep_users if u.last_logon])
        if active_count > 0:
            recommendations.append(f"Prioritize {active_count} active accounts with pre-auth disabled")
        
        return recommendations

# Example usage
if __name__ == "__main__":
    # Example Kerberos assessment
    kerberos_tools = KerberosTools("example.local")
    
    if kerberos_tools.connect_ldap():
        print("Connected to domain controller")
        
        # Enumerate SPNs
        spn_users = kerberos_tools.enumerate_spns()
        print(f"Found {len(spn_users)} users with SPNs")
        
        # Generate Kerberoast report
        kerberoast_report = kerberos_tools.generate_kerberoast_report(spn_users)
        print(f"Kerberoast Report: {json.dumps(kerberoast_report, indent=2)}")
        
        # Enumerate AS-REP users
        asrep_users = kerberos_tools.enumerate_asrep_users()
        print(f"Found {len(asrep_users)} AS-REP roastable users")
        
        # Analyze Kerberos policy
        policy = kerberos_tools.analyze_kerberos_policy()
        print(f"Kerberos Policy: {json.dumps(policy, indent=2)}")
    else:
        print("Failed to connect to domain controller")