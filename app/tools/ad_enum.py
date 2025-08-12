#!/usr/bin/env python3
"""
Active Directory Enumerator
License-clean AD enumeration and attack path analysis
"""

import ldap3
import sqlite3
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import uuid

@dataclass
class ADObject:
    dn: str
    object_class: str
    attributes: Dict[str, Any]
    domain: str

@dataclass
class ADRelationship:
    source_dn: str
    target_dn: str
    relationship_type: str
    attributes: Dict[str, Any]

class ADEnumerator:
    def __init__(self, domain: str, username: str = None, password: str = None):
        self.domain = domain
        self.username = username
        self.password = password
        self.db_path = f"ad_enum_{domain.replace('.', '_')}.db"
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for AD objects"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ad_objects (
                id TEXT PRIMARY KEY,
                dn TEXT UNIQUE NOT NULL,
                object_class TEXT NOT NULL,
                domain TEXT NOT NULL,
                attributes TEXT NOT NULL,
                discovered_at TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ad_relationships (
                id TEXT PRIMARY KEY,
                source_dn TEXT NOT NULL,
                target_dn TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                attributes TEXT NOT NULL,
                discovered_at TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_paths (
                id TEXT PRIMARY KEY,
                source_dn TEXT NOT NULL,
                target_dn TEXT NOT NULL,
                path_steps TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                calculated_at TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def connect(self) -> bool:
        """Connect to domain controller"""
        try:
            # Find domain controllers
            dc_servers = self._find_domain_controllers()
            
            for dc in dc_servers:
                try:
                    server = ldap3.Server(dc, get_info=ldap3.ALL)
                    
                    if self.username and self.password:
                        self.connection = ldap3.Connection(
                            server,
                            user=f"{self.domain}\\{self.username}",
                            password=self.password,
                            authentication=ldap3.NTLM
                        )
                    else:
                        # Anonymous bind
                        self.connection = ldap3.Connection(server)
                    
                    if self.connection.bind():
                        self.base_dn = server.info.other['defaultNamingContext'][0]
                        return True
                        
                except Exception as e:
                    print(f"Failed to connect to {dc}: {e}")
                    continue
            
            return False
            
        except Exception as e:
            print(f"Connection error: {e}")
            return False
    
    def enumerate_all(self) -> Dict[str, int]:
        """Enumerate all AD objects and relationships"""
        if not hasattr(self, 'connection'):
            if not self.connect():
                return {}
        
        results = {
            'users': self.enumerate_users(),
            'computers': self.enumerate_computers(),
            'groups': self.enumerate_groups(),
            'ous': self.enumerate_ous(),
            'gpos': self.enumerate_gpos(),
            'trusts': self.enumerate_trusts()
        }
        
        # Enumerate relationships
        self.enumerate_group_memberships()
        self.enumerate_acls()
        self.enumerate_local_admins()
        
        return results
    
    def enumerate_users(self) -> int:
        """Enumerate domain users"""
        search_filter = '(&(objectClass=user)(objectCategory=person))'
        attributes = [
            'sAMAccountName', 'displayName', 'mail', 'userPrincipalName',
            'lastLogon', 'pwdLastSet', 'userAccountControl', 'memberOf',
            'servicePrincipalName', 'adminCount'
        ]
        
        return self._enumerate_objects('user', search_filter, attributes)
    
    def enumerate_computers(self) -> int:
        """Enumerate domain computers"""
        search_filter = '(objectClass=computer)'
        attributes = [
            'sAMAccountName', 'dNSHostName', 'operatingSystem',
            'operatingSystemVersion', 'lastLogon', 'servicePrincipalName',
            'userAccountControl'
        ]
        
        return self._enumerate_objects('computer', search_filter, attributes)
    
    def enumerate_groups(self) -> int:
        """Enumerate domain groups"""
        search_filter = '(objectClass=group)'
        attributes = [
            'sAMAccountName', 'displayName', 'description', 'member',
            'memberOf', 'groupType', 'adminCount'
        ]
        
        return self._enumerate_objects('group', search_filter, attributes)
    
    def enumerate_ous(self) -> int:
        """Enumerate organizational units"""
        search_filter = '(objectClass=organizationalUnit)'
        attributes = ['name', 'description', 'gPLink']
        
        return self._enumerate_objects('ou', search_filter, attributes)
    
    def enumerate_gpos(self) -> int:
        """Enumerate group policy objects"""
        search_filter = '(objectClass=groupPolicyContainer)'
        attributes = ['displayName', 'gPCFileSysPath', 'versionNumber']
        
        return self._enumerate_objects('gpo', search_filter, attributes)
    
    def enumerate_trusts(self) -> int:
        """Enumerate domain trusts"""
        search_filter = '(objectClass=trustedDomain)'
        attributes = ['trustPartner', 'trustDirection', 'trustType', 'trustAttributes']
        
        return self._enumerate_objects('trust', search_filter, attributes)
    
    def enumerate_group_memberships(self):
        """Enumerate group membership relationships"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all groups with members
        cursor.execute(
            "SELECT dn, attributes FROM ad_objects WHERE object_class = 'group'"
        )
        
        for dn, attrs_json in cursor.fetchall():
            attrs = json.loads(attrs_json)
            members = attrs.get('member', [])
            
            if isinstance(members, str):
                members = [members]
            
            for member_dn in members:
                self._store_relationship(
                    member_dn, dn, 'member_of', {}
                )
        
        conn.close()
    
    def enumerate_acls(self):
        """Enumerate ACL relationships (simplified)"""
        # This would require more complex LDAP queries for nTSecurityDescriptor
        # For now, focus on adminCount and high-privilege indicators
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Find objects with adminCount=1 (protected by AdminSDHolder)
        cursor.execute('''
            SELECT dn, attributes FROM ad_objects 
            WHERE json_extract(attributes, '$.adminCount') = '1'
        ''')
        
        for dn, attrs_json in cursor.fetchall():
            self._store_relationship(
                dn, 'CN=AdminSDHolder,CN=System,' + self.base_dn,
                'protected_by', {'adminCount': 1}
            )
        
        conn.close()
    
    def enumerate_local_admins(self):
        """Enumerate local admin relationships (requires additional data)"""
        # This would typically require session enumeration or GPO analysis
        # For now, infer from group memberships
        
        admin_groups = [
            'Domain Admins', 'Enterprise Admins', 'Administrators',
            'Account Operators', 'Backup Operators', 'Server Operators'
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for group_name in admin_groups:
            cursor.execute('''
                SELECT dn FROM ad_objects 
                WHERE object_class = 'group' 
                AND json_extract(attributes, '$.sAMAccountName') = ?
            ''', (group_name,))
            
            group_result = cursor.fetchone()
            if group_result:
                group_dn = group_result[0]
                
                # Find members of this admin group
                cursor.execute('''
                    SELECT source_dn FROM ad_relationships 
                    WHERE target_dn = ? AND relationship_type = 'member_of'
                ''', (group_dn,))
                
                for (member_dn,) in cursor.fetchall():
                    self._store_relationship(
                        member_dn, 'LOCAL_ADMIN_ACCESS',
                        'local_admin', {'group': group_name}
                    )
        
        conn.close()
    
    def _enumerate_objects(self, obj_type: str, search_filter: str, attributes: List[str]) -> int:
        """Generic object enumeration"""
        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                attributes=attributes
            )
            
            count = 0
            for entry in self.connection.entries:
                obj_attrs = {}
                for attr in attributes:
                    if hasattr(entry, attr):
                        value = getattr(entry, attr).value
                        if isinstance(value, list) and len(value) == 1:
                            value = value[0]
                        obj_attrs[attr] = str(value) if value else None
                
                self._store_object(ADObject(
                    dn=str(entry.entry_dn),
                    object_class=obj_type,
                    attributes=obj_attrs,
                    domain=self.domain
                ))
                count += 1
            
            return count
            
        except Exception as e:
            print(f"Error enumerating {obj_type}: {e}")
            return 0
    
    def _store_object(self, obj: ADObject):
        """Store AD object in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO ad_objects 
            (id, dn, object_class, domain, attributes, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            obj.dn,
            obj.object_class,
            obj.domain,
            json.dumps(obj.attributes),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _store_relationship(self, source_dn: str, target_dn: str, 
                           rel_type: str, attributes: Dict[str, Any]):
        """Store AD relationship in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO ad_relationships 
            (id, source_dn, target_dn, relationship_type, attributes, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            source_dn,
            target_dn,
            rel_type,
            json.dumps(attributes),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _find_domain_controllers(self) -> List[str]:
        """Find domain controllers for the domain"""
        import dns.resolver
        
        try:
            # Query SRV records for domain controllers
            srv_query = f"_ldap._tcp.{self.domain}"
            answers = dns.resolver.resolve(srv_query, 'SRV')
            
            dcs = []
            for answer in answers:
                dc_name = str(answer.target).rstrip('.')
                dcs.append(dc_name)
            
            return dcs
            
        except Exception:
            # Fallback to domain name
            return [self.domain]
    
    def get_statistics(self) -> Dict[str, int]:
        """Get enumeration statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Object counts
        cursor.execute(
            "SELECT object_class, COUNT(*) FROM ad_objects GROUP BY object_class"
        )
        for obj_class, count in cursor.fetchall():
            stats[f"{obj_class}_count"] = count
        
        # Relationship counts
        cursor.execute(
            "SELECT relationship_type, COUNT(*) FROM ad_relationships GROUP BY relationship_type"
        )
        for rel_type, count in cursor.fetchall():
            stats[f"{rel_type}_relationships"] = count
        
        conn.close()
        return stats

# Example usage
if __name__ == "__main__":
    # Example enumeration
    enumerator = ADEnumerator("example.local", "user", "password")
    
    if enumerator.connect():
        print("Connected to domain controller")
        
        results = enumerator.enumerate_all()
        print(f"Enumeration results: {results}")
        
        stats = enumerator.get_statistics()
        print(f"Statistics: {stats}")
    else:
        print("Failed to connect to domain")