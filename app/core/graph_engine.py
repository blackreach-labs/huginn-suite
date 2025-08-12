#!/usr/bin/env python3
"""
Attack Graph Engine
Analyzes AD relationships to find attack paths and privilege escalation routes
"""

import sqlite3
import json
import networkx as nx
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import uuid

@dataclass
class AttackPath:
    source: str
    target: str
    steps: List[Dict[str, Any]]
    risk_score: int
    path_type: str
    description: str

@dataclass
class AttackStep:
    from_node: str
    to_node: str
    technique: str
    description: str
    risk_weight: int
    requirements: List[str]

class GraphEngine:
    def __init__(self, ad_db_path: str):
        self.ad_db_path = ad_db_path
        self.graph = nx.DiGraph()
        self.attack_techniques = self._load_attack_techniques()
        self._build_graph()
    
    def _load_attack_techniques(self) -> Dict[str, AttackStep]:
        """Load MITRE ATT&CK-style techniques"""
        return {
            'member_of': AttackStep(
                from_node='user', to_node='group',
                technique='T1078', description='Valid Accounts - Group Membership',
                risk_weight=1, requirements=[]
            ),
            'local_admin': AttackStep(
                from_node='user', to_node='computer',
                technique='T1078.002', description='Valid Accounts - Domain Accounts',
                risk_weight=3, requirements=['credentials']
            ),
            'dcsync': AttackStep(
                from_node='user', to_node='domain',
                technique='T1003.006', description='DCSync Attack',
                risk_weight=5, requirements=['Replicating Directory Changes']
            ),
            'golden_ticket': AttackStep(
                from_node='krbtgt', to_node='domain',
                technique='T1558.001', description='Golden Ticket Attack',
                risk_weight=5, requirements=['krbtgt_hash']
            ),
            'kerberoast': AttackStep(
                from_node='user', to_node='service_account',
                technique='T1558.003', description='Kerberoasting',
                risk_weight=3, requirements=['SPN']
            ),
            'asreproast': AttackStep(
                from_node='anonymous', to_node='user',
                technique='T1558.004', description='AS-REP Roasting',
                risk_weight=2, requirements=['DONT_REQ_PREAUTH']
            )
        }
    
    def _build_graph(self):
        """Build NetworkX graph from AD database"""
        conn = sqlite3.connect(self.ad_db_path)
        cursor = conn.cursor()
        
        # Add nodes (AD objects)
        cursor.execute("SELECT dn, object_class, attributes FROM ad_objects")
        for dn, obj_class, attrs_json in cursor.fetchall():
            attrs = json.loads(attrs_json)
            self.graph.add_node(dn, 
                               object_class=obj_class,
                               attributes=attrs,
                               risk_level=self._calculate_node_risk(obj_class, attrs))
        
        # Add edges (relationships)
        cursor.execute("SELECT source_dn, target_dn, relationship_type, attributes FROM ad_relationships")
        for source, target, rel_type, attrs_json in cursor.fetchall():
            attrs = json.loads(attrs_json)
            
            if source in self.graph.nodes and target in self.graph.nodes:
                weight = self._calculate_edge_weight(rel_type, attrs)
                self.graph.add_edge(source, target,
                                  relationship=rel_type,
                                  attributes=attrs,
                                  weight=weight)
        
        conn.close()
    
    def find_attack_paths(self, source: str = None, target: str = None, 
                         max_paths: int = 10) -> List[AttackPath]:
        """Find attack paths between source and target"""
        paths = []
        
        # If no source specified, find all low-privilege users
        if not source:
            sources = self._find_low_privilege_users()
        else:
            sources = [source]
        
        # If no target specified, find high-value targets
        if not target:
            targets = self._find_high_value_targets()
        else:
            targets = [target]
        
        for src in sources[:5]:  # Limit sources to prevent explosion
            for tgt in targets[:5]:  # Limit targets
                if src == tgt:
                    continue
                
                try:
                    # Find shortest paths
                    simple_paths = list(nx.all_shortest_paths(self.graph, src, tgt))
                    
                    for path_nodes in simple_paths[:3]:  # Top 3 paths per pair
                        attack_path = self._analyze_path(path_nodes)
                        if attack_path:
                            paths.append(attack_path)
                
                except nx.NetworkXNoPath:
                    continue
                except Exception as e:
                    print(f"Path finding error: {e}")
                    continue
        
        # Sort by risk score and return top paths
        paths.sort(key=lambda x: x.risk_score, reverse=True)
        return paths[:max_paths]
    
    def find_shortest_path_to_da(self, source: str = None) -> Optional[AttackPath]:
        """Find shortest path to Domain Admin"""
        if not source:
            sources = self._find_low_privilege_users()
        else:
            sources = [source]
        
        # Find Domain Admins group
        da_group = self._find_domain_admins_group()
        if not da_group:
            return None
        
        best_path = None
        min_length = float('inf')
        
        for src in sources[:10]:  # Check top 10 low-priv users
            try:
                path_nodes = nx.shortest_path(self.graph, src, da_group)
                if len(path_nodes) < min_length:
                    min_length = len(path_nodes)
                    best_path = self._analyze_path(path_nodes)
            except nx.NetworkXNoPath:
                continue
        
        return best_path
    
    def identify_privilege_escalation_opportunities(self) -> List[Dict[str, Any]]:
        """Identify privilege escalation opportunities"""
        opportunities = []
        
        # Find users with SPNs (Kerberoastable)
        kerberoastable = self._find_kerberoastable_users()
        for user in kerberoastable:
            opportunities.append({
                'type': 'kerberoast',
                'target': user,
                'technique': 'T1558.003',
                'description': f'Kerberoastable service account: {user}',
                'risk_score': 3
            })
        
        # Find users without pre-auth (AS-REP Roastable)
        asrep_roastable = self._find_asrep_roastable_users()
        for user in asrep_roastable:
            opportunities.append({
                'type': 'asreproast',
                'target': user,
                'technique': 'T1558.004',
                'description': f'AS-REP Roastable user: {user}',
                'risk_score': 2
            })
        
        # Find computers with unconstrained delegation
        unconstrained_delegation = self._find_unconstrained_delegation()
        for computer in unconstrained_delegation:
            opportunities.append({
                'type': 'unconstrained_delegation',
                'target': computer,
                'technique': 'T1558.002',
                'description': f'Unconstrained delegation: {computer}',
                'risk_score': 4
            })
        
        return sorted(opportunities, key=lambda x: x['risk_score'], reverse=True)
    
    def generate_attack_playbook(self, attack_path: AttackPath) -> Dict[str, Any]:
        """Generate step-by-step attack playbook"""
        playbook = {
            'title': f"Attack Path: {attack_path.source} → {attack_path.target}",
            'risk_score': attack_path.risk_score,
            'estimated_time': len(attack_path.steps) * 30,  # 30 min per step
            'prerequisites': [],
            'steps': []
        }
        
        for i, step in enumerate(attack_path.steps):
            step_info = {
                'step_number': i + 1,
                'title': step.get('description', 'Unknown step'),
                'technique': step.get('technique', 'Unknown'),
                'commands': self._generate_commands_for_step(step),
                'expected_output': self._generate_expected_output(step),
                'verification': self._generate_verification_steps(step)
            }
            playbook['steps'].append(step_info)
        
        return playbook
    
    def _find_low_privilege_users(self) -> List[str]:
        """Find low-privilege user accounts"""
        low_priv_users = []
        
        for node, data in self.graph.nodes(data=True):
            if (data.get('object_class') == 'user' and 
                data.get('risk_level', 0) <= 2):
                
                attrs = data.get('attributes', {})
                # Skip service accounts and admin accounts
                sam_account = attrs.get('sAMAccountName', '').lower()
                if not any(keyword in sam_account for keyword in 
                          ['admin', 'service', 'svc', 'sql', 'iis']):
                    low_priv_users.append(node)
        
        return low_priv_users[:20]  # Limit to prevent explosion
    
    def _find_high_value_targets(self) -> List[str]:
        """Find high-value targets (admin groups, DCs, etc.)"""
        high_value = []
        
        admin_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins']
        
        for node, data in self.graph.nodes(data=True):
            attrs = data.get('attributes', {})
            
            # Admin groups
            if (data.get('object_class') == 'group' and
                attrs.get('sAMAccountName') in admin_groups):
                high_value.append(node)
            
            # Domain controllers
            elif (data.get('object_class') == 'computer' and
                  'SERVER' in attrs.get('operatingSystem', '').upper()):
                high_value.append(node)
            
            # High-risk users (adminCount=1)
            elif (data.get('object_class') == 'user' and
                  attrs.get('adminCount') == '1'):
                high_value.append(node)
        
        return high_value
    
    def _find_domain_admins_group(self) -> Optional[str]:
        """Find Domain Admins group DN"""
        for node, data in self.graph.nodes(data=True):
            if (data.get('object_class') == 'group' and
                data.get('attributes', {}).get('sAMAccountName') == 'Domain Admins'):
                return node
        return None
    
    def _find_kerberoastable_users(self) -> List[str]:
        """Find users with SPNs (Kerberoastable)"""
        kerberoastable = []
        
        for node, data in self.graph.nodes(data=True):
            if data.get('object_class') == 'user':
                attrs = data.get('attributes', {})
                spns = attrs.get('servicePrincipalName')
                if spns and spns != 'None':
                    kerberoastable.append(node)
        
        return kerberoastable
    
    def _find_asrep_roastable_users(self) -> List[str]:
        """Find users without pre-authentication required"""
        asrep_roastable = []
        
        for node, data in self.graph.nodes(data=True):
            if data.get('object_class') == 'user':
                attrs = data.get('attributes', {})
                uac = attrs.get('userAccountControl', '0')
                try:
                    # Check DONT_REQ_PREAUTH flag (0x400000)
                    if int(uac) & 0x400000:
                        asrep_roastable.append(node)
                except (ValueError, TypeError):
                    continue
        
        return asrep_roastable
    
    def _find_unconstrained_delegation(self) -> List[str]:
        """Find computers with unconstrained delegation"""
        unconstrained = []
        
        for node, data in self.graph.nodes(data=True):
            if data.get('object_class') == 'computer':
                attrs = data.get('attributes', {})
                uac = attrs.get('userAccountControl', '0')
                try:
                    # Check TRUSTED_FOR_DELEGATION flag (0x80000)
                    if int(uac) & 0x80000:
                        unconstrained.append(node)
                except (ValueError, TypeError):
                    continue
        
        return unconstrained
    
    def _analyze_path(self, path_nodes: List[str]) -> Optional[AttackPath]:
        """Analyze a path and create AttackPath object"""
        if len(path_nodes) < 2:
            return None
        
        steps = []
        total_risk = 0
        
        for i in range(len(path_nodes) - 1):
            current = path_nodes[i]
            next_node = path_nodes[i + 1]
            
            if self.graph.has_edge(current, next_node):
                edge_data = self.graph[current][next_node]
                rel_type = edge_data.get('relationship', 'unknown')
                
                step = {
                    'from': current,
                    'to': next_node,
                    'relationship': rel_type,
                    'technique': self.attack_techniques.get(rel_type, {}).get('technique', 'Unknown'),
                    'description': self._generate_step_description(current, next_node, rel_type),
                    'risk_weight': edge_data.get('weight', 1)
                }
                
                steps.append(step)
                total_risk += step['risk_weight']
        
        return AttackPath(
            source=path_nodes[0],
            target=path_nodes[-1],
            steps=steps,
            risk_score=total_risk,
            path_type='privilege_escalation',
            description=f"Path from {self._get_node_name(path_nodes[0])} to {self._get_node_name(path_nodes[-1])}"
        )
    
    def _calculate_node_risk(self, obj_class: str, attributes: Dict[str, Any]) -> int:
        """Calculate risk level for a node"""
        risk = 0
        
        if obj_class == 'user':
            if attributes.get('adminCount') == '1':
                risk += 3
            if attributes.get('servicePrincipalName'):
                risk += 2
        elif obj_class == 'group':
            group_name = attributes.get('sAMAccountName', '').lower()
            if 'admin' in group_name:
                risk += 4
        elif obj_class == 'computer':
            os_name = attributes.get('operatingSystem', '').lower()
            if 'server' in os_name:
                risk += 2
        
        return risk
    
    def _calculate_edge_weight(self, rel_type: str, attributes: Dict[str, Any]) -> int:
        """Calculate weight for an edge"""
        weights = {
            'member_of': 1,
            'local_admin': 3,
            'dcsync': 5,
            'protected_by': 2
        }
        
        return weights.get(rel_type, 1)
    
    def _generate_step_description(self, from_node: str, to_node: str, rel_type: str) -> str:
        """Generate human-readable step description"""
        from_name = self._get_node_name(from_node)
        to_name = self._get_node_name(to_node)
        
        descriptions = {
            'member_of': f"Use {from_name} membership in {to_name}",
            'local_admin': f"Use {from_name} local admin access on {to_name}",
            'dcsync': f"Perform DCSync attack from {from_name}",
            'protected_by': f"Exploit AdminSDHolder protection on {from_name}"
        }
        
        return descriptions.get(rel_type, f"Exploit relationship from {from_name} to {to_name}")
    
    def _get_node_name(self, dn: str) -> str:
        """Extract readable name from DN"""
        if '=' in dn:
            return dn.split('=')[1].split(',')[0]
        return dn
    
    def _generate_commands_for_step(self, step: Dict[str, Any]) -> List[str]:
        """Generate commands for attack step"""
        rel_type = step.get('relationship', '')
        
        commands = {
            'member_of': [
                "# Enumerate group membership",
                "net user /domain",
                "net group \"Domain Users\" /domain"
            ],
            'local_admin': [
                "# Test local admin access",
                "psexec \\\\target cmd",
                "wmic /node:target process list"
            ],
            'kerberoast': [
                "# Kerberoast attack",
                "GetUserSPNs.py domain/user:password -dc-ip DC_IP -request",
                "hashcat -m 13100 hashes.txt wordlist.txt"
            ]
        }
        
        return commands.get(rel_type, ["# Manual exploitation required"])
    
    def _generate_expected_output(self, step: Dict[str, Any]) -> str:
        """Generate expected output for step"""
        return "Expected output varies based on environment configuration"
    
    def _generate_verification_steps(self, step: Dict[str, Any]) -> List[str]:
        """Generate verification steps"""
        return [
            "Verify access gained",
            "Document evidence",
            "Test privilege level"
        ]

# Example usage
if __name__ == "__main__":
    # Example graph analysis
    engine = GraphEngine("ad_enum_example_local.db")
    
    # Find attack paths
    paths = engine.find_attack_paths()
    print(f"Found {len(paths)} attack paths")
    
    for path in paths[:3]:
        print(f"\nPath: {path.description}")
        print(f"Risk Score: {path.risk_score}")
        print(f"Steps: {len(path.steps)}")
    
    # Find privilege escalation opportunities
    opportunities = engine.identify_privilege_escalation_opportunities()
    print(f"\nFound {len(opportunities)} privilege escalation opportunities")
    
    for opp in opportunities[:5]:
        print(f"- {opp['description']} (Risk: {opp['risk_score']})")