import asyncio
import random
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import time

class AgentState(Enum):
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PERSISTENCE = "persistence"
    REPORTING = "reporting"

@dataclass
class AgentMemory:
    discovered_assets: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    exploitation_results: List[Dict] = field(default_factory=list)
    learned_patterns: Dict[str, Any] = field(default_factory=dict)
    success_rate: float = 0.0
    confidence_level: float = 0.5

@dataclass
class AgentDecision:
    action: str
    target: str
    method: str
    confidence: float
    reasoning: str

class AutonomousSecurityAgent:
    """7-state autonomous security testing agent with self-directed capabilities"""
    
    def __init__(self):
        self.current_state = AgentState.RECONNAISSANCE
        self.memory = AgentMemory()
        self.state_transitions = {
            AgentState.RECONNAISSANCE: [AgentState.ENUMERATION, AgentState.VULNERABILITY_DISCOVERY],
            AgentState.ENUMERATION: [AgentState.VULNERABILITY_DISCOVERY, AgentState.EXPLOITATION],
            AgentState.VULNERABILITY_DISCOVERY: [AgentState.EXPLOITATION, AgentState.ENUMERATION],
            AgentState.EXPLOITATION: [AgentState.POST_EXPLOITATION, AgentState.VULNERABILITY_DISCOVERY],
            AgentState.POST_EXPLOITATION: [AgentState.PERSISTENCE, AgentState.REPORTING],
            AgentState.PERSISTENCE: [AgentState.REPORTING, AgentState.ENUMERATION],
            AgentState.REPORTING: [AgentState.RECONNAISSANCE]
        }
        self.mission_objectives = []
        self.current_target = None
        self.learning_rate = 0.1
    
    async def execute_autonomous_mission(self, target: str, objectives: List[str]) -> Dict[str, Any]:
        """Execute autonomous security testing mission"""
        self.current_target = target
        self.mission_objectives = objectives
        mission_results = {
            'target': target,
            'objectives': objectives,
            'states_executed': [],
            'discoveries': [],
            'exploitations': [],
            'recommendations': [],
            'mission_success': False
        }
        
        # Execute mission through state transitions
        max_iterations = 20
        iteration = 0
        
        while iteration < max_iterations and not self._mission_complete():
            state_result = await self._execute_current_state()
            mission_results['states_executed'].append({
                'state': self.current_state.value,
                'result': state_result,
                'timestamp': time.time()
            })
            
            # Learn from results
            self._update_memory(state_result)
            
            # Decide next state
            next_state = self._decide_next_state()
            self.current_state = next_state
            
            iteration += 1
        
        # Compile final results
        mission_results['discoveries'] = self.memory.vulnerabilities
        mission_results['exploitations'] = self.memory.exploitation_results
        mission_results['recommendations'] = self._generate_recommendations()
        mission_results['mission_success'] = self._evaluate_mission_success()
        
        return mission_results
    
    async def _execute_current_state(self) -> Dict[str, Any]:
        """Execute actions for current agent state"""
        state_handlers = {
            AgentState.RECONNAISSANCE: self._execute_reconnaissance,
            AgentState.ENUMERATION: self._execute_enumeration,
            AgentState.VULNERABILITY_DISCOVERY: self._execute_vulnerability_discovery,
            AgentState.EXPLOITATION: self._execute_exploitation,
            AgentState.POST_EXPLOITATION: self._execute_post_exploitation,
            AgentState.PERSISTENCE: self._execute_persistence,
            AgentState.REPORTING: self._execute_reporting
        }
        
        handler = state_handlers.get(self.current_state)
        if handler:
            return await handler()
        
        return {'status': 'unknown_state', 'actions': []}
    
    async def _execute_reconnaissance(self) -> Dict[str, Any]:
        """Execute reconnaissance phase"""
        actions = []
        discoveries = []
        
        # Passive information gathering
        recon_techniques = [
            'subdomain_enumeration',
            'certificate_transparency',
            'dns_enumeration',
            'social_media_osint',
            'technology_fingerprinting'
        ]
        
        for technique in recon_techniques:
            if self._should_execute_technique(technique):
                result = await self._simulate_technique(technique)
                actions.append(result)
                if result['success']:
                    discoveries.extend(result.get('discoveries', []))
        
        # Update memory with discoveries
        self.memory.discovered_assets.extend(discoveries)
        
        return {
            'state': 'reconnaissance',
            'actions_taken': len(actions),
            'discoveries': discoveries,
            'success_rate': sum(1 for a in actions if a['success']) / len(actions) if actions else 0
        }
    
    async def _execute_enumeration(self) -> Dict[str, Any]:
        """Execute enumeration phase"""
        actions = []
        findings = []
        
        # Active enumeration techniques
        enum_techniques = [
            'port_scanning',
            'service_enumeration',
            'directory_bruteforcing',
            'parameter_discovery',
            'api_endpoint_enumeration'
        ]
        
        for technique in enum_techniques:
            if self._should_execute_technique(technique):
                result = await self._simulate_technique(technique)
                actions.append(result)
                if result['success']:
                    findings.extend(result.get('findings', []))
        
        return {
            'state': 'enumeration',
            'actions_taken': len(actions),
            'findings': findings,
            'attack_surface_expanded': len(findings) > 0
        }
    
    async def _execute_vulnerability_discovery(self) -> Dict[str, Any]:
        """Execute vulnerability discovery phase"""
        actions = []
        vulnerabilities = []
        
        # Vulnerability discovery techniques
        vuln_techniques = [
            'automated_scanning',
            'manual_testing',
            'fuzzing',
            'code_analysis',
            'configuration_review'
        ]
        
        for technique in vuln_techniques:
            if self._should_execute_technique(technique):
                result = await self._simulate_technique(technique)
                actions.append(result)
                if result['success']:
                    vulns = result.get('vulnerabilities', [])
                    vulnerabilities.extend(vulns)
                    self.memory.vulnerabilities.extend(vulns)
        
        return {
            'state': 'vulnerability_discovery',
            'actions_taken': len(actions),
            'vulnerabilities_found': len(vulnerabilities),
            'critical_vulns': len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        }
    
    async def _execute_exploitation(self) -> Dict[str, Any]:
        """Execute exploitation phase"""
        actions = []
        successful_exploits = []
        
        # Select vulnerabilities for exploitation
        exploitable_vulns = [v for v in self.memory.vulnerabilities 
                           if v.get('exploitable', False)]
        
        for vuln in exploitable_vulns[:3]:  # Limit to top 3
            exploit_result = await self._attempt_exploitation(vuln)
            actions.append(exploit_result)
            
            if exploit_result['success']:
                successful_exploits.append(exploit_result)
                self.memory.exploitation_results.append(exploit_result)
        
        return {
            'state': 'exploitation',
            'attempts': len(actions),
            'successful_exploits': len(successful_exploits),
            'compromise_level': self._assess_compromise_level(successful_exploits)
        }
    
    async def _execute_post_exploitation(self) -> Dict[str, Any]:
        """Execute post-exploitation phase"""
        actions = []
        
        if not self.memory.exploitation_results:
            return {'state': 'post_exploitation', 'actions_taken': 0, 'reason': 'no_successful_exploits'}
        
        # Post-exploitation activities
        post_exploit_activities = [
            'privilege_escalation',
            'lateral_movement',
            'data_exfiltration_test',
            'persistence_establishment',
            'evidence_collection'
        ]
        
        for activity in post_exploit_activities:
            if self._should_execute_technique(activity):
                result = await self._simulate_technique(activity)
                actions.append(result)
        
        return {
            'state': 'post_exploitation',
            'actions_taken': len(actions),
            'successful_actions': sum(1 for a in actions if a['success']),
            'impact_assessment': self._assess_impact()
        }
    
    async def _execute_persistence(self) -> Dict[str, Any]:
        """Execute persistence phase"""
        actions = []
        
        # Persistence techniques (for testing purposes only)
        persistence_techniques = [
            'scheduled_task_creation',
            'registry_modification',
            'service_installation',
            'startup_folder_placement'
        ]
        
        for technique in persistence_techniques:
            if self._should_execute_technique(technique) and self.memory.success_rate > 0.7:
                result = await self._simulate_technique(technique, safe_mode=True)
                actions.append(result)
        
        return {
            'state': 'persistence',
            'actions_taken': len(actions),
            'persistence_established': any(a['success'] for a in actions)
        }
    
    async def _execute_reporting(self) -> Dict[str, Any]:
        """Execute reporting phase"""
        report = {
            'state': 'reporting',
            'mission_summary': {
                'target': self.current_target,
                'objectives_met': self._count_objectives_met(),
                'vulnerabilities_found': len(self.memory.vulnerabilities),
                'successful_exploits': len(self.memory.exploitation_results),
                'overall_success_rate': self.memory.success_rate
            },
            'recommendations': self._generate_recommendations(),
            'lessons_learned': self._extract_lessons_learned()
        }
        
        return report
    
    def _decide_next_state(self) -> AgentState:
        """Decide next state based on current situation and learning"""
        possible_states = self.state_transitions.get(self.current_state, [])
        
        if not possible_states:
            return AgentState.REPORTING
        
        # Decision logic based on memory and confidence
        if self.current_state == AgentState.RECONNAISSANCE:
            return AgentState.ENUMERATION if self.memory.discovered_assets else AgentState.VULNERABILITY_DISCOVERY
        
        elif self.current_state == AgentState.ENUMERATION:
            return AgentState.VULNERABILITY_DISCOVERY
        
        elif self.current_state == AgentState.VULNERABILITY_DISCOVERY:
            return AgentState.EXPLOITATION if self.memory.vulnerabilities else AgentState.ENUMERATION
        
        elif self.current_state == AgentState.EXPLOITATION:
            return AgentState.POST_EXPLOITATION if self.memory.exploitation_results else AgentState.VULNERABILITY_DISCOVERY
        
        elif self.current_state == AgentState.POST_EXPLOITATION:
            return AgentState.PERSISTENCE if self.memory.success_rate > 0.8 else AgentState.REPORTING
        
        elif self.current_state == AgentState.PERSISTENCE:
            return AgentState.REPORTING
        
        else:  # REPORTING
            return AgentState.RECONNAISSANCE if len(self.memory.vulnerabilities) < 5 else AgentState.REPORTING
    
    def _should_execute_technique(self, technique: str) -> bool:
        """Decide whether to execute a technique based on learning"""
        # Base probability
        base_prob = 0.7
        
        # Adjust based on past success with this technique
        technique_success = self.memory.learned_patterns.get(technique, {}).get('success_rate', 0.5)
        adjusted_prob = base_prob * (0.5 + technique_success)
        
        # Adjust based on confidence level
        final_prob = adjusted_prob * self.memory.confidence_level
        
        return random.random() < final_prob
    
    async def _simulate_technique(self, technique: str, safe_mode: bool = True) -> Dict[str, Any]:
        """Simulate execution of a security technique"""
        # Simulate technique execution with random success
        success_probability = self.memory.learned_patterns.get(technique, {}).get('success_rate', 0.6)
        success = random.random() < success_probability
        
        result = {
            'technique': technique,
            'success': success,
            'timestamp': time.time(),
            'safe_mode': safe_mode
        }
        
        if success:
            # Generate simulated findings based on technique
            if 'enumeration' in technique or 'discovery' in technique:
                result['findings'] = [f"{technique}_finding_{i}" for i in range(random.randint(1, 3))]
            elif 'vulnerability' in technique:
                result['vulnerabilities'] = [{
                    'type': f"{technique}_vuln",
                    'severity': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                    'exploitable': random.random() > 0.5
                }]
            elif technique == 'subdomain_enumeration':
                result['discoveries'] = [f"sub{i}.{self.current_target}" for i in range(random.randint(2, 5))]
        
        return result
    
    async def _attempt_exploitation(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to exploit a vulnerability"""
        exploit_success_rate = {
            'CRITICAL': 0.8,
            'HIGH': 0.6,
            'MEDIUM': 0.4,
            'LOW': 0.2
        }
        
        severity = vulnerability.get('severity', 'LOW')
        success_prob = exploit_success_rate.get(severity, 0.3)
        success = random.random() < success_prob
        
        return {
            'vulnerability': vulnerability,
            'success': success,
            'impact': severity if success else 'NONE',
            'timestamp': time.time()
        }
    
    def _update_memory(self, state_result: Dict[str, Any]):
        """Update agent memory with learning from state execution"""
        # Update success rate
        if 'success_rate' in state_result:
            old_rate = self.memory.success_rate
            new_rate = state_result['success_rate']
            self.memory.success_rate = old_rate + self.learning_rate * (new_rate - old_rate)
        
        # Update confidence based on recent success
        recent_success = state_result.get('success_rate', 0.5)
        self.memory.confidence_level = min(1.0, self.memory.confidence_level + 0.1 * recent_success)
        
        # Learn technique patterns
        for action in state_result.get('actions', []):
            if isinstance(action, dict) and 'technique' in action:
                technique = action['technique']
                success = action.get('success', False)
                
                if technique not in self.memory.learned_patterns:
                    self.memory.learned_patterns[technique] = {'success_rate': 0.5, 'attempts': 0}
                
                pattern = self.memory.learned_patterns[technique]
                pattern['attempts'] += 1
                old_rate = pattern['success_rate']
                pattern['success_rate'] = old_rate + self.learning_rate * (float(success) - old_rate)
    
    def _mission_complete(self) -> bool:
        """Check if mission objectives are complete"""
        return len(self.memory.vulnerabilities) >= 5 or self.memory.success_rate > 0.9
    
    def _count_objectives_met(self) -> int:
        """Count how many mission objectives were met"""
        # Simplified objective counting
        objectives_met = 0
        if 'find_vulnerabilities' in self.mission_objectives and self.memory.vulnerabilities:
            objectives_met += 1
        if 'test_exploits' in self.mission_objectives and self.memory.exploitation_results:
            objectives_met += 1
        return objectives_met
    
    def _assess_compromise_level(self, exploits: List[Dict]) -> str:
        """Assess level of system compromise"""
        if not exploits:
            return 'NONE'
        
        critical_exploits = [e for e in exploits if e.get('impact') == 'CRITICAL']
        if critical_exploits:
            return 'CRITICAL'
        elif len(exploits) > 2:
            return 'HIGH'
        elif len(exploits) > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _assess_impact(self) -> str:
        """Assess overall impact of successful attacks"""
        if len(self.memory.exploitation_results) >= 3:
            return 'HIGH'
        elif len(self.memory.exploitation_results) >= 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if self.memory.vulnerabilities:
            recommendations.append("Implement vulnerability management program")
            recommendations.append("Conduct regular security assessments")
        
        if self.memory.exploitation_results:
            recommendations.append("Implement defense-in-depth security controls")
            recommendations.append("Enhance monitoring and incident response capabilities")
        
        if self.memory.success_rate > 0.7:
            recommendations.append("Critical security improvements needed immediately")
        
        return recommendations
    
    def _extract_lessons_learned(self) -> List[str]:
        """Extract lessons learned from the mission"""
        lessons = []
        
        # Analyze successful techniques
        successful_techniques = [t for t, data in self.memory.learned_patterns.items() 
                               if data['success_rate'] > 0.7]
        if successful_techniques:
            lessons.append(f"Most effective techniques: {', '.join(successful_techniques[:3])}")
        
        # Analyze overall performance
        if self.memory.success_rate > 0.8:
            lessons.append("High success rate indicates weak security posture")
        elif self.memory.success_rate < 0.3:
            lessons.append("Low success rate indicates strong security controls")
        
        return lessons
    
    def _evaluate_mission_success(self) -> bool:
        """Evaluate overall mission success"""
        return (len(self.memory.vulnerabilities) > 0 and 
                self.memory.success_rate > 0.5 and 
                self._count_objectives_met() > 0)