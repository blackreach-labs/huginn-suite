# app/core/intelligent_scan_orchestrator.py
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import asyncio
import json
from enum import Enum
from .centralized_scan_data import centralized_scan_data
from .advanced_analytics_engine import create_advanced_analytics_engine
from .cross_scan_correlator import create_cross_scan_correlator
from app.core.logger import logger

class ScanPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class IntelligentScanTask:
    """Intelligent scan task with AI-driven prioritization"""
    task_id: str
    scan_type: str
    target: str
    priority: ScanPriority
    estimated_duration: int  # minutes
    dependencies: List[str]  # task_ids this depends on
    ai_reasoning: str
    confidence_score: float  # 0-1
    created_at: str
    scheduled_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: ScanStatus = ScanStatus.PENDING
    results: Optional[Dict] = None
    error_message: Optional[str] = None

@dataclass
class ScanRecommendation:
    """AI-generated scan recommendation"""
    recommended_scan: str
    target: str
    reasoning: str
    confidence: float
    priority: ScanPriority
    estimated_value: float  # Expected security value (0-10)

class IntelligentScanOrchestrator:
    """AI-powered scan orchestration and prioritization engine"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.analytics_engine = create_advanced_analytics_engine(tenant_id)
        self.correlator = create_cross_scan_correlator(tenant_id)
        self.active_tasks: Dict[str, IntelligentScanTask] = {}
        self.task_queue: List[IntelligentScanTask] = []
        self.max_concurrent_scans = 3
        self.running_scans = 0
    
    def analyze_scan_needs(self) -> List[ScanRecommendation]:
        """Analyze current security posture and recommend scans"""
        recommendations = []
        
        try:
            # Get current scan data
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports', 'http_directories', 'smb_shares']
            
            # Analyze coverage gaps
            coverage_recs = self._analyze_coverage_gaps(scan_types)
            recommendations.extend(coverage_recs)
            
            # Analyze correlation-based recommendations
            correlation_recs = self._analyze_correlation_needs()
            recommendations.extend(correlation_recs)
            
            # Analyze temporal patterns
            temporal_recs = self._analyze_temporal_patterns()
            recommendations.extend(temporal_recs)
            
            # Analyze threat intelligence
            threat_recs = self._analyze_threat_intelligence()
            recommendations.extend(threat_recs)
            
            # Sort by priority and confidence
            recommendations.sort(key=lambda x: (x.priority.value, -x.confidence, -x.estimated_value))
            
            return recommendations[:10]  # Top 10 recommendations
        
        except Exception as e:
            print(f"Error analyzing scan needs: {e}")
            return []
    
    def create_intelligent_scan_plan(self, targets: List[str], 
                                   time_budget_hours: int = 8) -> List[IntelligentScanTask]:
        """Create an intelligent scan plan based on AI analysis"""
        try:
            recommendations = self.analyze_scan_needs()
            
            # Filter recommendations for specified targets
            if targets:
                recommendations = [r for r in recommendations if r.target in targets or any(t in r.target for t in targets)]
            
            tasks = []
            total_time_minutes = 0
            time_budget_minutes = time_budget_hours * 60
            
            for i, rec in enumerate(recommendations):
                if total_time_minutes >= time_budget_minutes:
                    break
                
                # Estimate scan duration based on scan type and target
                duration = self._estimate_scan_duration(rec.recommended_scan, rec.target)
                
                if total_time_minutes + duration > time_budget_minutes:
                    continue
                
                # Create intelligent scan task
                task = IntelligentScanTask(
                    task_id=f"intelligent_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{i}",
                    scan_type=rec.recommended_scan,
                    target=rec.target,
                    priority=rec.priority,
                    estimated_duration=duration,
                    dependencies=self._calculate_dependencies(rec.recommended_scan, tasks),
                    ai_reasoning=rec.reasoning,
                    confidence_score=rec.confidence,
                    created_at=datetime.now().isoformat()
                )
                
                tasks.append(task)
                total_time_minutes += duration
            
            # Optimize task order based on dependencies and priorities
            optimized_tasks = self._optimize_task_order(tasks)
            
            return optimized_tasks
        
        except Exception as e:
            print(f"Error creating intelligent scan plan: {e}")
            return []
    
    def execute_intelligent_scan_plan(self, tasks: List[IntelligentScanTask]) -> Dict[str, Any]:
        """Execute intelligent scan plan with real-time optimization"""
        try:
            # Add tasks to queue
            self.task_queue.extend(tasks)
            
            # Start execution
            execution_results = {
                'plan_id': f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'total_tasks': len(tasks),
                'started_at': datetime.now().isoformat(),
                'status': 'running',
                'completed_tasks': 0,
                'failed_tasks': 0,
                'estimated_completion': self._calculate_estimated_completion(tasks)
            }
            
            # Process tasks (simplified synchronous version)
            for task in tasks:
                if self._can_execute_task(task):
                    result = self._execute_single_task(task)
                    execution_results['completed_tasks'] += 1 if result['success'] else 0
                    execution_results['failed_tasks'] += 0 if result['success'] else 1
            
            execution_results['status'] = 'completed'
            execution_results['completed_at'] = datetime.now().isoformat()
            
            return execution_results
        
        except Exception as e:
            print(f"Error executing intelligent scan plan: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def get_real_time_recommendations(self) -> Dict[str, Any]:
        """Get real-time scan recommendations based on current state"""
        try:
            # Analyze current security posture
            security_score = self.analytics_engine.calculate_security_score()
            anomalies = self.analytics_engine.detect_anomalies(hours_back=6)
            correlations = self.correlator.correlate_all_findings(time_window_hours=12)
            
            # Generate immediate recommendations
            immediate_recs = []
            
            # Critical security score recommendations
            if security_score['score'] < 60:
                immediate_recs.append({
                    'type': 'urgent_scan',
                    'recommendation': 'Immediate comprehensive vulnerability scan recommended',
                    'reasoning': f"Security score is {security_score['score']:.0f}/100 (below acceptable threshold)",
                    'priority': 'critical',
                    'estimated_impact': 'high'
                })
            
            # Anomaly-based recommendations
            critical_anomalies = [a for a in anomalies if a.severity in ['critical', 'high']]
            if critical_anomalies:
                immediate_recs.append({
                    'type': 'anomaly_investigation',
                    'recommendation': f'Investigate {len(critical_anomalies)} critical anomalies detected',
                    'reasoning': 'Unusual patterns detected that may indicate security issues',
                    'priority': 'high',
                    'estimated_impact': 'medium'
                })
            
            # Correlation-based recommendations
            high_risk_correlations = [c for c in correlations if c.risk_score >= 8.0]
            if high_risk_correlations:
                immediate_recs.append({
                    'type': 'correlation_deep_dive',
                    'recommendation': f'Deep dive analysis of {len(high_risk_correlations)} high-risk attack paths',
                    'reasoning': 'Multiple vulnerabilities create exploitable attack chains',
                    'priority': 'high',
                    'estimated_impact': 'high'
                })
            
            return {
                'timestamp': datetime.now().isoformat(),
                'security_score': security_score,
                'immediate_recommendations': immediate_recs,
                'total_anomalies': len(anomalies),
                'total_correlations': len(correlations),
                'recommended_action': self._determine_recommended_action(security_score, anomalies, correlations)
            }
        
        except Exception as e:
            print(f"Error getting real-time recommendations: {e}")
            return {}
    
    def _analyze_coverage_gaps(self, scan_types: List[str]) -> List[ScanRecommendation]:
        """Analyze coverage gaps and recommend scans"""
        recommendations = []
        
        try:
            # Get all targets across scan types
            all_targets = set()
            scan_coverage = {}
            
            for scan_type in scan_types:
                data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=100)
                targets = set(item['target'] for item in data)
                all_targets.update(targets)
                scan_coverage[scan_type] = targets
            
            # Find targets with incomplete coverage
            for target in all_targets:
                missing_scans = []
                for scan_type in scan_types:
                    if target not in scan_coverage.get(scan_type, set()):
                        missing_scans.append(scan_type)
                
                # Recommend missing scans with high priority for critical targets
                for missing_scan in missing_scans:
                    priority = ScanPriority.HIGH if len(missing_scans) > 2 else ScanPriority.MEDIUM
                    
                    recommendations.append(ScanRecommendation(
                        recommended_scan=missing_scan,
                        target=target,
                        reasoning=f"Coverage gap detected - {missing_scan} not performed on {target}",
                        confidence=0.8,
                        priority=priority,
                        estimated_value=7.0 if priority == ScanPriority.HIGH else 5.0
                    ))
            
            return recommendations[:5]  # Top 5 coverage recommendations
        
        except Exception as e:
            print(f"Error analyzing coverage gaps: {e}")
            return []
    
    def _analyze_correlation_needs(self) -> List[ScanRecommendation]:
        """Analyze correlations to recommend additional scans"""
        recommendations = []
        
        try:
            correlations = self.correlator.correlate_all_findings(time_window_hours=48)
            
            # Analyze correlation patterns to suggest additional scans
            for correlation in correlations:
                if correlation.risk_score >= 7.0:
                    # High-risk correlations suggest need for deeper scanning
                    target = correlation.primary_finding.get('target', 'unknown')
                    
                    # Recommend comprehensive scanning for high-risk targets
                    recommendations.append(ScanRecommendation(
                        recommended_scan='comprehensive_scan',
                        target=target,
                        reasoning=f"High-risk correlation detected ({correlation.correlation_type}) - deeper analysis needed",
                        confidence=0.9,
                        priority=ScanPriority.HIGH,
                        estimated_value=8.5
                    ))
            
            return recommendations[:3]  # Top 3 correlation-based recommendations
        
        except Exception as e:
            print(f"Error analyzing correlation needs: {e}")
            return []
    
    def _analyze_temporal_patterns(self) -> List[ScanRecommendation]:
        """Analyze temporal patterns to recommend scans"""
        recommendations = []
        
        try:
            # Analyze scan frequency patterns
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports']
            
            for scan_type in scan_types:
                data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=50)
                
                if not data:
                    continue
                
                # Check for stale data (older than 7 days)
                recent_data = []
                for item in data:
                    try:
                        item_time = datetime.fromisoformat(item['last_seen'].replace('Z', '+00:00'))
                        if item_time > datetime.now() - timedelta(days=7):
                            recent_data.append(item)
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
                
                # If less than 20% of data is recent, recommend refresh
                if len(recent_data) / len(data) < 0.2:
                    targets = list(set(item['target'] for item in data))[:3]  # Top 3 targets
                    
                    for target in targets:
                        recommendations.append(ScanRecommendation(
                            recommended_scan=scan_type,
                            target=target,
                            reasoning=f"Stale data detected - {scan_type} data is older than 7 days",
                            confidence=0.7,
                            priority=ScanPriority.MEDIUM,
                            estimated_value=6.0
                        ))
            
            return recommendations[:4]  # Top 4 temporal recommendations
        
        except Exception as e:
            print(f"Error analyzing temporal patterns: {e}")
            return []
    
    def _analyze_threat_intelligence(self) -> List[ScanRecommendation]:
        """Analyze threat intelligence to recommend targeted scans"""
        recommendations = []
        
        try:
            # Simulate threat intelligence analysis
            # In real implementation, this would integrate with threat feeds
            
            # Example: Recent RPC vulnerabilities suggest RPC scanning
            recommendations.append(ScanRecommendation(
                recommended_scan='rpc_endpoints',
                target='all_discovered_targets',
                reasoning='Recent threat intelligence indicates increased RPC-based attacks',
                confidence=0.6,
                priority=ScanPriority.MEDIUM,
                estimated_value=7.5
            ))
            
            # Example: DNS poisoning campaigns suggest DNS enumeration
            recommendations.append(ScanRecommendation(
                recommended_scan='dns_subdomains',
                target='primary_domains',
                reasoning='DNS-based attacks trending in threat landscape',
                confidence=0.5,
                priority=ScanPriority.LOW,
                estimated_value=5.5
            ))
            
            return recommendations
        
        except Exception as e:
            print(f"Error analyzing threat intelligence: {e}")
            return []
    
    def _estimate_scan_duration(self, scan_type: str, target: str) -> int:
        """Estimate scan duration in minutes"""
        # Base durations by scan type
        base_durations = {
            'rpc_endpoints': 15,
            'dns_subdomains': 10,
            'port_open_ports': 20,
            'http_directories': 25,
            'smb_shares': 12,
            'comprehensive_scan': 60
        }
        
        base_duration = base_durations.get(scan_type, 15)
        
        # Adjust based on target complexity (simplified)
        if 'all_' in target or 'multiple' in target:
            base_duration *= 3
        elif '/' in target:  # Network range
            base_duration *= 2
        
        return base_duration
    
    def _calculate_dependencies(self, scan_type: str, existing_tasks: List[IntelligentScanTask]) -> List[str]:
        """Calculate task dependencies"""
        dependencies = []
        
        # Define dependency rules
        dependency_rules = {
            'http_directories': ['port_open_ports'],  # HTTP enum depends on port scan
            'smb_shares': ['port_open_ports'],        # SMB enum depends on port scan
            'comprehensive_scan': ['rpc_endpoints', 'dns_subdomains', 'port_open_ports']
        }
        
        required_scans = dependency_rules.get(scan_type, [])
        
        for task in existing_tasks:
            if task.scan_type in required_scans:
                dependencies.append(task.task_id)
        
        return dependencies
    
    def _optimize_task_order(self, tasks: List[IntelligentScanTask]) -> List[IntelligentScanTask]:
        """Optimize task execution order based on dependencies and priorities"""
        # Simple topological sort with priority consideration
        optimized = []
        remaining = tasks.copy()
        
        while remaining:
            # Find tasks with no unmet dependencies
            ready_tasks = []
            for task in remaining:
                unmet_deps = [dep for dep in task.dependencies 
                             if not any(t.task_id == dep for t in optimized)]
                if not unmet_deps:
                    ready_tasks.append(task)
            
            if not ready_tasks:
                # Break circular dependencies by taking highest priority task
                ready_tasks = [max(remaining, key=lambda t: t.priority.value)]
            
            # Sort ready tasks by priority and confidence
            ready_tasks.sort(key=lambda t: (t.priority.value, -t.confidence_score))
            
            # Add highest priority ready task
            next_task = ready_tasks[0]
            optimized.append(next_task)
            remaining.remove(next_task)
        
        return optimized
    
    def _calculate_estimated_completion(self, tasks: List[IntelligentScanTask]) -> str:
        """Calculate estimated completion time"""
        total_duration = sum(task.estimated_duration for task in tasks)
        
        # Account for parallel execution
        parallel_duration = total_duration / self.max_concurrent_scans
        
        completion_time = datetime.now() + timedelta(minutes=parallel_duration)
        return completion_time.isoformat()
    
    def _can_execute_task(self, task: IntelligentScanTask) -> bool:
        """Check if task can be executed (dependencies met, resources available)"""
        # Check dependencies
        for dep_id in task.dependencies:
            if dep_id not in self.active_tasks or self.active_tasks[dep_id].status != ScanStatus.COMPLETED:
                return False
        
        # Check resource availability
        if self.running_scans >= self.max_concurrent_scans:
            return False
        
        return True
    
    def _execute_single_task(self, task: IntelligentScanTask) -> Dict[str, Any]:
        """Execute a single scan task (simplified implementation)"""
        try:
            task.status = ScanStatus.RUNNING
            task.started_at = datetime.now().isoformat()
            self.running_scans += 1
            
            # Simulate scan execution
            # In real implementation, this would call actual scan functions
            
            # Simulate success/failure
            import random
            success = random.random() > 0.1  # 90% success rate
            
            if success:
                task.status = ScanStatus.COMPLETED
                task.completed_at = datetime.now().isoformat()
                task.results = {'simulated': True, 'findings': random.randint(1, 10)}
            else:
                task.status = ScanStatus.FAILED
                task.error_message = "Simulated scan failure"
            
            self.active_tasks[task.task_id] = task
            self.running_scans -= 1
            
            return {'success': success, 'task_id': task.task_id}
        
        except Exception as e:
            task.status = ScanStatus.FAILED
            task.error_message = str(e)
            self.running_scans -= 1
            return {'success': False, 'error': str(e)}
    
    def _determine_recommended_action(self, security_score: Dict, anomalies: List, correlations: List) -> str:
        """Determine the recommended immediate action"""
        score = security_score.get('score', 50)
        critical_anomalies = len([a for a in anomalies if a.severity == 'critical'])
        high_risk_correlations = len([c for c in correlations if c.risk_score >= 8.0])
        
        if score < 40 or critical_anomalies > 2 or high_risk_correlations > 3:
            return "IMMEDIATE_ACTION_REQUIRED"
        elif score < 60 or critical_anomalies > 0 or high_risk_correlations > 1:
            return "ENHANCED_MONITORING"
        elif score < 80:
            return "ROUTINE_SCANNING"
        else:
            return "MAINTAIN_CURRENT_POSTURE"

def create_intelligent_scan_orchestrator(tenant_id: str = "default") -> IntelligentScanOrchestrator:
    """Create intelligent scan orchestrator for specific tenant"""
    return IntelligentScanOrchestrator(tenant_id=tenant_id)