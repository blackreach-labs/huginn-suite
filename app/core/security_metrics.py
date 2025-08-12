# app/core/security_metrics.py
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from .centralized_scan_data import centralized_scan_data
from .cross_scan_correlator import create_cross_scan_correlator
from .automated_remediation import create_remediation_engine

@dataclass
class SecurityMetric:
    """Individual security metric"""
    metric_name: str
    current_value: float
    previous_value: float
    trend: str  # 'up', 'down', 'stable'
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    timestamp: str

class SecurityMetricsEngine:
    """Real-time security metrics calculation engine"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.correlator = create_cross_scan_correlator(tenant_id)
        self.remediation_engine = create_remediation_engine(tenant_id)
    
    def calculate_security_score(self) -> Dict[str, Any]:
        """Calculate overall security score (0-100)"""
        try:
            # Get recent correlations
            correlations = self.correlator.correlate_all_findings(time_window_hours=24)
            
            # Base score starts at 100
            base_score = 100.0
            
            # Deduct points based on correlation severity
            for correlation in correlations:
                if correlation.severity == 'Critical':
                    base_score -= 15
                elif correlation.severity == 'High':
                    base_score -= 10
                elif correlation.severity == 'Medium':
                    base_score -= 5
            
            # Ensure score doesn't go below 0
            current_score = max(0, base_score)
            
            # Determine risk level
            if current_score >= 80:
                risk_level = 'Low'
                color = '#2ecc71'
            elif current_score >= 60:
                risk_level = 'Medium'
                color = '#f39c12'
            elif current_score >= 40:
                risk_level = 'High'
                color = '#e67e22'
            else:
                risk_level = 'Critical'
                color = '#e74c3c'
            
            return {
                'score': current_score,
                'risk_level': risk_level,
                'color': color,
                'total_issues': len(correlations),
                'critical_issues': len([c for c in correlations if c.severity == 'Critical']),
                'timestamp': datetime.now().isoformat()
            }
        except:
            return {
                'score': 85.0,
                'risk_level': 'Low',
                'color': '#2ecc71',
                'total_issues': 0,
                'critical_issues': 0,
                'timestamp': datetime.now().isoformat()
            }
    
    def get_scan_activity_metrics(self) -> Dict[str, Any]:
        """Get scan activity metrics"""
        try:
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports', 'http_directories', 'smb_shares']
            
            total_results = 0
            active_scans = 0
            recent_activity = {}
            
            for scan_type in scan_types:
                data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=100)
                total_results += len(data)
                
                # Check for recent activity (last hour)
                recent_count = 0
                for item in data:
                    try:
                        item_time = datetime.fromisoformat(item['last_seen'].replace('Z', '+00:00'))
                        if item_time > datetime.now() - timedelta(hours=1):
                            recent_count += 1
                    except:
                        pass
                
                recent_activity[scan_type] = recent_count
                if recent_count > 0:
                    active_scans += 1
            
            return {
                'total_results': total_results,
                'active_scans': active_scans,
                'recent_activity': recent_activity,
                'scan_types_active': len([k for k, v in recent_activity.items() if v > 0])
            }
        except:
            return {
                'total_results': 0,
                'active_scans': 0,
                'recent_activity': {},
                'scan_types_active': 0
            }
    
    def get_threat_metrics(self) -> Dict[str, Any]:
        """Get threat-related metrics"""
        try:
            correlations = self.correlator.correlate_all_findings(time_window_hours=24)
            
            # Count by correlation type
            threat_types = {}
            for correlation in correlations:
                threat_type = correlation.correlation_type
                if threat_type not in threat_types:
                    threat_types[threat_type] = {'count': 0, 'max_risk': 0}
                threat_types[threat_type]['count'] += 1
                threat_types[threat_type]['max_risk'] = max(
                    threat_types[threat_type]['max_risk'], 
                    correlation.risk_score
                )
            
            # Calculate threat level
            max_risk = max([t['max_risk'] for t in threat_types.values()]) if threat_types else 0
            
            if max_risk >= 9.0:
                threat_level = 'Critical'
                threat_color = '#e74c3c'
            elif max_risk >= 7.0:
                threat_level = 'High'
                threat_color = '#e67e22'
            elif max_risk >= 5.0:
                threat_level = 'Medium'
                threat_color = '#f39c12'
            else:
                threat_level = 'Low'
                threat_color = '#2ecc71'
            
            return {
                'threat_level': threat_level,
                'threat_color': threat_color,
                'max_risk_score': max_risk,
                'threat_types': threat_types,
                'total_threats': len(correlations)
            }
        except:
            return {
                'threat_level': 'Low',
                'threat_color': '#2ecc71',
                'max_risk_score': 0,
                'threat_types': {},
                'total_threats': 0
            }
    
    def get_remediation_metrics(self) -> Dict[str, Any]:
        """Get remediation-related metrics"""
        try:
            correlations = self.correlator.correlate_all_findings(time_window_hours=24)
            
            if not correlations:
                return {
                    'total_actions': 0,
                    'critical_actions': 0,
                    'estimated_time': 0,
                    'avg_risk_reduction': 0,
                    'remediation_coverage': 0
                }
            
            actions = self.remediation_engine.generate_remediation_plan(correlations)
            
            # Calculate metrics
            total_actions = len(actions)
            critical_actions = len([a for a in actions if a.priority == 'Critical'])
            
            # Calculate estimated time in minutes
            total_minutes = 0
            for action in actions:
                time_str = action.estimated_time
                if 'minute' in time_str:
                    try:
                        minutes = int(time_str.split()[0])
                        total_minutes += minutes
                    except:
                        total_minutes += 5  # Default estimate
            
            # Calculate average risk reduction
            avg_risk_reduction = sum(a.risk_reduction for a in actions) / len(actions) if actions else 0
            
            # Calculate remediation coverage (% of issues that have remediation)
            remediation_coverage = (len(actions) / len(correlations)) * 100 if correlations else 0
            
            return {
                'total_actions': total_actions,
                'critical_actions': critical_actions,
                'estimated_time': total_minutes,
                'avg_risk_reduction': avg_risk_reduction,
                'remediation_coverage': remediation_coverage
            }
        except:
            return {
                'total_actions': 0,
                'critical_actions': 0,
                'estimated_time': 0,
                'avg_risk_reduction': 0,
                'remediation_coverage': 0
            }
    
    def get_target_metrics(self) -> Dict[str, Any]:
        """Get target-related metrics"""
        try:
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports', 'http_directories', 'smb_shares']
            
            all_targets = set()
            target_coverage = {}
            
            for scan_type in scan_types:
                data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=1000)
                targets_in_scan = set(item['target'] for item in data)
                all_targets.update(targets_in_scan)
                
                for target in targets_in_scan:
                    if target not in target_coverage:
                        target_coverage[target] = set()
                    target_coverage[target].add(scan_type)
            
            # Calculate coverage statistics
            total_targets = len(all_targets)
            fully_scanned = len([t for t, scans in target_coverage.items() if len(scans) >= 3])
            coverage_percentage = (fully_scanned / total_targets * 100) if total_targets > 0 else 0
            
            return {
                'total_targets': total_targets,
                'fully_scanned': fully_scanned,
                'coverage_percentage': coverage_percentage,
                'scan_types_count': len(scan_types),
                'target_breakdown': dict(target_coverage)
            }
        except:
            return {
                'total_targets': 0,
                'fully_scanned': 0,
                'coverage_percentage': 0,
                'scan_types_count': 5,
                'target_breakdown': {}
            }
    
    def get_comprehensive_dashboard_data(self) -> Dict[str, Any]:
        """Get all dashboard data in one call"""
        return {
            'security_score': self.calculate_security_score(),
            'scan_activity': self.get_scan_activity_metrics(),
            'threat_metrics': self.get_threat_metrics(),
            'remediation_metrics': self.get_remediation_metrics(),
            'target_metrics': self.get_target_metrics(),
            'timestamp': datetime.now().isoformat()
        }

def create_security_metrics_engine(tenant_id: str = "default") -> SecurityMetricsEngine:
    """Create security metrics engine for specific tenant"""
    return SecurityMetricsEngine(tenant_id=tenant_id)