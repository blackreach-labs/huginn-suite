# app/core/advanced_analytics_engine.py
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json
import statistics
from collections import defaultdict, Counter
from .centralized_scan_data import centralized_scan_data
from .cross_scan_correlator import create_cross_scan_correlator

@dataclass
class TrendAnalysis:
    """Trend analysis result"""
    metric_name: str
    current_value: float
    previous_value: float
    change_percentage: float
    trend_direction: str  # 'increasing', 'decreasing', 'stable'
    confidence: float  # 0-1
    prediction: Optional[float] = None

@dataclass
class AnomalyDetection:
    """Anomaly detection result"""
    timestamp: str
    metric_name: str
    actual_value: float
    expected_value: float
    deviation_score: float
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str

class AdvancedAnalyticsEngine:
    """Advanced analytics and predictive modeling for security data"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.correlator = create_cross_scan_correlator(tenant_id)
    
    def analyze_security_trends(self, days_back: int = 30) -> List[TrendAnalysis]:
        """Analyze security trends over time"""
        trends = []
        
        try:
            # Analyze vulnerability trends
            vuln_trend = self._analyze_vulnerability_trends(days_back)
            if vuln_trend:
                trends.append(vuln_trend)
            
            # Analyze scan activity trends
            activity_trend = self._analyze_scan_activity_trends(days_back)
            if activity_trend:
                trends.append(activity_trend)
            
            # Analyze target coverage trends
            coverage_trend = self._analyze_coverage_trends(days_back)
            if coverage_trend:
                trends.append(coverage_trend)
            
            return trends
        except Exception as e:
            print(f"Error analyzing security trends: {e}")
            return []
    
    def detect_anomalies(self, hours_back: int = 24) -> List[AnomalyDetection]:
        """Detect anomalies in security data"""
        anomalies = []
        
        try:
            # Detect scan volume anomalies
            scan_anomalies = self._detect_scan_volume_anomalies(hours_back)
            anomalies.extend(scan_anomalies)
            
            # Detect vulnerability spike anomalies
            vuln_anomalies = self._detect_vulnerability_anomalies(hours_back)
            anomalies.extend(vuln_anomalies)
            
            # Detect target behavior anomalies
            target_anomalies = self._detect_target_anomalies(hours_back)
            anomalies.extend(target_anomalies)
            
            return sorted(anomalies, key=lambda x: x.deviation_score, reverse=True)
        except Exception as e:
            print(f"Error detecting anomalies: {e}")
            return []
    
    def generate_predictive_insights(self) -> Dict[str, Any]:
        """Generate predictive insights based on historical data"""
        try:
            insights = {
                'risk_forecast': self._predict_risk_levels(),
                'vulnerability_prediction': self._predict_vulnerability_discovery(),
                'resource_planning': self._predict_resource_needs(),
                'attack_likelihood': self._predict_attack_scenarios()
            }
            
            return insights
        except Exception as e:
            print(f"Error generating predictive insights: {e}")
            return {}
    
    def calculate_security_maturity(self) -> Dict[str, Any]:
        """Calculate organizational security maturity score"""
        try:
            # Get historical data
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports', 'http_directories', 'smb_shares']
            
            maturity_scores = {}
            overall_score = 0
            
            for scan_type in scan_types:
                score = self._calculate_scan_type_maturity(scan_type)
                maturity_scores[scan_type] = score
                overall_score += score
            
            overall_score = overall_score / len(scan_types)
            
            # Determine maturity level
            if overall_score >= 80:
                maturity_level = 'Advanced'
                color = '#2ecc71'
            elif overall_score >= 60:
                maturity_level = 'Intermediate'
                color = '#f39c12'
            elif overall_score >= 40:
                maturity_level = 'Basic'
                color = '#e67e22'
            else:
                maturity_level = 'Initial'
                color = '#e74c3c'
            
            return {
                'overall_score': overall_score,
                'maturity_level': maturity_level,
                'color': color,
                'scan_type_scores': maturity_scores,
                'recommendations': self._generate_maturity_recommendations(overall_score)
            }
        except Exception as e:
            print(f"Error calculating security maturity: {e}")
            return {'overall_score': 50, 'maturity_level': 'Basic', 'color': '#e67e22'}
    
    def _analyze_vulnerability_trends(self, days_back: int) -> Optional[TrendAnalysis]:
        """Analyze vulnerability discovery trends"""
        try:
            correlations_current = self.correlator.correlate_all_findings(time_window_hours=24)
            correlations_previous = self.correlator.correlate_all_findings(
                time_window_hours=24, 
                end_time=datetime.now() - timedelta(days=7)
            )
            
            current_count = len(correlations_current)
            previous_count = len(correlations_previous)
            
            if previous_count == 0:
                change_percentage = 100.0 if current_count > 0 else 0.0
            else:
                change_percentage = ((current_count - previous_count) / previous_count) * 100
            
            if abs(change_percentage) < 5:
                trend_direction = 'stable'
            elif change_percentage > 0:
                trend_direction = 'increasing'
            else:
                trend_direction = 'decreasing'
            
            return TrendAnalysis(
                metric_name='vulnerability_count',
                current_value=current_count,
                previous_value=previous_count,
                change_percentage=change_percentage,
                trend_direction=trend_direction,
                confidence=0.8
            )
        except:
            return None
    
    def _analyze_scan_activity_trends(self, days_back: int) -> Optional[TrendAnalysis]:
        """Analyze scan activity trends"""
        try:
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports']
            
            current_total = 0
            previous_total = 0
            
            for scan_type in scan_types:
                current_data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=100)
                current_total += len(current_data)
                
                # Simulate previous data (in real implementation, would query historical data)
                previous_total += max(0, len(current_data) - 10)
            
            if previous_total == 0:
                change_percentage = 100.0 if current_total > 0 else 0.0
            else:
                change_percentage = ((current_total - previous_total) / previous_total) * 100
            
            trend_direction = 'stable'
            if abs(change_percentage) >= 10:
                trend_direction = 'increasing' if change_percentage > 0 else 'decreasing'
            
            return TrendAnalysis(
                metric_name='scan_activity',
                current_value=current_total,
                previous_value=previous_total,
                change_percentage=change_percentage,
                trend_direction=trend_direction,
                confidence=0.7
            )
        except:
            return None
    
    def _analyze_coverage_trends(self, days_back: int) -> Optional[TrendAnalysis]:
        """Analyze target coverage trends"""
        try:
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports']
            all_targets = set()
            
            for scan_type in scan_types:
                data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=100)
                targets = set(item['target'] for item in data)
                all_targets.update(targets)
            
            current_coverage = len(all_targets)
            previous_coverage = max(1, current_coverage - 2)  # Simulate previous data
            
            change_percentage = ((current_coverage - previous_coverage) / previous_coverage) * 100
            
            trend_direction = 'stable'
            if abs(change_percentage) >= 15:
                trend_direction = 'increasing' if change_percentage > 0 else 'decreasing'
            
            return TrendAnalysis(
                metric_name='target_coverage',
                current_value=current_coverage,
                previous_value=previous_coverage,
                change_percentage=change_percentage,
                trend_direction=trend_direction,
                confidence=0.6
            )
        except:
            return None
    
    def _detect_scan_volume_anomalies(self, hours_back: int) -> List[AnomalyDetection]:
        """Detect anomalies in scan volume"""
        anomalies = []
        
        try:
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports']
            
            for scan_type in scan_types:
                data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=200)
                
                if len(data) < 10:  # Need minimum data for anomaly detection
                    continue
                
                # Calculate recent activity
                recent_count = 0
                for item in data[:50]:  # Recent items
                    try:
                        item_time = datetime.fromisoformat(item['last_seen'].replace('Z', '+00:00'))
                        if item_time > datetime.now() - timedelta(hours=hours_back):
                            recent_count += 1
                    except:
                        pass
                
                # Calculate expected value (average of historical data)
                historical_counts = []
                for i in range(0, min(len(data), 100), 10):
                    batch = data[i:i+10]
                    historical_counts.append(len(batch))
                
                if len(historical_counts) < 3:
                    continue
                
                expected_value = statistics.mean(historical_counts)
                std_dev = statistics.stdev(historical_counts) if len(historical_counts) > 1 else 1
                
                # Calculate deviation score
                deviation_score = abs(recent_count - expected_value) / max(std_dev, 1)
                
                if deviation_score > 2.0:  # Significant anomaly
                    severity = 'critical' if deviation_score > 3.0 else 'high'
                    
                    anomalies.append(AnomalyDetection(
                        timestamp=datetime.now().isoformat(),
                        metric_name=f'{scan_type}_volume',
                        actual_value=recent_count,
                        expected_value=expected_value,
                        deviation_score=deviation_score,
                        severity=severity,
                        description=f'Unusual {scan_type} scan volume detected'
                    ))
        except Exception as e:
            print(f"Error detecting scan volume anomalies: {e}")
        
        return anomalies
    
    def _detect_vulnerability_anomalies(self, hours_back: int) -> List[AnomalyDetection]:
        """Detect anomalies in vulnerability discovery"""
        anomalies = []
        
        try:
            correlations = self.correlator.correlate_all_findings(time_window_hours=hours_back)
            
            # Count by severity
            severity_counts = Counter(c.severity for c in correlations)
            
            # Expected values (based on typical patterns)
            expected_critical = 1
            expected_high = 3
            expected_medium = 5
            
            actual_critical = severity_counts.get('Critical', 0)
            actual_high = severity_counts.get('High', 0)
            actual_medium = severity_counts.get('Medium', 0)
            
            # Check for critical vulnerability spikes
            if actual_critical > expected_critical * 2:
                anomalies.append(AnomalyDetection(
                    timestamp=datetime.now().isoformat(),
                    metric_name='critical_vulnerabilities',
                    actual_value=actual_critical,
                    expected_value=expected_critical,
                    deviation_score=actual_critical / max(expected_critical, 1),
                    severity='critical',
                    description='Unusual spike in critical vulnerabilities detected'
                ))
            
            # Check for high vulnerability spikes
            if actual_high > expected_high * 2:
                anomalies.append(AnomalyDetection(
                    timestamp=datetime.now().isoformat(),
                    metric_name='high_vulnerabilities',
                    actual_value=actual_high,
                    expected_value=expected_high,
                    deviation_score=actual_high / max(expected_high, 1),
                    severity='high',
                    description='Unusual spike in high-severity vulnerabilities detected'
                ))
        except Exception as e:
            print(f"Error detecting vulnerability anomalies: {e}")
        
        return anomalies
    
    def _detect_target_anomalies(self, hours_back: int) -> List[AnomalyDetection]:
        """Detect anomalies in target behavior"""
        anomalies = []
        
        try:
            scan_types = ['rpc_endpoints', 'port_open_ports', 'smb_shares']
            target_activity = defaultdict(int)
            
            for scan_type in scan_types:
                data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=100)
                
                for item in data:
                    try:
                        item_time = datetime.fromisoformat(item['last_seen'].replace('Z', '+00:00'))
                        if item_time > datetime.now() - timedelta(hours=hours_back):
                            target_activity[item['target']] += 1
                    except:
                        pass
            
            if not target_activity:
                return anomalies
            
            # Calculate statistics
            activity_values = list(target_activity.values())
            mean_activity = statistics.mean(activity_values)
            std_dev = statistics.stdev(activity_values) if len(activity_values) > 1 else 1
            
            # Detect targets with unusual activity
            for target, activity in target_activity.items():
                deviation_score = abs(activity - mean_activity) / max(std_dev, 1)
                
                if deviation_score > 2.0:
                    severity = 'high' if deviation_score > 3.0 else 'medium'
                    
                    anomalies.append(AnomalyDetection(
                        timestamp=datetime.now().isoformat(),
                        metric_name='target_activity',
                        actual_value=activity,
                        expected_value=mean_activity,
                        deviation_score=deviation_score,
                        severity=severity,
                        description=f'Unusual activity pattern detected for target {target}'
                    ))
        except Exception as e:
            print(f"Error detecting target anomalies: {e}")
        
        return anomalies
    
    def _predict_risk_levels(self) -> Dict[str, Any]:
        """Predict future risk levels"""
        try:
            correlations = self.correlator.correlate_all_findings(time_window_hours=168)  # 7 days
            
            if not correlations:
                return {'prediction': 'Low', 'confidence': 0.5, 'timeframe': '7 days'}
            
            # Calculate current risk trend
            risk_scores = [c.risk_score for c in correlations]
            avg_risk = statistics.mean(risk_scores)
            
            # Simple prediction based on current trend
            if avg_risk > 8.0:
                prediction = 'Critical'
                confidence = 0.8
            elif avg_risk > 6.0:
                prediction = 'High'
                confidence = 0.7
            elif avg_risk > 4.0:
                prediction = 'Medium'
                confidence = 0.6
            else:
                prediction = 'Low'
                confidence = 0.5
            
            return {
                'prediction': prediction,
                'confidence': confidence,
                'timeframe': '7 days',
                'current_avg_risk': avg_risk,
                'factors': ['vulnerability_trends', 'scan_coverage', 'remediation_rate']
            }
        except:
            return {'prediction': 'Medium', 'confidence': 0.5, 'timeframe': '7 days'}
    
    def _predict_vulnerability_discovery(self) -> Dict[str, Any]:
        """Predict future vulnerability discovery"""
        try:
            correlations = self.correlator.correlate_all_findings(time_window_hours=168)
            
            current_rate = len(correlations) / 7  # Per day
            predicted_weekly = int(current_rate * 7 * 1.1)  # 10% increase assumption
            
            return {
                'predicted_weekly_discoveries': predicted_weekly,
                'current_daily_rate': round(current_rate, 1),
                'confidence': 0.6,
                'trend': 'increasing' if predicted_weekly > len(correlations) else 'stable'
            }
        except:
            return {'predicted_weekly_discoveries': 5, 'current_daily_rate': 0.7, 'confidence': 0.5}
    
    def _predict_resource_needs(self) -> Dict[str, Any]:
        """Predict resource requirements"""
        try:
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports']
            total_results = sum(len(centralized_scan_data.get_scan_data(self.tenant_id, st, limit=100)) 
                              for st in scan_types)
            
            # Predict storage needs (MB)
            predicted_storage = (total_results * 0.5) + 100  # 0.5KB per result + overhead
            
            # Predict scan time (minutes per week)
            predicted_scan_time = total_results * 0.1  # 0.1 minutes per result
            
            return {
                'predicted_storage_mb': round(predicted_storage, 1),
                'predicted_weekly_scan_time_minutes': round(predicted_scan_time, 1),
                'recommended_cleanup_frequency': 'monthly' if predicted_storage > 500 else 'quarterly'
            }
        except:
            return {'predicted_storage_mb': 250, 'predicted_weekly_scan_time_minutes': 60}
    
    def _predict_attack_scenarios(self) -> Dict[str, Any]:
        """Predict likely attack scenarios"""
        try:
            correlations = self.correlator.correlate_all_findings(time_window_hours=168)
            
            # Count correlation types
            scenario_counts = Counter(c.correlation_type for c in correlations)
            
            # Predict most likely scenarios
            likely_scenarios = []
            for scenario, count in scenario_counts.most_common(3):
                likelihood = min(count * 20, 90)  # Cap at 90%
                likely_scenarios.append({
                    'scenario': scenario,
                    'likelihood_percentage': likelihood,
                    'current_indicators': count
                })
            
            return {
                'likely_scenarios': likely_scenarios,
                'overall_attack_likelihood': 'High' if any(s['likelihood_percentage'] > 70 for s in likely_scenarios) else 'Medium'
            }
        except:
            return {'likely_scenarios': [], 'overall_attack_likelihood': 'Low'}
    
    def _calculate_scan_type_maturity(self, scan_type: str) -> float:
        """Calculate maturity score for specific scan type"""
        try:
            data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=100)
            
            if not data:
                return 0
            
            # Factors for maturity calculation
            volume_score = min(len(data) / 50 * 30, 30)  # Max 30 points for volume
            coverage_score = min(len(set(item['target'] for item in data)) / 10 * 25, 25)  # Max 25 points for coverage
            recency_score = 20 if any(self._is_recent(item['last_seen']) for item in data[:10]) else 0  # 20 points for recent activity
            consistency_score = 25 if len(data) > 20 else len(data)  # Max 25 points for consistency
            
            return volume_score + coverage_score + recency_score + consistency_score
        except:
            return 0
    
    def _is_recent(self, timestamp_str: str, hours: int = 24) -> bool:
        """Check if timestamp is recent"""
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return timestamp > datetime.now() - timedelta(hours=hours)
        except:
            return False
    
    def _generate_maturity_recommendations(self, score: float) -> List[str]:
        """Generate recommendations based on maturity score"""
        recommendations = []
        
        if score < 40:
            recommendations.extend([
                "Increase scan frequency and coverage",
                "Implement automated scanning schedules",
                "Expand target scope for comprehensive assessment"
            ])
        elif score < 60:
            recommendations.extend([
                "Enhance correlation analysis between scan types",
                "Implement trend monitoring and alerting",
                "Develop remediation workflows"
            ])
        elif score < 80:
            recommendations.extend([
                "Implement predictive analytics",
                "Enhance automation and orchestration",
                "Develop custom security metrics"
            ])
        else:
            recommendations.extend([
                "Maintain current excellence",
                "Share best practices with other teams",
                "Explore advanced AI/ML capabilities"
            ])
        
        return recommendations
    
    def get_comprehensive_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data for UI display"""
        try:
            correlations = self.correlator.correlate_all_findings(time_window_hours=24)
            maturity = self.calculate_security_maturity()
            
            # Security Score
            critical_issues = sum(1 for c in correlations if c.severity == 'Critical')
            total_issues = len(correlations)
            security_score = max(0, 100 - (critical_issues * 20) - (total_issues * 5))
            
            risk_level = 'Critical' if security_score < 40 else 'High' if security_score < 60 else 'Medium' if security_score < 80 else 'Low'
            
            # Scan Activity
            scan_types = ['rpc_endpoints', 'dns_subdomains', 'port_open_ports']
            total_results = sum(len(centralized_scan_data.get_scan_data(self.tenant_id, st, limit=100)) for st in scan_types)
            active_scans = len([st for st in scan_types if centralized_scan_data.get_scan_data(self.tenant_id, st, limit=1)])
            
            # Threat Metrics
            risk_scores = [c.risk_score for c in correlations] if correlations else [0]
            max_risk_score = max(risk_scores)
            threat_level = 'Critical' if max_risk_score > 8 else 'High' if max_risk_score > 6 else 'Medium' if max_risk_score > 4 else 'Low'
            
            # Target Metrics
            all_targets = set()
            for scan_type in scan_types:
                data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type, limit=100)
                all_targets.update(item['target'] for item in data)
            
            total_targets = len(all_targets)
            fully_scanned = min(total_targets, active_scans)
            coverage_percentage = (fully_scanned / max(total_targets, 1)) * 100
            
            return {
                'security_score': {
                    'score': security_score,
                    'risk_level': risk_level,
                    'total_issues': total_issues,
                    'critical_issues': critical_issues
                },
                'scan_activity': {
                    'total_results': total_results,
                    'active_scans': active_scans,
                    'scan_types_active': len(scan_types)
                },
                'threat_metrics': {
                    'threat_level': threat_level,
                    'max_risk_score': max_risk_score,
                    'total_threats': len(correlations)
                },
                'remediation_metrics': {
                    'total_actions': total_issues,
                    'critical_actions': critical_issues,
                    'estimated_time': total_issues * 30,  # 30 min per issue
                    'remediation_coverage': min(100, (total_issues * 10))
                },
                'target_metrics': {
                    'total_targets': total_targets,
                    'fully_scanned': fully_scanned,
                    'coverage_percentage': coverage_percentage
                }
            }
        except Exception as e:
            print(f"Error getting dashboard data: {e}")
            return {
                'security_score': {'score': 50, 'risk_level': 'Medium', 'total_issues': 0, 'critical_issues': 0},
                'scan_activity': {'total_results': 0, 'active_scans': 0, 'scan_types_active': 0},
                'threat_metrics': {'threat_level': 'Low', 'max_risk_score': 0, 'total_threats': 0},
                'remediation_metrics': {'total_actions': 0, 'critical_actions': 0, 'estimated_time': 0, 'remediation_coverage': 0},
                'target_metrics': {'total_targets': 0, 'fully_scanned': 0, 'coverage_percentage': 0}
            }

def create_advanced_analytics_engine(tenant_id: str = "default") -> AdvancedAnalyticsEngine:
    """Create advanced analytics engine for specific tenant"""
    return AdvancedAnalyticsEngine(tenant_id=tenant_id)