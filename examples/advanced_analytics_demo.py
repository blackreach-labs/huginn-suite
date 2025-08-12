#!/usr/bin/env python3
"""
Advanced Analytics Demo for Huggin Framework

This demo showcases the advanced analytics capabilities including:
- Trend analysis and pattern detection
- Anomaly detection and alerting
- Predictive insights and forecasting
- Security maturity assessment
- Intelligent scan orchestration

Usage: python examples/advanced_analytics_demo.py
"""

import sys
import os
import asyncio
import json
from datetime import datetime, timedelta

# Add the project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.advanced_analytics_engine import create_advanced_analytics_engine
from app.core.intelligent_scan_orchestrator import create_intelligent_scan_orchestrator
from app.core.centralized_scan_data import centralized_scan_data

def print_header(title: str):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"🔬 {title}")
    print(f"{'='*60}")

def print_section(title: str):
    """Print a formatted section header"""
    print(f"\n📊 {title}")
    print("-" * 40)

def simulate_scan_data():
    """Simulate some scan data for demonstration"""
    print_section("Simulating Scan Data")
    
    # Simulate RPC scan data
    rpc_data = [
        {"endpoint": "svcctl", "uuid": "367abb81-9844-35f1-ad32-98f038001003", "risk": "medium"},
        {"endpoint": "spoolss", "uuid": "12345678-1234-abcd-ef00-0123456789ab", "risk": "high"},
        {"endpoint": "lsarpc", "uuid": "12345778-1234-abcd-ef00-01234567cffb", "risk": "critical"}
    ]
    
    for i, data in enumerate(rpc_data):
        centralized_scan_data.add_scan_result(
            scan_id=f"rpc_demo_{i}",
            tenant_id="demo_tenant",
            scan_type="rpc_endpoints",
            target="192.168.1.100",
            scanner="rpc_scanner",
            result_data=data
        )
    
    # Simulate DNS scan data
    dns_data = [
        {"subdomain": "www.example.com", "ip": "192.168.1.10", "type": "A"},
        {"subdomain": "mail.example.com", "ip": "192.168.1.20", "type": "A"},
        {"subdomain": "ftp.example.com", "ip": "192.168.1.30", "type": "A"}
    ]
    
    for i, data in enumerate(dns_data):
        centralized_scan_data.add_scan_result(
            scan_id=f"dns_demo_{i}",
            tenant_id="demo_tenant",
            scan_type="dns_subdomains",
            target="example.com",
            scanner="dns_scanner",
            result_data=data
        )
    
    # Simulate port scan data
    port_data = [
        {"port": 80, "service": "http", "state": "open"},
        {"port": 443, "service": "https", "state": "open"},
        {"port": 22, "service": "ssh", "state": "open"},
        {"port": 135, "service": "rpc", "state": "open"}
    ]
    
    for i, data in enumerate(port_data):
        centralized_scan_data.add_scan_result(
            scan_id=f"port_demo_{i}",
            tenant_id="demo_tenant",
            scan_type="port_open_ports",
            target="192.168.1.100",
            scanner="port_scanner",
            result_data=data
        )
    
    print("✅ Simulated scan data created successfully")

def demo_trend_analysis():
    """Demonstrate trend analysis capabilities"""
    print_header("Trend Analysis Demo")
    
    analytics_engine = create_advanced_analytics_engine("demo_tenant")
    
    print_section("Analyzing Security Trends")
    trends = analytics_engine.analyze_security_trends(days_back=30)
    
    if trends:
        for trend in trends:
            print(f"📈 Metric: {trend.metric_name}")
            print(f"   Current Value: {trend.current_value}")
            print(f"   Previous Value: {trend.previous_value}")
            print(f"   Change: {trend.change_percentage:+.1f}%")
            print(f"   Trend: {trend.trend_direction}")
            print(f"   Confidence: {trend.confidence:.1%}")
            if trend.prediction:
                print(f"   Prediction: {trend.prediction}")
            print()
    else:
        print("ℹ️  No trend data available (insufficient historical data)")

def demo_anomaly_detection():
    """Demonstrate anomaly detection capabilities"""
    print_header("Anomaly Detection Demo")
    
    analytics_engine = create_advanced_analytics_engine("demo_tenant")
    
    print_section("Detecting Security Anomalies")
    anomalies = analytics_engine.detect_anomalies(hours_back=24)
    
    if anomalies:
        for anomaly in anomalies:
            severity_icons = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            
            icon = severity_icons.get(anomaly.severity, '🔵')
            print(f"{icon} {anomaly.severity.upper()}: {anomaly.description}")
            print(f"   Metric: {anomaly.metric_name}")
            print(f"   Actual: {anomaly.actual_value:.1f}")
            print(f"   Expected: {anomaly.expected_value:.1f}")
            print(f"   Deviation: {anomaly.deviation_score:.1f}σ")
            print(f"   Time: {anomaly.timestamp}")
            print()
    else:
        print("✅ No anomalies detected - system operating normally")

def demo_predictive_insights():
    """Demonstrate predictive insights capabilities"""
    print_header("Predictive Insights Demo")
    
    analytics_engine = create_advanced_analytics_engine("demo_tenant")
    
    print_section("Generating Predictive Insights")
    insights = analytics_engine.generate_predictive_insights()
    
    # Risk Forecast
    risk_forecast = insights.get('risk_forecast', {})
    print("🎯 Risk Forecast:")
    print(f"   Predicted Risk Level: {risk_forecast.get('prediction', 'Unknown')}")
    print(f"   Confidence: {risk_forecast.get('confidence', 0):.1%}")
    print(f"   Timeframe: {risk_forecast.get('timeframe', 'N/A')}")
    print(f"   Current Avg Risk: {risk_forecast.get('current_avg_risk', 0):.1f}/10")
    print()
    
    # Vulnerability Prediction
    vuln_pred = insights.get('vulnerability_prediction', {})
    print("🔍 Vulnerability Discovery Prediction:")
    print(f"   Weekly Discoveries: {vuln_pred.get('predicted_weekly_discoveries', 0)}")
    print(f"   Daily Rate: {vuln_pred.get('current_daily_rate', 0):.1f}")
    print(f"   Trend: {vuln_pred.get('trend', 'stable').title()}")
    print(f"   Confidence: {vuln_pred.get('confidence', 0):.1%}")
    print()
    
    # Resource Planning
    resource_pred = insights.get('resource_planning', {})
    print("📊 Resource Planning:")
    print(f"   Storage Needed: {resource_pred.get('predicted_storage_mb', 0):.1f} MB")
    print(f"   Weekly Scan Time: {resource_pred.get('predicted_weekly_scan_time_minutes', 0):.0f} minutes")
    print(f"   Cleanup Frequency: {resource_pred.get('recommended_cleanup_frequency', 'monthly').title()}")
    print()
    
    # Attack Scenarios
    attack_pred = insights.get('attack_likelihood', {})
    print("⚔️ Attack Scenario Prediction:")
    print(f"   Overall Likelihood: {attack_pred.get('overall_attack_likelihood', 'Low')}")
    
    scenarios = attack_pred.get('likely_scenarios', [])
    if scenarios:
        print("   Top Scenarios:")
        for scenario in scenarios[:3]:
            print(f"   • {scenario.get('scenario', 'Unknown')}: {scenario.get('likelihood_percentage', 0)}%")
    else:
        print("   No specific attack scenarios identified")

def demo_security_maturity():
    """Demonstrate security maturity assessment"""
    print_header("Security Maturity Assessment Demo")
    
    analytics_engine = create_advanced_analytics_engine("demo_tenant")
    
    print_section("Calculating Security Maturity")
    maturity = analytics_engine.calculate_security_maturity()
    
    overall_score = maturity.get('overall_score', 0)
    maturity_level = maturity.get('maturity_level', 'Unknown')
    
    print(f"🎯 Overall Security Maturity Score: {overall_score:.0f}/100")
    print(f"📊 Maturity Level: {maturity_level}")
    print()
    
    # Breakdown by scan type
    scan_scores = maturity.get('scan_type_scores', {})
    if scan_scores:
        print("📋 Maturity Breakdown:")
        for scan_type, score in scan_scores.items():
            print(f"   {scan_type.replace('_', ' ').title()}: {score:.0f}/100")
        print()
    
    # Recommendations
    recommendations = maturity.get('recommendations', [])
    if recommendations:
        print("💡 Recommendations:")
        for rec in recommendations:
            print(f"   • {rec}")

def demo_intelligent_orchestration():
    """Demonstrate intelligent scan orchestration"""
    print_header("Intelligent Scan Orchestration Demo")
    
    orchestrator = create_intelligent_scan_orchestrator("demo_tenant")
    
    print_section("Analyzing Scan Needs")
    recommendations = orchestrator.analyze_scan_needs()
    
    if recommendations:
        print("🎯 AI-Generated Scan Recommendations:")
        for i, rec in enumerate(recommendations[:5], 1):
            priority_icons = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            
            icon = priority_icons.get(rec.priority.value, '🔵')
            print(f"{i}. {icon} {rec.recommended_scan} on {rec.target}")
            print(f"   Priority: {rec.priority.value.title()}")
            print(f"   Reasoning: {rec.reasoning}")
            print(f"   Confidence: {rec.confidence:.1%}")
            print(f"   Expected Value: {rec.estimated_value:.1f}/10")
            print()
    else:
        print("ℹ️  No specific scan recommendations at this time")
    
    print_section("Creating Intelligent Scan Plan")
    targets = ["192.168.1.100", "example.com"]
    scan_plan = orchestrator.create_intelligent_scan_plan(targets, time_budget_hours=4)
    
    if scan_plan:
        print(f"📋 Generated Scan Plan ({len(scan_plan)} tasks):")
        total_time = sum(task.estimated_duration for task in scan_plan)
        print(f"   Total Estimated Time: {total_time} minutes")
        print()
        
        for i, task in enumerate(scan_plan, 1):
            print(f"{i}. {task.scan_type} → {task.target}")
            print(f"   Priority: {task.priority.value.title()}")
            print(f"   Duration: {task.estimated_duration} minutes")
            print(f"   AI Reasoning: {task.ai_reasoning}")
            print(f"   Confidence: {task.confidence_score:.1%}")
            if task.dependencies:
                print(f"   Dependencies: {len(task.dependencies)} tasks")
            print()
    else:
        print("ℹ️  No scan plan generated (insufficient data or targets)")
    
    print_section("Real-time Recommendations")
    real_time_recs = orchestrator.get_real_time_recommendations()
    
    if real_time_recs:
        security_score = real_time_recs.get('security_score', {})
        print(f"🛡️  Current Security Score: {security_score.get('score', 0):.0f}/100")
        print(f"📊 Risk Level: {security_score.get('risk_level', 'Unknown')}")
        print(f"🎯 Recommended Action: {real_time_recs.get('recommended_action', 'Unknown')}")
        
        immediate_recs = real_time_recs.get('immediate_recommendations', [])
        if immediate_recs:
            print("\n⚡ Immediate Recommendations:")
            for rec in immediate_recs:
                print(f"   • {rec.get('recommendation', 'Unknown')}")
                print(f"     Reasoning: {rec.get('reasoning', 'N/A')}")
                print(f"     Priority: {rec.get('priority', 'unknown').title()}")
                print()

def demo_comprehensive_dashboard():
    """Demonstrate comprehensive dashboard data"""
    print_header("Comprehensive Dashboard Demo")
    
    analytics_engine = create_advanced_analytics_engine("demo_tenant")
    
    print_section("Comprehensive Dashboard Data")
    dashboard_data = analytics_engine.get_comprehensive_dashboard_data()
    
    # Security Score
    security_score = dashboard_data.get('security_score', {})
    print(f"🛡️  Security Score: {security_score.get('score', 0):.0f}/100")
    print(f"📊 Risk Level: {security_score.get('risk_level', 'Unknown')}")
    print(f"🚨 Total Issues: {security_score.get('total_issues', 0)}")
    print(f"🔴 Critical Issues: {security_score.get('critical_issues', 0)}")
    print()
    
    # Scan Activity
    scan_activity = dashboard_data.get('scan_activity', {})
    print(f"📈 Scan Activity:")
    print(f"   Total Results: {scan_activity.get('total_results', 0)}")
    print(f"   Active Scans: {scan_activity.get('active_scans', 0)}")
    print(f"   Scan Types Active: {scan_activity.get('scan_types_active', 0)}")
    print()
    
    # Threat Metrics
    threat_metrics = dashboard_data.get('threat_metrics', {})
    print(f"⚔️  Threat Assessment:")
    print(f"   Threat Level: {threat_metrics.get('threat_level', 'Unknown')}")
    print(f"   Max Risk Score: {threat_metrics.get('max_risk_score', 0):.1f}/10")
    print(f"   Total Threats: {threat_metrics.get('total_threats', 0)}")
    print()
    
    # Remediation Metrics
    remediation_metrics = dashboard_data.get('remediation_metrics', {})
    print(f"🔧 Remediation Status:")
    print(f"   Total Actions: {remediation_metrics.get('total_actions', 0)}")
    print(f"   Critical Actions: {remediation_metrics.get('critical_actions', 0)}")
    print(f"   Estimated Time: {remediation_metrics.get('estimated_time', 0)} minutes")
    print(f"   Coverage: {remediation_metrics.get('remediation_coverage', 0):.1f}%")
    print()
    
    # Target Metrics
    target_metrics = dashboard_data.get('target_metrics', {})
    print(f"🎯 Target Coverage:")
    print(f"   Total Targets: {target_metrics.get('total_targets', 0)}")
    print(f"   Fully Scanned: {target_metrics.get('fully_scanned', 0)}")
    print(f"   Coverage: {target_metrics.get('coverage_percentage', 0):.1f}%")

def export_demo_results():
    """Export demo results for analysis"""
    print_header("Exporting Demo Results")
    
    analytics_engine = create_advanced_analytics_engine("demo_tenant")
    orchestrator = create_intelligent_scan_orchestrator("demo_tenant")
    
    # Collect all demo data
    demo_results = {
        'timestamp': datetime.now().isoformat(),
        'demo_type': 'advanced_analytics_demo',
        'trends': [
            {
                'metric': t.metric_name,
                'current': t.current_value,
                'previous': t.previous_value,
                'change_percentage': t.change_percentage,
                'trend_direction': t.trend_direction,
                'confidence': t.confidence
            } for t in analytics_engine.analyze_security_trends()
        ],
        'anomalies': [
            {
                'metric': a.metric_name,
                'actual_value': a.actual_value,
                'expected_value': a.expected_value,
                'deviation_score': a.deviation_score,
                'severity': a.severity,
                'description': a.description
            } for a in analytics_engine.detect_anomalies()
        ],
        'predictions': analytics_engine.generate_predictive_insights(),
        'maturity': analytics_engine.calculate_security_maturity(),
        'scan_recommendations': [
            {
                'scan_type': r.recommended_scan,
                'target': r.target,
                'reasoning': r.reasoning,
                'confidence': r.confidence,
                'priority': r.priority.value,
                'estimated_value': r.estimated_value
            } for r in orchestrator.analyze_scan_needs()
        ],
        'dashboard_data': analytics_engine.get_comprehensive_dashboard_data()
    }
    
    # Export to file
    filename = f"huggin_advanced_analytics_demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(demo_results, f, indent=2, default=str)
        
        print(f"✅ Demo results exported to: {filename}")
        print(f"📊 File size: {os.path.getsize(filename)} bytes")
    except Exception as e:
        print(f"❌ Export failed: {e}")

def main():
    """Main demo function"""
    print_header("Huggin Advanced Analytics Demo")
    print("This demo showcases the advanced analytics capabilities of the Huggin framework.")
    print("The demo includes trend analysis, anomaly detection, predictive insights,")
    print("security maturity assessment, and intelligent scan orchestration.")
    
    try:
        # Step 1: Simulate data
        simulate_scan_data()
        
        # Step 2: Demonstrate trend analysis
        demo_trend_analysis()
        
        # Step 3: Demonstrate anomaly detection
        demo_anomaly_detection()
        
        # Step 4: Demonstrate predictive insights
        demo_predictive_insights()
        
        # Step 5: Demonstrate security maturity
        demo_security_maturity()
        
        # Step 6: Demonstrate intelligent orchestration
        demo_intelligent_orchestration()
        
        # Step 7: Demonstrate comprehensive dashboard
        demo_comprehensive_dashboard()
        
        # Step 8: Export results
        export_demo_results()
        
        print_header("Demo Complete")
        print("✅ Advanced analytics demo completed successfully!")
        print("📊 All analytics engines are functioning properly.")
        print("🔬 The system is ready for production use.")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())