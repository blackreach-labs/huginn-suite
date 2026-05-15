# examples/security_dashboard_demo.py
"""
Real-Time Security Dashboard Demo

This demo shows the real-time security dashboard that provides live metrics,
threat levels, and operational status across all security components.
"""

import sys
import os
from datetime import datetime

# Add the app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.security_metrics import create_security_metrics_engine

def demonstrate_security_score():
    """Demonstrate security score calculation"""
    print("🛡️ Security Score Calculation")
    print("=" * 50)
    
    metrics_engine = create_security_metrics_engine("demo_company")
    security_data = metrics_engine.calculate_security_score()
    
    print(f"Current Security Score: {security_data['score']:.1f}/100")
    print(f"Risk Level: {security_data['risk_level']}")
    print(f"Total Issues: {security_data['total_issues']}")
    print(f"Critical Issues: {security_data['critical_issues']}")
    print(f"Status Color: {security_data['color']}")
    
    # Explain scoring
    print(f"\n📊 Scoring Methodology:")
    print(f"   - Base Score: 100 points")
    print(f"   - Critical Issues: -15 points each")
    print(f"   - High Issues: -10 points each") 
    print(f"   - Medium Issues: -5 points each")
    print(f"   - Minimum Score: 0 points")
    
    return security_data

def demonstrate_scan_activity():
    """Demonstrate scan activity metrics"""
    print("\n📊 Scan Activity Metrics")
    print("=" * 50)
    
    metrics_engine = create_security_metrics_engine("demo_company")
    activity_data = metrics_engine.get_scan_activity_metrics()
    
    print(f"Total Results: {activity_data['total_results']}")
    print(f"Active Scans: {activity_data['active_scans']}")
    print(f"Scan Types Active: {activity_data['scan_types_active']}")
    
    print(f"\nRecent Activity (last hour):")
    for scan_type, count in activity_data['recent_activity'].items():
        scan_name = scan_type.replace('_', ' ').title()
        status = "🟢 Active" if count > 0 else "⚪ Idle"
        print(f"   {scan_name}: {count} results {status}")
    
    return activity_data

def demonstrate_threat_metrics():
    """Demonstrate threat analysis metrics"""
    print("\n⚠️ Threat Analysis Metrics")
    print("=" * 50)
    
    metrics_engine = create_security_metrics_engine("demo_company")
    threat_data = metrics_engine.get_threat_metrics()
    
    print(f"Threat Level: {threat_data['threat_level']}")
    print(f"Max Risk Score: {threat_data['max_risk_score']:.1f}/10")
    print(f"Total Threats: {threat_data['total_threats']}")
    print(f"Threat Color: {threat_data['threat_color']}")
    
    if threat_data['threat_types']:
        print(f"\nThreat Breakdown:")
        for threat_type, info in threat_data['threat_types'].items():
            threat_name = threat_type.replace('_', ' ').title()
            print(f"   {threat_name}: {info['count']} instances (max risk: {info['max_risk']:.1f})")
    else:
        print(f"\n✅ No active threats detected")
    
    return threat_data

def demonstrate_remediation_metrics():
    """Demonstrate remediation metrics"""
    print("\n🛠️ Remediation Metrics")
    print("=" * 50)
    
    metrics_engine = create_security_metrics_engine("demo_company")
    remediation_data = metrics_engine.get_remediation_metrics()
    
    print(f"Total Actions: {remediation_data['total_actions']}")
    print(f"Critical Actions: {remediation_data['critical_actions']}")
    print(f"Estimated Time: {remediation_data['estimated_time']} minutes")
    print(f"Avg Risk Reduction: {remediation_data['avg_risk_reduction']:.1f}/10")
    print(f"Remediation Coverage: {remediation_data['remediation_coverage']:.1f}%")
    
    if remediation_data['total_actions'] > 0:
        print(f"\n📋 Remediation Status:")
        print(f"   ✅ {remediation_data['total_actions']} automated fixes available")
        print(f"   🔴 {remediation_data['critical_actions']} require immediate attention")
        print(f"   ⏱️ Estimated completion time: {remediation_data['estimated_time']} minutes")
    else:
        print(f"\n✅ No remediation actions needed")
    
    return remediation_data

def demonstrate_target_metrics():
    """Demonstrate target coverage metrics"""
    print("\n🎯 Target Coverage Metrics")
    print("=" * 50)
    
    metrics_engine = create_security_metrics_engine("demo_company")
    target_data = metrics_engine.get_target_metrics()
    
    print(f"Total Targets: {target_data['total_targets']}")
    print(f"Fully Scanned: {target_data['fully_scanned']}")
    print(f"Coverage Percentage: {target_data['coverage_percentage']:.1f}%")
    print(f"Scan Types Available: {target_data['scan_types_count']}")
    
    if target_data['target_breakdown']:
        print(f"\nTarget Breakdown (showing first 5):")
        for i, (target, scans) in enumerate(list(target_data['target_breakdown'].items())[:5]):
            scan_list = ', '.join(scans)
            coverage = len(scans)
            status = "🟢 Complete" if coverage >= 3 else "🟡 Partial" if coverage >= 2 else "🔴 Limited"
            print(f"   {target}: {coverage} scans {status}")
            print(f"      Scans: {scan_list}")
    else:
        print(f"\n⚪ No targets scanned yet")
    
    return target_data

def demonstrate_comprehensive_dashboard():
    """Demonstrate comprehensive dashboard data"""
    print("\n🖥️ Comprehensive Dashboard Data")
    print("=" * 50)
    
    metrics_engine = create_security_metrics_engine("demo_company")
    dashboard_data = metrics_engine.get_comprehensive_dashboard_data()
    
    print(f"Dashboard Generated: {dashboard_data['timestamp']}")
    print(f"Data Sources: {len(dashboard_data) - 1} metric categories")
    
    # Summary view
    security = dashboard_data['security_score']
    threat = dashboard_data['threat_metrics']
    scans = dashboard_data['scan_activity']
    remediation = dashboard_data['remediation_metrics']
    targets = dashboard_data['target_metrics']
    
    print(f"\n📊 Executive Summary:")
    print(f"   Security Score: {security['score']:.0f}/100 ({security['risk_level']} Risk)")
    print(f"   Threat Level: {threat['threat_level']} ({threat['total_threats']} issues)")
    print(f"   Scan Activity: {scans['active_scans']} active ({scans['total_results']} results)")
    print(f"   Remediation: {remediation['total_actions']} actions ({remediation['estimated_time']} min)")
    print(f"   Target Coverage: {targets['coverage_percentage']:.0f}% ({targets['total_targets']} targets)")
    
    return dashboard_data

def demonstrate_real_time_capabilities():
    """Demonstrate real-time dashboard capabilities"""
    print("\n⏱️ Real-Time Dashboard Capabilities")
    print("=" * 50)
    
    print("✅ Live Metrics Updates:")
    print("   - Security score recalculated every 10 seconds")
    print("   - Threat levels updated based on new correlations")
    print("   - Scan activity monitored in real-time")
    print("   - Remediation metrics auto-refreshed")
    print("   - Target coverage tracked continuously")
    
    print("\n✅ Interactive Features:")
    print("   - Click-to-refresh manual updates")
    print("   - Export metrics to JSON format")
    print("   - Color-coded risk indicators")
    print("   - Activity timeline with recent events")
    print("   - Responsive metric cards")
    
    print("\n✅ Integration Points:")
    print("   - Centralized scan data integration")
    print("   - Cross-scan correlation analysis")
    print("   - Automated remediation planning")
    print("   - Multi-tenant support")
    print("   - Historical trend analysis")

def demonstrate_dashboard_ui_integration():
    """Demonstrate dashboard UI integration"""
    print("\n🖥️ Dashboard UI Integration")
    print("=" * 50)
    
    print("📱 Access Path:")
    print("   Main Application → Attack Chain Home → 🛡️ Dashboard Tab")
    
    print("\n🎨 Dashboard Components:")
    print("   📊 Security Score Card - Overall security posture")
    print("   ⚠️ Threat Level Card - Current threat assessment")
    print("   🔍 Active Scans Card - Real-time scan activity")
    print("   🛠️ Remediation Card - Available fixes and time estimates")
    print("   🎯 Coverage Card - Target scanning coverage")
    print("   💻 System Status Card - Overall system health")
    
    print("\n📈 Activity Timeline:")
    print("   - Recent security findings")
    print("   - New scan results")
    print("   - Threat detections")
    print("   - Remediation opportunities")
    
    print("\n🔄 Auto-Refresh:")
    print("   - Updates every 10 seconds")
    print("   - Manual refresh button available")
    print("   - Last updated timestamp shown")

def main():
    """Main demo function"""
    print("🚀 Real-Time Security Dashboard Demo")
    print("=" * 50)
    
    try:
        # Step 1: Security Score
        security_data = demonstrate_security_score()
        
        # Step 2: Scan Activity
        activity_data = demonstrate_scan_activity()
        
        # Step 3: Threat Metrics
        threat_data = demonstrate_threat_metrics()
        
        # Step 4: Remediation Metrics
        remediation_data = demonstrate_remediation_metrics()
        
        # Step 5: Target Metrics
        target_data = demonstrate_target_metrics()
        
        # Step 6: Comprehensive Dashboard
        dashboard_data = demonstrate_comprehensive_dashboard()
        
        # Step 7: Real-time Capabilities
        demonstrate_real_time_capabilities()
        
        # Step 8: UI Integration
        demonstrate_dashboard_ui_integration()
        
        print("\n🎉 Security Dashboard Demo Complete!")
        print("\n💡 Key Benefits Demonstrated:")
        print("   ✅ Real-time security posture monitoring")
        print("   ✅ Comprehensive threat level assessment")
        print("   ✅ Live scan activity tracking")
        print("   ✅ Automated remediation planning")
        print("   ✅ Target coverage analysis")
        print("   ✅ Executive-level security metrics")
        
        print(f"\n📊 Demo Results Summary:")
        print(f"   Security Score: {security_data['score']:.0f}/100")
        print(f"   Threat Level: {threat_data['threat_level']}")
        print(f"   Active Scans: {activity_data['active_scans']}")
        print(f"   Remediation Actions: {remediation_data['total_actions']}")
        print(f"   Target Coverage: {target_data['coverage_percentage']:.0f}%")
        
        print(f"\n🎯 Next Steps:")
        print(f"   1. Launch Huginn application")
        print(f"   2. Navigate to Attack Chain Home")
        print(f"   3. Click '🛡️ Dashboard' tab")
        print(f"   4. View real-time security metrics")
        print(f"   5. Export metrics for reporting")
        
    except Exception as e:
        print(f"❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()