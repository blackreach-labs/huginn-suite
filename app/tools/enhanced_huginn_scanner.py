# app/tools/enhanced_huginn_scanner.py
"""
Enhanced Huginn Scanner with Advanced Analysis Integration
Extends the original scanner with comprehensive vulnerability analysis,
attack chain correlation, and strategic remediation planning.
"""

import asyncio
import json
from datetime import datetime
from .huginn_vuln_scanner import HuginnVulnScanner
from ..core.huginn_results_analyzer import huginn_analyzer
from ..core.vulnerability_correlation_engine import correlation_engine
from ..core.centralized_scan_data import centralized_scan_data

class EnhancedHuginnScanner(HuginnVulnScanner):
    """Enhanced Huginn scanner with advanced analysis capabilities"""
    
    def __init__(self, target_url, profile='normal', config_path=None, tenant_id='default'):
        super().__init__(target_url, profile, config_path)
        self.tenant_id = tenant_id
        self.analysis_results = {}
        self.attack_chains = []
        self.mitigation_strategies = {}
    
    async def scan_and_analyze(self):
        """Run scan and perform comprehensive analysis"""
        print(f"Starting enhanced scan of {self.target_url}")
        print("=" * 60)
        
        # Run original scan
        scan_results = await self.scan()
        
        # Perform advanced analysis
        print("\nPerforming advanced vulnerability analysis...")
        self.analysis_results = huginn_analyzer.analyze_scan_results(scan_results)
        
        # Generate attack chains
        print("Analyzing attack chains and correlations...")
        vulnerabilities = scan_results.get('vulnerabilities', [])
        self.attack_chains = correlation_engine.analyze_attack_chains(vulnerabilities)
        
        # Generate mitigation strategies
        print("Developing mitigation strategies...")
        self.mitigation_strategies = correlation_engine.generate_mitigation_strategy(self.attack_chains)
        
        # Store results in centralized database
        self._store_enhanced_results(scan_results)
        
        # Display enhanced results
        self._display_enhanced_results()
        
        return {
            'scan_results': scan_results,
            'analysis_results': self.analysis_results,
            'attack_chains': self.attack_chains,
            'mitigation_strategies': self.mitigation_strategies
        }
    
    def _store_enhanced_results(self, scan_results):
        """Store enhanced results in centralized database"""
        try:
            scan_id = f"enhanced_huginn_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Store original scan results
            centralized_scan_data.add_scan_result(
                scan_id=scan_id,
                tenant_id=self.tenant_id,
                scan_type="huginn_enhanced",
                target=self.target_url,
                scanner="enhanced_huginn_scanner",
                result_data={
                    'scan_results': scan_results,
                    'analysis_results': self.analysis_results,
                    'attack_chains': [
                        {
                            'chain_id': chain.chain_id,
                            'vulnerabilities': chain.vulnerabilities,
                            'attack_path': chain.attack_path,
                            'risk_score': chain.risk_score,
                            'description': chain.description,
                            'mitigation_priority': chain.mitigation_priority
                        } for chain in self.attack_chains
                    ],
                    'mitigation_strategies': self.mitigation_strategies
                }
            )
            print(f"Results stored in centralized database with ID: {scan_id}")
        except Exception as e:
            print(f"Failed to store enhanced results: {e}")
    
    def _display_enhanced_results(self):
        """Display enhanced analysis results"""
        print("\n" + "=" * 60)
        print("ENHANCED HUGINN SCANNER RESULTS")
        print("=" * 60)
        
        # Risk Assessment
        risk_assessment = self.analysis_results.get('risk_assessment', {})
        print(f"\nOVERALL RISK ASSESSMENT:")
        print(f"  Risk Score: {risk_assessment.get('overall_risk_score', 0):.1f}%")
        print(f"  Risk Level: {risk_assessment.get('risk_level', 'Unknown')}")
        print(f"  Total Vulnerabilities: {risk_assessment.get('vulnerability_count', 0)}")
        
        # Vulnerability Breakdown
        scan_summary = self.analysis_results.get('scan_summary', {})
        severity_breakdown = scan_summary.get('severity_breakdown', {})
        print(f"\nVULNERability BREAKDOWN:")
        for severity, count in severity_breakdown.items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        # Attack Chains
        if self.attack_chains:
            print(f"\nATTACK CHAINS IDENTIFIED ({len(self.attack_chains)}):")
            for i, chain in enumerate(self.attack_chains[:5], 1):  # Top 5 chains
                print(f"  {i}. {chain.chain_id} (Risk: {chain.risk_score:.1f}/10)")
                print(f"     {chain.description}")
                print(f"     Priority: {chain.mitigation_priority}")
        
        # Executive Insights
        insights = self.analysis_results.get('executive_insights', [])
        if insights:
            print(f"\nEXECUTIVE INSIGHTS:")
            for insight in insights[:3]:  # Top 3 insights
                print(f"  - {insight}")
        
        # Compliance Status
        compliance = self.analysis_results.get('compliance_status', {})
        owasp_status = compliance.get('owasp_top_10', {})
        print(f"\nCOMPLIANCE STATUS:")
        print(f"  OWASP Top 10: {owasp_status.get('score', 0)}% ({owasp_status.get('status', 'Unknown')})")
        
        pci_status = compliance.get('pci_dss', {})
        print(f"  PCI DSS: {pci_status.get('status', 'Unknown')}")
        
        # Top Remediation Priorities
        roadmap = self.analysis_results.get('remediation_roadmap', [])
        if roadmap:
            print(f"\nTOP REMEDIATION PRIORITIES:")
            for item in roadmap[:3]:  # Top 3 priorities
                print(f"  {item.get('priority')}. {item.get('vulnerability_type')}")
                print(f"     Timeline: {item.get('timeline')}")
                print(f"     Effort: {item.get('effort_estimate')}")
        
        # Immediate Actions
        immediate_actions = self.mitigation_strategies.get('immediate_actions', [])
        if immediate_actions:
            print(f"\nIMMEDIATE ACTIONS REQUIRED:")
            for action in immediate_actions[:3]:
                print(f"  - {action}")
        
        print(f"\nScan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("Use the Huginn Dashboard for detailed interactive analysis.")
    
    def generate_comprehensive_report(self, format='html'):
        """Generate comprehensive report in specified format"""
        if format == 'html':
            return huginn_analyzer.generate_detailed_report(self.analysis_results)
        elif format == 'json':
            return json.dumps({
                'analysis_results': self.analysis_results,
                'attack_chains': [
                    {
                        'chain_id': chain.chain_id,
                        'vulnerabilities': chain.vulnerabilities,
                        'attack_path': chain.attack_path,
                        'risk_score': chain.risk_score,
                        'description': chain.description,
                        'mitigation_priority': chain.mitigation_priority
                    } for chain in self.attack_chains
                ],
                'mitigation_strategies': self.mitigation_strategies
            }, indent=2)
        elif format == 'executive':
            return self._generate_executive_report()
        else:
            return "Unsupported format"
    
    def _generate_executive_report(self):
        """Generate executive summary report"""
        risk_assessment = self.analysis_results.get('risk_assessment', {})
        insights = self.analysis_results.get('executive_insights', [])
        
        report = f"""
EXECUTIVE SECURITY ASSESSMENT SUMMARY
=====================================

Target: {self.target_url}
Assessment Date: {datetime.now().strftime('%Y-%m-%d')}

RISK OVERVIEW:
- Overall Risk Level: {risk_assessment.get('risk_level', 'Unknown')}
- Risk Score: {risk_assessment.get('overall_risk_score', 0):.1f}%
- Total Vulnerabilities: {risk_assessment.get('vulnerability_count', 0)}

KEY FINDINGS:
"""
        for insight in insights:
            report += f"- {insight}\n"
        
        report += f"""
ATTACK CHAIN ANALYSIS:
{len(self.attack_chains)} potential attack chains identified.
"""
        
        for chain in self.attack_chains[:3]:  # Top 3 chains
            report += f"- {chain.description} (Risk: {chain.risk_score:.1f}/10)\n"
        
        immediate_actions = self.mitigation_strategies.get('immediate_actions', [])
        if immediate_actions:
            report += f"\nIMMEDIATE ACTIONS REQUIRED:\n"
            for action in immediate_actions:
                report += f"- {action}\n"
        
        return report

# Usage example and CLI interface
async def main():
    """Main function for CLI usage"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python enhanced_huginn_scanner.py <target_url> [profile] [tenant_id]")
        print("Example: python enhanced_huginn_scanner.py https://example.com normal my_company")
        return
    
    target_url = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) > 2 else 'normal'
    tenant_id = sys.argv[3] if len(sys.argv) > 3 else 'default'
    
    # Create enhanced scanner
    scanner = EnhancedHuginnScanner(target_url, profile, tenant_id=tenant_id)
    
    # Run enhanced scan
    results = await scanner.scan_and_analyze()
    
    # Generate reports
    print("\nGenerating comprehensive reports...")
    
    # HTML report
    html_report = scanner.generate_comprehensive_report('html')
    with open(f'huginn_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html', 'w') as f:
        f.write(html_report)
    
    # JSON export
    json_report = scanner.generate_comprehensive_report('json')
    with open(f'huginn_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'w') as f:
        f.write(json_report)
    
    # Executive summary
    exec_report = scanner.generate_comprehensive_report('executive')
    with open(f'huginn_executive_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt', 'w') as f:
        f.write(exec_report)
    
    print("Reports generated successfully!")
    print("Enhanced scan complete.")

if __name__ == "__main__":
    asyncio.run(main())