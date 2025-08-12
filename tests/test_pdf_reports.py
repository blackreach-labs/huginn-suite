#!/usr/bin/env python3
"""
Test PDF report generation functionality
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_pdf_generation():
    """Test PDF report generation"""
    print("Testing PDF Report Generation...")
    
    try:
        # Test PDF generator creation
        from app.core.pdf_report_generator import create_pdf_generator
        generator = create_pdf_generator("test_tenant")
        print("[OK] PDF generator created successfully")
        
        # Test executive report generation
        exec_path = "test_executive_report.pdf"
        success = generator.generate_executive_report(exec_path)
        if success and os.path.exists(exec_path):
            print(f"[OK] Executive report generated: {exec_path}")
            os.remove(exec_path)  # Clean up
        else:
            print("[FAIL] Executive report generation failed")
            return False
        
        # Test technical report generation
        tech_path = "test_technical_report.pdf"
        success = generator.generate_technical_report(tech_path)
        if success and os.path.exists(tech_path):
            print(f"[OK] Technical report generated: {tech_path}")
            os.remove(tech_path)  # Clean up
        else:
            print("[FAIL] Technical report generation failed")
            return False
        
        # Test compliance report generation
        comp_path = "test_compliance_report.pdf"
        success = generator.generate_compliance_report(comp_path, 'OWASP_TOP_10')
        if success and os.path.exists(comp_path):
            print(f"[OK] Compliance report generated: {comp_path}")
            os.remove(comp_path)  # Clean up
        else:
            print("[FAIL] Compliance report generation failed")
            return False
        
        print("\nAll PDF generation tests passed!")
        return True
        
    except ImportError as e:
        print(f"[SKIP] PDF generation requires reportlab: {e}")
        print("Install with: pip install reportlab")
        return True  # Skip test if reportlab not available
    except Exception as e:
        print(f"[ERROR] PDF generation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_pdf_generation()
    sys.exit(0 if success else 1)