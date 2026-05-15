#!/usr/bin/env python3
"""
Test Normal Profile Fix - Verify phase tracking works correctly
"""

import asyncio
import sys
import time
import logging
from app.tools.huginn_vuln_scanner import HuginnVulnScanner

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def test_normal_profile_fix(target_url):
    """Test that normal profile now works with proper phase tracking"""
    logger.info(f"Testing NORMAL profile fix for {target_url}")
    
    try:
        scanner = HuginnVulnScanner(target_url, 'normal')
        
        # Monitor progress
        async def monitor_progress():
            while True:
                await asyncio.sleep(2)
                logger.info(f"Phase: {scanner.current_phase}, Progress: {scanner.phase_progress}%, "
                           f"Requests: {scanner.completed_requests}/{scanner.total_requests}")
        
        # Start monitoring
        monitor_task = asyncio.create_task(monitor_progress())
        
        # Run scan with timeout
        start_time = time.time()
        try:
            results = await asyncio.wait_for(scanner.scan(), timeout=120)  # 2 minute timeout
            monitor_task.cancel()
            
            duration = time.time() - start_time
            logger.info(f"✅ NORMAL profile completed successfully in {duration:.1f}s")
            logger.info(f"Found {len(results.get('vulnerabilities', []))} vulnerabilities")
            
            # Log phase timings
            logger.info("Phase execution times:")
            for phase, timing in results.get('scan_stats', {}).items():
                logger.info(f"  {phase}: {timing}")
            
            return True
            
        except asyncio.TimeoutError:
            monitor_task.cancel()
            logger.error("❌ NORMAL profile still times out after fix")
            return False
            
    except Exception as e:
        logger.error(f"❌ NORMAL profile failed with error: {e}")
        return False

async def compare_profiles(target_url):
    """Compare light vs normal after fix"""
    logger.info("Comparing profiles after fix...")
    
    # Test LIGHT
    logger.info("Testing LIGHT profile...")
    light_start = time.time()
    try:
        light_scanner = HuginnVulnScanner(target_url, 'light')
        light_results = await asyncio.wait_for(light_scanner.scan(), timeout=60)
        light_time = time.time() - light_start
        light_vulns = len(light_results.get('vulnerabilities', []))
        logger.info(f"LIGHT: {light_vulns} vulns in {light_time:.1f}s")
    except Exception as e:
        logger.error(f"LIGHT failed: {e}")
        light_time = 0
        light_vulns = 0
    
    # Test NORMAL
    logger.info("Testing NORMAL profile...")
    normal_success = await test_normal_profile_fix(target_url)
    
    if normal_success:
        logger.info("✅ FIX SUCCESSFUL - Normal profile now works correctly")
    else:
        logger.error("❌ FIX FAILED - Normal profile still has issues")

async def main():
    if len(sys.argv) < 2:
        print("Usage: python test_normal_fix.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    await compare_profiles(target_url)

if __name__ == "__main__":
    asyncio.run(main())