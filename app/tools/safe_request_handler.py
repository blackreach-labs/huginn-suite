"""
Safe request handler to prevent target system crashes
"""
import asyncio
import aiohttp
from aiohttp import ClientTimeout, TCPConnector
import logging

class SafeRequestHandler:
    """Handles HTTP requests with safety measures to prevent target crashes"""
    
    def __init__(self, max_concurrent=5, request_delay=0.2, timeout=10):
        self.max_concurrent = max_concurrent
        self.request_delay = request_delay
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session = None
        
    async def __aenter__(self):
        connector = TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=self.max_concurrent,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        
        timeout = ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'Huginn-Scanner/1.0'}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    async def safe_request(self, method, url, **kwargs):
        """Make a safe HTTP request with rate limiting"""
        async with self.semaphore:
            try:
                # Add delay to prevent overwhelming target
                await asyncio.sleep(self.request_delay)
                
                async with self.session.request(method, url, **kwargs) as response:
                    # Limit response size to prevent memory issues
                    content = await response.read()
                    if len(content) > 1024 * 1024:  # 1MB limit
                        content = content[:1024 * 1024]
                        
                    return {
                        'status': response.status,
                        'headers': dict(response.headers),
                        'content': content,
                        'url': str(response.url)
                    }
                    
            except asyncio.TimeoutError:
                logging.warning(f"Request timeout for {url}")
                return None
            except Exception as e:
                logging.error(f"Request failed for {url}: {e}")
                return None