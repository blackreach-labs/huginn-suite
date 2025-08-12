# app/core/crawler.py
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from PyQt6.QtCore import QObject, pyqtSignal, QThread
import time
import re

class WebCrawler(QObject):
    url_discovered = pyqtSignal(str, str)  # url, method
    crawl_completed = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.discovered_urls = set()
        self.crawled_urls = set()
        self.max_depth = 2
        self.max_urls = 100
        
    def crawl_site(self, base_url, max_depth=2, max_urls=100):
        """Crawl a website to discover URLs and parameters"""
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.discovered_urls.clear()
        self.crawled_urls.clear()
        
        # Start crawling
        self._crawl_recursive(base_url, 0)
        
        # Emit completion
        self.crawl_completed.emit(list(self.discovered_urls))
    
    def _crawl_recursive(self, url, depth):
        """Recursively crawl URLs"""
        if depth > self.max_depth or len(self.discovered_urls) >= self.max_urls:
            return
        
        if url in self.crawled_urls:
            return
        
        self.crawled_urls.add(url)
        
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                # Parse HTML for links
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    if self._is_valid_url(full_url, url):
                        self.discovered_urls.add(full_url)
                        self.url_discovered.emit(full_url, 'GET')
                        
                        # Recursively crawl
                        if depth < self.max_depth:
                            self._crawl_recursive(full_url, depth + 1)
                
                # Find forms
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    form_url = urljoin(url, action) if action else url
                    
                    if self._is_valid_url(form_url, url):
                        self.discovered_urls.add(form_url)
                        self.url_discovered.emit(form_url, method)
                
                # Find JavaScript files for potential endpoints
                for script in soup.find_all('script', src=True):
                    script_url = urljoin(url, script['src'])
                    if self._is_valid_url(script_url, url):
                        self.discovered_urls.add(script_url)
                        self.url_discovered.emit(script_url, 'GET')
        
        except Exception as e:
            pass  # Continue crawling even if one URL fails
        
        time.sleep(0.1)  # Be nice to the server
    
    def _is_valid_url(self, url, base_url):
        """Check if URL is valid for crawling"""
        try:
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            
            # Only crawl same domain
            if parsed_url.netloc != parsed_base.netloc:
                return False
            
            # Skip certain file types
            skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.exe']
            if any(url.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            # Skip fragments and duplicates
            if '#' in url:
                return False
            
            return True
        except:
            return False

class CrawlerThread(QThread):
    def __init__(self, crawler, base_url, max_depth, max_urls):
        super().__init__()
        self.crawler = crawler
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_urls = max_urls
    
    def run(self):
        self.crawler.crawl_site(self.base_url, self.max_depth, self.max_urls)