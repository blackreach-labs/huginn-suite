# app/core/web_crawler.py
import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from app.core.logger import logger

class WebCrawler:
    def __init__(self, max_depth=2, max_pages=50):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        # Honour the global SSL verification setting instead of hardcoding False.
        try:
            from app.core.config import config as _cfg
            self.session.verify = _cfg.get('security.ssl_verify', True)
        except Exception:
            self.session.verify = True
        self.visited_urls = set()
        self.crawled_data = {}
    
    def crawl_site(self, start_url, max_pages=None):
        """Crawl a website starting from the given URL"""
        if max_pages:
            self.max_pages = max_pages
        
        # Normalize start URL
        if not start_url.startswith(('http://', 'https://')):
            start_url = f"http://{start_url}"
        
        start_url = self._normalize_url(start_url)
        
        base_domain = urlparse(start_url).netloc
        
        # Start crawling
        self._crawl_recursive(start_url, base_domain, 0)
        
        return self.crawled_data
    
    def _crawl_recursive(self, url, base_domain, depth):
        """Recursively crawl pages"""
        # Normalize URL to prevent duplicates
        url = self._normalize_url(url)
        
        if (depth > self.max_depth or 
            len(self.visited_urls) >= self.max_pages or 
            url in self.visited_urls):
            return
        
        try:
            # Parse URL to check domain
            parsed_url = urlparse(url)
            if parsed_url.netloc != base_domain:
                return  # Don't crawl external domains
            
            self.visited_urls.add(url)
            
            # Make request
            response = self.session.get(url, timeout=10)
            
            # Store page data
            page_data = {
                'url': url,
                'status_code': response.status_code,
                'title': self._extract_title(response.text),
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': len(response.content),
                'links': [],
                'forms': [],
                'depth': depth
            }
            
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                # Extract links and forms
                page_data['links'] = self._extract_links(response.text, url)
                page_data['forms'] = self._extract_forms(response.text, url)
                
                # Continue crawling found links
                for link in page_data['links'][:10]:  # Limit links per page
                    if len(self.visited_urls) < self.max_pages:
                        self._crawl_recursive(link, base_domain, depth + 1)
            
            self.crawled_data[url] = page_data
            
        except Exception as e:
            # Store error information
            self.crawled_data[url] = {
                'url': url,
                'error': str(e),
                'depth': depth
            }
    
    def _extract_title(self, html_content):
        """Extract page title"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.get_text().strip() if title_tag else 'No title'
        except Exception:
            # Fallback regex
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            return title_match.group(1).strip() if title_match else 'No title'
    
    def _extract_links(self, html_content, base_url):
        """Extract links from HTML content"""
        links = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for link_tag in soup.find_all('a', href=True):
                href = link_tag['href']
                if href.startswith(('http://', 'https://')):
                    links.append(href)
                elif href.startswith('/'):
                    links.append(urljoin(base_url, href))
                elif not href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                    links.append(urljoin(base_url, href))
        except Exception:
            # Fallback regex
            link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>'
            matches = re.findall(link_pattern, html_content, re.IGNORECASE)
            for href in matches:
                if href.startswith(('http://', 'https://')):
                    links.append(href)
                elif href.startswith('/'):
                    links.append(urljoin(base_url, href))
        
        return list(set(links))  # Remove duplicates
    
    def _extract_forms(self, html_content, base_url):
        """Extract forms from HTML content"""
        forms = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for form_tag in soup.find_all('form'):
                action = form_tag.get('action', '')
                method = form_tag.get('method', 'GET').upper()
                
                # Resolve relative URLs
                if action:
                    if not action.startswith(('http://', 'https://')):
                        action = urljoin(base_url, action)
                else:
                    action = base_url
                
                # Extract input fields
                inputs = []
                for input_tag in form_tag.find_all(['input', 'select', 'textarea']):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    if input_info['name']:
                        inputs.append(input_info)
                
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs
                })
        except Exception:
            # Fallback regex
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
            matches = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
            for action, form_content in matches:
                if not action.startswith(('http://', 'https://')):
                    action = urljoin(base_url, action)
                
                input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
                inputs = [{'name': name, 'type': 'text', 'value': ''} 
                         for name in re.findall(input_pattern, form_content, re.IGNORECASE)]
                
                forms.append({
                    'action': action,
                    'method': 'GET',
                    'inputs': inputs
                })
        
        return forms
    
    def _normalize_url(self, url):
        """Normalize URL to prevent duplicates"""
        parsed = urlparse(url)
        # Add trailing slash to root paths
        if parsed.path == '' or parsed.path == '/':
            path = '/'
        else:
            path = parsed.path.rstrip('/')
        
        return f"{parsed.scheme}://{parsed.netloc}{path}"