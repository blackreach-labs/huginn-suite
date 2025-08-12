# examples/authenticated_crawler_demo.py
"""
Demonstration of the authenticated crawler functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QObject
from app.core.authenticated_crawler import AuthenticatedCrawler

class CrawlerDemo(QObject):
    def __init__(self):
        super().__init__()
        self.crawler = AuthenticatedCrawler()
        
        # Connect signals for demonstration
        self.crawler.auth_success.connect(self.on_auth_success)
        self.crawler.auth_failed.connect(self.on_auth_failed)
        self.crawler.page_crawled.connect(self.on_page_crawled)
        self.crawler.token_extracted.connect(self.on_token_extracted)
    
    def on_auth_success(self, method, credentials):
        print(f"✅ Authentication successful via {method}")
        print(f"   Credentials: {list(credentials.keys())}")
    
    def on_auth_failed(self, method, error):
        print(f"❌ Authentication failed via {method}: {error}")
    
    def on_page_crawled(self, url, page_data):
        print(f"🔍 Crawled: {url}")
        print(f"   Title: {page_data.get('title', 'No title')}")
        print(f"   Status: {page_data.get('status_code', 'Unknown')}")
        
        # Show authentication artifacts if found
        auth_artifacts = page_data.get('auth_artifacts', {})
        if auth_artifacts.get('tokens'):
            print(f"   🔑 Tokens found: {len(auth_artifacts['tokens'])}")
        if auth_artifacts.get('storage_data'):
            storage_count = sum(len(data) for data in auth_artifacts['storage_data'].values())
            print(f"   💾 Storage data: {storage_count} items")
    
    def on_token_extracted(self, token_type, token_value, source):
        masked_token = token_value[:15] + "..." if len(token_value) > 15 else token_value
        print(f"🎯 {token_type} token found in {source}: {masked_token}")
    
    def demo_session_replay(self):
        """Demonstrate session replay authentication"""
        print("\n=== Session Replay Authentication Demo ===")
        
        # Example cookies (replace with real ones)
        cookies = {
            "PHPSESSID": "abc123def456",
            "csrftoken": "xyz789",
            "sessionid": "user_session_123"
        }
        
        success = self.crawler.authenticate(
            target_url="https://httpbin.org/cookies",
            auth_method="session_replay",
            cookies=cookies
        )
        
        if success:
            print("Session replay authentication successful!")
            # Export session for reuse
            session_data = self.crawler.export_auth_session()
            print(f"Session exported with {len(session_data.get('cookies', {}))} cookies")
        else:
            print("Session replay authentication failed")
    
    def demo_form_login(self):
        """Demonstrate form-based login"""
        print("\n=== Form Login Authentication Demo ===")
        
        # This would work with a real login form
        success = self.crawler.authenticate(
            target_url="https://httpbin.org/forms/post",
            auth_method="form_login",
            username="testuser",
            password="testpass"
        )
        
        if success:
            print("Form login successful!")
        else:
            print("Form login failed (expected for demo URL)")
    
    def demo_header_auth(self):
        """Demonstrate header-based authentication"""
        print("\n=== Header Authentication Demo ===")
        
        # Example API key authentication
        headers = {
            "Authorization": "Bearer your_api_token_here",
            "X-API-Key": "your_api_key_here"
        }
        
        success = self.crawler.authenticate(
            target_url="https://httpbin.org/bearer",
            auth_method="header_auth",
            custom_headers=headers
        )
        
        if success:
            print("Header authentication successful!")
        else:
            print("Header authentication failed (expected without real token)")
    
    def demo_basic_auth(self):
        """Demonstrate HTTP Basic authentication"""
        print("\n=== Basic Authentication Demo ===")
        
        success = self.crawler.authenticate(
            target_url="https://httpbin.org/basic-auth/user/pass",
            auth_method="basic_auth",
            username="user",
            password="pass"
        )
        
        if success:
            print("Basic authentication successful!")
        else:
            print("Basic authentication failed")
    
    def demo_authenticated_crawling(self):
        """Demonstrate authenticated crawling"""
        print("\n=== Authenticated Crawling Demo ===")
        
        # First authenticate (using session replay for demo)
        cookies = {"demo_session": "authenticated_user"}
        
        success = self.crawler.authenticate(
            target_url="https://httpbin.org",
            auth_method="session_replay",
            cookies=cookies
        )
        
        if success:
            print("Starting authenticated crawl...")
            
            # Perform authenticated crawling
            crawled_data = self.crawler.crawl_authenticated(
                target_url="https://httpbin.org",
                max_depth=2,
                max_pages=10
            )
            
            print(f"Crawled {len(crawled_data)} pages with authentication")
            
            # Show some results
            for url, page_data in list(crawled_data.items())[:3]:
                if 'error' not in page_data:
                    print(f"  📄 {url} - {page_data.get('title', 'No title')}")
        else:
            print("Authentication failed, cannot perform authenticated crawl")

def main():
    """Main demonstration function"""
    app = QApplication(sys.argv)
    
    print("🔐 Authenticated Crawler Demonstration")
    print("=" * 50)
    
    demo = CrawlerDemo()
    
    # Run demonstrations
    demo.demo_session_replay()
    demo.demo_form_login()
    demo.demo_header_auth()
    demo.demo_basic_auth()
    demo.demo_authenticated_crawling()
    
    print("\n✅ Demo completed!")
    print("\nTo use in your HTTP enumeration:")
    print("1. Configure authentication in the HTTP Enum tool")
    print("2. Select 'Crawler' scan type")
    print("3. Run the scan to perform authenticated crawling")
    
    # Don't start the event loop for this demo
    # app.exec()

if __name__ == "__main__":
    main()