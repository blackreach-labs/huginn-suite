# app/core/facebook_scraper.py
import requests
from typing import List, Dict

class FacebookScraper:
    def __init__(self):
        self.access_token = "EAABwzLixnjYBO7ZCZCuZBiZBZBvZCZCOZCZCuZBiZBZBvZCZCOZCZCuZBiZBZBvZCZCO"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def search_pages(self, target: str) -> List[Dict]:
        """Search for Facebook pages using Graph API"""
        try:
            url = f"https://graph.facebook.com/v18.0/search?q={target}&type=page&access_token={self.access_token}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                return self._parse_page_response(response.json())
                
        except Exception as e:
            print(f"Facebook API Error: {e}")
        
        return []
    
    def _parse_page_response(self, data):
        """Parse Facebook Graph API response"""
        results = []
        if 'data' in data:
            for page in data['data']:
                results.append({
                    'name': page.get('name', 'Unknown'),
                    'page_id': page.get('id', ''),
                    'category': page.get('category', 'Not specified'),
                    'url': f"https://facebook.com/{page.get('id', '')}",
                    'verified': page.get('verification_status') == 'blue_verified'
                })
        return results

# Global instance
facebook_scraper = FacebookScraper()