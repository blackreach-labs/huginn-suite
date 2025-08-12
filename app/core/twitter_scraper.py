# app/core/twitter_scraper.py
import requests
import base64
from typing import List, Dict

class TwitterScraper:
    def __init__(self):
        self.bearer_token = "AAAAAAAAAAAAAAAAAAAAAOF%2F3AEAAAAA%2Btp0uHckTijX0feN4RW8QyG8a48%3D8TVM8lZGdSCGP1jYsRgsLTaVb4lA175i8deDnX5i3y1CgioEkg"
        self.access_token = "951328747478659072-e2IuGpwJ2WIThOeyfZ2wQCNQjGK7aJp"
        self.access_token_secret = "En625LNkyCLo3PShzRgk8W3ku4OBP9pEQV9OAfYrxrMpz"
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.bearer_token}',
            'User-Agent': 'TwitterBot/1.0'
        })
    

    
    def search_users(self, target: str) -> List[Dict]:
        """Search for users/company mentions using Twitter API"""
        try:
            # Search for users by username
            url = f"https://api.twitter.com/2/users/by/username/{target}?user.fields=public_metrics,location,verified,description"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                return self._parse_user_response(response.json())
            
            # Search tweets mentioning target
            url = f"https://api.twitter.com/2/tweets/search/recent?query={target}&tweet.fields=author_id,public_metrics&expansions=author_id&user.fields=public_metrics,verified,location,description"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                return self._parse_tweet_response(response.json())
                
        except Exception as e:
            print(f"Twitter API Error: {e}")
        
        return []
    
    def _parse_user_response(self, data):
        """Parse Twitter user API response"""
        results = []
        if 'data' in data:
            user = data['data']
            results.append({
                'user': f"@{user['username']}",
                'content': user.get('description', 'No bio available'),
                'followers': user.get('public_metrics', {}).get('followers_count', 0),
                'location': user.get('location', 'Not specified'),
                'verified': user.get('verified', False)
            })
        return results
    
    def _parse_tweet_response(self, data):
        """Parse Twitter tweet search API response"""
        results = []
        if 'data' in data and 'includes' in data and 'users' in data['includes']:
            users = {user['id']: user for user in data['includes']['users']}
            for tweet in data['data']:
                author = users.get(tweet['author_id'])
                if author:
                    results.append({
                        'user': f"@{author['username']}",
                        'content': tweet['text'][:100] + '...' if len(tweet['text']) > 100 else tweet['text'],
                        'followers': author.get('public_metrics', {}).get('followers_count', 0),
                        'location': author.get('location', 'Not specified'),
                        'verified': author.get('verified', False)
                    })
        return results

# Global instance
twitter_scraper = TwitterScraper()