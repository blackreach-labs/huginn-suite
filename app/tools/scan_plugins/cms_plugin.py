# app/tools/scan_plugins/cms_plugin.py

class CMSPlugin:
    def __init__(self):
        self.name = "CMS Detection"
    
    def scan(self, url, response, session):
        """Detect Content Management System"""
        try:
            content = response.text.lower()
            headers = response.headers
            
            cms_signatures = {
                'WordPress': [
                    '/wp-content/', '/wp-includes/', 'wp-json',
                    'wordpress', 'wp_version'
                ],
                'Joomla': [
                    '/components/', '/modules/', '/templates/',
                    'joomla', 'option=com_'
                ],
                'Drupal': [
                    '/sites/default/', '/misc/', 'drupal',
                    'x-drupal-cache', 'x-generator: drupal'
                ],
                'Magento': [
                    '/skin/frontend/', '/js/mage/', 'magento',
                    'mage/cookies'
                ],
                'PrestaShop': [
                    '/themes/', '/modules/', 'prestashop',
                    'ps_'
                ],
                'Shopify': [
                    'shopify', 'cdn.shopify.com',
                    'x-shopify-stage'
                ]
            }
            
            detected_cms = []
            headers_str = str(headers).lower()
            
            for cms_name, signatures in cms_signatures.items():
                for signature in signatures:
                    if signature in content or signature in headers_str:
                        detected_cms.append(cms_name)
                        break
            
            # Version detection for WordPress
            version_info = {}
            if 'WordPress' in detected_cms:
                import re
                version_match = re.search(r'wp-includes/js/.*ver=([0-9.]+)', content)
                if version_match:
                    version_info['WordPress'] = version_match.group(1)
            
            return {
                'detected_cms': detected_cms,
                'versions': version_info
            }
            
        except Exception as e:
            return {'error': str(e)}