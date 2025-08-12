# app/core/auth_differential_tester.py
import asyncio
import time
from typing import Dict, List, Optional, Tuple
from PyQt6.QtCore import QObject, pyqtSignal, QThread
from .http_client import HttpRequest, HttpResponse, UnifiedHttpClient

class AuthDifferentialTester(QObject):
    """Performs differential testing on authentication flows"""
    
    test_started = pyqtSignal(str)  # test_id
    test_completed = pyqtSignal(str, dict)  # test_id, results
    difference_found = pyqtSignal(str, dict)  # test_id, diff_info
    
    def __init__(self):
        super().__init__()
        self.http_client = UnifiedHttpClient()
        self.active_tests = {}
    
    def compare_auth_vs_unauth(self, flow_data: dict, test_name: str = "auth_vs_unauth") -> str:
        """Compare authenticated vs unauthenticated requests"""
        test_id = f"{test_name}_{int(time.time())}"
        
        # Start differential test in thread
        diff_thread = DifferentialTestThread(
            test_id, flow_data, self.http_client, "auth_vs_unauth"
        )
        diff_thread.test_completed.connect(self.test_completed)
        diff_thread.difference_found.connect(self.difference_found)
        diff_thread.start()
        
        self.active_tests[test_id] = diff_thread
        self.test_started.emit(test_id)
        
        return test_id
    
    def compare_admin_vs_user(self, flow_data: dict, admin_token: str, user_token: str, test_name: str = "admin_vs_user") -> str:
        """Compare admin vs standard user requests"""
        test_id = f"{test_name}_{int(time.time())}"
        
        # Start differential test in thread
        diff_thread = DifferentialTestThread(
            test_id, flow_data, self.http_client, "admin_vs_user",
            admin_token=admin_token, user_token=user_token
        )
        diff_thread.test_completed.connect(self.test_completed)
        diff_thread.difference_found.connect(self.difference_found)
        diff_thread.start()
        
        self.active_tests[test_id] = diff_thread
        self.test_started.emit(test_id)
        
        return test_id
    
    def compare_different_users(self, flow_data: dict, user1_token: str, user2_token: str, test_name: str = "user_vs_user") -> str:
        """Compare requests between different users"""
        test_id = f"{test_name}_{int(time.time())}"
        
        # Start differential test in thread
        diff_thread = DifferentialTestThread(
            test_id, flow_data, self.http_client, "user_vs_user",
            user1_token=user1_token, user2_token=user2_token
        )
        diff_thread.test_completed.connect(self.test_completed)
        diff_thread.difference_found.connect(self.difference_found)
        diff_thread.start()
        
        self.active_tests[test_id] = diff_thread
        self.test_started.emit(test_id)
        
        return test_id
    
    def stop_test(self, test_id: str):
        """Stop an active test"""
        if test_id in self.active_tests:
            thread = self.active_tests[test_id]
            thread.stop()
            del self.active_tests[test_id]

class DifferentialTestThread(QThread):
    """Thread for running differential tests"""
    
    test_completed = pyqtSignal(str, dict)  # test_id, results
    difference_found = pyqtSignal(str, dict)  # test_id, diff_info
    
    def __init__(self, test_id: str, flow_data: dict, http_client: UnifiedHttpClient, 
                 test_type: str, **kwargs):
        super().__init__()
        self.test_id = test_id
        self.flow_data = flow_data
        self.http_client = http_client
        self.test_type = test_type
        self.kwargs = kwargs
        self.should_stop = False
        
        self.results = {
            'test_id': test_id,
            'test_type': test_type,
            'start_time': time.time(),
            'requests_tested': 0,
            'differences_found': 0,
            'differences': [],
            'summary': {}
        }
    
    def stop(self):
        """Stop the test"""
        self.should_stop = True
    
    def run(self):
        """Run the differential test"""
        try:
            if self.test_type == "auth_vs_unauth":
                self._run_auth_vs_unauth_test()
            elif self.test_type == "admin_vs_user":
                self._run_admin_vs_user_test()
            elif self.test_type == "user_vs_user":
                self._run_user_vs_user_test()
            
            self.results['end_time'] = time.time()
            self.results['duration'] = self.results['end_time'] - self.results['start_time']
            
            # Generate summary
            self._generate_summary()
            
            self.test_completed.emit(self.test_id, self.results)
            
        except Exception as e:
            self.results['error'] = str(e)
            self.test_completed.emit(self.test_id, self.results)
    
    def _run_auth_vs_unauth_test(self):
        """Compare authenticated vs unauthenticated requests"""
        requests = self.flow_data.get('requests', [])\n        \n        for i, request_data in enumerate(requests):\n            if self.should_stop:\n                break\n            \n            # Skip non-auth-related requests\n            if not request_data.get('is_auth_related', False):\n                continue\n            \n            # Create authenticated request\n            auth_request = self._create_http_request(request_data)\n            \n            # Create unauthenticated request (remove auth)\n            unauth_request = self._remove_authentication(auth_request)\n            \n            # Send both requests\n            auth_response = self.http_client.send_request(auth_request)\n            time.sleep(0.5)  # Small delay\n            unauth_response = self.http_client.send_request(unauth_request)\n            \n            self.results['requests_tested'] += 1\n            \n            # Compare responses\n            if auth_response and unauth_response:\n                diff = self._compare_responses(auth_response, unauth_response, i)\n                if diff:\n                    self.results['differences'].append(diff)\n                    self.results['differences_found'] += 1\n                    self.difference_found.emit(self.test_id, diff)\n            \n            time.sleep(1)  # Delay between requests\n    \n    def _run_admin_vs_user_test(self):\n        \"\"\"Compare admin vs user requests\"\"\"\n        admin_token = self.kwargs.get('admin_token')\n        user_token = self.kwargs.get('user_token')\n        \n        if not admin_token or not user_token:\n            return\n        \n        requests = self.flow_data.get('requests', [])\n        \n        for i, request_data in enumerate(requests):\n            if self.should_stop:\n                break\n            \n            # Create admin request\n            admin_request = self._create_http_request(request_data)\n            admin_request = self._set_token(admin_request, admin_token)\n            \n            # Create user request\n            user_request = self._create_http_request(request_data)\n            user_request = self._set_token(user_request, user_token)\n            \n            # Send both requests\n            admin_response = self.http_client.send_request(admin_request)\n            time.sleep(0.5)\n            user_response = self.http_client.send_request(user_request)\n            \n            self.results['requests_tested'] += 1\n            \n            # Compare responses\n            if admin_response and user_response:\n                diff = self._compare_responses(admin_response, user_response, i, \"admin\", \"user\")\n                if diff:\n                    self.results['differences'].append(diff)\n                    self.results['differences_found'] += 1\n                    self.difference_found.emit(self.test_id, diff)\n            \n            time.sleep(1)\n    \n    def _run_user_vs_user_test(self):\n        \"\"\"Compare requests between different users\"\"\"\n        user1_token = self.kwargs.get('user1_token')\n        user2_token = self.kwargs.get('user2_token')\n        \n        if not user1_token or not user2_token:\n            return\n        \n        requests = self.flow_data.get('requests', [])\n        \n        for i, request_data in enumerate(requests):\n            if self.should_stop:\n                break\n            \n            # Create user1 request\n            user1_request = self._create_http_request(request_data)\n            user1_request = self._set_token(user1_request, user1_token)\n            \n            # Create user2 request\n            user2_request = self._create_http_request(request_data)\n            user2_request = self._set_token(user2_request, user2_token)\n            \n            # Send both requests\n            user1_response = self.http_client.send_request(user1_request)\n            time.sleep(0.5)\n            user2_response = self.http_client.send_request(user2_request)\n            \n            self.results['requests_tested'] += 1\n            \n            # Compare responses\n            if user1_response and user2_response:\n                diff = self._compare_responses(user1_response, user2_response, i, \"user1\", \"user2\")\n                if diff:\n                    self.results['differences'].append(diff)\n                    self.results['differences_found'] += 1\n                    self.difference_found.emit(self.test_id, diff)\n            \n            time.sleep(1)\n    \n    def _create_http_request(self, request_data: dict) -> HttpRequest:\n        \"\"\"Create HttpRequest from recorded request data\"\"\"\n        return HttpRequest(\n            method=request_data.get('method', 'GET'),\n            url=request_data.get('url', ''),\n            headers=request_data.get('headers', {}).copy(),\n            data=request_data.get('data', ''),\n            params=request_data.get('params', {}).copy(),\n            cookies=request_data.get('cookies', {}).copy(),\n            timeout=30,\n            allow_redirects=False,  # Don't follow redirects for comparison\n            verify=True\n        )\n    \n    def _remove_authentication(self, request: HttpRequest) -> HttpRequest:\n        \"\"\"Remove authentication from request\"\"\"\n        unauth_request = HttpRequest(\n            method=request.method,\n            url=request.url,\n            headers=request.headers.copy(),\n            data=request.data,\n            params=request.params.copy(),\n            cookies=request.cookies.copy(),\n            timeout=request.timeout,\n            allow_redirects=request.allow_redirects,\n            verify=request.verify\n        )\n        \n        # Remove Authorization header\n        if 'Authorization' in unauth_request.headers:\n            del unauth_request.headers['Authorization']\n        \n        # Remove session cookies\n        session_cookies = ['session', 'JSESSIONID', 'PHPSESSID', 'auth']\n        for cookie_name in list(unauth_request.cookies.keys()):\n            if any(indicator in cookie_name.lower() for indicator in session_cookies):\n                del unauth_request.cookies[cookie_name]\n        \n        # Remove auth tokens from parameters\n        auth_params = ['access_token', 'token', 'auth_token']\n        for param in auth_params:\n            if param in unauth_request.params:\n                del unauth_request.params[param]\n        \n        return unauth_request\n    \n    def _set_token(self, request: HttpRequest, token: str) -> HttpRequest:\n        \"\"\"Set authentication token in request\"\"\"\n        # Set Authorization header\n        request.headers['Authorization'] = f'Bearer {token}'\n        return request\n    \n    def _compare_responses(self, response1: HttpResponse, response2: HttpResponse, \n                         sequence: int, label1: str = \"authenticated\", label2: str = \"unauthenticated\") -> Optional[dict]:\n        \"\"\"Compare two responses and return differences\"\"\"\n        differences = []\n        \n        # Compare status codes\n        if response1.status_code != response2.status_code:\n            differences.append({\n                'type': 'status_code',\n                'description': f'Status code differs: {label1}={response1.status_code}, {label2}={response2.status_code}',\n                f'{label1}_value': response1.status_code,\n                f'{label2}_value': response2.status_code\n            })\n        \n        # Compare content length\n        len1 = len(response1.text)\n        len2 = len(response2.text)\n        if abs(len1 - len2) > 100:  # Significant difference\n            differences.append({\n                'type': 'content_length',\n                'description': f'Content length differs significantly: {label1}={len1}, {label2}={len2}',\n                f'{label1}_value': len1,\n                f'{label2}_value': len2\n            })\n        \n        # Compare response times\n        time1 = response1.elapsed_time\n        time2 = response2.elapsed_time\n        if abs(time1 - time2) > 2.0:  # More than 2 second difference\n            differences.append({\n                'type': 'response_time',\n                'description': f'Response time differs significantly: {label1}={time1:.2f}s, {label2}={time2:.2f}s',\n                f'{label1}_value': time1,\n                f'{label2}_value': time2\n            })\n        \n        # Compare specific headers\n        important_headers = ['content-type', 'set-cookie', 'location', 'www-authenticate']\n        for header in important_headers:\n            val1 = response1.headers.get(header, '')\n            val2 = response2.headers.get(header, '')\n            if val1 != val2:\n                differences.append({\n                    'type': f'header_{header}',\n                    'description': f'Header {header} differs: {label1}=\"{val1}\", {label2}=\"{val2}\"',\n                    f'{label1}_value': val1,\n                    f'{label2}_value': val2\n                })\n        \n        # Look for specific content differences\n        content1_lower = response1.text.lower()\n        content2_lower = response2.text.lower()\n        \n        # Check for error messages\n        error_indicators = ['error', 'unauthorized', 'forbidden', 'access denied', 'login required']\n        for indicator in error_indicators:\n            in1 = indicator in content1_lower\n            in2 = indicator in content2_lower\n            if in1 != in2:\n                differences.append({\n                    'type': f'content_{indicator}',\n                    'description': f'Content contains \"{indicator}\": {label1}={in1}, {label2}={in2}',\n                    f'{label1}_value': in1,\n                    f'{label2}_value': in2\n                })\n        \n        # Check for admin/user specific content\n        if label1 == \"admin\" and label2 == \"user\":\n            admin_indicators = ['admin', 'administrator', 'manage', 'delete', 'edit']\n            for indicator in admin_indicators:\n                in1 = indicator in content1_lower\n                in2 = indicator in content2_lower\n                if in1 and not in2:\n                    differences.append({\n                        'type': f'admin_content_{indicator}',\n                        'description': f'Admin-specific content \"{indicator}\" found only in admin response',\n                        'admin_value': True,\n                        'user_value': False,\n                        'severity': 'high'  # Potential privilege escalation\n                    })\n        \n        if differences:\n            return {\n                'sequence': sequence,\n                'url': response1.url,\n                'differences': differences,\n                'timestamp': time.time(),\n                f'{label1}_status': response1.status_code,\n                f'{label2}_status': response2.status_code\n            }\n        \n        return None\n    \n    def _generate_summary(self):\n        \"\"\"Generate test summary\"\"\"\n        summary = {\n            'total_requests': self.results['requests_tested'],\n            'total_differences': self.results['differences_found'],\n            'difference_types': {},\n            'high_risk_findings': [],\n            'recommendations': []\n        }\n        \n        # Count difference types\n        for diff in self.results['differences']:\n            for sub_diff in diff['differences']:\n                diff_type = sub_diff['type']\n                summary['difference_types'][diff_type] = summary['difference_types'].get(diff_type, 0) + 1\n                \n                # Check for high-risk findings\n                if sub_diff.get('severity') == 'high':\n                    summary['high_risk_findings'].append({\n                        'type': diff_type,\n                        'url': diff['url'],\n                        'description': sub_diff['description']\n                    })\n        \n        # Generate recommendations\n        if 'status_code' in summary['difference_types']:\n            summary['recommendations'].append(\n                \"Review status code differences - may indicate authentication bypass or access control issues\"\n            )\n        \n        if any('admin_content' in dt for dt in summary['difference_types']):\n            summary['recommendations'].append(\n                \"Admin-specific content found - verify proper role-based access controls\"\n            )\n        \n        if 'content_unauthorized' in summary['difference_types']:\n            summary['recommendations'].append(\n                \"Inconsistent unauthorized responses - check authentication enforcement\"\n            )\n        \n        self.results['summary'] = summary