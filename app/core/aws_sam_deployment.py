# app/core/aws_sam_deployment.py
import json
import requests
from PyQt6.QtCore import QObject, pyqtSignal

class SAMDeploymentManager(QObject):
    deployment_started = pyqtSignal(str, str)
    deployment_completed = pyqtSignal(str, bool, str)
    
    def __init__(self):
        super().__init__()
        self.gitlab_token = None
        self.gitlab_url = None
        self.project_id = None
        self.aws_credentials = {}
        
    def configure_gitlab(self, url: str, token: str, project_id: str) -> bool:
        self.gitlab_url = url.rstrip('/')
        self.gitlab_token = token
        self.project_id = project_id
        
        headers = {'PRIVATE-TOKEN': token}
        response = requests.get(f"{url}/api/v4/projects/{project_id}", headers=headers)
        return response.status_code == 200
    
    def configure_aws(self, access_key: str, secret_key: str, region: str = 'us-east-1') -> bool:
        self.aws_credentials = {
            'AWS_ACCESS_KEY_ID': access_key,
            'AWS_SECRET_ACCESS_KEY': secret_key,
            'AWS_DEFAULT_REGION': region
        }
        return True
    
    def deploy_proxy_servers(self, config: dict) -> str:
        return self._deploy('proxy', config)
    
    def deploy_vpn_servers(self, config: dict) -> str:
        return self._deploy('vpn', config)
    
    def _deploy(self, deployment_type: str, config: dict) -> str:
        variables = []
        for key, value in self.aws_credentials.items():
            variables.append({'key': key, 'value': value, 'variable_type': 'env_var', 'masked': True})
        
        variables.extend([
            {'key': 'DEPLOYMENT_TYPE', 'value': deployment_type, 'variable_type': 'env_var'},
            {'key': 'SAM_CONFIG', 'value': json.dumps(config), 'variable_type': 'env_var'}
        ])
        
        headers = {'PRIVATE-TOKEN': self.gitlab_token, 'Content-Type': 'application/json'}
        data = {'ref': 'main', 'variables': variables}
        
        response = requests.post(f"{self.gitlab_url}/api/v4/projects/{self.project_id}/pipeline", headers=headers, json=data)
        
        if response.status_code == 201:
            job_id = str(response.json()['id'])
            self.deployment_started.emit(deployment_type, job_id)
            return job_id
        return None

sam_deployment_manager = SAMDeploymentManager()