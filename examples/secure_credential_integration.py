# examples/secure_credential_integration.py
"""
Example demonstrating how to integrate tools with the secure credential manager.
This shows the pattern that all tools should follow for credential access.
"""

from app.core.secure_credential_manager import secure_credential_manager
import requests
import boto3

class ExampleAPITool:
    """Example showing API tool integration with secure credentials"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def scan_with_shodan(self, target_ip: str):
        """Example Shodan integration using secure credentials"""
        
        # Get credential from secure manager (no manual input required)
        credential = secure_credential_manager.get_credential("shodan")
        
        if not credential or not credential.api_key:
            return {"error": "Shodan API key not configured. Please add to credential manager."}
        
        try:
            # Use the API key from secure storage
            response = self.session.get(
                f"https://api.shodan.io/shodan/host/{target_ip}",
                params={"key": credential.api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"error": f"Shodan API error: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def scan_with_virustotal(self, domain: str):
        """Example VirusTotal integration using secure credentials"""
        
        credential = secure_credential_manager.get_credential("virustotal")
        
        if not credential or not credential.api_key:
            return {"error": "VirusTotal API key not configured. Please add to credential manager."}
        
        try:
            import base64
            domain_id = base64.urlsafe_b64encode(domain.encode()).decode().strip("=")
            
            response = self.session.get(
                f"https://www.virustotal.com/api/v3/domains/{domain_id}",
                headers={"x-apikey": credential.api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"error": f"VirusTotal API error: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}

class ExampleAWSTool:
    """Example showing AWS tool integration with secure credentials"""
    
    def __init__(self):
        self.session = None
    
    def connect_to_aws(self, service_name: str = "aws-default"):
        """Connect to AWS using secure credentials"""
        
        credential = secure_credential_manager.get_credential(service_name)
        
        if not credential:
            return False, f"AWS credentials not found for service '{service_name}'"
        
        try:
            # Create boto3 session with secure credentials
            self.session = boto3.Session(
                aws_access_key_id=credential.username,      # Access Key ID
                aws_secret_access_key=credential.password,  # Secret Access Key
                aws_session_token=credential.token if credential.token else None,
                region_name='us-east-1'
            )
            
            # Test connection
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            
            return True, f"Connected as: {identity.get('Arn', 'Unknown')}"
            
        except Exception as e:
            return False, str(e)
    
    def list_s3_buckets(self):
        """List S3 buckets using secure credentials"""
        
        if not self.session:
            return {"error": "Not connected to AWS. Call connect_to_aws() first."}
        
        try:
            s3 = self.session.client('s3')
            response = s3.list_buckets()
            
            buckets = [bucket['Name'] for bucket in response['Buckets']]
            return {"success": True, "buckets": buckets}
            
        except Exception as e:
            return {"error": str(e)}

class ExampleDatabaseTool:
    """Example showing database tool integration with secure credentials"""
    
    def connect_to_mysql(self, host: str, service_name: str = "mysql"):
        """Connect to MySQL using secure credentials"""
        
        credential = secure_credential_manager.get_credential(service_name)
        
        if not credential:
            return {"error": f"MySQL credentials not found for service '{service_name}'"}
        
        try:
            import mysql.connector
            
            connection = mysql.connector.connect(
                host=host,
                user=credential.username,
                password=credential.password,
                database=credential.domain if credential.domain else None
            )
            
            if connection.is_connected():
                return {"success": True, "message": "Connected to MySQL"}
            else:
                return {"error": "Failed to connect to MySQL"}
                
        except ImportError:
            return {"error": "mysql-connector-python not installed"}
        except Exception as e:
            return {"error": str(e)}
    
    def connect_to_mssql(self, host: str, service_name: str = "mssql"):
        """Connect to MSSQL using secure credentials"""
        
        credential = secure_credential_manager.get_credential(service_name)
        
        if not credential:
            return {"error": f"MSSQL credentials not found for service '{service_name}'"}
        
        try:
            import pyodbc
            
            connection_string = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={host};"
                f"UID={credential.username};"
                f"PWD={credential.password};"
            )
            
            if credential.domain:
                connection_string += f"DATABASE={credential.domain};"
            
            connection = pyodbc.connect(connection_string)
            return {"success": True, "message": "Connected to MSSQL"}
            
        except ImportError:
            return {"error": "pyodbc not installed"}
        except Exception as e:
            return {"error": str(e)}

class ExampleWebTool:
    """Example showing web tool integration with secure credentials"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def authenticate_web_app(self, login_url: str, service_name: str = "web-login"):
        """Authenticate to web application using secure credentials"""
        
        credential = secure_credential_manager.get_credential(service_name)
        
        if not credential:
            return {"error": f"Web credentials not found for service '{service_name}'"}
        
        try:
            # Get login page
            response = self.session.get(login_url)
            
            # Simple form-based authentication example
            login_data = {
                'username': credential.username,
                'password': credential.password
            }
            
            # Submit login
            response = self.session.post(login_url, data=login_data)
            
            # Check if authentication was successful (simple check)
            if response.status_code == 200 and 'logout' in response.text.lower():
                return {"success": True, "message": "Authentication successful"}
            else:
                return {"error": "Authentication failed"}
                
        except Exception as e:
            return {"error": str(e)}

def demonstrate_secure_credential_usage():
    """Demonstrate proper usage of secure credential manager"""
    
    print("=== Secure Credential Manager Integration Examples ===\n")
    
    # 1. Setup credentials (normally done through UI)
    print("1. Setting up example credentials...")
    
    # Store example credentials
    secure_credential_manager.store_credential(
        service="shodan",
        api_key="example_shodan_key",
        notes="Shodan API for host enumeration"
    )
    
    secure_credential_manager.store_credential(
        service="aws-prod",
        username="AKIA...",
        password="secret_key",
        token="session_token",
        notes="Production AWS environment"
    )
    
    secure_credential_manager.store_credential(
        service="mysql-prod",
        username="dbuser",
        password="secure_password",
        domain="production_db",
        notes="Production MySQL database"
    )
    
    print("✓ Credentials stored securely\n")
    
    # 2. API Tool Example
    print("2. API Tool Integration:")
    api_tool = ExampleAPITool()
    
    result = api_tool.scan_with_shodan("8.8.8.8")
    if "error" in result:
        print(f"   Shodan: {result['error']}")
    else:
        print("   ✓ Shodan API call successful")
    
    result = api_tool.scan_with_virustotal("example.com")
    if "error" in result:
        print(f"   VirusTotal: {result['error']}")
    else:
        print("   ✓ VirusTotal API call successful")
    
    print()
    
    # 3. AWS Tool Example
    print("3. AWS Tool Integration:")
    aws_tool = ExampleAWSTool()
    
    success, message = aws_tool.connect_to_aws("aws-prod")
    if success:
        print(f"   ✓ AWS Connection: {message}")
        
        result = aws_tool.list_s3_buckets()
        if result.get("success"):
            print(f"   ✓ Found {len(result['buckets'])} S3 buckets")
        else:
            print(f"   S3 Error: {result['error']}")
    else:
        print(f"   AWS Error: {message}")
    
    print()
    
    # 4. Database Tool Example
    print("4. Database Tool Integration:")
    db_tool = ExampleDatabaseTool()
    
    result = db_tool.connect_to_mysql("localhost", "mysql-prod")
    if result.get("success"):
        print("   ✓ MySQL connection successful")
    else:
        print(f"   MySQL: {result['error']}")
    
    result = db_tool.connect_to_mssql("localhost", "mssql-prod")
    if result.get("success"):
        print("   ✓ MSSQL connection successful")
    else:
        print(f"   MSSQL: {result['error']}")
    
    print()
    
    # 5. Security Summary
    print("5. Security Summary:")
    summary = secure_credential_manager.get_security_summary()
    
    print(f"   Total Credentials: {summary['total_credentials']}")
    print(f"   Environment Variables: {summary['environment_credentials']}")
    print(f"   Encryption Enabled: {summary['encryption_enabled']}")
    print(f"   Secrets Manager: {summary['secrets_manager_configured']}")
    
    print("\n=== Integration Complete ===")

def demonstrate_enterprise_setup():
    """Demonstrate enterprise secrets manager setup"""
    
    print("=== Enterprise Secrets Manager Setup ===\n")
    
    # HashiCorp Vault example
    print("1. HashiCorp Vault Integration:")
    try:
        success = secure_credential_manager.configure_secrets_manager(
            provider="vault",
            vault_url="https://vault.company.com:8200",
            vault_token="hvs.XXXXXXXXXXXXXXXX"
        )
        
        if success:
            print("   ✓ Vault connection successful")
        else:
            print("   ✗ Vault connection failed")
    except Exception as e:
        print(f"   ✗ Vault setup error: {e}")
    
    # AWS Secrets Manager example
    print("\n2. AWS Secrets Manager Integration:")
    try:
        success = secure_credential_manager.configure_secrets_manager(
            provider="aws",
            region="us-east-1"
        )
        
        if success:
            print("   ✓ AWS Secrets Manager connection successful")
        else:
            print("   ✗ AWS Secrets Manager connection failed")
    except Exception as e:
        print(f"   ✗ AWS Secrets Manager setup error: {e}")
    
    # Azure Key Vault example
    print("\n3. Azure Key Vault Integration:")
    try:
        success = secure_credential_manager.configure_secrets_manager(
            provider="azure",
            vault_url="https://company-keyvault.vault.azure.net/"
        )
        
        if success:
            print("   ✓ Azure Key Vault connection successful")
        else:
            print("   ✗ Azure Key Vault connection failed")
    except Exception as e:
        print(f"   ✗ Azure Key Vault setup error: {e}")
    
    print("\n=== Enterprise Setup Complete ===")

if __name__ == "__main__":
    # Run demonstrations
    demonstrate_secure_credential_usage()
    print("\n" + "="*60 + "\n")
    demonstrate_enterprise_setup()