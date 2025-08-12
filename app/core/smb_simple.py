"""
Simplified SMB client using smbprotocol library
"""
try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

class SimpleSMBClient:
    def __init__(self):
        self.connection = None
        self.session = None
        self.tree = None
        
    def connect(self, target, domain, username, password):
        """Connect using smbprotocol"""
        if not SMB_AVAILABLE:
            return False
            
        try:
            # Create connection
            self.connection = Connection(uuid.uuid4(), target, 445)
            self.connection.connect()
            
            # Create session
            self.session = Session(self.connection, username, password, domain)
            self.session.connect()
            
            # Connect to IPC$
            self.tree = TreeConnect(self.session, f"\\\\{target}\\IPC$")
            self.tree.connect()
            
            return True
            
        except Exception as e:
            print(f"SMB connection failed: {e}")
            return False
    
    def disconnect(self):
        """Clean disconnect"""
        try:
            if self.tree:
                self.tree.disconnect()
            if self.session:
                self.session.disconnect()
            if self.connection:
                self.connection.disconnect()
        except:
            pass