"""Hash record domain model"""

class HashRecord:
    def __init__(self, hash_value: str, plaintext: str, source: str):
        self.hash_value = hash_value
        self.plaintext = plaintext
        self.source = source
    
    def __repr__(self):
        return f"HashRecord(hash={self.hash_value[:8]}..., plaintext={self.plaintext}, source={self.source})"