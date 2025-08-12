# tests/test_validators.py
import unittest
from app.core.validators import InputValidator, ValidationError

class TestInputValidator(unittest.TestCase):
    
    def setUp(self):
        self.validator = InputValidator()
    
    def test_valid_ip(self):
        self.assertTrue(self.validator.validate_ip("192.168.1.1"))
        self.assertTrue(self.validator.validate_ip("10.0.0.1"))
    
    def test_invalid_ip(self):
        with self.assertRaises(ValidationError):
            self.validator.validate_ip("256.1.1.1")
        with self.assertRaises(ValidationError):
            self.validator.validate_ip("invalid")
    
    def test_valid_domain(self):
        self.assertTrue(self.validator.validate_domain("example.com"))
        self.assertTrue(self.validator.validate_domain("sub.example.org"))
    
    def test_invalid_domain(self):
        with self.assertRaises(ValidationError):
            self.validator.validate_domain(""))
        with self.assertRaises(ValidationError):
            self.validator.validate_domain("invalid..domain")

if __name__ == '__main__':
    unittest.main()