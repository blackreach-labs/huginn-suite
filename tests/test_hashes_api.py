#!/usr/bin/env python3
"""Test script for hashes.com API"""

import requests

# Test the API key with a known hash
api_key = "4c654682b2af0433afb5369cf925d1a4"
test_hash = "e10adc3949ba59abbe56e057f20f883e"  # MD5 of "123456"

# Method 1: Using files parameter (multipart/form-data)
print("Testing with files parameter:")
files = {
    'key': (None, api_key),
    'hashes[]': (None, test_hash)
}

resp = requests.post('https://hashes.com/en/api/search', files=files)
print(f"Status: {resp.status_code}")
print(f"Response: {resp.text}")
print()

# Method 2: Using data parameter with dict
print("Testing with data dict:")
data = {
    'key': api_key,
    'hashes[]': test_hash
}

resp = requests.post('https://hashes.com/en/api/search', data=data)
print(f"Status: {resp.status_code}")
print(f"Response: {resp.text}")
print()

# Method 3: Manual form encoding
print("Testing with manual form encoding:")
import urllib.parse
form_data = urllib.parse.urlencode([
    ('key', api_key),
    ('hashes[]', test_hash)
])
headers = {'Content-Type': 'application/x-www-form-urlencoded'}

resp = requests.post('https://hashes.com/en/api/search', data=form_data, headers=headers)
print(f"Status: {resp.status_code}")
print(f"Response: {resp.text}")