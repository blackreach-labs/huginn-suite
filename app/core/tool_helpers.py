# app/core/tool_helpers.py
import os
import json

def load_tool_configs():
    """Load tool configurations from JSON file"""
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'config', 'tool_configs.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)