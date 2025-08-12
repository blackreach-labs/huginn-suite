#!/usr/bin/env python3
import argparse
import json
import sys
from abc import ABC, abstractmethod
from .input_validator import InputValidator
from .credential_manager import CredentialManager

class BaseTool(ABC):
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.validator = InputValidator()
        self.cred_manager = CredentialManager()
        self.results = []
        self.output_format = 'text'
    
    def setup_parser(self):
        """Setup common argument parser"""
        parser = argparse.ArgumentParser(description=self.description)
        parser.add_argument('--output', choices=['text', 'json', 'xml'], 
                          default='text', help='Output format')
        parser.add_argument('--timeout', type=int, default=10, 
                          help='Connection timeout in seconds')
        parser.add_argument('--verbose', '-v', action='store_true', 
                          help='Verbose output')
        return parser
    
    def validate_target(self, target):
        """Validate target input"""
        if self.validator.validate_ip(target):
            return target
        elif self.validator.validate_hostname(target):
            return target
        else:
            raise ValueError(f"Invalid target: {target}")
    
    def validate_port(self, port):
        """Validate port input"""
        if not self.validator.validate_port(port):
            raise ValueError(f"Invalid port: {port}")
        return int(port)
    
    def add_result(self, result_type, message, data=None):
        """Add structured result"""
        result = {
            'type': result_type,
            'message': message,
            'timestamp': self._get_timestamp(),
            'data': data or {}
        }
        self.results.append(result)
        
        if self.output_format == 'text':
            self._print_text_result(result)
    
    def _print_text_result(self, result):
        """Print result in text format"""
        prefix = {
            'success': '[+]',
            'error': '[-]',
            'info': '[*]',
            'warning': '[!]'
        }.get(result['type'], '[?]')
        
        print(f"{prefix} {result['message']}")
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def output_results(self):
        """Output results in specified format"""
        if self.output_format == 'json':
            print(json.dumps(self.results, indent=2))
        elif self.output_format == 'xml':
            self._output_xml()
    
    def _output_xml(self):
        """Output results in XML format"""
        print('<?xml version="1.0" encoding="UTF-8"?>')
        print(f'<{self.name}_results>')
        for result in self.results:
            print(f'  <result type="{result["type"]}" timestamp="{result["timestamp"]}">')
            print(f'    <message>{result["message"]}</message>')
            if result['data']:
                print('    <data>')
                for key, value in result['data'].items():
                    print(f'      <{key}>{value}</{key}>')
                print('    </data>')
            print('  </result>')
        print(f'</{self.name}_results>')
    
    def handle_error(self, error, context=""):
        """Handle errors consistently"""
        error_msg = f"{context}: {str(error)}" if context else str(error)
        self.add_result('error', error_msg)
        if self.output_format == 'text':
            return  # Already printed
    
    @abstractmethod
    def run(self, args):
        """Main execution method - must be implemented by subclasses"""
        pass
    
    def execute(self):
        """Execute the tool with error handling"""
        try:
            parser = self.setup_parser()
            self.add_custom_args(parser)
            args = parser.parse_args()
            
            self.output_format = args.output
            
            self.run(args)
            
            if self.output_format != 'text':
                self.output_results()
                
        except KeyboardInterrupt:
            self.add_result('warning', 'Operation interrupted by user')
            sys.exit(1)
        except Exception as e:
            self.handle_error(e, 'Execution failed')
            sys.exit(1)
    
    @abstractmethod
    def add_custom_args(self, parser):
        """Add tool-specific arguments - must be implemented by subclasses"""
        pass