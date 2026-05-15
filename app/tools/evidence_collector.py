#!/usr/bin/env python3
"""
Post-Exploitation Evidence & Forensics Collector
Standardized POC capture modules with encryption and chain-of-custody
"""

import os
import json
import time
import hashlib
import subprocess
import sqlite3
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid
from cryptography.fernet import Fernet
import base64

@dataclass
class EvidenceItem:
    evidence_id: str
    evidence_type: str
    source_system: str
    collection_method: str
    file_path: str
    file_hash: str
    file_size: int
    collected_at: str
    collector_info: Dict[str, Any]
    chain_of_custody: List[Dict[str, Any]]
    metadata: Dict[str, Any]

class EvidenceCollector:
    def __init__(self, case_id: str = None, evidence_dir: str = "evidence"):
        self.case_id = case_id or f"case_{int(time.time())}"
        self.evidence_dir = Path(evidence_dir) / self.case_id
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize encryption
        self.encryption_key = self._generate_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Initialize database
        self.db_path = self.evidence_dir / "evidence_catalog.db"
        self._init_database()
        
        # Collector information
        self.collector_info = {
            'tool': 'Huginn Evidence Collector',
            'version': '1.0',
            'operator': os.getenv('USERNAME', 'unknown'),
            'hostname': os.getenv('COMPUTERNAME', 'unknown')
        }
    
    def _generate_encryption_key(self) -> bytes:
        """Generate or load encryption key"""
        key_file = self.evidence_dir / "evidence.key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def _init_database(self):
        """Initialize evidence catalog database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_items (
                evidence_id TEXT PRIMARY KEY,
                evidence_type TEXT NOT NULL,
                source_system TEXT NOT NULL,
                collection_method TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                collected_at TEXT NOT NULL,
                collector_info TEXT NOT NULL,
                chain_of_custody TEXT NOT NULL,
                metadata TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS collection_sessions (
                session_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                evidence_count INTEGER DEFAULT 0,
                total_size INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def collect_process_snapshot(self, detailed: bool = False) -> EvidenceItem:
        """Collect running processes snapshot"""
        evidence_id = str(uuid.uuid4())
        
        try:
            if detailed:
                # Detailed process information
                ps_command = '''
                Get-Process | Select-Object Name, Id, CPU, WorkingSet, VirtualMemorySize, 
                Path, Company, ProductVersion, FileVersion, StartTime, Threads |
                ConvertTo-Json -Depth 3
                '''
            else:
                # Basic process list
                ps_command = '''
                Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path |
                ConvertTo-Json
                '''
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Save raw output
                output_file = self.evidence_dir / f"processes_{evidence_id}.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
                
                # Encrypt and store
                encrypted_file = self._encrypt_file(output_file)
                
                evidence = EvidenceItem(
                    evidence_id=evidence_id,
                    evidence_type='process_snapshot',
                    source_system=self.collector_info['hostname'],
                    collection_method='PowerShell Get-Process',
                    file_path=str(encrypted_file),
                    file_hash=self._calculate_file_hash(encrypted_file),
                    file_size=encrypted_file.stat().st_size,
                    collected_at=datetime.now().isoformat(),
                    collector_info=self.collector_info,
                    chain_of_custody=[self._create_custody_entry('collected')],
                    metadata={'detailed': detailed, 'process_count': len(json.loads(result.stdout))}
                )
                
                self._store_evidence(evidence)
                return evidence
            
        except Exception as e:
            print(f"Process collection error: {e}")
        
        return None
    
    def collect_event_logs(self, log_names: List[str], hours_back: int = 24, 
                          max_events: int = 1000) -> EvidenceItem:
        """Collect Windows Event Logs"""
        evidence_id = str(uuid.uuid4())
        
        try:
            all_events = []
            
            for log_name in log_names:
                ps_command = f'''
                Get-WinEvent -LogName "{log_name}" -MaxEvents {max_events} |
                Where-Object {{$_.TimeCreated -gt (Get-Date).AddHours(-{hours_back})}} |
                Select-Object TimeCreated, Id, LevelDisplayName, LogName, Message, UserId |
                ConvertTo-Json -Depth 2
                '''
                
                result = subprocess.run(
                    ["powershell", "-Command", ps_command],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        events = json.loads(result.stdout)
                        if isinstance(events, dict):
                            events = [events]
                        all_events.extend(events)
                    except json.JSONDecodeError:
                        continue
            
            if all_events:
                # Save events
                output_file = self.evidence_dir / f"eventlogs_{evidence_id}.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(all_events, f, indent=2, default=str)
                
                # Encrypt and store
                encrypted_file = self._encrypt_file(output_file)
                
                evidence = EvidenceItem(
                    evidence_id=evidence_id,
                    evidence_type='event_logs',
                    source_system=self.collector_info['hostname'],
                    collection_method='PowerShell Get-WinEvent',
                    file_path=str(encrypted_file),
                    file_hash=self._calculate_file_hash(encrypted_file),
                    file_size=encrypted_file.stat().st_size,
                    collected_at=datetime.now().isoformat(),
                    collector_info=self.collector_info,
                    chain_of_custody=[self._create_custody_entry('collected')],
                    metadata={
                        'log_names': log_names,
                        'hours_back': hours_back,
                        'event_count': len(all_events)
                    }
                )
                
                self._store_evidence(evidence)
                return evidence
            
        except Exception as e:
            print(f"Event log collection error: {e}")
        
        return None
    
    def collect_screenshots(self, count: int = 1, interval: int = 2) -> EvidenceItem:
        """Collect desktop screenshots"""
        evidence_id = str(uuid.uuid4())
        
        try:
            import PIL.ImageGrab as ImageGrab
            
            screenshots = []
            screenshot_dir = self.evidence_dir / f"screenshots_{evidence_id}"
            screenshot_dir.mkdir(exist_ok=True)
            
            for i in range(count):
                screenshot = ImageGrab.grab()
                filename = f"screenshot_{i+1:03d}.png"
                screenshot_path = screenshot_dir / filename
                screenshot.save(screenshot_path)
                screenshots.append(str(screenshot_path))
                
                if i < count - 1:
                    time.sleep(interval)
            
            # Create archive
            archive_path = self.evidence_dir / f"screenshots_{evidence_id}.zip"
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for screenshot_path in screenshots:
                    zipf.write(screenshot_path, Path(screenshot_path).name)
            
            # Encrypt archive
            encrypted_file = self._encrypt_file(archive_path)
            
            evidence = EvidenceItem(
                evidence_id=evidence_id,
                evidence_type='screenshots',
                source_system=self.collector_info['hostname'],
                collection_method='PIL ImageGrab',
                file_path=str(encrypted_file),
                file_hash=self._calculate_file_hash(encrypted_file),
                file_size=encrypted_file.stat().st_size,
                collected_at=datetime.now().isoformat(),
                collector_info=self.collector_info,
                chain_of_custody=[self._create_custody_entry('collected')],
                metadata={'screenshot_count': count, 'interval': interval}
            )
            
            self._store_evidence(evidence)
            return evidence
            
        except Exception as e:
            print(f"Screenshot collection error: {e}")
        
        return None
    
    def collect_network_info(self) -> EvidenceItem:
        """Collect network configuration and connections"""
        evidence_id = str(uuid.uuid4())
        
        try:
            network_info = {}
            
            # Network configuration
            ps_commands = {
                'interfaces': 'Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed | ConvertTo-Json',
                'ip_config': 'Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer | ConvertTo-Json',
                'connections': 'Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | ConvertTo-Json',
                'routes': 'Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric | ConvertTo-Json'
            }
            
            for info_type, command in ps_commands.items():
                try:
                    result = subprocess.run(
                        ["powershell", "-Command", command],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        network_info[info_type] = json.loads(result.stdout)
                        
                except Exception as e:
                    network_info[info_type] = f"Collection error: {e}"
            
            # Save network info
            output_file = self.evidence_dir / f"network_info_{evidence_id}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(network_info, f, indent=2, default=str)
            
            # Encrypt and store
            encrypted_file = self._encrypt_file(output_file)
            
            evidence = EvidenceItem(
                evidence_id=evidence_id,
                evidence_type='network_info',
                source_system=self.collector_info['hostname'],
                collection_method='PowerShell Network Cmdlets',
                file_path=str(encrypted_file),
                file_hash=self._calculate_file_hash(encrypted_file),
                file_size=encrypted_file.stat().st_size,
                collected_at=datetime.now().isoformat(),
                collector_info=self.collector_info,
                chain_of_custody=[self._create_custody_entry('collected')],
                metadata={'info_types': list(network_info.keys())}
            )
            
            self._store_evidence(evidence)
            return evidence
            
        except Exception as e:
            print(f"Network info collection error: {e}")
        
        return None
    
    def collect_file_sample(self, file_path: str, description: str = "") -> EvidenceItem:
        """Collect a file sample with metadata"""
        evidence_id = str(uuid.uuid4())
        
        try:
            source_path = Path(file_path)
            if not source_path.exists():
                return None
            
            # Copy file to evidence directory
            evidence_file = self.evidence_dir / f"file_sample_{evidence_id}_{source_path.name}"
            
            # Read and copy file
            with open(source_path, 'rb') as src, open(evidence_file, 'wb') as dst:
                dst.write(src.read())
            
            # Get file metadata
            stat_info = source_path.stat()
            file_metadata = {
                'original_path': str(source_path),
                'file_size': stat_info.st_size,
                'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'description': description
            }
            
            # Encrypt file
            encrypted_file = self._encrypt_file(evidence_file)
            
            evidence = EvidenceItem(
                evidence_id=evidence_id,
                evidence_type='file_sample',
                source_system=self.collector_info['hostname'],
                collection_method='File Copy',
                file_path=str(encrypted_file),
                file_hash=self._calculate_file_hash(encrypted_file),
                file_size=encrypted_file.stat().st_size,
                collected_at=datetime.now().isoformat(),
                collector_info=self.collector_info,
                chain_of_custody=[self._create_custody_entry('collected')],
                metadata=file_metadata
            )
            
            self._store_evidence(evidence)
            return evidence
            
        except Exception as e:
            print(f"File collection error: {e}")
        
        return None
    
    def collect_command_output(self, command: str, description: str = "") -> EvidenceItem:
        """Collect output from a command execution.
        
        Args:
            command: Command as a list of strings, e.g. ['ipconfig', '/all'].
                     A plain string is accepted but will be split via shlex —
                     shell=True is intentionally avoided to prevent injection.
            description: Human-readable description of what this command collects.
        """
        evidence_id = str(uuid.uuid4())
        
        try:
            import shlex
            cmd = shlex.split(command) if isinstance(command, str) else command

            # Execute command — shell=False prevents metacharacter injection
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Prepare output data
            output_data = {
                'command': command,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'execution_time': datetime.now().isoformat(),
                'description': description
            }
            
            # Save output
            output_file = self.evidence_dir / f"command_output_{evidence_id}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2)
            
            # Encrypt and store
            encrypted_file = self._encrypt_file(output_file)
            
            evidence = EvidenceItem(
                evidence_id=evidence_id,
                evidence_type='command_output',
                source_system=self.collector_info['hostname'],
                collection_method='Command Execution',
                file_path=str(encrypted_file),
                file_hash=self._calculate_file_hash(encrypted_file),
                file_size=encrypted_file.stat().st_size,
                collected_at=datetime.now().isoformat(),
                collector_info=self.collector_info,
                chain_of_custody=[self._create_custody_entry('collected')],
                metadata={'command': command, 'return_code': result.returncode}
            )
            
            self._store_evidence(evidence)
            return evidence
            
        except Exception as e:
            print(f"Command execution error: {e}")
        
        return None
    
    def _encrypt_file(self, file_path: Path) -> Path:
        """Encrypt a file and return encrypted file path"""
        encrypted_path = file_path.with_suffix(file_path.suffix + '.enc')
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = self.cipher.encrypt(file_data)
        
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Remove original file
        file_path.unlink()
        
        return encrypted_path
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _create_custody_entry(self, action: str) -> Dict[str, Any]:
        """Create chain of custody entry"""
        return {
            'action': action,
            'timestamp': datetime.now().isoformat(),
            'operator': self.collector_info['operator'],
            'system': self.collector_info['hostname']
        }
    
    def _store_evidence(self, evidence: EvidenceItem):
        """Store evidence item in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO evidence_items 
            (evidence_id, evidence_type, source_system, collection_method, file_path,
             file_hash, file_size, collected_at, collector_info, chain_of_custody, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            evidence.evidence_id,
            evidence.evidence_type,
            evidence.source_system,
            evidence.collection_method,
            evidence.file_path,
            evidence.file_hash,
            evidence.file_size,
            evidence.collected_at,
            json.dumps(evidence.collector_info),
            json.dumps(evidence.chain_of_custody),
            json.dumps(evidence.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def get_evidence_catalog(self) -> List[EvidenceItem]:
        """Get all evidence items"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM evidence_items ORDER BY collected_at DESC")
        rows = cursor.fetchall()
        conn.close()
        
        evidence_items = []
        for row in rows:
            evidence = EvidenceItem(
                evidence_id=row[0],
                evidence_type=row[1],
                source_system=row[2],
                collection_method=row[3],
                file_path=row[4],
                file_hash=row[5],
                file_size=row[6],
                collected_at=row[7],
                collector_info=json.loads(row[8]),
                chain_of_custody=json.loads(row[9]),
                metadata=json.loads(row[10])
            )
            evidence_items.append(evidence)
        
        return evidence_items
    
    def decrypt_evidence(self, evidence_id: str, output_path: str = None) -> Optional[str]:
        """Decrypt evidence file for analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT file_path FROM evidence_items WHERE evidence_id = ?", (evidence_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        encrypted_path = Path(result[0])
        if not encrypted_path.exists():
            return None
        
        # Decrypt file
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = self.cipher.decrypt(encrypted_data)
        
        # Save decrypted file
        if not output_path:
            output_path = str(encrypted_path).replace('.enc', '_decrypted')
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        return output_path
    
    def generate_evidence_report(self) -> Dict[str, Any]:
        """Generate evidence collection report"""
        evidence_items = self.get_evidence_catalog()
        
        report = {
            'case_id': self.case_id,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_items': len(evidence_items),
                'total_size': sum(item.file_size for item in evidence_items),
                'evidence_types': {}
            },
            'evidence_items': []
        }
        
        # Count by type
        for item in evidence_items:
            if item.evidence_type not in report['summary']['evidence_types']:
                report['summary']['evidence_types'][item.evidence_type] = 0
            report['summary']['evidence_types'][item.evidence_type] += 1
            
            # Add to items list (without sensitive data)
            report['evidence_items'].append({
                'evidence_id': item.evidence_id,
                'evidence_type': item.evidence_type,
                'collected_at': item.collected_at,
                'file_size': item.file_size,
                'file_hash': item.file_hash,
                'metadata': item.metadata
            })
        
        return report

# Example usage
if __name__ == "__main__":
    # Example evidence collection
    collector = EvidenceCollector("test_case_001")
    
    print("Collecting evidence...")
    
    # Collect process snapshot
    process_evidence = collector.collect_process_snapshot(detailed=True)
    if process_evidence:
        print(f"Process evidence collected: {process_evidence.evidence_id}")
    
    # Collect event logs
    event_evidence = collector.collect_event_logs(["System", "Security"], hours_back=1)
    if event_evidence:
        print(f"Event log evidence collected: {event_evidence.evidence_id}")
    
    # Collect screenshots
    screenshot_evidence = collector.collect_screenshots(count=2)
    if screenshot_evidence:
        print(f"Screenshot evidence collected: {screenshot_evidence.evidence_id}")
    
    # Generate report
    report = collector.generate_evidence_report()
    print(f"Evidence Report: {json.dumps(report, indent=2)}")