# app/core/exporter.py
import json
import csv
import xml.etree.ElementTree as ET
import uuid
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from app.core.logger import logger
from shared.configuration.config_manager import ConfigManager
from app.core.validators import InputValidator
from app.core.session_manager import session_manager
from infrastructure.data.repositories.sqlite_scan_repository import SQLiteScanRepository
from domain.models.scan_result import ScanResultModel, Target, ScanStatus

class ScanExporter:
    """Handles exporting scan results to various formats"""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.export_config = self.config_manager.get("export", {})
        self.scan_repository = SQLiteScanRepository()
        self._init_export_tables()
    
    def _init_export_tables(self):
        """Initialize export tracking tables."""
        import sqlite3
        try:
            with sqlite3.connect(self.scan_repository.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS export_records (
                        id TEXT PRIMARY KEY,
                        session_id TEXT,
                        scan_result_id TEXT,
                        file_path TEXT NOT NULL,
                        format TEXT NOT NULL,
                        target TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        file_size INTEGER
                    )
                """)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def export_results(self, results, target, format_type="json", filename=None, scan_type=None):
        """
        Export scan results to specified format
        Returns: (success: bool, filepath: str, error_message: str)
        """
        try:
            # Generate filename if not provided
            if not filename:
                timestamp = int(datetime.now().timestamp())
                filename = f"scan_results_{InputValidator.sanitize_filename(target)}_{timestamp}"
            
            # Create exports directory
            export_dir = Path("exports")
            export_dir.mkdir(exist_ok=True)
            
            # Check if this is a port scan and append message if needed
            if self._is_port_scan(results, scan_type):
                results = self._append_port_scan_message(results)
            
            # Export based on format
            if format_type.lower() == "json":
                filepath = self._export_json_simple(results, export_dir, filename)
            elif format_type.lower() == "csv":
                filepath = self._export_csv_simple(results, export_dir, filename)
            elif format_type.lower() == "xml":
                filepath = self._export_xml_simple(results, export_dir, filename)
            elif format_type.lower() == "html":
                filepath = self._export_html(results, export_dir, filename, target)
            else:
                return False, "", f"Unsupported export format: {format_type}"
            
            # Track export in session and database
            self._track_export(str(filepath), format_type, target)
            
            logger.info(f"Results exported to {filepath}")
            return True, str(filepath), "Export successful"
            
        except Exception as e:
            logger.error(f"Export failed: {str(e)}")
            return False, "", f"Export failed: {str(e)}"
    
    def save_results(self, results, target, format_type, project_root=None):
        """Backward compatibility method for save_results."""
        success, filepath, message = self.export_results(results, target, format_type)
        if success:
            return Path(filepath).name
        else:
            raise Exception(message)
    
    def export_scan_result(self, scan_result: ScanResultModel, format_type: str = "json") -> tuple[bool, str, str]:
        """Export a ScanResultModel using new repository interface."""
        try:
            # Convert scan result to exportable format
            results = {
                'scan_id': scan_result.id,
                'target': scan_result.target.address,
                'scanner_type': scan_result.scanner_type,
                'status': scan_result.status.value,
                'started_at': scan_result.started_at.isoformat(),
                'completed_at': scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                'data': scan_result.data,
                'vulnerabilities': [{
                    'name': v.name,
                    'description': v.description,
                    'severity': v.severity.value,
                    'cvss_score': v.cvss_score,
                    'cve_id': v.cve_id
                } for v in scan_result.vulnerabilities],
                'error_message': scan_result.error_message
            }
            
            # Export using existing method
            success, filepath, message = self.export_results(
                results, 
                scan_result.target.address, 
                format_type,
                scan_type=scan_result.scanner_type
            )
            
            # Track with scan result ID
            if success:
                self._track_export(filepath, format_type, scan_result.target.address, scan_result.id)
            
            return success, filepath, message
            
        except Exception as e:
            logger.error(f"Export scan result failed: {str(e)}")
            return False, "", f"Export failed: {str(e)}"
    
    def get_export_history(self, session_id: Optional[str] = None, limit: int = 50) -> list[Dict[str, Any]]:
        """Get export history from repository."""
        import sqlite3
        try:
            with sqlite3.connect(self.scan_repository.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                query = "SELECT * FROM export_records WHERE 1=1"
                params = []
                
                if session_id:
                    query += " AND session_id = ?"
                    params.append(session_id)
                
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get export history: {str(e)}")
            return []
    
    def _is_port_scan(self, results, scan_type=None):
        """Check if results are from a port scan"""
        if scan_type and 'port' in scan_type.lower():
            return True
        
        # Check result structure for port scan indicators
        if isinstance(results, dict):
            for host_data in results.values():
                if isinstance(host_data, dict) and 'open_ports' in host_data:
                    return True
        return False
    
    def _append_port_scan_message(self, results):
        """Append message to port scan results"""
        message = "\n\n--- Port Scan Analysis Complete ---\nThis scan identified open network services. Consider:\n• Service enumeration on discovered ports\n• Version detection for security assessment\n• Vulnerability scanning of identified services\n• Review firewall rules and access controls"
        
        if isinstance(results, dict):
            # Create a copy to avoid modifying original
            modified_results = results.copy()
            modified_results['_scan_message'] = message
            return modified_results
        
        return results
    

    
    def _export_json_simple(self, results, export_dir, filename):
        """Export results to JSON format (simple version)"""
        filepath = export_dir / f"{filename}.json"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def _export_csv_simple(self, results, export_dir, filename):
        """Export results to CSV format (simple version)"""
        filepath = export_dir / f"{filename}.csv"
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Extract message if present
            scan_message = results.pop('_scan_message', None) if isinstance(results, dict) else None
            
            # Handle flat structure (like RPC results)
            if isinstance(results, dict) and any(not isinstance(v, dict) for v in results.values()):
                writer.writerow(["Field", "Value"])
                for key, value in results.items():
                    if key == '_scan_message':
                        continue
                    if isinstance(value, list):
                        for item in value:
                            writer.writerow([key, str(item)])
                    else:
                        writer.writerow([key, str(value)])
            else:
                # Handle nested structure (like DNS results)
                writer.writerow(["Domain", "Type", "Value"])
                for domain, record_types in results.items():
                    if domain == '_scan_message':
                        continue
                    if isinstance(record_types, dict):
                        for record_type, values in record_types.items():
                            if isinstance(values, list):
                                for value in values:
                                    writer.writerow([domain, record_type, value])
                            else:
                                writer.writerow([domain, record_type, values])
                    else:
                        writer.writerow([domain, "info", str(record_types)])
            
            # Append message at the end
            if scan_message:
                writer.writerow([])
                for line in scan_message.split('\n'):
                    if line.strip():
                        writer.writerow([line.strip()])
        
        return filepath
    
    def _export_xml_simple(self, results, export_dir, filename):
        """Export results to XML format (simple version)"""
        filepath = export_dir / f"{filename}.xml"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n<scan_results>\n')
            
            # Extract message if present
            scan_message = results.pop('_scan_message', None) if isinstance(results, dict) else None
            
            # Handle flat structure (like RPC results)
            if isinstance(results, dict) and any(not isinstance(v, dict) for v in results.values()):
                for key, value in results.items():
                    if key == '_scan_message':
                        continue
                    safe_key = key.replace(' ', '_').replace(':', '').lower()
                    f.write(f'  <{safe_key}>\n')
                    if isinstance(value, list):
                        for item in value:
                            f.write(f'    <item>{self._escape_xml(str(item))}</item>\n')
                    else:
                        f.write(f'    {self._escape_xml(str(value))}\n')
                    f.write(f'  </{safe_key}>\n')
            else:
                # Handle nested structure (like DNS results)
                for domain, record_types in results.items():
                    if domain == '_scan_message':
                        continue
                    f.write(f'  <domain name="{self._escape_xml(domain)}">\n')
                    if isinstance(record_types, dict):
                        for record_type, values in record_types.items():
                            safe_type = record_type.lower().replace(' ', '_')
                            f.write(f'    <{safe_type}_records>\n')
                            if isinstance(values, list):
                                for value in values:
                                    f.write(f'      <record>{self._escape_xml(str(value))}</record>\n')
                            else:
                                f.write(f'      <record>{self._escape_xml(str(values))}</record>\n')
                            f.write(f'    </{safe_type}_records>\n')
                    else:
                        f.write(f'    <info>{self._escape_xml(str(record_types))}</info>\n')
                    f.write('  </domain>\n')
            
            # Append message at the end
            if scan_message:
                f.write('  <scan_message>\n')
                for line in scan_message.split('\n'):
                    if line.strip():
                        f.write(f'    <line>{self._escape_xml(line.strip())}</line>\n')
                f.write('  </scan_message>\n')
            
            f.write('</scan_results>\n')
        
        return filepath
    
    def _escape_xml(self, text):
        """Escape XML special characters"""
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')
    
    def _export_html(self, results, export_dir, filename, target):
        """Export source code to HTML file"""
        filepath = export_dir / f"{filename}.html"
        
        # Extract source code from results
        source_code = ""
        
        # Check if source_code exists directly in results
        if 'source_code' in results:
            source_data = results['source_code']
            if isinstance(source_data, dict) and 'source' in source_data:
                source_code = source_data['source']
            elif isinstance(source_data, str):
                source_code = source_data
        else:
            # Handle nested structure - look for source_code data
            for target_key, target_data in results.items():
                if isinstance(target_data, dict):
                    # Check if source_code exists and extract the actual source
                    if 'source_code' in target_data:
                        source_data = target_data['source_code']
                        # Handle both dict and direct string cases
                        if isinstance(source_data, dict) and 'source' in source_data:
                            source_code = source_data['source']
                            break
                        elif isinstance(source_data, str):
                            source_code = source_data
                            break
        
        # Write the HTML file
        with open(filepath, 'w', encoding='utf-8') as f:
            if source_code:
                # Check if source_code contains HTML tags (terminal output)
                if '<div style="font-family:' in source_code or '<p style=' in source_code:
                    # This is likely terminal HTML output, write as-is
                    f.write(source_code)
                else:
                    # This is raw source code, wrap in basic HTML
                    f.write(f'<!DOCTYPE html><html><head><title>Source Code - {target}</title></head><body>')
                    f.write(f'<h1>Source Code for {target}</h1>')
                    f.write('<pre>' + source_code.replace('<', '&lt;').replace('>', '&gt;') + '</pre>')
                    f.write('</body></html>')
            else:
                # Fallback - create formatted HTML report
                f.write(f'<!DOCTYPE html><html><head><title>Scan Results - {target}</title></head><body>')
                f.write(f'<h1>Scan Results for {target}</h1>')
                f.write('<pre>' + json.dumps(results, indent=2) + '</pre>')
                f.write('</body></html>')
        
        return filepath

    def _track_export(self, filepath: str, format_type: str, target: str, scan_result_id: Optional[str] = None):
        """Track export using new repository interface."""
        import sqlite3
        try:
            current_session = session_manager.get_current_session()
            session_id = current_session['id'] if current_session else None
            
            # Create export record
            export_id = str(uuid.uuid4())
            file_size = Path(filepath).stat().st_size if Path(filepath).exists() else 0
            
            # Save to database
            with sqlite3.connect(self.scan_repository.db_path) as conn:
                conn.execute("""
                    INSERT INTO export_records 
                    (id, session_id, scan_result_id, file_path, format, target, file_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (export_id, session_id, scan_result_id, filepath, format_type, target, file_size))
            
            # Add to session exports for backward compatibility
            if current_session:
                export_info = {
                    'id': export_id,
                    'file_path': filepath,
                    'format': format_type,
                    'target': target,
                    'file_size': file_size
                }
                session_manager.add_export_to_session(session_id, export_info)
                
        except Exception as e:
            logger.error(f"Failed to track export: {str(e)}")

# Global exporter instance
exporter = ScanExporter()