"""Hash source updater"""

import gzip
import hashlib
import os
import requests
from typing import List, Tuple
from shared.configuration.hash_config import SOURCES, CHUNK_SIZE, MAX_DOWNLOAD_SIZE, TIMEOUT
from infrastructure.data.repositories.sqlite_hash_repository import SQLiteHashRepository

class HashSourceUpdater:
    def __init__(self, repo: SQLiteHashRepository, progress_callback=None):
        self.repo = repo
        self.progress_callback = progress_callback
        # Set download directory to hashcrack wordlists folder
        self.download_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'wordlists', 'hashcrack')
        os.makedirs(self.download_dir, exist_ok=True)
    
    def _emit_progress(self, message):
        """Emit progress message"""
        if self.progress_callback:
            self.progress_callback(message)
        else:
            print(message)
    
    def update_source(self, name: str):
        """Update hash database from source"""
        if name not in SOURCES:
            raise ValueError(f"Unknown source: {name}")
        
        # Check if source already exists
        stats = self.repo.get_stats()
        if name in stats['sources'] and stats['sources'][name] > 0:
            self._emit_progress(f"Warning: Source '{name}' already exists with {stats['sources'][name]:,} records. Re-downloading will only add new entries.")
        
        src = SOURCES[name]
        file_path = self._download(src['url'])
        
        if not self._verify_checksum(file_path, src['checksum']):
            print(f"Warning: Checksum mismatch for {name}")
        
        try:
            records = self._parse_and_prepare(file_path, name, src['format'])
            
            # Get initial count to track actual new records
            initial_count = stats.get('sources', {}).get(name, 0)
            
            # Insert in chunks with progress
            self._emit_progress(f"Processing {len(records):,} records (duplicates will be ignored)...")
            total_chunks = (len(records) + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            for i in range(0, len(records), CHUNK_SIZE):
                chunk = records[i:i + CHUNK_SIZE]
                self.repo.bulk_insert(chunk)
                
                chunk_num = (i // CHUNK_SIZE) + 1
                if chunk_num % 10 == 0 or chunk_num == total_chunks:
                    self._emit_progress(f"Processed chunk {chunk_num}/{total_chunks} ({(chunk_num/total_chunks)*100:.1f}%)")
            
            # Get final count to show actual new records
            final_stats = self.repo.get_stats()
            final_count = final_stats.get('sources', {}).get(name, 0)
            new_records = final_count - initial_count
            
            if new_records == 0:
                self._emit_progress("No new records added - all entries were duplicates")
            else:
                self._emit_progress(f"Database update completed - {new_records:,} new records added")
            
            return new_records
        finally:
            # Always delete the downloaded file after processing
            if os.path.exists(file_path):
                self._emit_progress(f"Cleaning up downloaded file: {os.path.basename(file_path)}")
                os.remove(file_path)
    
    def _download(self, url: str) -> str:
        """Download file from URL with safety checks"""
        filename = url.split('/')[-1]
        if not filename:
            filename = "download.txt"
        
        # Download to hashcrack directory
        file_path = os.path.join(self.download_dir, filename)
        self._emit_progress(f"Downloading {filename} to {self.download_dir}...")
        
        response = requests.get(url, stream=True, timeout=TIMEOUT)
        response.raise_for_status()
        
        # Check content length
        content_length = response.headers.get('content-length')
        if content_length and int(content_length) > MAX_DOWNLOAD_SIZE:
            raise ValueError(f"File too large: {content_length} bytes (max: {MAX_DOWNLOAD_SIZE})")
        
        downloaded = 0
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if downloaded > MAX_DOWNLOAD_SIZE:
                        os.remove(file_path)
                        raise ValueError(f"Download exceeded size limit: {MAX_DOWNLOAD_SIZE} bytes")
        
        self._emit_progress(f"Downloaded {downloaded:,} bytes to {file_path}")
        return file_path
    
    def _verify_checksum(self, file_path: str, expected: str) -> bool:
        """Verify file checksum"""
        if len(expected) < 10:  # Skip placeholder checksums
            self._emit_progress("Warning: Skipping checksum verification (placeholder checksum)")
            return True
            
        self._emit_progress("Verifying file integrity...")
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        actual = sha256_hash.hexdigest()
        if actual != expected:
            self._emit_progress(f"Checksum mismatch: expected {expected}, got {actual}")
            return False
        
        self._emit_progress("Checksum verified")
        return True
    
    def _parse_and_prepare(self, file_path: str, source: str, format_type: str) -> List[Tuple[str, str, str]]:
        """Parse file and prepare records"""
        records = []
        line_count = 0
        
        self._emit_progress(f"Parsing {file_path}...")
        
        if file_path.endswith('.gz'):
            open_func = gzip.open
        else:
            open_func = open
        
        with open_func(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                line_count += 1
                if line_count % 50000 == 0:
                    self._emit_progress(f"Processed {line_count:,} passwords...")
                
                if format_type == "plaintext_list":
                    # Generate common hash types for plaintext
                    plaintext = line
                    md5_hash = hashlib.md5(plaintext.encode()).hexdigest()
                    sha1_hash = hashlib.sha1(plaintext.encode()).hexdigest()
                    records.extend([
                        (md5_hash, plaintext, source),
                        (sha1_hash, plaintext, source)
                    ])
                elif format_type == "hash_plain":
                    # Format: hash:plaintext
                    if ':' in line:
                        hash_val, plaintext = line.split(':', 1)
                        records.append((hash_val, plaintext, source))
        
        self._emit_progress(f"Parsed {line_count:,} passwords, generated {len(records):,} hash records")
        return records