# app/core/wordlist_manager.py
import os
from typing import Dict, List, Tuple

class WordlistManager:
    """Manages SecLists wordlist integration with presets and auto-loading"""
    
    def __init__(self, project_root: str):
        self.project_root = project_root
        self.wordlist_base = os.path.join(project_root, "resources", "wordlists")
        
        # SecLists preset configurations
        self.presets = {
            "PHP Apps": {
                "directories": ["php-common.txt", "directory-list-2.3-small.txt"],
                "files": ["php-files.txt", "common.txt"],
                "extensions": [".php", ".phtml", ".php3", ".php4", ".php5"]
            },
            "API-focused": {
                "directories": ["api-endpoints.txt", "rest-api.txt"],
                "files": ["api-common.txt", "swagger-paths.txt"],
                "extensions": [".json", ".xml", ".api", ""]
            },
            "Login Pages": {
                "directories": ["admin-panels.txt", "login-paths.txt"],
                "files": ["admin-common.txt", "login-forms.txt"],
                "extensions": [".php", ".asp", ".aspx", ".jsp", ".html"]
            },
            "Backup Files": {
                "directories": ["backup-dirs.txt"],
                "files": ["backup-files.txt", "config-files.txt"],
                "extensions": [".bak", ".backup", ".old", ".tmp", ".conf"]
            },
            "CMS Common": {
                "directories": ["cms-common.txt", "wordpress.txt"],
                "files": ["cms-files.txt", "wp-common.txt"],
                "extensions": [".php", ".html", ".js", ".css"]
            }
        }
        
        # Size categories for auto-loading
        self.size_categories = {
            "Small": {"max_lines": 1000, "suffix": "-small.txt"},
            "Medium": {"max_lines": 10000, "suffix": "-medium.txt"},
            "Large": {"max_lines": 50000, "suffix": "-large.txt"}
        }
    
    def get_available_presets(self) -> List[str]:
        """Get list of available wordlist presets"""
        return list(self.presets.keys())
    
    def get_preset_config(self, preset_name: str) -> Dict:
        """Get configuration for a specific preset"""
        return self.presets.get(preset_name, {})
    
    def find_wordlist_files(self, category: str = None) -> List[Tuple[str, str]]:
        """Find available wordlist files, optionally filtered by category"""
        wordlists = []
        
        if not os.path.exists(self.wordlist_base):
            return wordlists
        
        # Scan wordlist directory
        for root, dirs, files in os.walk(self.wordlist_base):
            for file in files:
                if file.endswith('.txt'):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.wordlist_base)
                    
                    # Categorize by directory structure
                    if category:
                        if category.lower() in rel_path.lower():
                            wordlists.append((file, full_path))
                    else:
                        wordlists.append((file, full_path))
        
        return sorted(wordlists)
    
    def get_wordlist_by_size(self, base_name: str, size: str) -> str:
        """Get wordlist path by size preference (Small/Medium/Large)"""
        if size not in self.size_categories:
            size = "Medium"
        
        suffix = self.size_categories[size]["suffix"]
        
        # Try to find file with size suffix
        size_file = base_name.replace(".txt", suffix)
        size_path = os.path.join(self.wordlist_base, size_file)
        
        if os.path.exists(size_path):
            return size_path
        
        # Fallback to original file
        original_path = os.path.join(self.wordlist_base, base_name)
        if os.path.exists(original_path):
            return original_path
        
        return None
    
    def get_preset_wordlists(self, preset_name: str, size: str = "Medium") -> Dict[str, List[str]]:
        """Get wordlist paths for a preset configuration"""
        preset = self.presets.get(preset_name, {})
        if not preset:
            return {}
        
        result = {"directories": [], "files": [], "extensions": preset.get("extensions", [])}
        
        # Find directory wordlists
        for wordlist in preset.get("directories", []):
            path = self.get_wordlist_by_size(wordlist, size)
            if path:
                result["directories"].append(path)
        
        # Find file wordlists
        for wordlist in preset.get("files", []):
            path = self.get_wordlist_by_size(wordlist, size)
            if path:
                result["files"].append(path)
        
        return result
    
    def create_combined_wordlist(self, wordlist_paths: List[str], output_name: str = None) -> str:
        """Combine multiple wordlists into a single temporary file"""
        if not wordlist_paths:
            return None
        
        if not output_name:
            output_name = "combined_wordlist.txt"
        
        output_path = os.path.join(self.wordlist_base, "temp", output_name)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        combined_entries = set()
        
        # Read all wordlists and combine unique entries
        for wordlist_path in wordlist_paths:
            if os.path.exists(wordlist_path):
                try:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            entry = line.strip()
                            if entry and not entry.startswith('#'):
                                combined_entries.add(entry)
                except Exception:
                    continue
        
        # Write combined wordlist
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                for entry in sorted(combined_entries):
                    f.write(f"{entry}\n")
            return output_path
        except Exception:
            return None
    
    def get_wordlist_info(self, wordlist_path: str) -> Dict:
        """Get information about a wordlist file"""
        if not os.path.exists(wordlist_path):
            return {}
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            return {
                "path": wordlist_path,
                "name": os.path.basename(wordlist_path),
                "size": len(lines),
                "file_size": os.path.getsize(wordlist_path),
                "category": self._categorize_wordlist(wordlist_path)
            }
        except Exception:
            return {}
    
    def _categorize_wordlist(self, wordlist_path: str) -> str:
        """Categorize wordlist based on path and filename"""
        path_lower = wordlist_path.lower()
        
        if any(term in path_lower for term in ['api', 'rest', 'graphql']):
            return "API"
        elif any(term in path_lower for term in ['admin', 'login', 'auth']):
            return "Authentication"
        elif any(term in path_lower for term in ['php', 'asp', 'jsp']):
            return "Web Applications"
        elif any(term in path_lower for term in ['backup', 'config', 'old']):
            return "Backup/Config"
        elif any(term in path_lower for term in ['directory', 'dir', 'folder']):
            return "Directories"
        else:
            return "General"

# Global instance
wordlist_manager = None

def get_wordlist_manager(project_root: str = None) -> WordlistManager:
    """Get global wordlist manager instance"""
    global wordlist_manager
    if wordlist_manager is None and project_root:
        wordlist_manager = WordlistManager(project_root)
    return wordlist_manager