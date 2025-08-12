# app/core/result_filter.py
import re
from typing import Dict, List, Any, Callable
from datetime import datetime

class ResultFilter:
    """Advanced result filtering and search functionality"""
    
    def __init__(self):
        self.filters = {}
        self.search_operators = {
            'contains': self._contains,
            'equals': self._equals,
            'starts_with': self._starts_with,
            'ends_with': self._ends_with,
            'regex': self._regex,
            'greater_than': self._greater_than,
            'less_than': self._less_than,
            'between': self._between
        }
    
    def filter_results(self, results: List[Dict], filters: Dict) -> List[Dict]:
        """Filter results based on criteria"""
        
        if not results or not filters:
            return results
        
        filtered = []
        
        for result in results:
            if self._matches_filters(result, filters):
                filtered.append(result)
        
        return filtered
    
    def search_results(self, results: List[Dict], query: str, fields: List[str] = None) -> List[Dict]:
        """Search results with text query"""
        
        if not results or not query:
            return results
        
        query = query.lower().strip()
        matched = []
        
        for result in results:
            if self._matches_search(result, query, fields):
                matched.append(result)
        
        return matched
    
    def create_filter_criteria(self, field: str, operator: str, value: Any) -> Dict:
        """Create filter criteria"""
        
        return {
            'field': field,
            'operator': operator,
            'value': value
        }
    
    def apply_multiple_filters(self, results: List[Dict], filter_list: List[Dict], 
                             logic: str = 'AND') -> List[Dict]:
        """Apply multiple filters with AND/OR logic"""
        
        if not results or not filter_list:
            return results
        
        filtered = []
        
        for result in results:
            if logic.upper() == 'AND':
                if all(self._matches_single_filter(result, f) for f in filter_list):
                    filtered.append(result)
            else:  # OR logic
                if any(self._matches_single_filter(result, f) for f in filter_list):
                    filtered.append(result)
        
        return filtered
    
    def sort_results(self, results: List[Dict], sort_field: str, 
                    reverse: bool = False) -> List[Dict]:
        """Sort results by field"""
        
        try:
            return sorted(results, 
                         key=lambda x: self._get_nested_value(x, sort_field) or '', 
                         reverse=reverse)
        except Exception:
            return results
    
    def group_results(self, results: List[Dict], group_field: str) -> Dict[str, List[Dict]]:
        """Group results by field value"""
        
        groups = {}
        
        for result in results:
            group_value = str(self._get_nested_value(result, group_field) or 'Unknown')
            
            if group_value not in groups:
                groups[group_value] = []
            
            groups[group_value].append(result)
        
        return groups
    
    def get_unique_values(self, results: List[Dict], field: str) -> List[str]:
        """Get unique values for a field"""
        
        values = set()
        
        for result in results:
            value = self._get_nested_value(result, field)
            if value is not None:
                values.add(str(value))
        
        return sorted(list(values))
    
    def create_summary_stats(self, results: List[Dict]) -> Dict:
        """Create summary statistics for results"""
        
        if not results:
            return {}
        
        stats = {
            'total_results': len(results),
            'field_stats': {},
            'common_fields': []
        }
        
        # Analyze common fields
        all_fields = set()
        for result in results:
            all_fields.update(self._get_all_fields(result))
        
        stats['common_fields'] = sorted(list(all_fields))
        
        # Field-specific statistics
        for field in stats['common_fields']:
            values = [self._get_nested_value(r, field) for r in results]
            values = [v for v in values if v is not None]
            
            if values:
                stats['field_stats'][field] = {
                    'count': len(values),
                    'unique_count': len(set(str(v) for v in values)),
                    'sample_values': list(set(str(v) for v in values))[:5]
                }
        
        return stats
    
    def _matches_filters(self, result: Dict, filters: Dict) -> bool:
        """Check if result matches all filters"""
        
        for field, criteria in filters.items():
            if not self._matches_field_criteria(result, field, criteria):
                return False
        
        return True
    
    def _matches_single_filter(self, result: Dict, filter_criteria: Dict) -> bool:
        """Check if result matches single filter"""
        
        field = filter_criteria.get('field')
        operator = filter_criteria.get('operator')
        value = filter_criteria.get('value')
        
        result_value = self._get_nested_value(result, field)
        
        if operator in self.search_operators:
            return self.search_operators[operator](result_value, value)
        
        return False
    
    def _matches_field_criteria(self, result: Dict, field: str, criteria: Dict) -> bool:
        """Check if field matches criteria"""
        
        result_value = self._get_nested_value(result, field)
        operator = criteria.get('operator', 'contains')
        value = criteria.get('value')
        
        if operator in self.search_operators:
            return self.search_operators[operator](result_value, value)
        
        return False
    
    def _matches_search(self, result: Dict, query: str, fields: List[str] = None) -> bool:
        """Check if result matches search query"""
        
        if fields:
            # Search specific fields
            for field in fields:
                value = self._get_nested_value(result, field)
                if value and query in str(value).lower():
                    return True
        else:
            # Search all string values
            for value in self._get_all_values(result):
                if isinstance(value, str) and query in value.lower():
                    return True
        
        return False
    
    def _get_nested_value(self, data: Dict, field: str) -> Any:
        """Get nested field value using dot notation"""
        
        try:
            keys = field.split('.')
            value = data
            
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key)
                elif isinstance(value, list) and key.isdigit():
                    value = value[int(key)]
                else:
                    return None
            
            return value
        except Exception:
            return None
    
    def _get_all_fields(self, data: Dict, prefix: str = '') -> List[str]:
        """Get all field names recursively"""
        
        fields = []
        
        for key, value in data.items():
            field_name = f"{prefix}.{key}" if prefix else key
            fields.append(field_name)
            
            if isinstance(value, dict):
                fields.extend(self._get_all_fields(value, field_name))
        
        return fields
    
    def _get_all_values(self, data: Dict) -> List[Any]:
        """Get all values recursively"""
        
        values = []
        
        for value in data.values():
            if isinstance(value, dict):
                values.extend(self._get_all_values(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        values.extend(self._get_all_values(item))
                    else:
                        values.append(item)
            else:
                values.append(value)
        
        return values
    
    # Search operators
    def _contains(self, result_value: Any, search_value: Any) -> bool:
        if result_value is None:
            return False
        return str(search_value).lower() in str(result_value).lower()
    
    def _equals(self, result_value: Any, search_value: Any) -> bool:
        return str(result_value).lower() == str(search_value).lower()
    
    def _starts_with(self, result_value: Any, search_value: Any) -> bool:
        if result_value is None:
            return False
        return str(result_value).lower().startswith(str(search_value).lower())
    
    def _ends_with(self, result_value: Any, search_value: Any) -> bool:
        if result_value is None:
            return False
        return str(result_value).lower().endswith(str(search_value).lower())
    
    def _regex(self, result_value: Any, pattern: str) -> bool:
        if result_value is None:
            return False
        try:
            return bool(re.search(pattern, str(result_value), re.IGNORECASE))
        except Exception:
            return False
    
    def _greater_than(self, result_value: Any, compare_value: Any) -> bool:
        try:
            return float(result_value) > float(compare_value)
        except Exception:
            return False
    
    def _less_than(self, result_value: Any, compare_value: Any) -> bool:
        try:
            return float(result_value) < float(compare_value)
        except Exception:
            return False
    
    def _between(self, result_value: Any, range_values: List) -> bool:
        if len(range_values) != 2:
            return False
        try:
            val = float(result_value)
            return float(range_values[0]) <= val <= float(range_values[1])
        except Exception:
            return False

# Global instance
result_filter = ResultFilter()