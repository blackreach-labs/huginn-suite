# Session Management

The Session Management feature in Huggin allows users to organize their scanning activities into projects and manage scan results efficiently.

## Features

### Core Functionality
- **Create Sessions**: Organize scans by project or target
- **Session Association**: Automatically associate scans with active sessions
- **Session Statistics**: Track scan counts, targets, and results
- **Session Export/Import**: Share session data between instances
- **Session History**: Maintain persistent session records

### GUI Integration
- **Export Dropdown Access**: Available via Export → Sessions
- **Full Management Interface**: Create, edit, delete, and manage sessions
- **Real-time Statistics**: View session progress and statistics
- **Session Selection**: Set active session for automatic scan association

## Usage

### Accessing Session Management
1. Run any enumeration tool (DNS, Port Scan, etc.)
2. Click the Export dropdown
3. Select "Sessions" to open the Session Management dialog

### Creating a New Session
1. Click "📁 New Session" button
2. Enter session name (required)
3. Add description (optional)
4. List target domains/IPs (optional)
5. Click OK to create

### Managing Sessions
- **Set Current**: Select a session and click "Set Current" to make it active
- **Edit**: Double-click or select and click "✏️ Edit" to modify session details
- **Delete**: Select and click "🗑️ Delete" to remove a session
- **View Details**: Double-click a session to view detailed information

### Automatic Scan Association
When a session is set as current:
- New scan results are automatically saved to the scan database
- Scans are associated with the active session
- Session statistics are updated in real-time

## API Usage

### Creating Sessions Programmatically
```python
from app.core.session_manager import session_manager

# Create new session
session = session_manager.create_session(
    name="Web App Assessment",
    description="Security assessment of web application",
    targets=["app.example.com", "api.example.com"]
)

# Set as current session
session_manager.set_current_session(session['id'])
```

### Managing Scan Association
```python
from app.core.scan_database import scan_db

# Save scan results
scan_id = scan_db.save_scan(
    target="example.com",
    scan_type="dns_enum",
    results=scan_results,
    duration=scan_duration
)

# Associate with session
session_manager.add_scan_to_session(session_id, scan_id)
```

### Session Statistics
```python
# Get session statistics
stats = session_manager.get_session_statistics(session_id)
print(f"Total scans: {stats['total_scans']}")
print(f"Targets scanned: {stats['targets_scanned']}")
print(f"Scan types: {stats['scan_types']}")
```

### Export/Import Sessions
```python
# Export session data
success = session_manager.export_session(session_id, "session_backup.json")

# Import session data
new_session_id = session_manager.import_session("session_backup.json")
```

## Data Structure

### Session Object
```json
{
    "id": "abc12345",
    "name": "Web App Assessment",
    "description": "Security assessment of web application",
    "created_date": "2024-01-15T10:30:00",
    "modified_date": "2024-01-15T14:45:00",
    "targets": ["app.example.com", "api.example.com"],
    "scan_ids": [1, 2, 3],
    "status": "active",
    "tags": [],
    "notes": ""
}
```

### Session Statistics
```json
{
    "total_scans": 5,
    "targets_scanned": 3,
    "scan_types": {
        "dns_enum": 2,
        "port_scan": 2,
        "http_enum": 1
    },
    "total_results": 47,
    "date_range": {
        "start": "2024-01-15T10:30:00",
        "end": "2024-01-15T14:45:00"
    }
}
```

## Integration Points

### Enumeration Tools
- All enumeration tools support automatic session association
- Scan results are saved to database when session is active
- Session statistics update in real-time

### Export System
- Session management accessible via export dropdown
- Seamless integration with existing export workflow
- No disruption to current export functionality

### Database Integration
- Sessions stored in JSON file (`sessions.json`)
- Scan data stored in SQLite database (`resources/scan_history.db`)
- Automatic relationship management between sessions and scans

## Best Practices

### Session Organization
- Use descriptive session names (e.g., "Client XYZ - External Assessment")
- Include relevant targets in session creation
- Add meaningful descriptions for context

### Workflow Integration
- Set active session before starting scans
- Review session statistics regularly
- Export sessions for backup and sharing

### Data Management
- Regular cleanup of old sessions
- Export important sessions before deletion
- Use session tags for categorization

## Troubleshooting

### Common Issues
1. **Session not saving scans**: Ensure session is set as current
2. **Export fails**: Check file permissions in project directory
3. **Statistics not updating**: Refresh the session management dialog

### Error Messages
- "Session name is required": Provide a name when creating sessions
- "Failed to associate scan": Check database connectivity
- "No session selected": Select a session before performing operations

## Technical Details

### File Locations
- Session data: `sessions.json` (project root)
- Scan database: `resources/scan_history.db`
- Export files: `exports/` directory

### Dependencies
- SQLite database for scan storage
- JSON file system for session persistence
- PyQt6 for GUI components

### Performance
- Lightweight JSON storage for sessions
- Efficient SQLite queries for scan data
- Real-time updates without blocking UI