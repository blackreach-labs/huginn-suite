# Session Management Features

## Overview

The Huggin application now includes comprehensive session management that automatically tracks your scanning activities and exported data. Each time you launch the application, a new session is created to organize your work.

## Key Features

### 1. Automatic Session Creation
- **New session on each launch**: Every time you start Huggin, a new session is automatically created
- **Unique session IDs**: Each session gets a unique identifier for easy tracking
- **Timestamp naming**: Sessions are named with the current date and time

### 2. Export Tracking
- **Automatic tracking**: All exported scan results are automatically tracked in the current session
- **Database integration**: Exports are stored in both the session data and a SQLite database
- **File metadata**: Track file paths, formats, sizes, and timestamps

### 3. Session Information Window
- **Access via**: View menu → "Session Info" (Ctrl+I)
- **Separate window**: Opens in its own window so you can view alongside the main application
- **Real-time updates**: Window refreshes every 5 seconds to show latest data
- **Multiple tabs**:
  - **Current Session**: Overview and quick statistics
  - **Exports**: Detailed list of all exported files with options to open or locate
  - **Scans**: History of all scans performed in the session
  - **Statistics**: Comprehensive analytics and charts

### 4. Session Management
- **Save sessions**: Backup your session data including all exports and scan history
- **Restore sessions**: Load previously saved sessions to continue work
- **Session switching**: View and manage multiple sessions through the session selector

## How to Use

### Viewing Current Session Information
1. Launch Huggin (a new session is automatically created)
2. Press Ctrl+I or go to View menu → "Session Info"
3. A separate window opens showing your session data across different tabs
4. You can keep this window open while working in the main application

### Exporting Data
1. Perform any scan (DNS enumeration, port scanning, etc.)
2. Export the results using the export functionality
3. The export is automatically tracked in your current session
4. View all exports in the Session Info page

### Managing Sessions
1. **Save current session**: 
   - Open Session Info window (Ctrl+I)
   - Click "💾 Save Session"
   - Choose location and filename
   
2. **Restore previous session**:
   - Open Session Info window (Ctrl+I)
   - Click "📂 Restore Session"
   - Select a previously saved session file

### Opening Exported Files
1. Open Session Info window → Exports tab
2. Select any export from the list
3. Click "📂 Open Export" to view the file
4. Click "📁 Show in Explorer" to locate the file

## Database Integration

All session and export data is stored in:
- **sessions.json**: Session metadata and configuration
- **resources/scan_history.db**: SQLite database with detailed scan and export records

This enables:
- **Advanced reporting**: Generate comprehensive reports from historical data
- **Data persistence**: Your session data survives application restarts
- **Search capabilities**: Find specific scans or exports across all sessions

## Professional Features

The session management system integrates with professional features:
- **Advanced reporting**: Generate executive summaries from session data
- **Compliance tracking**: Maintain audit trails of all scanning activities
- **Team collaboration**: Share session files with team members

## Tips

1. **Keep window open**: Leave the Session Info window open while working to monitor progress
2. **Regular backups**: Save important sessions before closing the application
3. **Organized naming**: Use descriptive names when saving sessions
4. **Export management**: Use the Session Info window to manage and organize your exports
5. **Statistics tracking**: Monitor your scanning patterns using the statistics tab

## Keyboard Shortcuts

- **Ctrl+I**: Open Session Info window
- **Ctrl+Shift+S**: Open Session Management dialog
- **Ctrl+E**: Export current results
- **F5**: Refresh session data (in Session Info window)

## Troubleshooting

If you encounter issues:
1. Check that the `exports/` directory exists and is writable
2. Ensure `sessions.json` and `resources/scan_history.db` are not corrupted
3. Restart the application to create a fresh session
4. Check the error log for detailed error messages

The session management system is designed to be transparent and automatic, requiring minimal user intervention while providing powerful tracking and organization capabilities.