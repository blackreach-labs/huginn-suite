# Local DNS Server

The Local DNS Server is a Professional and Enterprise feature that allows you to create and manage custom DNS records for testing and development purposes.

## Overview

The Local DNS Server provides a lightweight DNS server that runs locally on your machine, allowing you to:

- Create custom domain records (A, AAAA, CNAME)
- Test DNS resolution without modifying system DNS settings
- Simulate DNS environments for penetration testing
- Override DNS responses for specific domains

## Requirements

- **Professional or Enterprise License**: This feature requires a valid Professional or Enterprise license
- **Port 5353**: The DNS server runs on localhost port 5353 (configurable)

## Features

### Supported Record Types

- **A Records**: IPv4 address resolution
- **AAAA Records**: IPv6 address resolution  
- **CNAME Records**: Canonical name aliases

### Management Interface

The Local DNS Server includes a user-friendly management interface accessible through:
- **Menu**: Professional Features → Local DNS Server
- **Features**: Add, edit, delete DNS records
- **Auto-save**: Records are automatically saved and restored

## Usage

### Starting the Server

1. Open **Professional Features → Local DNS Server**
2. Click **Start Server** to begin listening on 127.0.0.1:5353
3. The server status will show "Running" when active

### Adding DNS Records

1. Enter the domain name (e.g., `test.local`)
2. Select record type (A, AAAA, or CNAME)
3. Enter the value:
   - **A Record**: IPv4 address (e.g., `192.168.1.100`)
   - **AAAA Record**: IPv6 address (e.g., `::1`)
   - **CNAME Record**: Target domain (e.g., `real-server.com`)
4. Click **Add Record**

### Using LocalDNS in Tools

To use the Local DNS Server in any DNS enumeration tool:

1. Set the **DNS Server** field to `LocalDNS`
2. The tool will automatically query 127.0.0.1:5353
3. Custom records will be returned for matching domains

### Example Workflow

```
1. Start Local DNS Server
2. Add record: test.local → A → 192.168.1.100
3. In DNS Enumeration tool:
   - Target: test.local
   - DNS Server: LocalDNS
4. Run scan - will resolve test.local to 192.168.1.100
```

## Configuration

### Server Settings

- **Listen Address**: 127.0.0.1 (localhost only)
- **Port**: 5353 (default)
- **Protocol**: UDP
- **Records File**: `local_dns_records.json`

### Record Storage

DNS records are automatically saved to `local_dns_records.json` in the application directory and restored when the application starts.

## Integration

### DNS Tools Integration

The Local DNS Server integrates seamlessly with:

- **DNS Enumeration**: Use `LocalDNS` as DNS server
- **Subdomain Brute Force**: Custom resolution for testing
- **Zone Transfer Testing**: Simulate zone data
- **PTR Record Testing**: Reverse DNS simulation

### API Integration

The Local DNS Server can be extended to support:

- REST API for record management
- Bulk record import/export
- Dynamic record updates
- Integration with external tools

## Security Considerations

### Local Only

- The DNS server only listens on localhost (127.0.0.1)
- No external network access by default
- Records are stored locally only

### License Protection

- Feature is disabled without valid Professional/Enterprise license
- License validation occurs on server start
- Graceful degradation if license expires

## Troubleshooting

### Common Issues

**Server Won't Start**
- Check if port 5353 is available
- Verify Professional/Enterprise license
- Check firewall settings

**Records Not Resolving**
- Ensure DNS server is set to `LocalDNS`
- Verify record was added correctly
- Check server is running

**Permission Errors**
- Ensure write permissions for records file
- Check application directory permissions

### Logs

DNS server activity is logged to the main application log with entries like:
```
Local DNS server started on port 5353
Added DNS record: test.local A 192.168.1.100
DNS query received for test.local
```

## Advanced Usage

### Testing Scenarios

**Subdomain Enumeration Testing**
```
Add records:
- admin.test.local → 192.168.1.10
- mail.test.local → 192.168.1.20
- www.test.local → 192.168.1.30

Run subdomain enumeration with LocalDNS
```

**DNS Spoofing Simulation**
```
Add records:
- google.com → 192.168.1.100
- facebook.com → 192.168.1.100

Test application behavior with spoofed DNS
```

**Load Balancing Testing**
```
Add multiple A records for same domain:
- app.test.local → 192.168.1.10
- app.test.local → 192.168.1.20
- app.test.local → 192.168.1.30
```

## Limitations

- **Record Types**: Only A, AAAA, and CNAME supported
- **Local Only**: No external network binding
- **Simple Protocol**: Basic DNS protocol implementation
- **No Recursion**: Does not forward unknown queries
- **No DNSSEC**: Security extensions not supported

## Future Enhancements

Planned improvements include:

- **Additional Record Types**: MX, TXT, SRV support
- **Zone File Import**: Import standard DNS zone files
- **Query Logging**: Detailed query/response logging
- **External Binding**: Option to bind to external interfaces
- **DNS Forwarding**: Forward unknown queries to upstream DNS
- **Web Interface**: Browser-based management interface

## License Information

The Local DNS Server is available in:

- **Professional License**: Full feature access
- **Enterprise License**: Full feature access + priority support
- **Free License**: Feature not available

For license upgrades, visit the License Manager in the application.