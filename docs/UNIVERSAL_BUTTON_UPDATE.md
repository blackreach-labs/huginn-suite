# Universal Run Button Implementation

## Summary
Standardized all scan buttons across the application to use a consistent universal run button with the following behavior:
- **Idle state**: Shows "Run" text
- **Running state**: Shows "Stop" text and flashes red
- **Toggle functionality**: Single button that starts/stops scans

## Files Updated

### 1. Universal Button Implementation
- **Created**: `app/ui/animations/universal_run_button.py`
  - New `UniversalRunButton` class with consistent behavior
  - Red pulsing animation when running
  - Automatic text switching between "Run" and "Stop"

### 2. Port Scanning
- **Updated**: `app/pages/recon_enumeration/port_scanning.py`
  - Changed from `PulsingButton` to `UniversalRunButton`
  - Replaced "End" text with "Stop" when running
  - Consistent button state management

### 3. DNS Enumeration
- **Updated**: `app/pages/dns_enumeration_page.py`
  - Changed from regular `QPushButton` to `UniversalRunButton`
  - Replaced "End" text with "Stop" when running
  - Added proper button state handling

### 4. Service Scanners
- **Updated**: `app/pages/recon_enumeration/service_scanners.py`
  - Standardized button state management
  - Consistent "Stop" text when running

- **Updated**: `app/pages/recon_enumeration/service_ui_components.py`
  - Changed from `PulsingButton` to `UniversalRunButton`
  - Updated button creation for all service enumeration tools

### 5. Huggin Scanner
- **Updated**: `app/components/huggin_scanner_component.py`
  - Replaced separate start/stop buttons with single toggle button
  - Changed from dual-button to `UniversalRunButton` approach
  - Added toggle functionality

### 6. Web Scanner
- **Updated**: `app/widgets/web_scanner_widget.py`
  - Replaced separate start/stop buttons with single toggle button
  - Changed from dual-button to `UniversalRunButton` approach
  - Added toggle functionality

## Behavior Changes

### Before
- **Port Scanning**: Used "End" when running
- **DNS Enumeration**: Used "End" when running  
- **Service Scanners**: Used "Stop" when running
- **Huggin Scanner**: Had separate "Start" and "Stop" buttons
- **Web Scanner**: Had separate "Start" and "Stop" buttons

### After
- **All Scanners**: Use "Stop" when running and flash red
- **All Scanners**: Use "Run" when idle
- **All Scanners**: Single toggle button approach
- **All Scanners**: Consistent red pulsing animation when active

## Benefits
1. **Consistency**: All scan buttons behave identically
2. **User Experience**: Clear visual feedback with red flashing
3. **Space Efficiency**: Single button instead of separate start/stop buttons
4. **Maintainability**: Centralized button logic in one class
5. **Accessibility**: Consistent interaction pattern across the application

## Implementation Details
- Fallback to regular `QPushButton` if `UniversalRunButton` import fails
- Backward compatibility maintained with existing button references
- Animation uses 500ms pulse interval for optimal visibility
- Button state automatically managed by the universal class