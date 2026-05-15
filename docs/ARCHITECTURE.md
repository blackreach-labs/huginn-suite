# Huginn Architecture

## Overview
Huginn follows a modular architecture with clear separation of concerns.

## Core Architecture

```
huginn/
├── app/                    # Main application
│   ├── core/              # Core functionality
│   ├── pages/             # UI pages
│   ├── widgets/           # Custom widgets
│   └── main_window.py     # Main window
├── tools/                 # Enumeration tools
├── tests/                 # Test suite
└── docs/                  # Documentation
```

## Component Layers

### 1. Core Layer (`app/core/`)
- **Managers**: Cache, Theme, Context Menu, System Tray
- **Workers**: Base worker classes for threading
- **Utilities**: Validators, Exporters, Database
- **HTTP Interceptor**: Proxy Engine, HTTP Client, Request/Response handling
- **Database**: Proxy Database (resources/proxy.db), Scan Database

### 2. UI Layer (`app/pages/`, `app/widgets/`)
- **Pages**: Main application screens
- **Widgets**: Reusable UI components
- **Theme Integration**: Advanced theming system

### 3. Tools Layer (`tools/`)
- **Enumeration Tools**: DNS, Port, SMB, SMTP, etc.
- **Base Classes**: Common functionality
- **Validators**: Input validation

### 4. Test Layer (`tests/`)
- **Unit Tests**: Individual component testing
- **Integration Tests**: Workflow testing

## Data Flow

1. **Input** → Validation → Processing
2. **Processing** → Caching → Storage
3. **Storage** → Export → Output
4. **UI** → Theme Application → Display
5. **HTTP Requests** → Proxy Interception → Database Storage
6. **Proxy Database** → History Display → Analysis

## Key Design Patterns

- **Singleton**: Cache Manager, Theme Manager
- **Observer**: Signal/Slot for UI updates
- **Factory**: Theme creation and application
- **Strategy**: Multiple export formats