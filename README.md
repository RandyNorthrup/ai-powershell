# AI Chat Client with PowerShell Tools

A standalone Windows chat application with 228+ embedded PowerShell management tools, OpenAI integration, and intelligent task tracking.

## Features

- **Pure PowerShell with WPF** - Zero dependencies, uses built-in Windows components only
- **228+ PowerShell Tools** - Comprehensive Windows management across 25 categories with detailed parameter documentation
- **Intelligent Tool Selection** - Automatically selects relevant tools based on your query (respects OpenAI's 128-tool limit)
- **Task Management & Context Awareness** - AI tracks completed tasks, creates plans, and maintains conversation history
- **OpenAI Function Calling** - Seamless tool execution with comprehensive parameter awareness
- **Secure Local Storage** - API keys and settings stored in %APPDATA%
- **Dark Theme Interface** - Clean, professional UI
- **PowerShell 5.1 & 7+ Compatible** - Works with Windows PowerShell and PowerShell Core

## Quick Start

### Option 1: Run Pre-compiled Executable (Recommended)
1. Download `ChatClient.exe` from the repository
2. Double-click to run (no installation needed)
3. Enter your OpenAI API key in Settings
4. Start chatting!

### Option 2: Run PowerShell Script
1. Run the script:
```powershell
.\ChatClient.ps1
```

2. Open Settings panel and enter your OpenAI API key
3. Choose your preferred model (default: gpt-4o-mini)
4. Add custom instructions (optional)
5. Start chatting - AI automatically executes PowerShell tools as needed

**Keyboard Shortcuts:**
- **Enter** - Send message
- **Shift+Enter** - New line in message

## Tool Categories (228+ Total)

### Network Tools (11)
- Test connectivity, ping, port testing, traceroute
- Get/manage network adapters and IP configuration
- DNS operations (resolve, clear cache)
- Firewall rules management
- Network stack reset

### Security Tools (16)
- User and group management
- ACL permissions viewing and modification
- Firewall rule creation and management
- Local user account operations
- Security group membership

### Registry Tools (12)
- Read, write, search registry keys and values
- Import/export registry files
- Backup registry hives
- Create and delete keys

### Event Log Tools (9)
- Read Windows Event Logs with filtering
- Search across multiple logs
- Export logs to files
- Clear and manage event logs
- Get recent errors and warnings

### Disk Tools (14)
- Disk health checks and S.M.A.R.T. data
- Volume and partition management
- Format, optimize, and defragment disks
- Resize partitions and assign drive letters

### Device Tools (9)
- Hardware device information and drivers
- USB device enumeration
- Graphics card details
- Enable/disable devices
- Scan for hardware changes

### Windows Update Tools (8)
- Check for and install updates
- View update history
- Hide or uninstall specific updates
- Get pending update status

### Licensing Tools (7)
- Windows activation status
- Product key management
- KMS server configuration
- License rearm operations

### Application Tools (12)
- List installed applications and Store apps
- Process management and monitoring
- Startup program configuration
- Windows feature installation
- Process priority management

### File Tools (15)
- Advanced file search and filtering
- File hashing (MD5, SHA1, SHA256)
- Compress/decompress archives
- Compare directories and find duplicates
- Bulk rename, copy, move operations
- Robocopy synchronization

### Computer Management Tools (11)
- Comprehensive system information
- Service management (start, stop, restart)
- Scheduled task operations (create, delete, import, export)
- Environment variable management
- Power management (shutdown, restart, sleep, hibernate)
- Performance counter monitoring
- System logs summary

### Power Management Tools (10)
- Get and set power plans (Balanced, High Performance, Power Saver)
- Battery status and charge level monitoring
- Display and sleep timeout configuration
- Hibernation enable/disable
- Lid close action settings
- Power button action settings
- Detailed power settings query

### Windows Defender Tools (10)
- Antivirus status and scans
- Threat detection and removal
- Signature updates
- Exclusion management
- Real-time protection control

### Task Management Tools (5)
- Create multi-step plans with named goals
- Track task completion with timestamps
- Review all completed tasks
- Check plan progress with percentage
- Get conversation history overview

### **NEW: Performance & Monitoring Tools (12)**
- Real-time CPU usage per core and total
- Detailed memory statistics and pressure
- Disk I/O monitoring (read/write bytes, IOPS)
- Network throughput tracking
- Top CPU and memory consuming processes
- System uptime and boot time
- Comprehensive performance reports
- Real-time process monitoring
- Resource alerts (high CPU, low memory, low disk)
- Disk benchmark tests
- System handle count tracking

### **NEW: Database & SQL Tools (8)**
- Test SQL Server connectivity
- Execute SQL queries with results
- Get SQL Server version and edition
- List databases and tables
- Backup and restore databases
- SQL Server performance metrics
- Support for Windows and SQL Authentication

### **NEW: Certificate & Encryption Tools (7)**
- List certificates in all stores
- Get detailed certificate information
- Test certificate expiration dates
- Export certificates (CER, PFX formats)
- Import certificates from files
- Test SSL/TLS certificates on websites
- Create self-signed certificates

### **NEW: Web & REST API Tools (10)**
- HTTP GET, POST, PUT, DELETE requests
- Custom headers and authentication
- File downloads with progress
- Test URL availability and response time
- Web page content extraction
- Comprehensive REST API testing
- JSON response parsing
- Base64 encoding/decoding

### **NEW: Printer & Print Queue Tools (6)**
- List all printers with status
- View print queue and job details
- Clear print queues
- Cancel specific print jobs
- Set default printer
- Pause/resume printers

### **NEW: Backup & Recovery Tools (8)**
- Create system restore points
- List and restore from restore points
- Volume Shadow Copy operations
- Create VSS snapshots
- Export Event Viewer configuration
- Full registry backup
- Windows Backup status
- System recovery operations

### **NEW: Active Directory Tools (9)** *(Requires RSAT)*
- Get AD user information
- Search AD users by attributes
- List AD group members
- Get user group memberships
- List domain computers
- Get AD domain information
- Test AD credentials
- Find locked out accounts
- Find disabled accounts

### **NEW: Share & Permission Tools (7)**
- List SMB network shares
- Create and remove network shares
- Get share permissions (SMB and NTFS)
- Set share-level permissions
- View open files over network
- Close SMB sessions
- Network share auditing

### **NEW: Audio & Video Tools (5)**
- List audio playback and recording devices
- Set system volume level (0-100)
- Mute/unmute system audio
- Capture screenshots (PNG, JPG, BMP)
- Get display information and resolution

### **NEW: Virtualization Tools (8)**
- List Hyper-V VMs with status *(Requires Hyper-V)*
- Start, stop, save, restart VMs
- Get detailed VM configuration
- Create VM checkpoints (snapshots)
- List Docker containers *(Requires Docker)*
- Manage Docker containers
- List WSL distributions *(Requires WSL)*
- Manage WSL distros

### **NEW: Compression & Archive Tools (5)**
- Compress with 7-Zip (ZIP, 7Z, TAR.GZ) *(Requires 7-Zip)*
- Extract archives (ZIP, RAR, 7Z, TAR, GZIP, etc.)
- List archive contents without extracting
- Test archive integrity
- Create cross-platform TAR.GZ archives

### **NEW: Text Processing Tools (8)**
- Search text across multiple files (grep-like)
- Find and replace text with regex support
- Parse CSV files to structured data
- Export data to CSV format
- Parse XML files with XPath queries
- Parse JSON files with property paths
- Convert file encoding (UTF-8, ASCII, Unicode, etc.)
- Count lines, words, and characters

## Task Tracking & Context Awareness

The AI assistant maintains:
- **Full conversation history** - References previous messages and responses
- **Task completion tracking** - Marks tasks complete with timestamps
- **Multi-step plan execution** - Creates plans and tracks progress through each step
- **Progress monitoring** - Shows percentage complete and remaining steps

Example usage:
```
You: Create a plan to optimize my system performance
AI: [Creates plan with specific steps]

You: What's our progress?
AI: [Shows completed steps and remaining work]
```

## Intelligent Tool Selection

With 228+ tools available but OpenAI's limit of 128 tools per request, the application intelligently:
1. Analyzes your query for keywords
2. Matches to relevant tool categories
3. Selects the top 3 most relevant categories
4. Always includes task management tools for context awareness
5. Adds essential system tools
6. Stays within the 128-tool limit

This ensures you always have access to the most relevant tools for your query.

## Comprehensive Parameter Documentation

Every tool includes:
- **Detailed descriptions** of what the tool does and which PowerShell cmdlets it uses
- **Complete parameter documentation** with examples and valid value ranges
- **Optional parameters** clearly explained with their purposes
- **Administrator privilege requirements** noted where applicable
- **Warnings** about destructive operations or data loss risks
- **Use case scenarios** for when to use each tool

This comprehensive documentation enables the AI to make intelligent decisions about tool selection and parameter usage without guessing.

## Settings

Stored in `%APPDATA%\AIChat\settings.json`:
- OpenAI API key
- Selected model
- Custom instructions
- Temperature (hardcoded to 0 for deterministic responses)

**Available Models:**
- **gpt-4o-mini** (default) - Fast and cost-effective
- **gpt-4o** - Most capable, balanced performance
- **gpt-4-turbo** - High performance with extended context
- **gpt-3.5-turbo** - Legacy model support

## Pre-compiled Executable

A ready-to-run `ChatClient.exe` is included in the repository:
- **Zero installation required** - Just download and run
- **No PowerShell experience needed** - Standard Windows application
- **All 228+ tools embedded** - Complete functionality in standalone executable
- **Same features as script** - Identical behavior and capabilities

To run: Simply double-click `ChatClient.exe`

**Note:** The executable will be larger after recompilation with new tools (~200-250 KB estimated).

## Build from Source (Optional)

If you want to compile your own executable with all 228+ tools:

```powershell
Install-Module ps2exe -Scope CurrentUser
Invoke-ps2exe -inputFile .\ChatClient.ps1 -outputFile .\ChatClient.exe -noConsole -title "AI Chat Client"
```

Results in a ~200-250 KB executable with all 228+ tools embedded.

## Requirements

- Windows PowerShell 5.1+ (pre-installed on Windows 10/11) or PowerShell 7+
- Internet connection for OpenAI API
- OpenAI API key (get one at platform.openai.com)

### Optional Components
Some advanced tools require additional software or Windows features:
- **7-Zip** - For advanced compression tools (ZIP, RAR, 7Z extraction)
- **RSAT** (Remote Server Administration Tools) - For Active Directory tools
- **Hyper-V role** - For Hyper-V VM management tools
- **Docker Desktop** - For Docker container management
- **WSL** (Windows Subsystem for Linux) - For WSL distribution management
- **SQL Server** - For database management tools

All core Windows management tools work without additional software.

## Architecture

- **Single .ps1 file (~1500+ lines)** - All code in one portable script
- **Switch-based tool execution** - Clean mapping of 228+ tool names to PowerShell commands
- **Dynamic tool selection** - Category-based filtering for optimal performance
- **WPF XAML UI** - Native Windows interface with dark theme
- **Zero external dependencies** - Uses only built-in Windows components
- **PowerShell version detection** - Automatically adapts to PS 5.1 or 7+ features
- **Temperature hardcoded to 0** - Ensures deterministic, consistent responses
- **Model verification** - Displays active model for each request

## Technical Details

### Tool Execution Flow
1. User sends message to OpenAI
2. `Get-RelevantTools` analyzes query and selects up to 128 relevant tools
3. OpenAI decides which tools to invoke and with what parameters
4. `Invoke-PowerShellTool` executes PowerShell commands via switch statement
5. Results returned to OpenAI for natural language response
6. AI maintains full conversation context and task history

### PowerShell Compatibility
- **PowerShell 5.1**: Uses manual PSObject property enumeration for JSON conversion
- **PowerShell 7+**: Uses `-AsHashtable` parameter for faster JSON conversion
- Automatically detects version at startup and adapts accordingly

## What's New in v2.0

**Massive Tool Expansion** - Added 83+ new tools across 12 new categories:
- Performance monitoring and system health diagnostics
- Database and SQL Server management
- SSL/TLS certificate operations
- Web scraping and REST API testing
- Printer and print queue management
- System backup and recovery operations
- Active Directory integration (RSAT)
- Network share and permission auditing
- Audio/video device control
- Hyper-V, Docker, and WSL management
- Advanced archive handling (7-Zip, TAR.GZ)
- Text processing and file parsing (CSV, XML, JSON, regex)

**Total Tool Count**: Expanded from 145 to 228+ comprehensive tools

## License

MIT License
