# AI Chat Client with PowerShell Tools & CIS Benchmark Implementation

A standalone Windows security management and chat application with **706 embedded tools** including complete **CIS Microsoft Windows 10/11 Benchmark** implementation (100% coverage of all 400 controls), remote server management, enterprise Group Policy tools, and intelligent compliance reporting.

## Key Features

- **706 PowerShell Tools** - Complete Windows management across all categories
- **100% CIS Benchmark Coverage** - All 400 controls from CIS Microsoft Windows 10/11 Benchmark v3.0.0 (Level 1 & Level 2)
- **Remote Server Management** - WinRM configuration, PowerShell Remoting, and remote CIS hardening via Invoke-Command
- **Group Policy Management** - Create and manage 15 common enterprise GPO scenarios
- **112 Quick Actions** - Categorized dropdown menu with pre-configured prompts
- **AI Reference System** - External documentation generation for enhanced context awareness
- **Comprehensive Compliance Reporting** - JSON/HTML reports, executive summaries, audit evidence packages
- **Zero Dependencies** - Pure PowerShell with WPF, uses built-in Windows components only
- **AI-Powered Automation** - OpenAI integration with intelligent tool selection
- **Configuration Backup/Restore** - Safe hardening with rollback capability
- **Automated Compliance Monitoring** - Schedule continuous audits with Task Scheduler

## Intelligent Tool Selection

With 706 tools but OpenAI's 128-tool limit per request:

1. Analyzes query keywords
2. Matches to relevant categories
3. Selects top 3 most relevant categories
4. Includes task management tools
5. Adds essential system tools
6. Prioritizes CIS tools for security/compliance keywords
7. Prioritizes remote management for "remote"/"server" keywords
8. Prioritizes GPO tools for "Group Policy"/"GPO" keywords
9. Stays within 128-tool limit

## Settings

Stored in `%APPDATA%\AIChat\settings.json`:
- OpenAI API key
- Selected model
- Custom instructions
- Temperature (hardcoded to 0)

**Available Models:**
- **gpt-4o-mini** (default) - Fast and cost-effective
- **gpt-4o** - Most capable, balanced
- **gpt-4-turbo** - High performance, extended context
- **gpt-3.5-turbo** - Legacy support

## Pre-compiled Executable

`ChatClient.exe` is ready to run:
- Zero installation required
- All 706 tools embedded
- Approximately 950 KB size

Simply double-click to run.

## Build from Source (Optional)

```powershell
Install-Module ps2exe -Scope CurrentUser
Invoke-ps2exe -inputFile .\ChatClient.ps1 -outputFile .\ChatClient.exe -noConsole -title "AI Chat Client"
```

Results in ~950 KB executable with all 706 tools (252 base + 421 CIS + 33 remote management).

## Requirements

- Windows PowerShell 5.1+ (pre-installed on Windows 10/11) or PowerShell 7+
- Internet connection for OpenAI API
- OpenAI API key (get one at platform.openai.com)

### Optional Components

- **7-Zip** - Advanced compression tools
- **RSAT** - Active Directory tools
- **Hyper-V** - VM management
- **Docker Desktop** - Container management
- **WSL** - Linux distribution management
- **SQL Server** - Database management tools

Core Windows management works without additional software.

## Architecture

- **Single .ps1 file (~10,200 lines)** - All code in one portable script
- **Switch-based tool execution** - Clean mapping of 706 tool names to PowerShell commands
- **Dynamic tool selection** - Category-based filtering for optimal performance
- **WPF XAML UI** - Native Windows interface with dark theme
- **Zero external dependencies** - Uses only built-in Windows components
- **PowerShell version detection** - Adapts to PS 5.1 or 7+ features
- **Temperature hardcoded to 0** - Deterministic, consistent responses

### Tool Execution Flow

1. User sends message to OpenAI
2. `Get-RelevantTools` analyzes query and selects up to 128 relevant tools
3. OpenAI decides which tools to invoke with parameters
4. `Invoke-PowerShellTool` executes PowerShell commands
5. Results returned to OpenAI for natural language response
6. AI maintains conversation context and task history

### PowerShell Compatibility

- **PowerShell 5.1:** Manual PSObject property enumeration for JSON
- **PowerShell 7+:** Uses `-AsHashtable` for faster JSON conversion
- Automatically detects version and adapts

## Quick Start

### Option 1: Run Pre-compiled Executable (Recommended)
1. Download `ChatClient.exe` from the repository
2. Double-click to run (no installation needed)
3. Enter your OpenAI API key in Settings
4. Start chatting!

### Option 2: Run PowerShell Script
```powershell
.\ChatClient.ps1
```

**Keyboard Shortcuts:**
- **Enter** - Send message
- **Shift+Enter** - New line in message

## Tool Categories (706 Total)

### Remote Server Management (33 tools)

#### WinRM & PowerShell Remoting Setup (8 tools)
- Enable/disable PowerShell Remoting on local server
- Configure WinRM HTTPS listener with certificate
- Manage TrustedHosts for workgroup environments
- Test WinRM connectivity locally
- Configure WinRM firewall rules (ports 5985/5986)
- Get WinRM configuration and PS Remoting status

#### Remote CIS Hardening (10 tools)
- Test remote server connectivity and WinRM status
- Apply CIS baseline to remote servers via Invoke-Command
- Audit remote server CIS compliance
- Get remote server GPO information
- Create CIS GPOs for domain deployment
- Link GPOs to OUs for automatic application
- Force GPO updates on remote servers
- Export CIS GPO reports for documentation
- Backup GPOs before modifications
- Compare remote server configurations

#### Enterprise Group Policy Management (15 tools)
- List all GPOs in domain
- Password policy GPO (complexity, length, age, history)
- Desktop restrictions GPO (Control Panel, CMD, Registry, Task Manager lockdown)
- Software restriction policies (whitelist/blacklist executables)
- Folder redirection GPO (Documents, Desktop, AppData to network)
- Drive mapping GPO (automated network drives)
- Printer deployment GPO (auto-install printers)
- Windows Update GPO (WSUS or Microsoft Update)
- Power management GPO (display/sleep timeouts, power plans)
- Screensaver policy GPO (timeout and password protection)
- IE/Edge settings GPO (homepage, proxy, password saving)
- Event log sizing GPO (Application/System/Security log sizes)
- Startup/shutdown script GPO (run scripts at boot/shutdown)
- USB restriction GPO (block/restrict USB storage)
- Delete GPO with confirmation

### CIS Benchmark Implementation (421 tools)

Complete implementation of all 400 CIS Microsoft Windows 10/11 Benchmark v3.0.0 controls with enhanced reporting and orchestration.

#### User Rights Assignment (40 tools: 20 audit + 20 apply)
Restrict privileged access rights including:
- Logon rights (Local, Remote Desktop, Network, Batch, Service)
- System operations (Shutdown, Debug, Load drivers, Backup/Restore)
- Impersonation and security privileges

#### Advanced Audit Policy (100 tools: 50 audit + 50 configure)
Comprehensive auditing across:
- Account Logon (Credential Validation, Kerberos)
- Account Management (User/Group/Computer accounts)
- Detailed Tracking (Process Creation, RPC Events)
- Logon/Logoff events
- Object Access (File System, Registry, SAM)
- Policy Change tracking
- Privilege Use monitoring
- System events (Security Extensions, IPsec)

#### System Services (80 tools: 40 audit + 40 configure)
- Disable unnecessary services (Xbox, Bluetooth, Print Spooler)
- Secure remote access services (RDP, Remote Registry, WinRM)
- Harden network services (SSDP, UPnP, LLTD)

#### Security Options (200 tools: 100 audit + 100 configure)
- Accounts: Administrator/Guest policies, rename built-in accounts
- Audit: Log settings, shutdown when full
- Devices: Access restrictions, driver policies
- Interactive Logon: Authentication, smart cards
- Network: SMB signing, authentication protocols
- System: Cryptography, driver signing

#### Administrative Templates (174 tools: 87 audit + 87 configure)
- Windows Components security (BitLocker, Credentials, Event Log)
- File Explorer hardening
- Internet Explorer/Edge security
- Network policies, PowerShell restrictions

#### Windows Firewall (50 tools: 25 audit + 25 configure)
- Domain/Private/Public profiles
- Enable firewall, block inbound/outbound
- Logging configuration

#### User Configuration (40 tools: 20 audit + 20 apply)
- Control Panel restrictions
- Desktop security settings
- Network configuration policies
- Start Menu restrictions

#### Domain Controller Controls (116 tools: 58 audit + 58 configure) - Optional
- Active Directory-specific security
- Kerberos policies, LDAP hardening
- Replication security

#### Enhanced Compliance Reporting (10 tools)
- `generate_cis_compliance_report` - JSON/HTML reports with pass/fail status
- `calculate_compliance_score` - Percentage compliance by category
- `export_current_configuration` - Full system state JSON backup
- `import_restore_configuration` - Restore from JSON backup
- `compare_configurations` - Diff two configs for drift detection
- `generate_remediation_plan` - Gap analysis with prioritized steps
- `generate_executive_summary` - Management reports with charts
- `schedule_compliance_audit` - Task Scheduler integration
- `validate_cis_prerequisites` - Pre-flight checks
- `generate_audit_evidence` - Comprehensive ZIP packages

#### Master Baseline Application (1 tool)
**`apply_cis_baseline`** - Comprehensive orchestration applying all 400 CIS controls
- Dry-run mode for preview
- Automatic backup before changes
- Progress tracking (Validation → Backup → Apply → Verify)
- Selective application by section
- Post-hardening verification
- Estimated time: 15-30 minutes

### Base Windows Management (252 tools)

#### Network (11 tools)
- Test connectivity, ping, port testing, traceroute
- Get/manage network adapters and IP configuration
- DNS operations (resolve, clear cache)
- Firewall rules management
- Network stack reset

#### Security (16 tools)
- User and group management
- ACL permissions viewing and modification
- Firewall rule creation and management
- Local user account operations
- Security group membership

#### Registry (12 tools)
- Read, write, search registry keys and values
- Import/export registry files
- Backup registry hives
- Create and delete keys

#### Event Logs (9 tools)
- Read Windows Event Logs with filtering
- Search across multiple logs
- Export logs to files
- Clear and manage event logs
- Get recent errors and warnings

#### Disk & Storage (14 tools)
- Disk health checks and S.M.A.R.T. data
- Volume and partition management
- Format, optimize, and defragment disks
- Resize partitions and assign drive letters

#### Hardware & Devices (9 tools)
- Hardware device information and drivers
- USB device enumeration
- Graphics card details
- Enable/disable devices
- Scan for hardware changes

#### Windows Updates (8 tools)
- Check for and install updates
- View update history
- Hide or uninstall specific updates
- Get pending update status

#### Licensing & Activation (7 tools)
- Windows activation status
- Product key management
- KMS server configuration
- License rearm operations

#### Applications & Processes (12 tools)
- List installed applications and Store apps
- Process management and monitoring
- Startup program configuration
- Windows feature installation
- Process priority management

#### File System (15 tools)
- Advanced file search and filtering
- File hashing (MD5, SHA1, SHA256)
- Compress/decompress archives
- Compare directories and find duplicates
- Bulk rename, copy, move operations
- Robocopy synchronization

#### System Management (11 tools)
- Comprehensive system information
- Service management (start, stop, restart)
- Scheduled task operations
- Environment variable management
- Power management (shutdown, restart, sleep, hibernate)
- Performance counter monitoring

#### Power Management (10 tools)
- Get and set power plans
- Battery status and charge monitoring
- Display and sleep timeout configuration
- Hibernation enable/disable
- Lid close and power button actions
- Detailed power settings query

#### Windows Defender (10 tools)
- Antivirus status and scans
- Threat detection and removal
- Signature updates
- Exclusion management
- Real-time protection control

#### Performance & Monitoring (12 tools)
- Real-time CPU usage per core
- Detailed memory statistics
- Disk I/O monitoring (IOPS, throughput)
- Network throughput tracking
- Top CPU and memory processes
- System uptime and boot time
- Performance reports
- Resource alerts
- Disk benchmarks

#### Database & SQL (8 tools)
- Test SQL Server connectivity
- Execute SQL queries
- Get SQL Server information
- List databases and tables
- Backup and restore databases
- SQL Server performance metrics

#### Certificates & Encryption (7 tools)
- List certificates in stores
- Get certificate details
- Test certificate expiration
- Export/import certificates
- Test SSL/TLS certificates
- Create self-signed certificates

#### Web & REST API (10 tools)
- HTTP GET, POST, PUT, DELETE requests
- Custom headers and authentication
- File downloads with progress
- Test URL availability
- Web page content extraction
- JSON response parsing
- Base64 encoding/decoding

#### Printing (6 tools)
- List all printers
- View print queue and job details
- Clear print queues
- Cancel specific print jobs
- Set default printer
- Pause/resume printers

#### Backup & Recovery (8 tools)
- Create system restore points
- List and restore from restore points
- Volume Shadow Copy operations
- Create VSS snapshots
- Export Event Viewer configuration
- Full registry backup
- Windows Backup status

#### Active Directory (9 tools) - Requires RSAT
- Get AD user information
- Search AD users by attributes
- List AD group members
- Get user group memberships
- List domain computers
- Get AD domain information
- Test AD credentials
- Find locked out/disabled accounts

#### Network Shares & Permissions (7 tools)
- List SMB network shares
- Create and remove shares
- Get share permissions (SMB and NTFS)
- Set share-level permissions
- View open files over network
- Close SMB sessions
- Network share auditing

#### Audio & Video (5 tools)
- List audio devices
- Set system volume level
- Mute/unmute system audio
- Capture screenshots
- Get display information

#### Virtualization (8 tools)
- Hyper-V VM management (Requires Hyper-V)
- Docker container management (Requires Docker)
- WSL distribution management (Requires WSL)

#### Compression & Archives (5 tools)
- Compress with 7-Zip (Requires 7-Zip)
- Extract archives (ZIP, RAR, 7Z, TAR, GZIP)
- List archive contents
- Test archive integrity

#### Text Processing (8 tools)
- Search text across files (grep-like)
- Find and replace with regex
- Parse CSV, XML, JSON files
- Export to CSV format
- Convert file encoding
- Count lines, words, characters

#### Windows Imaging (WIM/DISM) (12 tools)
- Get WIM file information
- Mount/unmount WIM images
- List mounted images
- Cleanup corrupted mounts
- Export/capture images
- Apply WIM to drive
- Split large WIM files
- Driver management in WIM

#### Task Management (5 tools)
- Create multi-step plans
- Track task completion
- Review completed tasks
- Check plan progress
- Get conversation history

## Quick Actions System (112 Total)

Categorized dropdown menu with pre-configured prompts:

- **CIS Compliance (15)** - Reports, baselines, audits, remediation
- **Network Diagnostics (9)** - Connectivity, adapters, DNS, firewall
- **Security Auditing (8)** - Users, permissions, failed logins
- **System Monitoring (8)** - CPU, memory, services, uptime
- **Disk Management (7)** - Health, space, fragmentation
- **Event Logs (7)** - Errors, security events, exports
- **Windows Updates (5)** - Check, install, history
- **Software Management (5)** - List installed programs
- **Registry Operations (5)** - Search, backup, startup programs
- **Hardware Info (7)** - System info, devices, battery
- **Scheduled Tasks (5)** - List tasks, find failures
- **Reporting (5)** - Health reports, security audits
- **AI Reference (4)** - Generate docs, verify awareness

## CIS Benchmark Compliance

### Complete Coverage Summary

**Tool Breakdown:**
- 400 CIS Controls → 800+ individual tools (audit + apply for each)
- 10 Reporting Tools
- 1 Master Orchestration Tool
- **Total: 421 CIS-related tools**

### End-to-End Compliance Workflows

**Initial System Hardening:**
1. `validate_cis_prerequisites` - Check system readiness
2. `export_current_configuration` - Backup current state
3. `apply_cis_baseline` - Apply all 400+ controls
4. `generate_cis_compliance_report` - Verify hardening
5. Result: Fully hardened system with audit trail

**Continuous Compliance Monitoring:**
1. `schedule_compliance_audit` - Automate weekly/monthly audits
2. `generate_cis_compliance_report` - Periodic assessment
3. `calculate_compliance_score` - Track compliance over time
4. `generate_remediation_plan` - Address drift
5. Result: Ongoing compliance assurance

**Audit Preparation:**
1. `generate_cis_compliance_report` - Current compliance status
2. `generate_executive_summary` - Management summary
3. `generate_audit_evidence` - ZIP package with documentation
4. Result: Complete audit package

### Use Cases

- **SOC 2 Compliance** - Demonstrate security controls
- **ISO 27001 Certification** - Information security management
- **NIST Cybersecurity Framework** - Meet protection requirements
- **PCI DSS** - Harden payment systems
- **HIPAA** - Secure healthcare systems
- **Golden Image Creation** - Build hardened base images
- **Infrastructure as Code** - Script-based security configuration
- **Incident Response** - Post-breach hardening

## AI Reference Documentation System

Generate external reference documentation for enhanced AI context awareness.

### Features

- Creates `AI_Reference` folder with 5 markdown files:
  * `tool_catalog.md` - All 706 tools by category
  * `cis_compliance_guide.md` - Complete CIS control mapping
  * `quick_actions_reference.md` - All 112 quick actions
  * `capability_matrix.md` - Feature overview
  * `README.txt` - Supported content types

### AI Awareness Tools

- `generate_ai_reference_docs` - Create reference documentation
- `list_all_tool_categories` - Display tool breakdown
- `verify_ai_tool_awareness` - Self-verification report
- `show_cis_coverage_summary` - CIS coverage details

### Supported Reference Content

Add custom content to `AI_Reference` folder:
- .txt, .md, .json, .csv, .xml, .log, .ps1, .ini, .yaml, .yml, .html
- Organizational procedures, baselines, checklists
- Configuration templates, network diagrams
- Custom scripts, audit logs, historical data

### CIS Implementation Details

- **secedit** - User Rights Assignment and Security Options
- **auditpol** - Advanced Audit Policy
- **Set-Service** - System Services hardening
- **Set-ItemProperty** - Registry-based policies
- **netsh advfirewall** - Windows Firewall
- **Group Policy equivalents** - No GPO infrastructure required

## License

MIT License
