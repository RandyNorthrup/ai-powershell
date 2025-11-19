# AI Chat Client with PowerShell Tools

A standalone Windows chat application with 145 embedded PowerShell management tools, OpenAI integration, and intelligent task tracking.

## Features

- **Pure PowerShell with WPF** - Zero dependencies, uses built-in Windows components only
- **145 PowerShell Tools** - Comprehensive Windows management across 13 categories with detailed parameter documentation
- **Intelligent Tool Selection** - Automatically selects relevant tools based on your query (respects OpenAI's 128-tool limit)
- **Task Management & Context Awareness** - AI tracks completed tasks, creates plans, and maintains conversation history
- **OpenAI Function Calling** - Seamless tool execution with comprehensive parameter awareness
- **Secure Local Storage** - API keys and settings stored in %APPDATA%
- **Dark Theme Interface** - Clean, professional UI
- **PowerShell 5.1 & 7+ Compatible** - Works with Windows PowerShell and PowerShell Core

## Quick Start

1. Run the script:
```powershell
.\ChatClient.ps1
```

2. Open Settings panel and enter your OpenAI API key
3. Choose your preferred model (default: gpt-4o-mini)
4. Add custom instructions (optional)
5. Start chatting - AI automatically executes PowerShell tools as needed

### Keyboard Shortcuts
- **Enter** - Send message
- **Shift+Enter** - New line in message

## Tool Categories (145 Total)

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
- **create_plan** - Create multi-step plans with named goals
- **mark_task_complete** - Track task completion with timestamps
- **get_completed_tasks** - Review all completed tasks
- **get_current_plan** - Check plan progress with percentage
- **get_conversation_summary** - Get conversation history overview

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

With 145 tools available but OpenAI's limit of 128 tools per request, the application intelligently:
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
- Selected model (gpt-4o-mini, gpt-4o, gpt-4-turbo, gpt-3.5-turbo)
- Custom instructions
- Temperature (hardcoded to 0 for deterministic responses)

### Available Models
- **gpt-4o-mini** (default) - Fast and cost-effective
- **gpt-4o** - Most capable, balanced performance
- **gpt-4-turbo** - High performance with extended context
- **gpt-3.5-turbo** - Legacy model support

## Optional: Compile to Executable

Create a standalone .exe with no dependencies:

```powershell
Install-Module ps2exe -Scope CurrentUser
Invoke-ps2exe -inputFile .\ChatClient.ps1 -outputFile .\ChatClient.exe -noConsole -iconFile .\build\icon.ico
```

Results in a ~6MB executable with all 145 tools embedded.

## Requirements

- Windows PowerShell 5.1+ (pre-installed on Windows 10/11) or PowerShell 7+
- Internet connection for OpenAI API
- OpenAI API key (get one at platform.openai.com)

## Architecture

- **Single .ps1 file (~944 lines)** - All code in one portable script
- **Switch-based tool execution** - Clean mapping of 145 tool names to PowerShell commands
- **Dynamic tool selection** - Category-based filtering for optimal performance
- **WPF XAML UI** - Native Windows interface with dark theme
- **Zero external dependencies** - Uses only built-in Windows components
- **PowerShell version detection** - Automatically adapts to PS 5.1 or 7+ features
- **Temperature hardcoded to 0** - Ensures deterministic, consistent responses
- **Model verification** - Displays active model for each request

## Technical Details

### Keyboard Behavior
- **Enter** alone sends the message immediately
- **Shift+Enter** inserts a new line for multi-line messages
- Uses `PreviewKeyDown` event for reliable key handling

### Tool Execution Flow
1. User sends message to OpenAI
2. `Get-RelevantTools` analyzes query and selects up to 128 relevant tools
3. OpenAI decides which tools to invoke and with what parameters
4. `Invoke-PowerShellTool` executes PowerShell commands via switch statement
5. Results returned to OpenAI for natural language response
6. AI maintains full conversation context and task history

### Compatibility
- **PowerShell 5.1**: Uses manual PSObject property enumeration for JSON conversion
- **PowerShell 7+**: Uses `-AsHashtable` parameter for faster JSON conversion
- Automatically detects version at startup and adapts accordingly

## License

MIT License
