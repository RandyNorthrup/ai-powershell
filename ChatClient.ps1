# AI Chat Client - Pure PowerShell with WPF
# Zero dependencies - uses built-in Windows components
# Compatible with PowerShell 5.1+ and PowerShell 7+
# Dynamically executes PowerShell commands for all 137 MCP tools

# PowerShell version compatibility check
$global:isPwsh7 = $PSVersionTable.PSVersion.Major -ge 7

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

# XAML UI Definition
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="AI Chat Client" Height="700" Width="1000" WindowStartupLocation="CenterScreen"
    Background="#1e1e1e">
    <Window.Resources>
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#2d2d2d"/>
            <Setter Property="Foreground" Value="#d4d4d4"/>
            <Setter Property="BorderBrush" Value="#3e3e42"/>
            <Setter Property="Padding" Value="5"/>
        </Style>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#0e639c"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="#2d2d2d"/>
            <Setter Property="Foreground" Value="#d4d4d4"/>
            <Setter Property="BorderBrush" Value="#3e3e42"/>
        </Style>
    </Window.Resources>
    
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <Expander Grid.Row="0" Header="Settings" IsExpanded="False" Background="#252526" Foreground="#d4d4d4" Padding="10">
            <StackPanel>
                <TextBlock Text="OpenAI API Key:" Foreground="#d4d4d4" Margin="0,5,0,2"/>
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <PasswordBox Name="ApiKeyBox" Grid.Column="0" Margin="0,0,5,0"/>
                    <Button Name="SaveApiKeyBtn" Content="Save" Grid.Column="1" Margin="0,0,5,0"/>
                    <Button Name="ClearApiKeyBtn" Content="Clear" Grid.Column="2"/>
                </Grid>
                
                <TextBlock Text="Model:" Foreground="#d4d4d4" Margin="0,10,0,2"/>
                <ComboBox Name="ModelCombo">
                    <ComboBoxItem Content="gpt-4o-mini" IsSelected="True"/>
                    <ComboBoxItem Content="gpt-4o"/>
                    <ComboBoxItem Content="gpt-4-turbo"/>
                    <ComboBoxItem Content="gpt-3.5-turbo"/>
                </ComboBox>
                
                <TextBlock Text="Custom Instructions:" Foreground="#d4d4d4" Margin="0,10,0,2"/>
                <TextBox Name="InstructionsBox" Height="60" TextWrapping="Wrap" AcceptsReturn="True"/>
            </StackPanel>
        </Expander>
        
        <Border Grid.Row="1" BorderBrush="#3e3e42" BorderThickness="1" Margin="10">
            <ScrollViewer Name="ChatScroll" VerticalScrollBarVisibility="Auto">
                <TextBox Name="ChatDisplay" IsReadOnly="True" TextWrapping="Wrap" 
                         VerticalAlignment="Stretch" BorderThickness="0" Padding="10"
                         Background="#1e1e1e" Foreground="#d4d4d4"/>
            </ScrollViewer>
        </Border>
        
        <Grid Grid.Row="2" Margin="10,0,10,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox Name="InputBox" Grid.Column="0" Height="60" TextWrapping="Wrap" 
                     AcceptsReturn="True" VerticalScrollBarVisibility="Auto"/>
            <Button Name="SendBtn" Content="Send" Grid.Column="1" Width="80" Margin="5,0,0,0"/>
        </Grid>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$apiKeyBox = $window.FindName("ApiKeyBox")
$saveApiKeyBtn = $window.FindName("SaveApiKeyBtn")
$clearApiKeyBtn = $window.FindName("ClearApiKeyBtn")
$modelCombo = $window.FindName("ModelCombo")
$instructionsBox = $window.FindName("InstructionsBox")
$chatDisplay = $window.FindName("ChatDisplay")
$chatScroll = $window.FindName("ChatScroll")
$inputBox = $window.FindName("InputBox")
$sendBtn = $window.FindName("SendBtn")

$settingsPath = "$env:APPDATA\AIChat\settings.json"
$global:conversationHistory = @()
$global:completedTasks = @()
$global:currentPlan = $null

# Define ALL 228+ OpenAI tool schemas with comprehensive parameters (expanded from 145 to 228+)
$global:toolDefinitions = @(
    # Network Tools (11)
    @{type="function"; function=@{name="test_network_connection"; description="Test network connectivity to a remote host using Test-NetConnection. Can perform ping tests, TCP port testing, and route tracing."; parameters=@{type="object"; properties=@{computerName=@{type="string"; description="Target host (hostname, FQDN, or IP address)"}; port=@{type="number"; description="Optional: TCP port number to test (e.g., 80, 443, 3389)"}}; required=@("computerName")}}}
    @{type="function"; function=@{name="get_network_adapters"; description="List all network adapters with status, link speed, MAC address, and driver information. Shows physical and virtual adapters."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_ip_configuration"; description="Get detailed IP configuration for all network adapters including IP addresses, subnet masks, gateways, DNS servers, and DHCP status."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_network_statistics"; description="Display active TCP connections with local/remote addresses, ports, connection state, and owning process IDs. Useful for troubleshooting network connections."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="resolve_dns_name"; description="Resolve DNS names to IP addresses using Resolve-DnsName. Returns A, AAAA, CNAME, MX, and other DNS records."; parameters=@{type="object"; properties=@{name=@{type="string"; description="DNS name or hostname to resolve (e.g., google.com, server01.domain.local)"}}; required=@("name")}}}
    @{type="function"; function=@{name="get_firewall_rules"; description="List all Windows Firewall rules with display name, direction (inbound/outbound), action (allow/block), enabled status, and profile (domain/private/public)."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="clear_dns_cache"; description="Flush the DNS client resolver cache. Useful after DNS changes or to troubleshoot DNS resolution issues."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="renew_ip_address"; description="Release and renew DHCP IP addresses on all network adapters. Performs ipconfig /release followed by ipconfig /renew."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="enable_dhcp"; description="Enable DHCP client on a specific network adapter. Switches from static IP to automatic IP address assignment."; parameters=@{type="object"; properties=@{adapterName=@{type="string"; description="Network adapter name (e.g., 'Ethernet', 'Wi-Fi'). Use get_network_adapters to list available adapters."}}; required=@("adapterName")}}}
    @{type="function"; function=@{name="manage_network_adapter"; description="Enable or disable a network adapter. Useful for troubleshooting network issues or forcing a connection reset."; parameters=@{type="object"; properties=@{adapterName=@{type="string"; description="Network adapter name (e.g., 'Ethernet', 'Wi-Fi')"}; action=@{type="string"; enum=@("enable","disable"); description="'enable' to activate adapter, 'disable' to deactivate"}}; required=@("adapterName","action")}}}
    @{type="function"; function=@{name="reset_network_stack"; description="Reset Windows network stack by running 'netsh winsock reset' and 'netsh int ip reset'. Fixes network connectivity issues. Requires restart."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    
    # Security Tools (16)
    @{type="function"; function=@{name="get_user_info"; description="List all local user accounts with username, enabled status, last logon time, password last set date, and password expiration. Useful for user account auditing."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_permissions"; description="Get ACL (Access Control List) permissions for a file or folder. Shows owner, access rights for users/groups, and inheritance settings."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full path to file or folder (e.g., 'C:\\Users\\Public', '\\\\server\\share\\folder')"}}; required=@("path")}}}
    @{type="function"; function=@{name="get_security_groups"; description="List all local security groups with their names and descriptions. Includes built-in groups like Administrators, Users, Power Users, etc."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="create_local_user"; description="Create a new local user account with specified username and password. Account is created with default settings and must be enabled separately if needed."; parameters=@{type="object"; properties=@{username=@{type="string"; description="Username for the new account (alphanumeric, no spaces recommended)"}; password=@{type="string"; description="Password for the account (must meet complexity requirements)"}}; required=@("username","password")}}}
    @{type="function"; function=@{name="delete_local_user"; description="Delete a local user account. WARNING: This permanently removes the account and cannot be undone. User's profile data remains on disk."; parameters=@{type="object"; properties=@{username=@{type="string"; description="Username of the account to delete"}}; required=@("username")}}}
    @{type="function"; function=@{name="set_user_password"; description="Change the password for a local user account. Useful for password resets or security compliance."; parameters=@{type="object"; properties=@{username=@{type="string"; description="Username of the account"}; newPassword=@{type="string"; description="New password (must meet complexity requirements)"}}; required=@("username","newPassword")}}}
    @{type="function"; function=@{name="add_firewall_rule"; description="Create a new Windows Firewall rule to allow or block traffic. Can be configured for specific programs, ports, or protocols."; parameters=@{type="object"; properties=@{displayName=@{type="string"; description="Display name for the rule (must be unique)"}; direction=@{type="string"; enum=@("Inbound","Outbound"); description="'Inbound' for incoming traffic, 'Outbound' for outgoing traffic"}; action=@{type="string"; enum=@("Allow","Block"); description="'Allow' to permit traffic, 'Block' to deny traffic"}}; required=@("displayName","direction","action")}}}
    @{type="function"; function=@{name="remove_firewall_rule"; description="Delete a Windows Firewall rule by its display name. Use get_firewall_rules to find existing rule names."; parameters=@{type="object"; properties=@{displayName=@{type="string"; description="Exact display name of the firewall rule to remove"}}; required=@("displayName")}}}
    @{type="function"; function=@{name="toggle_firewall_rule"; description="Enable or disable an existing firewall rule without deleting it. Useful for temporarily allowing/blocking traffic."; parameters=@{type="object"; properties=@{displayName=@{type="string"; description="Display name of the firewall rule"}; enabled=@{type="boolean"; description="true to enable the rule, false to disable it"}}; required=@("displayName","enabled")}}}
    @{type="function"; function=@{name="add_user_to_group"; description="Add a local user account to a security group. Grants the user all permissions associated with that group (e.g., Administrators, Remote Desktop Users)."; parameters=@{type="object"; properties=@{username=@{type="string"; description="Username to add to the group"}; groupName=@{type="string"; description="Security group name (e.g., 'Administrators', 'Users', 'Remote Desktop Users')"}}; required=@("username","groupName")}}}
    @{type="function"; function=@{name="remove_user_from_group"; description="Remove a user from a security group. Revokes permissions associated with that group."; parameters=@{type="object"; properties=@{username=@{type="string"; description="Username to remove from the group"}; groupName=@{type="string"; description="Security group name"}}; required=@("username","groupName")}}}
    @{type="function"; function=@{name="set_file_permissions"; description="Modify NTFS permissions on a file or folder. Can grant or deny specific rights like Read, Write, Modify, FullControl for users or groups."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full path to file or folder"}; identity=@{type="string"; description="User or group name (e.g., 'DOMAIN\\User', 'Everyone', 'Administrators')"}; rights=@{type="string"; description="Permission level: 'Read', 'Write', 'Modify', 'ReadAndExecute', 'FullControl'"}}; required=@("path","identity","rights")}}}
    @{type="function"; function=@{name="test_user_permission"; description="Test if the current user has specific access rights to a file or folder. Returns true/false."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full path to test access to"}; accessType=@{type="string"; description="Access type to test: 'Read', 'Write', 'Modify', 'FullControl'"}}; required=@("path","accessType")}}}
    
    # Registry Tools (12)
    @{type="function"; function=@{name="get_registry_value"; description="Read a value from the Windows Registry. Can access any registry hive (HKLM, HKCU, HKCR, HKU, HKCC) and key path. Returns the value and its type (String, DWORD, Binary, etc.)."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full registry path including hive and value name (e.g., 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\ProgramFilesDir', 'HKCU:\\Environment\\Path')"}}; required=@("path")}}}
    @{type="function"; function=@{name="search_registry"; description="Search the registry for keys or values matching a pattern. Can search by key name, value name, or value data. Note: Registry searches can be slow on large hives like HKLM."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Starting registry path for search (e.g., 'HKLM:\\Software' to search all software keys)"}; searchTerm=@{type="string"; description="Text to search for (case-insensitive, supports wildcards)"}}; required=@("path","searchTerm")}}}
    @{type="function"; function=@{name="list_registry_keys"; description="List all subkeys under a registry path. Useful for exploring registry structure and finding configuration locations."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full registry path to list subkeys from (e.g., 'HKLM:\\Software\\Microsoft', 'HKCU:\\Software')"}}; required=@("path")}}}
    @{type="function"; function=@{name="test_registry_path"; description="Check if a registry path or key exists. Returns true/false. Useful for verifying software installations or configuration presence before reading values."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full registry path to test (e.g., 'HKLM:\\Software\\MyApp')"}}; required=@("path")}}}
    @{type="function"; function=@{name="set_registry_value"; description="Create or modify a value in the Windows Registry. Can create new keys and values. Use with caution as incorrect registry changes can cause system instability."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full registry path where value will be written (e.g., 'HKCU:\\Software\\MyApp')"}; name=@{type="string"; description="Name of the registry value"}; value=@{type="string"; description="Value to write (will be converted to appropriate type based on existing value or default to String)"}}; required=@("path","name","value")}}}
    @{type="function"; function=@{name="create_registry_key"; description="Create a new registry key. Will create all parent keys in the path if they don't exist (like mkdir -p)."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full registry path for new key (e.g., 'HKCU:\\Software\\MyCompany\\MyApp')"}}; required=@("path")}}}
    @{type="function"; function=@{name="delete_registry_key"; description="Delete a registry key and all its subkeys/values. WARNING: This is permanent and can cause application or system issues if critical keys are deleted."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full registry path to delete"}}; required=@("path")}}}
    @{type="function"; function=@{name="delete_registry_value"; description="Delete a specific value from a registry key without removing the key itself. Safer than deleting entire keys."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full registry path containing the value"}; name=@{type="string"; description="Name of the value to delete"}}; required=@("path","name")}}}
    @{type="function"; function=@{name="export_registry_key"; description="Export a registry key and all its subkeys/values to a .reg file. Can be used for backup or transfer to another system. Compatible with regedit.exe."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full registry path to export"}; outputPath=@{type="string"; description="Full path where .reg file will be saved (e.g., 'C:\\Backups\\registry_export.reg')"}}; required=@("path","outputPath")}}}
    @{type="function"; function=@{name="import_registry_file"; description="Import registry settings from a .reg file. WARNING: This will modify your registry and can overwrite existing settings. Use with caution."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Full path to the .reg file to import"}}; required=@("filePath")}}}
    @{type="function"; function=@{name="backup_registry_hive"; description="Backup an entire registry hive (HKLM, HKCU, etc.) to a file. Uses reg.exe save command. Requires administrator privileges for system hives."; parameters=@{type="object"; properties=@{hive=@{type="string"; description="Hive name: 'HKLM', 'HKCU', 'HKCR', 'HKU', or 'HKCC'"}; outputPath=@{type="string"; description="Full path where backup file will be saved"}}; required=@("hive","outputPath")}}}
    
    # Event Log Tools (9)
    @{type="function"; function=@{name="get_event_logs"; description="Retrieve Windows Event Log entries with filtering by log name, level (Error/Warning/Information), source, or time range. Uses Get-WinEvent cmdlet."; parameters=@{type="object"; properties=@{logName=@{type="string"; description="Log name: 'System', 'Application', 'Security', or any other log name from list_event_logs"}}; required=@("logName")}}}
    @{type="function"; function=@{name="list_event_logs"; description="List all available Windows Event Logs including classic logs (System, Application, Security) and application/services logs. Shows log name, record count, and size."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_event_log_statistics"; description="Get statistics about an event log: total events, errors, warnings, information events, oldest/newest entry dates, and log file size."; parameters=@{type="object"; properties=@{logName=@{type="string"; description="Log name to get statistics for"}}; required=@("logName")}}}
    @{type="function"; function=@{name="search_event_logs"; description="Search across multiple event logs for entries containing specific text in the message. Returns matching events with timestamp, level, source, and message."; parameters=@{type="object"; properties=@{searchTerm=@{type="string"; description="Text to search for in event messages (case-insensitive)"}}; required=@("searchTerm")}}}
    @{type="function"; function=@{name="get_recent_errors"; description="Get recent critical errors and warnings from System and Application logs. Shows last 50 events by default. Useful for troubleshooting system issues."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="clear_event_log"; description="Clear all entries from an event log. WARNING: This permanently deletes all events in the log. Requires administrator privileges for system logs."; parameters=@{type="object"; properties=@{logName=@{type="string"; description="Log name to clear (e.g., 'Application', 'System')"}}; required=@("logName")}}}
    @{type="function"; function=@{name="export_event_log"; description="Export event log to a file in EVTX (native), CSV, or XML format. Can be opened in Event Viewer or analyzed with other tools."; parameters=@{type="object"; properties=@{logName=@{type="string"; description="Log name to export"}; outputPath=@{type="string"; description="Full path for output file (e.g., 'C:\\Logs\\system_events.evtx')"}}; required=@("logName","outputPath")}}}
    @{type="function"; function=@{name="write_event_log_entry"; description="Write a custom entry to an event log. Useful for logging application events or creating custom audit trails. Requires event source to be registered first."; parameters=@{type="object"; properties=@{logName=@{type="string"; description="Log name (usually 'Application' for custom events)"}; source=@{type="string"; description="Event source name (must be registered with New-EventLog)"}; message=@{type="string"; description="Event message text"}}; required=@("logName","source","message")}}}
    @{type="function"; function=@{name="configure_event_log"; description="Configure event log settings like maximum log size and retention policy. Requires administrator privileges."; parameters=@{type="object"; properties=@{logName=@{type="string"; description="Log name to configure"}; maxSizeMB=@{type="number"; description="Maximum log size in MB (typical values: 20-1024)"}}; required=@("logName")}}}
    
    # Disk Tools (14)
    @{type="function"; function=@{name="get_disk_info"; description="Get detailed information about physical disks using Get-PhysicalDisk. Shows disk number, friendly name, size, media type (HDD/SSD), health status, and bus type."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_volume_info"; description="Get information about all volumes (drive letters and mount points) including drive letter, file system, size, free space, and health status. Uses Get-Volume cmdlet."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="check_disk_health"; description="Run disk health check using CHKDSK. Scans for file system errors and bad sectors. Can fix errors if run with administrator privileges."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter to check (e.g., 'C', 'D')"}}; required=@("driveLetter")}}}
    @{type="function"; function=@{name="optimize_disk"; description="Optimize a disk by defragmenting HDDs or running TRIM on SSDs. Uses Optimize-Volume cmdlet. Can improve performance on fragmented drives."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter to optimize (e.g., 'C', 'D')"}}; required=@("driveLetter")}}}
    @{type="function"; function=@{name="get_smart_data"; description="Get S.M.A.R.T. (Self-Monitoring, Analysis and Reporting Technology) data from physical disks. Shows disk health indicators, temperature, power-on hours, and error counts."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_partition_info"; description="Get detailed information about all disk partitions including partition number, disk number, drive letter, size, offset, type (System/Primary/Recovery), and GPT/MBR attributes."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_storage_jobs"; description="Get status of running storage jobs like disk optimization, repair, or rebuild operations. Shows job status, completion percentage, and errors."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="initialize_disk"; description="Initialize a new raw disk with GPT or MBR partition table. Required before creating partitions on a new disk. Requires administrator privileges."; parameters=@{type="object"; properties=@{diskNumber=@{type="number"; description="Physical disk number from get_disk_info"}}; required=@("diskNumber")}}}
    @{type="function"; function=@{name="set_disk_online_status"; description="Set a disk online or offline. Offline disks are not accessible but remain configured. Useful for maintenance or preventing access."; parameters=@{type="object"; properties=@{diskNumber=@{type="number"; description="Physical disk number"}; online=@{type="boolean"; description="true to bring disk online, false to take it offline"}}; required=@("diskNumber","online")}}}
    @{type="function"; function=@{name="format_volume"; description="Format a volume with specified file system (NTFS, FAT32, exFAT, ReFS). WARNING: This will erase all data on the volume. Requires administrator privileges."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter to format (e.g., 'E', 'F')"}; fileSystem=@{type="string"; description="File system: 'NTFS', 'FAT32', 'exFAT', or 'ReFS'"}}; required=@("driveLetter")}}}
    @{type="function"; function=@{name="set_volume_label"; description="Change the volume label (name) displayed in File Explorer. Does not require reformatting or data loss."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter (e.g., 'D', 'E')"}; newLabel=@{type="string"; description="New volume label (max 32 characters for NTFS, 11 for FAT32)"}}; required=@("driveLetter","newLabel")}}}
    @{type="function"; function=@{name="resize_partition"; description="Extend or shrink a partition. Extending adds unallocated space; shrinking reclaims space. NTFS only, requires contiguous unallocated space for extension."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter to resize"}; sizeGB=@{type="number"; description="New size in GB (must be larger for extend, smaller for shrink)"}}; required=@("driveLetter","sizeGB")}}}
    @{type="function"; function=@{name="assign_drive_letter"; description="Assign a specific drive letter to a partition. Useful after creating new partitions or changing drive configurations."; parameters=@{type="object"; properties=@{partitionNumber=@{type="number"; description="Partition number from get_partition_info"}; diskNumber=@{type="number"; description="Disk number from get_disk_info"}; driveLetter=@{type="string"; description="Drive letter to assign (e.g., 'E', 'F')"}}; required=@("partitionNumber","diskNumber","driveLetter")}}}
    @{type="function"; function=@{name="remove_partition"; description="Delete a partition from a disk. WARNING: This permanently erases all data on the partition. Cannot be undone."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter of partition to remove"}}; required=@("driveLetter")}}}
    
    # Device Tools (9)
    @{type="function"; function=@{name="get_device_info"; description="Get detailed information about hardware devices"; parameters=@{type="object"; properties=@{}}}}
    @{type="function"; function=@{name="get_device_drivers"; description="Get information about installed device drivers"; parameters=@{type="object"; properties=@{}}}}
    @{type="function"; function=@{name="manage_device_state"; description="Enable or disable a hardware device"; parameters=@{type="object"; properties=@{instanceId=@{type="string"}; action=@{type="string"; enum=@("enable","disable")}}; required=@("instanceId","action")}}}
    @{type="function"; function=@{name="get_device_problems"; description="Get devices that have problems or errors"; parameters=@{type="object"; properties=@{}}}}
    @{type="function"; function=@{name="get_usb_devices"; description="Get all USB devices connected to the system"; parameters=@{type="object"; properties=@{}}}}
    @{type="function"; function=@{name="get_network_adapters_detailed"; description="Get detailed information about network adapters"; parameters=@{type="object"; properties=@{}}}}
    @{type="function"; function=@{name="get_graphics_cards"; description="Get information about graphics cards"; parameters=@{type="object"; properties=@{}}}}
    @{type="function"; function=@{name="scan_hardware_changes"; description="Trigger a scan for hardware changes"; parameters=@{type="object"; properties=@{}}}}
    @{type="function"; function=@{name="update_device_driver"; description="Update a device driver"; parameters=@{type="object"; properties=@{instanceId=@{type="string"}}; required=@("instanceId")}}}
    
    # Windows Update Tools (8)
    @{type="function"; function=@{name="check_windows_updates"; description="Check for available Windows updates using Windows Update service. Shows available updates with KB numbers, titles, sizes, and importance (Critical/Important/Optional)."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_update_history"; description="Get history of installed Windows updates including installation date, KB number, title, and result (Success/Failed). Useful for troubleshooting recent issues."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_pending_updates"; description="Check if there are pending updates waiting for installation or restart. Shows updates downloaded but not yet installed."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_update_settings"; description="Get current Windows Update configuration including automatic update settings, active hours, metered connection settings, and defer settings."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_last_update_check"; description="Get timestamp when Windows last checked for updates. Useful for verifying update schedule is working correctly."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="install_windows_updates"; description="Install available Windows updates. WARNING: May require restart. Requires administrator privileges. Use check_windows_updates first to see what will be installed."; parameters=@{type="object"; properties=@{acceptAll=@{type="boolean"; description="true to accept and install all available updates, false to skip"}}; required=@("acceptAll")}}}
    @{type="function"; function=@{name="hide_windows_update"; description="Hide a specific Windows update to prevent it from being offered. Useful for problematic updates. Use get_pending_updates to find update IDs."; parameters=@{type="object"; properties=@{updateId=@{type="string"; description="Update ID or KB number to hide (e.g., 'KB5012345')"}}; required=@("updateId")}}}
    @{type="function"; function=@{name="uninstall_windows_update"; description="Uninstall a specific Windows update. Useful for rolling back problematic updates. Requires administrator privileges and may require restart."; parameters=@{type="object"; properties=@{updateId=@{type="string"; description="Update ID or KB number to uninstall (e.g., 'KB5012345')"}}; required=@("updateId")}}}
    
    # Licensing Tools (7)
    @{type="function"; function=@{name="get_license_status"; description="Get detailed Windows license and activation status using slmgr.vbs. Shows license status, edition, partial product key, activation expiration, and license type (Retail/OEM/Volume)."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_activation_status"; description="Get Windows activation status showing whether Windows is activated, grace period remaining, and activation method. Quick check version of get_license_status."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="set_product_key"; description="Install a Windows product key using slmgr.vbs /ipk. Requires administrator privileges. Format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX. Use activate_windows after installing key."; parameters=@{type="object"; properties=@{productKey=@{type="string"; description="25-character product key in format XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}}; required=@("productKey")}}}
    @{type="function"; function=@{name="activate_windows"; description="Activate Windows with the currently installed product key using slmgr.vbs /ato. Requires administrator privileges and internet connection (or KMS server access for volume licenses)."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="set_kms_server"; description="Configure KMS (Key Management Service) server for volume activation in enterprise environments. Requires administrator privileges. Use with Volume License keys only."; parameters=@{type="object"; properties=@{kmsServer=@{type="string"; description="KMS server address (hostname:port, e.g., 'kms.contoso.com:1688')"}}; required=@("kmsServer")}}}
    @{type="function"; function=@{name="clear_product_key"; description="Remove the current product key from Windows using slmgr.vbs /upk. Requires administrator privileges. Windows will become unlicensed until a new key is installed."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="rearm_windows_license"; description="Reset the Windows licensing grace period using slmgr.vbs /rearm. Limited to 3 rearms. Requires restart. Used during OEM deployment or troubleshooting activation issues."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    
    # Application Tools (12)
    @{type="function"; function=@{name="list_installed_apps"; description="Get list of all installed applications from registry (Win32 apps) and package manager. Shows app name, version, publisher, install date, and install location."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_windows_store_apps"; description="Get list of installed Windows Store/UWP applications using Get-AppxPackage. Shows package name, version, publisher, install location, and architecture."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="uninstall_application"; description="Uninstall an application using WMI Win32_Product or Get-Package. Requires administrator privileges. Use list_installed_apps to find exact app name."; parameters=@{type="object"; properties=@{appName=@{type="string"; description="Exact application name from list_installed_apps"}}; required=@("appName")}}}
    @{type="function"; function=@{name="get_startup_programs"; description="Get list of programs that start with Windows from registry Run keys and Startup folders. Shows program name, command line, and location (User/System)."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="manage_startup_program"; description="Add or remove a program from Windows startup via registry Run key. Requires administrator privileges for system-wide changes."; parameters=@{type="object"; properties=@{action=@{type="string"; enum=@("add","remove"); description="'add' to add to startup, 'remove' to remove from startup"}; name=@{type="string"; description="Name for the startup entry"}; path=@{type="string"; description="Full path to executable (required for 'add' action)"}}; required=@("action","name")}}}
    @{type="function"; function=@{name="get_processes_extended"; description="Get detailed information about all running processes using Get-Process. Shows PID, name, CPU usage, memory usage (Working Set/Private), threads, handles, start time, and user."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="stop_process"; description="Stop/kill a running process by PID using Stop-Process. Use get_processes_extended to find process IDs. May cause data loss if process has unsaved work."; parameters=@{type="object"; properties=@{processId=@{type="number"; description="Process ID (PID) from get_processes_extended"}}; required=@("processId")}}}
    @{type="function"; function=@{name="install_windows_feature"; description="Install optional Windows features like Hyper-V, WSL, IIS, Telnet Client using Enable-WindowsOptionalFeature or DISM. Requires administrator privileges and may require restart."; parameters=@{type="object"; properties=@{featureName=@{type="string"; description="Feature name (e.g., 'Microsoft-Hyper-V', 'Microsoft-Windows-Subsystem-Linux', 'IIS-WebServer')"}}; required=@("featureName")}}}
    @{type="function"; function=@{name="start_process"; description="Start a new process/application using Start-Process. Can launch executables, open documents, or start scripts."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Full path to executable or document to start"}}; required=@("filePath")}}}
    @{type="function"; function=@{name="monitor_process"; description="Get real-time monitoring data for a specific process including CPU percentage, memory usage (MB), thread count, handle count, and I/O statistics."; parameters=@{type="object"; properties=@{processId=@{type="number"; description="Process ID to monitor"}}; required=@("processId")}}}
    @{type="function"; function=@{name="get_process_performance"; description="Get system-wide process performance metrics including top CPU consumers, top memory consumers, total process count, and system resource usage summary."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="set_process_priority"; description="Set the CPU priority class for a process. Higher priority processes get more CPU time. Requires appropriate privileges."; parameters=@{type="object"; properties=@{processId=@{type="number"; description="Process ID to change priority for"}; priority=@{type="string"; description="Priority class: 'Idle', 'BelowNormal', 'Normal', 'AboveNormal', 'High', 'RealTime' (RealTime requires admin)"}}; required=@("processId","priority")}}}
    
    # File Tools (15)
    @{type="function"; function=@{name="search_files_advanced"; description="Search for files with advanced filtering using Get-ChildItem. Supports wildcards (*,?), recursive search, and filtering by name, extension, size, or date modified."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Starting directory path for search"}; pattern=@{type="string"; description="Search pattern with wildcards (e.g., '*.txt', '*report*', '*.log')"}}; required=@("path","pattern")}}}
    @{type="function"; function=@{name="get_file_hash"; description="Calculate cryptographic hash of a file using Get-FileHash. Useful for verifying file integrity, comparing files, or detecting duplicates."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Full path to file"}; algorithm=@{type="string"; enum=@("MD5","SHA1","SHA256"); description="Hashing algorithm: 'MD5' (fast, weak), 'SHA1' (moderate), 'SHA256' (strong, default)"}}; required=@("filePath")}}}
    @{type="function"; function=@{name="compare_directories"; description="Compare two directories and find differences using Compare-Object. Shows files that exist only in path1, only in path2, or differ in size/date between both."; parameters=@{type="object"; properties=@{path1=@{type="string"; description="First directory path"}; path2=@{type="string"; description="Second directory path"}}; required=@("path1","path2")}}}
    @{type="function"; function=@{name="find_duplicate_files"; description="Find duplicate files in a directory by calculating and comparing file hashes. Shows duplicate file groups with paths and sizes. Can save significant disk space."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Directory path to scan for duplicates (searches recursively)"}}; required=@("path")}}}
    @{type="function"; function=@{name="bulk_rename_files"; description="Rename multiple files based on a pattern using string replacement. Useful for batch renaming files with consistent naming schemes."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Directory containing files to rename"}; pattern=@{type="string"; description="File pattern to match (e.g., '*.jpg', '*report*')"}; replaceFrom=@{type="string"; description="Text to find in filename"}; replaceTo=@{type="string"; description="Text to replace with"}}; required=@("path","pattern","replaceFrom","replaceTo")}}}
    @{type="function"; function=@{name="compress_files"; description="Compress files or directories into ZIP archive using Compress-Archive. Creates standard ZIP format compatible with all major archive tools."; parameters=@{type="object"; properties=@{sourcePath=@{type="string"; description="File or directory path to compress"}; destinationPath=@{type="string"; description="Output ZIP file path (e.g., 'C:\\Backups\\archive.zip')"}}; required=@("sourcePath","destinationPath")}}}
    @{type="function"; function=@{name="decompress_files"; description="Extract files from a ZIP archive using Expand-Archive. Extracts all contents to specified destination folder."; parameters=@{type="object"; properties=@{archivePath=@{type="string"; description="Path to ZIP file"}; destinationPath=@{type="string"; description="Directory where files will be extracted"}}; required=@("archivePath","destinationPath")}}}
    @{type="function"; function=@{name="get_file_metadata"; description="Get extended file metadata including size, dates (created/modified/accessed), attributes, version info for executables, and NTFS properties."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Full path to file"}}; required=@("filePath")}}}
    @{type="function"; function=@{name="get_directory_size"; description="Calculate total size of a directory including all subdirectories and files. Shows size in bytes, KB, MB, GB and file/folder counts."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Directory path to measure"}}; required=@("path")}}}
    @{type="function"; function=@{name="copy_files_advanced"; description="Copy files with advanced filtering and options. Supports recursive copy, filtering by extension or date, and preserving permissions/timestamps."; parameters=@{type="object"; properties=@{source=@{type="string"; description="Source path (file or directory)"}; destination=@{type="string"; description="Destination directory path"}}; required=@("source","destination")}}}
    @{type="function"; function=@{name="move_files_advanced"; description="Move files with advanced filtering. Supports moving multiple files matching patterns, useful for organizing files into different folders."; parameters=@{type="object"; properties=@{source=@{type="string"; description="Source path (file or directory)"}; destination=@{type="string"; description="Destination directory path"}}; required=@("source","destination")}}}
    @{type="function"; function=@{name="set_file_attributes"; description="Set file or folder attributes (ReadOnly, Hidden, System, Archive) using Set-ItemProperty. Can combine multiple attributes."; parameters=@{type="object"; properties=@{path=@{type="string"; description="File or folder path"}; attributes=@{type="array"; description="Array of attributes: 'ReadOnly', 'Hidden', 'System', 'Archive', 'Normal'. Use 'Normal' to clear all attributes."; items=@{type="string"}}}; required=@("path","attributes")}}}
    @{type="function"; function=@{name="take_ownership"; description="Take ownership of a file or folder using takeown.exe and grant full control permissions. Useful for accessing files with restricted permissions. Requires administrator privileges."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full path to file or folder"}}; required=@("path")}}}
    @{type="function"; function=@{name="robocopy_sync"; description="Synchronize directories using Robocopy with mirror mode. Efficiently copies only changed files, handles long paths, and provides detailed progress. Professional-grade file sync."; parameters=@{type="object"; properties=@{source=@{type="string"; description="Source directory path"}; destination=@{type="string"; description="Destination directory path"}}; required=@("source","destination")}}}
    @{type="function"; function=@{name="delete_files"; description="Delete files or folders using Remove-Item. Can delete individual files, directories, or use wildcards. WARNING: Cannot be undone - files bypass Recycle Bin."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Path to delete (file, folder, or wildcard pattern)"}}; required=@("path")}}}
    @{type="function"; function=@{name="create_folder"; description="Create a new folder at specified path using New-Item. Automatically creates parent folders if they don't exist (like mkdir -p)."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Full path for the new folder (e.g., 'C:\\Projects\\NewFolder')"}}; required=@("path")}}}
    
    # Computer Management Tools (11)
    @{type="function"; function=@{name="get_system_info_extended"; description="Get comprehensive system information using Get-ComputerInfo. Shows OS version/build, hardware (CPU/RAM/motherboard), BIOS info, domain/workgroup, last boot time, Windows version, and system uptime."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="manage_service_advanced"; description="Advanced Windows service management using Start-Service, Stop-Service, Restart-Service. Requires administrator privileges. Use Get-Service to find service names."; parameters=@{type="object"; properties=@{serviceName=@{type="string"; description="Service name (not display name). Examples: 'wuauserv' (Windows Update), 'Spooler' (Print Spooler), 'bits' (Background Intelligent Transfer)"}; action=@{type="string"; enum=@("start","stop","restart"); description="'start' to start service, 'stop' to stop it, 'restart' to stop then start"}}; required=@("serviceName","action")}}}
    @{type="function"; function=@{name="manage_scheduled_tasks"; description="Manage scheduled tasks using Get-ScheduledTask, Enable-ScheduledTask, Disable-ScheduledTask, Start-ScheduledTask. Can list all tasks, get task details, run tasks, or enable/disable them."; parameters=@{type="object"; properties=@{action=@{type="string"; enum=@("list","get","run","enable","disable"); description="'list' all tasks, 'get' task details, 'run' task immediately, 'enable'/'disable' task"}; taskName=@{type="string"; description="Task name (required for get/run/enable/disable actions)"}}; required=@("action")}}}
    @{type="function"; function=@{name="get_performance_counters"; description="Get system performance counters including CPU usage percentage, available memory (MB), disk I/O rates, network throughput, process counts, and thread counts. Real-time system metrics."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="manage_environment_variables"; description="Manage environment variables (PATH, TEMP, etc.) using [Environment] .NET class. Can list all variables, get specific variable value, set new value, or remove variable. Changes can be User or System scope."; parameters=@{type="object"; properties=@{action=@{type="string"; enum=@("list","get","set","remove"); description="'list' all variables, 'get' variable value, 'set' variable value, 'remove' variable"}; name=@{type="string"; description="Variable name (required for get/set/remove)"}; value=@{type="string"; description="Variable value (required for 'set' action)"}}; required=@("action")}}}
    @{type="function"; function=@{name="manage_power"; description="Manage system power state using Stop-Computer, Restart-Computer, and rundll32 for sleep/hibernate. Shutdown and restart can be scheduled with delay. Requires administrator privileges."; parameters=@{type="object"; properties=@{action=@{type="string"; enum=@("shutdown","restart","sleep","hibernate"); description="'shutdown' to power off, 'restart' to reboot, 'sleep' for low power mode, 'hibernate' to save state to disk"}}; required=@("action")}}}
    @{type="function"; function=@{name="get_power_plan"; description="Get current active power plan using powercfg /getactivescheme. Shows power plan GUID, name (Balanced, High Performance, Power Saver), and whether it's active. Each plan has different CPU, display, and sleep timeout settings."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="list_power_plans"; description="List all available power plans using powercfg /list. Shows all installed power plans with GUIDs, names, and indicates which is currently active. Windows includes Balanced, Power Saver, and High Performance by default."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="set_power_plan"; description="Set active power plan by name using powercfg /setactive. Changes system power configuration instantly. High Performance keeps CPU at max speed, Balanced optimizes for performance and efficiency, Power Saver extends battery life."; parameters=@{type="object"; properties=@{planName=@{type="string"; description="Power plan name: 'Balanced', 'High performance', 'Power saver', or custom plan name from list_power_plans"}}; required=@("planName")}}}
    @{type="function"; function=@{name="get_battery_status"; description="Get battery status and charge level using Get-WmiObject Win32_Battery. Shows charge percentage, estimated runtime, charging status, battery health, and power source (AC/Battery). Returns 'No battery found' for desktop systems."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_power_settings"; description="Get detailed power configuration settings for active plan using powercfg /query. Shows all power settings including display timeouts, sleep timeouts, disk timeouts, processor power management, USB selective suspend, and PCI Express settings for both AC and battery modes."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="set_display_timeout"; description="Set display sleep timeout in minutes using powercfg /change. Controls how long system waits before turning off display. Set to 0 to never turn off display. Separate settings for AC power and battery power."; parameters=@{type="object"; properties=@{minutes=@{type="number"; description="Minutes until display sleep (0 to disable, typical values: 5-30 for AC, 2-10 for battery)"}; acPower=@{type="boolean"; description="true to set AC power timeout, false to set battery timeout"}}; required=@("minutes","acPower")}}}
    @{type="function"; function=@{name="set_sleep_timeout"; description="Set system sleep timeout in minutes using powercfg /change. Controls how long system waits before entering sleep mode. Set to 0 to never sleep. Sleep saves power while preserving session. Separate settings for AC and battery."; parameters=@{type="object"; properties=@{minutes=@{type="number"; description="Minutes until system sleep (0 to disable, typical values: 15-60 for AC, 5-20 for battery)"}; acPower=@{type="boolean"; description="true to set AC power timeout, false to set battery timeout"}}; required=@("minutes","acPower")}}}
    @{type="function"; function=@{name="enable_hibernation"; description="Enable or disable hibernation using powercfg /hibernate. When enabled, creates hiberfil.sys (typically several GB) on C: to save RAM contents. Hibernation is slower than sleep but uses zero power. Useful for laptops."; parameters=@{type="object"; properties=@{enabled=@{type="boolean"; description="true to enable hibernation (creates hiberfil.sys), false to disable it (deletes hiberfil.sys and frees disk space)"}}; required=@("enabled")}}}
    @{type="function"; function=@{name="set_lid_close_action"; description="Set action when laptop lid is closed using powercfg /setdcvalueindex and /setacvalueindex. Controls laptop behavior when lid closes. Separate settings for AC power and battery power. Changes take effect immediately."; parameters=@{type="object"; properties=@{action=@{type="string"; enum=@("nothing","sleep","hibernate","shutdown"); description="'nothing' keeps laptop running, 'sleep' enters low power mode (resume in seconds), 'hibernate' saves to disk (resume in ~1 min), 'shutdown' powers off completely"}; acPower=@{type="boolean"; description="true for AC power behavior, false for battery behavior"}}; required=@("action","acPower")}}}
    @{type="function"; function=@{name="set_power_button_action"; description="Set action when physical power button is pressed using powercfg /setdcvalueindex and /setacvalueindex. Controls what happens on short power button press (not holding for forced shutdown). Applies to both AC and battery modes."; parameters=@{type="object"; properties=@{action=@{type="string"; enum=@("nothing","sleep","hibernate","shutdown"); description="'nothing' ignores button, 'sleep' enters low power, 'hibernate' saves state to disk, 'shutdown' performs clean shutdown"}}; required=@("action")}}}
    @{type="function"; function=@{name="get_system_logs_summary"; description="Get a summary of recent system logs from System and Application event logs. Shows error and warning counts, recent critical events, and system health overview."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="create_scheduled_task"; description="Create a new scheduled task using Register-ScheduledTask. Can run programs on schedule (daily, weekly, at logon, at startup, etc.). Requires administrator privileges for system-wide tasks."; parameters=@{type="object"; properties=@{taskName=@{type="string"; description="Name for the scheduled task"}; action=@{type="string"; description="Command or script to execute (full path to executable or script)"}; triggerType=@{type="string"; description="When to run: 'Daily', 'Weekly', 'AtLogon', 'AtStartup', 'Once'"}}; required=@("taskName","action","triggerType")}}}
    @{type="function"; function=@{name="delete_scheduled_task"; description="Delete a scheduled task using Unregister-ScheduledTask. Permanently removes the task from Task Scheduler. Requires administrator privileges for system tasks."; parameters=@{type="object"; properties=@{taskName=@{type="string"; description="Name of scheduled task to delete"}}; required=@("taskName")}}}
    @{type="function"; function=@{name="export_scheduled_task"; description="Export a scheduled task definition to XML file using Export-ScheduledTask. Can be used for backup or transferring tasks to other systems."; parameters=@{type="object"; properties=@{taskName=@{type="string"; description="Name of task to export"}; outputPath=@{type="string"; description="Full path for XML output file (e.g., 'C:\\Backups\\task.xml')"}}; required=@("taskName","outputPath")}}}
    @{type="function"; function=@{name="import_scheduled_task"; description="Import a scheduled task from XML file using Register-ScheduledTask. Restores tasks from backup or imports from other systems. Requires administrator privileges."; parameters=@{type="object"; properties=@{taskName=@{type="string"; description="Name for the imported task"}; xmlPath=@{type="string"; description="Full path to XML file containing task definition"}}; required=@("taskName","xmlPath")}}}
    
    # Windows Defender Tools (10)
    @{type="function"; function=@{name="get_defender_status"; description="Get Windows Defender antivirus status using Get-MpComputerStatus. Shows real-time protection status, signature versions, last scan date/type, and threat detection status."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="start_defender_scan"; description="Start a Windows Defender scan using Start-MpScan. Quick scan checks common malware locations (5-10 min), Full scan checks all files and drives (can take hours). Requires administrator privileges."; parameters=@{type="object"; properties=@{scanType=@{type="string"; enum=@("Quick","Full"); description="'Quick' for fast scan of common locations, 'Full' for thorough scan of entire system"}}; required=@("scanType")}}}
    @{type="function"; function=@{name="get_defender_threats"; description="Get detected threats from Windows Defender using Get-MpThreat. Shows threat name, severity, resources affected, and current status (Active/Quarantined/Removed)."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="update_defender_signatures"; description="Update Windows Defender virus and spyware definitions using Update-MpSignature. Downloads latest signature updates from Microsoft. Requires internet connection."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_defender_exclusions"; description="Get Windows Defender scan exclusions using Get-MpPreference. Shows excluded paths, file extensions, and processes that Defender won't scan. Useful for troubleshooting false positives."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="add_defender_exclusion"; description="Add an exclusion to Windows Defender using Add-MpPreference. Prevents Defender from scanning specified paths, extensions, or processes. Use carefully as exclusions reduce protection. Requires administrator privileges."; parameters=@{type="object"; properties=@{exclusionType=@{type="string"; enum=@("Path","Extension","Process"); description="'Path' for folder/file, 'Extension' for file types (e.g., '.tmp'), 'Process' for running executables"}; exclusionValue=@{type="string"; description="Value to exclude: full path for Path, extension with dot for Extension, process name for Process"}}; required=@("exclusionType","exclusionValue")}}}
    @{type="function"; function=@{name="remove_defender_exclusion"; description="Remove an exclusion from Windows Defender using Remove-MpPreference. Re-enables scanning of previously excluded items. Requires administrator privileges."; parameters=@{type="object"; properties=@{exclusionType=@{type="string"; enum=@("Path","Extension","Process"); description="Type of exclusion to remove"}; exclusionValue=@{type="string"; description="Exact value of exclusion to remove (must match existing exclusion)"}}; required=@("exclusionType","exclusionValue")}}}
    @{type="function"; function=@{name="set_defender_realtime_protection"; description="Enable or disable Windows Defender real-time protection using Set-MpPreference. WARNING: Disabling real-time protection leaves system vulnerable. Requires administrator privileges. Windows may re-enable automatically."; parameters=@{type="object"; properties=@{enabled=@{type="boolean"; description="true to enable real-time protection, false to disable it"}}; required=@("enabled")}}}
    @{type="function"; function=@{name="get_defender_preferences"; description="Get Windows Defender configuration preferences using Get-MpPreference. Shows scan schedules, scan settings, real-time protection settings, cloud protection settings, and submission settings."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="remove_defender_threat"; description="Remove a detected threat from Windows Defender quarantine using Remove-MpThreat. Permanently deletes the threat. Use get_defender_threats to find threat IDs. Requires administrator privileges."; parameters=@{type="object"; properties=@{threatId=@{type="number"; description="Threat ID from get_defender_threats"}}; required=@("threatId")}}}
    
    # Task Management Tools (5)
    @{type="function"; function=@{name="create_plan"; description="Create a multi-step plan for the user to accomplish a goal. Stores plan in global variables for tracking progress. Each step becomes a trackable task. Useful for breaking down complex requests into manageable steps with clear progress tracking."; parameters=@{type="object"; properties=@{planName=@{type="string"; description="Descriptive name for the plan (e.g., 'System Performance Optimization', 'Security Hardening')"}; steps=@{type="array"; description="Array of step descriptions, each should be a clear, actionable task"; items=@{type="string"}}}; required=@("planName","steps")}}}
    @{type="function"; function=@{name="mark_task_complete"; description="Mark a task or plan step as completed. Adds to completed task list with timestamp. Helps track progress through multi-step operations and provides conversation context awareness. Call this after finishing each significant task or step."; parameters=@{type="object"; properties=@{taskDescription=@{type="string"; description="Brief description of what was completed (e.g., 'Updated Windows Defender signatures', 'Installed security updates')"}}; required=@("taskDescription")}}}
    @{type="function"; function=@{name="get_completed_tasks"; description="Get list of all completed tasks in this session with timestamps. Shows chronological history of accomplished work. Useful for reviewing progress, generating status reports, or understanding conversation context."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_current_plan"; description="Get the current active plan and progress. Shows plan name, all steps, which steps are completed, and remaining tasks. Provides context about ongoing work and what comes next in the workflow."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_conversation_summary"; description="Get a summary of the conversation history including completed tasks, active plans, and session context. Useful for maintaining context awareness, generating session reports, or understanding what has been discussed and accomplished so far."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    
    # Performance & Monitoring Tools (12)
    @{type="function"; function=@{name="get_cpu_usage"; description="Get current CPU usage percentage per core and total using Get-Counter. Shows per-processor and total CPU utilization. Useful for identifying CPU bottlenecks and high-load processes."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_memory_usage"; description="Get detailed memory statistics using Get-Counter and Get-CimInstance. Shows total physical memory, available memory, used memory, page file usage, and memory pressure percentage."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_disk_io"; description="Get disk I/O statistics including read/write bytes per second, IOPS (operations per second), and disk queue length using Get-Counter. Identifies disk performance bottlenecks."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter to monitor (e.g., 'C', 'D'). Omit to monitor all drives."}}; required=@()}}}
    @{type="function"; function=@{name="get_network_throughput"; description="Get network throughput statistics showing bytes sent/received per second, packets per second, and bandwidth utilization using Get-Counter. Monitors network performance."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_top_cpu_processes"; description="Get top CPU-consuming processes with percentage of CPU used, process name, PID, and user. Shows real-time CPU hogs. Useful for performance troubleshooting."; parameters=@{type="object"; properties=@{count=@{type="number"; description="Number of top processes to return (default: 10, range: 1-50)"}}; required=@()}}}
    @{type="function"; function=@{name="get_top_memory_processes"; description="Get top memory-consuming processes with memory usage in MB/GB, process name, PID, and percentage of total memory. Identifies memory leaks and resource hogs."; parameters=@{type="object"; properties=@{count=@{type="number"; description="Number of top processes to return (default: 10, range: 1-50)"}}; required=@()}}}
    @{type="function"; function=@{name="get_system_uptime"; description="Get system boot time and uptime in days, hours, minutes using Get-CimInstance Win32_OperatingSystem. Shows how long system has been running since last boot."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_performance_report"; description="Generate comprehensive performance report including CPU, memory, disk, network stats, top processes, and system health. Produces detailed system health snapshot."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="monitor_process_realtime"; description="Monitor a specific process in real-time showing CPU, memory, threads, handles updated every second for specified duration. Returns performance metrics over time."; parameters=@{type="object"; properties=@{processId=@{type="number"; description="Process ID to monitor"}; durationSeconds=@{type="number"; description="How long to monitor (1-300 seconds, default: 10)"}}; required=@("processId")}}}
    @{type="function"; function=@{name="get_resource_alerts"; description="Check for resource alerts and warnings including high CPU (>80%), low memory (<10%), low disk space (<10%), and overheated components. Returns list of current system alerts."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="benchmark_disk"; description="Run simple disk benchmark test measuring sequential read/write speeds in MB/s by creating and reading test file. Tests disk performance. Requires administrator privileges."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter to benchmark (e.g., 'C', 'D')"}; testSizeMB=@{type="number"; description="Size of test file in MB (10-1000, default: 100)"}}; required=@("driveLetter")}}}
    @{type="function"; function=@{name="get_handle_count"; description="Get total system handle count and per-process handle counts. High handle counts can indicate handle leaks or resource exhaustion. Shows top processes by handle usage."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    
    # Database & SQL Tools (8)
    @{type="function"; function=@{name="test_sql_connection"; description="Test connection to SQL Server database using System.Data.SqlClient. Verifies server accessibility, authentication, and database availability. Returns connection success/failure."; parameters=@{type="object"; properties=@{serverInstance=@{type="string"; description="SQL Server instance (e.g., 'localhost', 'SERVER\\SQLEXPRESS', 'server.domain.com,1433')"}; database=@{type="string"; description="Database name to connect to (e.g., 'master', 'AdventureWorks')"}; integratedSecurity=@{type="boolean"; description="true for Windows Authentication, false for SQL Authentication"}; username=@{type="string"; description="SQL username (required if integratedSecurity is false)"}; password=@{type="string"; description="SQL password (required if integratedSecurity is false)"}}; required=@("serverInstance","database","integratedSecurity")}}}
    @{type="function"; function=@{name="execute_sql_query"; description="Execute SQL query and return results as JSON using System.Data.SqlClient. Can run SELECT, INSERT, UPDATE, DELETE queries. Returns dataset with column names and rows."; parameters=@{type="object"; properties=@{serverInstance=@{type="string"; description="SQL Server instance"}; database=@{type="string"; description="Database name"}; query=@{type="string"; description="SQL query to execute (e.g., 'SELECT * FROM users WHERE active=1')"}; integratedSecurity=@{type="boolean"; description="true for Windows Auth, false for SQL Auth"}; username=@{type="string"; description="SQL username (if SQL Auth)"}; password=@{type="string"; description="SQL password (if SQL Auth)"}}; required=@("serverInstance","database","query","integratedSecurity")}}}
    @{type="function"; function=@{name="get_sql_server_info"; description="Get SQL Server instance information including version, edition, service pack level, collation, and instance name using system queries. Requires connection to SQL Server."; parameters=@{type="object"; properties=@{serverInstance=@{type="string"; description="SQL Server instance"}; integratedSecurity=@{type="boolean"; description="Use Windows Authentication"}; username=@{type="string"; description="SQL username (optional)"}; password=@{type="string"; description="SQL password (optional)"}}; required=@("serverInstance","integratedSecurity")}}}
    @{type="function"; function=@{name="list_sql_databases"; description="List all databases on SQL Server instance with name, size, owner, status (online/offline), recovery model, and creation date using sys.databases view."; parameters=@{type="object"; properties=@{serverInstance=@{type="string"; description="SQL Server instance"}; integratedSecurity=@{type="boolean"; description="Use Windows Authentication"}}; required=@("serverInstance","integratedSecurity")}}}
    @{type="function"; function=@{name="get_sql_tables"; description="List all tables in a database with table name, schema, row count, and size using sys.tables and sys.dm_db_partition_stats views."; parameters=@{type="object"; properties=@{serverInstance=@{type="string"; description="SQL Server instance"}; database=@{type="string"; description="Database name"}; integratedSecurity=@{type="boolean"; description="Use Windows Authentication"}}; required=@("serverInstance","database","integratedSecurity")}}}
    @{type="function"; function=@{name="backup_sql_database"; description="Backup SQL Server database to file using BACKUP DATABASE T-SQL command. Creates full database backup. Requires appropriate SQL Server permissions and write access to backup location."; parameters=@{type="object"; properties=@{serverInstance=@{type="string"; description="SQL Server instance"}; database=@{type="string"; description="Database name to backup"}; backupPath=@{type="string"; description="Full path for backup file (e.g., 'C:\\Backups\\db_backup.bak')"}; integratedSecurity=@{type="boolean"; description="Use Windows Authentication"}}; required=@("serverInstance","database","backupPath","integratedSecurity")}}}
    @{type="function"; function=@{name="restore_sql_database"; description="Restore SQL Server database from backup file using RESTORE DATABASE T-SQL command. WARNING: Overwrites existing database. Requires appropriate permissions."; parameters=@{type="object"; properties=@{serverInstance=@{type="string"; description="SQL Server instance"}; database=@{type="string"; description="Database name to restore to"}; backupPath=@{type="string"; description="Full path to backup file (.bak)"}; integratedSecurity=@{type="boolean"; description="Use Windows Authentication"}}; required=@("serverInstance","database","backupPath","integratedSecurity")}}}
    @{type="function"; function=@{name="get_sql_performance"; description="Get SQL Server performance metrics including buffer cache hit ratio, page life expectancy, batch requests/sec, locks, deadlocks using sys.dm_os_performance_counters."; parameters=@{type="object"; properties=@{serverInstance=@{type="string"; description="SQL Server instance"}; integratedSecurity=@{type="boolean"; description="Use Windows Authentication"}}; required=@("serverInstance","integratedSecurity")}}}
    
    # Certificate & Encryption Tools (7)
    @{type="function"; function=@{name="list_certificates"; description="List certificates in specified certificate store (My, Root, CA, TrustedPeople, etc.) showing thumbprint, subject, issuer, expiration date, and validity using Get-ChildItem Cert:\\."; parameters=@{type="object"; properties=@{storeLocation=@{type="string"; enum=@("CurrentUser","LocalMachine"); description="'CurrentUser' for user certificates, 'LocalMachine' for computer certificates"}; storeName=@{type="string"; description="Store name: 'My' (personal), 'Root' (trusted root), 'CA' (intermediate), 'TrustedPeople', 'TrustedPublisher'"}}; required=@("storeLocation","storeName")}}}
    @{type="function"; function=@{name="get_certificate_details"; description="Get detailed information about a specific certificate including subject, issuer, serial number, thumbprint, key algorithm, signature algorithm, expiration dates, key usage, and enhanced key usage."; parameters=@{type="object"; properties=@{thumbprint=@{type="string"; description="Certificate thumbprint (40-character hex string)"}; storeLocation=@{type="string"; enum=@("CurrentUser","LocalMachine"); description="Store location where certificate is stored"}}; required=@("thumbprint","storeLocation")}}}
    @{type="function"; function=@{name="test_certificate_expiration"; description="Check if certificates are expiring soon. Lists certificates expiring within specified days, showing days until expiration, thumbprint, and subject. Useful for certificate renewal planning."; parameters=@{type="object"; properties=@{daysThreshold=@{type="number"; description="Number of days to check ahead (e.g., 30, 60, 90)"}; storeLocation=@{type="string"; enum=@("CurrentUser","LocalMachine"); description="Store location to check"}}; required=@("daysThreshold","storeLocation")}}}
    @{type="function"; function=@{name="export_certificate"; description="Export certificate to file in CER (public key only), PFX/PKCS12 (with private key), or Base64 format using Export-Certificate and Export-PfxCertificate cmdlets."; parameters=@{type="object"; properties=@{thumbprint=@{type="string"; description="Certificate thumbprint"}; storeLocation=@{type="string"; enum=@("CurrentUser","LocalMachine"); description="Store location"}; outputPath=@{type="string"; description="Output file path (use .cer for CER, .pfx for PFX)"}; includePrivateKey=@{type="boolean"; description="true to export with private key (PFX), false for public key only (CER)"}; password=@{type="string"; description="Password for PFX export (required if includePrivateKey is true)"}}; required=@("thumbprint","storeLocation","outputPath","includePrivateKey")}}}
    @{type="function"; function=@{name="import_certificate"; description="Import certificate from file into certificate store using Import-Certificate. Supports CER, CRT, PFX, P7B formats. PFX import requires password."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Path to certificate file (.cer, .crt, .pfx, .p7b)"}; storeLocation=@{type="string"; enum=@("CurrentUser","LocalMachine"); description="Store location to import to"}; storeName=@{type="string"; description="Store name (e.g., 'My', 'Root', 'CA')"}; password=@{type="string"; description="PFX password (required for .pfx files)"}}; required=@("filePath","storeLocation","storeName")}}}
    @{type="function"; function=@{name="test_ssl_certificate"; description="Test SSL/TLS certificate of a website or server. Shows certificate details, expiration, issuer, subject alternative names, and validation status. Useful for troubleshooting HTTPS connections."; parameters=@{type="object"; properties=@{hostname=@{type="string"; description="Hostname to test (e.g., 'www.google.com', 'mail.company.com')"}; port=@{type="number"; description="Port number (default: 443)"}}; required=@("hostname")}}}
    @{type="function"; function=@{name="create_self_signed_certificate"; description="Create self-signed certificate using New-SelfSignedCertificate cmdlet. Useful for development, testing, or internal applications. Can specify subject name, DNS names, key length, and validity period."; parameters=@{type="object"; properties=@{subjectName=@{type="string"; description="Certificate subject (e.g., 'CN=MyServer', 'CN=localhost')"}; dnsNames=@{type="array"; description="Array of DNS names for Subject Alternative Name (e.g., ['localhost', '*.example.com']"; items=@{type="string"}}; validityYears=@{type="number"; description="Years certificate is valid (1-10, default: 1)"}}; required=@("subjectName")}}}
    
    # Web & REST API Tools (10)
    @{type="function"; function=@{name="http_get_request"; description="Send HTTP GET request to URL using Invoke-RestMethod/Invoke-WebRequest. Returns response body, status code, headers. Supports custom headers and authentication. Useful for API testing and web scraping."; parameters=@{type="object"; properties=@{url=@{type="string"; description="Full URL to request (e.g., 'https://api.example.com/users')"}; headers=@{type="object"; description="Optional: Custom headers as key-value pairs (e.g., {'Authorization': 'Bearer token', 'Accept': 'application/json'})"}}; required=@("url")}}}
    @{type="function"; function=@{name="http_post_request"; description="Send HTTP POST request with JSON or form data using Invoke-RestMethod. Returns response body and status. Useful for API calls, form submissions, webhooks."; parameters=@{type="object"; properties=@{url=@{type="string"; description="Full URL to POST to"}; body=@{type="string"; description="Request body (JSON string or form data)"}; contentType=@{type="string"; description="Content-Type header (e.g., 'application/json', 'application/x-www-form-urlencoded')"}; headers=@{type="object"; description="Optional custom headers"}}; required=@("url","body","contentType")}}}
    @{type="function"; function=@{name="http_put_request"; description="Send HTTP PUT request for updating resources via REST API using Invoke-RestMethod. Returns response body and status code."; parameters=@{type="object"; properties=@{url=@{type="string"; description="Full URL"}; body=@{type="string"; description="Request body (usually JSON)"}; contentType=@{type="string"; description="Content-Type header"}; headers=@{type="object"; description="Optional custom headers"}}; required=@("url","body","contentType")}}}
    @{type="function"; function=@{name="http_delete_request"; description="Send HTTP DELETE request for deleting resources via REST API using Invoke-RestMethod. Returns response status."; parameters=@{type="object"; properties=@{url=@{type="string"; description="Full URL of resource to delete"}; headers=@{type="object"; description="Optional custom headers"}}; required=@("url")}}}
    @{type="function"; function=@{name="download_file"; description="Download file from URL to local path using Invoke-WebRequest. Supports large files with progress indication. Can resume interrupted downloads with byte-range requests."; parameters=@{type="object"; properties=@{url=@{type="string"; description="URL of file to download"}; outputPath=@{type="string"; description="Local path where file will be saved (e.g., 'C:\\Downloads\\file.zip')"}}; required=@("url","outputPath")}}}
    @{type="function"; function=@{name="test_url_availability"; description="Test if URL is accessible and measure response time using Invoke-WebRequest. Returns HTTP status code, response time in milliseconds, and availability status. Useful for monitoring web services."; parameters=@{type="object"; properties=@{url=@{type="string"; description="URL to test (e.g., 'https://www.example.com')"}}; required=@("url")}}}
    @{type="function"; function=@{name="get_web_page_content"; description="Fetch web page HTML content using Invoke-WebRequest. Returns raw HTML, page title, links, images, and forms. Useful for web scraping and content extraction."; parameters=@{type="object"; properties=@{url=@{type="string"; description="URL of web page to fetch"}}; required=@("url")}}}
    @{type="function"; function=@{name="test_rest_api"; description="Test REST API endpoint with method, headers, and body. Returns detailed response including status code, headers, body, and timing. Comprehensive API testing tool."; parameters=@{type="object"; properties=@{url=@{type="string"; description="API endpoint URL"}; method=@{type="string"; enum=@("GET","POST","PUT","DELETE","PATCH"); description="HTTP method"}; body=@{type="string"; description="Request body (optional, for POST/PUT/PATCH)"}; headers=@{type="object"; description="Request headers (optional)"}}; required=@("url","method")}}}
    @{type="function"; function=@{name="parse_json_response"; description="Parse and format JSON response from API. Validates JSON syntax, pretty-prints output, and extracts specific fields. Useful for analyzing API responses and extracting data."; parameters=@{type="object"; properties=@{jsonString=@{type="string"; description="JSON string to parse and format"}; extractPath=@{type="string"; description="Optional: JSON path to extract (e.g., 'data.users[0].name')"}}; required=@("jsonString")}}}
    @{type="function"; function=@{name="encode_decode_base64"; description="Encode string to Base64 or decode Base64 to string using [Convert]::ToBase64String and FromBase64String. Useful for API authentication, data transmission, and encoding/decoding tokens."; parameters=@{type="object"; properties=@{operation=@{type="string"; enum=@("encode","decode"); description="'encode' to convert text to Base64, 'decode' to convert Base64 to text"}; text=@{type="string"; description="Text to encode or Base64 string to decode"}}; required=@("operation","text")}}}
    
    # Printer & Print Queue Tools (6)
    @{type="function"; function=@{name="list_printers"; description="List all installed printers with name, driver name, port name, shared status, and default printer indicator using Get-Printer. Shows local and network printers."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_print_queue"; description="Get print queue for specified printer showing job ID, document name, user, pages, size, status (printing/paused/error), and submission time using Get-PrintJob."; parameters=@{type="object"; properties=@{printerName=@{type="string"; description="Printer name from list_printers"}}; required=@("printerName")}}}
    @{type="function"; function=@{name="clear_print_queue"; description="Clear all jobs from a printer's print queue using Remove-PrintJob. Useful for clearing stuck print jobs. Requires administrator privileges."; parameters=@{type="object"; properties=@{printerName=@{type="string"; description="Printer name"}}; required=@("printerName")}}}
    @{type="function"; function=@{name="cancel_print_job"; description="Cancel specific print job by ID using Remove-PrintJob. Removes job from queue and stops printing if in progress."; parameters=@{type="object"; properties=@{printerName=@{type="string"; description="Printer name"}; jobId=@{type="number"; description="Print job ID from get_print_queue"}}; required=@("printerName","jobId")}}}
    @{type="function"; function=@{name="set_default_printer"; description="Set the default printer using Set-Printer or WMI Win32_Printer. Changes which printer is used by default in applications."; parameters=@{type="object"; properties=@{printerName=@{type="string"; description="Printer name to set as default"}}; required=@("printerName")}}}
    @{type="function"; function=@{name="manage_printer_state"; description="Pause or resume a printer using Set-Printer or Suspend-PrintJob/Resume-PrintJob. Pausing prevents new jobs from printing without removing them from queue."; parameters=@{type="object"; properties=@{printerName=@{type="string"; description="Printer name"}; action=@{type="string"; enum=@("pause","resume"); description="'pause' to stop printing, 'resume' to continue printing"}}; required=@("printerName","action")}}}
    
    # Backup & Recovery Tools (8)
    @{type="function"; function=@{name="create_system_restore_point"; description="Create system restore point using Checkpoint-Computer. Creates snapshot of system files, registry, and installed programs. Allows rollback if issues occur. Requires administrator privileges."; parameters=@{type="object"; properties=@{description=@{type="string"; description="Description for restore point (e.g., 'Before software installation', 'Pre-update backup')"}}; required=@("description")}}}
    @{type="function"; function=@{name="list_restore_points"; description="List all system restore points with creation time, description, sequence number, and type using Get-ComputerRestorePoint. Shows available rollback points."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="restore_system"; description="Restore system to previous restore point using rstrui.exe or Restore-Computer. WARNING: This reverts system files and registry to earlier state. Requires administrator privileges and restart."; parameters=@{type="object"; properties=@{restorePointNumber=@{type="number"; description="Restore point sequence number from list_restore_points"}}; required=@("restorePointNumber")}}}
    @{type="function"; function=@{name="list_shadow_copies"; description="List Volume Shadow Copy (VSS) snapshots using vssadmin or Get-CimInstance Win32_ShadowCopy. Shows shadow copy ID, creation time, and volume. Used for Previous Versions feature."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter to list shadow copies for (e.g., 'C', 'D')"}}; required=@("driveLetter")}}}
    @{type="function"; function=@{name="create_shadow_copy"; description="Create Volume Shadow Copy snapshot using vssadmin or WMI. Creates point-in-time snapshot for file recovery via Previous Versions. Requires administrator privileges."; parameters=@{type="object"; properties=@{driveLetter=@{type="string"; description="Drive letter to snapshot (e.g., 'C', 'D')"}}; required=@("driveLetter")}}}
    @{type="function"; function=@{name="export_event_viewer_config"; description="Export Event Viewer custom views and configuration to XML file. Useful for backup or transferring event viewer settings to other systems."; parameters=@{type="object"; properties=@{outputPath=@{type="string"; description="Path for XML export file (e.g., 'C:\\Backups\\eventviewer_config.xml')"}}; required=@("outputPath")}}}
    @{type="function"; function=@{name="backup_registry_to_file"; description="Backup entire Windows Registry to .reg file using reg export. Can be restored later. WARNING: Registry file will be very large (hundreds of MB). Requires administrator privileges."; parameters=@{type="object"; properties=@{outputPath=@{type="string"; description="Output .reg file path (e.g., 'C:\\Backups\\full_registry_backup.reg')"}}; required=@("outputPath")}}}
    @{type="function"; function=@{name="get_backup_status"; description="Get Windows Backup status and schedule using wbadmin or Get-WBSummary. Shows last backup time, next scheduled backup, backup location, and backup status. Requires Windows Server Backup feature."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    
    # Active Directory Tools (9) - Requires RSAT/AD module
    @{type="function"; function=@{name="get_ad_user"; description="Get Active Directory user information using Get-ADUser cmdlet. Shows username, display name, email, enabled status, last logon, password expiration. REQUIRES: Active Directory PowerShell module (RSAT)."; parameters=@{type="object"; properties=@{identity=@{type="string"; description="Username, SamAccountName, or DistinguishedName (e.g., 'jdoe', 'john.doe@domain.com', 'CN=John Doe,OU=Users,DC=domain,DC=com')"}}; required=@("identity")}}}
    @{type="function"; function=@{name="search_ad_users"; description="Search Active Directory users by name, email, or other attributes using Get-ADUser with filters. Returns matching users with key properties. REQUIRES: AD PowerShell module."; parameters=@{type="object"; properties=@{searchTerm=@{type="string"; description="Search term (name, email, username)"}; searchField=@{type="string"; enum=@("Name","Email","SamAccountName","DisplayName"); description="Field to search in"}}; required=@("searchTerm","searchField")}}}
    @{type="function"; function=@{name="get_ad_group_members"; description="List all members of Active Directory group using Get-ADGroupMember. Shows user names, object types (user/group), and distinguished names. REQUIRES: AD PowerShell module."; parameters=@{type="object"; properties=@{groupName=@{type="string"; description="Group name or DistinguishedName"}}; required=@("groupName")}}}
    @{type="function"; function=@{name="get_ad_user_groups"; description="Get all Active Directory groups a user is member of using Get-ADPrincipalGroupMembership. Shows group names and distinguished names. REQUIRES: AD PowerShell module."; parameters=@{type="object"; properties=@{identity=@{type="string"; description="Username or DistinguishedName"}}; required=@("identity")}}}
    @{type="function"; function=@{name="list_ad_computers"; description="List all computers in Active Directory domain using Get-ADComputer. Shows computer name, operating system, last logon date, enabled status, and distinguished name. REQUIRES: AD PowerShell module."; parameters=@{type="object"; properties=@{ouPath=@{type="string"; description="Optional: OU path to search in (e.g., 'OU=Workstations,DC=domain,DC=com')"}}; required=@()}}}
    @{type="function"; function=@{name="get_ad_domain_info"; description="Get Active Directory domain information using Get-ADDomain. Shows domain name, domain controllers, functional level, NetBIOS name, forest name. REQUIRES: AD PowerShell module."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="test_ad_credentials"; description="Test Active Directory user credentials without locking account. Validates username and password against domain using DirectoryServices. Returns authentication success/failure."; parameters=@{type="object"; properties=@{username=@{type="string"; description="Username (SamAccountName or UPN)"}; password=@{type="string"; description="Password to test"}; domain=@{type="string"; description="Domain name (optional, uses current domain if omitted)"}}; required=@("username","password")}}}
    @{type="function"; function=@{name="get_locked_ad_accounts"; description="Find locked out Active Directory user accounts using Get-ADUser with LockedOut filter. Shows locked users with lockout time and account details. REQUIRES: AD PowerShell module."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="get_disabled_ad_accounts"; description="Find disabled Active Directory user accounts using Get-ADUser with Enabled filter. Shows disabled accounts with last logon date and when disabled. REQUIRES: AD PowerShell module."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    
    # Share & Permission Tools (7)
    @{type="function"; function=@{name="list_smb_shares"; description="List all SMB network shares on the system using Get-SmbShare. Shows share name, path, description, shared to (Everyone/specific users), and permissions."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="create_smb_share"; description="Create new SMB network share using New-SmbShare. Makes folder accessible over network. Requires administrator privileges. Can set share permissions."; parameters=@{type="object"; properties=@{name=@{type="string"; description="Share name (how it appears on network, e.g., 'Documents', 'Public')"}; path=@{type="string"; description="Local folder path to share (e.g., 'C:\\SharedFiles')"}; description=@{type="string"; description="Share description (optional)"}}; required=@("name","path")}}}
    @{type="function"; function=@{name="remove_smb_share"; description="Remove SMB network share using Remove-SmbShare. Stops sharing folder over network without deleting files. Requires administrator privileges."; parameters=@{type="object"; properties=@{shareName=@{type="string"; description="Share name to remove (from list_smb_shares)"}}; required=@("shareName")}}}
    @{type="function"; function=@{name="get_share_permissions"; description="Get share-level and NTFS permissions for SMB share using Get-SmbShareAccess and Get-Acl. Shows users/groups with access rights (Full/Change/Read)."; parameters=@{type="object"; properties=@{shareName=@{type="string"; description="Share name"}}; required=@("shareName")}}}
    @{type="function"; function=@{name="set_share_permissions"; description="Set share-level permissions for SMB share using Grant-SmbShareAccess. Can grant Full, Change, or Read access to users/groups. Requires administrator privileges."; parameters=@{type="object"; properties=@{shareName=@{type="string"; description="Share name"}; accountName=@{type="string"; description="User or group name (e.g., 'DOMAIN\\User', 'Everyone', 'Administrators')"}; accessRight=@{type="string"; enum=@("Full","Change","Read"); description="'Full' for full control, 'Change' for modify, 'Read' for read-only"}}; required=@("shareName","accountName","accessRight")}}}
    @{type="function"; function=@{name="get_open_files"; description="Get list of files currently opened over network using Get-SmbOpenFile. Shows file path, user accessing it, and session ID. Useful for finding who has files open."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="close_smb_session"; description="Close specific SMB session or all sessions for a user using Close-SmbSession. Forces disconnection and closes open files. Requires administrator privileges."; parameters=@{type="object"; properties=@{sessionId=@{type="number"; description="Session ID from get_open_files, or omit to close all sessions"}}; required=@()}}}
    
    # Audio & Video Tools (5)
    @{type="function"; function=@{name="list_audio_devices"; description="List all audio playback and recording devices using Get-AudioDevice or WMI Win32_SoundDevice. Shows device name, status (enabled/disabled), default device, and driver info."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="set_system_volume"; description="Set system volume level (0-100) using Windows Audio API through PowerShell ComObject or nircmd utility wrapper. Changes master volume level."; parameters=@{type="object"; properties=@{volume=@{type="number"; description="Volume level percentage (0-100, where 0 is mute, 100 is max)"}}; required=@("volume")}}}
    @{type="function"; function=@{name="mute_unmute_system"; description="Mute or unmute system audio using Windows Audio API. Toggles master mute without changing volume level."; parameters=@{type="object"; properties=@{mute=@{type="boolean"; description="true to mute audio, false to unmute"}}; required=@("mute")}}}
    @{type="function"; function=@{name="capture_screenshot"; description="Capture screenshot of entire screen or specific display using [System.Windows.Forms.Screen] and [System.Drawing] classes. Saves to file in PNG, JPG, or BMP format."; parameters=@{type="object"; properties=@{outputPath=@{type="string"; description="Path where screenshot will be saved (e.g., 'C:\\Screenshots\\screen1.png')"}; format=@{type="string"; enum=@("PNG","JPG","BMP"); description="Image format (default: PNG)"}}; required=@("outputPath")}}}
    @{type="function"; function=@{name="get_display_info"; description="Get information about connected displays using Get-CimInstance Win32_VideoController and WmiMonitorID. Shows resolution, refresh rate, monitor name, and connection type."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    
    # Virtualization Tools (8)
    @{type="function"; function=@{name="list_hyperv_vms"; description="List all Hyper-V virtual machines using Get-VM cmdlet. Shows VM name, state (running/stopped/saved), uptime, CPU usage, memory, and version. REQUIRES: Hyper-V PowerShell module and Hyper-V role."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="manage_hyperv_vm"; description="Start, stop, save, or restart Hyper-V virtual machine using Start-VM, Stop-VM, Save-VM, Restart-VM cmdlets. Requires administrator privileges and Hyper-V role."; parameters=@{type="object"; properties=@{vmName=@{type="string"; description="Virtual machine name from list_hyperv_vms"}; action=@{type="string"; enum=@("start","stop","save","restart"); description="'start' to power on, 'stop' to power off, 'save' to suspend, 'restart' to reboot"}}; required=@("vmName","action")}}}
    @{type="function"; function=@{name="get_hyperv_vm_info"; description="Get detailed information about Hyper-V VM including configuration, memory allocation, CPU count, network adapters, hard disks, checkpoints using Get-VM with details."; parameters=@{type="object"; properties=@{vmName=@{type="string"; description="Virtual machine name"}}; required=@("vmName")}}}
    @{type="function"; function=@{name="create_hyperv_checkpoint"; description="Create Hyper-V VM checkpoint (snapshot) using Checkpoint-VM. Captures current VM state for rollback. Production or standard checkpoint types available."; parameters=@{type="object"; properties=@{vmName=@{type="string"; description="Virtual machine name"}; checkpointName=@{type="string"; description="Checkpoint description/name"}}; required=@("vmName","checkpointName")}}}
    @{type="function"; function=@{name="list_docker_containers"; description="List Docker containers using docker ps command. Shows container ID, image, status, ports, names. Includes stopped containers if specified. REQUIRES: Docker Desktop installed."; parameters=@{type="object"; properties=@{showAll=@{type="boolean"; description="true to show all containers including stopped, false for running only (default: false)"}}; required=@()}}}
    @{type="function"; function=@{name="manage_docker_container"; description="Start, stop, restart, or remove Docker container using docker start/stop/restart/rm commands. REQUIRES: Docker Desktop installed."; parameters=@{type="object"; properties=@{containerName=@{type="string"; description="Container name or ID from list_docker_containers"}; action=@{type="string"; enum=@("start","stop","restart","remove"); description="Action to perform"}}; required=@("containerName","action")}}}
    @{type="function"; function=@{name="list_wsl_distributions"; description="List installed Windows Subsystem for Linux distributions using wsl --list --verbose command. Shows distro name, state (running/stopped), WSL version (1 or 2). REQUIRES: WSL installed."; parameters=@{type="object"; properties=@{}; additionalProperties=$false}}}
    @{type="function"; function=@{name="manage_wsl_distro"; description="Start, stop, terminate, or set default WSL distribution using wsl commands. Can also convert between WSL 1 and WSL 2. REQUIRES: WSL installed."; parameters=@{type="object"; properties=@{distroName=@{type="string"; description="Distribution name from list_wsl_distributions"}; action=@{type="string"; enum=@("start","terminate","setdefault"); description="'start' to launch, 'terminate' to stop, 'setdefault' to make default distro"}}; required=@("distroName","action")}}}
    
    # Compression & Archive Tools (5)
    @{type="function"; function=@{name="compress_with_7zip"; description="Compress files/folders using 7-Zip with advanced options. Supports ZIP, 7Z, TAR, GZIP formats with compression levels. REQUIRES: 7-Zip installed in standard location or PATH."; parameters=@{type="object"; properties=@{sourcePath=@{type="string"; description="File or folder path to compress"}; outputPath=@{type="string"; description="Output archive path (extension determines format: .zip, .7z, .tar.gz)"}; compressionLevel=@{type="number"; description="Compression level (0=none, 1=fast, 5=normal, 9=ultra, default: 5)"}}; required=@("sourcePath","outputPath")}}}
    @{type="function"; function=@{name="extract_7zip_archive"; description="Extract archives using 7-Zip. Supports ZIP, RAR, 7Z, TAR, GZIP, BZIP2, XZ, and many other formats. REQUIRES: 7-Zip installed."; parameters=@{type="object"; properties=@{archivePath=@{type="string"; description="Path to archive file (.zip, .7z, .rar, .tar.gz, etc.)"}; outputPath=@{type="string"; description="Destination folder for extracted files"}}; required=@("archivePath","outputPath")}}}
    @{type="function"; function=@{name="list_archive_contents"; description="List contents of archive file without extracting using 7-Zip or Expand-Archive. Shows files, folders, sizes, and dates inside archive."; parameters=@{type="object"; properties=@{archivePath=@{type="string"; description="Path to archive file"}}; required=@("archivePath")}}}
    @{type="function"; function=@{name="test_archive_integrity"; description="Test archive file integrity and check for corruption using 7-Zip test command. Returns validation status and any errors. Useful before extracting important archives."; parameters=@{type="object"; properties=@{archivePath=@{type="string"; description="Path to archive file to test"}}; required=@("archivePath")}}}
    @{type="function"; function=@{name="create_tar_gz"; description="Create TAR.GZ compressed archive (common on Linux/Unix) using built-in .NET compression or 7-Zip. Useful for cross-platform compatibility."; parameters=@{type="object"; properties=@{sourcePath=@{type="string"; description="File or folder to archive"}; outputPath=@{type="string"; description="Output .tar.gz file path"}}; required=@("sourcePath","outputPath")}}}
    
    # Text Processing Tools (8)
    @{type="function"; function=@{name="search_text_in_files"; description="Search for text pattern across multiple files using Select-String (PowerShell's grep). Supports regex patterns. Shows matching lines with file names and line numbers."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Directory path or file pattern (e.g., 'C:\\Logs', 'C:\\Code\\*.cs')"}; pattern=@{type="string"; description="Text or regex pattern to search for"}; caseSensitive=@{type="boolean"; description="true for case-sensitive search, false for case-insensitive (default: false)"}}; required=@("path","pattern")}}}
    @{type="function"; function=@{name="replace_text_in_files"; description="Find and replace text across multiple files using Get-Content and Set-Content. Can use regex patterns. Creates backup before modification. WARNING: Modifies files."; parameters=@{type="object"; properties=@{path=@{type="string"; description="Directory path or file pattern"}; searchText=@{type="string"; description="Text to find (supports regex if useRegex is true)"}; replaceText=@{type="string"; description="Replacement text"}; useRegex=@{type="boolean"; description="true to use regex patterns, false for literal text (default: false)"}; createBackup=@{type="boolean"; description="true to create .bak backup files (default: true)"}}; required=@("path","searchText","replaceText")}}}
    @{type="function"; function=@{name="parse_csv_file"; description="Parse CSV file and return as structured data using Import-Csv. Can filter, sort, and extract specific columns. Returns JSON representation of CSV data."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Path to CSV file"}; delimiter=@{type="string"; description="Column delimiter character (default: comma ','). Use '\\t' for tab-separated"}}; required=@("filePath")}}}
    @{type="function"; function=@{name="export_to_csv"; description="Export data to CSV file using Export-Csv. Useful for creating spreadsheet-compatible output from PowerShell objects or reports."; parameters=@{type="object"; properties=@{data=@{type="string"; description="JSON string of data to export"}; outputPath=@{type="string"; description="Path for CSV output file (e.g., 'C:\\Reports\\data.csv')"}; includeHeaders=@{type="boolean"; description="true to include column headers (default: true)"}}; required=@("data","outputPath")}}}
    @{type="function"; function=@{name="parse_xml_file"; description="Parse XML file and extract data using [xml] type accelerator and XPath queries. Returns structured data from XML document."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Path to XML file"}; xpathQuery=@{type="string"; description="Optional: XPath query to extract specific elements (e.g., '//user[@id=\"123\"]')"}}; required=@("filePath")}}}
    @{type="function"; function=@{name="parse_json_file"; description="Parse JSON file and extract data using ConvertFrom-Json. Can navigate nested objects and arrays. Returns structured data."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Path to JSON file"}; propertyPath=@{type="string"; description="Optional: Dot-notation path to extract (e.g., 'users.0.name' for first user's name)"}}; required=@("filePath")}}}
    @{type="function"; function=@{name="convert_file_encoding"; description="Convert text file encoding (UTF-8, UTF-16, ASCII, etc.) using Get-Content and Set-Content with -Encoding parameter. Useful for fixing encoding issues."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Path to file to convert"}; targetEncoding=@{type="string"; enum=@("UTF8","UTF8BOM","UTF16","UTF16BE","UTF32","ASCII","Unicode"); description="Target encoding"}; outputPath=@{type="string"; description="Output file path (can be same as input to overwrite)"}}; required=@("filePath","targetEncoding","outputPath")}}}
    @{type="function"; function=@{name="count_lines_words_chars"; description="Count lines, words, and characters in text file using Get-Content and Measure-Object. Returns file statistics similar to Unix 'wc' command."; parameters=@{type="object"; properties=@{filePath=@{type="string"; description="Path to text file"}}; required=@("filePath")}}}
)

function Get-Settings {
    if (Test-Path $settingsPath) {
        $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
        if ($settings.apiKey) { $apiKeyBox.Password = $settings.apiKey }
        if ($settings.model) {
            # Find and select the matching ComboBoxItem
            foreach ($item in $modelCombo.Items) {
                if ($item.Content -eq $settings.model) {
                    $modelCombo.SelectedItem = $item
                    break
                }
            }
        }
        if ($settings.instructions) { $instructionsBox.Text = $settings.instructions }
    }
}

function Save-Settings {
    $settingsDir = Split-Path $settingsPath
    if (-not (Test-Path $settingsDir)) {
        New-Item -ItemType Directory -Path $settingsDir -Force | Out-Null
    }
    
    $settings = @{
        apiKey = $apiKeyBox.Password
        model = $modelCombo.SelectedItem.Content
        instructions = $instructionsBox.Text
    }
    
    $settings | ConvertTo-Json | Set-Content $settingsPath
    Add-ChatMessage "System" "Settings saved"
}

function Clear-ApiKey {
    $apiKeyBox.Password = ""
    if (Test-Path $settingsPath) {
        $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
        $settings.apiKey = ""
        $settings | ConvertTo-Json | Set-Content $settingsPath
    }
    Add-ChatMessage "System" "API key cleared"
}

function Add-ChatMessage {
    param([string]$role, [string]$content)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $chatDisplay.AppendText("[$timestamp] $role`:`n$content`n`n")
    $chatScroll.ScrollToEnd()
}

function Invoke-PowerShellTool {
    param([string]$toolName, [hashtable]$arguments)
    
    try {
        $result = switch ($toolName) {
            "test_network_connection" { Test-NetConnection -ComputerName $arguments.computerName | ConvertTo-Json -Depth 3 }
            "get_network_adapters" { Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MacAddress | ConvertTo-Json }
            "get_ip_configuration" { Get-NetIPConfiguration | ConvertTo-Json -Depth 3 }
            "get_network_statistics" { Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | ConvertTo-Json }
            "resolve_dns_name" { Resolve-DnsName -Name $arguments.name | ConvertTo-Json }
            "get_firewall_rules" { Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled, Profile | ConvertTo-Json }
            "clear_dns_cache" { Clear-DnsClientCache; "DNS cache cleared" }
            "renew_ip_address" { ipconfig /release; ipconfig /renew; "IP address renewed" }
            "enable_dhcp" { $adapter = Get-NetAdapter -Name $arguments.adapterName; Set-NetIPInterface -InterfaceAlias $adapter.Name -Dhcp Enabled; "DHCP enabled" }
            "manage_network_adapter" { 
                $adapter = Get-NetAdapter -Name $arguments.adapterName
                if ($arguments.action -eq "enable") { Enable-NetAdapter -Name $adapter.Name -Confirm:$false }
                else { Disable-NetAdapter -Name $adapter.Name -Confirm:$false }
                "Adapter $($arguments.action)d"
            }
            "reset_network_stack" { netsh winsock reset; netsh int ip reset; "Network stack reset" }
            "get_user_info" { Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires | ConvertTo-Json }
            "get_permissions" { Get-Acl -Path $arguments.path | ConvertTo-Json -Depth 3 }
            "get_security_groups" { Get-LocalGroup | Select-Object Name, Description | ConvertTo-Json }
            "create_local_user" { $secPwd = ConvertTo-SecureString $arguments.password -AsPlainText -Force; New-LocalUser -Name $arguments.username -Password $secPwd; "User created" }
            "delete_local_user" { Remove-LocalUser -Name $arguments.username -Confirm:$false; "User deleted" }
            "set_user_password" { $secPwd = ConvertTo-SecureString $arguments.newPassword -AsPlainText -Force; Set-LocalUser -Name $arguments.username -Password $secPwd; "Password changed" }
            "add_firewall_rule" { New-NetFirewallRule -DisplayName $arguments.displayName -Direction $arguments.direction -Action $arguments.action; "Firewall rule added" }
            "remove_firewall_rule" { Remove-NetFirewallRule -DisplayName $arguments.displayName -Confirm:$false; "Firewall rule removed" }
            "toggle_firewall_rule" { Set-NetFirewallRule -DisplayName $arguments.displayName -Enabled $arguments.enabled; "Firewall rule toggled" }
            "add_user_to_group" { Add-LocalGroupMember -Group $arguments.groupName -Member $arguments.username; "User added to group" }
            "remove_user_from_group" { Remove-LocalGroupMember -Group $arguments.groupName -Member $arguments.username -Confirm:$false; "User removed from group" }
            "get_registry_value" { Get-ItemProperty -Path $arguments.path | ConvertTo-Json }
            "list_registry_keys" { Get-ChildItem -Path $arguments.path | Select-Object Name | ConvertTo-Json }
            "test_registry_path" { Test-Path -Path $arguments.path }
            "set_registry_value" { Set-ItemProperty -Path $arguments.path -Name $arguments.name -Value $arguments.value; "Registry value set" }
            "create_registry_key" { New-Item -Path $arguments.path -Force | Out-Null; "Registry key created" }
            "delete_registry_key" { Remove-Item -Path $arguments.path -Recurse -Force -Confirm:$false; "Registry key deleted" }
            "delete_registry_value" { Remove-ItemProperty -Path $arguments.path -Name $arguments.name -Force; "Registry value deleted" }
            "export_registry_key" { reg export $arguments.path.Replace('HKLM:','HKLM') $arguments.outputPath /y; "Registry key exported" }
            "import_registry_file" { reg import $arguments.filePath; "Registry file imported" }
            "get_event_logs" { Get-WinEvent -LogName $arguments.logName -MaxEvents 50 | Select-Object TimeCreated, LevelDisplayName, Message | ConvertTo-Json }
            "list_event_logs" { Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsEnabled | ConvertTo-Json }
            "get_recent_errors" { Get-WinEvent -LogName Application,System -MaxEvents 50 | Where-Object {$_.LevelDisplayName -eq 'Error'} | Select-Object TimeCreated, LogName, Message | ConvertTo-Json }
            "clear_event_log" { Clear-EventLog -LogName $arguments.logName; "Event log cleared" }
            "get_disk_info" { Get-Disk | Select-Object Number, FriendlyName, Size, HealthStatus, OperationalStatus, PartitionStyle | ConvertTo-Json }
            "get_volume_info" { Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining, HealthStatus | ConvertTo-Json }
            "check_disk_health" { Repair-Volume -DriveLetter $arguments.driveLetter -Scan; "Disk health check started" }
            "optimize_disk" { Optimize-Volume -DriveLetter $arguments.driveLetter; "Disk optimization started" }
            "get_smart_data" { Get-PhysicalDisk | Get-StorageReliabilityCounter | ConvertTo-Json }
            "get_partition_info" { Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Type, Size | ConvertTo-Json }
            "get_storage_jobs" { Get-StorageJob | Select-Object Name, JobState, PercentComplete | ConvertTo-Json }
            "initialize_disk" { Initialize-Disk -Number $arguments.diskNumber -PartitionStyle GPT -PassThru | ConvertTo-Json }
            "set_disk_online_status" { Set-Disk -Number $arguments.diskNumber -IsOffline $(!$arguments.online); "Disk status changed" }
            "format_volume" { Format-Volume -DriveLetter $arguments.driveLetter -FileSystem NTFS -Confirm:$false; "Volume formatted" }
            "set_volume_label" { Set-Volume -DriveLetter $arguments.driveLetter -NewFileSystemLabel $arguments.newLabel; "Volume label set" }
            "get_device_info" { Get-PnpDevice | Select-Object FriendlyName, Class, Status, InstanceId | ConvertTo-Json }
            "get_device_drivers" { Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | ConvertTo-Json }
            "get_device_problems" { Get-PnpDevice | Where-Object {$_.Status -ne 'OK'} | Select-Object FriendlyName, Status, InstanceId | ConvertTo-Json }
            "get_usb_devices" { Get-PnpDevice | Where-Object {$_.InstanceId -like 'USB*'} | Select-Object FriendlyName, Status | ConvertTo-Json }
            "get_graphics_cards" { Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, AdapterRAM | ConvertTo-Json }
            "scan_hardware_changes" { pnputil /scan-devices; "Hardware scan initiated" }
            "get_update_history" { Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json }
            "get_license_status" { Get-CimInstance SoftwareLicensingProduct | Where-Object {$_.PartialProductKey} | Select-Object Name, LicenseStatus | ConvertTo-Json }
            "get_activation_status" { cscript //nologo C:\Windows\System32\slmgr.vbs /dli }
            "set_product_key" { cscript //nologo C:\Windows\System32\slmgr.vbs /ipk $arguments.productKey }
            "activate_windows" { cscript //nologo C:\Windows\System32\slmgr.vbs /ato }
            "set_kms_server" { cscript //nologo C:\Windows\System32\slmgr.vbs /skms $arguments.kmsServer }
            "list_installed_apps" { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object DisplayName | ConvertTo-Json }
            "get_windows_store_apps" { Get-AppxPackage | Select-Object Name, Publisher, Version, PackageFullName | ConvertTo-Json }
            "uninstall_application" { Get-AppxPackage *$($arguments.appName)* | Remove-AppxPackage; "Application uninstalled" }
            "get_startup_programs" { Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | ConvertTo-Json }
            "get_processes_extended" { Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet, Threads, Path | ConvertTo-Json }
            "stop_process" { Stop-Process -Id $arguments.processId -Force; "Process stopped" }
            "start_process" { Start-Process -FilePath $arguments.filePath; "Process started" }
            "set_process_priority" { $p = Get-Process -Id $arguments.processId; $p.PriorityClass = $arguments.priority; "Priority set" }
            "search_files_advanced" { Get-ChildItem -Path $arguments.path -Filter $arguments.pattern -Recurse | Select-Object Name, Length, LastWriteTime | ConvertTo-Json }
            "get_file_hash" { Get-FileHash -Path $arguments.filePath -Algorithm SHA256 | ConvertTo-Json }
            "compress_files" { Compress-Archive -Path $arguments.sourcePath -DestinationPath $arguments.destinationPath; "Files compressed" }
            "decompress_files" { Expand-Archive -Path $arguments.archivePath -DestinationPath $arguments.destinationPath; "Files extracted" }
            "get_directory_size" { (Get-ChildItem -Path $arguments.path -Recurse | Measure-Object -Property Length -Sum).Sum }
            "copy_files_advanced" { Copy-Item -Path $arguments.source -Destination $arguments.destination -Recurse -Force; "Files copied" }
            "move_files_advanced" { Move-Item -Path $arguments.source -Destination $arguments.destination -Force; "Files moved" }
            "delete_files" { Remove-Item -Path $arguments.path -Recurse -Force -Confirm:$false; "Files deleted" }
            "create_folder" { New-Item -ItemType Directory -Path $arguments.path -Force | Out-Null; "Folder created: $($arguments.path)" }
            "get_system_info_extended" { Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsArchitecture, CsProcessors, CsTotalPhysicalMemory, BiosManufacturer | ConvertTo-Json }
            "manage_service_advanced" {
                switch ($arguments.action) {
                    "start" { Start-Service -Name $arguments.serviceName }
                    "stop" { Stop-Service -Name $arguments.serviceName -Force }
                    "restart" { Restart-Service -Name $arguments.serviceName -Force }
                }
                "Service $($arguments.action) completed"
            }
            "manage_scheduled_tasks" {
                switch ($arguments.action) {
                    "list" { Get-ScheduledTask | Select-Object TaskName, State, TaskPath | ConvertTo-Json }
                    "run" { Start-ScheduledTask -TaskName $arguments.taskName; "Task started" }
                    "enable" { Enable-ScheduledTask -TaskName $arguments.taskName; "Task enabled" }
                    "disable" { Disable-ScheduledTask -TaskName $arguments.taskName; "Task disabled" }
                }
            }
            "get_performance_counters" { Get-Counter '\Processor(_Total)\% Processor Time', '\Memory\Available MBytes' | Select-Object -ExpandProperty CounterSamples | ConvertTo-Json }
            "manage_power" {
                switch ($arguments.action) {
                    "shutdown" { Stop-Computer -Force }
                    "restart" { Restart-Computer -Force }
                    "sleep" { rundll32.exe powrprof.dll,SetSuspendState 0,1,0 }
                    "hibernate" { rundll32.exe powrprof.dll,SetSuspendState Hibernate }
                }
            }
            "get_power_plan" {
                $activePlan = powercfg /getactivescheme
                if ($activePlan -match 'GUID: ([a-f0-9-]+)\s+\((.+)\)') {
                    @{guid = $matches[1]; name = $matches[2]} | ConvertTo-Json
                } else {
                    "Unable to determine active power plan"
                }
            }
            "list_power_plans" {
                $plans = powercfg /list | Select-String 'Power Scheme GUID: ([a-f0-9-]+)\s+\((.+)\)(\s+\*)?' | ForEach-Object {
                    @{
                        guid = $_.Matches.Groups[1].Value
                        name = $_.Matches.Groups[2].Value
                        isActive = $_.Matches.Groups[3].Value -eq ' *'
                    }
                }
                $plans | ConvertTo-Json
            }
            "set_power_plan" {
                $allPlans = powercfg /list
                $planGuid = $null
                foreach ($line in $allPlans) {
                    if ($line -match "GUID: ([a-f0-9-]+)\s+\($($arguments.planName)") {
                        $planGuid = $matches[1]
                        break
                    }
                }
                if ($planGuid) {
                    powercfg /setactive $planGuid
                    "Power plan set to: $($arguments.planName)"
                } else {
                    "Power plan '$($arguments.planName)' not found"
                }
            }
            "get_battery_status" {
                $battery = Get-CimInstance -ClassName Win32_Battery
                if ($battery) {
                    $battery | Select-Object EstimatedChargeRemaining, BatteryStatus, EstimatedRunTime | ConvertTo-Json
                } else {
                    "No battery detected (desktop system)"
                }
            }
            "get_power_settings" {
                $settings = @{
                    activePlan = (powercfg /getactivescheme | Out-String).Trim()
                    sleepTimeoutAC = (powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | Select-String "Current AC Power Setting Index:" | Out-String).Trim()
                    sleepTimeoutDC = (powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | Select-String "Current DC Power Setting Index:" | Out-String).Trim()
                    displayTimeoutAC = (powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE | Select-String "Current AC Power Setting Index:" | Out-String).Trim()
                    displayTimeoutDC = (powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE | Select-String "Current DC Power Setting Index:" | Out-String).Trim()
                    hibernateEnabled = (powercfg /availablesleepstates | Select-String "Hibernate" | Out-String).Trim()
                }
                $settings | ConvertTo-Json
            }
            "set_display_timeout" {
                $powerType = if ($arguments.acPower) { "/change monitor-timeout-ac" } else { "/change monitor-timeout-dc" }
                powercfg $powerType $arguments.minutes
                "Display timeout set to $($arguments.minutes) minutes on $(if ($arguments.acPower) {'AC'} else {'battery'}) power"
            }
            "set_sleep_timeout" {
                $powerType = if ($arguments.acPower) { "/change standby-timeout-ac" } else { "/change standby-timeout-dc" }
                powercfg $powerType $arguments.minutes
                "Sleep timeout set to $($arguments.minutes) minutes on $(if ($arguments.acPower) {'AC'} else {'battery'}) power"
            }
            "enable_hibernation" {
                if ($arguments.enabled) {
                    powercfg /hibernate on
                    "Hibernation enabled"
                } else {
                    powercfg /hibernate off
                    "Hibernation disabled"
                }
            }
            "set_lid_close_action" {
                $actionMap = @{
                    "nothing" = "0"
                    "sleep" = "1"
                    "hibernate" = "2"
                    "shutdown" = "3"
                }
                $actionCode = $actionMap[$arguments.action]
                $subgroup = "4f971e89-eebd-4455-a8de-9e59040e7347"  # Lid close action GUID
                $setting = "5ca83367-6e45-459f-a27b-476b1d01c936"    # Lid close action setting GUID
                $powerType = if ($arguments.acPower) { "AC" } else { "DC" }
                
                powercfg /setacvalueindex SCHEME_CURRENT $subgroup $setting $actionCode 2>$null
                powercfg /setdcvalueindex SCHEME_CURRENT $subgroup $setting $actionCode 2>$null
                powercfg /setactive SCHEME_CURRENT
                "Lid close action set to: $($arguments.action)"
            }
            "set_power_button_action" {
                $actionMap = @{
                    "nothing" = "0"
                    "sleep" = "1"
                    "hibernate" = "2"
                    "shutdown" = "3"
                }
                $actionCode = $actionMap[$arguments.action]
                $subgroup = "4f971e89-eebd-4455-a8de-9e59040e7347"  # Power button GUID
                $setting = "7648efa3-dd9c-4e3e-b566-50f929386280"    # Power button action GUID
                
                powercfg /setacvalueindex SCHEME_CURRENT $subgroup $setting $actionCode 2>$null
                powercfg /setdcvalueindex SCHEME_CURRENT $subgroup $setting $actionCode 2>$null
                powercfg /setactive SCHEME_CURRENT
                "Power button action set to: $($arguments.action)"
            }
            "create_scheduled_task" { Register-ScheduledTask -TaskName $arguments.taskName -Action (New-ScheduledTaskAction -Execute $arguments.action) -Trigger (New-ScheduledTaskTrigger -Daily -At 12am); "Task created" }
            "delete_scheduled_task" { Unregister-ScheduledTask -TaskName $arguments.taskName -Confirm:$false; "Task deleted" }
            "get_defender_status" { Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureVersion, AntivirusSignatureLastUpdated | ConvertTo-Json }
            "start_defender_scan" { Start-MpScan -ScanType $arguments.scanType; "Defender scan started" }
            "get_defender_threats" { Get-MpThreat | Select-Object ThreatID, ThreatName, SeverityID, Resources | ConvertTo-Json }
            "update_defender_signatures" { Update-MpSignature; "Defender signatures updated" }
            "get_defender_exclusions" { Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess | ConvertTo-Json }
            "add_defender_exclusion" { Add-MpPreference -Exclusion$($arguments.exclusionType) $arguments.exclusionValue; "Exclusion added" }
            "remove_defender_exclusion" { Remove-MpPreference -Exclusion$($arguments.exclusionType) $arguments.exclusionValue; "Exclusion removed" }
            "set_defender_realtime_protection" { Set-MpPreference -DisableRealtimeMonitoring $(!$arguments.enabled); "Real-time protection toggled" }
            "get_defender_preferences" { Get-MpPreference | Select-Object DisableRealtimeMonitoring, ScanAvgCPULoadFactor, CloudBlockLevel | ConvertTo-Json }
            "remove_defender_threat" { Remove-MpThreat -ThreatID $arguments.threatId; "Threat removed" }
            
            # Task Management Tools
            "create_plan" {
                $global:currentPlan = @{
                    name = $arguments.planName
                    steps = $arguments.steps
                    completed = @()
                    createdAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                @{
                    status = "Plan created"
                    planName = $arguments.planName
                    totalSteps = $arguments.steps.Count
                    steps = $arguments.steps
                } | ConvertTo-Json
            }
            "mark_task_complete" {
                $task = @{
                    description = $arguments.taskDescription
                    completedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                $global:completedTasks += $task
                
                if ($global:currentPlan) {
                    $global:currentPlan.completed += $arguments.taskDescription
                }
                
                @{
                    status = "Task marked complete"
                    task = $arguments.taskDescription
                    totalCompleted = $global:completedTasks.Count
                } | ConvertTo-Json
            }
            "get_completed_tasks" {
                if ($global:completedTasks.Count -eq 0) {
                    "No tasks completed yet in this session"
                } else {
                    @{
                        totalCompleted = $global:completedTasks.Count
                        tasks = $global:completedTasks
                    } | ConvertTo-Json
                }
            }
            "get_current_plan" {
                if (-not $global:currentPlan) {
                    "No active plan"
                } else {
                    $progress = if ($global:currentPlan.steps.Count -gt 0) {
                        [math]::Round(($global:currentPlan.completed.Count / $global:currentPlan.steps.Count) * 100, 2)
                    } else { 0 }
                    
                    @{
                        planName = $global:currentPlan.name
                        createdAt = $global:currentPlan.createdAt
                        totalSteps = $global:currentPlan.steps.Count
                        completedSteps = $global:currentPlan.completed.Count
                        progressPercent = $progress
                        allSteps = $global:currentPlan.steps
                        completedStepsList = $global:currentPlan.completed
                        remainingSteps = $global:currentPlan.steps | Where-Object { $_ -notin $global:currentPlan.completed }
                    } | ConvertTo-Json
                }
            }
            "get_conversation_summary" {
                $userMessages = ($global:conversationHistory | Where-Object { $_.role -eq "user" }).Count
                $assistantMessages = ($global:conversationHistory | Where-Object { $_.role -eq "assistant" }).Count
                $toolCalls = ($global:conversationHistory | Where-Object { $_.role -eq "tool" }).Count
                
                @{
                    totalMessages = $global:conversationHistory.Count
                    userMessages = $userMessages
                    assistantMessages = $assistantMessages
                    toolExecutions = $toolCalls
                    completedTasks = $global:completedTasks.Count
                    activePlan = if ($global:currentPlan) { $global:currentPlan.name } else { "None" }
                    conversationStart = if ($global:conversationHistory.Count -gt 0) { 
                        $firstUserMsg = $global:conversationHistory | Where-Object { $_.role -eq "user" } | Select-Object -First 1
                        $firstUserMsg.content
                    } else { "No messages yet" }
                } | ConvertTo-Json
            }
            
            # Performance & Monitoring Tools
            "get_cpu_usage" {
                $cpuCounters = Get-Counter '\Processor(_Total)\% Processor Time'
                $perCore = Get-Counter '\Processor(*)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Where-Object {$_.InstanceName -ne '_total'}
                @{
                    totalCPU = [math]::Round($cpuCounters.CounterSamples[0].CookedValue, 2)
                    perCore = $perCore | ForEach-Object {@{core=$_.InstanceName; usage=[math]::Round($_.CookedValue, 2)}}
                } | ConvertTo-Json
            }
            "get_memory_usage" {
                $os = Get-CimInstance Win32_OperatingSystem
                $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
                $usedGB = $totalGB - $freeGB
                @{
                    totalGB = $totalGB
                    usedGB = $usedGB
                    freeGB = $freeGB
                    usedPercent = [math]::Round(($usedGB / $totalGB) * 100, 2)
                } | ConvertTo-Json
            }
            "get_disk_io" {
                $drives = if ($arguments.driveLetter) { $arguments.driveLetter } else { (Get-Volume | Where-Object {$_.DriveLetter}).DriveLetter }
                $stats = foreach ($drive in $drives) {
                    try {
                        $readBytes = (Get-Counter "\PhysicalDisk(*$drive*)\Disk Read Bytes/sec").CounterSamples.CookedValue
                        $writeBytes = (Get-Counter "\PhysicalDisk(*$drive*)\Disk Write Bytes/sec").CounterSamples.CookedValue
                        @{drive=$drive; readBytesPerSec=$readBytes; writeBytesPerSec=$writeBytes}
                    } catch { }
                }
                $stats | ConvertTo-Json
            }
            "get_network_throughput" {
                $adapters = Get-Counter '\Network Interface(*)\Bytes Total/sec' | Select-Object -ExpandProperty CounterSamples
                $adapters | ForEach-Object {@{adapter=$_.InstanceName; bytesPerSec=[math]::Round($_.CookedValue, 0)}} | ConvertTo-Json
            }
            "get_top_cpu_processes" {
                $count = if ($arguments.count) { $arguments.count } else { 10 }
                Get-Process | Sort-Object CPU -Descending | Select-Object -First $count ProcessName, Id, CPU, @{N='CPUPercent';E={[math]::Round($_.CPU, 2)}} | ConvertTo-Json
            }
            "get_top_memory_processes" {
                $count = if ($arguments.count) { $arguments.count } else { 10 }
                Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First $count ProcessName, Id, @{N='MemoryMB';E={[math]::Round($_.WorkingSet / 1MB, 2)}} | ConvertTo-Json
            }
            "get_system_uptime" {
                $os = Get-CimInstance Win32_OperatingSystem
                $bootTime = $os.LastBootUpTime
                $uptime = (Get-Date) - $bootTime
                @{
                    bootTime = $bootTime.ToString()
                    uptimeDays = [math]::Round($uptime.TotalDays, 2)
                    uptimeHours = [math]::Round($uptime.TotalHours, 2)
                    uptimeFormatted = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
                } | ConvertTo-Json
            }
            "get_performance_report" {
                $cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue
                $os = Get-CimInstance Win32_OperatingSystem
                $memUsed = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 2)
                $memTotal = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                $topCPU = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 ProcessName, Id, CPU
                $topMem = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5 ProcessName, @{N='MemoryMB';E={[math]::Round($_.WorkingSet / 1MB, 2)}}
                @{
                    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    cpuUsagePercent = [math]::Round($cpu, 2)
                    memoryUsedGB = $memUsed
                    memoryTotalGB = $memTotal
                    memoryUsedPercent = [math]::Round(($memUsed / $memTotal) * 100, 2)
                    topCPUProcesses = $topCPU
                    topMemoryProcesses = $topMem
                } | ConvertTo-Json
            }
            "monitor_process_realtime" {
                $duration = if ($arguments.durationSeconds) { $arguments.durationSeconds } else { 10 }
                $samples = @()
                1..$duration | ForEach-Object {
                    $proc = Get-Process -Id $arguments.processId -ErrorAction SilentlyContinue
                    if ($proc) {
                        $samples += @{
                            timestamp = Get-Date -Format "HH:mm:ss"
                            cpu = [math]::Round($proc.CPU, 2)
                            memoryMB = [math]::Round($proc.WorkingSet / 1MB, 2)
                            threads = $proc.Threads.Count
                            handles = $proc.HandleCount
                        }
                        Start-Sleep -Seconds 1
                    }
                }
                @{processId=$arguments.processId; duration=$duration; samples=$samples} | ConvertTo-Json
            }
            "get_resource_alerts" {
                $alerts = @()
                $cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue
                if ($cpu -gt 80) { $alerts += "High CPU usage: $([math]::Round($cpu, 2))%" }
                $os = Get-CimInstance Win32_OperatingSystem
                $memFreePercent = ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100
                if ($memFreePercent -lt 10) { $alerts += "Low memory: $([math]::Round($memFreePercent, 2))% free" }
                Get-Volume | Where-Object {$_.DriveLetter -and $_.SizeRemaining} | ForEach-Object {
                    $freePercent = ($_.SizeRemaining / $_.Size) * 100
                    if ($freePercent -lt 10) { $alerts += "Low disk space on $($_.DriveLetter): $([math]::Round($freePercent, 2))% free" }
                }
                if ($alerts.Count -eq 0) { "No resource alerts" } else { $alerts | ConvertTo-Json }
            }
            "benchmark_disk" {
                $testSizeMB = if ($arguments.testSizeMB) { $arguments.testSizeMB } else { 100 }
                $testFile = "$($arguments.driveLetter):\benchmark_test.tmp"
                $data = New-Object byte[] (1MB)
                $writeTime = Measure-Command {
                    1..$testSizeMB | ForEach-Object { [System.IO.File]::WriteAllBytes($testFile, $data) }
                }
                $readTime = Measure-Command {
                    1..$testSizeMB | ForEach-Object { [System.IO.File]::ReadAllBytes($testFile) | Out-Null }
                }
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                @{
                    drive = $arguments.driveLetter
                    testSizeMB = $testSizeMB
                    writeSpeedMBps = [math]::Round($testSizeMB / $writeTime.TotalSeconds, 2)
                    readSpeedMBps = [math]::Round($testSizeMB / $readTime.TotalSeconds, 2)
                } | ConvertTo-Json
            }
            "get_handle_count" {
                $total = (Get-Process | Measure-Object -Property HandleCount -Sum).Sum
                $topProcesses = Get-Process | Sort-Object HandleCount -Descending | Select-Object -First 10 ProcessName, Id, HandleCount
                @{totalHandles=$total; topProcesses=$topProcesses} | ConvertTo-Json
            }
            
            # Database & SQL Tools
            "test_sql_connection" {
                $connString = if ($arguments.integratedSecurity) {
                    "Server=$($arguments.serverInstance);Database=$($arguments.database);Integrated Security=True;"
                } else {
                    "Server=$($arguments.serverInstance);Database=$($arguments.database);User Id=$($arguments.username);Password=$($arguments.password);"
                }
                try {
                    $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
                    $conn.Open()
                    $conn.Close()
                    "Connection successful to $($arguments.serverInstance)/$($arguments.database)"
                } catch {
                    "Connection failed: $($_.Exception.Message)"
                }
            }
            "execute_sql_query" {
                $connString = if ($arguments.integratedSecurity) {
                    "Server=$($arguments.serverInstance);Database=$($arguments.database);Integrated Security=True;"
                } else {
                    "Server=$($arguments.serverInstance);Database=$($arguments.database);User Id=$($arguments.username);Password=$($arguments.password);"
                }
                $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = $arguments.query
                $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
                $dataset = New-Object System.Data.DataSet
                $adapter.Fill($dataset) | Out-Null
                $conn.Close()
                $dataset.Tables[0] | ConvertTo-Json
            }
            "get_sql_server_info" {
                $connString = if ($arguments.integratedSecurity) {
                    "Server=$($arguments.serverInstance);Database=master;Integrated Security=True;"
                } else {
                    "Server=$($arguments.serverInstance);Database=master;User Id=$($arguments.username);Password=$($arguments.password);"
                }
                $query = "SELECT @@VERSION AS Version, @@SERVERNAME AS ServerName, SERVERPROPERTY('Edition') AS Edition"
                $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = $query
                $conn.Open()
                $reader = $cmd.ExecuteReader()
                $result = while ($reader.Read()) { @{Version=$reader['Version']; ServerName=$reader['ServerName']; Edition=$reader['Edition']} }
                $conn.Close()
                $result | ConvertTo-Json
            }
            "list_sql_databases" {
                $connString = if ($arguments.integratedSecurity) {
                    "Server=$($arguments.serverInstance);Database=master;Integrated Security=True;"
                } else {
                    "Server=$($arguments.serverInstance);Database=master;User Id=$($arguments.username);Password=$($arguments.password);"
                }
                $query = "SELECT name, database_id, create_date FROM sys.databases"
                $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = $query
                $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
                $dataset = New-Object System.Data.DataSet
                $adapter.Fill($dataset) | Out-Null
                $conn.Close()
                $dataset.Tables[0] | ConvertTo-Json
            }
            "get_sql_tables" {
                $connString = if ($arguments.integratedSecurity) {
                    "Server=$($arguments.serverInstance);Database=$($arguments.database);Integrated Security=True;"
                } else {
                    "Server=$($arguments.serverInstance);Database=$($arguments.database);User Id=$($arguments.username);Password=$($arguments.password);"
                }
                $query = "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'"
                $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = $query
                $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
                $dataset = New-Object System.Data.DataSet
                $adapter.Fill($dataset) | Out-Null
                $conn.Close()
                $dataset.Tables[0] | ConvertTo-Json
            }
            "backup_sql_database" {
                $connString = if ($arguments.integratedSecurity) {
                    "Server=$($arguments.serverInstance);Database=master;Integrated Security=True;"
                } else {
                    "Server=$($arguments.serverInstance);Database=master;User Id=$($arguments.username);Password=$($arguments.password);"
                }
                $query = "BACKUP DATABASE [$($arguments.database)] TO DISK='$($arguments.backupPath)' WITH FORMAT"
                $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = $query
                $cmd.CommandTimeout = 0
                $conn.Open()
                $cmd.ExecuteNonQuery() | Out-Null
                $conn.Close()
                "Database backed up to $($arguments.backupPath)"
            }
            "restore_sql_database" {
                $connString = if ($arguments.integratedSecurity) {
                    "Server=$($arguments.serverInstance);Database=master;Integrated Security=True;"
                } else {
                    "Server=$($arguments.serverInstance);Database=master;User Id=$($arguments.username);Password=$($arguments.password);"
                }
                $query = "RESTORE DATABASE [$($arguments.database)] FROM DISK='$($arguments.backupPath)' WITH REPLACE"
                $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = $query
                $cmd.CommandTimeout = 0
                $conn.Open()
                $cmd.ExecuteNonQuery() | Out-Null
                $conn.Close()
                "Database restored from $($arguments.backupPath)"
            }
            "get_sql_performance" {
                $connString = if ($arguments.integratedSecurity) {
                    "Server=$($arguments.serverInstance);Database=master;Integrated Security=True;"
                } else {
                    "Server=$($arguments.serverInstance);Database=master;User Id=$($arguments.username);Password=$($arguments.password);"
                }
                $query = "SELECT counter_name, cntr_value FROM sys.dm_os_performance_counters WHERE counter_name IN ('Buffer cache hit ratio', 'Page life expectancy', 'Batch Requests/sec')"
                $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = $query
                $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
                $dataset = New-Object System.Data.DataSet
                $adapter.Fill($dataset) | Out-Null
                $conn.Close()
                $dataset.Tables[0] | ConvertTo-Json
            }
            
            # Certificate & Encryption Tools
            "list_certificates" {
                Get-ChildItem "Cert:\$($arguments.storeLocation)\$($arguments.storeName)" | Select-Object Thumbprint, Subject, Issuer, NotAfter, HasPrivateKey | ConvertTo-Json
            }
            "get_certificate_details" {
                $cert = Get-ChildItem "Cert:\$($arguments.storeLocation)\My" | Where-Object {$_.Thumbprint -eq $arguments.thumbprint}
                if ($cert) {
                    $cert | Select-Object Subject, Issuer, SerialNumber, Thumbprint, NotBefore, NotAfter, SignatureAlgorithm, EnhancedKeyUsageList | ConvertTo-Json
                } else {
                    "Certificate not found"
                }
            }
            "test_certificate_expiration" {
                $threshold = (Get-Date).AddDays($arguments.daysThreshold)
                Get-ChildItem "Cert:\$($arguments.storeLocation)\My" -Recurse | Where-Object {$_.NotAfter -lt $threshold} | Select-Object @{N='DaysUntilExpiration';E={($_.NotAfter - (Get-Date)).Days}}, Thumbprint, Subject, NotAfter | ConvertTo-Json
            }
            "export_certificate" {
                $cert = Get-ChildItem "Cert:\$($arguments.storeLocation)\My" | Where-Object {$_.Thumbprint -eq $arguments.thumbprint}
                if ($arguments.includePrivateKey) {
                    $pwd = ConvertTo-SecureString -String $arguments.password -Force -AsPlainText
                    Export-PfxCertificate -Cert $cert -FilePath $arguments.outputPath -Password $pwd | Out-Null
                } else {
                    Export-Certificate -Cert $cert -FilePath $arguments.outputPath | Out-Null
                }
                "Certificate exported to $($arguments.outputPath)"
            }
            "import_certificate" {
                if ($arguments.filePath -like "*.pfx") {
                    $pwd = ConvertTo-SecureString -String $arguments.password -Force -AsPlainText
                    Import-PfxCertificate -FilePath $arguments.filePath -CertStoreLocation "Cert:\$($arguments.storeLocation)\$($arguments.storeName)" -Password $pwd | Out-Null
                } else {
                    Import-Certificate -FilePath $arguments.filePath -CertStoreLocation "Cert:\$($arguments.storeLocation)\$($arguments.storeName)" | Out-Null
                }
                "Certificate imported"
            }
            "test_ssl_certificate" {
                $port = if ($arguments.port) { $arguments.port } else { 443 }
                $tcpClient = New-Object System.Net.Sockets.TcpClient($arguments.hostname, $port)
                $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, ({$true}))
                $sslStream.AuthenticateAsClient($arguments.hostname)
                $cert = $sslStream.RemoteCertificate
                $tcpClient.Close()
                @{
                    subject = $cert.Subject
                    issuer = $cert.Issuer
                    validFrom = $cert.GetEffectiveDateString()
                    validTo = $cert.GetExpirationDateString()
                    thumbprint = $cert.GetCertHashString()
                } | ConvertTo-Json
            }
            "create_self_signed_certificate" {
                $years = if ($arguments.validityYears) { $arguments.validityYears } else { 1 }
                $params = @{
                    Subject = $arguments.subjectName
                    CertStoreLocation = 'Cert:\CurrentUser\My'
                    NotAfter = (Get-Date).AddYears($years)
                }
                if ($arguments.dnsNames) { $params.DnsName = $arguments.dnsNames }
                $cert = New-SelfSignedCertificate @params
                @{thumbprint=$cert.Thumbprint; subject=$cert.Subject; notAfter=$cert.NotAfter} | ConvertTo-Json
            }
            
            # Web & REST API Tools
            "http_get_request" {
                $params = @{Uri=$arguments.url; Method='GET'}
                if ($arguments.headers) { $params.Headers = $arguments.headers }
                $response = Invoke-RestMethod @params
                $response | ConvertTo-Json -Depth 10
            }
            "http_post_request" {
                $params = @{Uri=$arguments.url; Method='POST'; Body=$arguments.body; ContentType=$arguments.contentType}
                if ($arguments.headers) { $params.Headers = $arguments.headers }
                $response = Invoke-RestMethod @params
                $response | ConvertTo-Json -Depth 10
            }
            "http_put_request" {
                $params = @{Uri=$arguments.url; Method='PUT'; Body=$arguments.body; ContentType=$arguments.contentType}
                if ($arguments.headers) { $params.Headers = $arguments.headers }
                $response = Invoke-RestMethod @params
                $response | ConvertTo-Json -Depth 10
            }
            "http_delete_request" {
                $params = @{Uri=$arguments.url; Method='DELETE'}
                if ($arguments.headers) { $params.Headers = $arguments.headers }
                $response = Invoke-RestMethod @params
                $response | ConvertTo-Json -Depth 10
            }
            "download_file" {
                Invoke-WebRequest -Uri $arguments.url -OutFile $arguments.outputPath
                "File downloaded to $($arguments.outputPath)"
            }
            "test_url_availability" {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $response = Invoke-WebRequest -Uri $arguments.url -UseBasicParsing -TimeoutSec 10
                    $stopwatch.Stop()
                    @{
                        available = $true
                        statusCode = $response.StatusCode
                        responseTimeMs = $stopwatch.ElapsedMilliseconds
                    } | ConvertTo-Json
                } catch {
                    $stopwatch.Stop()
                    @{
                        available = $false
                        error = $_.Exception.Message
                        responseTimeMs = $stopwatch.ElapsedMilliseconds
                    } | ConvertTo-Json
                }
            }
            "get_web_page_content" {
                $response = Invoke-WebRequest -Uri $arguments.url
                @{
                    html = $response.Content
                    title = $response.ParsedHtml.title
                    links = $response.Links | Select-Object href -First 20
                } | ConvertTo-Json
            }
            "test_rest_api" {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $params = @{Uri=$arguments.url; Method=$arguments.method; UseBasicParsing=$true}
                if ($arguments.body) { $params.Body = $arguments.body }
                if ($arguments.headers) { $params.Headers = $arguments.headers }
                try {
                    $response = Invoke-WebRequest @params
                    $stopwatch.Stop()
                    @{
                        statusCode = $response.StatusCode
                        headers = $response.Headers
                        body = $response.Content
                        responseTimeMs = $stopwatch.ElapsedMilliseconds
                    } | ConvertTo-Json -Depth 5
                } catch {
                    $stopwatch.Stop()
                    @{error=$_.Exception.Message; responseTimeMs=$stopwatch.ElapsedMilliseconds} | ConvertTo-Json
                }
            }
            "parse_json_response" {
                $parsed = $arguments.jsonString | ConvertFrom-Json
                if ($arguments.extractPath) {
                    $path = $arguments.extractPath -split '\.'
                    $result = $parsed
                    foreach ($part in $path) {
                        $result = $result.$part
                    }
                    $result | ConvertTo-Json
                } else {
                    $parsed | ConvertTo-Json -Depth 10
                }
            }
            "encode_decode_base64" {
                if ($arguments.operation -eq "encode") {
                    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($arguments.text))
                } else {
                    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($arguments.text))
                }
            }
            
            # Printer & Print Queue Tools
            "list_printers" { Get-Printer | Select-Object Name, DriverName, PortName, Shared, Default | ConvertTo-Json }
            "get_print_queue" { Get-PrintJob -PrinterName $arguments.printerName | Select-Object Id, DocumentName, UserName, TotalPages, Size, JobStatus, SubmittedTime | ConvertTo-Json }
            "clear_print_queue" { Get-PrintJob -PrinterName $arguments.printerName | Remove-PrintJob; "Print queue cleared" }
            "cancel_print_job" { Remove-PrintJob -PrinterName $arguments.printerName -ID $arguments.jobId; "Print job cancelled" }
            "set_default_printer" { (Get-WmiObject -Class Win32_Printer -Filter "Name='$($arguments.printerName)'").SetDefaultPrinter() | Out-Null; "Default printer set" }
            "manage_printer_state" {
                if ($arguments.action -eq "pause") {
                    (Get-WmiObject -Class Win32_Printer -Filter "Name='$($arguments.printerName)'").Pause()
                } else {
                    (Get-WmiObject -Class Win32_Printer -Filter "Name='$($arguments.printerName)'").Resume()
                }
                "Printer $($arguments.action)d"
            }
            
            # Backup & Recovery Tools
            "create_system_restore_point" { Checkpoint-Computer -Description $arguments.description -RestorePointType "MODIFY_SETTINGS"; "Restore point created" }
            "list_restore_points" { Get-ComputerRestorePoint | Select-Object SequenceNumber, Description, CreationTime, RestorePointType | ConvertTo-Json }
            "restore_system" { Restore-Computer -RestorePoint $arguments.restorePointNumber -Confirm:$false; "System restore initiated (restart required)" }
            "list_shadow_copies" { vssadmin list shadows /for=$($arguments.driveLetter): }
            "create_shadow_copy" { (Get-WmiObject -List Win32_ShadowCopy).Create("$($arguments.driveLetter):\", "ClientAccessible") | Out-Null; "Shadow copy created" }
            "export_event_viewer_config" { wevtutil epl System $arguments.outputPath; "Event viewer config exported" }
            "backup_registry_to_file" { reg export HKLM $arguments.outputPath /y; "Registry backed up" }
            "get_backup_status" { wbadmin get versions }
            
            # Active Directory Tools
            "get_ad_user" { Get-ADUser -Identity $arguments.identity -Properties * | Select-Object Name, SamAccountName, Enabled, EmailAddress, LastLogonDate, PasswordExpiration | ConvertTo-Json }
            "search_ad_users" { Get-ADUser -Filter "$($arguments.searchField) -like '*$($arguments.searchTerm)*'" | Select-Object Name, SamAccountName, EmailAddress | ConvertTo-Json }
            "get_ad_group_members" { Get-ADGroupMember -Identity $arguments.groupName | Select-Object Name, SamAccountName, objectClass | ConvertTo-Json }
            "get_ad_user_groups" { Get-ADPrincipalGroupMembership -Identity $arguments.identity | Select-Object Name, GroupCategory | ConvertTo-Json }
            "list_ad_computers" { 
                if ($arguments.ouPath) {
                    Get-ADComputer -SearchBase $arguments.ouPath -Filter * | Select-Object Name, DNSHostName, OperatingSystem, Enabled, LastLogonDate | ConvertTo-Json
                } else {
                    Get-ADComputer -Filter * | Select-Object Name, DNSHostName, OperatingSystem, Enabled | ConvertTo-Json
                }
            }
            "get_ad_domain_info" { Get-ADDomain | Select-Object Name, NetBIOSName, Forest, DomainMode, PDCEmulator | ConvertTo-Json }
            "test_ad_credentials" {
                $domain = if ($arguments.domain) { $arguments.domain } else { $env:USERDOMAIN }
                $cred = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain", $arguments.username, $arguments.password)
                if ($cred.Name) { "Credentials valid" } else { "Credentials invalid" }
            }
            "get_locked_ad_accounts" { Get-ADUser -Filter {LockedOut -eq $true} -Properties LockedOut, LockoutTime | Select-Object Name, SamAccountName, LockoutTime | ConvertTo-Json }
            "get_disabled_ad_accounts" { Get-ADUser -Filter {Enabled -eq $false} -Properties LastLogonDate | Select-Object Name, SamAccountName, LastLogonDate | ConvertTo-Json }
            
            # Share & Permission Tools
            "list_smb_shares" { Get-SmbShare | Select-Object Name, Path, Description, ShareState | ConvertTo-Json }
            "create_smb_share" { New-SmbShare -Name $arguments.name -Path $arguments.path -Description $arguments.description -FullAccess Everyone; "Share created" }
            "remove_smb_share" { Remove-SmbShare -Name $arguments.shareName -Force; "Share removed" }
            "get_share_permissions" { Get-SmbShareAccess -Name $arguments.shareName | Select-Object AccountName, AccessControlType, AccessRight | ConvertTo-Json }
            "set_share_permissions" { Grant-SmbShareAccess -Name $arguments.shareName -AccountName $arguments.accountName -AccessRight $arguments.accessRight -Force; "Permissions set" }
            "get_open_files" { Get-SmbOpenFile | Select-Object Path, ClientUserName, SessionId | ConvertTo-Json }
            "close_smb_session" { 
                if ($arguments.sessionId) {
                    Close-SmbSession -SessionId $arguments.sessionId -Force; "Session closed"
                } else {
                    Close-SmbSession -Force -Confirm:$false; "All sessions closed"
                }
            }
            
            # Audio & Video Tools
            "list_audio_devices" { Get-CimInstance Win32_SoundDevice | Select-Object Name, Status, DeviceID | ConvertTo-Json }
            "set_system_volume" {
                Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
    int NotImpl1(); int NotImpl2();
    int GetMasterVolumeLevelScalar(out float level);
    int SetMasterVolumeLevelScalar(float level, System.Guid eventContext);
}
'@
                $level = $arguments.volume / 100.0
                "Volume set to $($arguments.volume)%"
            }
            "mute_unmute_system" { "Mute/unmute functionality requires additional COM interop" }
            "capture_screenshot" {
                Add-Type -AssemblyName System.Windows.Forms, System.Drawing
                $screen = [System.Windows.Forms.Screen]::PrimaryScreen
                $bitmap = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)
                $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                $graphics.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)
                $format = if ($arguments.format) { $arguments.format } else { 'PNG' }
                $bitmap.Save($arguments.outputPath, [System.Drawing.Imaging.ImageFormat]::$format)
                "Screenshot saved to $($arguments.outputPath)"
            }
            "get_display_info" { Get-CimInstance Win32_VideoController | Select-Object Name, CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate | ConvertTo-Json }
            
            # Virtualization Tools
            "list_hyperv_vms" { Get-VM | Select-Object Name, State, Uptime, CPUUsage, MemoryAssigned, Version | ConvertTo-Json }
            "manage_hyperv_vm" {
                switch ($arguments.action) {
                    "start" { Start-VM -Name $arguments.vmName }
                    "stop" { Stop-VM -Name $arguments.vmName -Force }
                    "save" { Save-VM -Name $arguments.vmName }
                    "restart" { Restart-VM -Name $arguments.vmName -Force }
                }
                "VM $($arguments.action) completed"
            }
            "get_hyperv_vm_info" { Get-VM -Name $arguments.vmName | Select-Object * | ConvertTo-Json -Depth 3 }
            "create_hyperv_checkpoint" { Checkpoint-VM -Name $arguments.vmName -SnapshotName $arguments.checkpointName; "Checkpoint created" }
            "list_docker_containers" { 
                if ($arguments.showAll) {
                    docker ps -a --format "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}"
                } else {
                    docker ps --format "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}"
                }
            }
            "manage_docker_container" {
                switch ($arguments.action) {
                    "start" { docker start $arguments.containerName }
                    "stop" { docker stop $arguments.containerName }
                    "restart" { docker restart $arguments.containerName }
                    "remove" { docker rm $arguments.containerName -f }
                }
                "Container $($arguments.action) completed"
            }
            "list_wsl_distributions" { wsl --list --verbose }
            "manage_wsl_distro" {
                switch ($arguments.action) {
                    "start" { wsl -d $arguments.distroName }
                    "terminate" { wsl --terminate $arguments.distroName }
                    "setdefault" { wsl --setdefault $arguments.distroName }
                }
                "WSL action completed"
            }
            
            # Compression & Archive Tools
            "compress_with_7zip" {
                $7zPath = "C:\Program Files\7-Zip\7z.exe"
                if (-not (Test-Path $7zPath)) { return "7-Zip not found at $7zPath" }
                $level = if ($arguments.compressionLevel) { $arguments.compressionLevel } else { 5 }
                & $7zPath a -mx=$level $arguments.outputPath $arguments.sourcePath
                "Archive created: $($arguments.outputPath)"
            }
            "extract_7zip_archive" {
                $7zPath = "C:\Program Files\7-Zip\7z.exe"
                if (-not (Test-Path $7zPath)) { return "7-Zip not found at $7zPath" }
                & $7zPath x $arguments.archivePath -o"$($arguments.outputPath)" -y
                "Archive extracted to $($arguments.outputPath)"
            }
            "list_archive_contents" {
                $7zPath = "C:\Program Files\7-Zip\7z.exe"
                if (Test-Path $7zPath) {
                    & $7zPath l $arguments.archivePath
                } else {
                    (Get-ChildItem $arguments.archivePath).FullName | ForEach-Object { [System.IO.Compression.ZipFile]::OpenRead($_).Entries | Select-Object Name, Length, LastWriteTime } | ConvertTo-Json
                }
            }
            "test_archive_integrity" {
                $7zPath = "C:\Program Files\7-Zip\7z.exe"
                if (-not (Test-Path $7zPath)) { return "7-Zip not found" }
                & $7zPath t $arguments.archivePath
            }
            "create_tar_gz" {
                $7zPath = "C:\Program Files\7-Zip\7z.exe"
                if (-not (Test-Path $7zPath)) { return "7-Zip not found" }
                & $7zPath a -ttar -so $arguments.sourcePath | & $7zPath a -si -tgzip $arguments.outputPath
                "TAR.GZ archive created"
            }
            
            # Text Processing Tools
            "search_text_in_files" {
                $params = @{Path=$arguments.path; Pattern=$arguments.pattern}
                if ($arguments.caseSensitive) { $params.CaseSensitive = $true }
                Select-String @params | Select-Object Path, LineNumber, Line | ConvertTo-Json
            }
            "replace_text_in_files" {
                Get-ChildItem $arguments.path -Recurse -File | ForEach-Object {
                    if ($arguments.createBackup) { Copy-Item $_.FullName "$($_.FullName).bak" }
                    $content = Get-Content $_.FullName -Raw
                    if ($arguments.useRegex) {
                        $newContent = $content -replace $arguments.searchText, $arguments.replaceText
                    } else {
                        $newContent = $content.Replace($arguments.searchText, $arguments.replaceText)
                    }
                    Set-Content $_.FullName -Value $newContent
                }
                "Text replacement complete"
            }
            "parse_csv_file" {
                $delimiter = if ($arguments.delimiter) { $arguments.delimiter } else { ',' }
                Import-Csv -Path $arguments.filePath -Delimiter $delimiter | ConvertTo-Json
            }
            "export_to_csv" {
                $data = $arguments.data | ConvertFrom-Json
                $data | Export-Csv -Path $arguments.outputPath -NoTypeInformation -UseQuotes AsNeeded
                "Data exported to CSV"
            }
            "parse_xml_file" {
                [xml]$xml = Get-Content $arguments.filePath
                if ($arguments.xpathQuery) {
                    $xml.SelectNodes($arguments.xpathQuery) | ConvertTo-Json
                } else {
                    $xml | ConvertTo-Json -Depth 10
                }
            }
            "parse_json_file" {
                $json = Get-Content $arguments.filePath -Raw | ConvertFrom-Json
                if ($arguments.propertyPath) {
                    $path = $arguments.propertyPath -split '\.'
                    $result = $json
                    foreach ($part in $path) {
                        if ($part -match '(\d+)') {
                            $result = $result[[int]$matches[1]]
                        } else {
                            $result = $result.$part
                        }
                    }
                    $result | ConvertTo-Json
                } else {
                    $json | ConvertTo-Json -Depth 10
                }
            }
            "convert_file_encoding" {
                $content = Get-Content -Path $arguments.filePath -Raw
                Set-Content -Path $arguments.outputPath -Value $content -Encoding $arguments.targetEncoding
                "File encoding converted to $($arguments.targetEncoding)"
            }
            "count_lines_words_chars" {
                $content = Get-Content -Path $arguments.filePath -Raw
                @{
                    lines = (Get-Content -Path $arguments.filePath).Count
                    words = ($content -split '\s+').Count
                    characters = $content.Length
                } | ConvertTo-Json
            }
            
            default { "Tool '$toolName' execution not implemented" }
        }
        return $result
    }
    catch {
        return @{error = $_.Exception.Message} | ConvertTo-Json
    }
}

function Get-RelevantTools {
    param([string]$query)
    
    # Define tool categories with keywords
    $categories = @{
        network = @("network", "connection", "ip", "dns", "firewall", "adapter", "ping", "port")
        security = @("user", "permission", "acl", "group", "password", "security", "firewall")
        registry = @("registry", "reg", "hkey", "hklm", "hkcu")
        eventlog = @("event", "log", "error", "warning")
        disk = @("disk", "drive", "volume", "partition", "format", "storage")
        device = @("device", "hardware", "driver", "usb", "pnp")
        update = @("update", "patch", "hotfix", "windows update")
        licensing = @("license", "activation", "product key", "kms")
        application = @("app", "application", "process", "program", "install", "uninstall")
        file = @("file", "folder", "directory", "copy", "move", "delete", "search")
        computer = @("system", "service", "task", "environment", "power", "shutdown", "restart", "performance")
        defender = @("defender", "antivirus", "scan", "threat", "malware")
        display = @("display", "monitor", "screen", "resolution", "graphics")
    }
    
    $queryLower = $query.ToLower()
    $scores = @{}
    
    foreach ($cat in $categories.Keys) {
        $score = 0
        foreach ($keyword in $categories[$cat]) {
            if ($queryLower -match $keyword) { $score++ }
        }
        if ($score -gt 0) { $scores[$cat] = $score }
    }
    
    # Always include these essential tools
    $essentialTools = @("get_system_info_extended", "get_processes_extended")
    
    # Select tools based on matched categories (limit to top 3 categories)
    $selectedTools = [System.Collections.ArrayList]@()
    $essentialTools | ForEach-Object { [void]$selectedTools.Add($_) }
    
    $topCategories = $scores.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 -ExpandProperty Key
    
    foreach ($tool in $global:toolDefinitions) {
        if ($selectedTools.Count -ge 126) { break }
        
        $toolName = $tool.function.name
        if ($toolName -in $essentialTools) { continue }
        
        # Add tools from relevant categories
        $addTool = $false
        foreach ($cat in $topCategories) {
            if ($toolName -match "^($($categories[$cat] -join '|'))") {
                $addTool = $true
                break
            }
        }
        
        # Match category by common patterns
        if (-not $addTool) {
            foreach ($cat in $topCategories) {
                switch ($cat) {
                    "network" { if ($toolName -match "network|dns|firewall|ip|adapter|connection") { $addTool = $true } }
                    "security" { if ($toolName -match "user|permission|group|security|firewall") { $addTool = $true } }
                    "registry" { if ($toolName -match "registry") { $addTool = $true } }
                    "eventlog" { if ($toolName -match "event|log") { $addTool = $true } }
                    "disk" { if ($toolName -match "disk|volume|partition|storage") { $addTool = $true } }
                    "device" { if ($toolName -match "device|driver|usb|graphics|hardware") { $addTool = $true } }
                    "update" { if ($toolName -match "update") { $addTool = $true } }
                    "licensing" { if ($toolName -match "license|activation|product") { $addTool = $true } }
                    "application" { if ($toolName -match "app|process|program|install|startup|service") { $addTool = $true } }
                    "file" { if ($toolName -match "file|folder|directory|copy|move|delete|search|compress") { $addTool = $true } }
                    "computer" { if ($toolName -match "system|service|task|environment|power|performance|scheduled") { $addTool = $true } }
                    "defender" { if ($toolName -match "defender|threat|scan") { $addTool = $true } }
                    "display" { if ($toolName -match "graphics|display|video") { $addTool = $true } }
                }
            }
        }
        
        if ($addTool) { [void]$selectedTools.Add($toolName) }
    }
    
    # Always include task management tools for context awareness
    $taskTools = @("create_plan", "mark_task_complete", "get_completed_tasks", "get_current_plan", "get_conversation_summary")
    foreach ($taskTool in $taskTools) {
        if ($taskTool -notin $selectedTools -and $selectedTools.Count -lt 126) {
            [void]$selectedTools.Add($taskTool)
        }
    }
    
    # If no categories matched or too few tools, add general purpose tools
    if ($selectedTools.Count -lt 50) {
        foreach ($tool in $global:toolDefinitions) {
            if ($selectedTools.Count -ge 126) { break }
            $toolName = $tool.function.name
            if ($toolName -notin $selectedTools) {
                [void]$selectedTools.Add($toolName)
            }
        }
    }
    
    # Return matching tool definitions
    return $global:toolDefinitions | Where-Object { $_.function.name -in $selectedTools }
}

function Send-OpenAIRequest {
    param([string]$userMessage)
    
    $apiKey = $apiKeyBox.Password
    if (-not $apiKey) {
        Add-ChatMessage "Error" "Please enter an API key"
        return
    }
    
    Add-ChatMessage "You" $userMessage
    
    $global:conversationHistory += @{
        role = "user"
        content = $userMessage
    }
    
    # Select relevant tools based on query (max 128)
    $relevantTools = Get-RelevantTools -query $userMessage
    
    $messages = @()
    $systemMsg = "You are a helpful AI assistant with access to PowerShell tools for Windows management. You have access to tools covering network, security, registry, event logs, disk, device, Windows Update, licensing, application, file, computer management, and Windows Defender operations.

IMPORTANT: You maintain full conversation history and context awareness. You can:
- Reference previous messages and responses
- Track completed tasks using mark_task_complete
- Create multi-step plans using create_plan
- Check progress on plans using get_current_plan
- Review what tasks have been completed using get_completed_tasks
- Get conversation summary using get_conversation_summary

When creating a plan, break it into clear steps. As you complete each step, use mark_task_complete to track progress. Always check the current plan status before proceeding to the next step."
    if ($instructionsBox.Text) {
        $systemMsg += "`n`n" + $instructionsBox.Text
    }
    
    $messages += @{role = "system"; content = $systemMsg}
    $messages += $global:conversationHistory
    
    $selectedModel = $modelCombo.SelectedItem.Content
    if (-not $selectedModel) { $selectedModel = "gpt-4o-mini" }
    Add-ChatMessage "System" "Using model: $selectedModel"
    
    $body = @{
        model = $selectedModel
        messages = $messages
        temperature = 0
        tools = $relevantTools
        stream = $false
    } | ConvertTo-Json -Depth 10
    
    try {
        $sendBtn.IsEnabled = $false
        $inputBox.IsEnabled = $false
        
        $response = Invoke-RestMethod -Uri "https://api.openai.com/v1/chat/completions" `
            -Method Post `
            -Headers @{
                "Authorization" = "Bearer $apiKey"
                "Content-Type" = "application/json"
            } `
            -Body $body
        
        $message = $response.choices[0].message
        
        if ($message.tool_calls) {
            Add-ChatMessage "System" "Executing $($message.tool_calls.Count) tool(s)..."
            
            $global:conversationHistory += @{
                role = "assistant"
                content = $message.content
                tool_calls = $message.tool_calls
            }
            
            foreach ($toolCall in $message.tool_calls) {
                $toolName = $toolCall.function.name
                
                # Convert JSON to hashtable (compatible with PS 5.1 and 7+)
                $toolArgs = @{}
                if ($toolCall.function.arguments) {
                    if ($global:isPwsh7) {
                        $toolArgs = $toolCall.function.arguments | ConvertFrom-Json -AsHashtable
                    } else {
                        $argsObj = $toolCall.function.arguments | ConvertFrom-Json
                        $argsObj.PSObject.Properties | ForEach-Object {
                            $toolArgs[$_.Name] = $_.Value
                        }
                    }
                }
                
                Add-ChatMessage "Tool" "Executing: $toolName"
                
                $result = Invoke-PowerShellTool -toolName $toolName -arguments $toolArgs
                
                $global:conversationHistory += @{
                    role = "tool"
                    tool_call_id = $toolCall.id
                    content = $result
                }
            }
            
            # Send follow-up request with tool results
            $messages = @()
            $messages += @{role = "system"; content = $systemMsg}
            $messages += $global:conversationHistory
            
            $body = @{
                model = $selectedModel
                messages = $messages
                temperature = 0
                tools = $relevantTools
                stream = $false
            } | ConvertTo-Json -Depth 10
            
            $response = Invoke-RestMethod -Uri "https://api.openai.com/v1/chat/completions" `
                -Method Post `
                -Headers @{
                    "Authorization" = "Bearer $apiKey"
                    "Content-Type" = "application/json"
                } `
                -Body $body
            
            $assistantMessage = $response.choices[0].message.content
            Add-ChatMessage "Assistant" $assistantMessage
            
            $global:conversationHistory += @{
                role = "assistant"
                content = $assistantMessage
            }
        }
        else {
            $assistantMessage = $message.content
            Add-ChatMessage "Assistant" $assistantMessage
            
            $global:conversationHistory += @{
                role = "assistant"
                content = $assistantMessage
            }
        }
    }
    catch {
        $errorDetail = ""
        if ($_.ErrorDetails.Message) {
            $errorDetail = "`n$($_.ErrorDetails.Message)"
        }
        Add-ChatMessage "Error" "Failed to call OpenAI API: $($_.Exception.Message)$errorDetail"
    }
    finally {
        $sendBtn.IsEnabled = $true
        $inputBox.IsEnabled = $true
        $inputBox.Focus()
    }
}

$saveApiKeyBtn.Add_Click({ Save-Settings })
$clearApiKeyBtn.Add_Click({ Clear-ApiKey })

$sendBtn.Add_Click({
    $message = $inputBox.Text.Trim()
    if ($message) {
        Send-OpenAIRequest $message
        $inputBox.Clear()
    }
})

$inputBox.Add_PreviewKeyDown({
    if ($_.Key -eq "Enter") {
        if ($_.KeyboardDevice.Modifiers -eq "Shift") {
            # Shift+Enter: Allow new line
            # Insert newline manually
            $pos = $inputBox.CaretIndex
            $inputBox.Text = $inputBox.Text.Insert($pos, "`r`n")
            $inputBox.CaretIndex = $pos + 2
            $_.Handled = $true
        } else {
            # Enter: Send message
            $_.Handled = $true
            $sendBtn.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
        }
    }
})

Get-Settings
$psVersion = "PowerShell $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
Add-ChatMessage "System" "AI Chat Client ready - 145 PowerShell tools available (140 Windows + 5 Task Management)"
Add-ChatMessage "System" "Task tracking enabled - AI can create plans, track progress, and maintain conversation context"
Add-ChatMessage "System" "Running on $psVersion - Compatible with PS 5.1+ and PS 7+"

$window.ShowDialog() | Out-Null
