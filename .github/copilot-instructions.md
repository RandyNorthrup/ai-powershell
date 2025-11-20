# GitHub Copilot Instructions for AI Chat Client

## Core Principles

### 1. Standalone Architecture
- **ALWAYS maintain zero external dependencies** - Use only built-in Windows components (WPF, PowerShell cmdlets)
- **Single-file design** - All code must remain in ChatClient.ps1 (no separate modules or files)
- **No external packages** - Never suggest npm, pip, or any package managers
- **Built-in only** - Only use .NET Framework classes and native PowerShell cmdlets that ship with Windows

### 2. Comprehensive Documentation
When adding or modifying ANY tool, command, or feature:

#### Required Elements
1. **Detailed Description**
   - Explain what the tool does
   - List which PowerShell cmdlets or .NET classes it uses
   - Describe when and why to use it
   - Include any caveats or limitations

2. **Complete Parameter Documentation**
   - Document EVERY parameter with clear descriptions
   - Provide examples of valid values
   - Specify value ranges (min/max, enums, formats)
   - Mark optional vs required parameters explicitly
   - Include default values when applicable

3. **Flags and Options**
   - List ALL available flags/switches
   - Explain what each flag does
   - Show examples of flag combinations
   - Document any flag dependencies or conflicts

4. **Configuration Details**
   - Explain how to configure the feature
   - Provide step-by-step configuration instructions
   - Show example configurations
   - Document where settings are stored

5. **Administrator Privileges**
   - Clearly note when admin privileges are required
   - Explain why elevation is needed
   - Suggest alternatives when possible

6. **Warnings and Safety**
   - Add warnings for destructive operations
   - Note operations that cannot be undone
   - Highlight potential data loss risks
   - Document system requirements (restart needed, internet required, etc.)

### 3. Tool Definition Format
Every tool in `$global:toolDefinitions` must follow this pattern:

```powershell
@{type="function"; function=@{
    name="tool_name"
    description="Comprehensive description that includes:
        - What the tool does
        - Which cmdlets/classes it uses (e.g., Get-Process, Test-NetConnection)
        - When to use it (use cases/scenarios)
        - Any requirements or prerequisites"
    parameters=@{
        type="object"
        properties=@{
            paramName=@{
                type="string|number|boolean|array"
                description="Detailed parameter description with examples and valid values"
                enum=@("option1","option2")  # For restricted choices
                items=@{type="string"}       # For arrays
            }
        }
        required=@("param1","param2")
        additionalProperties=$false  # For parameters with no arguments
    }
}}
```

### 4. Examples of Good Documentation

#### ✅ GOOD - Comprehensive
```powershell
description="Set display sleep timeout in minutes using powercfg /change. Controls how long system waits before turning off display. Set to 0 to never turn off display. Separate settings for AC power and battery power."
parameters=@{
    minutes=@{
        type="number"
        description="Minutes until display sleep (0 to disable, typical values: 5-30 for AC, 2-10 for battery)"
    }
    acPower=@{
        type="boolean"
        description="true to set AC power timeout, false to set battery timeout"
    }
}
```

#### ❌ BAD - Insufficient
```powershell
description="Set display timeout"
parameters=@{
    minutes=@{type="number"}
    acPower=@{type="boolean"}
}
```

### 5. Code Standards

#### PowerShell Compatibility
- Support both PowerShell 5.1 and 7+
- Use `$global:isPwsh7` for version detection
- Adapt JSON conversion based on version
- Test with both versions when possible

#### Error Handling
- Always include try/catch blocks for tool execution
- Return meaningful error messages
- Don't expose sensitive information in errors
- Log errors to help with debugging

#### Performance
- Keep intelligent tool selection efficient
- Respect OpenAI's 128-tool limit
- Use category-based filtering
- Minimize API calls

### 6. Forbidden Practices
- ❌ Never add external dependencies (npm, pip, NuGet packages, etc.)
- ❌ Never split into multiple files
- ❌ Never use external APIs beyond OpenAI
- ❌ Never hard-code API keys or sensitive data
- ❌ Never create tools without comprehensive documentation
- ❌ Never omit parameter descriptions or valid value ranges
- ❌ Never skip safety warnings for destructive operations

### 7. Before Committing Changes
Checklist for any new tool or feature:
- [ ] Zero new dependencies added
- [ ] Comprehensive description included
- [ ] All parameters documented with examples
- [ ] All flags/options listed and explained
- [ ] Configuration steps provided
- [ ] Admin requirements noted
- [ ] Warnings added for destructive operations
- [ ] Works on PowerShell 5.1 and 7+
- [ ] Tested in both script and compiled .exe form

## Summary
**This project is a standalone, single-file PowerShell application with comprehensive, self-documenting tools. Every addition must maintain this principle and include complete documentation so the AI can intelligently use all features without guessing.**
