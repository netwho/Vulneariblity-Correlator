# Wireshark Vulnerability Correlator Plugin Installer for Windows
# Author: Walter Hofstetter (walter.hofstetter@netwho.com)
# Version: 1.0

param(
    [switch]$Help
)

# Configuration
$PLUGIN_NAME = "vulners_correlator_final.lua"
$PROFILE_NAME = "Vulnerability Analysis"
$WIRESHARK_PLUGINS_DIR = "$env:APPDATA\Wireshark\plugins"
$WIRESHARK_PROFILES_DIR = "$env:APPDATA\Wireshark\profiles"
$INSTALL_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Color functions for output
function Write-Header {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "    Wireshark Vulnerability Correlator Plugin Installer (Windows)" -ForegroundColor Blue  
    Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "➤ $Message" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Cyan
}

function Show-Help {
    Write-Header
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  .\install_vulners_plugin_windows.ps1"
    Write-Host ""
    Write-Host "DESCRIPTION:" -ForegroundColor Yellow
    Write-Host "  Installs the Wireshark Vulnerability Correlator plugin on Windows."
    Write-Host "  Creates plugin directory, copies files, and sets up Wireshark profile."
    Write-Host ""
    Write-Host "REQUIREMENTS:" -ForegroundColor Yellow
    Write-Host "  - Wireshark installed"
    Write-Host "  - PowerShell 5.0 or later"
    Write-Host "  - $PLUGIN_NAME in the same directory as this script"
    Write-Host ""
    Write-Host "OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -Help    Show this help message"
    Write-Host ""
    exit 0
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Prerequisites {
    Write-Step "Checking prerequisites..."
    
    $missingDeps = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Error "PowerShell 5.0 or later is required. Current version: $($PSVersionTable.PSVersion)"
        $missingDeps += "PowerShell 5.0+"
    }
    
    # Check if Wireshark is installed
    $wiresharkPaths = @(
        "${env:ProgramFiles}\Wireshark\Wireshark.exe",
        "${env:ProgramFiles(x86)}\Wireshark\Wireshark.exe",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps\Wireshark.exe"
    )
    
    $wiresharkFound = $false
    foreach ($path in $wiresharkPaths) {
        if (Test-Path $path) {
            Write-Success "Wireshark found at: $path"
            $wiresharkFound = $true
            break
        }
    }
    
    # Also check PATH
    if (-not $wiresharkFound) {
        try {
            $wiresharkCmd = Get-Command wireshark -ErrorAction Stop
            Write-Success "Wireshark command found in PATH: $($wiresharkCmd.Source)"
            $wiresharkFound = $true
        }
        catch {
            # Wireshark not in PATH
        }
    }
    
    if (-not $wiresharkFound) {
        $missingDeps += "Wireshark"
    }
    
    if ($missingDeps.Count -gt 0) {
        Write-Error "Missing prerequisites: $($missingDeps -join ', ')"
        Write-Host ""
        Write-Info "Please install the missing components:"
        
        foreach ($dep in $missingDeps) {
            switch ($dep) {
                "Wireshark" {
                    Write-Host "  • Download Wireshark from: https://www.wireshark.org/download.html"
                    Write-Host "    Choose the Windows x64 Installer"
                }
                "PowerShell 5.0+" {
                    Write-Host "  • Update PowerShell from: https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows"
                }
                default {
                    Write-Host "  • Install $dep"
                }
            }
        }
        throw "Missing prerequisites"
    }
    
    Write-Success "All prerequisites satisfied"
}

function New-Directories {
    Write-Step "Creating necessary directories..."
    
    # Create plugin directory
    if (-not (Test-Path $WIRESHARK_PLUGINS_DIR)) {
        try {
            New-Item -ItemType Directory -Path $WIRESHARK_PLUGINS_DIR -Force | Out-Null
            Write-Success "Created plugins directory: $WIRESHARK_PLUGINS_DIR"
        }
        catch {
            Write-Error "Failed to create plugins directory: $($_.Exception.Message)"
            throw
        }
    }
    else {
        Write-Success "Plugins directory exists: $WIRESHARK_PLUGINS_DIR"
    }
    
    # Create profiles directory
    if (-not (Test-Path $WIRESHARK_PROFILES_DIR)) {
        try {
            New-Item -ItemType Directory -Path $WIRESHARK_PROFILES_DIR -Force | Out-Null
            Write-Success "Created profiles directory: $WIRESHARK_PROFILES_DIR"
        }
        catch {
            Write-Error "Failed to create profiles directory: $($_.Exception.Message)"
            throw
        }
    }
    else {
        Write-Success "Profiles directory exists: $WIRESHARK_PROFILES_DIR"
    }
}

function Install-Plugin {
    Write-Step "Installing Vulnerability Correlator plugin..."
    
    $sourcePlugin = Join-Path $INSTALL_DIR $PLUGIN_NAME
    $targetPlugin = Join-Path $WIRESHARK_PLUGINS_DIR $PLUGIN_NAME
    
    if (-not (Test-Path $sourcePlugin)) {
        Write-Error "Plugin file not found: $sourcePlugin"
        Write-Info "Make sure $PLUGIN_NAME is in the same directory as this installer"
        throw "Plugin file not found"
    }
    
    # Backup existing plugin if it exists
    if (Test-Path $targetPlugin) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = "$targetPlugin.backup.$timestamp"
        try {
            Copy-Item $targetPlugin $backupFile
            Write-Info "Backed up existing plugin to: $backupFile"
        }
        catch {
            Write-Warning "Could not backup existing plugin: $($_.Exception.Message)"
        }
    }
    
    # Copy plugin
    try {
        Copy-Item $sourcePlugin $targetPlugin -Force
        Write-Success "Plugin installed: $targetPlugin"
    }
    catch {
        Write-Error "Failed to copy plugin file: $($_.Exception.Message)"
        throw
    }
}

function New-Profile {
    Write-Step "Creating Wireshark profile: $PROFILE_NAME..."
    
    $profileDir = Join-Path $WIRESHARK_PROFILES_DIR $PROFILE_NAME
    
    # Create profile directory
    try {
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    }
    catch {
        Write-Error "Failed to create profile directory: $($_.Exception.Message)"
        throw
    }
    
    # Create preferences file with vulnerability columns
    $preferencesContent = @'
####### User Interface: Columns ########

# Packet list hidden columns
gui.column.hide: 4,5,6,7,8,19,20,21,22,23,24,25,26,27,28,29,30,31,32

# Packet list column format
# Each pair of strings consists of a column title and its format
gui.column.format: 
	"No.", "%m",
	"Time", "%t",
	"Time Delta", "%Gt",
	"Source", "%s",
	"Destination", "%d",
	"CVSS Score", "%Cus:vulners.cvss_high:0:R",
	"CVE ID", "%Cus:vulners.cve_id:0:R",
	"Service Description", "%Cus:vulners.service_desc:0:R",
	"Protocol", "%p",
	"Length", "%L",
	"Info", "%i"

####### User Interface: Font ########

# Font name for packet list, protocol tree, and hex dump panes. (Qt)
# Using Consolas, a common monospace font on Windows
gui.qt.font_name: Consolas,10,-1,5,50,0,0,0,0,0

####### User Interface: Layout ########

# Layout content of the pane 3 (enable packet diagram)
gui.layout_content_3: PDIAGRAM

####### Name Resolution ########

# Resolve network (IP) addresses
name_resolve.network_name: TRUE

# Resolve transport names
name_resolve.transport_name: TRUE
'@
    
    try {
        $preferencesFile = Join-Path $profileDir "preferences"
        $preferencesContent | Out-File -FilePath $preferencesFile -Encoding UTF8
    }
    catch {
        Write-Error "Failed to create preferences file: $($_.Exception.Message)"
        throw
    }
    
    # Create colorfilters file with vulnerability highlighting
    $colorfiltersContent = @'
# Colorfilters for Vulnerability Analysis Profile
@High CVSS Vulnerabilities (≥7.0)@vulners.cvss_high >= 7.0@[65535,20560,20560][0,0,0]
@Medium CVSS Vulnerabilities (4.0-6.9)@vulners.cvss_high >= 4.0 and vulners.cvss_high < 7.0@[65535,65535,20560][0,0,0]
@Low CVSS Vulnerabilities (>0-3.9)@vulners.cvss_high > 0 and vulners.cvss_high < 4.0@[20560,65535,20560][0,0,0]
@TCP@tcp@[59367,58339,58853][0,0,0]
@UDP@udp@[28784,57054,65535][0,0,0]
@ICMP@icmp@[64250,47802,12850][0,0,0]
@ARP@arp@[64507,49601,2313][0,0,0]
@ICMP errors@icmp.type eq 3 or icmp.type eq 4 or icmp.type eq 5 or icmp.type eq 11 or icmpv6.type eq 1 or icmpv6.type eq 2 or icmpv6.type eq 3 or icmpv6.type eq 4@[0,65535,3616][0,0,0]
@Broadcast@eth.dst == ff:ff:ff:ff:ff:ff@[65535,65535,65535][0,0,0]
@Background@@@[65535,65535,65535][0,0,0]
'@
    
    try {
        $colorfiltersFile = Join-Path $profileDir "colorfilters"
        $colorfiltersContent | Out-File -FilePath $colorfiltersFile -Encoding UTF8
    }
    catch {
        Write-Error "Failed to create colorfilters file: $($_.Exception.Message)"
        throw
    }
    
    # Create recent file with basic settings
    $recentContent = @'
# Recent settings file for Vulnerability Analysis Profile

######## Recent capture files (latest last), cannot be altered through command line ########

######## Recent capture filters (latest last), cannot be altered through command line ########

######## Recent display filters (latest last), cannot be altered through command line ########

gui.recent.display_filter0: vulners.cvss_high > 0
gui.recent.display_filter1: vulners.cvss_high >= 7.0
gui.recent.display_filter2: vulners.cve_id
gui.recent.display_filter3: vulners.service_desc contains "Apache"
gui.recent.display_filter4: vulners.service_desc contains "SSH"

# Main window geometry
gui.geometry.main.x: 100
gui.geometry.main.y: 100
gui.geometry.main.width: 1400
gui.geometry.main.height: 900

# Main window maximized
gui.geometry.main.maximized: FALSE
'@
    
    try {
        $recentFile = Join-Path $profileDir "recent"
        $recentContent | Out-File -FilePath $recentFile -Encoding UTF8
    }
    catch {
        Write-Error "Failed to create recent file: $($_.Exception.Message)"
        throw
    }
    
    Write-Success "Created Wireshark profile: $profileDir"
}

function Test-Installation {
    Write-Step "Verifying installation..."
    
    # Check plugin file
    $pluginFile = Join-Path $WIRESHARK_PLUGINS_DIR $PLUGIN_NAME
    if (Test-Path $pluginFile) {
        Write-Success "Plugin file verified: $pluginFile"
    }
    else {
        Write-Error "Plugin file missing!"
        return $false
    }
    
    # Check profile
    $profileDir = Join-Path $WIRESHARK_PROFILES_DIR $PROFILE_NAME
    if (Test-Path $profileDir) {
        Write-Success "Profile verified: $profileDir"
    }
    else {
        Write-Error "Profile directory missing!"
        return $false
    }
    
    # Check if we can read the plugin file (basic check)
    try {
        $pluginContent = Get-Content $pluginFile -Raw
        if ($pluginContent -match "vulners_correlator") {
            Write-Success "Plugin content verified"
        }
        else {
            Write-Warning "Plugin content may be incomplete"
        }
    }
    catch {
        Write-Warning "Could not verify plugin content: $($_.Exception.Message)"
    }
    
    return $true
}

function Show-Usage {
    Write-Step "Installation completed successfully!"
    Write-Host ""
    Write-Info "Next steps:"
    Write-Host "  1. Launch Wireshark"
    Write-Host "  2. Go to: Edit → Configuration Profiles"
    Write-Host "  3. Select the '$PROFILE_NAME' profile"
    Write-Host "  4. Load a packet capture file"
    Write-Host "  5. Use the Tools menu: Tools → Vulnerability Correlator"
    Write-Host ""
    Write-Info "Important setup:"
    Write-Host "  • Update the XML file path in the plugin if needed:"
    Write-Host "    Edit: $WIRESHARK_PLUGINS_DIR\$PLUGIN_NAME"
    Write-Host "    Look for: prefs.xml_path = `"C:\path\to\your\vulners_scan.xml`""
    Write-Host ""
    Write-Info "Example display filters:"
    Write-Host "  • vulners.cvss_high > 5        (CVSS score greater than 5)"
    Write-Host "  • vulners.cvss_high >= 7.0     (High severity vulnerabilities)"
    Write-Host "  • vulners.cve_id               (Show packets with CVE IDs)"
    Write-Host "  • vulners.service_desc contains `"Apache`"  (Apache services only)"
    Write-Host ""
    Write-Info "Troubleshooting:"
    Write-Host "  • If Wireshark doesn't detect the plugin, restart Wireshark"
    Write-Host "  • Check Help → About → Plugins to see if plugin is loaded"
    Write-Host "  • Ensure you're using the 'Vulnerability Analysis' profile"
    Write-Host ""
    Write-Info "Plugin location: $WIRESHARK_PLUGINS_DIR\$PLUGIN_NAME"
    Write-Info "Profile location: $WIRESHARK_PROFILES_DIR\$PROFILE_NAME"
    Write-Host ""
    Write-Success "Happy vulnerability hunting! 🔍"
}

# Main installation process
function Start-Installation {
    try {
        Write-Header
        
        # Check if running as administrator
        if (Test-Administrator) {
            Write-Warning "Running as Administrator. This is not recommended for user-specific installation."
            Write-Info "Consider running as regular user for proper file permissions."
        }
        
        Test-Prerequisites
        New-Directories
        Install-Plugin
        New-Profile
        
        if (Test-Installation) {
            Show-Usage
        }
        else {
            Write-Error "Installation verification failed!"
            exit 1
        }
    }
    catch {
        Write-Error "Installation failed: $($_.Exception.Message)"
        Write-Host ""
        Write-Info "Common solutions:"
        Write-Host "  • Run PowerShell as Administrator if you have permission issues"
        Write-Host "  • Ensure Wireshark is properly installed"
        Write-Host "  • Check that $PLUGIN_NAME exists in the same directory as this script"
        Write-Host "  • Temporarily disable antivirus if files are being blocked"
        exit 1
    }
}

# Script entry point
if ($Help) {
    Show-Help
}
else {
    Start-Installation
}