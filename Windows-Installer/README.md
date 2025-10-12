# Wireshark Vulnerability Correlator - Windows Installation

Easy installation of the Wireshark Vulnerability Correlator plugin on Windows systems using our automated PowerShell installer script.

## 🪟 **Supported Windows Versions**

✅ **Officially Supported:**
- Windows 10 (1903+)
- Windows 11 (all versions)
- Windows Server 2019/2022

✅ **Should Work On:**
- Windows 8.1 (with PowerShell 5.0+)
- Windows Server 2016
- Any Windows version with PowerShell 5.0+ and Wireshark

## 📋 **Prerequisites**

Before running the installer, ensure you have:

- **Wireshark** installed (version 3.0 or later recommended)
- **PowerShell 5.0** or later (included in Windows 10+)
- **Administrative privileges** (if needed for antivirus/permissions)
- **Internet access** (for downloading if cloning repository)

## 🚀 **Quick Installation**

### **1. Download Files**

#### **Option 1: Download from GitHub**
1. Go to the [GitHub repository](https://github.com/yourusername/wireshark-vulnerability-correlator)
2. Navigate to **Windows-Installer/**
3. Download both files:
   - `install_vulners_plugin_windows.ps1`
   - `vulners_correlator_final.lua`

#### **Option 2: Clone Repository**
```powershell
# Using Git for Windows
git clone https://github.com/yourusername/wireshark-vulnerability-correlator.git
cd wireshark-vulnerability-correlator\Windows-Installer\
```

#### **Option 3: Direct Download with PowerShell**
```powershell
# Create a directory for the installer
mkdir C:\temp\wireshark-plugin
cd C:\temp\wireshark-plugin

# Download files
Invoke-WebRequest -Uri "https://github.com/yourusername/wireshark-vulnerability-correlator/raw/main/Windows-Installer/install_vulners_plugin_windows.ps1" -OutFile "install_vulners_plugin_windows.ps1"
Invoke-WebRequest -Uri "https://github.com/yourusername/wireshark-vulnerability-correlator/raw/main/Windows-Installer/vulners_correlator_final.lua" -OutFile "vulners_correlator_final.lua"
```

### **2. Run the Installer**

#### **Method 1: Right-Click Run (Recommended)**
1. Right-click on `install_vulners_plugin_windows.ps1`
2. Select **"Run with PowerShell"**
3. If prompted about execution policy, choose **"Run once"**

#### **Method 2: PowerShell Command Line**
```powershell
# Open PowerShell (as regular user, NOT as administrator)
# Navigate to the installer directory
cd "C:\path\to\installer\directory"

# Run the installer
.\install_vulners_plugin_windows.ps1

# Or get help first
.\install_vulners_plugin_windows.ps1 -Help
```

### **3. Follow the Installation**
The installer will:
- ✅ Check PowerShell version and Wireshark installation
- ✅ Install the plugin to `%APPDATA%\Wireshark\plugins\`
- ✅ Create the "Vulnerability Analysis" profile
- ✅ Configure vulnerability columns and color highlighting
- ✅ Verify the installation and show next steps

## 📦 **Wireshark Installation (If Needed)**

If Wireshark is not installed, download it from the official site:

### **Download Wireshark for Windows**
1. Go to: https://www.wireshark.org/download.html
2. Click **"Windows x64 Installer"** (recommended for most systems)
3. Or **"Windows x86 Installer"** for 32-bit systems
4. Run the installer with default settings

### **Alternative: Wireshark via Package Manager**
```powershell
# Using Chocolatey (if installed)
choco install wireshark

# Using Winget (Windows 10 1709+)
winget install Wireshark.Wireshark

# Using Scoop (if installed)
scoop install wireshark
```

## 🔐 **PowerShell Execution Policy**

If you encounter execution policy errors:

### **Check Current Policy**
```powershell
Get-ExecutionPolicy
```

### **Temporary Solution (Current Session Only)**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\install_vulners_plugin_windows.ps1
```

### **Permanent Solution (For Current User)**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 🎯 **What the Installer Creates**

### **Plugin Installation**
- **Location**: `%APPDATA%\Wireshark\plugins\vulners_correlator_final.lua`
- **Full Path**: `C:\Users\USERNAME\AppData\Roaming\Wireshark\plugins\`
- **Backup**: Any existing plugin is backed up with timestamp

### **Wireshark Profile: "Vulnerability Analysis"**
- **Location**: `%APPDATA%\Wireshark\profiles\Vulnerability Analysis\`
- **Columns**: Pre-configured with CVSS Score, CVE ID, Service Description
- **Colors**: Automatic highlighting for vulnerability severity levels
- **Filters**: Ready-to-use display filters in history

### **Profile Files Created**
```
%APPDATA%\Wireshark\profiles\Vulnerability Analysis\
├── preferences      # Column layout and display settings
├── colorfilters     # Vulnerability severity color coding
└── recent          # Recent filters and window settings
```

## 🎨 **Visual Features**

### **Automatic Packet Coloring**
- 🔴 **Red Background**: High severity (CVSS ≥ 7.0)
- 🟡 **Yellow Background**: Medium severity (CVSS 4.0-6.9)
- 🟢 **Green Background**: Low severity (CVSS > 0-3.9)

### **Custom Columns**
| Column | Field | Description |
|--------|-------|-------------|
| CVSS Score | `vulners.cvss_high` | Vulnerability severity (0.0-10.0) |
| CVE ID | `vulners.cve_id` | CVE identifier |
| Service Description | `vulners.service_desc` | Service info from nmap scan |

### **Font Selection**
- Uses **Consolas** font (standard Windows monospace font)
- Optimized for readability and security analysis

## 📁 **Default XML Location**

### **Automatic Detection**
The plugin is **pre-configured** to look for vulnerability scan files at:
- **Location**: `%USERPROFILE%\vulners_scan.xml`
- **Example**: `C:\Users\YourName\vulners_scan.xml`
- **Benefit**: Zero configuration required!

### **Quick Workflow**
```powershell
# 1. Generate scan to default location (use PowerShell or Command Prompt)
nmap -sV --script vuln,vulners -oX "%USERPROFILE%\vulners_scan.xml" 192.168.1.0/24

# 2. Install plugin (already done if using installer)
# 3. Launch Wireshark - vulnerability data loads automatically!
```

## 🔍 **Usage After Installation**

### **1. Launch Wireshark**
- Start Menu → "Wireshark"
- Or run: `C:\Program Files\Wireshark\Wireshark.exe`

### **2. Select Profile**
- Go to: **Edit → Configuration Profiles**
- Select: **"Vulnerability Analysis"**

### **3. Configure XML Path (Optional)**

**📁 Default Configuration**: The plugin automatically looks for `vulners_scan.xml` in your **user profile directory**:
- **Location**: `%USERPROFILE%\vulners_scan.xml`
- **Example**: `C:\Users\YourName\vulners_scan.xml`

**✅ No configuration needed** if your scan file is at the default location!

**🔧 For custom locations**, edit the plugin file:
1. Open File Explorer: `%APPDATA%\Wireshark\plugins\`
2. Right-click `vulners_correlator_final.lua` → **Open with Notepad**
3. Line 5 shows current default:
   ```lua
   prefs.xml_path = os.getenv("HOME") .. "/vulners_scan.xml"  -- Default
   ```
4. For custom path, change to:
   ```lua
   prefs.xml_path = "C:\\path\\to\\your\\custom_scan.xml"
   ```
   **Note**: Use double backslashes (`\\`) in Windows paths!

### **4. Load Capture and Analyze**
- Load a packet capture file
- Vulnerability data appears automatically in columns
- Use **Tools → Vulnerability Correlator** for advanced features

## 🔍 **Display Filter Examples**

```
# Show all packets with vulnerability data
vulners.cvss_high > 0

# High severity vulnerabilities only
vulners.cvss_high >= 7.0

# Specific service vulnerabilities
vulners.service_desc contains "Apache"
vulners.service_desc contains "OpenSSH"

# CVE-specific filtering
vulners.cve_id contains "CVE-2018"
vulners.cve_id == "CVE-2018-1312"

# Combined filtering
vulners.cvss_high >= 7.0 and tcp.port == 22
```

## 🚨 **Troubleshooting**

### **Plugin Not Loading**
1. **Check Plugin Location**:
   ```powershell
   # Open File Explorer and navigate to:
   %APPDATA%\Wireshark\plugins\
   
   # Verify file exists and is not empty
   Get-ChildItem "$env:APPDATA\Wireshark\plugins\" | Where-Object {$_.Name -like "*vulners*"}
   ```

2. **Check Wireshark Plugin Loading**:
   - In Wireshark: **Help → About → Plugins**
   - Look for "vulners_correlator_final.lua" in the list

3. **Restart Wireshark**: Close and reopen Wireshark completely

### **PowerShell Execution Errors**
```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Temporarily bypass execution policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Check if file is blocked (downloaded from internet)
Get-Item ".\install_vulners_plugin_windows.ps1" | Get-ItemProperty -Name IsDownloaded

# Unblock file if needed
Unblock-File ".\install_vulners_plugin_windows.ps1"
```

### **Antivirus Blocking Files**
- **Windows Defender**: May quarantine the .ps1 file
- **Third-party AV**: May block PowerShell execution or file operations
- **Solution**: Temporarily disable real-time protection during installation

### **Permission Issues**
```powershell
# Check if directories exist and are accessible
Test-Path "$env:APPDATA\Wireshark"
Test-Path "$env:APPDATA\Wireshark\plugins"

# Check write permissions
New-Item -Path "$env:APPDATA\Wireshark\test.txt" -ItemType File -Force
Remove-Item "$env:APPDATA\Wireshark\test.txt"
```

### **No Vulnerability Data Showing**
1. **Verify XML Path**:
   ```powershell
   # Check if XML file exists
   Test-Path "C:\path\to\your\vulners_scan.xml"
   
   # View first few lines to verify format
   Get-Content "C:\path\to\your\vulners_scan.xml" -TotalCount 10
   ```

2. **Check Plugin Configuration**:
   - Edit plugin file: `%APPDATA%\Wireshark\plugins\vulners_correlator_final.lua`
   - Find line 5: `prefs.xml_path = "C:\\path\\to\\your\\scan.xml"`
   - Ensure path uses double backslashes (`\\`)

3. **Plugin Loading**: **Tools → Vulnerability Correlator → Load XML Data**

### **Display Filters Not Working**
- Ensure you're using the **"Vulnerability Analysis"** profile
- CVSS fields use numeric comparisons: `vulners.cvss_high >= 7.0`
- CVE/Service fields use string operations: `vulners.cve_id contains "CVE"`
- Test basic filter first: `vulners.cvss_high > 0`

### **Installer Specific Issues**

#### **"Script not found" Error**
- Ensure both files are in the same directory
- Check spelling of file names (case-sensitive)
- Try running from the directory containing the files

#### **"Access Denied" Errors**
```powershell
# Run as different user if needed
Start-Process PowerShell -Credential (Get-Credential) -ArgumentList "-File .\install_vulners_plugin_windows.ps1"

# Or check file permissions
Get-Acl ".\install_vulners_plugin_windows.ps1" | Format-List
```

## 📁 **File Locations Reference**

### **Plugin Files**
- **Plugin**: `%APPDATA%\Wireshark\plugins\vulners_correlator_final.lua`
- **Full Path**: `C:\Users\USERNAME\AppData\Roaming\Wireshark\plugins\`
- **Backup**: Same directory with `.backup.TIMESTAMP` extension

### **Configuration Files**
- **Profiles**: `%APPDATA%\Wireshark\profiles\`
- **Analysis Profile**: `%APPDATA%\Wireshark\profiles\Vulnerability Analysis\`

### **Wireshark Installation**
- **Default Location**: `C:\Program Files\Wireshark\`
- **Alternative**: `C:\Program Files (x86)\Wireshark\` (32-bit)
- **Windows Store**: `%LOCALAPPDATA%\Microsoft\WindowsApps\`

### **Quick Access Commands**
```powershell
# Open plugin directory
explorer "$env:APPDATA\Wireshark\plugins"

# Open profile directory  
explorer "$env:APPDATA\Wireshark\profiles"

# Open Wireshark program directory
explorer "${env:ProgramFiles}\Wireshark"
```

## 🛠️ **Manual Installation (Advanced)**

If the automated installer doesn't work:

```powershell
# 1. Create directories
New-Item -Path "$env:APPDATA\Wireshark\plugins" -ItemType Directory -Force
New-Item -Path "$env:APPDATA\Wireshark\profiles" -ItemType Directory -Force

# 2. Copy plugin file
Copy-Item "vulners_correlator_final.lua" "$env:APPDATA\Wireshark\plugins\"

# 3. Create profile manually in Wireshark GUI:
# Edit → Configuration Profiles → Create new profile
# Add custom columns as described in the main documentation
```

## 🖥️ **Command Line Options**

### **Installer Help**
```powershell
.\install_vulners_plugin_windows.ps1 -Help
```

### **Useful PowerShell Commands**
```powershell
# Check Wireshark version
& "${env:ProgramFiles}\Wireshark\Wireshark.exe" -v

# List installed Wireshark plugins
Get-ChildItem "$env:APPDATA\Wireshark\plugins"

# View plugin content
Get-Content "$env:APPDATA\Wireshark\plugins\vulners_correlator_final.lua" -TotalCount 20
```

## 📞 **Support**

### **Getting Help**
- **Email**: walter.hofstetter@netwho.com
- **Plugin Issues**: Check the main project repository issues
- **Wireshark Issues**: Visit [Wireshark Support](https://ask.wireshark.org/)

### **Reporting Bugs**
When reporting issues, please include:
- Windows version (`Get-ComputerInfo | Select WindowsProductName, WindowsVersion`)
- PowerShell version (`$PSVersionTable.PSVersion`)
- Wireshark version (from **Help → About**)
- Full installer output (copy from PowerShell window)
- Any error messages or screenshots

### **Common Information Commands**
```powershell
# System information
Get-ComputerInfo | Select WindowsProductName, WindowsVersion

# PowerShell version
$PSVersionTable

# Check execution policy
Get-ExecutionPolicy -List

# Check if Wireshark is installed
Get-Command wireshark -ErrorAction SilentlyContinue
Test-Path "${env:ProgramFiles}\Wireshark\Wireshark.exe"
```

## 📝 **License**

This plugin is provided under the MIT License. See the main project LICENSE file for details.

---

**For other platforms**: See [Mac-Installer](../Mac-Installer/) or [Linux-Installer](../Linux-Installer/)

**Happy vulnerability hunting on Windows!** 🪟🔍