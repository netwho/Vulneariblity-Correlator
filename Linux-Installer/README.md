# Wireshark Vulnerability Correlator - Linux Installation

Easy installation of the Wireshark Vulnerability Correlator plugin on Linux systems using our automated installer script.

## 🐧 **Supported Linux Distributions**

✅ **Officially Tested:**
- Ubuntu 18.04+ / Debian 9+
- Fedora 30+ / CentOS 7+ / RHEL 7+
- Arch Linux
- openSUSE Leap 15.0+

✅ **Should Work On:**
- Any modern Linux distribution with Wireshark 3.0+
- Other Debian/Ubuntu derivatives
- Other Red Hat derivatives

## 📋 **Prerequisites**

Before running the installer, ensure you have:

- **Wireshark** installed (version 3.0 or later recommended)
- **Bash shell** (standard on all Linux systems)
- **Standard tools**: `curl`, `grep`, `sed` (usually pre-installed)
- **Network capture permissions** (see setup below)

## 🚀 **Quick Installation**

### **1. Download Files**
```bash
# Option 1: Clone the repository
git clone https://github.com/yourusername/wireshark-vulnerability-correlator.git
cd wireshark-vulnerability-correlator/Linux-Installer/

# Option 2: Download individual files
wget https://github.com/yourusername/wireshark-vulnerability-correlator/raw/main/Linux-Installer/install_vulners_plugin_linux.sh
wget https://github.com/yourusername/wireshark-vulnerability-correlator/raw/main/Linux-Installer/vulners_correlator_final.lua
```

### **2. Run the Installer**
```bash
# Make the installer executable
chmod +x install_vulners_plugin_linux.sh

# Run the installer as your regular user (NOT as root!)
./install_vulners_plugin_linux.sh
```

### **3. Follow the Output**
The installer will:
- ✅ Detect your Linux distribution
- ✅ Check for Wireshark and required tools
- ✅ Install the plugin to `~/.local/lib/wireshark/plugins/`
- ✅ Create the "Vulnerability Analysis" profile
- ✅ Configure vulnerability columns and color highlighting
- ✅ Verify the installation

## 📦 **Distribution-Specific Wireshark Installation**

If Wireshark is not installed, the installer will provide the correct command for your distribution:

### **Ubuntu / Debian**
```bash
sudo apt update && sudo apt install wireshark
```

### **Fedora**
```bash
sudo dnf install wireshark-qt
```

### **CentOS / RHEL**
```bash
# CentOS 7/8
sudo yum install wireshark-qt

# RHEL 8+
sudo dnf install wireshark-qt
```

### **Arch Linux**
```bash
sudo pacman -S wireshark-qt
```

### **openSUSE**
```bash
sudo zypper install wireshark-ui-qt
```

## 🔐 **Network Capture Permissions Setup**

After installing Wireshark, you'll need permission to capture network traffic:

### **Method 1: Add User to wireshark Group (Recommended)**
```bash
# Add your user to the wireshark group
sudo usermod -a -G wireshark $USER

# Log out and back in (or reboot) for changes to take effect
# Verify membership:
groups | grep wireshark
```

### **Method 2: Use sudo (Less Secure)**
```bash
# Run Wireshark with sudo (not recommended for regular use)
sudo wireshark
```

## 🎯 **What the Installer Creates**

### **Plugin Installation**
- **Location**: `~/.local/lib/wireshark/plugins/vulners_correlator_final.lua`
- **Permissions**: Read/write for user only (644)
- **Backup**: Any existing plugin is backed up with timestamp

### **Wireshark Profile: "Vulnerability Analysis"**
- **Location**: `~/.config/wireshark/profiles/Vulnerability Analysis/`
- **Columns**: Pre-configured with CVSS Score, CVE ID, Service Description
- **Colors**: Automatic highlighting for vulnerability severity levels
- **Filters**: Ready-to-use display filters in history

### **Profile Files Created**
```
~/.config/wireshark/profiles/Vulnerability Analysis/
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

## 🔍 **Usage After Installation**

### **1. Launch Wireshark**
```bash
wireshark
# or
/usr/bin/wireshark  # if not in PATH
```

### **2. Select Profile**
- Go to: **Edit → Configuration Profiles**
- Select: **"Vulnerability Analysis"**

### **3. Configure XML Path**
Edit the plugin to point to your vulnerability scan:
```bash
nano ~/.local/lib/wireshark/plugins/vulners_correlator_final.lua

# Update line 5:
prefs.xml_path = "/path/to/your/vulners_scan.xml"
```

### **4. Load Capture and Analyze**
- Load a packet capture file
- Vulnerability data appears automatically in columns
- Use **Tools → Vulnerability Correlator** for advanced features

## 🔍 **Display Filter Examples**

```bash
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
```bash
# Verify plugin location and permissions
ls -la ~/.local/lib/wireshark/plugins/vulners_correlator_final.lua

# Check Wireshark plugins
wireshark -v  # Shows plugin directories
# Then: Help → About → Plugins (in Wireshark GUI)
```

### **Permission Issues**
```bash
# Fix plugin file permissions
chmod 644 ~/.local/lib/wireshark/plugins/vulners_correlator_final.lua

# Fix directory permissions  
chmod 755 ~/.local/lib/wireshark/plugins/
```

### **Can't Capture Packets**
```bash
# Check if user is in wireshark group
groups | grep wireshark

# If not, add user and reboot
sudo usermod -a -G wireshark $USER
sudo reboot

# Alternative: Check dumpcap permissions
ls -la /usr/bin/dumpcap
# Should show: -rwxr-x--- root wireshark
```

### **No Vulnerability Data Showing**
```bash
# Verify XML file path
grep xml_path ~/.local/lib/wireshark/plugins/vulners_correlator_final.lua

# Test XML file accessibility
cat /path/to/your/vulners_scan.xml | head -20

# Check plugin loading in Wireshark console
# Tools → Vulnerability Correlator → Load XML Data
```

### **Display Filters Not Working**
- Ensure you're using the "Vulnerability Analysis" profile
- Remember: CVSS fields use numeric comparisons (`>`, `>=`, `<`)
- CVE/Service fields use string operations (`contains`, `==`)
- Test basic filter first: `vulners.cvss_high > 0`

### **Installer Issues**
```bash
# Re-run installer with verbose output
bash -x ./install_vulners_plugin_linux.sh

# Check installer requirements
which curl grep sed lua
echo $SHELL

# Verify Wireshark installation
which wireshark
wireshark --version
```

## 📁 **File Locations Reference**

### **Plugin Files**
- **Plugin**: `~/.local/lib/wireshark/plugins/vulners_correlator_final.lua`
- **Backup**: `~/.local/lib/wireshark/plugins/vulners_correlator_final.lua.backup.TIMESTAMP`

### **Configuration Files**
- **Profiles**: `~/.config/wireshark/profiles/`
- **Analysis Profile**: `~/.config/wireshark/profiles/Vulnerability Analysis/`

### **System Wireshark**
- **Binary**: `/usr/bin/wireshark` (most distributions)
- **System Plugins**: `/usr/lib/x86_64-linux-gnu/wireshark/plugins/` (varies by distro)
- **System Config**: `/etc/wireshark/`

## 🛠️ **Manual Installation (Advanced)**

If the automated installer doesn't work for your setup:

```bash
# 1. Create directories
mkdir -p ~/.local/lib/wireshark/plugins
mkdir -p ~/.config/wireshark/profiles

# 2. Copy plugin
cp vulners_correlator_final.lua ~/.local/lib/wireshark/plugins/
chmod 644 ~/.local/lib/wireshark/plugins/vulners_correlator_final.lua

# 3. Create profile manually in Wireshark GUI
# Edit → Configuration Profiles → Create new profile
# Add custom columns as described above
```

## 📞 **Support**

### **Getting Help**
- **Email**: walter.hofstetter@netwho.com
- **Plugin Issues**: Check the main project repository issues
- **Wireshark Issues**: Consult [Wireshark Documentation](https://www.wireshark.org/docs/)

### **Reporting Bugs**
When reporting issues, please include:
- Linux distribution and version (`cat /etc/os-release`)
- Wireshark version (`wireshark --version`)
- Installer output (copy the full terminal output)
- Error messages from Wireshark console

## 📝 **License**

This plugin is provided under the MIT License. See the main project LICENSE file for details.

---

**For other platforms**: See [Mac-Installer](../Mac-Installer/) or [Windows-Installer](../Windows-Installer/)

**Happy vulnerability hunting on Linux!** 🐧🔍