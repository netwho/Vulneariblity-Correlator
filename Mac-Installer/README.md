# Wireshark Vulnerability Correlator Plugin

A powerful Wireshark plugin that correlates nmap Vulners XML vulnerability scan results with captured network traffic, providing real-time vulnerability context directly in the Wireshark interface.

## Features

- 🎯 **Real-time Vulnerability Detection**: Automatically identifies vulnerable services in network traffic
- 📊 **CVSS Scoring**: Displays CVSS scores for immediate risk assessment
- 🏷️ **CVE Integration**: Shows CVE identifiers for tracked vulnerabilities  
- 🖥️ **Service Identification**: Displays service information (e.g., "Apache httpd 2.4.7")
- 🎨 **Color Coding**: Automatically highlights high-risk packets
- 📈 **Detailed Reports**: Generate comprehensive vulnerability correlation reports
- 🔍 **Advanced Filtering**: Use Wireshark display filters with vulnerability data

## Installation (Automated)

### Prerequisites
- **Wireshark** installed (from [wireshark.org](https://www.wireshark.org/download.html))
- **macOS** (tested on macOS 10.15+)
- **nmap Vulners scan results** in XML format

### Quick Install
1. Download or clone this repository
2. Open Terminal and navigate to the plugin directory
3. Run the installer:
   ```bash
   ./install_vulners_plugin.sh
   ```

The installer will:
- ✅ Check prerequisites (Wireshark, required tools)
- ✅ Create necessary directories
- ✅ Install the plugin file
- ✅ Create a pre-configured "Vulnerability Analysis" Wireshark profile
- ✅ Set up color filters for vulnerability highlighting
- ✅ Verify the installation

## Manual Installation

If you prefer to install manually:

### 1. Install Plugin
```bash
# Create plugin directory
mkdir -p ~/.local/lib/wireshark/plugins

# Copy plugin file
cp vulners_correlator_final.lua ~/.local/lib/wireshark/plugins/
```

### 2. Configure Wireshark Profile
1. Launch Wireshark
2. Go to **Edit → Configuration Profiles**
3. Create a new profile called "Vulnerability Analysis"
4. Add these columns to the packet list:
   - CVSS Score: `%Cus:vulners.cvss_high:0:R`
   - CVE ID: `%Cus:vulners.cve_id:0:R`
   - Service Description: `%Cus:vulners.service_desc:0:R`

## Usage

### 1. Generate Vulnerability Scan
First, scan your target network with nmap and the Vulners script:
```bash
nmap -sV --script vuln,vulners --script-args vulners.shodan-api-key=YOUR_KEY \
     -oX vulners_scan.xml 192.168.1.0/24
```

### 2. Configure Plugin
Edit the XML file path in the plugin:
```bash
# Open the plugin file
nano ~/.local/lib/wireshark/plugins/vulners_correlator_final.lua

# Update line 5:
prefs.xml_path = "/path/to/your/vulners_scan.xml"
```

### 3. Launch Wireshark
1. Start Wireshark
2. Select the "Vulnerability Analysis" profile
3. Load a packet capture file
4. The vulnerability data will automatically populate in the columns

### 4. Access Plugin Features
Use the **Tools → Vulnerability Correlator** menu for:
- **Load XML Data**: Parse vulnerability scan results
- **Generate Report**: Create detailed correlation reports
- **Instructions**: View setup and usage help

## Display Filters

The plugin adds powerful filtering capabilities:

### CVSS Score Filtering
- `vulners.cvss_high > 5.0` - Show vulnerabilities with CVSS > 5.0
- `vulners.cvss_high >= 7.0` - Show high severity (≥7.0)
- `vulners.cvss_high >= 9.0` - Show critical severity (≥9.0)
- `vulners.cvss_high between 4.0 and 6.9` - Show medium severity range

### CVE Filtering  
- `vulners.cve_id` - Show packets with CVE identifiers
- `vulners.cve_id == "CVE-2018-1312"` - Show specific CVE
- `vulners.cve_id contains "CVE-2018"` - Show CVEs from 2018
- `vulners.cve_id matches "CVE-201[5-8]"` - Regex matching

### Service Filtering
- `vulners.service_desc contains "Apache"` - Show Apache services
- `vulners.service_desc contains "SSH"` - Show SSH services  
- `vulners.service_desc contains "ProFTPD"` - Show ProFTPD services

### Combined Filters
- `vulners.cvss_high >= 7.0 and tcp.port == 80` - High-risk HTTP traffic
- `vulners.cve_id and vulners.cvss_high > 5.0` - CVEs with CVSS > 5.0

## Color Coding

The plugin automatically applies color filters:
- 🔴 **Red Background**: High severity (CVSS ≥ 7.0)
- 🟡 **Yellow Background**: Medium severity (CVSS 4.0-6.9)  
- 🟢 **Green Background**: Low severity (CVSS > 0-3.9)

## Reports

Generate detailed vulnerability correlation reports:
1. Go to **Tools → Vulnerability Correlator → Generate Report**
2. Reports include:
   - Scan summary with vulnerability statistics
   - Correlation summary showing traffic matches
   - Detailed findings with packet numbers and locations

## Field Reference

| Field Name | Type | Description | Example Usage |
|------------|------|-------------|---------------|
| `vulners.cvss_high` | Float | CVSS score | `vulners.cvss_high >= 7.0` |
| `vulners.cve_id` | String | CVE identifier | `vulners.cve_id == "CVE-2018-1312"` |
| `vulners.service_desc` | String | Service description | `vulners.service_desc contains "Apache"` |

## Troubleshooting

### Plugin Not Loading
- Ensure the plugin file is in `~/.local/lib/wireshark/plugins/`
- Check Wireshark's **Help → About → Plugins** tab
- Verify file permissions: `chmod 644 vulners_correlator_final.lua`

### No Vulnerability Data Showing
- Verify the XML file path in the plugin configuration
- Ensure the XML file contains Vulners script output
- Check the Wireshark console for plugin messages

### Display Filter Not Working
- Ensure you're using the correct field names
- Remember CVSS fields use numeric comparisons: `vulners.cvss_high > 5.0`
- String fields use string operations: `vulners.cve_id contains "CVE"`

## Configuration Files

### Plugin Location
- **Plugin**: `~/.local/lib/wireshark/plugins/vulners_correlator_final.lua`
- **Profile**: `~/.config/wireshark/profiles/Vulnerability Analysis/`

### Profile Files Created
- `preferences` - Column layout and display settings
- `colorfilters` - Vulnerability highlighting rules
- `recent` - Recent filters and window settings

## Support

For issues, questions, or feature requests:
- **Email**: walter.hofstetter@netwho.com
- **Plugin Location**: `~/.local/lib/wireshark/plugins/vulners_correlator_final.lua`

## License

This plugin is provided as-is for educational and professional security analysis purposes.

---

**Happy vulnerability hunting!** 🔍🛡️