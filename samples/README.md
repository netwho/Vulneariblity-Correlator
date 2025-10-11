# Wireshark Vulnerability Correlator - Sample Files

This directory contains sample files to help you test and demonstrate the functionality of the Wireshark Vulnerability Correlator plugin. These files provide a realistic scenario showing how vulnerable services appear in network traffic and how the plugin correlates them with vulnerability scan data.

## 📁 Sample Files Overview

### `Metasploit_ProFTP.pcapng` 
**Network Capture File** - Contains captured network traffic showing:
- ProFTP service communication on port 21
- Authentication attempts and file transfer protocol interactions
- Various network protocols and service communications
- Real-world traffic patterns that can be correlated with vulnerability data

### `vulners_scan.xml`
**Nmap Vulnerability Scan Results** - XML output from nmap with Vulners script containing:
- Vulnerability scan results for network hosts
- CVE identifiers and CVSS scores for discovered vulnerabilities
- Service version information (ProFTP, SSH, HTTP, etc.)
- Comprehensive vulnerability data that correlates with the network traffic

## 🚀 Quick Start with Sample Files

### Step 1: Install the Plugin
If you haven't already installed the plugin, follow the main installation instructions in the [root README](../README.md).

### Step 2: Configure Plugin Path
Update the plugin configuration to use the sample XML file:

```bash
# Edit the plugin file
nano ~/.local/lib/wireshark/plugins/vulners_correlator_final.lua

# Update line 5 with the sample XML path:
prefs.xml_path = "/Users/walterh/vulner-correlator/samples/vulners_scan.xml"
```

### Step 3: Launch Wireshark with Sample Data
1. Open Wireshark with the "Vulnerability Analysis" profile
2. Load the sample capture: **File → Open → `Metasploit_ProFTP.pcapng`**
3. Observe the vulnerability columns populate with data from the XML scan

## 🔍 What You'll See in the Demo

### Vulnerability Columns
Once loaded, you'll see these new columns in the packet list:
- **CVSS Score**: Numerical vulnerability scores (e.g., 9.8, 7.5, 5.3)
- **CVE ID**: Specific vulnerability identifiers (e.g., CVE-2015-3306)
- **Service Description**: Detailed service information (e.g., "ProFTPD 1.3.5")

### Color Coding
Packets will be automatically color-coded based on vulnerability severity:
- 🔴 **Red**: High/Critical vulnerabilities (CVSS ≥ 7.0)
- 🟡 **Yellow**: Medium vulnerabilities (CVSS 4.0-6.9)
- 🟢 **Green**: Low vulnerabilities (CVSS 1.0-3.9)

### Sample Display Filters
Try these filters to explore the vulnerability data:

```bash
# Show all vulnerable traffic
vulners.cvss_high > 0

# High severity vulnerabilities only
vulners.cvss_high >= 7.0

# ProFTP-specific vulnerabilities
vulners.service_desc contains "ProFTP"

# Specific CVE tracking
vulners.cve_id contains "CVE-2015"

# Combine with protocol filters
vulners.cvss_high >= 7.0 and tcp.port == 21
```

## 📊 Expected Analysis Results

### Vulnerability Correlation
The sample files demonstrate:
- **Host Correlation**: Network traffic from hosts that appear in the vulnerability scan
- **Service Matching**: ProFTP traffic correlated with ProFTP vulnerabilities
- **Port Association**: Traffic on port 21 linked to FTP service vulnerabilities
- **Real-time Context**: Immediate vulnerability information for each packet

### Sample Report Output
When you generate a report using **Tools → Vulnerability Correlator**, expect output similar to:

```
═══════════════════════════════════════════════════════════════════
                 VULNERABILITY CORRELATION REPORT
═══════════════════════════════════════════════════════════════════

📊 SCAN SUMMARY
────────────────────────────────────────────────────────────────
• Total Hosts Scanned: 5
• Total Vulnerable Services: 8  
• Total Vulnerabilities Found: 23
• Critical (CVSS ≥9.0): 2 | High (CVSS ≥7.0): 6

📈 CORRELATION SUMMARY  
────────────────────────────────────────────────────────────────
• Vulnerable Hosts Found in Traffic: 3 of 5 (60.0%)
• Vulnerable Services with Traffic: 4
• Total Vulnerabilities in Captured Traffic: 12

🔍 DETAILED FINDINGS
────────────────────────────────────────────────────────────────
📍 192.168.1.100
  🔴 tcp/21 - ProFTPD 1.3.5 (CVSS: 9.8) CVE-2015-3306
      Packets: 45, 67, 89, 123, 156...
```

## 🎯 Learning Objectives

These sample files help you understand:

### Core Functionality
- How vulnerability scan data integrates with network traffic analysis
- The correlation between nmap scan results and actual network communications
- Visual identification of vulnerable services in packet captures

### Practical Applications
- **Incident Response**: Identify vulnerable services actively communicating
- **Network Assessment**: Validate vulnerability scan results with traffic evidence
- **Threat Hunting**: Search for exploitation attempts on known vulnerable services
- **Compliance**: Document vulnerable service exposure with network evidence

## 🔧 Customizing the Samples

### Using Your Own Data
To use these samples as a template for your own analysis:

1. **Replace the XML file**:
   ```bash
   # Generate your own scan
   nmap -sV --script vuln,vulners -oX your_scan.xml 192.168.1.0/24
   
   # Update plugin configuration
   nano ~/.local/lib/wireshark/plugins/vulners_correlator_final.lua
   # Change: prefs.xml_path = "/path/to/your_scan.xml"
   ```

2. **Capture your own traffic**:
   ```bash
   # Capture while scanning
   tcpdump -i eth0 -w your_traffic.pcapng
   
   # Or use Wireshark's capture interface
   ```

### Advanced Analysis
Try these advanced correlation techniques:

```bash
# Time-based correlation
vulners.cvss_high > 0 and frame.time >= "2024-01-01 10:00:00"

# Multi-host vulnerability tracking
vulners.cvss_high >= 7.0 and (ip.src == 192.168.1.100 or ip.dst == 192.168.1.100)

# Service-specific threat hunting
vulners.service_desc contains "ProFTP" and tcp.flags.syn == 1
```

## 🛠️ Troubleshooting Sample Files

### Common Issues

#### Plugin Not Loading Sample Data
```bash
# Check file paths are correct
ls -la /Users/walterh/vulner-correlator/samples/vulners_scan.xml

# Verify plugin path configuration
grep "xml_path" ~/.local/lib/wireshark/plugins/vulners_correlator_final.lua
```

#### No Vulnerability Columns Visible
1. Ensure you're using the "Vulnerability Analysis" profile
2. Check that columns are configured:
   - Right-click packet list header → Column Preferences
   - Verify vulnerability columns are enabled

#### Sample PCAP Won't Open
```bash
# Check file integrity
file Metasploit_ProFTP.pcapng

# Verify Wireshark can read it
tshark -r Metasploit_ProFTP.pcapng -c 5
```

### Getting Help
If you encounter issues with the sample files:
1. Check the main [troubleshooting section](../README.md#-troubleshooting) in the root README
2. Verify your plugin installation is working with other PCAP files
3. Test the XML file format by examining its contents

## 📚 Next Steps

After testing with these samples:

1. **Generate Your Own Scans**: Use nmap with Vulners script on your network
2. **Capture Live Traffic**: Use Wireshark or tcpdump during vulnerability scanning
3. **Advanced Filtering**: Experiment with complex display filters combining vulnerability and protocol data
4. **Reporting**: Generate comprehensive reports for your security assessments

## 🎓 Educational Value

These samples demonstrate real-world scenarios where:
- Network administrators discover vulnerable services in their traffic
- Security analysts correlate scan results with actual network activity
- Incident responders identify compromised or targeted systems
- Penetration testers validate exploit attempts against vulnerable services

The ProFTP example is particularly valuable as it shows a commonly exploited service with well-documented vulnerabilities, making it perfect for understanding the plugin's correlation capabilities.

---

**Ready to analyze network vulnerabilities like a pro?** Load these samples and start exploring! 🔍🛡️

*For questions or issues with these sample files, please refer to the main project documentation or submit an issue on GitHub.*