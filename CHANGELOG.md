# Changelog

## [0.2.0] - 2025-10-12

### 🎯 Major Improvements

#### Fixed Vulnerability Targeting Logic
- **BREAKING CHANGE**: Vulnerability fields now only appear for packets **targeting** vulnerable hosts (destination), not originating from them
- Eliminates confusion between attack traffic and server responses
- Clean, focused highlighting of actual potential attacks
- Improves security analysis accuracy

#### Enhanced OpenVAS Integration
- **NEW**: Complete support for OpenVAS CSV exports via `helper/openvas_csv_to_xml.py`
- **FIXED**: Missing vulnerabilities without official CVEs now included using synthetic identifiers (NOVT-*)
- **RESOLVED**: CVSS 10.0 Drupal Coder RCE vulnerability no longer missed from OpenVAS data
- Enhanced service detection with nmap-style service names

#### Service Detection Improvements
- **NEW**: nmap-style service naming (e.g., "ProFTPD 1.3.5 Server", "Apache httpd")
- **ENHANCED**: Context-aware service descriptions (e.g., "ProFTPD 1.3.5 Server (mod_copy vulnerability)")
- **IMPROVED**: Better version extraction and service identification
- **ADDED**: Intelligent fallback to port-based service identification

### 🔧 Configuration Updates

#### Default XML Path
- **CHANGED**: Default scan file location now `~/vulners_scan.xml` (previously temp file)
- **IMPROVED**: Cross-platform compatibility maintained
- **ADDED**: Automatic detection of XML format (nmap vs OpenVAS)

### 🐛 Bug Fixes

- **FIXED**: Vulnerabilities without CVE identifiers no longer skipped
- **FIXED**: False version extraction from OID numbers in SSH detection
- **FIXED**: Missing CVSS 10.0 entries in OpenVAS conversions
- **IMPROVED**: More reliable XML parsing and error handling

### 🚀 New Features

#### Enhanced OpenVAS Support
- **NEW**: `helper/openvas_csv_to_xml.py` - Convert OpenVAS CSV exports to plugin-compatible XML
- **NEW**: Sample OpenVAS data included for testing (`helper/sample-imput.csv`)
- **NEW**: Synthetic CVE generation for vulnerabilities without official identifiers
- **NEW**: Enhanced service information extraction from vulnerability data

#### Improved User Experience
- **ENHANCED**: Better debug logging with targeting context
- **IMPROVED**: Plugin initialization messages show data source type
- **ADDED**: Comprehensive vulnerability statistics in reports
- **UPDATED**: Documentation reflects all changes

### 🗂️ File Structure Changes

```
helper/                                    # NEW: OpenVAS integration tools
├── openvas_csv_to_xml.py                 # CSV to XML converter
├── sample-imput.csv                      # Sample OpenVAS data
├── sample-output.xml                     # Example converted output
└── README.md                             # Helper documentation

WARP.md                                   # NEW: Development guidance
CHANGELOG.md                              # NEW: Version history
```

### 📋 Technical Details

#### Plugin Architecture
- **Targeting Logic**: Only destination-based vulnerability field population
- **XML Processing**: Automatic format detection (nmap Vulners vs OpenVAS)
- **Service Detection**: Intelligent service name mapping with version inference
- **Performance**: Improved caching and packet processing efficiency

#### Compatibility
- **Wireshark**: 4.0+ (unchanged)
- **Platforms**: macOS, Linux, Windows (unchanged)
- **Scan Sources**: nmap Vulners + OpenVAS (expanded)

### 🔄 Migration Guide

#### For Existing Users
1. **Plugin automatically uses new default location**: `~/vulners_scan.xml`
2. **Targeting behavior change**: Only attacking traffic shows vulnerability data
3. **Enhanced service names**: More detailed service descriptions in columns

#### For OpenVAS Users
1. **Export CSV** from OpenVAS
2. **Convert to XML**: `python3 helper/openvas_csv_to_xml.py input.csv output.xml`
3. **Copy to default location**: `cp output.xml ~/vulners_scan.xml`
4. **Restart Wireshark** and load your capture

### 🎯 Breaking Changes

- **Vulnerability Field Population**: Now only shows for packets targeting vulnerable hosts (not responses from them)
- **Default XML Location**: Changed from temp files to `~/vulners_scan.xml`

### 📝 Developer Notes

- All installer Lua files synchronized with improvements
- Enhanced error handling and validation
- Improved code documentation and comments
- Ready for distribution across all platforms

---

### Previous Versions

## [0.1.x] - Previous releases
- Basic nmap Vulners integration
- Initial Wireshark plugin implementation
- Cross-platform installers
