#!/bin/bash

# Wireshark Vulnerability Correlator Plugin Installer for Linux
# Author: Walter Hofstetter (walter.hofstetter@netwho.com)
# Version: 1.0

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PLUGIN_NAME="vulners_correlator_final.lua"
PROFILE_NAME="Vulnerability Analysis"
WIRESHARK_PLUGINS_DIR="$HOME/.local/lib/wireshark/plugins"
WIRESHARK_PROFILES_DIR="$HOME/.config/wireshark/profiles"
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

# Print functions
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}    Wireshark Vulnerability Correlator Plugin Installer (Linux)${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}\n"
}

print_step() {
    echo -e "${YELLOW}➤ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
        DISTRO_VERSION=$DISTRIB_RELEASE
    else
        DISTRO="unknown"
        DISTRO_VERSION="unknown"
    fi
    
    print_info "Detected Linux distribution: $DISTRO $DISTRO_VERSION"
}

# Check if running as root
check_not_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This installer should NOT be run as root/sudo"
        print_info "Run as your regular user: ./install_vulners_plugin_linux.sh"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."
    
    local missing_deps=()
    
    # Check if Wireshark is installed
    if ! command -v wireshark >/dev/null 2>&1; then
        # Check common installation locations
        local wireshark_found=false
        for path in "/usr/bin/wireshark" "/usr/local/bin/wireshark" "/opt/wireshark/bin/wireshark"; do
            if [[ -x "$path" ]]; then
                wireshark_found=true
                print_success "Wireshark found at: $path"
                break
            fi
        done
        
        if [[ "$wireshark_found" == "false" ]]; then
            missing_deps+=("Wireshark")
        fi
    else
        print_success "Wireshark command found in PATH"
    fi
    
    # Check for required commands
    for cmd in curl grep sed; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing prerequisites: ${missing_deps[*]}"
        echo
        print_info "Please install the missing components:"
        for dep in "${missing_deps[@]}"; do
            case $dep in
                "Wireshark")
                    case $DISTRO in
                        "ubuntu"|"debian")
                            echo "  • Install Wireshark: sudo apt update && sudo apt install wireshark"
                            ;;
                        "fedora"|"centos"|"rhel")
                            echo "  • Install Wireshark: sudo dnf install wireshark-qt (Fedora) or sudo yum install wireshark-qt (CentOS/RHEL)"
                            ;;
                        "arch")
                            echo "  • Install Wireshark: sudo pacman -S wireshark-qt"
                            ;;
                        "opensuse")
                            echo "  • Install Wireshark: sudo zypper install wireshark-ui-qt"
                            ;;
                        *)
                            echo "  • Install Wireshark using your distribution's package manager"
                            echo "    Or download from: https://www.wireshark.org/download.html"
                            ;;
                    esac
                    ;;
                *)
                    echo "  • Install $dep using your package manager"
                    ;;
            esac
        done
        exit 1
    fi
    
    print_success "All prerequisites satisfied"
}

# Create directories
create_directories() {
    print_step "Creating necessary directories..."
    
    # Create plugin directory
    if [[ ! -d "$WIRESHARK_PLUGINS_DIR" ]]; then
        mkdir -p "$WIRESHARK_PLUGINS_DIR"
        print_success "Created plugins directory: $WIRESHARK_PLUGINS_DIR"
    else
        print_success "Plugins directory exists: $WIRESHARK_PLUGINS_DIR"
    fi
    
    # Create profiles directory
    if [[ ! -d "$WIRESHARK_PROFILES_DIR" ]]; then
        mkdir -p "$WIRESHARK_PROFILES_DIR"
        print_success "Created profiles directory: $WIRESHARK_PROFILES_DIR"
    else
        print_success "Profiles directory exists: $WIRESHARK_PROFILES_DIR"
    fi
}

# Install plugin
install_plugin() {
    print_step "Installing Vulnerability Correlator plugin..."
    
    local source_plugin="$INSTALL_DIR/$PLUGIN_NAME"
    local target_plugin="$WIRESHARK_PLUGINS_DIR/$PLUGIN_NAME"
    
    if [[ ! -f "$source_plugin" ]]; then
        print_error "Plugin file not found: $source_plugin"
        print_info "Make sure $PLUGIN_NAME is in the same directory as this installer"
        exit 1
    fi
    
    # Backup existing plugin if it exists
    if [[ -f "$target_plugin" ]]; then
        local backup_file="${target_plugin}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$target_plugin" "$backup_file"
        print_info "Backed up existing plugin to: $backup_file"
    fi
    
    # Copy plugin
    cp "$source_plugin" "$target_plugin"
    chmod 644 "$target_plugin"
    print_success "Plugin installed: $target_plugin"
}

# Create Wireshark profile
create_profile() {
    print_step "Creating Wireshark profile: $PROFILE_NAME..."
    
    local profile_dir="$WIRESHARK_PROFILES_DIR/$PROFILE_NAME"
    
    # Create profile directory
    mkdir -p "$profile_dir"
    
    # Create preferences file with vulnerability columns
    cat > "$profile_dir/preferences" << 'EOF'
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
# Using a common monospace font available on most Linux systems
gui.qt.font_name: Monospace,10,-1,5,50,0,0,0,0,0

####### User Interface: Layout ########

# Layout content of the pane 3 (enable packet diagram)
gui.layout_content_3: PDIAGRAM

####### Name Resolution ########

# Resolve network (IP) addresses
name_resolve.network_name: TRUE

# Resolve transport names
name_resolve.transport_name: TRUE
EOF

    # Create colorfilters file with vulnerability highlighting
    cat > "$profile_dir/colorfilters" << 'EOF'
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
EOF

    # Create recent file with basic settings
    cat > "$profile_dir/recent" << 'EOF'
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
EOF

    print_success "Created Wireshark profile: $profile_dir"
}

# Verify installation
verify_installation() {
    print_step "Verifying installation..."
    
    # Check plugin file
    if [[ -f "$WIRESHARK_PLUGINS_DIR/$PLUGIN_NAME" ]]; then
        print_success "Plugin file verified: $WIRESHARK_PLUGINS_DIR/$PLUGIN_NAME"
    else
        print_error "Plugin file missing!"
        return 1
    fi
    
    # Check profile
    if [[ -d "$WIRESHARK_PROFILES_DIR/$PROFILE_NAME" ]]; then
        print_success "Profile verified: $WIRESHARK_PROFILES_DIR/$PROFILE_NAME"
    else
        print_error "Profile directory missing!"
        return 1
    fi
  # Check Lua syntax (compile only; don't execute)
   if command -v luac >/dev/null 2>&1; then
    if luac -p "$WIRESHARK_PLUGINS_DIR/$PLUGIN_NAME"; then
        print_success "Plugin Lua syntax verified"
    else
        print_error "Plugin has Lua syntax errors!"
        return 1
    fi
   elif command -v lua >/dev/null 2>&1; then
    # loadfile compiles without executing the script
    if lua -e 'local f,arg1=loadfile(...); if not f then os.exit(1) end' "$WIRESHARK_PLUGINS_DIR/$PLUGIN_NAME"; then
        print_success "Plugin Lua syntax verified"
    else
        print_error "Plugin has Lua syntax errors!"
        return 1
    fi
else
    print_info "Lua/luac not available for syntax checking (optional)"
fi
  
  
}

# Check user permissions for Wireshark
check_wireshark_permissions() {
    print_step "Checking Wireshark permissions..."
    
    # Check if user is in wireshark group (common requirement on Linux)
    if command -v wireshark >/dev/null 2>&1; then
        if groups | grep -q wireshark 2>/dev/null; then
            print_success "User is in wireshark group"
        else
            print_info "User may need to be added to wireshark group for packet capture"
            print_info "Run: sudo usermod -a -G wireshark \$USER"
            print_info "Then log out and back in for changes to take effect"
        fi
    fi
}

# Print usage instructions
print_usage() {
    print_step "Installation completed successfully!"
    echo
    print_info "Next steps:"
    echo "  1. Launch Wireshark"
    echo "  2. Go to: Edit → Configuration Profiles"
    echo "  3. Select the '$PROFILE_NAME' profile"
    echo "  4. Load a packet capture file"
    echo "  5. Use the Tools menu: Tools → Vulnerability Correlator"
    echo
    print_info "Important setup:"
    echo "  • Update the XML file path in the plugin if needed:"
    echo "    Edit: $WIRESHARK_PLUGINS_DIR/$PLUGIN_NAME"
    echo "    Look for: prefs.xml_path = \"/path/to/your/vulners_scan.xml\""
    echo
    print_info "Example display filters:"
    echo "  • vulners.cvss_high > 5        (CVSS score greater than 5)"
    echo "  • vulners.cvss_high >= 7.0     (High severity vulnerabilities)"
    echo "  • vulners.cve_id               (Show packets with CVE IDs)"
    echo "  • vulners.service_desc contains \"Apache\"  (Apache services only)"
    echo
    print_info "Troubleshooting:"
    echo "  • If you can't capture packets, add user to wireshark group:"
    echo "    sudo usermod -a -G wireshark \$USER"
    echo "  • Then log out and back in"
    echo
    print_info "Plugin location: $WIRESHARK_PLUGINS_DIR/$PLUGIN_NAME"
    print_info "Profile location: $WIRESHARK_PROFILES_DIR/$PROFILE_NAME"
    echo
    print_success "Happy vulnerability hunting! 🔍"
}

# Main installation process
main() {
    print_header
    
    detect_distro
    check_not_root
    check_prerequisites
    create_directories
    install_plugin
    create_profile
    verify_installation
    check_wireshark_permissions
    print_usage
}

# Run main function
main "$@"
