#!/usr/bin/env python3
"""
openvas_csv_to_xml.py

Parse an OpenVAS CSV export and produce a reduced XML:
- Per IP address
- Per service (port/protocol)
- Per CVE (with CVSS and short description taken from "NVT Name")

Rows without a port/protocol are skipped (not a service).
Rows without a CVE are skipped.

Usage:
  python openvas_csv_to_xml.py input.csv output.xml
"""

import argparse
import csv
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

def indent(elem, level=0):
    # Pretty-print XML for Python versions before ET.indent existed
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for child in elem:
            indent(child, level + 1)
        if not child.tail or not child.tail.strip():  # type: ignore[name-defined]
            child.tail = i
    if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = i

def norm(s):
    if s is None:
        return ""
    return " ".join(str(s).replace("\r", "").split())

def parse_cves(cve_field):
    # Split on commas and keep tokens that look like CVE ids
    if not cve_field:
        return []
    parts = [p.strip() for p in cve_field.split(",")]
    # Keep anything that starts with CVE- (OpenVAS sometimes includes ranges or extra text—keep conservative)
    cves = [p for p in parts if p.upper().startswith("CVE-")]
    # Dedup preserving order
    seen = set()
    out = []
    for c in cves:
        if c not in seen:
            out.append(c)
            seen.add(c)
    return out

def extract_service_info(row):
    """
    Extract service information from OpenVAS CSV row in nmap-style format.
    Attempts to create service banners similar to nmap's service detection.
    """
    nvt_name = norm(row.get("NVT Name", ""))
    specific_result = norm(row.get("Specific Result", ""))
    product_detection = norm(row.get("Product Detection Result", ""))
    affected_software = norm(row.get("Affected Software/OS", ""))
    port = norm(row.get("Port", ""))
    
    service_info = ""
    
    # Enhanced service detection with version extraction
    combined_text = f"{nvt_name} {specific_result} {product_detection} {affected_software}".lower()
    
    # ProFTPD detection with version inference
    if "proftpd" in combined_text:
        # ProFTPD mod_copy vulnerability is specific to version 1.3.5
        if "mod_copy" in combined_text or "cve-2015-3306" in combined_text:
            service_info = "ProFTPD 1.3.5 Server (mod_copy vulnerability)"
        else:
            service_info = "ProFTPD Server"
    
    # Apache HTTP Server detection
    elif "apache" in combined_text or ("http" in combined_text and port == "80"):
        # For Apache, we'll use a simple but reliable approach
        # Since OpenVAS vulnerability data doesn't typically contain precise version banners
        if "ubuntu" in combined_text:
            service_info = "Apache httpd (Ubuntu)"
        elif "debian" in combined_text:
            service_info = "Apache httpd (Debian)"
        elif "centos" in combined_text or "rhel" in combined_text:
            service_info = "Apache httpd (CentOS/RHEL)"
        else:
            service_info = "Apache httpd"
    
    # Drupal application detection (runs on Apache)
    elif "drupal" in combined_text:
        drupal_version = ""
        # Extract Drupal version
        version_match = re.search(r"drupal[^0-9]*([0-9]+(?:\.[0-9x]+)?)", combined_text)
        if version_match:
            drupal_version = version_match.group(1)
        elif "7.x" in combined_text or "7.32" in combined_text:
            drupal_version = "7.x"
        
        if "coder" in combined_text:
            if drupal_version:
                service_info = f"Drupal {drupal_version} (Coder module vulnerability)"
            else:
                service_info = "Drupal (Coder module vulnerability)"
        else:
            if drupal_version:
                service_info = f"Drupal {drupal_version} on Apache"
            else:
                service_info = "Drupal CMS on Apache"
    
    # SSH Server detection
    elif "ssh" in combined_text and port == "22":
        # SSH implementation detection without unreliable version extraction
        if "openssh" in combined_text:
            service_info = "OpenSSH"
        elif "dropbear" in combined_text:
            service_info = "Dropbear SSH"
        else:
            service_info = "SSH Server"
    
    # FTP Server detection (generic)
    elif "ftp" in combined_text and port == "21" and "proftpd" not in combined_text:
        if "vsftpd" in combined_text:
            version_match = re.search(r"vsftpd[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", combined_text)
            if version_match:
                service_info = f"vsftpd {version_match.group(1)}"
            else:
                service_info = "vsftpd"
        else:
            service_info = "FTP Server"
    
    # MySQL detection
    elif "mysql" in combined_text:
        version_match = re.search(r"mysql[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", combined_text)
        if version_match:
            service_info = f"MySQL {version_match.group(1)}"
        else:
            service_info = "MySQL Server"
    
    # jQuery (client-side library, but detected via web scans)
    elif "jquery" in combined_text:
        version_match = re.search(r"installed version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", combined_text)
        if not version_match:
            version_match = re.search(r"jquery[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", combined_text)
        
        if version_match:
            service_info = f"jQuery {version_match.group(1)} (JavaScript library)"
        else:
            service_info = "jQuery (JavaScript library)"
    
    # SSL/TLS Services
    elif "ssl" in combined_text or "tls" in combined_text:
        if port == "443":
            service_info = "HTTPS/SSL Server"
        elif port == "993":
            service_info = "IMAPS (SSL)"
        elif port == "995":
            service_info = "POP3S (SSL)"
        else:
            service_info = f"SSL/TLS Service on port {port}"
    
    # Extract from CPE identifiers if available
    if not service_info and product_detection:
        if "cpe:/a:" in product_detection:
            cpe_match = re.search(r"cpe:/a:([^:]+):([^:]+)(?::([^:]+))?", product_detection)
            if cpe_match:
                vendor = cpe_match.group(1).replace("_", " ").title()
                product = cpe_match.group(2).replace("_", " ").title()
                version = cpe_match.group(3) if cpe_match.group(3) else ""
                
                # Map common CPE products to nmap-style names
                if product.lower() == "http_server" and vendor.lower() == "apache":
                    service_info = f"Apache httpd {version}" if version else "Apache httpd"
                elif product.lower() == "proftpd":
                    service_info = f"ProFTPD {version} Server" if version else "ProFTPD Server"
                elif product.lower() == "openssh":
                    service_info = f"OpenSSH {version}" if version else "OpenSSH"
                else:
                    if version:
                        service_info = f"{product} {version}"
                    else:
                        service_info = f"{vendor} {product}"
    
    # Port-based fallback with nmap-style naming
    if not service_info and port:
        nmap_style_services = {
            "21": "FTP Server",
            "22": "SSH Server", 
            "23": "Telnet Server",
            "25": "SMTP Server",
            "53": "DNS Server",
            "80": "HTTP Server",
            "110": "POP3 Server",
            "143": "IMAP Server",
            "443": "HTTPS Server",
            "993": "IMAPS Server",
            "995": "POP3S Server",
            "3306": "MySQL Server",
            "5432": "PostgreSQL Server",
            "1433": "Microsoft SQL Server",
            "3389": "Microsoft RDP",
            "631": "CUPS/IPP Server",
            "1521": "Oracle Database",
            "5060": "SIP Server",
            "8080": "HTTP Proxy/Alternative",
            "8443": "HTTPS Alternative"
        }
        service_info = nmap_style_services.get(port, f"Unknown service on port {port}")
    
    return service_info

def main(inp, outp):
    # Data structure: hosts[ip][service_tuple] -> dict of cve -> payload
    # service_tuple = (port, protocol)
    hosts = defaultdict(lambda: defaultdict(dict))
    # Also track service information per host/port
    service_cache = defaultdict(dict)  # hosts[ip][(port, protocol)] -> service_info

    # Open with universal newline handling; DictReader will handle quoted multiline fields
    with open(inp, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter=",", quotechar='"', skipinitialspace=True)
        # Normalize header keys (strip BOMs / whitespace)
        # DictReader already maps by header; we'll tolerate exact names from OpenVAS
        for row in reader:
            ip = norm(row.get("IP"))
            port = norm(row.get("Port"))
            proto = norm(row.get("Port Protocol"))
            cvss = norm(row.get("CVSS"))
            nvt_name = norm(row.get("NVT Name"))  # short description/title
            cve_field = norm(row.get("CVEs"))

            # Skip entries that aren't tied to a service
            if not ip or not port or not proto:
                continue

            # Parse CVEs; if none found, generate synthetic identifier from NVT OID
            cves = parse_cves(cve_field)
            if not cves:
                # Generate synthetic CVE from NVT OID for vulnerabilities without official CVEs
                nvt_oid = norm(row.get("NVT OID", ""))
                if nvt_oid:
                    # Convert OID to a synthetic CVE-like identifier
                    # Format: NOVT-YYYY-NNNN where YYYY is extracted from OID and NNNN is sequential
                    oid_parts = nvt_oid.split('.')
                    if len(oid_parts) >= 9:  # Standard OpenVAS OID format
                        synthetic_id = f"NOVT-{oid_parts[-1]}"
                        cves = [synthetic_id]
                    else:
                        # Fallback: use a hash-based identifier
                        import hashlib
                        oid_hash = hashlib.md5(nvt_oid.encode()).hexdigest()[:8]
                        cves = [f"NOVT-{oid_hash}"]
                else:
                    # Skip if no OID available either
                    continue

            svc_key = (port, proto.lower())
            
            # Extract service information for this row
            service_info = extract_service_info(row)
            
            # Store service information (use the most detailed service info we find)
            if service_info and (svc_key not in service_cache[ip] or len(service_info) > len(service_cache[ip].get(svc_key, ""))):
                service_cache[ip][svc_key] = service_info

            for cve in cves:
                # Deduplicate per service per CVE
                if cve not in hosts[ip][svc_key]:
                    hosts[ip][svc_key][cve] = {
                        "cvss": cvss,
                        "title": nvt_name or "",  # fallback to empty if missing
                    }

    # Build XML
    root = ET.Element("report")
    for ip, services in sorted(hosts.items(), key=lambda x: x[0]):
        host_el = ET.SubElement(root, "host", attrib={"ip": ip})
        for (port, proto), vulns in sorted(
            services.items(),
            key=lambda x: (int(x[0][0]) if x[0][0].isdigit() else 65535, x[0][1]),
        ):
            # Create service element with service information if available
            svc_attribs = {"port": port, "protocol": proto}
            service_name = service_cache[ip].get((port, proto), "")
            if service_name:
                svc_attribs["name"] = service_name
            
            svc_el = ET.SubElement(host_el, "service", attrib=svc_attribs)
            # Sort CVEs numerically where possible
            def cve_sort_key(c):
                try:
                    parts = c.upper().split("-")
                    return (int(parts[1]), int(parts[2]))
                except Exception:
                    return (9999, 99999999)
            for cve in sorted(vulns.keys(), key=cve_sort_key):
                v = vulns[cve]
                vuln_el = ET.SubElement(svc_el, "vulnerability", attrib={"cve": cve})
                if v["cvss"]:
                    vuln_el.set("cvss", v["cvss"])
                title_el = ET.SubElement(vuln_el, "title")
                title_el.text = v["title"] or ""
                # If you also want a <description> from the long "Summary", swap the field above.

    indent(root)
    tree = ET.ElementTree(root)
    tree.write(outp, encoding="utf-8", xml_declaration=True)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Reduce OpenVAS CSV to IP→Service→CVE XML")
    ap.add_argument("input_csv", help="Path to OpenVAS CSV export")
    ap.add_argument("output_xml", help="Path to write XML output")
    args = ap.parse_args()
    try:
        main(args.input_csv, args.output_xml)
    except FileNotFoundError as e:
        print(f"File error: {e}", file=sys.stderr)
        sys.exit(1)
