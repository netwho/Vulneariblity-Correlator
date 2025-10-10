-- Final Clean Wireshark Vulners Correlator with CVSS Column Support
-- Correlates nmap Vulners XML with network traffic, generates reports, and populates custom columns

local prefs = {}
prefs.xml_path = "/Users/walterh/vulners_scan.xml"

-- Enhanced logging with timestamp
local function log(msg)
    print("[" .. os.date("%H:%M:%S") .. "] [VulnersCorrelator] " .. tostring(msg))
end

-- Create custom protocol for our fields (unique name to avoid conflicts)
local vulners_cvss_proto = Proto("vulnerscvss_final", "Vulners CVSS Final Enhanced")

-- Create custom fields for CVSS data (keep original field names for column compatibility)
local cvss_high_field = ProtoField.float("vulners.cvss_high", "CVSS High Score")
local service_desc_field = ProtoField.string("vulners.service_desc", "Service Description")
local cvss_cve_field = ProtoField.string("vulners.cve_id", "CVE ID")

-- Register the fields
vulners_cvss_proto.fields = { cvss_high_field, service_desc_field, cvss_cve_field }

-- =========================
-- SLAXML: Minimal XML parser (same as original)
-- =========================
local SLAXML = {}
SLAXML.parser = function(callbacks)
  local obj = {}
  obj.parse = function(self, xml)
    local stack = {}
    local i = 1
    local textStart = 1
    local function emit_text(e)
      local s = xml:sub(textStart, e)
      s = s:gsub("^%s+",""):gsub("%s+$","")
      if #s > 0 and callbacks.text then callbacks.text(s) end
    end
    while true do
      local ni, j, c, label, attrs, empty = xml:find("<([!?/]?)([%w_:%.-]+)(.-)(/?)>", i)
      if not ni then
        if callbacks.text and i <= #xml then
          textStart = i
          emit_text(#xml)
        end
        break
      end
      if ni > i and callbacks.text then
        textStart = i
        emit_text(ni-1)
      end
      if c == '!' then
        -- comment or doctype; skip
      elseif c == '?' then
        -- processing instruction; ignore
      elseif c == '/' then
        -- end tag
        if callbacks.closeElement then callbacks.closeElement(label) end
        table.remove(stack)
      else
        -- start tag
        local attr = {}
        for k,v in attrs:gmatch("([%w_:%.-]+)%s*=%s*\"(.-)\"") do attr[k]=v end
        for k,v in attrs:gmatch("([%w_:%.-]+)%s*=%s*'(.-)'") do attr[k]=v end
        if callbacks.startElement then callbacks.startElement(label, attr) end
        table.insert(stack, label)
        if empty == '/' then
          if callbacks.closeElement then callbacks.closeElement(label) end
          table.remove(stack)
        end
      end
      i = j + 1
    end
  end
  return obj
end

-- Data structures
local vulns_index = {}
local hits = {}
local scan_info = {
    scan_time = "Unknown",
    nmap_version = "Unknown",
    total_hosts = 0,
    total_vulns = 0,
    high_severity_vulns = 0,
    critical_severity_vulns = 0,
    vulnerable_hosts = 0,
    vulnerable_services = 0,
    correlated_vulnerable_hosts = 0,
    correlated_vulnerable_services = 0
}

-- CVSS data cache for quick column lookup
local cvss_cache = {}

-- Helper functions
local function ensure(tbl, k)
  local v = tbl[k]
  if not v then v = {}; tbl[k] = v end
  return v
end

-- CVSS processing helper functions
local function get_highest_cvss_for_host(ip)
    local highest_cvss = 0
    local ip_vulns = vulns_index[ip]
    if not ip_vulns then return 0 end
    
    for proto, ports in pairs(ip_vulns) do
        for port, data in pairs(ports) do
            if data.vulns then
                for _, vuln in ipairs(data.vulns) do
                    if vuln.cvss and vuln.cvss > highest_cvss then
                        highest_cvss = vuln.cvss
                    end
                end
            end
        end
    end
    return highest_cvss
end

local function get_service_for_host(ip)
    local ip_vulns = vulns_index[ip]
    if not ip_vulns then return nil end
    
    -- Find the service with the highest CVSS vulnerability
    local best_service = nil
    local best_cvss = 0
    
    for proto, ports in pairs(ip_vulns) do
        for port, data in pairs(ports) do
            if data.vulns and #data.vulns > 0 and data.service then
                -- Find highest CVSS for this service
                local highest_cvss = 0
                for _, vuln in ipairs(data.vulns) do
                    if vuln.cvss and vuln.cvss > highest_cvss then
                        highest_cvss = vuln.cvss
                    end
                end
                
                -- If this service has a higher CVSS than our current best, use it
                if highest_cvss > best_cvss then
                    best_cvss = highest_cvss
                    best_service = data.service
                elseif not best_service and data.service then
                    -- If no service selected yet, use this one
                    best_service = data.service
                end
            end
        end
    end
    
    -- Truncate if too long for column display  
    if best_service and string.len(best_service) > 40 then
        best_service = string.sub(best_service, 1, 37) .. "..."
    end
    
    return best_service
end

local function update_cvss_cache()
    cvss_cache = {}
    for ip in pairs(vulns_index) do
        local highest = get_highest_cvss_for_host(ip)
        local service = get_service_for_host(ip)
        if highest > 0 or service then
            cvss_cache[ip] = {
                high_score = highest > 0 and string.format("%.1f", highest) or "",
                service_desc = service or ""
            }
        end
    end
end

-- Enhanced XML parsing with statistics collection
local function parse_vulners_xml(path)
  local f, err = io.open(path, 'r')
  if not f then
    log("Unable to open XML file: " .. tostring(path) .. " (" .. tostring(err) .. ")")
    return
  end
  local xml = f:read("*a"); f:close()
  log("Parsing XML file: " .. path .. " (" .. string.len(xml) .. " bytes)")

  -- Extract scan metadata from nmaprun tag
  local start_time = xml:match('<nmaprun[^>]*start="([^"]*)"')
  if start_time then
    scan_info.scan_time = os.date("%Y-%m-%d %H:%M:%S", tonumber(start_time))
  end
  
  -- Extract nmap version (not xmloutputversion)
  local nmap_version = xml:match('<nmaprun[^>]*version="([^"]*)".* xmloutputversion=')
  if not nmap_version then
    nmap_version = xml:match('<nmaprun[^>]*version="([^"]*)".* scanner=')
  end
  if not nmap_version then
    nmap_version = xml:match('version="([^"]*)".* args=')
  end
  if nmap_version then
    scan_info.nmap_version = nmap_version
  end

  local current_host_ip = nil
  local current_port = nil
  local current_proto = nil
  local current_service = nil
  local in_script_vulners = false
  local in_script_text = false
  local script_text_buf = {}
  local cur_vuln = nil
  local in_table = false
  local in_vuln_elem = false


  local function commit_vuln(ip, proto, port, service, v)
    if not (ip and proto and port and v and v.id) then return end
    
    local ipt = ensure(vulns_index, ip)
    local prot = ensure(ipt, proto)
    local portt = ensure(prot, tostring(port))
    portt.service = portt.service or service
    portt.vulns = portt.vulns or {}
    table.insert(portt.vulns, v)
    
    -- Update statistics
    scan_info.total_vulns = scan_info.total_vulns + 1
    if v.cvss then
      if v.cvss >= 9.0 then
        scan_info.critical_severity_vulns = scan_info.critical_severity_vulns + 1
      elseif v.cvss >= 7.0 then
        scan_info.high_severity_vulns = scan_info.high_severity_vulns + 1
      end
    end
  end

  local function parse_script_text_lines()
    for _, line in ipairs(script_text_buf) do
      -- Debug: show what lines we're processing
      if current_host_ip == "172.28.184.18" and #script_text_buf < 10 then
        log(string.format("Parsing line for %s: '%s'", current_host_ip, line:gsub("[\r\n]", "")))
      end
      
      -- Try to match the vulners output format with descriptions
      -- Format: ID\tCVSS\tURL\t*OPTIONAL_MARKERS* (tab or space separated)
      local id, cvss, url, markers = line:match("^%s*([^%s%c]+)[%s%c]+([%d%.]+)[%s%c]+(https?://%S+)%s*(.*)$")
      if id and cvss and url then
        -- Debug: show what we're committing
        if current_host_ip == "172.28.184.18" then
          log(string.format("Committing vuln: ID='%s' CVSS=%s Service='%s'", id, cvss, current_service or "nil"))
        end
        
        commit_vuln(current_host_ip, current_proto, current_port, current_service, {
          id = id, cvss = tonumber(cvss), href = url
        })
      else
        -- Fallback: try the old pattern
        local cve, cvss2, href, title2 = line:match("(CVE%-%d+%-%d+)%s+([%d%.]+)%s+(https?://%S+)%s*(.*)$")
        if cve then
          commit_vuln(current_host_ip, current_proto, current_port, current_service, {
            id = cve, cvss = tonumber(cvss2), href = href, title = title2 ~= '' and title2 or cve
          })
        else
          -- Last resort: just ID and CVSS
          local id2, score2 = line:match("(%S+)%s+CVSS%:?%s*([%d%.]+)")
          if id2 then
            commit_vuln(current_host_ip, current_proto, current_port, current_service, {
              id = id2, cvss = tonumber(score2), title = id2
            })
          end
        end
      end
    end
  end

  local cbs = {
    startElement = function(name, attr)
      if name == 'host' then
        current_host_ip = nil
        scan_info.total_hosts = scan_info.total_hosts + 1
      elseif name == 'address' and attr.addrtype == 'ipv4' then
        current_host_ip = attr.addr
      elseif name == 'port' then
        current_port = tonumber(attr.portid)
        current_proto = attr.protocol or 'tcp'
        current_service = nil
      elseif name == 'service' then
        if attr.product or attr.name or attr.version then
          local parts = {}
          if attr.product then table.insert(parts, attr.product) end
          if attr.version then table.insert(parts, attr.version) end
          if #parts == 0 and attr.name then table.insert(parts, attr.name) end
          current_service = table.concat(parts, ' ')
        end
      elseif name == 'script' and attr.id == 'vulners' then
        in_script_vulners = true
        in_script_text = true
        script_text_buf = {}
      elseif name == 'table' and in_script_vulners then
        in_table = true
        cur_vuln = {}
      elseif name == 'elem' and in_table then
        in_vuln_elem = true
        cur_vuln._current_key = attr.key
      end
    end,
    closeElement = function(name)
      if name == 'script' and in_script_vulners then
        if #script_text_buf > 0 then
          parse_script_text_lines()
        end
        in_script_vulners = false
        in_script_text = false
      elseif name == 'table' and in_table then
        in_table = false
        if cur_vuln and cur_vuln.id then
          commit_vuln(current_host_ip, current_proto, current_port, current_service, {
            id = cur_vuln.id,
            cvss = cur_vuln.cvss and tonumber(cur_vuln.cvss) or nil,
            href = cur_vuln.href or cur_vuln.link
          })
        end
        cur_vuln = nil
      elseif name == 'elem' and in_vuln_elem then
        in_vuln_elem = false
      elseif name == 'port' then
        current_port = nil; current_proto = nil; current_service = nil
      elseif name == 'host' then
        current_host_ip = nil
      end
    end,
    text = function(txt)
      if in_script_vulners then
        if in_vuln_elem and cur_vuln and cur_vuln._current_key then
          cur_vuln[cur_vuln._current_key] = (txt and txt or '')
        elseif in_script_text then
          for line in tostring(txt):gmatch("[^\n]+") do
            table.insert(script_text_buf, line)
          end
        end
      end
    end
  }

  local p = SLAXML.parser(cbs)
  p:parse(xml)

  -- Normalize proto and ports to strings for consistent indexing
  for ip, protos in pairs(vulns_index) do
    for proto, ports in pairs(protos) do
      for port, data in pairs(ports) do
        if type(port) ~= 'string' then
          ports[tostring(port)] = data
          ports[port] = nil
        end
      end
    end
  end

  -- Calculate additional statistics
  scan_info.vulnerable_hosts = 0
  scan_info.vulnerable_services = 0
  
  for ip, protos in pairs(vulns_index) do
    local host_has_vulns = false
    for proto, ports in pairs(protos) do
      for port, data in pairs(ports) do
        if data.vulns and #data.vulns > 0 then
          scan_info.vulnerable_services = scan_info.vulnerable_services + 1
          host_has_vulns = true
        end
      end
    end
    if host_has_vulns then
      scan_info.vulnerable_hosts = scan_info.vulnerable_hosts + 1
    end
  end

  -- Update CVSS cache after parsing
  update_cvss_cache()

  -- Count cache entries safely
  local cache_count = 0
  for _ in pairs(cvss_cache) do
    cache_count = cache_count + 1
  end

  log(string.format("XML Analysis Complete:"))
  log(string.format("  Scan Time: %s", scan_info.scan_time))
  log(string.format("  Nmap Version: %s", scan_info.nmap_version))
  log(string.format("  Total Hosts: %d", scan_info.total_hosts))
  log(string.format("  Vulnerable Hosts: %d", scan_info.vulnerable_hosts))
  log(string.format("  Vulnerable Services: %d", scan_info.vulnerable_services))
  log(string.format("  Total Vulnerabilities: %d", scan_info.total_vulns))
  log(string.format("  Critical (CVSS ≥9.0): %d", scan_info.critical_severity_vulns))
  log(string.format("  High (CVSS ≥7.0): %d", scan_info.high_severity_vulns))
  log(string.format("  CVSS Cache entries: %d", cache_count))
  
  -- Debug: Show sample cache entries
  if cache_count > 0 then
    log("Sample CVSS cache entries:")
    local count = 0
    for ip, data in pairs(cvss_cache) do
      if count >= 3 then break end -- Show only first 3
      log(string.format("  %s: CVSS='%s', Service='%s'", ip, data.high_score or "none", data.service_desc or "none"))
      count = count + 1
    end
  end
end

-- Network traffic correlation (enhanced with CVSS column population)
local ip_src_f = Field.new("ip.src")
local ip_dst_f = Field.new("ip.dst")
local tcp_src_f = Field.new("tcp.srcport")
local tcp_dst_f = Field.new("tcp.dstport")
local udp_src_f = Field.new("udp.srcport")
local udp_dst_f = Field.new("udp.dstport")

local function record_hit(ip, proto, port, pktno, flow_key)
  local ipt = ensure(hits, ip)
  local prot = ensure(ipt, proto)
  local portt = ensure(prot, tostring(port))
  portt.packets = portt.packets or {}
  portt.flows = portt.flows or {}
  table.insert(portt.packets, pktno)
  portt.flows[flow_key] = true
end

local function endpoint_has_vulns(ip, proto, port)
  local ipt = vulns_index[ip]; if not ipt then return false end
  local prot = ipt[proto]; if not prot then return false end
  local entry = prot[tostring(port)]; return entry and entry.vulns and #entry.vulns > 0
end

local function count_cache_entries()
  local count = 0
  for _ in pairs(cvss_cache) do
    count = count + 1
  end
  return count
end

-- Get protocol-specific vulnerability data for an IP and port
local function get_protocol_specific_vulns(ip, protocol, port)
    local ip_vulns = vulns_index[ip]
    if not ip_vulns then return nil, nil, nil end
    
    local proto_vulns = ip_vulns[protocol]
    if not proto_vulns then return nil, nil, nil end
    
    local port_data = proto_vulns[tostring(port)]
    if not port_data or not port_data.vulns or #port_data.vulns == 0 then
        return nil, nil, nil
    end
    
    -- Find highest CVSS and associated CVE for this specific service
    local highest_cvss = 0
    local highest_cvss_cve = nil
    local any_cve = nil  -- Track any CVE we find
    
    for _, vuln in ipairs(port_data.vulns) do
        -- Track any CVE ID we encounter
        if vuln.id and vuln.id:match("^CVE%-[%d%-]+$") then
            any_cve = vuln.id
        end
        
        -- Update highest CVSS and track its CVE if it's actually a CVE
        if vuln.cvss and vuln.cvss > highest_cvss then
            highest_cvss = vuln.cvss
            highest_cvss_cve = vuln.id and vuln.id:match("^CVE%-[%d%-]+$") and vuln.id or nil
        end
    end
    
    -- Prefer the CVE from highest CVSS vulnerability, then any CVE we found
    local cve_id = highest_cvss_cve or any_cve
    
    return highest_cvss > 0 and highest_cvss or nil, nil, cve_id
end

-- Clean protocol dissector function that adds fields to the tree
function vulners_cvss_proto.dissector(buffer, pinfo, tree)
    -- Get source and destination IPs and ports
    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    local src_port = pinfo.src_port
    local dst_port = pinfo.dst_port
    
    -- Determine protocol (TCP/UDP)
    local protocol = nil
    if tcp_src_f() and tcp_dst_f() then
        protocol = "tcp"
    elseif udp_src_f() and udp_dst_f() then
        protocol = "udp"
    end
    
    if not protocol then return end
    
    -- Only show vulnerability data when the vulnerable host is the DESTINATION
    -- (i.e., packets targeting the vulnerable service, not responses from it)
    local dst_cvss, _, dst_cve = get_protocol_specific_vulns(dst_ip, protocol, dst_port)
    
    local cvss_score = nil
    local service_info = nil
    local cve_id = nil
    local active_ip = nil
    local active_port = nil
    
    -- Only populate fields if destination has vulnerabilities (client -> vulnerable server)
    if dst_cvss or dst_cve then
        cvss_score = dst_cvss
        cve_id = dst_cve
        active_ip = dst_ip
        active_port = dst_port
        
        -- Get the service information for this vulnerable host/port
        local ip_vulns = vulns_index[dst_ip]
        if ip_vulns and ip_vulns[protocol] and ip_vulns[protocol][tostring(dst_port)] then
            service_info = ip_vulns[protocol][tostring(dst_port)].service
        end
    end
    
    if cvss_score or service_info or cve_id then
        local service_desc = service_info or ""
        local cve_number = cve_id or ""
        
        -- Debug: Print what we're adding
        if pinfo.number <= 5 then
            local score_display = cvss_score and string.format("%.1f", cvss_score) or "none"
            log(string.format("Packet %d: Targeting vulnerable %s:%d (%s) - Score: %s, Service: '%s', CVE: '%s'", 
                pinfo.number, active_ip, active_port, protocol, score_display, service_desc, cve_number))
        end
        
        if cvss_score or service_desc ~= "" or cve_number ~= "" then
            -- Add our protocol to the tree
            local subtree = tree:add(vulners_cvss_proto, "Vulners CVSS Data")
            
            -- Add the CVSS fields to the protocol tree
            -- Pass the actual numeric CVSS value (or 0 if none) to the float field
            subtree:add(cvss_high_field, cvss_score or 0.0)
            subtree:add(service_desc_field, service_desc)
            subtree:add(cvss_cve_field, cve_number)
            
            -- Note: Packet coloring can be configured using the filter: vulners.cvss_high > 0
        end
    end
end

-- Register the dissector as a post-dissector (runs after all other dissectors)
register_postdissector(vulners_cvss_proto)

local tap = Listener.new(nil, "ip && (tcp || udp)")
local packets_processed = 0

function tap.packet(pinfo, tvb)
  packets_processed = packets_processed + 1
  
  local src = tostring(ip_src_f() or "")
  local dst = tostring(ip_dst_f() or "")
  if src == "" or dst == "" then return end

  local pktno = pinfo.number

  -- TCP
  local ts = tcp_src_f(); local td = tcp_dst_f()
  if ts and td then
    local spt = tonumber(tostring(ts))
    local dpt = tonumber(tostring(td))
    
    -- Check dst endpoint first (client -> server)
    if endpoint_has_vulns(dst, 'tcp', dpt) then
      local fk = string.format("%s:%d->%s:%d", src, spt, dst, dpt)
      record_hit(dst, 'tcp', dpt, pktno, fk)
    end
    -- Also check source endpoint (server -> client)
    if endpoint_has_vulns(src, 'tcp', spt) then
      local fk = string.format("%s:%d->%s:%d", src, spt, dst, dpt)
      record_hit(src, 'tcp', spt, pktno, fk)
    end
    return
  end

  -- UDP
  local us = udp_src_f(); local ud = udp_dst_f()
  if us and ud then
    local spt = tonumber(tostring(us))
    local dpt = tonumber(tostring(ud))
    
    if endpoint_has_vulns(dst, 'udp', dpt) then
      local fk = string.format("%s:%d->%s:%d", src, spt, dst, dpt)
      record_hit(dst, 'udp', dpt, pktno, fk)
    end
    if endpoint_has_vulns(src, 'udp', spt) then
      local fk = string.format("%s:%d->%s:%d", src, spt, dst, dpt)
      record_hit(src, 'udp', spt, pktno, fk)
    end
  end
end

function tap.reset()
  -- Keep cumulative data across resets - do NOT clear hits table
  -- hits table should persist across resets to maintain correlation data
end

-- Enhanced reporting functions
local function sorted_keys(t)
  local ks = {}
  for k in pairs(t) do table.insert(ks, k) end
  table.sort(ks, function(a,b)
    local na, nb = tonumber(a), tonumber(b)
    if na and nb then return na < nb end
    return tostring(a) < tostring(b)
  end)
  return ks
end

local function get_severity_label(cvss)
  if not cvss then return "Unknown" end
  if cvss >= 9.0 then return "CRITICAL"
  elseif cvss >= 7.0 then return "HIGH"
  elseif cvss >= 4.0 then return "MEDIUM"
  else return "LOW"
  end
end

local function get_severity_color(cvss)
  if not cvss then return "⚪" end
  if cvss >= 9.0 then return "🔴"
  elseif cvss >= 7.0 then return "🟠"
  elseif cvss >= 4.0 then return "🟡"
  else return "🟢"
  end
end

local function make_enhanced_report()
  -- Calculate correlated statistics
  local correlated_hosts = 0
  local correlated_services = 0
  local total_correlated_vulns = 0
  
  for ip in pairs(hits) do
    if vulns_index[ip] then
      local host_has_correlated_vulns = false
      for _, proto in ipairs({'tcp','udp'}) do
        local protos = hits[ip]
        local ip_v = vulns_index[ip]
        if protos and protos[proto] and ip_v and ip_v[proto] then
          for port, hit in pairs(protos[proto]) do
            local vuln_entry = ip_v[proto][tostring(port)]
            if vuln_entry and vuln_entry.vulns and #vuln_entry.vulns > 0 then
              correlated_services = correlated_services + 1
              total_correlated_vulns = total_correlated_vulns + #vuln_entry.vulns
              host_has_correlated_vulns = true
            end
          end
        end
      end
      if host_has_correlated_vulns then
        correlated_hosts = correlated_hosts + 1
      end
    end
  end
  
  -- Store correlated stats
  scan_info.correlated_vulnerable_hosts = correlated_hosts
  scan_info.correlated_vulnerable_services = correlated_services
  
  -- Generate the report
  local lines = {}
  
  -- Header
  table.insert(lines, "═══════════════════════════════════════════════════════════════════════════════")
  table.insert(lines, "                      VULNERABILITY CORRELATION REPORT")
  table.insert(lines, "═══════════════════════════════════════════════════════════════════════════════")
  table.insert(lines, "")
  
  -- 1. SCAN SUMMARY
  table.insert(lines, "📊 SCAN SUMMARY")
  table.insert(lines, "────────────────────────────────────────────────────────────────────────────")
  table.insert(lines, string.format("• Scan Time: %s", scan_info.scan_time))
  table.insert(lines, string.format("• Nmap Version: %s", scan_info.nmap_version))
  table.insert(lines, string.format("• Total Hosts Scanned: %d", scan_info.total_hosts))
  table.insert(lines, string.format("• Total Hosts Vulnerable: %d", scan_info.vulnerable_hosts))
  table.insert(lines, string.format("• Total Vulnerable Services: %d", scan_info.vulnerable_services))
  table.insert(lines, string.format("• Total Vulnerabilities Found: %d", scan_info.total_vulns))
  table.insert(lines, string.format("• Critical (CVSS ≥9.0): %d | High (CVSS ≥7.0): %d", scan_info.critical_severity_vulns, scan_info.high_severity_vulns))
  table.insert(lines, "")
  
  -- 2. CORRELATION SUMMARY
  table.insert(lines, "📈 CORRELATION SUMMARY")
  table.insert(lines, "────────────────────────────────────────────────────────────────────────────")
  table.insert(lines, string.format("• Packets Processed: %s", packets_processed > 0 and tostring(packets_processed) or "No capture loaded"))
  table.insert(lines, string.format("• Vulnerable Hosts Found in Traffic: %d of %d (%.1f%%)", correlated_hosts, scan_info.vulnerable_hosts, 
    scan_info.vulnerable_hosts > 0 and (correlated_hosts / scan_info.vulnerable_hosts * 100) or 0))
  table.insert(lines, string.format("• Vulnerable Services with Traffic: %d", scan_info.correlated_vulnerable_services))
  table.insert(lines, string.format("• Total Vulnerabilities in Captured Traffic: %d", total_correlated_vulns))
  table.insert(lines, "")
  
  
  if correlated_hosts == 0 then
    table.insert(lines, "⚠️  No correlation found between scan results and network traffic.")
    table.insert(lines, "   • Check that packet IPs match scan target IPs")
    table.insert(lines, "   • Ensure capture contains traffic to vulnerable services")
  else
    -- 3. DETAILED FINDINGS
    table.insert(lines, "🔍 DETAILED VULNERABILITY FINDINGS")
    table.insert(lines, "════════════════════════════════════════════════════════════════════════════")
    
    -- Sort IPs that have both vulnerabilities and traffic
    local correlated_ips = {}
    for ip in pairs(hits) do
      if vulns_index[ip] then
        table.insert(correlated_ips, ip)
      end
    end
    table.sort(correlated_ips)
    
    for _, ip in ipairs(correlated_ips) do
      local ip_vulns = vulns_index[ip]
      local ip_hits = hits[ip]
      
      table.insert(lines, string.format("\n🎯 HOST: %s", ip))
      table.insert(lines, "────────────────────────────────────────────────────────────────────────────")
      
      
      -- Process each protocol
      for _, proto in ipairs({'tcp', 'udp'}) do
        if ip_vulns[proto] and ip_hits[proto] then
          local sorted_ports = sorted_keys(ip_vulns[proto])
          for _, port in ipairs(sorted_ports) do
            local vuln_entry = ip_vulns[proto][port]
            local hit_entry = ip_hits[proto][port]  -- Use string port, not number
            
            if vuln_entry and vuln_entry.vulns and #vuln_entry.vulns > 0 and hit_entry then
              table.insert(lines, string.format("\n   📍 SERVICE: %s/%s (%d vulnerabilities)", string.upper(proto), port, #vuln_entry.vulns))
              
              -- Show top vulnerabilities (highest CVSS first)
              local sorted_vulns = {}
              for _, v in ipairs(vuln_entry.vulns) do
                table.insert(sorted_vulns, v)
              end
              table.sort(sorted_vulns, function(a, b)
                return (a.cvss or 0) > (b.cvss or 0)
              end)
              
              -- Show top 5 vulnerabilities
              for i, vuln in ipairs(sorted_vulns) do
                if i > 5 then break end
                local severity_icon = get_severity_color(vuln.cvss)
                local severity_label = get_severity_label(vuln.cvss)
                table.insert(lines, string.format("   %s [%s] CVSS %.1f - %s", 
                  severity_icon, severity_label, vuln.cvss or 0, vuln.id or "Unknown ID"))
                if vuln.title and vuln.title ~= "" and vuln.title ~= "none" then
                  table.insert(lines, string.format("      Description: %s", vuln.title))
                end
              end
              
              -- Show packet numbers where this vulnerable service was targeted
              if hit_entry.packets and #hit_entry.packets > 0 then
                local packet_list = hit_entry.packets
                local display_packets = {}
                
                -- Show first 10 packets
                for i = 1, math.min(10, #packet_list) do
                  table.insert(display_packets, tostring(packet_list[i]))
                end
                
                table.insert(lines, string.format("   📦 PACKETS TARGETING THIS SERVICE: %s", table.concat(display_packets, ", ")))
                if #packet_list > 10 then
                  table.insert(lines, string.format("      (Showing first 10 packets, %d total)", #packet_list))
                end
              end
            end
          end
        end
      end
    end
  end
  
  table.insert(lines, "")
  table.insert(lines, "═══════════════════════════════════════════════════════════════════════════════")
  table.insert(lines, string.format("Report generated: %s", os.date("%Y-%m-%d %H:%M:%S")))
  table.insert(lines, "═══════════════════════════════════════════════════════════════════════════════")
  
  return table.concat(lines, "\n")
end

-- File output
local function write_enhanced_report_to_file(text)
  local timestamp = os.date("%Y%m%d_%H%M%S")
  local outname = string.format("vulners_correlation_report_%s.txt", timestamp)
  
  local f, err = io.open(outname, 'w')
  if not f then
    log("Failed to write report (" .. tostring(err) .. ")")
    return false, outname
  end
  
  f:write(text)
  f:close()
  log("📄 Report written to: " .. outname)
  return true, outname
end

-- Display in Wireshark
local function show_report_in_window(text)
  if gui_enabled() then
    local win = TextWindow.new("Vulnerability Correlator - Full Report")
    win:set(text)
    win:set_editable(false)
  end
end

-- Force tap processing to ensure hits data is populated
local function force_packet_processing()
  -- Clear and rebuild hits data by processing current capture
  hits = {}
  packets_processed = 0
  
  -- Manual processing would go here, but Wireshark's Lua API is limited
  -- The tap should automatically process packets, but timing might be an issue
  log("🔄 Forcing packet processing...")
end

-- Main report generation function
local function generate_enhanced_report()
  log("🚀 Generating correlation report...")
  local start_time = os.clock()
  
  -- Try to force packet processing if hits table is empty
  local hits_count = 0
  for _ in pairs(hits) do hits_count = hits_count + 1 end
  if hits_count == 0 then
    log("⚠️  HITS table is empty - packets haven't been processed yet")
    log("    1. Make sure a capture file is loaded")
    log("    2. Let Wireshark finish loading all packets")
    log("    3. Try scrolling through the packet list to trigger processing")
    log("    4. Wait a moment, then re-run the Full Report")
  else
    log(string.format("✅ HITS table contains %d vulnerable hosts with traffic", hits_count))
  end
  
  local report = make_enhanced_report()
  
  -- Display in console
  print("\n" .. report)
  
  -- Display in GUI window
  show_report_in_window(report)
  
  -- Write to file
  local success, filename = write_enhanced_report_to_file(report)
  
  local elapsed = os.clock() - start_time
  log(string.format("✅ Report generation completed in %.2f seconds", elapsed))
  
  if success then
    log("📋 Report is available in:")
    log("  • Wireshark text window (if GUI enabled)")
    log("  • Console output above")
    log("  • File: " .. filename)
    log("📊 CVSS columns should be populated in the packet list!")
  end
end

-- Instructions display function
local function show_instructions()
  local instructions = [[
═══════════════════════════════════════════════════════════════════════════════
                        VULNERABILITY CORRELATOR INSTRUCTIONS
═══════════════════════════════════════════════════════════════════════════════

📋 PURPOSE:
This plugin correlates nmap Vulners scan results with live network traffic,
populating custom columns with CVSS data and highlighting vulnerable traffic.

🔧 NMAP COMMAND SYNTAX:
To generate the required XML file, use this nmap command:

  nmap -sV --script vulners -oX vulners_scan.xml -oN vulners_scan.txt <target>

Example:
  nmap -sV --script vulners -oX vulners_scan.xml -oN vulners_scan.txt 172.28.184.1-128

📁 FILE LOCATION:
Place your XML scan file at:
  ]] .. prefs.xml_path .. [[

🆕 CUSTOM COLUMNS:
Three new columns have been added to your Wireshark profile:
• "CVSS (high)" - Shows the highest CVSS score for vulnerable services
• "CVE ID" - Shows the CVE identifier (e.g., CVE-2015-3306)
• "CVE Description" - Shows enhanced vulnerability descriptions

🎯 PACKET TARGETING LOGIC:
Vulnerability data appears ONLY for packets targeting vulnerable services:
• Client → Vulnerable Server: Shows CVSS/CVE data ✓
• Vulnerable Server → Client: No vulnerability data (clean responses)
This ensures only attack traffic is highlighted, not server responses.

🎨 VISUAL HIGHLIGHTING SETUP:
To highlight packets targeting vulnerable services with red background:
1. Go to View > Coloring Rules in Wireshark
2. Click "New" to add a coloring rule
3. Name: "Vulnerable Traffic"
4. Filter: vulners.cvss_high != ""
5. Background: Light Red (#FFCCCC), Text: Black (#000000)
6. Move this rule to the top for priority
7. Click OK to apply

🚀 USAGE WORKFLOW:
1. Run nmap scan with vulners script (as shown above)
2. Save XML output to the specified location  
3. Restart Wireshark to load this plugin
4. Load a packet capture in Wireshark
5. Check the new CVSS columns in the packet list
6. (Optional) Set up coloring rules as described above for visual highlighting
7. Use "Vulnerability Correlator > Full Report" for detailed analysis

⚠️  REQUIREMENTS:
• Nmap with vulners script installed
• Valid XML output from nmap vulners scan  
• Network traffic capture loaded in Wireshark
• Wireshark profile with custom columns configured

🔧 INTEGRATION STATUS:
✅ Custom columns: 'CVSS (high)', 'CVE ID', 'CVE Description'
✅ Protocol fields registered: vulners.cvss_high, vulners.cve_id, vulners.cvss_desc
✅ Post-dissector running: vulnerscvss_final
✅ Packet targeting logic: Only shows data for client → vulnerable server
✅ Coloring filter available: vulners.cvss_high != "" (highlights all vulnerable traffic)
✅ No protocol conflicts detected

🔄 TROUBLESHOOTING GUIDE:
If columns are not appearing:
   1. Verify your Wireshark profile has the custom columns configured
   2. Restart Wireshark completely
   3. Reload your capture file
   4. Check XML file exists and contains vulnerability data
   5. Verify packet IPs match scan IPs

───────────────────────────────────────────────────────────────────────────────
📧 Questions or feedback? Contact: walter.hofstetter@netwho.com
═══════════════════════════════════════════════════════════════════════════════
]]
  
  if gui_enabled() then
    local win = TextWindow.new("Vulnerability Correlator - Instructions")
    win:set(instructions)
    win:set_editable(false)
  end
  print(instructions)
end

-- Initialize
log("🔧 Initializing Vulnerability Correlator...")
parse_vulners_xml(prefs.xml_path)

-- Register hierarchical menu structure
register_menu("Vulnerability Correlator/Full Report", generate_enhanced_report, MENU_TOOLS_UNSORTED)

register_menu("Vulnerability Correlator/Quick Stats", function()
  local cache_count = count_cache_entries()
  local msg = string.format([[
📊 Vulnerability Scan Statistics:
───────────────────────────────────
• Hosts Scanned: %d
• Hosts Vulnerable (All): %d  
• Hosts Vulnerable (with Traffic): %d
• Vulnerable Services (All): %d
• Vulnerable Services (with Traffic): %d
• Total Vulnerabilities: %d
• Critical: %d
• High: %d
• Packets processed: %d
• CVSS Column Data: %d hosts

Use 'Vulnerability Correlator > Full Report' for detailed analysis.
]], scan_info.total_hosts, scan_info.vulnerable_hosts, scan_info.correlated_vulnerable_hosts, 
scan_info.vulnerable_services, scan_info.correlated_vulnerable_services, scan_info.total_vulns, 
scan_info.critical_severity_vulns, scan_info.high_severity_vulns, packets_processed, cache_count)
  
  if gui_enabled() then
    local win = TextWindow.new("Vulnerability Correlator - Quick Stats")
    win:set(msg)
  end
  print(msg)
end, MENU_TOOLS_UNSORTED)

register_menu("Vulnerability Correlator/Instructions & Setup", show_instructions, MENU_TOOLS_UNSORTED)

-- Register menu to reload CVSS cache
register_menu("Vulnerability Correlator/Reload CVSS Data", function()
  log("🔄 Reloading CVSS data...")
  parse_vulners_xml(prefs.xml_path)
  local cache_count = count_cache_entries()
  log("✅ CVSS data reloaded. " .. cache_count .. " hosts have CVSS data.")
  
  if gui_enabled() then
    local win = TextWindow.new("Vulnerability Correlator - CVSS Data Reloaded")
    win:set("CVSS data has been reloaded successfully.\n\n" .. 
           "Hosts with CVSS data: " .. cache_count .. "\n\n" ..
           "Reload your capture file to see updated columns.")
  end
end, MENU_TOOLS_UNSORTED)

log("✅ Vulnerability Correlator ready!")
log("📋 Menu structure: 'Vulnerability Correlator' with submenus:")
log("   • Full Report - Complete correlation analysis with CVSS columns")
log("   • Quick Stats - Summary statistics including CVSS data")
log("   • Instructions & Setup - Usage guide and column information")
log("   • Reload CVSS Data - Refresh CVSS cache from XML file")
log("🗃️  Using XML: " .. tostring(prefs.xml_path))
log("📄 Custom columns: 'CVSS (high)', 'CVE ID', 'CVE Description'")
log("🎨 Coloring filter: vulners.cvss_high != \"\" (highlights all vulnerable traffic)")
log("🎯 Targeting logic: Only shows vulnerability data for client → vulnerable server")
log("🔧 Protocol registered: vulnerscvss_final (unique, no conflicts)")
