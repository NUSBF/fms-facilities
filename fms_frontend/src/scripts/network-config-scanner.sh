#!/bin/bash
# network-config-scanner.sh - Extract fixed IPs from DHCP and NFS configurations

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to resolve hostname from IP address with timeout and fallbacks
resolve_hostname() {
    local ip="$1"
    local hostname="N/A"
    local timeout=2
    
    # Skip if not a valid IP
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$ip"
        return
    fi
    
    # Method 1: Try nslookup with timeout
    if command -v nslookup >/dev/null 2>&1; then
        hostname=$(timeout $timeout nslookup "$ip" 2>/dev/null | awk '/name =/ {gsub(/\.$/, "", $4); print $4; exit}')
    fi
    
    # Method 2: Try dig if nslookup failed
    if [[ "$hostname" == "N/A" || -z "$hostname" ]] && command -v dig >/dev/null 2>&1; then
        hostname=$(timeout $timeout dig -x "$ip" +short 2>/dev/null | sed 's/\.$//' | head -n1)
    fi
    
    # Method 3: Try host command if dig failed
    if [[ "$hostname" == "N/A" || -z "$hostname" ]] && command -v host >/dev/null 2>&1; then
        hostname=$(timeout $timeout host "$ip" 2>/dev/null | awk '/domain name pointer/ {gsub(/\.$/, "", $5); print $5; exit}')
    fi
    
    # Method 4: Check /etc/hosts as fallback
    if [[ "$hostname" == "N/A" || -z "$hostname" ]]; then
        hostname=$(grep "^$ip[[:space:]]" /etc/hosts 2>/dev/null | awk '{print $2}' | head -n1)
    fi
    
    # Method 5: Try a quick ping to see if host is alive (optional info)
    local ping_status="offline"
    if timeout 1 ping -c 1 "$ip" >/dev/null 2>&1; then
        ping_status="online"
    fi
    
    # Return hostname or IP if no hostname found
    if [[ -z "$hostname" || "$hostname" == "N/A" ]]; then
        echo "$ip ($ping_status)"
    else
        echo "$hostname ($ping_status)"
    fi
}

# Function to resolve hostname from IP with failsafe
resolve_hostname_failsafe() {
    local ip="$1"
    local timeout=2
    
    # Skip if not a valid IP address
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$ip"
        return
    fi
    
    # Try multiple methods with short timeouts
    local hostname=""
    
    # Method 1: Use host command with timeout
    if command -v host >/dev/null 2>&1; then
        hostname=$(timeout ${timeout}s host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
    fi
    
    # Method 2: Use nslookup if host failed
    if [[ -z "$hostname" ]] && command -v nslookup >/dev/null 2>&1; then
        hostname=$(timeout ${timeout}s nslookup "$ip" 2>/dev/null | grep "name =" | awk '{print $NF}' | sed 's/\.$//')
    fi
    
    # Method 3: Use getent if others failed
    if [[ -z "$hostname" ]] && command -v getent >/dev/null 2>&1; then
        hostname=$(timeout ${timeout}s getent hosts "$ip" 2>/dev/null | awk '{print $2}')
    fi
    
    # Check if host is reachable with a quick ping
    local status="unknown"
    if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
        status="online"
    else
        status="offline"
    fi
    
    # Return hostname with status, or just IP if no hostname found
    if [[ -n "$hostname" && "$hostname" != "$ip" ]]; then
        echo "${hostname} (${status})"
    else
        echo "Unknown (${status})"
    fi
}

# Function to print section headers
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run with sudo for full access to configuration files${NC}"
    echo "Some files may not be readable without root privileges"
    echo
fi

print_header "Network Configuration Scanner"
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# DHCP Configuration Analysis
print_header "DHCP Fixed IP Addresses"

# Common DHCP config file locations
DHCP_CONFIGS=(
    "/etc/dhcp/dhcpd.conf"
    "/etc/dhcpd.conf" 
    "/usr/local/etc/dhcpd.conf"
    "/etc/dhcp3/dhcpd.conf"
    "/etc/dhcp/dhcp.conf"
)

DHCP_FOUND=false

for config_file in "${DHCP_CONFIGS[@]}"; do
    if [[ -f "$config_file" && -r "$config_file" ]]; then
        echo -e "${GREEN}Found DHCP config: $config_file${NC}"
        DHCP_FOUND=true
        
        echo -e "\n${YELLOW}Fixed IP Reservations:${NC}"
        printf "%-20s %-15s %-18s %s\n" "Hostname" "IP Address" "MAC Address" "Status"
        printf "%-20s %-15s %-18s %s\n" "--------" "----------" "-----------" "------"
        
        # Parse DHCP config for host entries with fixed addresses
        awk '
        BEGIN { 
            in_host = 0
            host_name = ""
            fixed_ip = ""
            mac_addr = ""
        }
        
        # Start of host block
        /^[[:space:]]*host[[:space:]]+/ { 
            in_host = 1
            host_name = $2
            gsub(/[{}[:space:]]*$/, "", host_name)
            fixed_ip = ""
            mac_addr = ""
        }
        
        # Inside host block
        in_host {
            if (/fixed-address/) {
                for(i=1; i<=NF; i++) {
                    if($i ~ /([0-9]{1,3}\.){3}[0-9]{1,3}/) {
                        gsub(/[;[:space:]]*$/, "", $i)
                        fixed_ip = $i
                        break
                    }
                }
            }
            if (/hardware[[:space:]]+ethernet/) {
                for(i=1; i<=NF; i++) {
                    if($i ~ /([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/) {
                        gsub(/[;[:space:]]*$/, "", $i)
                        mac_addr = $i
                        break
                    }
                }
            }
        }
        
        # End of host block
        /^[[:space:]]*}/ && in_host {
            if (fixed_ip != "" && host_name != "") {
                printf "%-20s %-15s %-18s %s\n", host_name, fixed_ip, mac_addr, "Reserved"
            }
            in_host = 0
            host_name = ""
            fixed_ip = ""
            mac_addr = ""
        }
        ' "$config_file" 2>/dev/null
        
        # Extract subnet information for context
        echo -e "\n${YELLOW}Network Subnets:${NC}"
        grep -E "subnet[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]+netmask" "$config_file" 2>/dev/null | while read -r line; do
            subnet=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            netmask=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
            echo "  Network: $subnet/$netmask"
        done
        
        # Extract dynamic ranges
        echo -e "\n${YELLOW}Dynamic IP Ranges:${NC}"
        grep -E "range[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}" "$config_file" 2>/dev/null | while read -r line; do
            range_start=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            range_end=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
            if [[ "$range_start" != "$range_end" ]]; then
                echo "  Range: $range_start - $range_end"
            else
                echo "  Range: $range_start"
            fi
        done
        
        echo
        break
    fi
done

if [[ "$DHCP_FOUND" == false ]]; then
    echo -e "${RED}No DHCP configuration files found or accessible${NC}"
    echo "Searched locations:"
    for config_file in "${DHCP_CONFIGS[@]}"; do
        if [[ -f "$config_file" ]]; then
            echo "  - $config_file (exists but not readable)"
        else
            echo "  - $config_file (not found)"
        fi
    done
fi

# NFS Exports Analysis
print_header "NFS Export Configurations"

NFS_CONFIG="/etc/exports"

if [[ -f "$NFS_CONFIG" && -r "$NFS_CONFIG" ]]; then
    echo -e "${GREEN}Found NFS exports: $NFS_CONFIG${NC}"
    
    if [[ -s "$NFS_CONFIG" ]]; then
        echo -e "\n${YELLOW}NFS Exports and Client Access:${NC}"
        printf "%-35s %-20s %s\n" "Export Path" "Client" "Type"
        printf "%-35s %-20s %s\n" "-----------" "------" "----"
        
        # Parse exports file
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] && continue
            
            # Extract export path (first field)
            export_path=$(echo "$line" | awk '{print $1}')
            
            # Extract client specifications - everything after the path
            clients_part=$(echo "$line" | sed "s|^$export_path||" | sed 's/^[[:space:]]*//')
            
            # Parse each client entry - extract only valid IP addresses, networks, and hostnames
            # Split by spaces and parentheses to separate clients from mount options
            echo "$clients_part" | tr ' ' '\n' | tr '(' '\n' | tr ')' '\n' | while read -r client_spec; do
                # Skip empty lines and mount options
                [[ -z "$client_spec" ]] && continue
                
                # Skip common NFS mount options
                [[ "$client_spec" =~ ^(rw|ro|sync|async|no_subtree_check|subtree_check|no_root_squash|root_squash|all_squash|no_all_squash|anonuid|anongid|sec|fsid|crossmnt|no_acl|mountpoint|mp)$ ]] && continue
                [[ "$client_spec" =~ ^(rw|ro|sync|async|no_subtree_check|subtree_check|no_root_squash|root_squash|all_squash|no_all_squash)= ]] && continue
                [[ "$client_spec" =~ ^(anonuid|anongid|sec|fsid)= ]] && continue
                [[ "$client_spec" =~ ^[0-9]+$ ]] && continue  # Skip numeric-only values (likely UIDs/GIDs)
                
                # Only process valid client specifications
                if [[ "$client_spec" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                    printf "%-35s %-20s %s\n" "$export_path" "$client_spec" "Single IP"
                elif [[ "$client_spec" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$ ]]; then
                    printf "%-35s %-20s %s\n" "$export_path" "$client_spec" "Network"
                elif [[ "$client_spec" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    printf "%-35s %-20s %s\n" "$export_path" "$client_spec" "Hostname"
                elif [[ "$client_spec" == "*" ]]; then
                    printf "%-35s %-20s %s\n" "$export_path" "$client_spec" "All Hosts"
                fi
            done
            
        done < "$NFS_CONFIG"
        
        # Summary of unique IPs and networks
        echo -e "\n${YELLOW}Summary - Unique Client IPs/Networks:${NC}"
        # Parse exports more carefully to extract only valid IPs/networks
        temp_ips=$(mktemp)
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] && continue
            export_path=$(echo "$line" | awk '{print $1}')
            clients_part=$(echo "$line" | sed "s|^$export_path||" | sed 's/^[[:space:]]*//')
            
            echo "$clients_part" | tr ' ' '\n' | tr '(' '\n' | tr ')' '\n' | while read -r client_spec; do
                [[ -z "$client_spec" ]] && continue
                # Skip mount options
                [[ "$client_spec" =~ ^(rw|ro|sync|async|no_subtree_check|subtree_check|no_root_squash|root_squash|all_squash|no_all_squash|anonuid|anongid|sec|fsid|crossmnt|no_acl|mountpoint|mp)$ ]] && continue
                [[ "$client_spec" =~ ^(rw|ro|sync|async|no_subtree_check|subtree_check|no_root_squash|root_squash|all_squash|no_all_squash)= ]] && continue
                [[ "$client_spec" =~ ^(anonuid|anongid|sec|fsid)= ]] && continue
                [[ "$client_spec" =~ ^[0-9]+$ ]] && continue
                
                if [[ "$client_spec" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?$ ]]; then
                    echo "$client_spec" >> "$temp_ips"
                fi
            done
        done < "$NFS_CONFIG"
        
        all_ips=$(sort -V "$temp_ips" 2>/dev/null | uniq)
        rm -f "$temp_ips"
        
        if [[ -n "$all_ips" ]]; then
            echo "$all_ips" | while read -r ip; do
                if [[ "$ip" =~ /[0-9]+$ ]]; then
                    echo "  $ip (Network)"
                else
                    echo "  $ip (Single IP)"
                fi
            done
        else
            echo "  No IP addresses found"
        fi
        
        # Summary of hostnames
        echo -e "\n${YELLOW}Summary - Unique Hostnames:${NC}"
        temp_hostnames=$(mktemp)
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] && continue
            export_path=$(echo "$line" | awk '{print $1}')
            clients_part=$(echo "$line" | sed "s|^$export_path||" | sed 's/^[[:space:]]*//')
            
            echo "$clients_part" | tr ' ' '\n' | tr '(' '\n' | tr ')' '\n' | while read -r client_spec; do
                [[ -z "$client_spec" ]] && continue
                # Skip mount options
                [[ "$client_spec" =~ ^(rw|ro|sync|async|no_subtree_check|subtree_check|no_root_squash|root_squash|all_squash|no_all_squash|anonuid|anongid|sec|fsid|crossmnt|no_acl|mountpoint|mp)$ ]] && continue
                [[ "$client_spec" =~ ^(rw|ro|sync|async|no_subtree_check|subtree_check|no_root_squash|root_squash|all_squash|no_all_squash)= ]] && continue
                [[ "$client_spec" =~ ^(anonuid|anongid|sec|fsid)= ]] && continue
                [[ "$client_spec" =~ ^[0-9]+$ ]] && continue
                
                if [[ "$client_spec" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    echo "$client_spec" >> "$temp_hostnames"
                fi
            done
        done < "$NFS_CONFIG"
        
        hostnames=$(sort "$temp_hostnames" 2>/dev/null | uniq)
        rm -f "$temp_hostnames"
        
        if [[ -n "$hostnames" ]]; then
            echo "$hostnames" | while read -r hostname; do
                echo "  $hostname"
            done
        else
            echo "  No hostnames found"
        fi
        
    else
        echo -e "${YELLOW}NFS exports file is empty${NC}"
    fi
else
    if [[ -f "$NFS_CONFIG" ]]; then
        echo -e "${RED}NFS exports file exists but not readable: $NFS_CONFIG${NC}"
    else
        echo -e "${RED}NFS exports file not found: $NFS_CONFIG${NC}"
    fi
fi

# Network Summary
print_header "Network Summary"

echo -e "${YELLOW}Current System Network Interfaces:${NC}"
if command -v ip >/dev/null 2>&1; then
    ip addr show 2>/dev/null | grep -E "inet [0-9]" | awk '{print "  " $2 " (" $(NF) ")"}' 2>/dev/null || echo "  Unable to retrieve interface information"
else
    ifconfig 2>/dev/null | grep -E "inet [0-9]" | awk '{print "  " $2}' 2>/dev/null || echo "  Unable to retrieve interface information"
fi

echo -e "\n${YELLOW}DNS Servers:${NC}"
if [[ -f /etc/resolv.conf ]]; then
    grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print "  " $2}' || echo "  No DNS servers configured"
else
    echo "  No DNS configuration found"
fi

# Generate JSON output summary
print_header "JSON Summary"

# Create temporary files for JSON data
TEMP_DHCP=$(mktemp)
TEMP_NFS=$(mktemp)

# Generate DHCP JSON entries
if [[ "$DHCP_FOUND" == true ]]; then
    for config_file in "${DHCP_CONFIGS[@]}"; do
        if [[ -f "$config_file" && -r "$config_file" ]]; then
            awk '
            /^[[:space:]]*host[[:space:]]+/ { 
                in_host = 1
                host_name = $2
                gsub(/[{}[:space:]]*$/, "", host_name)
                fixed_ip = ""
                mac_addr = ""
            }
            in_host {
                if (/fixed-address/) {
                    for(i=1; i<=NF; i++) {
                        if($i ~ /([0-9]{1,3}\.){3}[0-9]{1,3}/) {
                            gsub(/[;[:space:]]*$/, "", $i)
                            fixed_ip = $i
                            break
                        }
                    }
                }
                if (/hardware[[:space:]]+ethernet/) {
                    for(i=1; i<=NF; i++) {
                        if($i ~ /([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/) {
                            gsub(/[;[:space:]]*$/, "", $i)
                            mac_addr = $i
                            break
                        }
                    }
                }
            }
            /^[[:space:]]*}/ && in_host {
                if (fixed_ip != "" && host_name != "") {
                    printf "    {\"hostname\": \"%s\", \"ip_address\": \"%s\", \"mac_address\": \"%s\"}\n", host_name, fixed_ip, mac_addr
                }
                in_host = 0
            }
            ' "$config_file" 2>/dev/null > "$TEMP_DHCP"
            break
        fi
    done
fi

# Generate NFS JSON entries with hostname resolution
if [[ -f "$NFS_CONFIG" && -r "$NFS_CONFIG" && -s "$NFS_CONFIG" ]]; then
    echo -e "${YELLOW}Resolving hostnames for NFS clients (this may take a moment)...${NC}"
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] && continue
        export_path=$(echo "$line" | awk '{print $1}')
        clients_part=$(echo "$line" | sed "s|^$export_path||" | sed 's/^[[:space:]]*//')
        
        echo "$clients_part" | tr ' ' '\n' | tr '(' '\n' | tr ')' '\n' | while read -r client_spec; do
            # Skip empty lines and mount options
            [[ -z "$client_spec" ]] && continue
            
            # Skip common NFS mount options
            [[ "$client_spec" =~ ^(rw|ro|sync|async|no_subtree_check|subtree_check|no_root_squash|root_squash|all_squash|no_all_squash|anonuid|anongid|sec|fsid|crossmnt|no_acl|mountpoint|mp)$ ]] && continue
            [[ "$client_spec" =~ ^(rw|ro|sync|async|no_subtree_check|subtree_check|no_root_squash|root_squash|all_squash|no_all_squash)= ]] && continue
            [[ "$client_spec" =~ ^(anonuid|anongid|sec|fsid)= ]] && continue
            [[ "$client_spec" =~ ^[0-9]+$ ]] && continue  # Skip numeric-only values (likely UIDs/GIDs)
            
            # Only process valid client specifications
            if [[ "$client_spec" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?$ ]]; then
                # Extract IP without subnet mask
                client_ip=$(echo "$client_spec" | cut -d'/' -f1)
                resolved_hostname=$(resolve_hostname "$client_ip")
                printf "    {\"export_path\": \"%s\", \"client\": \"%s\", \"client_ip\": \"%s\", \"resolved_hostname\": \"%s\"}\n" "$export_path" "$client_spec" "$client_ip" "$resolved_hostname"
            elif [[ "$client_spec" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                # Already a hostname, try to resolve IP
                client_ip=$(timeout 2 nslookup "$client_spec" 2>/dev/null | awk '/^Address: / && !/127\./ {print $2; exit}')
                if [[ -z "$client_ip" ]]; then
                    client_ip="N/A"
                fi
                printf "    {\"export_path\": \"%s\", \"client\": \"%s\", \"client_ip\": \"%s\", \"resolved_hostname\": \"%s\"}\n" "$export_path" "$client_spec" "$client_ip" "$client_spec"
            elif [[ "$client_spec" == "*" ]]; then
                printf "    {\"export_path\": \"%s\", \"client\": \"%s\", \"client_ip\": \"*\", \"resolved_hostname\": \"All hosts\"}\n" "$export_path" "$client_spec"
            fi
        done
    done < "$NFS_CONFIG" > "$TEMP_NFS"
fi

# Build the final JSON
echo "{"
echo "  \"scan_timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
echo "  \"dhcp_fixed_ips\": ["

# Add DHCP entries with proper comma handling
if [[ -s "$TEMP_DHCP" ]]; then
    # Add commas to all but the last line
    sed '$!s/$/,/' "$TEMP_DHCP"
fi

echo "  ],"
echo "  \"nfs_exports\": ["

# Add NFS entries with proper comma handling
if [[ -s "$TEMP_NFS" ]]; then
    # Add commas to all but the last line
    sed '$!s/$/,/' "$TEMP_NFS"
fi

echo "  ]"
echo "}"

# Clean up temporary files
rm -f "$TEMP_DHCP" "$TEMP_NFS"

print_header "Scan Complete"
echo "Run with: sudo ./network-config-scanner.sh"
