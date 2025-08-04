#!/bin/bash
# asset-scan.sh - IT Asset Documentation Script for Debian 12
# Usage: sudo ./asset-scan.sh

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

# Function to safely get command output
safe_cmd() {
    local cmd="$1"
    local default="$2"
    result=$(eval "$cmd" 2>/dev/null) || result="$default"
    echo "$result"
}

# Generate timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Start JSON output
cat << EOF
{
  "scan_timestamp": "$TIMESTAMP",
  "system_identification": {
    "hostname": "$(safe_cmd 'hostname' 'unknown')",
    "fqdn": "$(safe_cmd 'hostname -f' 'unknown')",
    "internal_ip": "$(safe_cmd "ip route get 1.1.1.1 | awk '{print \$7}' | head -1" 'unknown')",
    "external_ip": "$(safe_cmd 'curl -s ifconfig.me' 'unknown')",
    "mac_addresses": [$(ip link show | grep -E 'link/ether' | awk '{print "\"" $2 "\""}' | paste -sd ',' -)],
    "domain_membership": "$(safe_cmd 'realm list --name-only' 'none')",
    "serial_number": "$(safe_cmd 'dmidecode -s system-serial-number' 'unknown')"
  },
  "hardware_information": {
    "cpu_model": "$(safe_cmd "lscpu | grep 'Model name' | sed 's/Model name:[[:space:]]*//' | head -1" 'unknown')",
    "cpu_cores": "$(safe_cmd "nproc" '0')",
    "cpu_architecture": "$(safe_cmd 'uname -m' 'unknown')",
    "total_ram_gb": "$(safe_cmd "free -g | awk '/^Mem:/{print \$2}'" '0')",
    "total_ram_mb": "$(safe_cmd "free -m | awk '/^Mem:/{print \$2}'" '0')",
    "storage_devices": [
$(lsblk -ndo KNAME,SIZE,TYPE,MODEL | grep 'disk' | while read line; do
    name=$(echo $line | awk '{print $1}')
    size=$(echo $line | awk '{print $2}')
    model=$(echo $line | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//')
    echo "      {\"device\": \"/dev/$name\", \"size\": \"$size\", \"model\": \"$model\"},"
done | sed '$s/,$//')
    ],
    "network_interfaces": [
$(ip -o link show | grep -v lo | while read line; do
    iface=$(echo $line | awk -F': ' '{print $2}')
    state=$(echo $line | grep -o 'state [A-Z]*' | awk '{print $2}')
    echo "      {\"interface\": \"$iface\", \"state\": \"$state\"},"
done | sed '$s/,$//')
    ],
    "system_manufacturer": "$(safe_cmd 'dmidecode -s system-manufacturer' 'unknown')",
    "system_model": "$(safe_cmd 'dmidecode -s system-product-name' 'unknown')"
  },
  "operating_system": {
    "os_name": "$(safe_cmd "lsb_release -d | cut -f2" 'unknown')",
    "kernel_version": "$(safe_cmd 'uname -r' 'unknown')",
    "architecture": "$(safe_cmd 'dpkg --print-architecture' 'unknown')",
    "timezone": "$(safe_cmd 'timedatectl show --property=Timezone --value' 'unknown')",
    "boot_time": "$(safe_cmd 'uptime -s' 'unknown')"
  },
  "network_configuration": {
    "dns_servers": [$(grep nameserver /etc/resolv.conf | awk '{print "\"" $2 "\""}' | paste -sd ',' -)],
    "default_gateway": "$(safe_cmd "ip route | grep default | awk '{print \$3}' | head -1" 'unknown')",
    "firewall_status": "$(safe_cmd 'ufw status | head -1' 'unknown')"
  },
  "security_and_updates": {
    "user_accounts": [$(cut -d: -f1 /etc/passwd | grep -v '^_' | while read user; do echo "\"$user\","; done | sed '$s/,$//')],
    "last_update": "$(safe_cmd "stat -c %y /var/log/apt/history.log | cut -d' ' -f1" 'unknown')",
    "update_available": "$(safe_cmd 'apt list --upgradable 2>/dev/null | wc -l' '0')",
    "security_updates_available": "$(safe_cmd 'apt list --upgradable 2>/dev/null | grep -c security' '0')"
  }
}
EOF
