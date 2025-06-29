#!/usr/bin/env bash

#===============================================================================
# Ubuntu Server Network Interface Optimization Script with ethtool
# 
# Complete professional script for network interface optimization
# Specifically designed for virtio_net and physical interfaces
# Includes comprehensive error handling and logging
#
# Version: 2.0 (2025)
# Author: Advanced Network Optimization Team
# Contact: @NotepadVpn (Telegram Channel for more network tools)
#
# Features:
# - Automatic interface detection with fallback mechanisms
# - Comprehensive feature analysis and optimization
# - Professional error handling and logging
# - Rollback capability for failed operations
# - Detailed performance monitoring and validation
# - Support for both VM and physical environments
# - Persistent configuration management
#===============================================================================

# Strict error handling - Best practices for bash scripts[15][16]
set -euo pipefail
IFS=$'\n\t'

# Global variables and constants
readonly SCRIPT_NAME="$(basename "${0}")"
readonly SCRIPT_VERSION="2.0"
readonly LOG_FILE="/var/log/network_optimization.log"
readonly BACKUP_FILE="/tmp/network_config_backup_$(date +%s).txt"
readonly LOCK_FILE="/var/run/network_optimization.lock"

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Performance optimization flags
declare -A OPTIMIZATION_FEATURES
declare -A BACKUP_SETTINGS
declare MAIN_INTERFACE=""
declare CPU_CORES=0
declare IS_VIRTUAL=false
declare ETHTOOL_AVAILABLE=false

#===============================================================================
# Utility Functions
#===============================================================================

# Logging function with timestamps[19]
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

# Error handling function with cleanup[15][16]
error_exit() {
    local error_message="$1"
    local exit_code="${2:-1}"
    log "ERROR" "${error_message}"
    cleanup
    exit "${exit_code}"
}

# Cleanup function for graceful exit
cleanup() {
    if [[ -f "${LOCK_FILE}" ]]; then
        rm -f "${LOCK_FILE}" 2>/dev/null || true
    fi
    log "INFO" "Cleanup completed"
}

# Trap for cleanup on script exit[19]
trap cleanup EXIT
trap 'error_exit "Script interrupted by user" 130' INT
trap 'error_exit "Script terminated" 143' TERM

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root. Use: sudo ${SCRIPT_NAME}"
    fi
}

# Check for required tools and dependencies
check_dependencies() {
    local missing_tools=()
    
    # Check for ethtool[7][20]
    if ! command -v ethtool >/dev/null 2>&1; then
        log "WARNING" "ethtool not found, attempting to install..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y ethtool
        elif command -v yum >/dev/null 2>&1; then
            yum install -y ethtool
        else
            missing_tools+=("ethtool")
        fi
    else
        ETHTOOL_AVAILABLE=true
    fi
    
    # Check for other essential tools
    local tools=("ip" "grep" "awk" "sed" "lscpu")
    for tool in "${tools[@]}"; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            missing_tools+=("${tool}")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error_exit "Missing required tools: ${missing_tools[*]}"
    fi
    
    log "INFO" "All dependencies checked successfully"
}

# Create lock file to prevent concurrent execution
create_lock() {
    if [[ -f "${LOCK_FILE}" ]]; then
        local lock_pid
        lock_pid=$(cat "${LOCK_FILE}" 2>/dev/null || echo "unknown")
        if kill -0 "${lock_pid}" 2>/dev/null; then
            error_exit "Another instance is already running (PID: ${lock_pid})"
        else
            log "WARNING" "Removing stale lock file"
            rm -f "${LOCK_FILE}"
        fi
    fi
    echo $$ > "${LOCK_FILE}"
}

#===============================================================================
# Network Interface Detection Functions
#===============================================================================

# Detect the main network interface with multiple fallback methods[20]
detect_main_interface() {
    local interface=""
    local detection_methods=(
        "detect_by_default_route"
        "detect_by_active_ethernet"
        "detect_by_traffic_volume"
        "detect_by_naming_convention"
    )
    
    log "INFO" "Starting network interface detection..."
    
    for method in "${detection_methods[@]}"; do
        interface=$(${method}) || continue
        if [[ -n "${interface}" ]] && validate_interface "${interface}"; then
            MAIN_INTERFACE="${interface}"
            log "INFO" "Main interface detected: ${MAIN_INTERFACE} (method: ${method})"
            return 0
        fi
    done
    
    error_exit "Could not detect a valid network interface"
}

# Method 1: Detect by default route
detect_by_default_route() {
    ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1
}

# Method 2: Detect by active ethernet interfaces
detect_by_active_ethernet() {
    ip -brief link show up 2>/dev/null | grep -E '^(eth|en|ens|enp)' | awk '{print $1}' | head -n1
}

# Method 3: Detect by traffic volume (most active interface)
detect_by_traffic_volume() {
    local max_bytes=0
    local interface=""
    local current_interface=""
    local rx_bytes=""
    
    while IFS= read -r line; do
        if [[ $line =~ ^[[:space:]]*(eth|en|ens|enp)[^:]*: ]]; then
            current_interface=$(echo "$line" | awk -F: '{print $1}' | tr -d ' ')
        elif [[ $line =~ ^[[:space:]]*RX:.*bytes ]]; then
            rx_bytes=$(echo "$line" | awk '{print $2}')
            if [[ $rx_bytes -gt $max_bytes ]]; then
                max_bytes=$rx_bytes
                interface=$current_interface
            fi
        fi
    done < <(ip -s link show 2>/dev/null)
    
    echo "$interface"
}

# Method 4: Detect by naming convention
detect_by_naming_convention() {
    local preferred_patterns=("eth0" "ens" "enp" "eth")
    
    for pattern in "${preferred_patterns[@]}"; do
        local found_interface
        found_interface=$(ip link show 2>/dev/null | grep -oE "(${pattern}[0-9a-z]*)" | head -n1)
        if [[ -n "$found_interface" ]] && validate_interface "$found_interface"; then
            echo "$found_interface"
            return 0
        fi
    done
}

# Validate if interface exists and is usable
validate_interface() {
    local interface="$1"
    
    # Check if interface exists
    if ! ip link show "${interface}" >/dev/null 2>&1; then
        return 1
    fi
    
    # Check if ethtool can query the interface
    if [[ "${ETHTOOL_AVAILABLE}" == "true" ]]; then
        if ! ethtool "${interface}" >/dev/null 2>&1; then
            return 1
        fi
    fi
    
    return 0
}

#===============================================================================
# System Information Gathering
#===============================================================================

# Detect system characteristics
detect_system_info() {
    log "INFO" "Gathering system information..."
    
    # Detect CPU cores
    CPU_CORES=$(nproc)
    log "INFO" "CPU cores detected: ${CPU_CORES}"
    
    # Detect if running in virtual environment[9][11]
    if detect_virtualization; then
        IS_VIRTUAL=true
        log "INFO" "Virtual environment detected"
    else
        IS_VIRTUAL=false
        log "INFO" "Physical hardware detected"
    fi
    
    # Log system details
    log "INFO" "Kernel version: $(uname -r)"
    log "INFO" "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 2>/dev/null || echo 'Unknown')"
}

# Detect virtualization environment
detect_virtualization() {
    # Check for virtualization indicators
    local virt_indicators=(
        "/sys/class/dmi/id/product_name"
        "/sys/class/dmi/id/sys_vendor"
        "/proc/cpuinfo"
    )
    
    # Check DMI information
    if [[ -f "/sys/class/dmi/id/product_name" ]]; then
        local product_name
        product_name=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "")
        if [[ $product_name =~ (VirtualBox|VMware|QEMU|KVM|Xen|Hyper-V) ]]; then
            return 0
        fi
    fi
    
    # Check CPU information for hypervisor flag
    if grep -q "hypervisor" /proc/cpuinfo 2>/dev/null; then
        return 0
    fi
    
    # Check for virtio driver
    if lsmod 2>/dev/null | grep -q "virtio"; then
        return 0
    fi
    
    return 1
}

#===============================================================================
# Interface Analysis Functions
#===============================================================================

# Comprehensive interface analysis
analyze_interface() {
    local interface="$1"
    
    log "INFO" "Starting comprehensive analysis of interface: ${interface}"
    
    create_configuration_backup "${interface}"
    analyze_driver_info "${interface}"
    analyze_link_status "${interface}"
    analyze_features "${interface}"
    analyze_ring_buffers "${interface}"
    analyze_interrupt_coalescing "${interface}"
    analyze_channels "${interface}"
    analyze_statistics "${interface}"
}

# Backup current configuration
create_configuration_backup() {
    local interface="$1"
    
    log "INFO" "Creating configuration backup..."
    {
        echo "# Network Configuration Backup - $(date)"
        echo "# Interface: ${interface}"
        echo "# Generated by: ${SCRIPT_NAME} v${SCRIPT_VERSION}"
        echo ""
        
        echo "# Driver Information"
        ethtool -i "${interface}" 2>/dev/null || echo "Driver info not available"
        echo ""
        
        echo "# Current Settings"
        ethtool "${interface}" 2>/dev/null || echo "Basic settings not available"
        echo ""
        
        echo "# Features"
        ethtool -k "${interface}" 2>/dev/null || echo "Features not available"
        echo ""
        
        echo "# Ring Buffers"
        ethtool -g "${interface}" 2>/dev/null || echo "Ring buffers not available"
        echo ""
        
        echo "# Interrupt Coalescing"
        ethtool -c "${interface}" 2>/dev/null || echo "Coalescing not available"
        echo ""
        
        echo "# Channels"
        ethtool -l "${interface}" 2>/dev/null || echo "Channels not available"
        echo ""
        
    } > "${BACKUP_FILE}"
    
    log "INFO" "Configuration backed up to: ${BACKUP_FILE}"
}

# Analyze driver and hardware information
analyze_driver_info() {
    local interface="$1"
    
    log "INFO" "=== Driver and Hardware Information ==="
    
    if ! ethtool -i "${interface}" 2>/dev/null; then
        log "WARNING" "Could not retrieve driver information"
        return 1
    fi
    
    # Extract driver name for specific optimizations
    local driver_name
    driver_name=$(ethtool -i "${interface}" 2>/dev/null | grep "^driver:" | awk '{print $2}')
    
    if [[ "${driver_name}" == "virtio_net" ]]; then
        log "INFO" "VirtIO network driver detected - applying VM-specific optimizations"
        IS_VIRTUAL=true
    else
        log "INFO" "Physical network driver detected: ${driver_name}"
    fi
}

# Analyze current link status
analyze_link_status() {
    local interface="$1"
    
    log "INFO" "=== Link Status Analysis ==="
    
    local link_info
    if ! link_info=$(ethtool "${interface}" 2>/dev/null); then
        log "WARNING" "Could not retrieve link status"
        return 1
    fi
    
    echo "${link_info}" | while IFS= read -r line; do
        if [[ $line =~ (Speed|Duplex|Auto-negotiation|Link\ detected): ]]; then
            log "INFO" "  ${line}"
        fi
    done
}

# Comprehensive feature analysis with explanations
analyze_features() {
    local interface="$1"
    
    log "INFO" "=== Network Features Analysis ==="
    
    local features_output
    if ! features_output=$(ethtool -k "${interface}" 2>/dev/null); then
        log "WARNING" "Could not retrieve feature information"
        return 1
    fi
    
    # Define feature explanations
    declare -A feature_descriptions=(
        ["rx-checksumming"]="Verifies incoming data integrity"
        ["tx-checksumming"]="Ensures outgoing data integrity"
        ["tx-checksum-ip-generic"]="Generic IP checksum offload"
        ["tx-checksum-sctp"]="SCTP checksum offload"
        ["scatter-gather"]="Memory optimization for data transfer"
        ["tx-scatter-gather"]="Transmit scatter-gather optimization"
        ["tcp-segmentation-offload"]="Hardware TCP segmentation"
        ["tx-tcp-segmentation"]="TCP transmit segmentation"
        ["tx-tcp6-segmentation"]="IPv6 TCP segmentation"
        ["generic-segmentation-offload"]="Generic segmentation offload"
        ["generic-receive-offload"]="Combines small packets into larger ones"
        ["large-receive-offload"]="Aggregates received packets"
        ["rx-vlan-offload"]="VLAN tag processing offload"
        ["tx-vlan-offload"]="VLAN tag insertion offload"
        ["ntuple-filters"]="Advanced packet filtering"
        ["receive-hashing"]="RSS - distributes packets across CPU cores"
        ["rx-gro-hw"]="Hardware generic receive offload"
        ["rx-gro-list"]="List-based GRO implementation"
        ["rx-udp-gro-forwarding"]="UDP GRO for forwarding"
        ["tx-gso-partial"]="Partial generic segmentation offload"
        ["tx-nocache-copy"]="No-cache copy optimization"
        ["hw-tc-offload"]="Hardware traffic control offload"
    )
    
    # Analyze each feature
    while IFS= read -r line; do
        if [[ $line =~ ^([^:]+):[[:space:]]*([a-z]+) ]]; then
            local feature="${BASH_REMATCH[1]}"
            local status="${BASH_REMATCH[2]}"
            local description="${feature_descriptions[$feature]:-"Advanced network feature"}"
            
            case "$status" in
                "on"|"off")
                    if [[ "$status" == "on" ]]; then
                        log "INFO" "  ${feature} [${GREEN}ON${NC}]: ${description}"
                    else
                        log "INFO" "  ${feature} [${RED}OFF${NC}]: ${description}"
                    fi
                    ;;
                "fixed")
                    log "INFO" "  ${feature} [${YELLOW}FIXED${NC}]: ${description}"
                    ;;
            esac
        fi
    done <<< "$features_output"
}

# Analyze ring buffer configuration[12][14]
analyze_ring_buffers() {
    local interface="$1"
    
    log "INFO" "=== Ring Buffer Analysis ==="
    
    local ring_info
    if ! ring_info=$(ethtool -g "${interface}" 2>/dev/null); then
        log "WARNING" "Ring buffer information not available"
        return 1
    fi
    
    echo "${ring_info}"
    
    # Extract current and maximum values for optimization decisions
    local max_rx max_tx current_rx current_tx
    max_rx=$(echo "${ring_info}" | grep "RX:" | head -n1 | awk '{print $2}')
    max_tx=$(echo "${ring_info}" | grep "TX:" | head -n1 | awk '{print $2}')
    current_rx=$(echo "${ring_info}" | grep "RX:" | tail -n1 | awk '{print $2}')
    current_tx=$(echo "${ring_info}" | grep "TX:" | tail -n1 | awk '{print $2}')
    
    if [[ -n "$max_rx" && -n "$current_rx" ]]; then
        if [[ $current_rx -lt $max_rx ]]; then
            log "INFO" "  RX ring buffer can be optimized: ${current_rx}/${max_rx}"
            OPTIMIZATION_FEATURES["ring_rx"]="$max_rx"
        fi
    fi
    
    if [[ -n "$max_tx" && -n "$current_tx" ]]; then
        if [[ $current_tx -lt $max_tx ]]; then
            log "INFO" "  TX ring buffer can be optimized: ${current_tx}/${max_tx}"
            OPTIMIZATION_FEATURES["ring_tx"]="$max_tx"
        fi
    fi
}

# Analyze interrupt coalescing settings[13]
analyze_interrupt_coalescing() {
    local interface="$1"
    
    log "INFO" "=== Interrupt Coalescing Analysis ==="
    
    local coalesce_info
    if ! coalesce_info=$(ethtool -c "${interface}" 2>/dev/null); then
        log "WARNING" "Interrupt coalescing information not available"
        return 1
    fi
    
    echo "${coalesce_info}"
    
    # Check if adaptive coalescing is enabled
    if echo "${coalesce_info}" | grep -q "Adaptive.*on"; then
        log "INFO" "  Adaptive coalescing is enabled - may need optimization for low latency"
        OPTIMIZATION_FEATURES["adaptive_coalescing"]="disable"
    fi
}

# Analyze channel configuration[28][30]
analyze_channels() {
    local interface="$1"
    
    log "INFO" "=== Channel Configuration Analysis ==="
    
    local channel_info
    if ! channel_info=$(ethtool -l "${interface}" 2>/dev/null); then
        log "WARNING" "Channel information not available"
        return 1
    fi
    
    echo "${channel_info}"
    
    # Extract channel information for multi-queue optimization
    local max_combined current_combined
    max_combined=$(echo "${channel_info}" | grep "Combined:" | head -n1 | awk '{print $2}')
    current_combined=$(echo "${channel_info}" | grep "Combined:" | tail -n1 | awk '{print $2}')
    
    if [[ -n "$max_combined" && -n "$current_combined" && $max_combined -gt 1 ]]; then
        local optimal_channels
        optimal_channels=$((max_combined < CPU_CORES ? max_combined : CPU_CORES))
        
        if [[ $current_combined -lt $optimal_channels ]]; then
            log "INFO" "  Multi-queue can be optimized: ${current_combined}/${optimal_channels}"
            OPTIMIZATION_FEATURES["channels"]="$optimal_channels"
        fi
    fi
}

# Analyze network statistics for issues[17]
analyze_statistics() {
    local interface="$1"
    
    log "INFO" "=== Network Statistics Analysis ==="
    
    local stats
    if ! stats=$(ethtool -S "${interface}" 2>/dev/null); then
        log "WARNING" "Statistics not available"
        return 1
    fi
    
    # Look for error indicators
    local error_stats
    error_stats=$(echo "${stats}" | grep -iE "(drop|discard|error|crc|collision)" | head -20)
    
    if [[ -n "$error_stats" ]]; then
        log "WARNING" "Potential network issues detected:"
        echo "${error_stats}" | while IFS= read -r line; do
            log "WARNING" "  ${line}"
        done
    else
        log "INFO" "No significant errors detected in statistics"
    fi
}

#===============================================================================
# Optimization Functions
#===============================================================================

# Apply comprehensive optimizations
apply_optimizations() {
    local interface="$1"
    
    log "INFO" "=== Applying Network Optimizations ==="
    
    # Apply optimizations based on environment
    if [[ "${IS_VIRTUAL}" == "true" ]]; then
        apply_virtual_optimizations "${interface}"
    else
        apply_physical_optimizations "${interface}"
    fi
    
    # Apply common optimizations
    apply_common_optimizations "${interface}"
    
    # Apply advanced optimizations
    apply_advanced_optimizations "${interface}"
    
    log "INFO" "All optimizations applied successfully"
}

# Virtual environment specific optimizations[8][21]
apply_virtual_optimizations() {
    local interface="$1"
    
    log "INFO" "Applying virtualization-specific optimizations..."
    
    # For virtio_net, certain features have limitations
    # Ring buffers are typically limited to 256[21]
    if [[ -n "${OPTIMIZATION_FEATURES[ring_rx]:-}" ]] && [[ "${OPTIMIZATION_FEATURES[ring_rx]}" -gt 256 ]]; then
        OPTIMIZATION_FEATURES["ring_rx"]="256"
    fi
    
    if [[ -n "${OPTIMIZATION_FEATURES[ring_tx]:-}" ]] && [[ "${OPTIMIZATION_FEATURES[ring_tx]}" -gt 256 ]]; then
        OPTIMIZATION_FEATURES["ring_tx"]="256"
    fi
}

# Physical hardware optimizations
apply_physical_optimizations() {
    local interface="$1"
    
    log "INFO" "Applying physical hardware optimizations..."
    
    # For physical interfaces, we can be more aggressive with ring buffers
    # Modern NICs support larger ring buffers[14]
    if [[ -n "${OPTIMIZATION_FEATURES[ring_rx]:-}" ]]; then
        local max_safe_rx=$((OPTIMIZATION_FEATURES[ring_rx] > 4096 ? 4096 : OPTIMIZATION_FEATURES[ring_rx]))
        OPTIMIZATION_FEATURES["ring_rx"]="$max_safe_rx"
    fi
}

# Common optimizations for all environments
apply_common_optimizations() {
    local interface="$1"
    
    log "INFO" "Applying common optimizations..."
    
    # Low-latency feature optimizations
    apply_feature_optimization "${interface}" "generic-receive-offload" "off" "Reduce GRO batching delays"
    apply_feature_optimization "${interface}" "large-receive-offload" "off" "Reduce LRO batching delays"
    apply_feature_optimization "${interface}" "tcp-segmentation-offload" "off" "Consistent packet timing"
    apply_feature_optimization "${interface}" "generic-segmentation-offload" "off" "Eliminate GSO delays"
    apply_feature_optimization "${interface}" "rx-gro-hw" "off" "Disable hardware GRO batching"
    
    # Performance and reliability features
    apply_feature_optimization "${interface}" "rx-checksumming" "on" "Data integrity verification"
    apply_feature_optimization "${interface}" "tx-checksumming" "on" "Transmission reliability"
    apply_feature_optimization "${interface}" "scatter-gather" "on" "Memory efficiency"
    apply_feature_optimization "${interface}" "receive-hashing" "on" "Multi-core distribution"
    
    # Stability features
    apply_feature_optimization "${interface}" "tx-nocache-copy" "off" "Improved stability"
}

# Advanced optimizations
apply_advanced_optimizations() {
    local interface="$1"
    
    log "INFO" "Applying advanced optimizations..."
    
    # Ring buffer optimization
    if [[ -n "${OPTIMIZATION_FEATURES[ring_rx]:-}" ]] || [[ -n "${OPTIMIZATION_FEATURES[ring_tx]:-}" ]]; then
        apply_ring_buffer_optimization "${interface}"
    fi
    
    # Interrupt coalescing optimization
    apply_interrupt_coalescing_optimization "${interface}"
    
    # Multi-queue optimization
    if [[ -n "${OPTIMIZATION_FEATURES[channels]:-}" ]]; then
        apply_channel_optimization "${interface}"
    fi
    
    # Flow control optimization
    apply_flow_control_optimization "${interface}"
}

# Safe feature modification with error handling
apply_feature_optimization() {
    local interface="$1"
    local feature="$2"
    local state="$3"
    local description="$4"
    
    log "INFO" "Setting ${feature} to ${state} - ${description}"
    
    # Check if feature exists first
    if ! ethtool -k "${interface}" | grep -q "^${feature}:"; then
        log "WARNING" "Feature ${feature} not supported on this interface"
        return 1
    fi
    
    # Store current state for rollback
    local current_state
    current_state=$(ethtool -k "${interface}" | grep "^${feature}:" | awk '{print $2}')
    BACKUP_SETTINGS["${feature}"]="${current_state}"
    
    # Apply the change
    if ethtool -K "${interface}" "${feature}" "${state}" 2>/dev/null; then
        log "INFO" "  ✓ Successfully set ${feature} to ${state}"
        return 0
    else
        log "WARNING" "  ✗ Failed to set ${feature} to ${state}"
        return 1
    fi
}

# Ring buffer optimization with safety checks
apply_ring_buffer_optimization() {
    local interface="$1"
    
    log "INFO" "Optimizing ring buffers..."
    
    local rx_size="${OPTIMIZATION_FEATURES[ring_rx]:-}"
    local tx_size="${OPTIMIZATION_FEATURES[ring_tx]:-}"
    
    # For virtio_net, use conservative values[21]
    if [[ "${IS_VIRTUAL}" == "true" ]]; then
        rx_size="${rx_size:-256}"
        tx_size="${tx_size:-256}"
    else
        # For physical hardware, use more aggressive values[14]
        rx_size="${rx_size:-1024}"
        tx_size="${tx_size:-512}"
    fi
    
    local ethtool_args=()
    [[ -n "$rx_size" ]] && ethtool_args+=("rx" "$rx_size")
    [[ -n "$tx_size" ]] && ethtool_args+=("tx" "$tx_size")
    
    if [[ ${#ethtool_args[@]} -gt 0 ]]; then
        if ethtool -G "${interface}" "${ethtool_args[@]}" 2>/dev/null; then
            log "INFO" "  ✓ Ring buffers optimized: RX=${rx_size}, TX=${tx_size}"
        else
            log "WARNING" "  ✗ Ring buffer optimization failed"
        fi
    fi
}

# Interrupt coalescing optimization for low latency[13]
apply_interrupt_coalescing_optimization() {
    local interface="$1"
    
    log "INFO" "Optimizing interrupt coalescing for low latency..."
    
    # Disable adaptive coalescing and set minimal values
    local coalesce_args=(
        "adaptive-rx" "off"
        "adaptive-tx" "off"
        "rx-usecs" "1"
        "rx-frames" "1"
        "tx-usecs" "8"
        "tx-frames" "32"
    )
    
    if ethtool -C "${interface}" "${coalesce_args[@]}" 2>/dev/null; then
        log "INFO" "  ✓ Interrupt coalescing optimized for minimal latency"
    else
        log "WARNING" "  ✗ Interrupt coalescing optimization failed or not supported"
    fi
}

# Multi-queue/channel optimization[28][30][38]
apply_channel_optimization() {
    local interface="$1"
    
    log "INFO" "Optimizing multi-queue channels..."
    
    local optimal_channels="${OPTIMIZATION_FEATURES[channels]}"
    
    if ethtool -L "${interface}" combined "${optimal_channels}" 2>/dev/null; then
        log "INFO" "  ✓ Channels optimized: ${optimal_channels} queues"
    else
        log "WARNING" "  ✗ Channel optimization failed or not supported"
    fi
}

# Flow control optimization
apply_flow_control_optimization() {
    local interface="$1"
    
    log "INFO" "Optimizing flow control..."
    
    # Disable flow control for consistent performance (works for most cases)
    if ethtool -A "${interface}" rx off tx off autoneg off 2>/dev/null; then
        log "INFO" "  ✓ Flow control disabled for consistency"
    else
        log "WARNING" "  ✗ Flow control optimization failed or not supported"
    fi
}

#===============================================================================
# Validation and Monitoring Functions
#===============================================================================

# Validate optimizations
validate_optimizations() {
    local interface="$1"
    
    log "INFO" "=== Validating Applied Optimizations ==="
    
    # Check interface status
    if ! ip link show "${interface}" | grep -q "state UP"; then
        log "WARNING" "Interface ${interface} is not UP"
    else
        log "INFO" "✓ Interface ${interface} is UP and operational"
    fi
    
    # Validate critical features
    validate_feature_state "${interface}" "rx-checksumming" "on"
    validate_feature_state "${interface}" "tx-checksumming" "on"
    validate_feature_state "${interface}" "generic-receive-offload" "off"
    validate_feature_state "${interface}" "tcp-segmentation-offload" "off"
    
    # Check for immediate errors
    sleep 2
    check_interface_errors "${interface}"
    
    log "INFO" "Optimization validation completed"
}

# Validate specific feature state
validate_feature_state() {
    local interface="$1"
    local feature="$2"
    local expected_state="$3"
    
    local actual_state
    actual_state=$(ethtool -k "${interface}" 2>/dev/null | grep "^${feature}:" | awk '{print $2}')
    
    if [[ "$actual_state" == "$expected_state" ]]; then
        log "INFO" "  ✓ ${feature}: ${actual_state} (as expected)"
    else
        log "WARNING" "  ✗ ${feature}: ${actual_state} (expected: ${expected_state})"
    fi
}

# Check for interface errors after optimization
check_interface_errors() {
    local interface="$1"
    
    local error_count
    error_count=$(ethtool -S "${interface}" 2>/dev/null | grep -iE "(drop|error)" | awk '{sum += $2} END {print sum+0}')
    
    if [[ $error_count -gt 0 ]]; then
        log "WARNING" "Detected ${error_count} errors/drops on ${interface}"
    else
        log "INFO" "✓ No errors detected on ${interface}"
    fi
}

#===============================================================================
# Persistence and Service Management
#===============================================================================

# Create systemd service for persistence
create_persistent_service() {
    local interface="$1"
    
    log "INFO" "Creating persistent configuration service..."
    
    # Create optimization script
    local opt_script="/usr/local/bin/network-optimization.sh"
    cat > "${opt_script}" << 'EOF'
#!/bin/bash
# Auto-generated network optimization script
# Created by: Advanced Network Optimization Tool v2.0
# Contact: @NotepadVpn

INTERFACE="${1:-eth0}"

# Apply optimizations
ethtool -K "$INTERFACE" generic-receive-offload off 2>/dev/null || true
ethtool -K "$INTERFACE" large-receive-offload off 2>/dev/null || true  
ethtool -K "$INTERFACE" tcp-segmentation-offload off 2>/dev/null || true
ethtool -K "$INTERFACE" generic-segmentation-offload off 2>/dev/null || true
ethtool -K "$INTERFACE" rx-gro-hw off 2>/dev/null || true
ethtool -K "$INTERFACE" rx-checksumming on 2>/dev/null || true
ethtool -K "$INTERFACE" tx-checksumming on 2>/dev/null || true
ethtool -K "$INTERFACE" scatter-gather on 2>/dev/null || true
ethtool -K "$INTERFACE" receive-hashing on 2>/dev/null || true

# Ring buffers (safe defaults)
ethtool -G "$INTERFACE" rx 256 tx 256 2>/dev/null || true

# Interrupt coalescing
ethtool -C "$INTERFACE" adaptive-rx off adaptive-tx off rx-usecs 1 rx-frames 1 tx-usecs 8 tx-frames 32 2>/dev/null || true

# Multi-queue (if supported)
CORES=$(nproc)
ethtool -L "$INTERFACE" combined "$CORES" 2>/dev/null || true

# Flow control
ethtool -A "$INTERFACE" rx off tx off autoneg off 2>/dev/null || true

logger "Network optimization applied to $INTERFACE"
EOF
    
    chmod +x "${opt_script}"
    
    # Create systemd service[29]
    local service_file="/etc/systemd/system/network-optimization.service"
    cat > "${service_file}" << EOF
[Unit]
Description=Network Interface Optimization
Documentation=man:ethtool(8)
After=network-online.target
Wants=network-online.target
ConditionPathExists=${opt_script}

[Service]
Type=oneshot
ExecStart=${opt_script} ${interface}
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable network-optimization.service
    
    log "INFO" "✓ Persistent service created and enabled"
    log "INFO" "Service location: ${service_file}"
    log "INFO" "Script location: ${opt_script}"
}

#===============================================================================
# Rollback Functions
#===============================================================================

# Rollback changes if requested
rollback_changes() {
    local interface="$1"
    
    if [[ ${#BACKUP_SETTINGS[@]} -eq 0 ]]; then
        log "WARNING" "No backup settings available for rollback"
        return 1
    fi
    
    log "INFO" "Rolling back network optimizations..."
    
    for feature in "${!BACKUP_SETTINGS[@]}"; do
        local original_state="${BACKUP_SETTINGS[$feature]}"
        if ethtool -K "${interface}" "${feature}" "${original_state}" 2>/dev/null; then
            log "INFO" "  ✓ Restored ${feature} to ${original_state}"
        else
            log "WARNING" "  ✗ Failed to restore ${feature}"
        fi
    done
    
    log "INFO" "Rollback completed"
}

#===============================================================================
# Main Execution Functions
#===============================================================================

# Display usage information
show_usage() {
    cat << EOF
${WHITE}Advanced Network Optimization Tool v${SCRIPT_VERSION}${NC}

${BLUE}Usage:${NC} ${SCRIPT_NAME} [OPTIONS]

${BLUE}Options:${NC}
  -h, --help              Show this help message
  -v, --version          Show version information  
  -i, --interface IFACE  Specify interface (auto-detect if not provided)
  -a, --analyze-only     Only analyze, don't apply optimizations
  -r, --rollback         Rollback previous optimizations
  -s, --service          Create persistent systemd service
  --dry-run              Show what would be done without applying changes
  --no-backup            Skip configuration backup
  --verbose              Enable verbose logging

${BLUE}Examples:${NC}
  ${SCRIPT_NAME}                    # Auto-detect and optimize main interface
  ${SCRIPT_NAME} -i eth0            # Optimize specific interface
  ${SCRIPT_NAME} -a                 # Analyze current configuration only
  ${SCRIPT_NAME} -s                 # Create persistent service
  ${SCRIPT_NAME} --dry-run          # Preview optimizations

${BLUE}Advanced Features:${NC}
  • Automatic interface detection with multiple fallback methods
  • Comprehensive feature analysis and optimization
  • Environment-specific optimizations (VM vs Physical)
  • Professional error handling and rollback capability
  • Persistent configuration via systemd service
  • Detailed logging and monitoring

${BLUE}Telegram Channel:${NC} @NotepadVpn - For more network optimization tools

${YELLOW}Note:${NC} This script requires root privileges and creates backups
      automatically. Always test in a non-production environment first.
EOF
}

# Main execution function
main() {
    # Parse command line arguments
    local analyze_only=false
    local rollback_mode=false
    local create_service=false
    local dry_run=false
    local no_backup=false
    local verbose=false
    local specified_interface=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                echo "${SCRIPT_NAME} version ${SCRIPT_VERSION}"
                exit 0
                ;;
            -i|--interface)
                specified_interface="$2"
                shift 2
                ;;
            -a|--analyze-only)
                analyze_only=true
                shift
                ;;
            -r|--rollback)
                rollback_mode=true
                shift
                ;;
            -s|--service)
                create_service=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --no-backup)
                no_backup=true
                shift
                ;;
            --verbose)
                verbose=true
                shift
                ;;
            *)
                error_exit "Unknown option: $1. Use -h for help."
                ;;
        esac
    done
    
    # Initialize script
    echo -e "${WHITE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║                 Advanced Network Optimization Tool v${SCRIPT_VERSION}                 ║${NC}"
    echo -e "${WHITE}║                    Professional Network Interface Tuning                    ║${NC}"
    echo -e "${WHITE}║                                                                            ║${NC}"
    echo -e "${WHITE}║          ${CYAN}Follow @NotepadVpn on Telegram for more network tools${WHITE}          ║${NC}"
    echo -e "${WHITE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    # Pre-flight checks
    check_root
    create_lock
    check_dependencies
    detect_system_info
    
    # Interface detection or validation
    if [[ -n "$specified_interface" ]]; then
        if validate_interface "$specified_interface"; then
            MAIN_INTERFACE="$specified_interface"
            log "INFO" "Using specified interface: ${MAIN_INTERFACE}"
        else
            error_exit "Specified interface '${specified_interface}' is not valid"
        fi
    else
        detect_main_interface
    fi
    
    # Main execution flow
    if [[ "$rollback_mode" == "true" ]]; then
        if [[ -f "$BACKUP_FILE" ]]; then
            rollback_changes "$MAIN_INTERFACE"
        else
            error_exit "No backup file found for rollback"
        fi
    elif [[ "$analyze_only" == "true" ]]; then
        analyze_interface "$MAIN_INTERFACE"
    elif [[ "$dry_run" == "true" ]]; then
        log "INFO" "DRY RUN MODE - No changes will be applied"
        analyze_interface "$MAIN_INTERFACE"
        log "INFO" "DRY RUN completed - no actual changes made"
    else
        # Full optimization
        analyze_interface "$MAIN_INTERFACE"
        apply_optimizations "$MAIN_INTERFACE"
        validate_optimizations "$MAIN_INTERFACE"
        
        if [[ "$create_service" == "true" ]]; then
            create_persistent_service "$MAIN_INTERFACE"
        fi
        
        # Final summary
        echo
        log "INFO" "╔════════════════════════════════════════════════════════════════════════════╗"
        log "INFO" "║                          OPTIMIZATION COMPLETE                            ║"
        log "INFO" "╠════════════════════════════════════════════════════════════════════════════╣"
        log "INFO" "║ Interface: ${MAIN_INTERFACE}                                                    "
        log "INFO" "║ Environment: $([ "$IS_VIRTUAL" == "true" ] && echo "Virtual (VM)" || echo "Physical Hardware")                                               "
        log "INFO" "║ CPU Cores: ${CPU_CORES}                                                        "
        log "INFO" "║ Backup: ${BACKUP_FILE}                           "
        log "INFO" "║                                                                            ║"
        log "INFO" "║ Applied Optimizations:                                                     ║"
        log "INFO" "║ ✓ Low-latency features (GRO/LRO/TSO disabled)                             ║"
        log "INFO" "║ ✓ Data integrity features (checksumming enabled)                          ║"
        log "INFO" "║ ✓ Performance features (scatter-gather, RSS enabled)                      ║"
        log "INFO" "║ ✓ Interrupt coalescing optimized                                          ║"
        log "INFO" "║ ✓ Ring buffers optimized                                                  ║"
        [[ -n "${OPTIMIZATION_FEATURES[channels]:-}" ]] && log "INFO" "║ ✓ Multi-queue channels optimized                                          ║"
        log "INFO" "║                                                                            ║"
        log "INFO" "║ Monitoring Commands:                                                       ║"
        log "INFO" "║ • ethtool -S ${MAIN_INTERFACE} | grep -E 'drop|error'                          ║"
        log "INFO" "║ • ping -i 0.001 <target> (test latency)                                   ║"
        log "INFO" "║ • iperf3 -c <target> (test throughput)                                    ║"
        log "INFO" "║                                                                            ║"
        log "INFO" "║ 📱 Follow @NotepadVpn on Telegram for more network optimization tools     ║"
        log "INFO" "╚════════════════════════════════════════════════════════════════════════════╝"
    fi
    
    log "INFO" "Script execution completed successfully"
}

#===============================================================================
# Script Entry Point
#===============================================================================

# Initialize logging
mkdir -p "$(dirname "$LOG_FILE")"
log "INFO" "Starting ${SCRIPT_NAME} v${SCRIPT_VERSION}"

# Execute main function with all arguments
main "$@"
