#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Core Configuration System
# Advanced configuration management for bug bounty reconnaissance
# =============================================================================

# Version and metadata
export NINA_VERSION="2.0.0"
export NINA_BUILD_DATE="2024-12-19"
export NINA_DESCRIPTION="Advanced Bug Bounty Reconnaissance Framework"

# =============================================================================
# COLOR DEFINITIONS
# =============================================================================

export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export WHITE='\033[1;37m'
export GRAY='\033[0;37m'
export BOLD='\033[1m'
export NC='\033[0m' # No Color

# =============================================================================
# CORE DIRECTORIES AND PATHS
# =============================================================================

# Core NINA directories
export DIR_NINA="${DIR_NINA:-/root/nina}"
export DIR_NINA_LOG="${DIR_NINA_LOG:-${DIR_NINA}/log}"
export DIR_NINA_TEMPLATES="${DIR_NINA_TEMPLATES:-${DIR_NINA}/templates}"
export DIR_NINA_LISTS="${DIR_NINA_LISTS:-${DIR_NINA}/lists}"
export DIR_NINA_CREDS="${DIR_NINA_CREDS:-${DIR_NINA}/creds}"
export DIR_NINA_TOOLS="${DIR_NINA_TOOLS:-${DIR_NINA}/tools}"

# Output and working directories
export DIR_OUTPUT="${DIR_OUTPUT:-/root/out}"
export DIR_WORK="${DIR_WORK:-/tmp/nina-work}"

# Modules directory
export DIR_MODULES="$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

# Configuration directory
export NINA_CONFIG_DIR="${NINA_CONFIG_DIR:-$HOME/.nina}"

# =============================================================================
# TOOL CONFIGURATION AND OPTIMIZATION
# =============================================================================

# HTTP/HTTPS probing settings
export HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-5}"
export HTTPX_RETRIES="${HTTPX_RETRIES:-2}"
export HTTPX_THREADS="${HTTPX_THREADS:-10000}"
export HTTPX_RATE_LIMIT="${HTTPX_RATE_LIMIT:-1000}"

# DNS resolution settings
export DNS_TIMEOUT="${DNS_TIMEOUT:-15}"
export DNS_THREADS="${DNS_THREADS:-5000}"
export DNS_RETRIES="${DNS_RETRIES:-3}"
export DNS_RESOLVERS="${DNS_RESOLVERS:-${DIR_NINA_LISTS}/resolvers.txt}"

# Subdomain enumeration settings
export SUBFINDER_TIMEOUT="${SUBFINDER_TIMEOUT:-20}"
export AMASS_TIMEOUT="${AMASS_TIMEOUT:-30}"
export ASSETFINDER_TIMEOUT="${ASSETFINDER_TIMEOUT:-15}"

# Bruteforce and active scanning settings
export SUBDOMAIN_BRUTEFORCE_LIMIT="${SUBDOMAIN_BRUTEFORCE_LIMIT:-100000}"
export PERMUTATION_LIMIT="${PERMUTATION_LIMIT:-50000}"
export WILDCARD_TESTS="${WILDCARD_TESTS:-100}"

# Nuclei vulnerability scanning settings
export NUCLEI_THREADS="${NUCLEI_THREADS:-500}"
export NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-1000}"
export NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-10}"
export NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-critical,high,medium,low}"
export NUCLEI_EXCLUDED="${NUCLEI_EXCLUDED:-expired-ssl,mismatched-ssl,deprecated-tls,weak-cipher-suites,self-signed-ssl}"

# Content discovery settings
export FUZZING_THREADS="${FUZZING_THREADS:-200}"
export FUZZING_TIMEOUT="${FUZZING_TIMEOUT:-10}"
export FUZZING_WORDLIST_LIMIT="${FUZZING_WORDLIST_LIMIT:-50000}"

# JavaScript analysis settings
export JS_ANALYSIS_TIMEOUT="${JS_ANALYSIS_TIMEOUT:-30}"
export JS_DOWNLOAD_LIMIT="${JS_DOWNLOAD_LIMIT:-100}"

# Notification settings (using ProjectDiscovery's notify)
export NOTIFY_ENABLED="${NOTIFY_ENABLED:-true}"
export NOTIFY_PROVIDER_ID="${NOTIFY_PROVIDER_ID:-nina-result}"
export NOTIFY_CONFIG="${NOTIFY_CONFIG:-$HOME/.config/notify/provider-config.yaml}"

# =============================================================================
# OPTIMIZATION PROFILES
# =============================================================================

# Quick profile (30-60 minutes)
if [[ "${SCAN_PROFILE:-}" == "quick" ]]; then
    export HTTPX_THREADS=1000
    export DNS_THREADS=1000
    export SUBFINDER_TIMEOUT=10
    export SUBDOMAIN_BRUTEFORCE_LIMIT=10000
    export NUCLEI_THREADS=100
    export FUZZING_THREADS=50
fi

# Deep profile (8+ hours)
if [[ "${SCAN_PROFILE:-}" == "deep" ]]; then
    export HTTPX_THREADS=50000
    export DNS_THREADS=10000
    export SUBFINDER_TIMEOUT=30
    export SUBDOMAIN_BRUTEFORCE_LIMIT=500000
    export NUCLEI_THREADS=1000
    export FUZZING_THREADS=500
fi

# =============================================================================
# WORDLISTS AND RESOURCES
# =============================================================================

# Main wordlists
export WORDLIST_SUBDOMAINS="${DIR_NINA_LISTS}/wordlist-base-subs.txt"
export WORDLIST_DIRECTORIES="${DIR_NINA_LISTS}/httparchive_directories_1m_2024_05_28.txt"
export WORDLIST_FILES="${DIR_NINA_LISTS}/paths.txt"
export WORDLIST_PARAMETERS="${DIR_NINA_LISTS}/params.txt"
export WORDLIST_MUTATIONS="${DIR_NINA_LISTS}/permutations_list.txt"

# Specialized wordlists
export WORDLIST_API="${DIR_NINA_LISTS}/api.txt"
export WORDLIST_ADMIN="${DIR_NINA_LISTS}/admin.txt"
export WORDLIST_BACKUP="${DIR_NINA_LISTS}/backup.txt"
export WORDLIST_CONFIG="${DIR_NINA_LISTS}/config.txt"

# Templates and patterns
export NUCLEI_TEMPLATES="${DIR_NINA_TEMPLATES}/nuclei"
export GF_PATTERNS="${DIR_NINA_TEMPLATES}/gf"

# =============================================================================
# NOTIFICATION AND INTEGRATION SETTINGS
# =============================================================================

# Notification settings
export NOTIFY_CONFIG="${DIR_NINA_CREDS}/provider-config-notify.yaml"
export SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
export DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"

# API keys and credentials
export GITHUB_TOKEN_FILE="${DIR_NINA_CREDS}/github.txt"
export SHODAN_API_KEY_FILE="${DIR_NINA_CREDS}/shodan.txt"
export SECURITYTRAILS_API_KEY_FILE="${DIR_NINA_CREDS}/securitytrails.txt"
export WHOISXML_API_KEY_FILE="${DIR_NINA_CREDS}/whoisxml.txt"

# =============================================================================
# ADVANCED OPTIMIZATION SETTINGS
# =============================================================================

# Memory and performance optimization
export GOLANG_MAX_PROCS="${GOLANG_MAX_PROCS:-0}"  # Auto-detect
export ULIMIT_NOFILE="${ULIMIT_NOFILE:-65536}"    # File descriptor limit
export TMPDIR="${TMPDIR:-/tmp}"

# Retry and error handling
export MAX_RETRIES="${MAX_RETRIES:-3}"
export RETRY_DELAY="${RETRY_DELAY:-5}"
export IGNORE_ERRORS="${IGNORE_ERRORS:-false}"

# =============================================================================
# SCOPE-SPECIFIC OPTIMIZATIONS
# =============================================================================

configure_for_closed_scope() {
    log_message "Configuring for closed scope optimization"
    export HTTPX_THREADS=1000
    export DNS_THREADS=500
    export SUBDOMAIN_BRUTEFORCE_LIMIT=10000
    export FOCUS_DEEP_ANALYSIS=true
    export ENABLE_PARAMETER_DISCOVERY=true
    export ENABLE_ADVANCED_FUZZING=true
}

configure_for_wildcard_scope() {
    log_message "Configuring for wildcard scope optimization"
    export HTTPX_THREADS=50000
    export DNS_THREADS=10000
    export SUBDOMAIN_BRUTEFORCE_LIMIT=200000
    export FOCUS_SUBDOMAIN_DISCOVERY=true
    export ENABLE_SUBDOMAIN_MUTATIONS=true
    export ENABLE_AGGRESSIVE_ENUMERATION=true
}

configure_for_open_scope() {
    log_message "Configuring for open scope optimization"
    export HTTPX_THREADS=20000
    export DNS_THREADS=5000
    export SUBDOMAIN_BRUTEFORCE_LIMIT=100000
    export FOCUS_BALANCED=true
    export ENABLE_MULTI_DOMAIN_ANALYSIS=true
}

# =============================================================================
# NOTIFICATION FUNCTIONS
# =============================================================================

# Check if notify tool is available and configured
check_notify_setup() {
    if [[ "$NOTIFY_ENABLED" != "true" ]]; then
        return 1
    fi
    
    if ! command -v notify >/dev/null 2>&1; then
        log_warning "notify tool not found. Install with: go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
        return 1
    fi
    
    if [[ ! -f "$NOTIFY_CONFIG" ]]; then
        log_warning "notify config not found at: $NOTIFY_CONFIG"
        log_info "Create config with your Telegram settings"
        return 1
    fi
    
    return 0
}

# Send notification using notify
send_notification() {
    local message="$1"
    local priority="${2:-info}"  # info, success, warning, error
    
    # Debug logging
    if [[ "${DEBUG_NOTIFY:-false}" == "true" ]]; then
        log_info "DEBUG: send_notification called with message: $message"
        log_info "DEBUG: NOTIFY_ENABLED=$NOTIFY_ENABLED"
        log_info "DEBUG: NOTIFY_CONFIG=$NOTIFY_CONFIG"
        log_info "DEBUG: NOTIFY_PROVIDER_ID=$NOTIFY_PROVIDER_ID"
    fi
    
    if ! check_notify_setup; then
        if [[ "${DEBUG_NOTIFY:-false}" == "true" ]]; then
            log_warning "DEBUG: check_notify_setup failed"
        fi
        return 0
    fi
    
    # Add emoji based on priority
    local emoji=""
    case "$priority" in
        "success") emoji="✅" ;;
        "warning") emoji="⚠️" ;;
        "error") emoji="❌" ;;
        "info") emoji="ℹ️" ;;
        "start") emoji="🚀" ;;
        "progress") emoji="⏳" ;;
        "complete") emoji="🎯" ;;
        *) emoji="📢" ;;
    esac
    
    # Format message for Telegram
    local formatted_message="${emoji} **NINA Recon**\n\n${message}"
    
    # Debug logging
    if [[ "${DEBUG_NOTIFY:-false}" == "true" ]]; then
        log_info "DEBUG: Sending notification with command:"
        log_info "DEBUG: echo -e \"$formatted_message\" | notify -provider-config \"$NOTIFY_CONFIG\" -id \"$NOTIFY_PROVIDER_ID\""
    fi
    
    # Send notification
    local notify_result=0
    echo -e "$formatted_message" | notify -provider-config "$NOTIFY_CONFIG" -id "$NOTIFY_PROVIDER_ID" 2>&1 || notify_result=$?
    
    if [[ $notify_result -ne 0 ]]; then
        log_warning "Failed to send notification (exit code: $notify_result)"
        if [[ "${DEBUG_NOTIFY:-false}" == "true" ]]; then
            log_warning "DEBUG: Check if notify tool is working: echo 'test' | notify -id $NOTIFY_PROVIDER_ID"
        fi
    elif [[ "${DEBUG_NOTIFY:-false}" == "true" ]]; then
        log_info "DEBUG: Notification sent successfully"
    fi
}

# Notification shortcuts for different types
notify_start() {
    local domain="$1"
    local profile="$2"
    send_notification "🚀 **Scan Started**\n\nTarget: \`${domain}\`\nProfile: \`${profile}\`\nTime: \`$(date '+%Y-%m-%d %H:%M:%S')\`" "start"
}

notify_progress() {
    local domain="$1"
    local module="$2"
    local status="$3"
    send_notification "⏳ **Progress Update**\n\nTarget: \`${domain}\`\nModule: \`${module}\`\nStatus: ${status}" "progress"
}

notify_module_complete() {
    local domain="$1"
    local module="$2"
    local results="$3"
    send_notification "✅ **Module Complete**\n\nTarget: \`${domain}\`\nModule: \`${module}\`\nResults: ${results}" "success"
}

notify_vulnerability_found() {
    local domain="$1"
    local vuln_type="$2"
    local count="$3"
    send_notification "🚨 **Vulnerabilities Found**\n\nTarget: \`${domain}\`\nType: \`${vuln_type}\`\nCount: \`${count}\`" "warning"
}

notify_scan_complete() {
    local domain="$1"
    local stats="$2"
    local duration="$3"
    send_notification "🎯 **Scan Complete**\n\nTarget: \`${domain}\`\nDuration: \`${duration}\`\n\n${stats}" "complete"
}

notify_error() {
    local domain="$1"
    local error_msg="$2"
    send_notification "❌ **Error Occurred**\n\nTarget: \`${domain}\`\nError: ${error_msg}" "error"
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log_message() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${GREEN}[+]${NC} ${timestamp} - ${message}"
    
    # Log to file if domain is set
    if [[ -n "${DOMAIN:-}" ]]; then
        local log_dir="${DIR_OUTPUT}/${DOMAIN}/log"
        mkdir -p "$log_dir" 2>/dev/null
        echo "[+] ${timestamp} - ${message}" >> "${log_dir}/log.txt" 2>/dev/null || true
    fi
}

log_error() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${RED}[!]${NC} ${timestamp} - ${message}" >&2
    
    # Log to file if domain is set
    if [[ -n "${DOMAIN:-}" ]]; then
        local log_dir="${DIR_OUTPUT}/${DOMAIN}/log"
        mkdir -p "$log_dir" 2>/dev/null
        echo "[!] ${timestamp} - ${message}" >> "${log_dir}/log.txt" 2>/dev/null || true
    fi
}

log_warning() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${YELLOW}[*]${NC} ${timestamp} - ${message}"
    
    # Log to file if domain is set
    if [[ -n "${DOMAIN:-}" ]]; then
        local log_dir="${DIR_OUTPUT}/${DOMAIN}/log"
        mkdir -p "$log_dir" 2>/dev/null
        echo "[*] ${timestamp} - ${message}" >> "${log_dir}/log.txt" 2>/dev/null || true
    fi
}

log_info() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${BLUE}[i]${NC} ${timestamp} - ${message}"
    
    # Log to file if domain is set
    if [[ -n "${DOMAIN:-}" ]]; then
        local log_dir="${DIR_OUTPUT}/${DOMAIN}/log"
        mkdir -p "$log_dir" 2>/dev/null
        echo "[i] ${timestamp} - ${message}" >> "${log_dir}/log.txt" 2>/dev/null || true
    fi
}

# Progress indicator
show_progress() {
    local current="$1"
    local total="$2"
    local description="$3"
    local percentage=$((current * 100 / total))
    local bar_length=30
    local filled_length=$((percentage * bar_length / 100))
    
    local bar=""
    for ((i=0; i<filled_length; i++)); do bar+="█"; done
    for ((i=filled_length; i<bar_length; i++)); do bar+="░"; done
    
    printf "\r${CYAN}[%s]${NC} %3d%% %s" "$bar" "$percentage" "$description"
    
    if [[ $current -eq $total ]]; then
        echo ""
    fi
}

# Notification functions
notify_slack() {
    local message="$1"
    if [[ -n "${SLACK_WEBHOOK:-}" ]]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
    elif command -v notify &> /dev/null; then
        echo "$message" | notify -silent -id nina-recon 2>/dev/null || true
    fi
}

notify_discord() {
    local message="$1"
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"content\":\"$message\"}" \
            "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
    fi
}

# Tool availability checking
tool_available() {
    command -v "$1" &> /dev/null
}

check_required_tools() {
    local required_tools=(
        "curl" "jq" "grep" "awk" "sed" "sort" "uniq" "wc"
        "subfinder" "httpx" "nuclei" "waybackurls" "gau"
    )
    
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! tool_available "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install missing tools before running NINA"
        return 1
    fi
    
    return 0
}

# File operations with safety checks
safe_anew() {
    local content="$1"
    local file="$2"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$file")" 2>/dev/null
    
    if tool_available anew; then
        echo "$content" | anew -q "$file" 2>/dev/null || true
    else
        echo "$content" >> "$file" 2>/dev/null
        sort -u "$file" -o "$file" 2>/dev/null || true
    fi
}

file_anew() {
    local input_file="$1"
    local output_file="$2"
    
    if [[ -f "$input_file" ]]; then
        mkdir -p "$(dirname "$output_file")" 2>/dev/null
        
        if tool_available anew; then
            cat "$input_file" | anew -q "$output_file" 2>/dev/null || true
        else
            cat "$input_file" >> "$output_file" 2>/dev/null
            sort -u "$output_file" -o "$output_file" 2>/dev/null || true
        fi
    fi
}

# Domain validation
validate_domain() {
    if [[ -z "${DOMAIN:-}" ]]; then
        log_error "Domain not specified"
        return 1
    fi
    
    # Basic domain validation
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "Invalid domain format: $DOMAIN"
        return 1
    fi
    
    return 0
}

# System requirements check
check_requirements() {
    log_info "Checking system requirements"
    
    # Check tools
    if ! check_required_tools; then
        return 1
    fi
    
    # Check directories
    local required_dirs=("$DIR_NINA" "$DIR_OUTPUT")
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_warning "Creating directory: $dir"
            mkdir -p "$dir" 2>/dev/null || {
                log_error "Failed to create directory: $dir"
                return 1
            }
        fi
    done
    
    # Check file descriptor limit
    local current_limit=$(ulimit -n)
    if [[ $current_limit -lt $ULIMIT_NOFILE ]]; then
        log_warning "Current file descriptor limit ($current_limit) is low"
        log_warning "Consider increasing it: ulimit -n $ULIMIT_NOFILE"
    fi
    
    # Check disk space (require at least 1GB free)
    local available_space=$(df "$DIR_OUTPUT" | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 1048576 ]]; then  # 1GB in KB
        log_warning "Low disk space available in $DIR_OUTPUT"
        log_warning "Consider freeing up space for optimal performance"
    fi
    
    log_info "System requirements check completed"
    return 0
}

# Configuration loading
load_custom_config() {
    local config_file="$1"
    
    if [[ -f "$config_file" ]]; then
        log_info "Loading custom configuration: $config_file"
        source "$config_file"
        return 0
    fi
    
    # Try user config directory
    local user_config="${NINA_CONFIG_DIR}/config.conf"
    if [[ -f "$user_config" ]]; then
        log_info "Loading user configuration: $user_config"
        source "$user_config"
        return 0
    fi
    
    return 1
}

# Module information display
show_module_info() {
    local module_name="$1"
    local module_description="$2"
    
    echo -e "${CYAN}╭─ ${module_name}${NC}"
    echo -e "${CYAN}│${NC}  ${module_description}"
    echo -e "${CYAN}│${NC}  Domain: ${YELLOW}${DOMAIN}${NC}"
    echo -e "${CYAN}│${NC}  Output: ${YELLOW}${DIR_OUTPUT}/${DOMAIN}${NC}"
    echo -e "${CYAN}│${NC}  Scope: ${YELLOW}${SCOPE_TYPE:-auto}${NC}"
    echo -e "${CYAN}╰─${NC}"
}

# Commit step function for tracking
commit_step() {
    local step_name="$1"
    if [[ -f "${DIR_NINA_TOOLS}/commit-steps.sh" ]]; then
        bash "${DIR_NINA_TOOLS}/commit-steps.sh" "${DOMAIN}" "${step_name}" 2>/dev/null || true
    fi
    log_info "Step completed: ${step_name}"
}

# =============================================================================
# INITIALIZATION AND VALIDATION
# =============================================================================

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo -e "${RED}Error: This file should be sourced, not executed directly${NC}"
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Export all functions for use in modules
export -f log_message log_error log_warning log_info show_progress
export -f notify_slack notify_discord tool_available check_required_tools
export -f safe_anew file_anew validate_domain check_requirements
export -f load_custom_config show_module_info commit_step
export -f configure_for_closed_scope configure_for_wildcard_scope configure_for_open_scope

# Initialize configuration
log_info "NINA Recon Optimized v${NINA_VERSION} configuration loaded"

# Apply ulimit if we can
if [[ $EUID -eq 0 ]] || groups | grep -q sudo; then
    ulimit -n "$ULIMIT_NOFILE" 2>/dev/null || true
fi

# =============================================================================
# SMART FILE CREATION
# =============================================================================

# Salva arquivo apenas se não estiver vazio
smart_save() {
    local temp_file="$1"
    local output_file="$2" 
    local description="${3:-data}"
    
    if [[ -s "$temp_file" ]]; then
        mv "$temp_file" "$output_file"
        local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
        log_info "💾 Saved $count lines of $description"
        return 0
    else
        rm -f "$temp_file" 2>/dev/null
        log_info "📭 No $description found - skipping file creation"
        return 1
    fi
}

# Processa múltiplos arquivos e salva apenas se houver resultado
smart_combine() {
    local output_file="${@: -1}"
    local input_files=("${@:1:$#-1}")
    local temp_file="${output_file}.tmp"
    
    cat "${input_files[@]}" 2>/dev/null | grep -v '^$' | sort -u > "$temp_file"
    smart_save "$temp_file" "$output_file" "combined results"
}

# Executa comando e salva apenas se houver saída
smart_run() {
    local command="$1"
    local output_file="$2"
    local description="${3:-command output}"
    local temp_file="${output_file}.tmp"
    
    eval "$command" > "$temp_file" 2>/dev/null
    smart_save "$temp_file" "$output_file" "$description"
}

