#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Advanced Bug Bounty Reconnaissance Framework
# Modular, efficient, and optimized for closed scopes and wildcard programs
# =============================================================================

VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source configuration and core modules
source "${SCRIPT_DIR}/modules/core/config.sh" || {
    echo "Error: Failed to load configuration. Please run setup first."
    exit 1
}

# =============================================================================
# GLOBAL SETTINGS AND OPTIMIZATIONS
# =============================================================================

# Performance optimizations
export HTTPX_THREADS=50000
export DNS_THREADS=10000
export SUBFINDER_TIMEOUT=15
export AMASS_TIMEOUT=30
export NUCLEI_RATE_LIMIT=1000

# Wildcard optimization settings
export WILDCARD_TESTS=100
export SUBDOMAIN_BRUTEFORCE_LIMIT=100000
export PERMUTATION_LIMIT=50000

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

show_banner() {
    if [[ "${QUIET_MODE:-false}" != "true" ]]; then
        cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║    ███╗   ██╗██╗███╗   ██╗ █████╗     ██████╗ ███████╗ ██████╗    ║
║    ████╗  ██║██║████╗  ██║██╔══██╗    ██╔══██╗██╔════╝██╔════╝    ║
║    ██╔██╗ ██║██║██╔██╗ ██║███████║    ██████╔╝█████╗  ██║         ║
║    ██║╚██╗██║██║██║╚██╗██║██╔══██║    ██╔══██╗██╔══╝  ██║         ║
║    ██║ ╚████║██║██║ ╚████║██║  ██║    ██║  ██║███████╗╚██████╗    ║
║    ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝    ║
║                                                                   ║
║            OPTIMIZED - Advanced Bug Bounty Framework              ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

EOF
        echo -e "${CYAN}Version: ${VERSION}${NC}"
        echo -e "${CYAN}Optimized for: Closed scopes & Wildcard programs${NC}"
        echo ""
    fi
}

show_help() {
    cat << 'EOF'
NINA RECON OPTIMIZED - Advanced Bug Bounty Reconnaissance Framework

USAGE:
    nina-recon.sh [OPTIONS] [DOMAIN]

OPTIONS:
    -d, --domain DOMAIN         Target domain for reconnaissance
    -s, --scope SCOPE_TYPE      Scope type: closed, wildcard, open (default: auto)
    -p, --profile PROFILE       Run predefined profile: quick, standard, deep
    -m, --modules MODULES       Comma-separated list of modules to run
    -c, --config FILE           Custom configuration file
    -o, --output DIR            Output directory (default: /root/out)
    -t, --threads NUM           Number of threads (default: auto)
    -w, --wordlist FILE         Custom wordlist for bruteforce
    -q, --quiet                 Suppress banner and minimize output
    --wildcard-check            Enable wildcard detection and mitigation
    --continuous                Enable continuous monitoring mode
    --notification              Enable Slack/Discord notifications
    -h, --help                  Show this help message
    -v, --version               Show version information

PROFILES:
    quick      - Fast reconnaissance (30-60 minutes)
                 • Passive recon + Basic HTTP probing
    standard   - Balanced approach (2-4 hours)  
                 • Passive + Active recon + Fuzzing + Basic vulns
    deep       - Comprehensive scan (8-12 hours)
                 • All modules + Advanced techniques + JS analysis

MODULES:
    setup      - Initialize directories and environment
    passive    - Passive reconnaissance (OSINT)
    active     - Active reconnaissance (DNS bruteforce)
    httpx      - HTTP probing and technology detection
    crawler    - Web crawling (Katana, Wayback, GAU)
    fuzzing    - Content fuzzing (FFUF, Feroxbuster, Gobuster)
    js         - JavaScript analysis and secrets extraction
    sensitive  - Sensitive files and endpoints discovery
    vulns      - Vulnerability scanning (Nuclei)
    monitor    - Continuous monitoring setup

SCOPE TYPES:
    closed     - Single subdomain or limited scope
                 • Optimized for deep analysis of specific targets
    wildcard   - Wildcard domain (*.example.com)
                 • Optimized for subdomain discovery and enumeration
    open       - Open scope with multiple domains
                 • Balanced approach for diverse targets

EXAMPLES:
    # Quick scan for closed scope
    ./nina-recon.sh -d api.example.com -s closed -p quick

    # Standard wildcard reconnaissance
    ./nina-recon.sh -d example.com -s wildcard -p standard

    # Deep scan with custom modules
    ./nina-recon.sh -d example.com -m passive,active,httpx,crawler,fuzzing

    # Continuous monitoring for specific domain
    ./nina-recon.sh -d example.com --continuous

    # Custom configuration and output
    ./nina-recon.sh -d example.com -c custom.conf -o /tmp/recon

CONFIGURATION:
    Configuration files are loaded from:
    1. Command line (-c option)
    2. ~/.nina/config.conf
    3. ./modules/core/config.sh (default)

ENVIRONMENT VARIABLES:
    NINA_CONFIG_DIR     - Configuration directory (default: ~/.nina)
    NINA_OUTPUT_DIR     - Default output directory
    NINA_THREADS        - Default thread count
    QUIET_MODE          - Suppress banner and verbose output

EOF
}

show_version() {
    echo "NINA Recon Optimized v${VERSION}"
    echo "Built for efficient bug bounty reconnaissance"
    echo ""
    echo "Dependencies:"
    check_tool_version "subfinder" "--version"
    check_tool_version "httpx" "-version" 
    check_tool_version "nuclei" "-version"
    check_tool_version "amass" "version"
}

check_tool_version() {
    local tool="$1"
    local version_flag="$2"
    
    if tool_available "$tool"; then
        local version_output
        version_output=$($tool $version_flag 2>/dev/null | head -1)
        echo "  ✓ $tool: $version_output"
    else
        echo "  ✗ $tool: Not installed"
    fi
}

# =============================================================================
# ARGUMENT PARSING AND VALIDATION
# =============================================================================

parse_arguments() {
    local domain=""
    local scope_type="auto"
    local profile=""
    local modules=""
    local config_file=""
    local output_dir=""
    local threads=""
    local wordlist=""
    local wildcard_check=false
    local continuous=false
    local notification=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                domain="$2"
                shift 2
                ;;
            -s|--scope)
                scope_type="$2"
                shift 2
                ;;
            -p|--profile)
                profile="$2"
                shift 2
                ;;
            -m|--modules)
                modules="$2"
                shift 2
                ;;
            -c|--config)
                config_file="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -t|--threads)
                threads="$2"
                shift 2
                ;;
            -w|--wordlist)
                wordlist="$2"
                shift 2
                ;;
            -q|--quiet)
                export QUIET_MODE=true
                shift
                ;;
            --wildcard-check)
                wildcard_check=true
                shift
                ;;
            --continuous)
                continuous=true
                shift
                ;;
            --notification)
                notification=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            *)
                if [[ -z "$domain" && ! "$1" =~ ^- ]]; then
                    domain="$1"
                else
                    log_error "Unknown option: $1"
                    echo "Use --help for usage information"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Export parsed arguments
    export TARGET_DOMAIN="$domain"
    export SCOPE_TYPE="$scope_type"
    export SCAN_PROFILE="$profile"
    export SELECTED_MODULES="$modules"
    export CONFIG_FILE="$config_file"
    export CUSTOM_OUTPUT_DIR="$output_dir"
    export CUSTOM_THREADS="$threads"
    export CUSTOM_WORDLIST="$wordlist"
    export WILDCARD_CHECK="$wildcard_check"
    export CONTINUOUS_MODE="$continuous"
    export NOTIFICATION_ENABLED="$notification"
}

validate_arguments() {
    # Validate domain
    if [[ -z "$TARGET_DOMAIN" ]]; then
        log_error "Domain is required. Use -d option or see --help"
        exit 1
    fi
    
    # Set DOMAIN for compatibility with existing modules
    export DOMAIN="$TARGET_DOMAIN"
    
    # Validate scope type
    if [[ "$SCOPE_TYPE" != "auto" ]] && [[ "$SCOPE_TYPE" != "closed" ]] && \
       [[ "$SCOPE_TYPE" != "wildcard" ]] && [[ "$SCOPE_TYPE" != "open" ]]; then
        log_error "Invalid scope type: $SCOPE_TYPE"
        log_error "Valid options: auto, closed, wildcard, open"
        exit 1
    fi
    
    # Validate profile
    if [[ -n "$SCAN_PROFILE" ]] && [[ "$SCAN_PROFILE" != "quick" ]] && \
       [[ "$SCAN_PROFILE" != "standard" ]] && [[ "$SCAN_PROFILE" != "deep" ]]; then
        log_error "Invalid profile: $SCAN_PROFILE"
        log_error "Valid options: quick, standard, deep"
        exit 1
    fi
    
    # Set output directory
    if [[ -n "$CUSTOM_OUTPUT_DIR" ]]; then
        export DIR_OUTPUT="$CUSTOM_OUTPUT_DIR"
    fi
    
    # Set custom threads
    if [[ -n "$CUSTOM_THREADS" ]]; then
        if [[ "$CUSTOM_THREADS" =~ ^[0-9]+$ ]] && [[ "$CUSTOM_THREADS" -gt 0 ]]; then
            export HTTPX_THREADS="$CUSTOM_THREADS"
            export DNS_THREADS="$CUSTOM_THREADS"
        else
            log_error "Invalid thread count: $CUSTOM_THREADS"
            exit 1
        fi
    fi
    
    # Load custom configuration if specified
    if [[ -n "$CONFIG_FILE" ]]; then
        if [[ -f "$CONFIG_FILE" ]]; then
            source "$CONFIG_FILE"
            log_message "Loaded custom configuration: $CONFIG_FILE"
        else
            log_error "Configuration file not found: $CONFIG_FILE"
            exit 1
        fi
    fi
}

# =============================================================================
# SCOPE DETECTION AND OPTIMIZATION
# =============================================================================

detect_scope_type() {
    if [[ "$SCOPE_TYPE" != "auto" ]]; then
        return 0
    fi
    
    log_message "Auto-detecting scope type for $TARGET_DOMAIN"
    
    # Check if it's a subdomain (contains more than 2 dots for common TLDs)
    local dot_count=$(echo "$TARGET_DOMAIN" | tr -cd '.' | wc -c)
    local domain_parts=($(echo "$TARGET_DOMAIN" | tr '.' ' '))
    
    if [[ ${#domain_parts[@]} -gt 2 ]]; then
        # Check if first part looks like a subdomain
        local first_part="${domain_parts[0]}"
        if [[ ${#first_part} -gt 2 ]] && [[ "$first_part" != "www" ]]; then
            export SCOPE_TYPE="closed"
            log_message "Detected scope type: closed (specific subdomain)"
            return 0
        fi
    fi
    
    # Default to wildcard for root domains
    export SCOPE_TYPE="wildcard"
    log_message "Detected scope type: wildcard (root domain)"
}

optimize_for_scope() {
    case "$SCOPE_TYPE" in
        closed)
            log_message "Optimizing for closed scope reconnaissance"
            # Focus on deep analysis of specific target
            export HTTPX_THREADS=1000
            export DNS_THREADS=500
            export SUBDOMAIN_BRUTEFORCE_LIMIT=10000
            export FOCUS_DEEP_ANALYSIS=true
            ;;
        wildcard)
            log_message "Optimizing for wildcard scope reconnaissance"
            # Focus on subdomain discovery
            export HTTPX_THREADS=50000
            export DNS_THREADS=10000
            export SUBDOMAIN_BRUTEFORCE_LIMIT=100000
            export FOCUS_SUBDOMAIN_DISCOVERY=true
            ;;
        open)
            log_message "Optimizing for open scope reconnaissance"
            # Balanced approach
            export HTTPX_THREADS=20000
            export DNS_THREADS=5000
            export SUBDOMAIN_BRUTEFORCE_LIMIT=50000
            export FOCUS_BALANCED=true
            ;;
    esac
}

# =============================================================================
# PROFILE EXECUTION
# =============================================================================

execute_profile() {
    case "$SCAN_PROFILE" in
        quick)
            log_message "Executing QUICK profile (30-60 minutes)"
            run_modules "setup,passive,httpx"
            ;;
        standard)
            log_message "Executing STANDARD profile (2-4 hours)"
            run_modules "setup,passive,active,httpx,crawler,fuzzing,vulns"
            ;;
        deep)
            log_message "Executing DEEP profile (8-12 hours)"
            run_modules "setup,passive,active,httpx,crawler,fuzzing,js,sensitive,vulns"
            ;;
        *)
            if [[ -n "$SELECTED_MODULES" ]]; then
                log_message "Executing custom modules: $SELECTED_MODULES"
                run_modules "$SELECTED_MODULES"
            else
                log_message "No profile specified, executing standard profile"
                run_modules "setup,passive,active,httpx,crawler,fuzzing,vulns"
            fi
            ;;
    esac
}

# =============================================================================
# MODULE EXECUTION SYSTEM
# =============================================================================

run_modules() {
    local modules_list="$1"
    IFS=',' read -ra MODULES <<< "$modules_list"
    
    local total_modules=${#MODULES[@]}
    local current_module=0
    
    log_message "Starting execution of $total_modules modules"
    
    for module in "${MODULES[@]}"; do
        ((current_module++))
        module=$(echo "$module" | xargs)  # Trim whitespace
        
        log_message "[$current_module/$total_modules] Running module: $module"
        
        case "$module" in
            setup)
                run_setup_module
                ;;
            passive)
                run_passive_module
                ;;
            active)
                run_active_module
                ;;
            httpx)
                run_httpx_module
                ;;
            crawler)
                run_crawler_module
                ;;
            fuzzing)
                run_fuzzing_module
                ;;
            js)
                run_js_module
                ;;
            sensitive)
                run_sensitive_module
                ;;
            vulns)
                run_vulns_module
                ;;
            monitor)
                run_monitor_module
                ;;
            *)
                log_warning "Unknown module: $module"
                ;;
        esac
        
        if [[ $? -eq 0 ]]; then
            log_message "[$current_module/$total_modules] Module $module completed successfully"
        else
            log_error "[$current_module/$total_modules] Module $module failed"
        fi
    done
    
    # Show final results
    # Ensure live-hosts.txt exists for other modules
    if [[ ! -f "${DIR_OUTPUT}/${DOMAIN}/live-hosts.txt" ]]; then
        if [[ -f "${DIR_OUTPUT}/${DOMAIN}/recon/subdomains-all.txt" ]]; then
            # Create basic URLs from subdomains
            while IFS= read -r subdomain; do
                echo "https://${subdomain}"
                echo "http://${subdomain}"
            done < "${DIR_OUTPUT}/${DOMAIN}/recon/subdomains-all.txt" | head -20 > "${DIR_OUTPUT}/${DOMAIN}/live-hosts.txt"
        else
            # Fallback to target domain
            echo "https://${DOMAIN}" > "${DIR_OUTPUT}/${DOMAIN}/live-hosts.txt"
            echo "http://${DOMAIN}" >> "${DIR_OUTPUT}/${DOMAIN}/live-hosts.txt"
        fi
    fi

    show_final_results
}

# Module execution functions
run_setup_module() {
    source "${SCRIPT_DIR}/modules/core/setup.sh"
}

run_passive_module() {
    source "${SCRIPT_DIR}/modules/recon/passive.sh"
}

run_active_module() {
    source "${SCRIPT_DIR}/modules/recon/active.sh"
}

run_httpx_module() {
    source "${SCRIPT_DIR}/modules/probing/httpx.sh"
}

run_crawler_module() {
    source "${SCRIPT_DIR}/modules/discovery/crawler.sh"
}

run_fuzzing_module() {
    source "${SCRIPT_DIR}/modules/discovery/fuzzing.sh"
}

run_js_module() {
    source "${SCRIPT_DIR}/modules/analysis/javascript.sh"
}

run_sensitive_module() {
    source "${SCRIPT_DIR}/modules/discovery/sensitive.sh"
}

run_vulns_module() {
    source "${SCRIPT_DIR}/modules/scanning/vulnerabilities.sh"
}

run_monitor_module() {
    source "${SCRIPT_DIR}/modules/monitoring/continuous.sh"
}

# =============================================================================
# RESULTS AND REPORTING
# =============================================================================

    # Ensure live-hosts.txt exists for other modules
    if [[ ! -f "${DIR_OUTPUT}/${DOMAIN}/live-hosts.txt" ]]; then
        if [[ -f "${DIR_OUTPUT}/${DOMAIN}/recon/subdomains-all.txt" ]]; then
            # Create basic URLs from subdomains
            while IFS= read -r subdomain; do
                echo "https://${subdomain}"
                echo "http://${subdomain}"
            done < "${DIR_OUTPUT}/${DOMAIN}/recon/subdomains-all.txt" | head -20 > "${DIR_OUTPUT}/${DOMAIN}/live-hosts.txt"
        else
            # Fallback to target domain
            echo "https://${DOMAIN}" > "${DIR_OUTPUT}/${DOMAIN}/live-hosts.txt"
            echo "http://${DOMAIN}" >> "${DIR_OUTPUT}/${DOMAIN}/live-hosts.txt"
        fi
    fi

show_final_results() {
    log_message "Reconnaissance completed for $TARGET_DOMAIN"
    
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  ║                         RESULTS SUMMARY                          ║${NC}"
    echo -e "${CYAN}  ╚══════════════════════════════════════════════════════════════════╝${NC}"
    
    local results_dir="${DIR_OUTPUT}/${TARGET_DOMAIN}"
    
    if [[ -d "$results_dir" ]]; then
        echo -e "\n${YELLOW}Target Domain:${NC} $TARGET_DOMAIN"
        echo -e "${YELLOW}Scope Type:${NC} $SCOPE_TYPE"
        echo -e "${YELLOW}Profile:${NC} ${SCAN_PROFILE:-custom}"
        echo -e "${YELLOW}Output Directory:${NC} $results_dir"
        echo ""
        
        # Count results by category
        echo -e "${YELLOW}Results Breakdown:${NC}"
        
        # Subdomains
        local passive_subs=0
        local active_subs=0
        local live_hosts=0
        
        [[ -f "$results_dir/recon-subdomains-passive.txt" ]] && \
            passive_subs=$(wc -l < "$results_dir/recon-subdomains-passive.txt")
        [[ -f "$results_dir/recon-subdomains-active.txt" ]] && \
            active_subs=$(wc -l < "$results_dir/recon-subdomains-active.txt")
        [[ -f "$results_dir/live-hosts.txt" ]] && \
            live_hosts=$(wc -l < "$results_dir/live-hosts.txt")
        
        echo "  🔍 Passive Subdomains: $passive_subs"
        echo "  🔨 Active Subdomains: $active_subs"
        echo "  🟢 Live Hosts: $live_hosts"
        
        # URLs and endpoints
        local urls=0
        local sensitive_files=0
        local js_files=0
        
        [[ -f "$results_dir/all-urls.txt" ]] && \
            urls=$(wc -l < "$results_dir/all-urls.txt")
        [[ -f "$results_dir/sensitive-files.txt" ]] && \
            sensitive_files=$(wc -l < "$results_dir/sensitive-files.txt")
        [[ -f "$results_dir/js-files.txt" ]] && \
            js_files=$(wc -l < "$results_dir/js-files.txt")
        
        echo "  🌐 Total URLs: $urls"
        echo "  🔐 Sensitive Files: $sensitive_files"
        echo "  📜 JavaScript Files: $js_files"
        
        # Vulnerabilities
        local vulnerabilities=0
        [[ -f "$results_dir/vulnerabilities.txt" ]] && \
            vulnerabilities=$(wc -l < "$results_dir/vulnerabilities.txt")
        
        echo "  🚨 Potential Vulnerabilities: $vulnerabilities"
        
        # Execution time
        local start_time_file="$results_dir/log/start_time.txt"
        if [[ -f "$start_time_file" ]]; then
            local start_time=$(cat "$start_time_file")
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            local hours=$((duration / 3600))
            local minutes=$(((duration % 3600) / 60))
            echo -e "\n${YELLOW}Execution Time:${NC} ${hours}h ${minutes}m"
        fi
        
        # Important files
        echo -e "\n${YELLOW}Key Output Files:${NC}"
        echo "  📁 All results: $results_dir/"
        echo "  📋 Summary log: $results_dir/log/log.txt"
        [[ -f "$results_dir/recon-subdomains-all.txt" ]] && \
            echo "  🎯 All subdomains: $results_dir/recon-subdomains-all.txt"
        [[ -f "$results_dir/live-hosts.txt" ]] && \
            echo "  🟢 Live hosts: $results_dir/live-hosts.txt"
        [[ -f "$results_dir/vulnerabilities.txt" ]] && \
            echo "  🚨 Vulnerabilities: $results_dir/vulnerabilities.txt"
        
    else
        log_warning "Results directory not found: $results_dir"
    fi
    
    # Send notification if enabled
    if [[ "$NOTIFICATION_ENABLED" == "true" ]]; then
        send_completion_notification
    fi
    
    echo ""
}

send_completion_notification() {
    local message="🎯 NINA Recon completed for $TARGET_DOMAIN"
    local details=""
    
    # Add basic stats to notification
    local results_dir="${DIR_OUTPUT}/${TARGET_DOMAIN}"
    if [[ -d "$results_dir" ]]; then
        local live_hosts=0
        local vulnerabilities=0
        
        [[ -f "$results_dir/live-hosts.txt" ]] && \
            live_hosts=$(wc -l < "$results_dir/live-hosts.txt")
        [[ -f "$results_dir/vulnerabilities.txt" ]] && \
            vulnerabilities=$(wc -l < "$results_dir/vulnerabilities.txt")
        
        details=" | Live hosts: $live_hosts | Vulns: $vulnerabilities"
    fi
    
    notify_slack "$message$details"
}

# =============================================================================
# CONTINUOUS MONITORING
# =============================================================================

setup_continuous_monitoring() {
    if [[ "$CONTINUOUS_MODE" != "true" ]]; then
        return 0
    fi
    
    log_message "Setting up continuous monitoring for $TARGET_DOMAIN"
    
    local monitor_script="${DIR_OUTPUT}/${TARGET_DOMAIN}/monitor.sh"
    local monitor_config="${DIR_OUTPUT}/${TARGET_DOMAIN}/monitor.conf"
    
    # Create monitoring configuration
    cat > "$monitor_config" << EOF
TARGET_DOMAIN="$TARGET_DOMAIN"
SCOPE_TYPE="$SCOPE_TYPE"
CHECK_INTERVAL="3600"  # 1 hour
NOTIFICATION_ENABLED="$NOTIFICATION_ENABLED"
MONITOR_MODULES="passive,httpx"
EOF
    
    # Create monitoring script
    cat > "$monitor_script" << 'EOF'
#!/bin/bash
source "$(dirname "$0")/monitor.conf"
source "$(dirname "$0")/../../modules/core/config.sh"

while true; do
    log_message "Running continuous monitoring check for $TARGET_DOMAIN"
    
    # Run monitoring modules
    IFS=',' read -ra MODULES <<< "$MONITOR_MODULES"
    for module in "${MODULES[@]}"; do
        case "$module" in
            passive)
                source "$(dirname "$0")/../../modules/monitoring/passive-monitor.sh"
                ;;
            httpx)
                source "$(dirname "$0")/../../modules/monitoring/httpx-monitor.sh"
                ;;
        esac
    done
    
    log_message "Monitoring cycle completed. Sleeping for $CHECK_INTERVAL seconds"
    sleep "$CHECK_INTERVAL"
done
EOF
    
    chmod +x "$monitor_script"
    
    log_message "Continuous monitoring setup completed"
    log_message "To start monitoring: nohup $monitor_script &"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Show banner
    show_banner
    
    # Validate arguments and setup environment
    validate_arguments
    
    # Check system requirements
    if ! check_requirements; then
        log_error "System requirements check failed"
        exit 1
    fi
    
    # Validate domain
    if ! validate_domain; then
        exit 1
    fi
    
    # Detect and optimize for scope type
    detect_scope_type
    optimize_for_scope
    
    # Record start time
    echo "$(date +%s)" > "${DIR_OUTPUT}/${TARGET_DOMAIN}/log/start_time.txt" 2>/dev/null || true
    
    # Log execution details
    log_message "Starting NINA Recon Optimized v${VERSION}"
    log_message "Target: $TARGET_DOMAIN"
    log_message "Scope: $SCOPE_TYPE"
    log_message "Profile: ${SCAN_PROFILE:-custom}"
    log_message "Output: ${DIR_OUTPUT}/${TARGET_DOMAIN}"
    
    # Send start notification
    if [[ "$NOTIFICATION_ENABLED" == "true" ]]; then
        notify_slack "🚀 Starting NINA Recon for $TARGET_DOMAIN (scope: $SCOPE_TYPE)"
    fi
    
    # Execute profile or custom modules
    execute_profile
    
    # Setup continuous monitoring if requested
    setup_continuous_monitoring
    
    log_message "NINA Recon Optimized execution completed successfully"
}

# Execute main function with all arguments
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
