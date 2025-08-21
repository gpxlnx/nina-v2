#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Examples and Usage Demonstrations
# Practical examples for different bug bounty scenarios
# =============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NINA_SCRIPT="${SCRIPT_DIR}/nina-recon-optimized.sh"

show_banner() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    ███╗   ██╗██╗███╗   ██╗ █████╗     ███████╗██╗  ██╗ █████╗   ║
║    ████╗  ██║██║████╗  ██║██╔══██╗    ██╔════╝╚██╗██╔╝██╔══██╗  ║
║    ██╔██╗ ██║██║██╔██╗ ██║███████║    █████╗   ╚███╔╝ ███████║  ║
║    ██║╚██╗██║██║██║╚██╗██║██╔══██║    ██╔══╝   ██╔██╗ ██╔══██║  ║
║    ██║ ╚████║██║██║ ╚████║██║  ██║    ███████╗██╔╝ ██╗██║  ██║  ║
║    ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝  ║
║                                                                  ║
║              EXAMPLES - Bug Bounty Usage Scenarios              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

EOF
}

show_help() {
    echo -e "${CYAN}Usage: $0 [SCENARIO] [DOMAIN]${NC}"
    echo ""
    echo -e "${YELLOW}Available Scenarios:${NC}"
    echo "  1. closed-scope    - Deep analysis of specific subdomain/API"
    echo "  2. wildcard-scope  - Aggressive subdomain discovery"  
    echo "  3. quick-test      - Fast reconnaissance (30-60 min)"
    echo "  4. deep-analysis   - Comprehensive analysis (8+ hours)"
    echo "  5. stealth-recon   - Low-profile reconnaissance"
    echo "  6. api-security    - API-focused security testing"
    echo "  7. monitoring      - Continuous monitoring setup"
    echo "  8. custom-config   - Custom configuration example"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 closed-scope api.example.com"
    echo "  $0 wildcard-scope example.com"
    echo "  $0 quick-test target.com"
    echo ""
    echo -e "${YELLOW}Interactive Mode:${NC}"
    echo "  $0 interactive"
    echo ""
}

validate_domain() {
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Error: Domain is required${NC}"
        return 1
    fi
    
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo -e "${RED}Error: Invalid domain format: $domain${NC}"
        return 1
    fi
    
    return 0
}

check_nina_script() {
    if [[ ! -f "$NINA_SCRIPT" ]]; then
        echo -e "${RED}Error: Nina script not found at $NINA_SCRIPT${NC}"
        echo "Please ensure you're running this from the correct directory."
        exit 1
    fi
    
    if [[ ! -x "$NINA_SCRIPT" ]]; then
        echo -e "${YELLOW}Making Nina script executable...${NC}"
        chmod +x "$NINA_SCRIPT"
    fi
}

log_command() {
    local description="$1"
    local command="$2"
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Scenario: $description${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Command:${NC} $command"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}\n"
}

run_scenario() {
    local scenario="$1"
    local domain="$2"
    
    case "$scenario" in
        closed-scope)
            closed_scope_example "$domain"
            ;;
        wildcard-scope)
            wildcard_scope_example "$domain"
            ;;
        quick-test)
            quick_test_example "$domain"
            ;;
        deep-analysis)
            deep_analysis_example "$domain"
            ;;
        stealth-recon)
            stealth_recon_example "$domain"
            ;;
        api-security)
            api_security_example "$domain"
            ;;
        monitoring)
            monitoring_example "$domain"
            ;;
        custom-config)
            custom_config_example "$domain"
            ;;
        interactive)
            interactive_mode
            ;;
        *)
            echo -e "${RED}Unknown scenario: $scenario${NC}"
            show_help
            exit 1
            ;;
    esac
}

closed_scope_example() {
    local domain="$1"
    
    log_command "Closed Scope Analysis" "$NINA_SCRIPT -d $domain -s closed -p deep --notification"
    
    echo -e "${GREEN}🎯 CLOSED SCOPE SCENARIO${NC}"
    echo "Perfect for:"
    echo "• VDP programs with specific subdomain targets"
    echo "• API endpoint analysis"
    echo "• Deep security analysis of single targets"
    echo "• When you have a specific subdomain like api.company.com"
    echo ""
    echo -e "${YELLOW}What this does:${NC}"
    echo "• Focuses threads on deep analysis rather than discovery"
    echo "• Enables advanced parameter discovery"
    echo "• Performs comprehensive API security testing"
    echo "• Deep content discovery with large wordlists"
    echo "• Extensive vulnerability scanning"
    echo "• JavaScript analysis for hidden endpoints"
    echo ""
    echo -e "${BLUE}Estimated time: 4-8 hours${NC}"
    echo -e "${BLUE}Expected results: Deep security analysis, API endpoints, vulnerabilities${NC}"
    echo ""
    
    read -p "Do you want to run this scenario? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        "$NINA_SCRIPT" -d "$domain" -s closed -p deep --notification
    else
        echo "Scenario cancelled."
    fi
}

wildcard_scope_example() {
    local domain="$1"
    
    log_command "Wildcard Scope Discovery" "$NINA_SCRIPT -d $domain -s wildcard -p standard --wildcard-check"
    
    echo -e "${GREEN}🌐 WILDCARD SCOPE SCENARIO${NC}"
    echo "Perfect for:"
    echo "• Programs with *.company.com scope"
    echo "• Maximum subdomain discovery"
    echo "• Large corporate targets"
    echo "• When scope allows all subdomains"
    echo ""
    echo -e "${YELLOW}What this does:${NC}"
    echo "• Maximizes threads for subdomain discovery"
    echo "• Aggressive DNS bruteforcing (100k+ subdomains)"
    echo "• Wildcard detection and filtering"
    echo "• Subdomain mutations and permutations"
    echo "• Massive HTTP probing with comprehensive ports"
    echo "• Content discovery across all found hosts"
    echo ""
    echo -e "${BLUE}Estimated time: 2-6 hours${NC}"
    echo -e "${BLUE}Expected results: Maximum subdomain discovery, broad attack surface${NC}"
    echo ""
    
    read -p "Do you want to run this scenario? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        "$NINA_SCRIPT" -d "$domain" -s wildcard -p standard --wildcard-check
    else
        echo "Scenario cancelled."
    fi
}

quick_test_example() {
    local domain="$1"
    
    log_command "Quick Test" "$NINA_SCRIPT -d $domain -p quick -q"
    
    echo -e "${GREEN}⚡ QUICK TEST SCENARIO${NC}"
    echo "Perfect for:"
    echo "• Initial target assessment"
    echo "• Testing script functionality"
    echo "• Time-constrained situations"
    echo "• Stealth reconnaissance"
    echo ""
    echo -e "${YELLOW}What this does:${NC}"
    echo "• Passive reconnaissance only"
    echo "• Basic HTTP probing on standard ports"
    echo "• Quick technology detection"
    echo "• Minimal footprint"
    echo "• Fast execution with reduced threads"
    echo ""
    echo -e "${BLUE}Estimated time: 30-60 minutes${NC}"
    echo -e "${BLUE}Expected results: Basic attack surface, live hosts, technologies${NC}"
    echo ""
    
    read -p "Do you want to run this scenario? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        "$NINA_SCRIPT" -d "$domain" -p quick -q
    else
        echo "Scenario cancelled."
    fi
}

deep_analysis_example() {
    local domain="$1"
    
    log_command "Deep Analysis" "$NINA_SCRIPT -d $domain -p deep -t 100000 --notification"
    
    echo -e "${GREEN}🔬 DEEP ANALYSIS SCENARIO${NC}"
    echo "Perfect for:"
    echo "• High-value targets"
    echo "• Comprehensive security assessment"
    echo "• When you have plenty of time"
    echo "• Maximum bug hunting potential"
    echo ""
    echo -e "${YELLOW}What this does:${NC}"
    echo "• All reconnaissance modules"
    echo "• Maximum thread utilization"
    echo "• Comprehensive content discovery"
    echo "• JavaScript analysis and secret extraction"
    echo "• Full vulnerability scanning suite"
    echo "• API security testing"
    echo "• SSL/TLS analysis"
    echo "• Subdomain takeover checks"
    echo ""
    echo -e "${BLUE}Estimated time: 8-12 hours${NC}"
    echo -e "${BLUE}Expected results: Complete security assessment, all vulnerabilities${NC}"
    echo ""
    
    read -p "Do you want to run this scenario? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        "$NINA_SCRIPT" -d "$domain" -p deep -t 100000 --notification
    else
        echo "Scenario cancelled."
    fi
}

stealth_recon_example() {
    local domain="$1"
    
    log_command "Stealth Reconnaissance" "$NINA_SCRIPT -d $domain -m passive,httpx -t 500 -q"
    
    echo -e "${GREEN}🥷 STEALTH RECONNAISSANCE SCENARIO${NC}"
    echo "Perfect for:"
    echo "• Avoiding detection"
    echo "• Low-profile assessments"
    echo "• Rate-limited targets"
    echo "• Initial reconnaissance"
    echo ""
    echo -e "${YELLOW}What this does:${NC}"
    echo "• Passive reconnaissance only"
    echo "• Limited HTTP probing"
    echo "• Low thread count (500)"
    echo "• No aggressive techniques"
    echo "• Minimal logging"
    echo "• No active DNS bruteforcing"
    echo ""
    echo -e "${BLUE}Estimated time: 1-2 hours${NC}"
    echo -e "${BLUE}Expected results: Stealthy intelligence gathering${NC}"
    echo ""
    
    read -p "Do you want to run this scenario? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        "$NINA_SCRIPT" -d "$domain" -m passive,httpx -t 500 -q
    else
        echo "Scenario cancelled."
    fi
}

api_security_example() {
    local domain="$1"
    
    log_command "API Security Testing" "$NINA_SCRIPT -d $domain -s closed -m passive,active,httpx,fuzzing,vulns"
    
    echo -e "${GREEN}🔌 API SECURITY SCENARIO${NC}"
    echo "Perfect for:"
    echo "• API endpoints (api.company.com)"
    echo "• REST/GraphQL services"
    echo "• Microservices architecture"
    echo "• API-first applications"
    echo ""
    echo -e "${YELLOW}What this does:${NC}"
    echo "• API endpoint discovery"
    echo "• Authentication bypass testing"
    echo "• CORS misconfiguration detection"
    echo "• Parameter discovery and testing"
    echo "• API documentation discovery (Swagger/OpenAPI)"
    echo "• Rate limiting tests"
    echo "• Error message analysis"
    echo ""
    echo -e "${BLUE}Estimated time: 3-5 hours${NC}"
    echo -e "${BLUE}Expected results: API vulnerabilities, exposed endpoints, auth issues${NC}"
    echo ""
    
    read -p "Do you want to run this scenario? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        "$NINA_SCRIPT" -d "$domain" -s closed -m passive,active,httpx,fuzzing,vulns
    else
        echo "Scenario cancelled."
    fi
}

monitoring_example() {
    local domain="$1"
    
    log_command "Continuous Monitoring" "$NINA_SCRIPT -d $domain --continuous --notification"
    
    echo -e "${GREEN}📊 CONTINUOUS MONITORING SCENARIO${NC}"
    echo "Perfect for:"
    echo "• Long-term target monitoring"
    echo "• Change detection"
    echo "• New subdomain alerts"
    echo "• Infrastructure monitoring"
    echo ""
    echo -e "${YELLOW}What this does:${NC}"
    echo "• Sets up continuous monitoring"
    echo "• Hourly checks for new subdomains"
    echo "• Certificate change detection"
    echo "• New vulnerability alerts"
    echo "• HTTP status change monitoring"
    echo "• Slack/Discord notifications"
    echo ""
    echo -e "${BLUE}Estimated time: Continuous (runs forever)${NC}"
    echo -e "${BLUE}Expected results: Real-time change notifications${NC}"
    echo ""
    echo -e "${YELLOW}Note: This will run continuously until stopped with Ctrl+C${NC}"
    echo ""
    
    read -p "Do you want to run this scenario? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        "$NINA_SCRIPT" -d "$domain" --continuous --notification
    else
        echo "Scenario cancelled."
    fi
}

custom_config_example() {
    local domain="$1"
    
    echo -e "${GREEN}⚙️ CUSTOM CONFIGURATION SCENARIO${NC}"
    echo "This example shows how to create and use custom configurations."
    echo ""
    
    # Create example config
    local config_file="/tmp/nina-custom-config.conf"
    
    cat > "$config_file" << 'EOF'
# Custom Nina Configuration
# High-performance bug bounty setup

# Threading configuration
export HTTPX_THREADS=150000
export DNS_THREADS=15000
export SUBDOMAIN_BRUTEFORCE_LIMIT=1000000
export NUCLEI_RATE_LIMIT=3000

# Fuzzing settings
export FUZZING_THREADS=1000
export FUZZING_TIMEOUT=15
export FUZZING_WORDLIST_LIMIT=100000

# Timeout settings
export HTTPX_TIMEOUT=10
export DNS_TIMEOUT=30
export SUBFINDER_TIMEOUT=45

# Notification settings
export SLACK_WEBHOOK="https://hooks.slack.com/your/webhook/here"

# API keys (uncomment and add your keys)
# export GITHUB_TOKEN_FILE="/root/nina/creds/github.txt"
# export SHODAN_API_KEY_FILE="/root/nina/creds/shodan.txt"
# export SECURITYTRAILS_API_KEY_FILE="/root/nina/creds/securitytrails.txt"

# Custom wordlists
export WORDLIST_SUBDOMAINS="/root/nina/lists/custom-subdomains.txt"
export WORDLIST_DIRECTORIES="/root/nina/lists/custom-directories.txt"

# Memory optimization
export GOLANG_MAX_PROCS=0
export ULIMIT_NOFILE=100000
EOF
    
    log_command "Custom Configuration" "$NINA_SCRIPT -d $domain -c $config_file -p standard"
    
    echo -e "${YELLOW}Created custom config at: $config_file${NC}"
    echo ""
    echo -e "${YELLOW}Configuration includes:${NC}"
    echo "• High-performance threading (150k HTTP, 15k DNS)"
    echo "• Extended timeouts for better coverage"
    echo "• Large wordlist limits"
    echo "• Memory optimizations"
    echo "• Slack notifications"
    echo "• Custom wordlist paths"
    echo ""
    echo -e "${BLUE}Review the config file and customize as needed${NC}"
    echo ""
    
    read -p "Do you want to view the config file? (y/N): " view_config
    if [[ "$view_config" =~ ^[Yy]$ ]]; then
        echo -e "\n${CYAN}Configuration file contents:${NC}"
        cat "$config_file"
        echo ""
    fi
    
    read -p "Do you want to run with this custom config? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        "$NINA_SCRIPT" -d "$domain" -c "$config_file" -p standard
    else
        echo "Scenario cancelled."
        echo "Config file saved at: $config_file"
    fi
}

interactive_mode() {
    echo -e "${GREEN}🎮 INTERACTIVE MODE${NC}"
    echo "Let's set up a customized reconnaissance based on your specific needs."
    echo ""
    
    # Get domain
    read -p "Enter target domain: " domain
    if ! validate_domain "$domain"; then
        exit 1
    fi
    
    # Get scope type
    echo ""
    echo -e "${YELLOW}Scope Type:${NC}"
    echo "1. Closed (specific subdomain/API)"
    echo "2. Wildcard (*.domain.com)"
    echo "3. Open (multiple domains)"
    echo "4. Auto-detect"
    read -p "Choose scope type (1-4): " scope_choice
    
    case "$scope_choice" in
        1) scope="closed" ;;
        2) scope="wildcard" ;;
        3) scope="open" ;;
        4) scope="auto" ;;
        *) scope="auto" ;;
    esac
    
    # Get profile
    echo ""
    echo -e "${YELLOW}Reconnaissance Profile:${NC}"
    echo "1. Quick (30-60 min)"
    echo "2. Standard (2-4 hours)"
    echo "3. Deep (8+ hours)"
    echo "4. Custom modules"
    read -p "Choose profile (1-4): " profile_choice
    
    case "$profile_choice" in
        1) profile="quick" ;;
        2) profile="standard" ;;
        3) profile="deep" ;;
        4) 
            echo ""
            echo -e "${YELLOW}Available modules:${NC}"
            echo "setup, passive, active, httpx, fuzzing, js, sensitive, vulns, monitor"
            read -p "Enter comma-separated modules: " custom_modules
            ;;
        *) profile="standard" ;;
    esac
    
    # Get additional options
    echo ""
    echo -e "${YELLOW}Additional Options:${NC}"
    read -p "Enable notifications? (y/N): " notifications
    read -p "Enable continuous monitoring? (y/N): " monitoring
    read -p "Enable wildcard checking? (y/N): " wildcard_check
    read -p "Custom thread count (enter for auto): " threads
    read -p "Run in quiet mode? (y/N): " quiet
    
    # Build command
    local cmd="$NINA_SCRIPT -d $domain"
    
    if [[ "$scope" != "auto" ]]; then
        cmd="$cmd -s $scope"
    fi
    
    if [[ -n "$custom_modules" ]]; then
        cmd="$cmd -m $custom_modules"
    elif [[ -n "$profile" ]]; then
        cmd="$cmd -p $profile"
    fi
    
    if [[ "$notifications" =~ ^[Yy]$ ]]; then
        cmd="$cmd --notification"
    fi
    
    if [[ "$monitoring" =~ ^[Yy]$ ]]; then
        cmd="$cmd --continuous"
    fi
    
    if [[ "$wildcard_check" =~ ^[Yy]$ ]]; then
        cmd="$cmd --wildcard-check"
    fi
    
    if [[ -n "$threads" ]]; then
        cmd="$cmd -t $threads"
    fi
    
    if [[ "$quiet" =~ ^[Yy]$ ]]; then
        cmd="$cmd -q"
    fi
    
    echo ""
    log_command "Interactive Custom Setup" "$cmd"
    
    read -p "Execute this command? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        eval "$cmd"
    else
        echo "Command cancelled."
        echo "You can run it manually: $cmd"
    fi
}

run_all_examples() {
    local domain="$1"
    
    echo -e "${GREEN}🎯 RUNNING ALL EXAMPLE SCENARIOS${NC}"
    echo "This will demonstrate all scenarios with $domain"
    echo ""
    echo -e "${RED}WARNING: This will take many hours to complete!${NC}"
    echo ""
    
    read -p "Are you sure you want to run ALL scenarios? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        return
    fi
    
    echo "Starting comprehensive demonstration..."
    
    # Quick test first
    echo -e "\n${CYAN}1/6 - Running Quick Test...${NC}"
    "$NINA_SCRIPT" -d "$domain" -p quick -q
    
    # Stealth recon
    echo -e "\n${CYAN}2/6 - Running Stealth Reconnaissance...${NC}"
    "$NINA_SCRIPT" -d "$domain" -m passive,httpx -t 500 -q
    
    # API security
    echo -e "\n${CYAN}3/6 - Running API Security Test...${NC}"
    "$NINA_SCRIPT" -d "$domain" -s closed -m passive,active,httpx,fuzzing,vulns
    
    # Closed scope
    echo -e "\n${CYAN}4/6 - Running Closed Scope Analysis...${NC}"
    "$NINA_SCRIPT" -d "$domain" -s closed -p standard
    
    # Wildcard scope
    echo -e "\n${CYAN}5/6 - Running Wildcard Scope Discovery...${NC}"
    "$NINA_SCRIPT" -d "$domain" -s wildcard -p standard --wildcard-check
    
    # Deep analysis
    echo -e "\n${CYAN}6/6 - Running Deep Analysis...${NC}"
    "$NINA_SCRIPT" -d "$domain" -p deep --notification
    
    echo -e "\n${GREEN}✅ All example scenarios completed!${NC}"
}

main() {
    show_banner
    check_nina_script
    
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi
    
    local scenario="$1"
    local domain="$2"
    
    # Special cases
    if [[ "$scenario" == "interactive" ]]; then
        interactive_mode
        exit 0
    fi
    
    if [[ "$scenario" == "all" ]]; then
        if [[ -z "$domain" ]]; then
            echo -e "${RED}Error: Domain required for 'all' scenario${NC}"
            exit 1
        fi
        validate_domain "$domain" || exit 1
        run_all_examples "$domain"
        exit 0
    fi
    
    # Regular scenarios
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Error: Domain is required for scenario '$scenario'${NC}"
        show_help
        exit 1
    fi
    
    validate_domain "$domain" || exit 1
    run_scenario "$scenario" "$domain"
}

# Execute main function with all arguments
main "$@"
