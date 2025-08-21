#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Setup Module
# Initialize environment and directory structure
# =============================================================================

# Ensure config is loaded
if [[ -z "${DIR_NINA:-}" ]]; then
    echo "Error: Config not loaded. This module should be run via nina-recon-optimized.sh"
    exit 1
fi

# =============================================================================
# SETUP FUNCTIONS
# =============================================================================

create_directory_structure() {
    log_message "Creating directory structure for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    
    # Core directories
    local directories=(
        "${base_dir}/log"
        "${base_dir}/recon"
        "${base_dir}/probing"
        "${base_dir}/discovery"
        "${base_dir}/analysis"
        "${base_dir}/vulnerabilities"
        "${base_dir}/monitoring"
        "${base_dir}/manual"
        "${base_dir}/screenshots"
        "${base_dir}/wordlists"
    )
    
    # Detailed subdirectories
    local detailed_dirs=(
        "${base_dir}/recon/passive"
        "${base_dir}/recon/active"
        "${base_dir}/recon/certificates"
        "${base_dir}/probing/http"
        "${base_dir}/probing/https"
        "${base_dir}/probing/ports"
        "${base_dir}/probing/technologies"
        "${base_dir}/probing/responses"
        "${base_dir}/probing/screenshots"
        "${base_dir}/probing/certificates"
        "${base_dir}/discovery/content"
        "${base_dir}/discovery/parameters"
        "${base_dir}/discovery/endpoints"
        "${base_dir}/discovery/archive_urls"
        "${base_dir}/discovery/js_endpoints"
        "${base_dir}/discovery/api_endpoints"
        "${base_dir}/discovery/wordlists"
        "${base_dir}/analysis/javascript"
        "${base_dir}/analysis/technologies"
        "${base_dir}/analysis/secrets"
        "${base_dir}/vulnerabilities/nuclei"
        "${base_dir}/vulnerabilities/custom"
        "${base_dir}/vulnerabilities/web_vulns"
        "${base_dir}/vulnerabilities/ssl_tls"
        "${base_dir}/vulnerabilities/subdomain_takeover"
        "${base_dir}/vulnerabilities/secrets"
        "${base_dir}/vulnerabilities/misconfigurations"
        "${base_dir}/vulnerabilities/apis"
        "${base_dir}/monitoring/changes"
        "${base_dir}/monitoring/new-subdomains"
    )
    
    # Create all directories
    for dir in "${directories[@]}" "${detailed_dirs[@]}"; do
        if ! mkdir -p "$dir" 2>/dev/null; then
            log_error "Failed to create directory: $dir"
            return 1
        fi
    done
    
    # Create work directory
    local work_dir="${DIR_WORK}/${DOMAIN}"
    mkdir -p "$work_dir" 2>/dev/null || true
    
    log_message "Directory structure created successfully"
    return 0
}

initialize_files() {
    log_message "Initializing core files for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    
    # Initialize domain file
    echo "$DOMAIN" > "${base_dir}/target-domain.txt"
    
    # Initialize tracking files
    local tracking_files=(
        "${base_dir}/recon/subdomains-passive.txt"
        "${base_dir}/recon/subdomains-active.txt"
        "${base_dir}/recon/subdomains-all.txt"
        "${base_dir}/probing/live-hosts.txt"
        "${base_dir}/probing/http-responses.txt"
        "${base_dir}/discovery/urls-all.txt"
        "${base_dir}/discovery/sensitive-files.txt"
        "${base_dir}/analysis/javascript-files.txt"
        "${base_dir}/vulnerabilities/findings.txt"
    )
    
    for file in "${tracking_files[@]}"; do
        touch "$file" 2>/dev/null || true
    done
    
    # Create configuration file for this scan
    create_scan_config "${base_dir}/scan-config.json"
    
    log_message "Core files initialized successfully"
    return 0
}

create_scan_config() {
    local config_file="$1"
    
    cat > "$config_file" << EOF
{
    "scan_info": {
        "domain": "$DOMAIN",
        "scope_type": "${SCOPE_TYPE:-auto}",
        "profile": "${SCAN_PROFILE:-standard}",
        "start_time": "$(date -Iseconds)",
        "nina_version": "$NINA_VERSION",
        "scan_id": "$(date +%s)_$(echo $DOMAIN | sed 's/\./_/g')"
    },
    "configuration": {
        "httpx_threads": "$HTTPX_THREADS",
        "dns_threads": "$DNS_THREADS",
        "subdomain_limit": "$SUBDOMAIN_BRUTEFORCE_LIMIT",
        "wildcard_tests": "$WILDCARD_TESTS",
        "nuclei_threads": "$NUCLEI_THREADS"
    },
    "modules": {
        "enabled": "${SELECTED_MODULES:-standard}",
        "continuous_monitoring": ${CONTINUOUS_MODE:-false},
        "notifications": ${NOTIFICATION_ENABLED:-false}
    },
    "status": {
        "current_module": "setup",
        "completed_modules": [],
        "failed_modules": [],
        "progress": 0
    }
}
EOF
    
    log_message "Scan configuration saved to $config_file"
}

check_dependencies() {
    log_message "Checking tool dependencies"
    
    local critical_tools=(
        "curl" "jq" "grep" "awk" "sed" "sort" "uniq" "wc"
    )
    
    local recon_tools=(
        "subfinder" "amass" "assetfinder" "httpx" "nuclei"
        "waybackurls" "gau" "katana" "dnsx" "tlsx"
    )
    
    local optional_tools=(
        "github-subdomains" "puredns" "shuffledns" "dnsgen"
        "altdns" "gobuster" "feroxbuster" "ffuf" "crlfuzz"
        "subzy" "goop" "anew" "unfurl" "notify"
    )
    
    local missing_critical=()
    local missing_recon=()
    local missing_optional=()
    
    # Check critical tools
    for tool in "${critical_tools[@]}"; do
        if ! tool_available "$tool"; then
            missing_critical+=("$tool")
        fi
    done
    
    # Check reconnaissance tools
    for tool in "${recon_tools[@]}"; do
        if ! tool_available "$tool"; then
            missing_recon+=("$tool")
        fi
    done
    
    # Check optional tools
    for tool in "${optional_tools[@]}"; do
        if ! tool_available "$tool"; then
            missing_optional+=("$tool")
        fi
    done
    
    # Report results
    if [[ ${#missing_critical[@]} -gt 0 ]]; then
        log_error "Missing critical tools: ${missing_critical[*]}"
        log_error "Cannot continue without these tools"
        return 1
    fi
    
    if [[ ${#missing_recon[@]} -gt 0 ]]; then
        log_warning "Missing reconnaissance tools: ${missing_recon[*]}"
        log_warning "Some modules may have limited functionality"
    fi
    
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        log_info "Missing optional tools: ${missing_optional[*]}"
        log_info "These tools would enhance functionality but are not required"
    fi
    
    log_message "Dependency check completed"
    return 0
}

validate_wordlists() {
    log_message "Validating wordlists and resources"
    
    local wordlists=(
        "$WORDLIST_SUBDOMAINS"
        "$WORDLIST_DIRECTORIES" 
        "$WORDLIST_FILES"
        "$WORDLIST_PARAMETERS"
    )
    
    local missing_wordlists=()
    
    for wordlist in "${wordlists[@]}"; do
        if [[ ! -f "$wordlist" ]]; then
            missing_wordlists+=("$(basename "$wordlist")")
        else
            local line_count=$(wc -l < "$wordlist" 2>/dev/null || echo "0")
            log_info "$(basename "$wordlist"): $line_count lines"
        fi
    done
    
    if [[ ${#missing_wordlists[@]} -gt 0 ]]; then
        log_warning "Missing wordlists: ${missing_wordlists[*]}"
        log_warning "This may affect reconnaissance quality"
        
        # Try to create basic wordlists if they don't exist
        create_basic_wordlists
    fi
    
    # Check resolvers
    if [[ ! -f "$DNS_RESOLVERS" ]]; then
        log_warning "DNS resolvers file not found: $DNS_RESOLVERS"
        create_basic_resolvers
    else
        local resolver_count=$(wc -l < "$DNS_RESOLVERS" 2>/dev/null || echo "0")
        log_info "DNS resolvers: $resolver_count available"
    fi
    
    return 0
}

create_basic_wordlists() {
    log_message "Creating basic wordlists"
    
    # Create basic subdomain wordlist
    if [[ ! -f "$WORDLIST_SUBDOMAINS" ]]; then
        mkdir -p "$(dirname "$WORDLIST_SUBDOMAINS")" 2>/dev/null
        cat > "$WORDLIST_SUBDOMAINS" << 'EOF'
www
api
admin
mail
ftp
test
dev
staging
app
mobile
blog
shop
store
portal
dashboard
panel
secure
vpn
cdn
img
images
static
assets
files
download
upload
media
video
support
help
docs
wiki
forum
community
chat
news
beta
alpha
demo
sandbox
qa
uat
prod
production
staging
development
www1
www2
mail1
mail2
ns1
ns2
dns1
dns2
mx1
mx2
smtp
pop
imap
webmail
autodiscover
remote
citrix
owa
exchange
sharepoint
intranet
extranet
partner
vendor
client
customer
guest
public
private
internal
external
backup
archive
old
new
legacy
v1
v2
v3
mobile
m
wap
3g
4g
5g
edge
wireless
wifi
voip
sip
rtp
streaming
live
stream
rtmp
hls
dash
EOF
        log_message "Created basic subdomain wordlist: $WORDLIST_SUBDOMAINS"
    fi
    
    # Create basic directory wordlist
    if [[ ! -f "$WORDLIST_DIRECTORIES" ]]; then
        mkdir -p "$(dirname "$WORDLIST_DIRECTORIES")" 2>/dev/null
        cat > "$WORDLIST_DIRECTORIES" << 'EOF'
admin
api
app
assets
backup
blog
cache
config
css
data
db
debug
docs
download
files
images
img
js
login
media
old
private
public
scripts
static
test
tmp
uploads
user
users
www
backup
backups
bak
temp
temporary
archive
archives
log
logs
error
errors
include
includes
lib
libs
vendor
vendors
node_modules
bower_components
.git
.svn
.hg
.bzr
.well-known
robots.txt
sitemap.xml
crossdomain.xml
.htaccess
.htpasswd
web.config
phpinfo.php
info.php
test.php
status.php
health.php
ping.php
version.php
readme.txt
changelog.txt
license.txt
install.txt
upgrade.txt
TODO.txt
INSTALL
README
CHANGELOG
LICENSE
COPYING
AUTHORS
CONTRIBUTORS
MAINTAINERS
Dockerfile
docker-compose.yml
package.json
composer.json
requirements.txt
Gemfile
Pipfile
setup.py
pom.xml
build.gradle
makefile
Makefile
EOF
        log_message "Created basic directory wordlist: $WORDLIST_DIRECTORIES"
    fi
    
    # Create basic parameters wordlist
    if [[ ! -f "$WORDLIST_PARAMETERS" ]]; then
        mkdir -p "$(dirname "$WORDLIST_PARAMETERS")" 2>/dev/null
        cat > "$WORDLIST_PARAMETERS" << 'EOF'
id
user
username
password
pass
passwd
email
mail
token
key
api_key
apikey
access_token
refresh_token
session
sessionid
sid
auth
authorization
bearer
oauth
csrf
xsrf
callback
redirect
return
url
link
href
src
file
path
dir
folder
page
view
action
method
format
type
mode
debug
test
admin
q
query
search
s
keyword
term
filter
sort
order
limit
offset
page_size
per_page
count
total
start
end
from
to
date
time
timestamp
year
month
day
hour
minute
second
lang
language
locale
country
region
city
zip
postal
code
phone
mobile
fax
name
first_name
last_name
full_name
title
company
organization
address
street
state
province
EOF
        log_message "Created basic parameters wordlist: $WORDLIST_PARAMETERS"
    fi
}

create_basic_resolvers() {
    log_message "Creating basic DNS resolvers file"
    
    mkdir -p "$(dirname "$DNS_RESOLVERS")" 2>/dev/null
    cat > "$DNS_RESOLVERS" << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
64.6.64.6
64.6.65.6
77.88.8.8
77.88.8.1
156.154.70.1
156.154.71.1
198.101.242.72
23.253.163.53
EOF
    
    log_message "Created basic DNS resolvers file: $DNS_RESOLVERS"
}

setup_monitoring() {
    if [[ "$CONTINUOUS_MODE" != "true" ]]; then
        return 0
    fi
    
    log_message "Setting up continuous monitoring infrastructure"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local monitor_dir="${base_dir}/monitoring"
    
    # Create monitoring configuration
    cat > "${monitor_dir}/config.json" << EOF
{
    "target": "$DOMAIN",
    "check_interval": 3600,
    "enabled_checks": [
        "new_subdomains",
        "certificate_changes",
        "http_status_changes",
        "new_vulnerabilities"
    ],
    "notification_settings": {
        "slack_enabled": ${NOTIFICATION_ENABLED:-false},
        "discord_enabled": false,
        "email_enabled": false
    },
    "thresholds": {
        "new_subdomains_threshold": 5,
        "new_vulnerabilities_threshold": 1,
        "status_change_threshold": 10
    }
}
EOF
    
    # Create baseline files for comparison
    touch "${monitor_dir}/baseline-subdomains.txt"
    touch "${monitor_dir}/baseline-live-hosts.txt"
    touch "${monitor_dir}/baseline-vulnerabilities.txt"
    
    log_message "Monitoring infrastructure setup completed"
}

optimize_system() {
    log_message "Applying system optimizations"
    
    # Set ulimits if possible
    if [[ $EUID -eq 0 ]] || groups | grep -q sudo; then
        ulimit -n "$ULIMIT_NOFILE" 2>/dev/null || true
        log_info "File descriptor limit set to $ULIMIT_NOFILE"
    else
        log_warning "Cannot set ulimits (not running as root/sudo)"
    fi
    
    # Create temporary work directory
    local work_dir="${DIR_WORK}/${DOMAIN}"
    mkdir -p "$work_dir" 2>/dev/null
    export TMPDIR="$work_dir"
    
    # Set Go environment for better performance
    export GOMAXPROCS="${GOLANG_MAX_PROCS}"
    
    log_message "System optimizations applied"
}

generate_scan_summary() {
    log_message "Generating initial scan summary"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local summary_file="${base_dir}/log/scan-summary.txt"
    
    cat > "$summary_file" << EOF
NINA RECON OPTIMIZED - Scan Summary
==================================

Target Domain: $DOMAIN
Scope Type: ${SCOPE_TYPE:-auto}
Profile: ${SCAN_PROFILE:-standard}
Start Time: $(date)
Nina Version: $NINA_VERSION

Configuration:
- HTTP Threads: $HTTPX_THREADS
- DNS Threads: $DNS_THREADS
- Subdomain Limit: $SUBDOMAIN_BRUTEFORCE_LIMIT
- Nuclei Threads: $NUCLEI_THREADS

Modules to Execute: ${SELECTED_MODULES:-standard}
Continuous Monitoring: ${CONTINUOUS_MODE:-false}
Notifications: ${NOTIFICATION_ENABLED:-false}

Output Directory: $base_dir
Work Directory: ${DIR_WORK}/${DOMAIN}

Status: Setup completed successfully
Next: Starting reconnaissance modules
EOF
    
    log_message "Scan summary saved to $summary_file"
}

# =============================================================================
# MAIN SETUP EXECUTION
# =============================================================================

main_setup() {
    show_module_info "SETUP" "Environment initialization and dependency checking"
    
    # Validate domain first
    if ! validate_domain; then
        log_error "Domain validation failed"
        return 1
    fi
    
    # Execute setup steps
    local setup_steps=(
        "create_directory_structure"
        "check_dependencies" 
        "validate_wordlists"
        "initialize_files"
        "optimize_system"
        "setup_monitoring"
        "generate_scan_summary"
    )
    
    local total_steps=${#setup_steps[@]}
    local current_step=0
    
    for step in "${setup_steps[@]}"; do
        ((current_step++))
        
        log_message "[$current_step/$total_steps] Executing: $step"
        
        if ! "$step"; then
            log_error "Setup step failed: $step"
            return 1
        fi
        
        show_progress "$current_step" "$total_steps" "Setup progress"
    done
    
    # Final notifications
    log_message "Setup module completed successfully"
    
    if [[ "$NOTIFICATION_ENABLED" == "true" ]]; then
        notify_slack "🔧 Setup completed for $DOMAIN - Ready to start reconnaissance"
    fi
    
    commit_step "Setup"
    return 0
}

# Execute main setup function
main_setup
