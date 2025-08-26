#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Sensitive Files Discovery Module
# Advanced sensitive files and endpoints discovery
# =============================================================================

# Ensure config is loaded
if [[ -z "${DIR_NINA:-}" ]]; then
    echo "Error: Config not loaded. This module should be run via nina-recon.sh"
    exit 1
fi

# Ensure base directories exist
mkdir -p "${DIR_OUTPUT}/${DOMAIN}/log" 2>/dev/null
mkdir -p "${DIR_OUTPUT}/${DOMAIN}/$(basename "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")" 2>/dev/null

# =============================================================================
# SENSITIVE FILES DISCOVERY FUNCTIONS
# =============================================================================

initialize_sensitive_discovery() {
    log_message "Initializing sensitive files discovery for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local sensitive_dir="${base_dir}/discovery/sensitive"
    
    # Create specialized subdirectories
    local subdirs=(
        "endpoints"
        "files"
        "parameters"
        "secrets"
        "configs"
        "backups"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${sensitive_dir}/${subdir}" 2>/dev/null
    done
    
    # Check if we have live hosts to work with
    if [[ ! -f "${base_dir}/live-hosts.txt" ]]; then
        log_warning "No live hosts found. Sensitive discovery will be limited."
        return 1
    fi
    
    return 0
}

discover_sensitive_endpoints() {
    log_message "Discovering sensitive endpoints"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local sensitive_dir="${base_dir}/discovery/sensitive"
    
    if [[ ! -s "${base_dir}/live-hosts.txt" ]]; then
        log_warning "No live hosts available for endpoint discovery"
        return 0
    fi
    
    # Common sensitive endpoints wordlist
    local endpoints_file="${sensitive_dir}/endpoints/sensitive-endpoints.txt"
    cat > "$endpoints_file" << 'EOF'
.env
.git/config
.git/HEAD
.htaccess
.htpasswd
.ssh/id_rsa
.ssh/id_dsa
.ssh/authorized_keys
admin
admin.php
administrator
api
api/v1
api/v2
api/swagger
backup
backup.zip
backup.tar.gz
config
config.php
config.json
config.yml
config.yaml
database
db
db.sql
dump.sql
logs
log
phpmyadmin
phpinfo.php
robots.txt
sitemap.xml
swagger
swagger.json
swagger-ui
test
test.php
upload
uploads
wp-admin
wp-config.php
.well-known/security.txt
.well-known/openid_configuration
security.txt
crossdomain.xml
clientaccesspolicy.xml
.DS_Store
web.config
app.config
application.properties
docker-compose.yml
Dockerfile
package.json
composer.json
requirements.txt
pom.xml
build.gradle
Makefile
README.md
LICENSE
CHANGELOG
VERSION
.version
status
health
debug
info
metrics
actuator
actuator/health
actuator/info
actuator/metrics
actuator/env
management
jmx-console
console
solr
elasticsearch
grafana
kibana
prometheus
EOF

    # Use ffuf if available for endpoint discovery
    if tool_available ffuf; then
        log_info "Running ffuf for endpoint discovery"
        
        # Get base URLs from live hosts
        cat "${base_dir}/live-hosts.txt" | head -50 | while IFS= read -r url; do
            local host=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
            
            # Run ffuf with rate limiting
            ffuf -u "${url}/FUZZ" \
                -w "$endpoints_file" \
                -mc 200,201,202,204,301,302,307,308,401,403,405,500 \
                -t 10 \
                -rate 50 \
                -timeout 10 \
                -o "${sensitive_dir}/endpoints/ffuf-${host}.json" \
                -of json \
                -s 2>/dev/null || true
        done
        
        # Consolidate ffuf results
        find "${sensitive_dir}/endpoints/" -name "ffuf-*.json" -exec cat {} \; 2>/dev/null | \
        jq -r '.results[]? | .url' 2>/dev/null | \
        sort -u > "${sensitive_dir}/endpoints/discovered-endpoints.txt" || true
    fi
    
    # Use gobuster if available as fallback
    if tool_available gobuster && [[ ! -s "${sensitive_dir}/endpoints/discovered-endpoints.txt" ]]; then
        log_info "Running gobuster for endpoint discovery"
        
        cat "${base_dir}/live-hosts.txt" | head -20 | while IFS= read -r url; do
            local host=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
            
            gobuster dir \
                -u "$url" \
                -w "$endpoints_file" \
                -t 10 \
                -q \
                --timeout 10s \
                -o "${sensitive_dir}/endpoints/gobuster-${host}.txt" 2>/dev/null || true
        done
        
        # Consolidate gobuster results
        find "${sensitive_dir}/endpoints/" -name "gobuster-*.txt" -exec cat {} \; 2>/dev/null | \
        grep -oP 'https?://[^\s]+' | \
        sort -u > "${sensitive_dir}/endpoints/discovered-endpoints.txt" || true
    fi
    
    commit_step "Sensitive Endpoint Discovery"
    return 0
}

discover_sensitive_files() {
    log_message "Discovering sensitive files"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local sensitive_dir="${base_dir}/discovery/sensitive"
    
    # Common sensitive file patterns
    local files_list="${sensitive_dir}/files/sensitive-files.txt"
    cat > "$files_list" << 'EOF'
backup.sql
backup.zip
backup.tar.gz
backup.tar
database.sql
db_backup.sql
dump.sql
site_backup.zip
web_backup.tar.gz
backup_$(date +%Y).zip
backup_$(date +%Y-%m).zip
config.bak
config.old
config.backup
.env.backup
.env.old
.env.local
.env.production
.env.development
secrets.txt
passwords.txt
users.txt
credentials.txt
access.log
error.log
debug.log
app.log
system.log
access_log
error_log
application.log
server.log
.ssh/id_rsa.pub
.ssh/known_hosts
private.key
private.pem
certificate.pem
ssl.crt
ssl.key
id_rsa
id_dsa
authorized_keys
shadow
passwd
htpasswd
.htpasswd
.passwd
user.dat
accounts.txt
EOF

    # Search for files using common discovery tools
    if tool_available dirb; then
        log_info "Running dirb for file discovery"
        
        cat "${base_dir}/live-hosts.txt" | head -10 | while IFS= read -r url; do
            local host=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
            
            dirb "$url" "$files_list" \
                -o "${sensitive_dir}/files/dirb-${host}.txt" \
                -S \
                -w 2>/dev/null || true
        done
    fi
    
    commit_step "Sensitive File Discovery"
    return 0
}

search_for_secrets() {
    log_message "Searching for exposed secrets"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local sensitive_dir="${base_dir}/discovery/sensitive"
    
    # Regex patterns for common secrets
    local secrets_patterns="${sensitive_dir}/secrets/secret-patterns.txt"
    cat > "$secrets_patterns" << 'EOF'
aws_access_key_id
aws_secret_access_key
api_key
apikey
auth_token
authorization
bearer
password
passwd
secret
private_key
client_secret
client_id
database_url
db_password
mysql_password
postgres_password
redis_password
mongodb_password
jwt_secret
session_secret
encryption_key
slack_token
github_token
gitlab_token
stripe_key
paypal
mailgun
twilio
sendgrid
EOF

    # Use gf if available for pattern matching
    if tool_available gf && [[ -f "${base_dir}/all-urls.txt" ]]; then
        log_info "Searching for secrets in URLs with gf"
        
        # Search for potential secret exposure in URLs
        cat "${base_dir}/all-urls.txt" | gf secrets > "${sensitive_dir}/secrets/potential-secrets.txt" 2>/dev/null || true
    fi
    
    # Search for common secret patterns in discovered content
    if [[ -f "${base_dir}/crawler/all-urls.txt" ]]; then
        grep -iE "(api_key|apikey|secret|password|token|auth)" "${base_dir}/crawler/all-urls.txt" > \
            "${sensitive_dir}/secrets/url-secrets.txt" 2>/dev/null || true
    fi
    
    commit_step "Secret Discovery"
    return 0
}

analyze_configuration_files() {
    log_message "Analyzing configuration files"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local sensitive_dir="${base_dir}/discovery/sensitive"
    
    # Common configuration file endpoints
    local config_endpoints=(
        "/.env"
        "/config.json"
        "/config.yml"
        "/config.yaml"
        "/app.config"
        "/web.config"
        "/application.properties"
        "/config.php"
        "/settings.json"
        "/settings.yml"
        "/docker-compose.yml"
        "/package.json"
        "/composer.json"
        "/requirements.txt"
        "/Gemfile"
        "/pom.xml"
        "/build.gradle"
    )
    
    # Test for configuration files
    if [[ -s "${base_dir}/live-hosts.txt" ]]; then
        log_info "Testing for configuration files"
        
        while IFS= read -r base_url; do
            for endpoint in "${config_endpoints[@]}"; do
                local full_url="${base_url}${endpoint}"
                
                # Use curl to check if file exists and is accessible
                local response=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$full_url" 2>/dev/null || echo "000")
                
                if [[ "$response" =~ ^(200|201|202)$ ]]; then
                    echo "$full_url" >> "${sensitive_dir}/configs/accessible-configs.txt"
                fi
            done
        done < <(head -20 "${base_dir}/live-hosts.txt")
    fi
    
    commit_step "Configuration Analysis"
    return 0
}

discover_backup_files() {
    log_message "Discovering backup files"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local sensitive_dir="${base_dir}/discovery/sensitive"
    
    # Common backup file patterns
    local backup_patterns=(
        ".bak"
        ".backup"
        ".old"
        ".orig"
        ".save"
        ".tmp"
        ".temp"
        "~"
        ".swp"
        ".swo"
    )
    
    # Generate backup file wordlist based on discovered files
    if [[ -f "${base_dir}/all-urls.txt" ]]; then
        log_info "Generating backup file wordlist from discovered files"
        
        # Extract file names and generate backup variants
        grep -oP 'https?://[^/]+/[^?#]*\.[a-zA-Z]{2,4}' "${base_dir}/all-urls.txt" | \
        sed 's|.*/||' | \
        sort -u | \
        head -100 | \
        while IFS= read -r filename; do
            for pattern in "${backup_patterns[@]}"; do
                echo "${filename}${pattern}"
            done
        done > "${sensitive_dir}/backups/backup-wordlist.txt"
        
        # Test for backup files using the generated wordlist
        if tool_available ffuf && [[ -s "${sensitive_dir}/backups/backup-wordlist.txt" ]]; then
            cat "${base_dir}/live-hosts.txt" | head -10 | while IFS= read -r url; do
                local host=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
                
                ffuf -u "${url}/FUZZ" \
                    -w "${sensitive_dir}/backups/backup-wordlist.txt" \
                    -mc 200,201,202,204 \
                    -t 5 \
                    -rate 30 \
                    -timeout 10 \
                    -o "${sensitive_dir}/backups/ffuf-backups-${host}.json" \
                    -of json \
                    -s 2>/dev/null || true
            done
        fi
    fi
    
    commit_step "Backup File Discovery"
    return 0
}

consolidate_sensitive_results() {
    log_message "Consolidating sensitive discovery results"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local sensitive_dir="${base_dir}/discovery/sensitive"
    
    # Consolidate all discovered sensitive items
    local all_results=(
        "${sensitive_dir}/endpoints/discovered-endpoints.txt"
        "${sensitive_dir}/configs/accessible-configs.txt"
        "${sensitive_dir}/secrets/potential-secrets.txt"
        "${sensitive_dir}/secrets/url-secrets.txt"
    )
    
    cat "${all_results[@]}" 2>/dev/null | \
    sort -u > "${base_dir}/sensitive-files.txt"
    
    # Generate summary
    local endpoints_count=$(wc -l < "${sensitive_dir}/endpoints/discovered-endpoints.txt" 2>/dev/null || echo "0")
    local configs_count=$(wc -l < "${sensitive_dir}/configs/accessible-configs.txt" 2>/dev/null || echo "0")
    local secrets_count=$(wc -l < "${sensitive_dir}/secrets/potential-secrets.txt" 2>/dev/null || echo "0")
    local total_count=$(wc -l < "${base_dir}/sensitive-files.txt" 2>/dev/null || echo "0")
    
    cat > "${sensitive_dir}/sensitive-summary.txt" << EOF
SENSITIVE FILES DISCOVERY SUMMARY
=================================

Domain: $DOMAIN
Date: $(date)

Results:
- Sensitive Endpoints: $endpoints_count
- Configuration Files: $configs_count
- Potential Secrets: $secrets_count
- Total Items: $total_count

Top Sensitive Items:
$(head -20 "${base_dir}/sensitive-files.txt" 2>/dev/null || echo "None found")
EOF
    
    log_message "Sensitive discovery completed: $total_count items found"
    
    return 0
}

# =============================================================================
# MAIN SENSITIVE DISCOVERY EXECUTION
# =============================================================================

main_sensitive() {
    show_module_info "SENSITIVE FILES DISCOVERY" "Advanced sensitive files and endpoints discovery"
    
    notify_slack "🔍 [${DOMAIN}] Starting sensitive files discovery"
    
    # Initialize
    initialize_sensitive_discovery || {
        log_error "Failed to initialize sensitive discovery"
        return 1
    }
    
    # Execute discovery steps
    local discovery_steps=(
        "discover_sensitive_endpoints"
        "discover_sensitive_files"
        "search_for_secrets"
        "analyze_configuration_files"
        "discover_backup_files"
        "consolidate_sensitive_results"
    )
    
    local total_steps=${#discovery_steps[@]}
    local current_step=0
    local failed_steps=()
    
    for step in "${discovery_steps[@]}"; do
        ((current_step++))
        
        log_message "[$current_step/$total_steps] Executing: $step"
        
        if ! "$step"; then
            log_warning "Step failed: $step"
            failed_steps+=("$step")
        fi
        
        show_progress "$current_step" "$total_steps" "Sensitive discovery"
    done
    
    # Report results
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local total_found=$(wc -l < "${base_dir}/sensitive-files.txt" 2>/dev/null || echo "0")
    
    if [[ $total_found -gt 0 ]]; then
        log_message "Sensitive discovery completed successfully"
        log_message "Total sensitive items found: $total_found"
        
        # Show sample results
        echo -e "\n${YELLOW}Sample sensitive items discovered:${NC}"
        head -10 "${base_dir}/sensitive-files.txt" 2>/dev/null | while read -r item; do
            echo "  • $item"
        done
    else
        log_message "Sensitive discovery completed with no items found"
    fi
    
    # Report failed steps
    if [[ ${#failed_steps[@]} -gt 0 ]]; then
        log_warning "Some steps failed: ${failed_steps[*]}"
    fi
    
    # Final notification
    notify_slack "✅ [${DOMAIN}] Sensitive discovery completed - Found $total_found items"
    
    commit_step "Sensitive Files Discovery"
    return 0
}

# Execute main sensitive discovery function
main_sensitive
