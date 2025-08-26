#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Fuzzing Module
# Directory and file fuzzing with ffuf, dirsearch, feroxbuster, gobuster
# =============================================================================

# Ensure config is loaded
if [[ -z "${DIR_NINA:-}" ]]; then
    echo "Error: Config not loaded. This module should be run via nina-recon.sh"
    exit 1
fi

# =============================================================================
# FUZZING FUNCTIONS
# =============================================================================

initialize_fuzzing() {
    log_message "Initializing content fuzzing for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local fuzzing_dir="${base_dir}/discovery"
    
    # Create specialized subdirectories for fuzzing
    local subdirs=(
        "content"
        "directories"
        "files"
        "parameters"
        "wordlists"
        "backups"
        "extensions"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${fuzzing_dir}/${subdir}" 2>/dev/null
    done
    
    # Check if we have targets to fuzz
    local has_targets=false
    
    if [[ -f "${base_dir}/live-hosts.txt" && -s "${base_dir}/live-hosts.txt" ]]; then
        has_targets=true
    elif [[ -f "${base_dir}/all-discovered-urls.txt" && -s "${base_dir}/all-discovered-urls.txt" ]]; then
        log_info "Using discovered URLs as fuzzing targets"
        # Extract base URLs for fuzzing
        grep -oP '^https?://[^/]+' "${base_dir}/all-discovered-urls.txt" | \
        sort -u | head -20 > "${base_dir}/live-hosts.txt"
        has_targets=true
    elif [[ -f "${base_dir}/recon/subdomains-all.txt" && -s "${base_dir}/recon/subdomains-all.txt" ]]; then
        log_info "Using subdomains as fuzzing targets"
        while IFS= read -r subdomain; do
            echo "https://${subdomain}"
            echo "http://${subdomain}"
        done < "${base_dir}/recon/subdomains-all.txt" | head -20 > "${base_dir}/live-hosts.txt"
        has_targets=true
    elif [[ -n "$DOMAIN" ]]; then
        log_info "Using target domain as fuzzing target"
        echo "https://${DOMAIN}" > "${base_dir}/live-hosts.txt"
        echo "http://${DOMAIN}" >> "${base_dir}/live-hosts.txt"
        has_targets=true
    fi
    
    if [[ "$has_targets" != "true" ]]; then
        log_warning "No targets found for fuzzing"
        return 1
    fi
    
    return 0
}

directory_fuzzing() {
    log_message "Starting directory fuzzing"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local fuzzing_dir="${base_dir}/discovery"
    
    if [[ ! -f "${base_dir}/live-hosts.txt" ]]; then
        log_warning "No live hosts found for directory fuzzing"
        return 1
    fi
    
    # Prepare directory wordlist
    prepare_directory_wordlist "${fuzzing_dir}/wordlists/directories.txt"
    
    if [[ ! -f "${fuzzing_dir}/wordlists/directories.txt" ]]; then
        log_warning "No directory wordlist available"
        return 1
    fi
    
    local wordlist="${fuzzing_dir}/wordlists/directories.txt"
    local wordlist_size=$(wc -l < "$wordlist" 2>/dev/null || echo "0")
    
    log_info "Directory fuzzing with $wordlist_size words"
    
    # FFUF - Fast directory fuzzing
    if tool_available ffuf; then
        log_info "Running FFUF directory fuzzing"
        
        # Scope-specific settings
        local threads=40
        local rate=100
        local timeout=10
        
        case "${SCOPE_TYPE:-closed}" in
            "closed")
                threads=20
                rate=50
                timeout=15
                ;;
            "wildcard")
                threads=30
                rate=75
                timeout=12
                ;;
            "open")
                threads=50
                rate=150
                timeout=8
                ;;
        esac
        
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                local clean_host=$(echo "$host" | sed 's|/$||')
                log_info "FFUF fuzzing: $clean_host"
                
                ffuf -w "$wordlist" \
                    -u "${clean_host}/FUZZ" \
                    -t $threads \
                    -rate $rate \
                    -timeout $timeout \
                    -mc 200,201,204,301,302,307,401,403,405 \
                    -fc 404 \
                    -s \
                    -o "${fuzzing_dir}/directories/ffuf-$(echo "$host" | sed 's|https\?://||; s|/.*||; s|:.*||').json" \
                    -of json 2>/dev/null || true
            fi
        done < "${base_dir}/live-hosts.txt"
        
        # Parse FFUF results
        find "${fuzzing_dir}/directories" -name "ffuf-*.json" -exec jq -r '.results[]? | .url' {} \; 2>/dev/null | \
        sort -u > "${fuzzing_dir}/directories/ffuf-results.tmp"
        
        smart_save "${fuzzing_dir}/directories/ffuf-results.tmp" "${fuzzing_dir}/directories/ffuf-results.txt" "FFUF directories"
    fi
    
    # Feroxbuster - Recursive directory fuzzing
    if tool_available feroxbuster; then
        log_info "Running Feroxbuster"
        
        local threads=30
        local depth=2
        local timeout=7
        
        case "${SCOPE_TYPE:-closed}" in
            "closed")
                threads=15
                depth=3
                timeout=10
                ;;
            "wildcard")
                threads=20
                depth=2
                timeout=8
                ;;
            "open")
                threads=40
                depth=1
                timeout=5
                ;;
        esac
        
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                log_info "Feroxbuster scanning: $host"
                
                feroxbuster \
                    --url "$host" \
                    --wordlist "$wordlist" \
                    --threads $threads \
                    --depth $depth \
                    --timeout $timeout \
                    --status-codes 200,204,301,302,307,401,403,405 \
                    --silent \
                    --output "${fuzzing_dir}/directories/ferox-$(echo "$host" | sed 's|https\?://||; s|/.*||; s|:.*||').txt" 2>/dev/null || true
            fi
        done < "${base_dir}/live-hosts.txt"
        
        # Parse Feroxbuster results
        find "${fuzzing_dir}/directories" -name "ferox-*.txt" -exec grep -oE 'https?://[^\s]+' {} \; 2>/dev/null | \
        sort -u > "${fuzzing_dir}/directories/feroxbuster-results.tmp"
        
        smart_save "${fuzzing_dir}/directories/feroxbuster-results.tmp" "${fuzzing_dir}/directories/feroxbuster-results.txt" "Feroxbuster directories"
    fi
    
    # Gobuster - Alternative directory fuzzing
    if tool_available gobuster; then
        log_info "Running Gobuster"
        
        local threads=30
        local timeout=10
        
        case "${SCOPE_TYPE:-closed}" in
            "closed")
                threads=20
                timeout=15
                ;;
            "wildcard")
                threads=25
                timeout=12
                ;;
            "open")
                threads=40
                timeout=8
                ;;
        esac
        
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                log_info "Gobuster scanning: $host"
                
                gobuster dir \
                    -u "$host" \
                    -w "$wordlist" \
                    -t $threads \
                    --timeout "${timeout}s" \
                    -s "200,204,301,302,307,401,403,405" \
                    -q \
                    -o "${fuzzing_dir}/directories/gobuster-$(echo "$host" | sed 's|https\?://||; s|/.*||; s|:.*||').txt" 2>/dev/null || true
            fi
        done < "${base_dir}/live-hosts.txt"
        
        # Parse Gobuster results
        find "${fuzzing_dir}/directories" -name "gobuster-*.txt" -exec grep -oE 'https?://[^\s]+' {} \; 2>/dev/null | \
        sort -u > "${fuzzing_dir}/directories/gobuster-results.tmp"
        
        smart_save "${fuzzing_dir}/directories/gobuster-results.tmp" "${fuzzing_dir}/directories/gobuster-results.txt" "Gobuster directories"
    fi
    
    # Dirsearch - Python-based directory fuzzing
    if tool_available dirsearch; then
        log_info "Running Dirsearch"
        
        local threads=30
        local extensions="php,html,js,txt,json,xml,config,bak,old"
        
        case "${SCOPE_TYPE:-closed}" in
            "closed")
                threads=20
                extensions="php,html,js,txt,json,xml,config,bak,old,log,sql,db"
                ;;
            "wildcard")
                threads=25
                extensions="php,html,js,txt,json,xml,config,bak"
                ;;
            "open")
                threads=40
                extensions="php,html,js,txt,json"
                ;;
        esac
        
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                log_info "Dirsearch scanning: $host"
                
                dirsearch \
                    -u "$host" \
                    -w "$wordlist" \
                    -t $threads \
                    -e "$extensions" \
                    --timeout=10 \
                    --quiet \
                    --format=simple \
                    -o "${fuzzing_dir}/directories/dirsearch-$(echo "$host" | sed 's|https\?://||; s|/.*||; s|:.*||').txt" 2>/dev/null || true
            fi
        done < "${base_dir}/live-hosts.txt"
        
        # Parse Dirsearch results
        find "${fuzzing_dir}/directories" -name "dirsearch-*.txt" -exec grep -oE 'https?://[^\s]+' {} \; 2>/dev/null | \
        sort -u > "${fuzzing_dir}/directories/dirsearch-results.tmp"
        
        smart_save "${fuzzing_dir}/directories/dirsearch-results.tmp" "${fuzzing_dir}/directories/dirsearch-results.txt" "Dirsearch directories"
    fi
    
    # Combine all directory fuzzing results
    local dir_sources=(
        "${fuzzing_dir}/directories/ffuf-results.txt"
        "${fuzzing_dir}/directories/feroxbuster-results.txt"
        "${fuzzing_dir}/directories/gobuster-results.txt"
        "${fuzzing_dir}/directories/dirsearch-results.txt"
    )
    
    smart_combine "${dir_sources[@]}" "${fuzzing_dir}/content/all-directories.txt"
    
    commit_step "Directory Fuzzing"
    return 0
}

file_fuzzing() {
    log_message "Starting file fuzzing"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local fuzzing_dir="${base_dir}/discovery"
    
    if [[ ! -f "${base_dir}/live-hosts.txt" ]]; then
        log_warning "No live hosts found for file fuzzing"
        return 1
    fi
    
    # Prepare file wordlist
    prepare_file_wordlist "${fuzzing_dir}/wordlists/files.txt"
    
    if [[ ! -f "${fuzzing_dir}/wordlists/files.txt" ]]; then
        log_warning "No file wordlist available"
        return 1
    fi
    
    local wordlist="${fuzzing_dir}/wordlists/files.txt"
    local wordlist_size=$(wc -l < "$wordlist" 2>/dev/null || echo "0")
    
    log_info "File fuzzing with $wordlist_size words"
    
    # FFUF for file fuzzing
    if tool_available ffuf; then
        log_info "Running FFUF file fuzzing"
        
        local threads=30
        local rate=80
        
        case "${SCOPE_TYPE:-closed}" in
            "closed")
                threads=20
                rate=50
                ;;
            "wildcard")
                threads=25
                rate=65
                ;;
            "open")
                threads=40
                rate=100
                ;;
        esac
        
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                local clean_host=$(echo "$host" | sed 's|/$||')
                log_info "FFUF file fuzzing: $clean_host"
                
                ffuf -w "$wordlist" \
                    -u "${clean_host}/FUZZ" \
                    -t $threads \
                    -rate $rate \
                    -timeout 10 \
                    -mc 200,201,204,301,302,401,403 \
                    -fc 404 \
                    -s \
                    -o "${fuzzing_dir}/files/ffuf-files-$(echo "$host" | sed 's|https\?://||; s|/.*||; s|:.*||').json" \
                    -of json 2>/dev/null || true
            fi
        done < "${base_dir}/live-hosts.txt"
        
        # Parse FFUF file results
        find "${fuzzing_dir}/files" -name "ffuf-files-*.json" -exec jq -r '.results[]? | .url' {} \; 2>/dev/null | \
        sort -u > "${fuzzing_dir}/files/ffuf-files.tmp"
        
        smart_save "${fuzzing_dir}/files/ffuf-files.tmp" "${fuzzing_dir}/files/ffuf-files.txt" "FFUF files"
    fi
    
    # Specialized backup file fuzzing
    backup_file_fuzzing
    
    # Common sensitive files
    sensitive_file_fuzzing
    
    # Combine all file results
    local file_sources=(
        "${fuzzing_dir}/files/ffuf-files.txt"
        "${fuzzing_dir}/backups/backup-files.txt"
        "${fuzzing_dir}/files/sensitive-files.txt"
    )
    
    smart_combine "${file_sources[@]}" "${fuzzing_dir}/content/all-files.txt"
    
    commit_step "File Fuzzing"
    return 0
}

backup_file_fuzzing() {
    log_message "Fuzzing for backup files"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local fuzzing_dir="${base_dir}/discovery"
    
    # Common backup file patterns
    local backup_extensions=(
        ".bak"
        ".backup"
        ".old"
        ".orig"
        ".save"
        ".tmp"
        ".temp"
        "~"
        ".1"
        ".2"
        ".swp"
        ".swo"
    )
    
    # Common backup filenames
    local backup_files=(
        "backup.zip"
        "backup.tar.gz"
        "backup.sql"
        "database.sql"
        "db.sql"
        "dump.sql"
        "config.bak"
        "config.old"
        "wp-config.php.bak"
        ".env.bak"
        ".env.old"
        "settings.py.bak"
        "web.config.bak"
    )
    
    # Test backup files
    if [[ -f "${base_dir}/live-hosts.txt" ]]; then
        log_info "Testing backup file patterns"
        
        {
            # Add backup extensions to common files
            for file in "index" "config" "settings" "database" "admin" "login" "test"; do
                for ext in "${backup_extensions[@]}"; do
                    echo "${file}${ext}"
                    echo "${file}.php${ext}"
                    echo "${file}.html${ext}"
                    echo "${file}.js${ext}"
                done
            done
            
            # Add specific backup files
            printf '%s\n' "${backup_files[@]}"
            
        } | sort -u > "${fuzzing_dir}/wordlists/backup-files.txt"
        
        # Use FFUF to test backup files
        if tool_available ffuf; then
            while IFS= read -r host; do
                if [[ -n "$host" ]]; then
                    local clean_host=$(echo "$host" | sed 's|/$||')
                    
                    ffuf -w "${fuzzing_dir}/wordlists/backup-files.txt" \
                        -u "${clean_host}/FUZZ" \
                        -t 20 \
                        -rate 40 \
                        -timeout 10 \
                        -mc 200,201,301,302,401,403 \
                        -fc 404 \
                        -s \
                        -o "${fuzzing_dir}/backups/backup-$(echo "$host" | sed 's|https\?://||; s|/.*||; s|:.*||').json" \
                        -of json 2>/dev/null || true
                fi
            done < "${base_dir}/live-hosts.txt"
            
            # Parse backup results
            find "${fuzzing_dir}/backups" -name "backup-*.json" -exec jq -r '.results[]? | .url' {} \; 2>/dev/null | \
            sort -u > "${fuzzing_dir}/backups/backup-files.tmp"
            
            smart_save "${fuzzing_dir}/backups/backup-files.tmp" "${fuzzing_dir}/backups/backup-files.txt" "backup files"
        fi
    fi
    
    return 0
}

sensitive_file_fuzzing() {
    log_message "Fuzzing for sensitive files"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local fuzzing_dir="${base_dir}/discovery"
    
    # Common sensitive files
    local sensitive_files=(
        ".env"
        ".env.local"
        ".env.production"
        "config.php"
        "configuration.php"
        "settings.php"
        "wp-config.php"
        "web.config"
        "app.config"
        "database.yml"
        "secrets.yml"
        "credentials.yml"
        "id_rsa"
        "id_dsa"
        "private.key"
        "server.key"
        "certificate.pem"
        "robots.txt"
        "sitemap.xml"
        "crossdomain.xml"
        "clientaccesspolicy.xml"
        "phpinfo.php"
        "info.php"
        "test.php"
        "debug.php"
        "adminer.php"
        "phpmyadmin"
        "admin"
        "administrator"
        "login"
        "auth"
        ".git/config"
        ".svn/entries"
        ".htaccess"
        ".htpasswd"
        "error_log"
        "access_log"
        "error.log"
        "access.log"
        "app.log"
        "application.log"
    )
    
    printf '%s\n' "${sensitive_files[@]}" > "${fuzzing_dir}/wordlists/sensitive-files.txt"
    
    # Test sensitive files
    if tool_available ffuf && [[ -f "${base_dir}/live-hosts.txt" ]]; then
        log_info "Testing sensitive files"
        
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                local clean_host=$(echo "$host" | sed 's|/$||')
                
                ffuf -w "${fuzzing_dir}/wordlists/sensitive-files.txt" \
                    -u "${clean_host}/FUZZ" \
                    -t 15 \
                    -rate 30 \
                    -timeout 10 \
                    -mc 200,201,301,302,401,403 \
                    -fc 404 \
                    -s \
                    -o "${fuzzing_dir}/files/sensitive-$(echo "$host" | sed 's|https\?://||; s|/.*||; s|:.*||').json" \
                    -of json 2>/dev/null || true
            fi
        done < "${base_dir}/live-hosts.txt"
        
        # Parse sensitive file results
        find "${fuzzing_dir}/files" -name "sensitive-*.json" -exec jq -r '.results[]? | .url' {} \; 2>/dev/null | \
        sort -u > "${fuzzing_dir}/files/sensitive-files.tmp"
        
        smart_save "${fuzzing_dir}/files/sensitive-files.tmp" "${fuzzing_dir}/files/sensitive-files.txt" "sensitive files"
    fi
    
    return 0
}

parameter_discovery() {
    log_message "Starting parameter discovery"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local fuzzing_dir="${base_dir}/discovery"
    
    # Prepare parameter wordlist
    prepare_parameter_wordlist "${fuzzing_dir}/wordlists/parameters.txt"
    
    if [[ ! -f "${fuzzing_dir}/wordlists/parameters.txt" ]]; then
        log_warning "No parameter wordlist available"
        return 1
    fi
    
    local wordlist="${fuzzing_dir}/wordlists/parameters.txt"
    local wordlist_size=$(wc -l < "$wordlist" 2>/dev/null || echo "0")
    
    log_info "Parameter discovery with $wordlist_size parameters"
    
    # Use discovered URLs or live hosts
    local target_file="${base_dir}/all-discovered-urls.txt"
    if [[ ! -f "$target_file" ]]; then
        target_file="${base_dir}/live-hosts.txt"
    fi
    
    if [[ ! -f "$target_file" ]]; then
        log_warning "No targets found for parameter discovery"
        return 1
    fi
    
    # FFUF parameter discovery
    if tool_available ffuf; then
        log_info "Running FFUF parameter discovery"
        
        local threads=25
        local rate=60
        
        case "${SCOPE_TYPE:-closed}" in
            "closed")
                threads=15
                rate=40
                ;;
            "wildcard")
                threads=20
                rate=50
                ;;
            "open")
                threads=30
                rate=80
                ;;
        esac
        
        # Take sample of URLs for parameter testing
        head -10 "$target_file" | while IFS= read -r url; do
            if [[ -n "$url" ]]; then
                log_info "Parameter fuzzing: $url"
                
                # Test GET parameters
                ffuf -w "$wordlist" \
                    -u "${url}?FUZZ=test" \
                    -t $threads \
                    -rate $rate \
                    -timeout 8 \
                    -mc 200,201,400,401,403,422,500 \
                    -fc 404 \
                    -s \
                    -o "${fuzzing_dir}/parameters/params-$(echo "$url" | sed 's|https\?://||; s|[^a-zA-Z0-9]|-|g').json" \
                    -of json 2>/dev/null || true
                    
                # Test POST parameters (basic)
                ffuf -w "$wordlist" \
                    -u "$url" \
                    -X POST \
                    -d "FUZZ=test" \
                    -H "Content-Type: application/x-www-form-urlencoded" \
                    -t $threads \
                    -rate $rate \
                    -timeout 8 \
                    -mc 200,201,400,401,403,422,500 \
                    -fc 404 \
                    -s \
                    -o "${fuzzing_dir}/parameters/post-params-$(echo "$url" | sed 's|https\?://||; s|[^a-zA-Z0-9]|-|g').json" \
                    -of json 2>/dev/null || true
            fi
        done
        
        # Parse parameter results
        find "${fuzzing_dir}/parameters" -name "*.json" -exec jq -r '.results[]? | .input.FUZZ' {} \; 2>/dev/null | \
        sort -u > "${fuzzing_dir}/parameters/found-parameters.tmp"
        
        smart_save "${fuzzing_dir}/parameters/found-parameters.tmp" "${fuzzing_dir}/parameters/found-parameters.txt" "parameters"
    fi
    
    commit_step "Parameter Discovery"
    return 0
}

consolidate_fuzzing_results() {
    log_message "Consolidating fuzzing results"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local fuzzing_dir="${base_dir}/discovery"
    
    # Combine all fuzzing results
    local all_sources=(
        "${fuzzing_dir}/content/all-directories.txt"
        "${fuzzing_dir}/content/all-files.txt"
        "${fuzzing_dir}/backups/backup-files.txt"
        "${fuzzing_dir}/files/sensitive-files.txt"
    )
    
    smart_combine "${all_sources[@]}" "${base_dir}/all-fuzzing-results.txt"
    
    # Create fuzzing summary
    local total_dirs=$(wc -l < "${fuzzing_dir}/content/all-directories.txt" 2>/dev/null || echo "0")
    local total_files=$(wc -l < "${fuzzing_dir}/content/all-files.txt" 2>/dev/null || echo "0")
    local backup_files=$(wc -l < "${fuzzing_dir}/backups/backup-files.txt" 2>/dev/null || echo "0")
    local sensitive_files=$(wc -l < "${fuzzing_dir}/files/sensitive-files.txt" 2>/dev/null || echo "0")
    local parameters=$(wc -l < "${fuzzing_dir}/parameters/found-parameters.txt" 2>/dev/null || echo "0")
    local total_findings=$(wc -l < "${base_dir}/all-fuzzing-results.txt" 2>/dev/null || echo "0")
    
    cat > "${fuzzing_dir}/fuzzing-summary.txt" << EOF
CONTENT FUZZING SUMMARY
=======================

Target Domain: $DOMAIN
Fuzzing Date: $(date)
Scope Type: ${SCOPE_TYPE:-auto}

DISCOVERED CONTENT:
• Total Directories: $total_dirs
• Total Files: $total_files  
• Backup Files: $backup_files
• Sensitive Files: $sensitive_files
• Parameters: $parameters
• Total Findings: $total_findings

FUZZING TOOLS USED:
✓ FFUF (Fast web fuzzer)
✓ Feroxbuster (Recursive fuzzing)
✓ Gobuster (Directory/file brute forcer)
✓ Dirsearch (Web path scanner)

FUZZING CATEGORIES:
✓ Directory Discovery
✓ File Discovery
✓ Backup File Detection
✓ Sensitive File Detection
✓ Parameter Discovery

FILES CREATED:
📁 ${fuzzing_dir}/content/all-directories.txt
📁 ${fuzzing_dir}/content/all-files.txt
📁 ${fuzzing_dir}/backups/backup-files.txt
📁 ${fuzzing_dir}/files/sensitive-files.txt
📁 ${fuzzing_dir}/parameters/found-parameters.txt
📁 ${base_dir}/all-fuzzing-results.txt

EOF
    
    log_message "Fuzzing completed: $total_findings total findings"
    
    commit_step "Fuzzing Results Consolidation"
    return 0
}

# =============================================================================
# WORDLIST PREPARATION FUNCTIONS
# =============================================================================

prepare_directory_wordlist() {
    local output_wordlist="$1"
    log_info "Preparing directory wordlist"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    
    # Base wordlist sources
    local wordlist_sources=(
        "$WORDLIST_DIRECTORIES"
        "${DIR_NINA_LISTS}/dicc.txt"
        "${DIR_NINA_LISTS}/common.txt"
        "${DIR_NINA_LISTS}/httparchive_directories_1m_2024_05_28.txt"
        "${base_dir}/discovery/wordlists/discovered-paths.txt"
    )
    
    # Start with base wordlists
    cat "${wordlist_sources[@]}" 2>/dev/null | \
    grep -v '^$' | \
    grep -E '^[a-zA-Z0-9._-]+$' | \
    sort -u > "$output_wordlist.tmp"
    
    # Add common directories if wordlist is small
    local current_size=$(wc -l < "$output_wordlist.tmp" 2>/dev/null || echo "0")
    if [[ $current_size -lt 1000 ]]; then
        log_info "Adding common directories to wordlist"
        
        local common_dirs=(
            "admin" "administrator" "auth" "login" "panel" "dashboard"
            "api" "rest" "graphql" "v1" "v2" "v3" "docs" "documentation"
            "backup" "backups" "old" "tmp" "temp" "test" "dev" "development"
            "config" "configuration" "settings" "setup" "install" "installation"
            "upload" "uploads" "files" "images" "img" "assets" "static"
            "js" "css" "scripts" "styles" "fonts" "media" "data"
            "include" "includes" "lib" "libs" "vendor" "modules" "plugins"
            "log" "logs" "debug" "error" "access" "audit"
            "db" "database" "sql" "mysql" "postgres" "mongo"
            "mail" "email" "smtp" "ftp" "ssh" "vpn" "proxy"
            "user" "users" "account" "accounts" "profile" "profiles"
            "search" "find" "browse" "view" "edit" "delete" "create"
            "news" "blog" "post" "posts" "article" "articles" "content"
            "shop" "store" "cart" "checkout" "payment" "order" "orders"
            "help" "support" "contact" "about" "terms" "privacy" "policy"
        )
        
        printf '%s\n' "${common_dirs[@]}" >> "$output_wordlist.tmp"
    fi
    
    # Final processing
    sort -u "$output_wordlist.tmp" | head -5000 > "$output_wordlist"
    rm -f "$output_wordlist.tmp"
    
    local final_size=$(wc -l < "$output_wordlist" 2>/dev/null || echo "0")
    log_info "Directory wordlist prepared: $final_size entries"
    
    return 0
}

prepare_file_wordlist() {
    local output_wordlist="$1"
    log_info "Preparing file wordlist"
    
    # Base file wordlist sources
    local wordlist_sources=(
        "$WORDLIST_FILES"
        "${DIR_NINA_LISTS}/files.txt"
        "${DIR_NINA_LISTS}/common-files.txt"
    )
    
    # Start with base wordlists
    cat "${wordlist_sources[@]}" 2>/dev/null | \
    grep -v '^$' | \
    grep -E '\.' | \
    sort -u > "$output_wordlist.tmp"
    
    # Add common file extensions if wordlist is small
    local current_size=$(wc -l < "$output_wordlist.tmp" 2>/dev/null || echo "0")
    if [[ $current_size -lt 500 ]]; then
        log_info "Adding common files to wordlist"
        
        local base_names=("index" "default" "home" "main" "app" "config" "settings" "test" "demo" "admin" "login" "auth" "api" "docs" "help" "contact" "about")
        local extensions=("php" "html" "htm" "js" "css" "txt" "xml" "json" "yml" "yaml" "conf" "config" "ini" "log" "bak" "backup" "old" "orig" "tmp" "temp")
        
        for base in "${base_names[@]}"; do
            for ext in "${extensions[@]}"; do
                echo "${base}.${ext}"
            done
        done >> "$output_wordlist.tmp"
    fi
    
    # Final processing
    sort -u "$output_wordlist.tmp" | head -3000 > "$output_wordlist"
    rm -f "$output_wordlist.tmp"
    
    local final_size=$(wc -l < "$output_wordlist" 2>/dev/null || echo "0")
    log_info "File wordlist prepared: $final_size entries"
    
    return 0
}

prepare_parameter_wordlist() {
    local output_wordlist="$1"
    log_info "Preparing parameter wordlist"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    
    local param_sources=(
        "$WORDLIST_PARAMETERS"
        "${base_dir}/discovery/wordlists/discovered-parameters.txt"
    )
    
    cat "${param_sources[@]}" 2>/dev/null | \
    grep -v '^$' | \
    sort -u > "$output_wordlist.tmp"
    
    # Add common parameters if wordlist is small
    local current_size=$(wc -l < "$output_wordlist.tmp" 2>/dev/null || echo "0")
    if [[ $current_size -lt 200 ]]; then
        log_info "Adding common parameters to wordlist"
        
        local common_params=(
            "id" "user" "username" "email" "password" "pass" "token" "key" "secret"
            "q" "query" "search" "term" "keyword" "filter" "sort" "order" "page" "limit"
            "name" "title" "description" "content" "message" "text" "data" "value"
            "action" "method" "type" "format" "mode" "status" "state" "flag" "option"
            "file" "filename" "path" "url" "link" "redirect" "return" "callback" "next"
            "api_key" "access_token" "refresh_token" "session" "csrf" "nonce" "hash"
            "admin" "debug" "test" "dev" "demo" "example" "sample" "mock" "fake"
            "lang" "language" "locale" "country" "region" "timezone" "date" "time"
            "category" "tag" "tags" "label" "group" "role" "permission" "level"
            "start" "end" "from" "to" "min" "max" "size" "count" "total" "sum"
        )
        
        printf '%s\n' "${common_params[@]}" >> "$output_wordlist.tmp"
    fi
    
    # Final processing
    sort -u "$output_wordlist.tmp" | head -2000 > "$output_wordlist"
    rm -f "$output_wordlist.tmp"
    
    local final_size=$(wc -l < "$output_wordlist" 2>/dev/null || echo "0")
    log_info "Parameter wordlist prepared: $final_size entries"
    
    return 0
}

# =============================================================================
# MAIN FUZZING EXECUTION
# =============================================================================

main_fuzzing() {
    log_message "Starting content fuzzing module"
    
    # Initialize fuzzing environment
    if ! initialize_fuzzing; then
        log_error "Failed to initialize fuzzing"
        return 1
    fi
    
    # Execute fuzzing functions
    directory_fuzzing
    file_fuzzing
    parameter_discovery
    consolidate_fuzzing_results
    
    log_message "Content fuzzing completed"
    return 0
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_fuzzing "$@"
fi
