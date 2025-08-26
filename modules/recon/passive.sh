#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Passive Reconnaissance Module
# Advanced OSINT-based subdomain enumeration and data gathering
# =============================================================================

# Ensure config is loaded

# Ensure base directories exist
mkdir -p "${DIR_OUTPUT}/${DOMAIN}/log" 2>/dev/null
mkdir -p "${DIR_OUTPUT}/${DOMAIN}/$(basename "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")" 2>/dev/null

if [[ -z "${DIR_NINA:-}" ]]; then
    echo "Error: Config not loaded. This module should be run via nina-recon.sh"
    exit 1
fi

# =============================================================================
# PASSIVE RECONNAISSANCE FUNCTIONS
# =============================================================================

initialize_passive_recon() {
    log_message "Initializing passive reconnaissance for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local recon_dir="${base_dir}/recon/passive"
    
    # Create specialized subdirectories
    local subdirs=(
        "certificates"
        "archives"
        "github"
        "apis"
        "dns"
        "search_engines"
        "threat_intel"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${recon_dir}/${subdir}" 2>/dev/null
    done
    
    # Initialize tracking files
    echo "$DOMAIN" > "${base_dir}/target-domain.txt"
    echo "$DOMAIN" > "${recon_dir}/seed-domains.txt"
    
    return 0
}

certificate_transparency() {
    log_message "Running certificate transparency search"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local cert_dir="${base_dir}/recon/passive/certificates"
    
    # crt.sh search with multiple approaches
    log_info "Searching crt.sh for certificate data"
    
    # Method 1: Standard wildcard search
    curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    grep -v '^$' | \
    sort -u > "${cert_dir}/crtsh-wildcard.txt" || true
    
    # Method 2: Direct domain search
    curl -s "https://crt.sh/?q=${DOMAIN}&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    grep -v '^$' | \
    sort -u > "${cert_dir}/crtsh-direct.txt" || true
    
    # Method 3: Search with percent encoding
    local encoded_domain=$(printf '%s\n' "$DOMAIN" | sed 's/\./\\./g')
    curl -s "https://crt.sh/?q=${encoded_domain}&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    grep -v '^$' | \
    sort -u > "${cert_dir}/crtsh-encoded.txt" || true
    
    # Combine all certificate results
    cat "${cert_dir}"/crtsh-*.txt 2>/dev/null | \
    sort -u > "${cert_dir}/all-certificates.txt"
    
    # TLSX enumeration if available
    if tool_available tlsx; then
        log_info "Running TLSX enumeration"
        echo "$DOMAIN" | tlsx -json -silent -cn -san 2>/dev/null | \
        jq -r '.subject_an[]?, .subject_cn?' 2>/dev/null | \
        grep -v '^null$' | grep -v '^$' | \
        sort -u > "${cert_dir}/tlsx-results.txt" || true
    fi
    
    # Certspotter API if available
    log_info "Checking Certspotter"
    curl -s "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" 2>/dev/null | \
    jq -r '.[].dns_names[]?' 2>/dev/null | \
    grep -v '^$' | \
    sort -u > "${cert_dir}/certspotter.txt" || true
    
    # Combine all certificate sources
    cat "${cert_dir}"/*.txt 2>/dev/null | \
    grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
    sort -u > "${base_dir}/recon/certificates-all.txt"
    
    local cert_count=$(wc -l < "${base_dir}/recon/certificates-all.txt" 2>/dev/null || echo "0")
    log_message "Certificate transparency: $cert_count subdomains found"
    
    commit_step "Certificate Transparency"
    return 0
}

threat_intelligence_apis() {
    log_message "Querying threat intelligence APIs"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local intel_dir="${base_dir}/recon/passive/threat_intel"
    
    # AlienVault OTX
    log_info "Querying AlienVault OTX"
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" 2>/dev/null | \
    jq -r '.passive_dns[]?.hostname' 2>/dev/null | \
    grep -v '^null$' | grep -v '^$' | \
    sort -u > "${intel_dir}/alienvault-otx.txt" || true
    
    # ThreatCrowd
    log_info "Querying ThreatCrowd"
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${DOMAIN}" 2>/dev/null | \
    jq -r '.subdomains[]?' 2>/dev/null | \
    grep -v '^null$' | grep -v '^$' | \
    sort -u > "${intel_dir}/threatcrowd.txt" || true
    
    # VirusTotal (if API key available)
    if [[ -f "${DIR_NINA_CREDS}/virustotal.txt" ]] && [[ -s "${DIR_NINA_CREDS}/virustotal.txt" ]]; then
        log_info "Querying VirusTotal"
        local vt_api_key=$(cat "${DIR_NINA_CREDS}/virustotal.txt" | head -1)
        curl -s -H "x-apikey: ${vt_api_key}" \
        "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${vt_api_key}&domain=${DOMAIN}" 2>/dev/null | \
        jq -r '.subdomains[]?' 2>/dev/null | \
        grep -v '^null$' | grep -v '^$' | \
        sort -u > "${intel_dir}/virustotal.txt" || true
    fi
    
    # SecurityTrails (if API key available)
    if [[ -f "${SECURITYTRAILS_API_KEY_FILE}" ]] && [[ -s "${SECURITYTRAILS_API_KEY_FILE}" ]]; then
        log_info "Querying SecurityTrails"
        local st_api_key=$(cat "${SECURITYTRAILS_API_KEY_FILE}" | head -1)
        curl -s -H "APIKEY: ${st_api_key}" \
        "https://api.securitytrails.com/v1/domain/${DOMAIN}/subdomains" 2>/dev/null | \
        jq -r '.subdomains[]?' 2>/dev/null | \
        sed "s/$/.${DOMAIN}/" | \
        grep -v '^null' | grep -v '^$' | \
        sort -u > "${intel_dir}/securitytrails.txt" || true
    fi
    
    # Combine threat intel results
    cat "${intel_dir}"/*.txt 2>/dev/null | \
    sort -u > "${base_dir}/recon/threat-intelligence.txt"
    
    local intel_count=$(wc -l < "${base_dir}/recon/threat-intelligence.txt" 2>/dev/null || echo "0")
    log_message "Threat intelligence: $intel_count subdomains found"
    
    commit_step "Threat Intelligence"
    return 0
}

web_archives_enumeration() {
    log_message "Enumerating web archives"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local archive_dir="${base_dir}/recon/passive/archives"
    
    # Wayback Machine
    log_info "Searching Wayback Machine"
    
    # Get archived URLs and extract subdomains
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=text&fl=original&collapse=urlkey" 2>/dev/null | \
    sed 's/^http[s]*:\/\///' | \
    awk -F[:/] '{print $1}' | \
    grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
    sort -u > "${archive_dir}/wayback-subdomains.txt" || true
    
    # Also get URLs for later processing
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=text&fl=original&collapse=urlkey" 2>/dev/null | \
    head -10000 > "${archive_dir}/wayback-urls.txt" || true
    
    # Common Crawl (using index)
    log_info "Searching Common Crawl"
    
    # Get latest index
    local cc_index=$(curl -s "https://index.commoncrawl.org/collinfo.json" 2>/dev/null | \
    jq -r '.[0].id' 2>/dev/null || echo "")
    
    if [[ -n "$cc_index" ]]; then
        curl -s "https://index.commoncrawl.org/${cc_index}-index?url=*.${DOMAIN}&output=json" 2>/dev/null | \
        jq -r '.url' 2>/dev/null | \
        sed 's/^http[s]*:\/\///' | \
        awk -F[:/] '{print $1}' | \
        grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
        sort -u > "${archive_dir}/commoncrawl.txt" || true
    fi
    
    # GAU (Get All URLs)
    if tool_available gau; then
        log_info "Running GAU"
        echo "$DOMAIN" | gau --subs --threads 50 2>/dev/null | \
        head -50000 | \
        grep -oE 'https?://[^/]+' | \
        sed 's/^http[s]*:\/\///' | \
        awk -F[:/] '{print $1}' | \
        grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
        sort -u > "${archive_dir}/gau-subdomains.txt" || true
        
        # Also save URLs for content discovery
        echo "$DOMAIN" | gau --subs --threads 50 2>/dev/null | \
        head -50000 > "${archive_dir}/gau-urls.txt" || true
    fi
    
    # Waybackurls
    if tool_available waybackurls; then
        log_info "Running Waybackurls"
        echo "$DOMAIN" | waybackurls 2>/dev/null | \
        head -50000 | \
        grep -oE 'https?://[^/]+' | \
        sed 's/^http[s]*:\/\///' | \
        awk -F[:/] '{print $1}' | \
        grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
        sort -u > "${archive_dir}/waybackurls-subdomains.txt" || true
        
        # Save URLs too
        echo "$DOMAIN" | waybackurls 2>/dev/null | \
        head -50000 > "${archive_dir}/waybackurls-urls.txt" || true
    fi
    
    # Combine archive results
    cat "${archive_dir}"/*-subdomains.txt 2>/dev/null | \
    sort -u > "${base_dir}/recon/archives-subdomains.txt"
    
    # Combine URLs for later use
    cat "${archive_dir}"/*-urls.txt 2>/dev/null | \
    sort -u > "${base_dir}/discovery/archive-urls.txt"
    
    local archive_count=$(wc -l < "${base_dir}/recon/archives-subdomains.txt" 2>/dev/null || echo "0")
    log_message "Web archives: $archive_count subdomains found"
    
    commit_step "Web Archives"
    return 0
}

github_reconnaissance() {
    log_message "Running GitHub reconnaissance"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local github_dir="${base_dir}/recon/passive/github"
    
    # GitHub Subdomains tool
    if tool_available github-subdomains && [[ -f "${GITHUB_TOKEN_FILE}" ]] && [[ -s "${GITHUB_TOKEN_FILE}" ]]; then
        log_info "Running github-subdomains tool"
        github-subdomains -d "$DOMAIN" -t "${GITHUB_TOKEN_FILE}" \
        -o "${github_dir}/github-subdomains-tool.txt" 2>/dev/null || true
    fi
    
    # Manual GitHub search using API
    if [[ -f "${GITHUB_TOKEN_FILE}" ]] && [[ -s "${GITHUB_TOKEN_FILE}" ]]; then
        log_info "Performing GitHub API search"
        local github_token=$(cat "${GITHUB_TOKEN_FILE}" | head -1)
        
        # Search for domain in code
        curl -s -H "Authorization: token ${github_token}" \
        "https://api.github.com/search/code?q=${DOMAIN}&per_page=100" 2>/dev/null | \
        jq -r '.items[]?.html_url' 2>/dev/null | \
        head -100 > "${github_dir}/github-code-references.txt" || true
        
        # Search for repositories
        curl -s -H "Authorization: token ${github_token}" \
        "https://api.github.com/search/repositories?q=${DOMAIN}&per_page=100" 2>/dev/null | \
        jq -r '.items[]?.html_url' 2>/dev/null | \
        head -100 > "${github_dir}/github-repositories.txt" || true
    fi
    
    # Dorking approach (without API)
    log_info "GitHub dorking search"
    
    # Use curl to search GitHub directly
    local search_terms=(
        "\"${DOMAIN}\""
        "site:${DOMAIN}"
        "*.${DOMAIN}"
        "${DOMAIN} subdomain"
        "${DOMAIN} api"
        "${DOMAIN} config"
    )
    
    for term in "${search_terms[@]}"; do
        # GitHub search (limited without API)
        curl -s "https://github.com/search?q=${term}&type=Code" 2>/dev/null | \
        grep -oE 'href="[^"]*"' | \
        grep -E "\.${DOMAIN}|${DOMAIN}" | \
        head -20 >> "${github_dir}/github-search-results.txt" || true
        
        sleep 2  # Be nice to GitHub
    done
    
    # Extract potential subdomains from all GitHub results
    cat "${github_dir}"/*.txt 2>/dev/null | \
    grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
    grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
    sort -u > "${base_dir}/recon/github-subdomains.txt"
    
    local github_count=$(wc -l < "${base_dir}/recon/github-subdomains.txt" 2>/dev/null || echo "0")
    log_message "GitHub reconnaissance: $github_count subdomains found"
    
    commit_step "GitHub Reconnaissance"
    return 0
}

dns_enumeration_passive() {
    log_message "Running passive DNS enumeration"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local dns_dir="${base_dir}/recon/passive/dns"
    
    # DNS History (using various sources)
    log_info "Querying DNS history sources"
    
    # Shodan (if API key available)
    if [[ -f "${SHODAN_API_KEY_FILE}" ]] && [[ -s "${SHODAN_API_KEY_FILE}" ]]; then
        log_info "Querying Shodan"
        local shodan_key=$(cat "${SHODAN_API_KEY_FILE}" | head -1)
        curl -s "https://api.shodan.io/dns/domain/${DOMAIN}?key=${shodan_key}" 2>/dev/null | \
        jq -r '.data[]?' 2>/dev/null | \
        grep -v '^null$' | \
        sort -u > "${dns_dir}/shodan.txt" || true
    fi
    
    # DNSDumpster (web scraping approach)
    log_info "Checking DNSDumpster"
    
    # Get CSRF token and perform search
    local csrf_token=$(curl -s "https://dnsdumpster.com/" | \
    grep -oP 'csrfmiddlewaretoken.*?value="\K[^"]*' | head -1)
    
    if [[ -n "$csrf_token" ]]; then
        curl -s -X POST "https://dnsdumpster.com/" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Referer: https://dnsdumpster.com/" \
        -d "csrfmiddlewaretoken=${csrf_token}&targetip=${DOMAIN}" 2>/dev/null | \
        grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
        grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
        sort -u > "${dns_dir}/dnsdumpster.txt" || true
    fi
    
    # RapidDNS
    log_info "Checking RapidDNS"
    curl -s "https://rapiddns.io/subdomain/${DOMAIN}?full=1" 2>/dev/null | \
    grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
    grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
    sort -u > "${dns_dir}/rapiddns.txt" || true
    
    # BufferOver
    log_info "Checking BufferOver"
    curl -s "https://dns.bufferover.run/dns?q=.${DOMAIN}" 2>/dev/null | \
    jq -r '.FDNS_A[]?, .RDNS[]?' 2>/dev/null | \
    grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
    grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
    sort -u > "${dns_dir}/bufferover.txt" || true
    
    # Combine DNS results
    cat "${dns_dir}"/*.txt 2>/dev/null | \
    sort -u > "${base_dir}/recon/dns-passive.txt"
    
    local dns_count=$(wc -l < "${base_dir}/recon/dns-passive.txt" 2>/dev/null || echo "0")
    log_message "Passive DNS: $dns_count subdomains found"
    
    commit_step "Passive DNS"
    return 0
}

search_engine_enumeration() {
    log_message "Running search engine enumeration"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local search_dir="${base_dir}/recon/passive/search_engines"
    
    # Google dorking (limited by rate limiting)
    log_info "Google search enumeration"
    
    local google_queries=(
        "site:${DOMAIN}"
        "site:*.${DOMAIN}"
        "inurl:${DOMAIN}"
        "\"${DOMAIN}\" filetype:pdf"
        "\"${DOMAIN}\" filetype:doc"
        "\"${DOMAIN}\" filetype:xls"
    )
    
    for query in "${google_queries[@]}"; do
        # Use a simple curl approach (limited effectiveness)
        curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        "https://www.google.com/search?q=${query}" 2>/dev/null | \
        grep -oE 'https?://[^/]*\.'"${DOMAIN}"'[^"]*' | \
        head -20 >> "${search_dir}/google-raw.txt" || true
        
        sleep 3  # Be respectful to Google
    done
    
    # Extract subdomains from Google results
    cat "${search_dir}/google-raw.txt" 2>/dev/null | \
    grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
    grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
    sort -u > "${search_dir}/google-subdomains.txt"
    
    # Bing search
    log_info "Bing search enumeration"
    curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "https://www.bing.com/search?q=site:${DOMAIN}" 2>/dev/null | \
    grep -oE 'https?://[^/]*\.'"${DOMAIN}"'[^"]*' | \
    head -50 | \
    grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
    grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
    sort -u > "${search_dir}/bing-subdomains.txt" || true
    
    # DuckDuckGo search
    log_info "DuckDuckGo search enumeration"
    curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "https://duckduckgo.com/html/?q=site:${DOMAIN}" 2>/dev/null | \
    grep -oE 'https?://[^/]*\.'"${DOMAIN}"'[^"]*' | \
    head -50 | \
    grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
    grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
    sort -u > "${search_dir}/duckduckgo-subdomains.txt" || true
    
    # Combine search engine results
    cat "${search_dir}"/*-subdomains.txt 2>/dev/null | \
    sort -u > "${base_dir}/recon/search-engines.txt"
    
    local search_count=$(wc -l < "${base_dir}/recon/search-engines.txt" 2>/dev/null || echo "0")
    log_message "Search engines: $search_count subdomains found"
    
    commit_step "Search Engines"
    return 0
}

specialized_enumeration() {
    log_message "Running specialized enumeration tools"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    
    # Subfinder
    if tool_available subfinder; then
        log_info "Running Subfinder"
        subfinder -d "$DOMAIN" -silent -timeout "$SUBFINDER_TIMEOUT" -all \
        -o "${base_dir}/recon/subfinder.txt" 2>/dev/null || true
    fi
    
    # Assetfinder
    if tool_available assetfinder; then
        log_info "Running Assetfinder"
        assetfinder --subs-only "$DOMAIN" > "${base_dir}/recon/assetfinder.txt" 2>/dev/null || true
    fi
    
    # Amass passive
    if tool_available amass; then
        log_info "Running Amass passive enumeration"
        timeout "$AMASS_TIMEOUT" amass enum -passive -d "$DOMAIN" \
        -o "${base_dir}/recon/amass-passive.txt" 2>/dev/null || true
    fi
    
    # Findomain
    if tool_available findomain; then
        log_info "Running Findomain"
        findomain -t "$DOMAIN" -u "${base_dir}/recon/findomain.txt" 2>/dev/null || true
    fi
    
    # Chaos
    if tool_available chaos; then
        log_info "Running Chaos"
        chaos -d "$DOMAIN" -silent > "${base_dir}/recon/chaos.txt" 2>/dev/null || true
    fi
    
    commit_step "Specialized Tools"
    return 0
}

consolidate_passive_results() {
    log_message "Consolidating passive reconnaissance results"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    
    # Combine all passive sources
    local passive_files=(
        "${base_dir}/recon/certificates-all.txt"
        "${base_dir}/recon/threat-intelligence.txt"
        "${base_dir}/recon/archives-subdomains.txt"
        "${base_dir}/recon/github-subdomains.txt"
        "${base_dir}/recon/dns-passive.txt"
        "${base_dir}/recon/search-engines.txt"
        "${base_dir}/recon/subfinder.txt"
        "${base_dir}/recon/assetfinder.txt"
        "${base_dir}/recon/amass-passive.txt"
        "${base_dir}/recon/findomain.txt"
        "${base_dir}/recon/chaos.txt"
    )
    
    # Combine and deduplicate
    cat "${passive_files[@]}" 2>/dev/null | \
    grep -v '^$' | \
    grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
    sort -u > "${base_dir}/recon/subdomains-passive-all.txt"
    
    # Create final passive results file
    cp "${base_dir}/recon/subdomains-passive-all.txt" \
       "${base_dir}/recon/subdomains-passive.txt"
    
    # Generate statistics
    local total_passive=$(wc -l < "${base_dir}/recon/subdomains-passive.txt" 2>/dev/null || echo "0")
    
    # Update wordlists for future use
    if [[ $total_passive -gt 0 ]]; then
        cat "${base_dir}/recon/subdomains-passive.txt" | \
        tr '.' '\n' | \
        grep -vE '[^a-zA-Z]' | \
        grep -v '^$' | \
        sort -u >> "${WORDLIST_SUBDOMAINS}" 2>/dev/null || true
        
        # Keep wordlist reasonable size
        if [[ -f "${WORDLIST_SUBDOMAINS}" ]]; then
            sort -u "${WORDLIST_SUBDOMAINS}" | head -500000 > "${WORDLIST_SUBDOMAINS}.tmp"
            mv "${WORDLIST_SUBDOMAINS}.tmp" "${WORDLIST_SUBDOMAINS}"
        fi
    fi
    
    # Create summary
    cat > "${base_dir}/recon/passive-summary.txt" << EOF
PASSIVE RECONNAISSANCE SUMMARY
==============================

Domain: $DOMAIN
Total Subdomains Found: $total_passive
Date: $(date)

Source Breakdown:
$(for file in "${passive_files[@]}"; do
    if [[ -f "$file" ]]; then
        local count=$(wc -l < "$file" 2>/dev/null || echo "0")
        echo "- $(basename "$file"): $count"
    fi
done)

Top 20 Subdomains:
$(head -20 "${base_dir}/recon/subdomains-passive.txt" 2>/dev/null || echo "None found")
EOF
    
    log_message "Passive reconnaissance completed: $total_passive unique subdomains found"
    
    return 0
}

# =============================================================================
# MAIN PASSIVE RECONNAISSANCE EXECUTION
# =============================================================================

main_passive() {
    show_module_info "PASSIVE RECONNAISSANCE" "Advanced OSINT-based subdomain enumeration and data gathering"
    
    notify_slack "🔍 [${DOMAIN}] Starting passive reconnaissance"
    
    # Initialize
    initialize_passive_recon || {
        log_error "Failed to initialize passive reconnaissance"
        return 1
    }
    
    # Execute passive reconnaissance steps
    local recon_steps=(
        "certificate_transparency"
        "threat_intelligence_apis"
        "web_archives_enumeration"
        "github_reconnaissance"
        "dns_enumeration_passive"
        "search_engine_enumeration"
        "specialized_enumeration"
        "consolidate_passive_results"
    )
    
    local total_steps=${#recon_steps[@]}
    local current_step=0
    local failed_steps=()
    
    for step in "${recon_steps[@]}"; do
        ((current_step++))
        
        log_message "[$current_step/$total_steps] Executing: $step"
        
        if ! "$step"; then
            log_warning "Step failed: $step"
            failed_steps+=("$step")
        fi
        
        show_progress "$current_step" "$total_steps" "Passive reconnaissance"
    done
    
    # Report results
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local total_found=$(wc -l < "${base_dir}/recon/subdomains-passive.txt" 2>/dev/null || echo "0")
    
    if [[ $total_found -gt 0 ]]; then
        log_message "Passive reconnaissance completed successfully"
        log_message "Total subdomains found: $total_found"
        
        # Show sample results
        echo -e "\n${YELLOW}Sample subdomains found:${NC}"
        head -10 "${base_dir}/recon/subdomains-passive.txt" 2>/dev/null | \
        while read -r subdomain; do
            echo "  • $subdomain"
        done
        
        if [[ $total_found -gt 10 ]]; then
            echo "  ... and $((total_found - 10)) more"
        fi
    else
        log_warning "No subdomains found during passive reconnaissance"
    fi
    
    # Report failed steps
    if [[ ${#failed_steps[@]} -gt 0 ]]; then
        log_warning "Some steps failed: ${failed_steps[*]}"
    fi
    
    # Final notification
    notify_slack "✅ [${DOMAIN}] Passive reconnaissance completed - Found $total_found subdomains"
    
    commit_step "Passive Reconnaissance"
    return 0
}

# Execute main passive reconnaissance function
main_passive
