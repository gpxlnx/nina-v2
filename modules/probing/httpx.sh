#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - HTTPX Probing Module
# Advanced HTTP/HTTPS probing and technology detection
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
# HTTPX PROBING FUNCTIONS
# =============================================================================

initialize_httpx_probing() {
    log_message "Initializing HTTPX probing for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    
    # Create specialized subdirectories
    local subdirs=(
        "http"
        "https"
        "ports"
        "technologies"
        "responses"
        "screenshots"
        "certificates"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${probing_dir}/${subdir}" 2>/dev/null
    done
    
    # Check if we have subdomains to probe
    if [[ ! -f "${base_dir}/recon/subdomains-all.txt" ]] || [[ ! -s "${base_dir}/recon/subdomains-all.txt" ]]; then
        log_warning "No subdomains found for HTTP probing"
        # Create minimal target list with just the domain
        echo "$DOMAIN" > "${base_dir}/recon/subdomains-all.txt"
    fi
    
    return 0
}

dns_resolution() {
    log_message "Resolving DNS for subdomains"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    
    # Use dnsx for fast DNS resolution if available
    if tool_available dnsx; then
        log_info "Using dnsx for DNS resolution"
        
        dnsx -l "${base_dir}/recon/subdomains-all.txt" \
        -t "$DNS_THREADS" \
        -retry "$DNS_RETRIES" -nc -silent \
        -resp -a -aaaa -cname -mx -ns -txt -ptr \
        -json -o "${probing_dir}/dns-resolution.json" 2>/dev/null || true
        
        # Extract just the live hosts
        if [[ -f "${probing_dir}/dns-resolution.json" ]]; then
            jq -r 'select(.a != null or .aaaa != null) | .host' \
            "${probing_dir}/dns-resolution.json" 2>/dev/null | \
            sort -u > "${probing_dir}/live-hosts.txt" || true
        fi
    else
        log_info "Using basic DNS resolution"
        
        # Fallback to basic dig resolution
        while IFS= read -r subdomain; do
            if dig +short "$subdomain" 2>/dev/null | grep -E '^[0-9]+\.' >/dev/null; then
                echo "$subdomain" >> "${probing_dir}/live-hosts.txt"
            fi
        done < "${base_dir}/recon/subdomains-all.txt"
        
        sort -u "${probing_dir}/live-hosts.txt" -o "${probing_dir}/live-hosts.txt" 2>/dev/null || true
    fi
    
    local live_count=$(wc -l < "${probing_dir}/live-hosts.txt" 2>/dev/null || echo "0")
    log_message "DNS resolution: $live_count live hosts found"
    
    commit_step "DNS Resolution"
    return 0
}

basic_http_probing() {
    log_message "Running basic HTTP probing"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    
    if [[ ! -s "${probing_dir}/live-hosts.txt" ]]; then
        log_warning "No live hosts found for HTTP probing"
        return 0
    fi
    
    local live_count=$(wc -l < "${probing_dir}/live-hosts.txt")
    log_info "Probing $live_count live hosts with HTTPX"
    
    # Basic HTTP/HTTPS probing
    if tool_available httpx; then
        # Standard web ports for quick scan
        local web_ports="80,443,8080,8443,3000,5000,8000,8888"
        
        httpx -l "${probing_dir}/live-hosts.txt" \
        -p "$web_ports" \
        -threads "$HTTPX_THREADS" \
        -timeout "$HTTPX_TIMEOUT" \
        -retries "$HTTPX_RETRIES" \
        -rate-limit "$HTTPX_RATE_LIMIT" \
        -silent -nc \
        -sc -cl -ct -server -title -tech-detect \
        -location -method -websocket -ip -cname -asn \
        -o "${probing_dir}/httpx-basic.txt" 2>/dev/null || true
        
        # Extract URLs for further processing
        if [[ -f "${probing_dir}/httpx-basic.txt" ]]; then
            awk '{print $1}' "${probing_dir}/httpx-basic.txt" | \
            sort -u > "${probing_dir}/live-urls-basic.txt"
            
            local url_count=$(wc -l < "${probing_dir}/live-urls-basic.txt")
            log_message "Basic probing: $url_count URLs responding"
        fi
    else
        log_error "HTTPX not available"
        return 1
    fi
    
    commit_step "Basic HTTP Probing"
    return 0
}

comprehensive_port_scan() {
    log_message "Running comprehensive port scanning"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    
    if [[ ! -s "${probing_dir}/live-hosts.txt" ]]; then
        return 0
    fi
    
    # Comprehensive port list for web services
    local comprehensive_ports="80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"
    
    log_info "Scanning comprehensive port list"
    
    httpx -l "${probing_dir}/live-hosts.txt" \
    -p "$comprehensive_ports" \
    -threads "$HTTPX_THREADS" \
    -timeout "$HTTPX_TIMEOUT" \
    -retries "$HTTPX_RETRIES" \
    -rate-limit "$HTTPX_RATE_LIMIT" \
    -silent -nc \
    -sc -cl -ct -server -title -tech-detect \
    -location -method -websocket -ip -cname -asn \
    -o "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null || true
    
    # Process comprehensive results
    if [[ -f "${probing_dir}/httpx-comprehensive.txt" ]]; then
        # Extract URLs
        awk '{print $1}' "${probing_dir}/httpx-comprehensive.txt" | \
        sort -u > "${probing_dir}/live-urls-comprehensive.txt"
        
        # Combine with basic results
        cat "${probing_dir}/live-urls-basic.txt" \
            "${probing_dir}/live-urls-comprehensive.txt" 2>/dev/null | \
        sort -u > "${probing_dir}/live-urls-all.txt"
        
        local total_urls=$(wc -l < "${probing_dir}/live-urls-all.txt")
        log_message "Comprehensive probing: $total_urls total URLs responding"
        
        # Extract IPs for IP-based scanning
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
        "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        sort -u > "${probing_dir}/discovered-ips.txt" || true
    fi
    
    commit_step "Comprehensive Port Scan"
    return 0
}

ip_based_scanning() {
    log_message "Running IP-based scanning"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    
    if [[ ! -s "${probing_dir}/discovered-ips.txt" ]]; then
        log_info "No IPs discovered for direct scanning"
        return 0
    fi
    
    local ip_count=$(wc -l < "${probing_dir}/discovered-ips.txt")
    log_info "Scanning $ip_count discovered IPs directly"
    
    # Scan IPs with common web ports
    httpx -l "${probing_dir}/discovered-ips.txt" \
    -p "80,443,8080,8443,3000,5000,8000,8888,9000" \
    -threads "$HTTPX_THREADS" \
    -timeout "$HTTPX_TIMEOUT" \
    -retries "$HTTPX_RETRIES" \
    -rate-limit "$HTTPX_RATE_LIMIT" \
    -silent -nc \
    -sc -cl -ct -server -title -tech-detect \
    -location -method -ip -asn \
    -o "${probing_dir}/httpx-ips.txt" 2>/dev/null || true
    
    if [[ -f "${probing_dir}/httpx-ips.txt" ]]; then
        # Extract IP-based URLs
        awk '{print $1}' "${probing_dir}/httpx-ips.txt" | \
        sort -u > "${probing_dir}/live-urls-ips.txt"
        
        # Add to comprehensive results
        cat "${probing_dir}/live-urls-all.txt" \
            "${probing_dir}/live-urls-ips.txt" 2>/dev/null | \
        sort -u > "${probing_dir}/live-urls-final.txt"
        
        local ip_urls=$(wc -l < "${probing_dir}/live-urls-ips.txt")
        log_message "IP scanning: $ip_urls additional URLs found"
    fi
    
    commit_step "IP-based Scanning"
    return 0
}

technology_detection() {
    log_message "Running advanced technology detection"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    local tech_dir="${probing_dir}/technologies"
    
    if [[ ! -s "${probing_dir}/live-urls-final.txt" ]]; then
        log_warning "No live URLs for technology detection"
        return 0
    fi
    
    # Extract technology information from HTTPX results
    if [[ -f "${probing_dir}/httpx-comprehensive.txt" ]]; then
        log_info "Analyzing technology information"
        
        # Parse HTTPX output for technologies
        grep -E '\[.*\]' "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        grep -oE '\[.*\]' | \
        sed 's/\[//g; s/\]//g' | \
        tr ',' '\n' | \
        sort | uniq -c | sort -nr > "${tech_dir}/technology-summary.txt" || true
        
        # Extract servers
        awk '{for(i=1;i<=NF;i++) if($i ~ /Server:/) print $(i+1)}' \
        "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        sort | uniq -c | sort -nr > "${tech_dir}/servers.txt" || true
        
        # Extract status codes
        awk '{for(i=1;i<=NF;i++) if($i ~ /\[[0-9]{3}\]/) print $i}' \
        "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        sed 's/\[//g; s/\]//g' | \
        sort | uniq -c | sort -nr > "${tech_dir}/status-codes.txt" || true
        
        # Extract content types
        awk '{for(i=1;i<=NF;i++) if($i ~ /Content-Type:/) print $(i+1)}' \
        "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        sort | uniq -c | sort -nr > "${tech_dir}/content-types.txt" || true
    fi
    
    # Advanced technology detection with nuclei if available
    if tool_available nuclei && [[ -s "${probing_dir}/live-urls-final.txt" ]]; then
        log_info "Running Nuclei technology detection"
        
        nuclei -l "${probing_dir}/live-urls-final.txt" \
        -t "/root/nuclei-templates/technologies/" \
        -silent -nc \
        -rate-limit 100 \
        -o "${tech_dir}/nuclei-technologies.txt" 2>/dev/null || true
    fi
    
    commit_step "Technology Detection"
    return 0
}

response_analysis() {
    log_message "Analyzing HTTP responses"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    local response_dir="${probing_dir}/responses"
    
    if [[ ! -s "${probing_dir}/live-urls-final.txt" ]]; then
        return 0
    fi
    
    # Analyze interesting response patterns
    log_info "Analyzing response patterns"
    
    # Find URLs with interesting status codes
    if [[ -f "${probing_dir}/httpx-comprehensive.txt" ]]; then
        # Redirect analysis
        grep -E '\[30[12378]\]' "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        awk '{print $1}' > "${response_dir}/redirects.txt" || true
        
        # Client errors (4xx)
        grep -E '\[4[0-9]{2}\]' "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        awk '{print $1}' > "${response_dir}/client-errors.txt" || true
        
        # Server errors (5xx)
        grep -E '\[5[0-9]{2}\]' "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        awk '{print $1}' > "${response_dir}/server-errors.txt" || true
        
        # Success responses (2xx)
        grep -E '\[2[0-9]{2}\]' "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        awk '{print $1}' > "${response_dir}/success.txt" || true
    fi
    
    # Find interesting content lengths
    if [[ -f "${probing_dir}/httpx-comprehensive.txt" ]]; then
        awk '{for(i=1;i<=NF;i++) if($i ~ /\[[0-9]+\]$/ && $i !~ /\[[0-9]{3}\]/) print $1 " " $i}' \
        "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null | \
        sort -k2 -n > "${response_dir}/content-lengths.txt" || true
        
        # Find unusually large responses
        awk '{for(i=1;i<=NF;i++) if($i ~ /\[[0-9]+\]$/ && $i !~ /\[[0-9]{3}\]/) {gsub(/\[|\]/, "", $i); if($i > 100000) print $1 " " $i}}' \
        "${probing_dir}/httpx-comprehensive.txt" 2>/dev/null > "${response_dir}/large-responses.txt" || true
    fi
    
    commit_step "Response Analysis"
    return 0
}

special_endpoint_detection() {
    log_message "Detecting special endpoints"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    
    if [[ ! -s "${probing_dir}/live-urls-final.txt" ]]; then
        return 0
    fi
    
    # Check for common interesting paths
    log_info "Probing for special endpoints"
    
    # Create list of interesting paths
    local interesting_paths=(
        "/admin"
        "/login"
        "/dashboard"
        "/panel"
        "/api"
        "/v1"
        "/v2"
        "/swagger"
        "/docs"
        "/graphql"
        "/health"
        "/status"
        "/debug"
        "/test"
        "/robots.txt"
        "/sitemap.xml"
        "/.well-known/security.txt"
        "/.env"
        "/config"
        "/backup"
    )
    
    # Test paths against all base URLs
    for path in "${interesting_paths[@]}"; do
        while IFS= read -r base_url; do
            echo "${base_url}${path}"
        done < "${probing_dir}/live-urls-final.txt"
    done > "${probing_dir}/endpoints-to-test.txt"
    
    # Test endpoints with httpx
    if [[ -s "${probing_dir}/endpoints-to-test.txt" ]]; then
        httpx -l "${probing_dir}/endpoints-to-test.txt" \
        -threads 500 \
        -timeout 5 \
        -retries 1 \
        -silent -nc \
        -sc -cl -title \
        -mc 200,201,202,204,301,302,307,308,401,403 \
        -o "${probing_dir}/special-endpoints.txt" 2>/dev/null || true
        
        if [[ -f "${probing_dir}/special-endpoints.txt" ]]; then
            local endpoint_count=$(wc -l < "${probing_dir}/special-endpoints.txt")
            log_message "Special endpoints: $endpoint_count interesting endpoints found"
        fi
    fi
    
    commit_step "Special Endpoint Detection"
    return 0
}

certificate_analysis() {
    log_message "Analyzing SSL/TLS certificates"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    local cert_dir="${probing_dir}/certificates"
    
    # Extract HTTPS URLs
    grep "^https://" "${probing_dir}/live-urls-final.txt" 2>/dev/null | \
    head -100 > "${cert_dir}/https-urls.txt" || true
    
    if [[ ! -s "${cert_dir}/https-urls.txt" ]]; then
        log_info "No HTTPS URLs found for certificate analysis"
        return 0
    fi
    
    # Use tlsx if available for detailed certificate analysis
    if tool_available tlsx; then
        log_info "Analyzing certificates with tlsx"
        
        tlsx -l "${cert_dir}/https-urls.txt" \
        -json -silent \
        -cn -san -so -expired -self-signed \
        -o "${cert_dir}/certificate-details.json" 2>/dev/null || true
        
        # Extract interesting certificate information
        if [[ -f "${cert_dir}/certificate-details.json" ]]; then
            # Extract SANs for potential new subdomains
            jq -r '.subject_an[]?' "${cert_dir}/certificate-details.json" 2>/dev/null | \
            grep -E "\.${DOMAIN}$|^${DOMAIN}$" | \
            sort -u > "${cert_dir}/certificate-sans.txt" || true
            
            # Extract certificate organizations
            jq -r '.subject_o' "${cert_dir}/certificate-details.json" 2>/dev/null | \
            sort | uniq > "${cert_dir}/certificate-orgs.txt" || true
            
            # Find expired or self-signed certificates
            jq -r 'select(.expired == true or .self_signed == true) | .host' \
            "${cert_dir}/certificate-details.json" 2>/dev/null | \
            sort -u > "${cert_dir}/problematic-certificates.txt" || true
        fi
    else
        # Basic certificate check with openssl
        log_info "Basic certificate analysis with openssl"
        
        while IFS= read -r url; do
            local host=$(echo "$url" | sed 's|^https://||' | cut -d'/' -f1)
            local port="443"
            
            if [[ "$host" =~ :[0-9]+$ ]]; then
                port=$(echo "$host" | cut -d':' -f2)
                host=$(echo "$host" | cut -d':' -f1)
            fi
            
            echo | timeout 10 openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null | \
            openssl x509 -noout -text 2>/dev/null | \
            grep -E "DNS:|Subject:" >> "${cert_dir}/certificate-info.txt" || true
            
        done < "${cert_dir}/https-urls.txt"
    fi
    
    commit_step "Certificate Analysis"
    return 0
}

consolidate_probing_results() {
    log_message "Consolidating HTTP probing results"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local probing_dir="${base_dir}/probing"
    
    # Ensure all required files exist
    touch "${probing_dir}/live-urls-final.txt" 2>/dev/null
    touch "${probing_dir}/special-endpoints.txt" 2>/dev/null
    touch "${probing_dir}/technologies/technology-summary.txt" 2>/dev/null
    touch "${probing_dir}/technologies/status-codes.txt" 2>/dev/null
    touch "${probing_dir}/certificates/problematic-certificates.txt" 2>/dev/null
    
    # Combine all URLs
    cat "${probing_dir}/live-urls-final.txt" \
        "${probing_dir}/special-endpoints.txt" 2>/dev/null | \
    awk '{print $1}' | \
    sort -u > "${base_dir}/live-hosts.txt"
    
    # Ensure files exist for summary
    touch "${probing_dir}/special-endpoints.txt" 2>/dev/null
    touch "${probing_dir}/certificates/problematic-certificates.txt" 2>/dev/null
    
    # Ensure all required files exist
    touch "${probing_dir}/special-endpoints.txt" 2>/dev/null
    touch "${probing_dir}/technologies/technology-summary.txt" 2>/dev/null
    touch "${probing_dir}/technologies/status-codes.txt" 2>/dev/null
    touch "${probing_dir}/certificates/problematic-certificates.txt" 2>/dev/null
    touch "${probing_dir}/live-urls-final.txt" 2>/dev/null

    # Create comprehensive summary
    local total_hosts=$(wc -l < "${probing_dir}/live-hosts.txt" 2>/dev/null || echo "0")
    local total_urls=$(wc -l < "${base_dir}/live-hosts.txt" 2>/dev/null || echo "0")
    local https_count=$(grep -c "^https://" "${base_dir}/live-hosts.txt" 2>/dev/null || echo "0")
    local http_count=$(grep -c "^http://" "${base_dir}/live-hosts.txt" 2>/dev/null || echo "0")
    
    # Extract unique hosts for further processing
    sed 's|^https\?://||' "${base_dir}/live-hosts.txt" | \
    cut -d'/' -f1 | \
    sort -u > "${base_dir}/unique-hosts.txt"
    
    local unique_hosts=$(wc -l < "${base_dir}/unique-hosts.txt" 2>/dev/null || echo "0")
    
    # Create summary
    cat > "${probing_dir}/probing-summary.txt" << EOF
HTTP PROBING SUMMARY
===================

Domain: $DOMAIN
Total Live Hosts: $total_hosts
Total URLs Found: $total_urls
Unique Hosts: $unique_hosts
HTTPS URLs: $https_count
HTTP URLs: $http_count
Date: $(date)

Scope Type: ${SCOPE_TYPE:-auto}
Threads Used: $HTTPX_THREADS
Timeout: $HTTPX_TIMEOUT seconds

Special Endpoints Found:
$(wc -l < "${probing_dir}/special-endpoints.txt" 2>/dev/null || echo "0")

Technologies Detected:
$(head -10 "${probing_dir}/technologies/technology-summary.txt" 2>/dev/null || echo "None")

Response Code Distribution:
$(head -10 "${probing_dir}/technologies/status-codes.txt" 2>/dev/null || echo "None")

Certificate Issues:
$(wc -l < "${probing_dir}/certificates/problematic-certificates.txt" 2>/dev/null || echo "0") hosts with certificate issues
EOF
    
    # Update wordlists with discovered paths
    if [[ -f "${probing_dir}/special-endpoints.txt" ]]; then
        awk '{print $1}' "${probing_dir}/special-endpoints.txt" | \
        sed 's|^https\?://[^/]*||' | \
        grep '^/' | \
        sort -u >> "${DIR_NINA_LISTS}/discovered-paths.txt" 2>/dev/null || true
    fi
    
    log_message "HTTP probing completed"
    log_message "Live hosts: $total_hosts | URLs: $total_urls | Unique hosts: $unique_hosts"
    
    return 0
}

# =============================================================================
# MAIN HTTPX PROBING EXECUTION
# =============================================================================

main_httpx() {
    show_module_info "HTTPX PROBING" "Advanced HTTP/HTTPS probing and technology detection"
    
    notify_slack "🌐 [${DOMAIN}] Starting HTTP probing"
    
    # Initialize
    initialize_httpx_probing || {
        log_error "Failed to initialize HTTPX probing"
        return 1
    }
    
    # Execute probing steps
    local probing_steps=(
        "dns_resolution"
        "basic_http_probing"
        "comprehensive_port_scan"
        "ip_based_scanning"
        "technology_detection"
        "response_analysis"
        "special_endpoint_detection"
        "certificate_analysis"
        "consolidate_probing_results"
    )
    
    local total_steps=${#probing_steps[@]}
    local current_step=0
    local failed_steps=()
    
    for step in "${probing_steps[@]}"; do
        ((current_step++))
        
        log_message "[$current_step/$total_steps] Executing: $step"
        
        if ! "$step"; then
            log_warning "Step failed: $step"
            failed_steps+=("$step")
        fi
        
        show_progress "$current_step" "$total_steps" "HTTP probing"
    done
    
    # Report results
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local total_urls=$(wc -l < "${base_dir}/live-hosts.txt" 2>/dev/null || echo "0")
    local unique_hosts=$(wc -l < "${base_dir}/unique-hosts.txt" 2>/dev/null || echo "0")
    
    if [[ $total_urls -gt 0 ]]; then
        log_message "HTTP probing completed successfully"
        log_message "Total URLs: $total_urls | Unique hosts: $unique_hosts"
        
        # Show sample results
        echo -e "\n${YELLOW}Sample discovered URLs:${NC}"
        head -10 "${base_dir}/live-hosts.txt" 2>/dev/null | \
        while read -r url; do
            echo "  • $url"
        done
        
        if [[ $total_urls -gt 10 ]]; then
            echo "  ... and $((total_urls - 10)) more"
        fi
    else
        log_warning "No live URLs found during HTTP probing"
    fi
    
    # Report failed steps
    if [[ ${#failed_steps[@]} -gt 0 ]]; then
        log_warning "Some steps failed: ${failed_steps[*]}"
    fi
    
    # Final notification
    notify_slack "✅ [${DOMAIN}] HTTP probing completed - Found $total_urls URLs on $unique_hosts hosts"
    
    commit_step "HTTPX Probing"
    return 0
}

# Execute main HTTPX probing function
main_httpx
