#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Crawler Module
# Web crawling and URL discovery
# Tools: Katana, Waybackurls, GAU, JS endpoint extraction
# =============================================================================

# Ensure config is loaded
if [[ -z "${DIR_NINA:-}" ]]; then
    echo "Error: Config not loaded. This module should be run via nina-recon-optimized.sh"
    exit 1
fi

# =============================================================================
# CRAWLER FUNCTIONS
# =============================================================================

initialize_crawler() {
    log_message "Initializing web crawler for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local crawler_dir="${base_dir}/discovery"
    
    # Create specialized subdirectories for crawling
    local subdirs=(
        "crawl"
        "archive_urls"
        "js_endpoints"
        "api_endpoints"
        "extracted_urls"
        "wayback"
        "gau"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${crawler_dir}/${subdir}" 2>/dev/null
    done
    
    # Check if we have targets to crawl
    local has_targets=false
    
    if [[ -f "${base_dir}/live-hosts.txt" && -s "${base_dir}/live-hosts.txt" ]]; then
        has_targets=true
    elif [[ -f "${base_dir}/recon/subdomains-all.txt" && -s "${base_dir}/recon/subdomains-all.txt" ]]; then
        log_info "Using subdomains as crawling targets"
        # Create basic HTTP URLs from subdomains
        while IFS= read -r subdomain; do
            echo "https://${subdomain}"
            echo "http://${subdomain}"
        done < "${base_dir}/recon/subdomains-all.txt" | head -50 > "${base_dir}/live-hosts.txt"
        has_targets=true
    elif [[ -n "$DOMAIN" ]]; then
        log_info "Using target domain as crawling target"
        echo "https://${DOMAIN}" > "${base_dir}/live-hosts.txt"
        echo "http://${DOMAIN}" >> "${base_dir}/live-hosts.txt"
        has_targets=true
    fi
    
    if [[ "$has_targets" != "true" ]]; then
        log_warning "No targets found for crawling"
        return 1
    fi
    
    return 0
}

archive_url_extraction() {
    log_message "Extracting URLs from web archives"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local archive_dir="${base_dir}/discovery/archive_urls"
    
    # Wayback Machine URLs
    if tool_available waybackurls; then
        log_info "Running Waybackurls"
        
        # Get URLs for the domain
        echo "$DOMAIN" | waybackurls 2>/dev/null | \
        grep -E '^https?://' | \
        head -10000 > "${archive_dir}/wayback-urls.tmp"
        
        smart_save "${archive_dir}/wayback-urls.tmp" "${archive_dir}/wayback-urls.txt" "wayback URLs"
        
        # Extract subdomains from wayback URLs
        if [[ -f "${archive_dir}/wayback-urls.txt" ]]; then
            grep -oP 'https?://\K[^/]+' "${archive_dir}/wayback-urls.txt" | \
            grep "\\.${DOMAIN}$" | \
            sort -u > "${archive_dir}/wayback-subdomains.tmp"
            
            smart_save "${archive_dir}/wayback-subdomains.tmp" "${archive_dir}/wayback-subdomains.txt" "wayback subdomains"
        fi
    fi
    
    # GAU (GetAllUrls)
    if tool_available gau; then
        log_info "Running GAU"
        
        echo "$DOMAIN" | gau --threads 5 --timeout 30 2>/dev/null | \
        head -10000 > "${archive_dir}/gau-urls.tmp"
        
        smart_save "${archive_dir}/gau-urls.tmp" "${base_dir}/discovery/gau/gau-urls.txt" "GAU URLs"
        
        # Extract subdomains from GAU URLs
        if [[ -f "${base_dir}/discovery/gau/gau-urls.txt" ]]; then
            grep -oP 'https?://\K[^/]+' "${base_dir}/discovery/gau/gau-urls.txt" | \
            grep "\\.${DOMAIN}$" | \
            sort -u > "${archive_dir}/gau-subdomains.tmp"
            
            smart_save "${archive_dir}/gau-subdomains.tmp" "${archive_dir}/gau-subdomains.txt" "GAU subdomains"
        fi
    fi
    
    # CommonCrawl (if available)
    if tool_available ccrawl; then
        log_info "Checking CommonCrawl"
        ccrawl -d "$DOMAIN" 2>/dev/null | head -5000 > "${archive_dir}/commoncrawl.tmp"
        smart_save "${archive_dir}/commoncrawl.tmp" "${archive_dir}/commoncrawl.txt" "CommonCrawl URLs"
    fi
    
    # Combine all archive URLs
    smart_combine \
        "${archive_dir}/wayback-urls.txt" \
        "${base_dir}/discovery/gau/gau-urls.txt" \
        "${archive_dir}/commoncrawl.txt" \
        "${base_dir}/discovery/all-archive-urls.txt"
    
    commit_step "Archive URL Extraction"
    return 0
}

katana_crawler() {
    log_message "Running Katana web crawler"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local crawl_dir="${base_dir}/discovery/crawl"
    
    if ! tool_available katana; then
        log_warning "Katana not available, skipping web crawling"
        return 1
    fi
    
    # Read live hosts for crawling
    if [[ ! -f "${base_dir}/live-hosts.txt" ]]; then
        log_warning "No live hosts found for crawling"
        return 1
    fi
    
    log_info "Starting Katana crawling"
    
    # Scope-specific crawling parameters
    local depth=2
    local js_crawl="false"
    local rate_limit=150
    
    case "${SCOPE_TYPE:-closed}" in
        "closed")
            depth=3
            js_crawl="true"
            rate_limit=100
            ;;
        "wildcard")
            depth=2
            js_crawl="true"
            rate_limit=200
            ;;
        "open")
            depth=1
            js_crawl="false"
            rate_limit=300
            ;;
    esac
    
    # Run Katana with appropriate settings
    katana -list "${base_dir}/live-hosts.txt" \
        -depth $depth \
        -js-crawl=$js_crawl \
        -crawl-scope "*.${DOMAIN}" \
        -rate-limit $rate_limit \
        -timeout 30 \
        -retries 2 \
        -silent \
        -output "${crawl_dir}/katana-urls.tmp" 2>/dev/null
    
    smart_save "${crawl_dir}/katana-urls.tmp" "${crawl_dir}/katana-urls.txt" "Katana crawled URLs"
    
    # Extract different types of URLs
    if [[ -f "${crawl_dir}/katana-urls.txt" ]]; then
        # Extract API endpoints
        grep -iE '(/api/|/v[0-9]+/|/rest/|/graphql|\.json|\.xml)' "${crawl_dir}/katana-urls.txt" | \
        head -1000 > "${crawl_dir}/api-endpoints.tmp"
        smart_save "${crawl_dir}/api-endpoints.tmp" "${base_dir}/discovery/api_endpoints/katana-api-endpoints.txt" "API endpoints"
        
        # Extract interesting files
        grep -iE '\.(js|css|json|xml|txt|log|conf|config|env|bak|backup|old|sql|db)' "${crawl_dir}/katana-urls.txt" | \
        head -1000 > "${crawl_dir}/interesting-files.tmp"
        smart_save "${crawl_dir}/interesting-files.tmp" "${crawl_dir}/interesting-files.txt" "interesting files"
        
        # Extract parameters
        grep -oP '\?[^&\s]+' "${crawl_dir}/katana-urls.txt" | \
        grep -oP '^\?[^=]+' | \
        sed 's/^?//' | \
        sort -u > "${crawl_dir}/found-parameters.tmp"
        smart_save "${crawl_dir}/found-parameters.tmp" "${crawl_dir}/found-parameters.txt" "URL parameters"
        
        # Extract paths for fuzzing
        sed 's/\?.*$//' "${crawl_dir}/katana-urls.txt" | \
        sed 's|https\?://[^/]*/||' | \
        grep -v '^$' | \
        sort -u > "${crawl_dir}/discovered-paths.tmp"
        smart_save "${crawl_dir}/discovered-paths.tmp" "${crawl_dir}/discovered-paths.txt" "discovered paths"
    fi
    
    commit_step "Katana Crawling"
    return 0
}

javascript_endpoint_extraction() {
    log_message "Extracting endpoints from JavaScript files"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local js_dir="${base_dir}/discovery/js_endpoints"
    
    # Find JavaScript files from crawling results
    local js_sources=(
        "${base_dir}/discovery/crawl/katana-urls.txt"
        "${base_dir}/discovery/all-archive-urls.txt"
    )
    
    # Extract JS file URLs
    cat "${js_sources[@]}" 2>/dev/null | \
    grep -iE '\.js(\?|$)' | \
    grep -v '\.min\.js' | \
    head -200 > "${js_dir}/js-files.tmp"
    
    if [[ ! -s "${js_dir}/js-files.tmp" ]]; then
        log_info "No JavaScript files found for endpoint extraction"
        rm -f "${js_dir}/js-files.tmp"
        return 1
    fi
    
    smart_save "${js_dir}/js-files.tmp" "${js_dir}/js-files.txt" "JavaScript files"
    
    # Extract endpoints from JS files
    if tool_available nuclei; then
        log_info "Using Nuclei to extract JS endpoints"
        
        nuclei -list "${js_dir}/js-files.txt" \
            -tags js,endpoints \
            -silent \
            -no-color \
            -output "${js_dir}/nuclei-js-endpoints.tmp" 2>/dev/null
        
        smart_save "${js_dir}/nuclei-js-endpoints.tmp" "${js_dir}/nuclei-js-endpoints.txt" "Nuclei JS endpoints"
    fi
    
    # Manual endpoint extraction using curl and grep
    log_info "Manual JavaScript endpoint extraction"
    
    while IFS= read -r js_url; do
        if [[ -n "$js_url" ]]; then
            curl -s --max-time 10 "$js_url" 2>/dev/null | \
            grep -oE '["'"'"'][/][^"'"'"']*["'"'"']' | \
            sed 's/['"'"'"]//'g | \
            grep -E '^/[a-zA-Z0-9]' | \
            head -20
        fi
    done < "${js_dir}/js-files.txt" | \
    sort -u > "${js_dir}/js-extracted-endpoints.tmp"
    
    smart_save "${js_dir}/js-extracted-endpoints.tmp" "${js_dir}/js-extracted-endpoints.txt" "JS extracted endpoints"
    
    # Extract URLs from JS files
    while IFS= read -r js_url; do
        if [[ -n "$js_url" ]]; then
            curl -s --max-time 10 "$js_url" 2>/dev/null | \
            grep -oE 'https?://[^"'"'"'\s]+' | \
            head -10
        fi
    done < "${js_dir}/js-files.txt" | \
    sort -u > "${js_dir}/js-extracted-urls.tmp"
    
    smart_save "${js_dir}/js-extracted-urls.tmp" "${js_dir}/js-extracted-urls.txt" "JS extracted URLs"
    
    commit_step "JavaScript Endpoint Extraction"
    return 0
}

api_endpoint_discovery() {
    log_message "Discovering API endpoints"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local api_dir="${base_dir}/discovery/api_endpoints"
    
    # Combine API endpoints from various sources
    local api_sources=(
        "${base_dir}/discovery/crawl/api-endpoints.txt"
        "${base_dir}/discovery/js_endpoints/js-extracted-endpoints.txt"
        "${api_dir}/katana-api-endpoints.txt"
    )
    
    smart_combine "${api_sources[@]}" "${api_dir}/all-api-endpoints.txt"
    
    if [[ ! -f "${api_dir}/all-api-endpoints.txt" ]]; then
        log_info "No API endpoints found"
        return 1
    fi
    
    # Test API endpoints for common patterns
    log_info "Testing API endpoints"
    
    # Common API paths to test
    local common_apis=(
        "/api"
        "/api/v1"
        "/api/v2"
        "/rest"
        "/graphql"
        "/swagger"
        "/swagger.json"
        "/swagger.yml"
        "/api-docs"
        "/docs"
        "/openapi.json"
    )
    
    # Test against live hosts
    if [[ -f "${base_dir}/live-hosts.txt" ]]; then
        while IFS= read -r host; do
            for api_path in "${common_apis[@]}"; do
                echo "${host}${api_path}"
            done
        done < "${base_dir}/live-hosts.txt" > "${api_dir}/potential-api-endpoints.tmp"
        
        smart_save "${api_dir}/potential-api-endpoints.tmp" "${api_dir}/potential-api-endpoints.txt" "potential API endpoints"
    fi
    
    # SwaggerSpy-like detection
    if [[ -f "${base_dir}/live-hosts.txt" ]]; then
        log_info "Checking for Swagger/OpenAPI documentation"
        
        while IFS= read -r host; do
            for swagger_path in "/swagger" "/swagger.json" "/swagger.yml" "/api-docs" "/openapi.json"; do
                response=$(curl -s -w "%{http_code}" -o /dev/null --max-time 5 "${host}${swagger_path}" 2>/dev/null)
                if [[ "$response" =~ ^(200|301|302)$ ]]; then
                    echo "${host}${swagger_path}"
                fi
            done
        done < "${base_dir}/live-hosts.txt" > "${api_dir}/found-swagger-endpoints.tmp"
        
        smart_save "${api_dir}/found-swagger-endpoints.tmp" "${api_dir}/found-swagger-endpoints.txt" "Swagger endpoints"
    fi
    
    commit_step "API Endpoint Discovery"
    return 0
}

consolidate_crawler_results() {
    log_message "Consolidating crawler results"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local crawler_dir="${base_dir}/discovery"
    
    # Combine all discovered URLs
    local url_sources=(
        "${crawler_dir}/all-archive-urls.txt"
        "${crawler_dir}/crawl/katana-urls.txt"
        "${crawler_dir}/js_endpoints/js-extracted-urls.txt"
        "${crawler_dir}/api_endpoints/all-api-endpoints.txt"
    )
    
    smart_combine "${url_sources[@]}" "${base_dir}/all-discovered-urls.txt"
    
    # Combine all discovered paths for fuzzing
    local path_sources=(
        "${crawler_dir}/crawl/discovered-paths.txt"
        "${crawler_dir}/js_endpoints/js-extracted-endpoints.txt"
    )
    
    smart_combine "${path_sources[@]}" "${crawler_dir}/wordlists/discovered-paths.txt"
    
    # Combine all discovered parameters
    local param_sources=(
        "${crawler_dir}/crawl/found-parameters.txt"
    )
    
    smart_combine "${param_sources[@]}" "${crawler_dir}/wordlists/discovered-parameters.txt"
    
    # Create crawler summary
    local total_urls=$(wc -l < "${base_dir}/all-discovered-urls.txt" 2>/dev/null || echo "0")
    local total_paths=$(wc -l < "${crawler_dir}/wordlists/discovered-paths.txt" 2>/dev/null || echo "0")
    local total_params=$(wc -l < "${crawler_dir}/wordlists/discovered-parameters.txt" 2>/dev/null || echo "0")
    local js_files=$(wc -l < "${crawler_dir}/js_endpoints/js-files.txt" 2>/dev/null || echo "0")
    local api_endpoints=$(wc -l < "${crawler_dir}/api_endpoints/all-api-endpoints.txt" 2>/dev/null || echo "0")
    
    cat > "${crawler_dir}/crawler-summary.txt" << EOF
WEB CRAWLER SUMMARY
===================

Target Domain: $DOMAIN
Crawl Date: $(date)
Scope Type: ${SCOPE_TYPE:-auto}

DISCOVERED RESOURCES:
• Total URLs: $total_urls
• Unique Paths: $total_paths  
• Parameters: $total_params
• JavaScript Files: $js_files
• API Endpoints: $api_endpoints

CRAWLER MODULES:
✓ Archive URL Extraction (Wayback, GAU)
✓ Katana Web Crawler
✓ JavaScript Endpoint Extraction
✓ API Endpoint Discovery

FILES CREATED:
📁 ${crawler_dir}/all-archive-urls.txt
📁 ${crawler_dir}/crawl/katana-urls.txt
📁 ${crawler_dir}/js_endpoints/js-extracted-endpoints.txt
📁 ${crawler_dir}/api_endpoints/all-api-endpoints.txt
📁 ${crawler_dir}/wordlists/discovered-paths.txt
📁 ${crawler_dir}/wordlists/discovered-parameters.txt

EOF
    
    log_message "Crawler discovered $total_urls URLs, $total_paths paths, $total_params parameters"
    
    commit_step "Crawler Results Consolidation"
    return 0
}

# =============================================================================
# MAIN CRAWLER EXECUTION
# =============================================================================

main_crawler() {
    log_message "Starting web crawling module"
    
    # Initialize crawler environment
    if ! initialize_crawler; then
        log_error "Failed to initialize crawler"
        return 1
    fi
    
    # Execute crawler functions
    archive_url_extraction
    katana_crawler
    javascript_endpoint_extraction
    api_endpoint_discovery
    consolidate_crawler_results
    
    log_message "Web crawling completed"
    return 0
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_crawler "$@"
fi

