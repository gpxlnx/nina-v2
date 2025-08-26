#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - JavaScript Analysis Module
# Advanced JavaScript file analysis, endpoint extraction, and secrets discovery
# =============================================================================

# Ensure config is loaded
if [[ -z "${DIR_NINA:-}" ]]; then
    echo "Error: Config not loaded. This module should be run via nina-recon.sh"
    exit 1
fi

# =============================================================================
# JAVASCRIPT ANALYSIS FUNCTIONS
# =============================================================================

initialize_javascript() {
    log_message "Initializing JavaScript analysis for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local js_dir="${base_dir}/analysis"
    
    # Create specialized subdirectories for JavaScript analysis
    local subdirs=(
        "javascript"
        "javascript/files"
        "javascript/endpoints"
        "javascript/secrets"
        "javascript/apis"
        "javascript/urls"
        "javascript/analysis"
        "javascript/downloaded"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${js_dir}/${subdir}" 2>/dev/null
    done
    
    return 0
}

collect_javascript_files() {
    log_message "Collecting JavaScript files from previous discoveries"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local js_dir="${base_dir}/analysis/javascript"
    local js_files="${js_dir}/all-js-files.txt"
    
    # Clear previous results
    > "$js_files"
    
    # Sources to search for JS files
    local search_sources=(
        "${base_dir}/all-discovered-urls.txt"
        "${base_dir}/all-fuzzing-results.txt" 
        "${base_dir}/discovery/content/all-files.txt"
        "${base_dir}/probing/live-urls-final.txt"
    )
    
    log_info "Searching for JavaScript files in discovered URLs"
    
    # Extract JavaScript files from various sources
    for source in "${search_sources[@]}"; do
        if [[ -f "$source" ]]; then
            grep -iE '\.(js|jsx|ts|tsx)(\?|$|#)' "$source" 2>/dev/null | \
            grep -v '\.min\.js' | \
            head -200 >> "$js_files"
        fi
    done
    
    # Also check for common JS file patterns
    if [[ -f "${base_dir}/live-hosts.txt" ]]; then
        log_info "Checking for common JavaScript file patterns"
        
        local common_js_files=(
            "app.js"
            "main.js"
            "script.js"
            "bundle.js"
            "vendor.js"
            "config.js"
            "api.js"
            "auth.js"
            "admin.js"
            "user.js"
            "dashboard.js"
            "core.js"
            "common.js"
            "utils.js"
            "helpers.js"
        )
        
        while IFS= read -r host; do
            for js_file in "${common_js_files[@]}"; do
                echo "${host}/${js_file}"
                echo "${host}/js/${js_file}"
                echo "${host}/scripts/${js_file}"
                echo "${host}/assets/js/${js_file}"
                echo "${host}/static/js/${js_file}"
            done
        done < "${base_dir}/live-hosts.txt" >> "$js_files"
    fi
    
    # Remove duplicates and invalid entries
    sort -u "$js_files" | grep -E '^https?://' > "${js_files}.tmp" && mv "${js_files}.tmp" "$js_files"
    
    local js_count=$(wc -l < "$js_files" 2>/dev/null || echo "0")
    log_message "Found $js_count JavaScript files for analysis"
    
    if [[ $js_count -eq 0 ]]; then
        log_warning "No JavaScript files found for analysis"
        return 1
    fi
    
    return 0
}

download_javascript_files() {
    log_message "Downloading JavaScript files for analysis"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local js_dir="${base_dir}/analysis/javascript"
    local js_files="${js_dir}/all-js-files.txt"
    local download_dir="${js_dir}/downloaded"
    
    if [[ ! -f "$js_files" ]]; then
        log_warning "No JavaScript files list found"
        return 1
    fi
    
    # Clean download directory
    rm -rf "$download_dir" 2>/dev/null
    mkdir -p "$download_dir"
    
    local downloaded=0
    local max_downloads=50
    
    log_info "Downloading up to $max_downloads JavaScript files"
    
    while IFS= read -r js_url && [[ $downloaded -lt $max_downloads ]]; do
        if [[ -z "$js_url" ]]; then
            continue
        fi
        
        local safe_filename=$(echo "$js_url" | sed 's|[^a-zA-Z0-9.-]|_|g' | cut -c1-100)
        local js_file="${download_dir}/${safe_filename}.js"
        
        log_info "Downloading: $js_url"
        
        # Download with proper headers and timeout
        if curl -s -L \
            --max-time 30 \
            --max-filesize 2M \
            -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
            -H "Accept: text/javascript, application/javascript, */*" \
            "$js_url" -o "$js_file" 2>/dev/null; then
            
            # Verify it's actually JavaScript content
            if file "$js_file" | grep -qE "(text|JavaScript|ASCII|UTF-8)"; then
                # Check file size (skip if too small or too large)
                local file_size=$(stat -f%z "$js_file" 2>/dev/null || stat -c%s "$js_file" 2>/dev/null || echo "0")
                if [[ $file_size -gt 100 && $file_size -lt 2000000 ]]; then
                    echo "$js_url" >> "${js_dir}/downloaded-files.txt"
                    ((downloaded++))
                else
                    rm -f "$js_file"
                fi
            else
                rm -f "$js_file"
            fi
        fi
        
    done < "$js_files"
    
    log_message "Successfully downloaded $downloaded JavaScript files"
    
    return 0
}

extract_endpoints_from_js() {
    log_message "Extracting endpoints from JavaScript files"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local js_dir="${base_dir}/analysis/javascript"
    local download_dir="${js_dir}/downloaded"
    local endpoints_dir="${js_dir}/endpoints"
    
    if [[ ! -d "$download_dir" ]]; then
        log_warning "No downloaded JavaScript files found"
        return 1
    fi
    
    # Clear previous results
    > "${endpoints_dir}/api-endpoints.txt"
    > "${endpoints_dir}/relative-paths.txt"
    > "${endpoints_dir}/full-urls.txt"
    > "${endpoints_dir}/parameters.txt"
    
    log_info "Analyzing JavaScript files for endpoints"
    
    find "$download_dir" -name "*.js" -type f | while read -r js_file; do
        if [[ ! -f "$js_file" ]]; then
            continue
        fi
        
        log_info "Analyzing: $(basename "$js_file")"
        
        # Extract API endpoints (common patterns)
        grep -oE '"[^"]*/(api|v[0-9]+|admin|user|auth|rest|graphql)[^"]*"' "$js_file" 2>/dev/null | \
        sed 's/^"//; s/"$//' | \
        grep -E '^/' | \
        head -50 >> "${endpoints_dir}/api-endpoints.txt"
        
        # Extract relative paths
        grep -oE '"/[a-zA-Z0-9._/-]+"' "$js_file" 2>/dev/null | \
        sed 's/^"//; s/"$//' | \
        grep -v -E '\.(css|png|jpg|jpeg|gif|ico|svg|woff|ttf)$' | \
        head -100 >> "${endpoints_dir}/relative-paths.txt"
        
        # Extract full URLs related to domain
        grep -oE 'https?://[^"'\''`\s]+' "$js_file" 2>/dev/null | \
        grep -E "\.${DOMAIN//./\\.}" | \
        head -50 >> "${endpoints_dir}/full-urls.txt"
        
        # Extract potential parameters
        grep -oE '\b[a-zA-Z_][a-zA-Z0-9_]*\s*:\s*"[^"]*"' "$js_file" 2>/dev/null | \
        grep -oE '^[a-zA-Z_][a-zA-Z0-9_]*' | \
        head -30 >> "${endpoints_dir}/parameters.txt"
        
    done
    
    # Process and deduplicate results
    for file in "${endpoints_dir}"/*.txt; do
        if [[ -f "$file" ]]; then
            sort -u "$file" -o "$file"
            # Remove empty lines
            sed -i '/^$/d' "$file" 2>/dev/null || sed -i.bak '/^$/d' "$file"
        fi
    done
    
    # Generate full URLs from relative paths
    if [[ -f "${endpoints_dir}/relative-paths.txt" && -f "${base_dir}/live-hosts.txt" ]]; then
        log_info "Converting relative paths to full URLs"
        
        while IFS= read -r path; do
            head -5 "${base_dir}/live-hosts.txt" | while IFS= read -r host; do
                echo "${host}${path}"
            done
        done < "${endpoints_dir}/relative-paths.txt" > "${endpoints_dir}/generated-urls.txt"
        
        sort -u "${endpoints_dir}/generated-urls.txt" -o "${endpoints_dir}/generated-urls.txt"
    fi
    
    # Summary
    local api_count=$(wc -l < "${endpoints_dir}/api-endpoints.txt" 2>/dev/null || echo "0")
    local paths_count=$(wc -l < "${endpoints_dir}/relative-paths.txt" 2>/dev/null || echo "0")
    local urls_count=$(wc -l < "${endpoints_dir}/full-urls.txt" 2>/dev/null || echo "0")
    local params_count=$(wc -l < "${endpoints_dir}/parameters.txt" 2>/dev/null || echo "0")
    
    log_message "Endpoint extraction: $api_count API endpoints, $paths_count paths, $urls_count URLs, $params_count parameters"
    
    commit_step "JavaScript Endpoint Extraction"
    return 0
}

extract_secrets_from_js() {
    log_message "Extracting secrets and sensitive data from JavaScript files"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local js_dir="${base_dir}/analysis/javascript"
    local download_dir="${js_dir}/downloaded"
    local secrets_dir="${js_dir}/secrets"
    
    if [[ ! -d "$download_dir" ]]; then
        log_warning "No downloaded JavaScript files found"
        return 1
    fi
    
    # Clear previous results
    > "${secrets_dir}/api-keys.txt"
    > "${secrets_dir}/tokens.txt"
    > "${secrets_dir}/passwords.txt"
    > "${secrets_dir}/urls.txt"
    > "${secrets_dir}/emails.txt"
    > "${secrets_dir}/sensitive-patterns.txt"
    
    log_info "Analyzing JavaScript files for secrets and sensitive data"
    
    find "$download_dir" -name "*.js" -type f | while read -r js_file; do
        if [[ ! -f "$js_file" ]]; then
            continue
        fi
        
        local filename=$(basename "$js_file")
        
        # API Keys patterns
        grep -oE '(api_key|apikey|api-key)["\s]*[:=]["\s]*"[a-zA-Z0-9_-]{10,}"' "$js_file" 2>/dev/null | \
        sed "s/^/$filename: /" >> "${secrets_dir}/api-keys.txt"
        
        # Access tokens
        grep -oE '(access_token|accesstoken|bearer)["\s]*[:=]["\s]*"[a-zA-Z0-9_.-]{20,}"' "$js_file" 2>/dev/null | \
        sed "s/^/$filename: /" >> "${secrets_dir}/tokens.txt"
        
        # JWT tokens
        grep -oE 'eyJ[a-zA-Z0-9_.-]+' "$js_file" 2>/dev/null | \
        sed "s/^/$filename: JWT: /" >> "${secrets_dir}/tokens.txt"
        
        # Passwords (common patterns)
        grep -oE '(password|passwd|pwd)["\s]*[:=]["\s]*"[^"]{6,}"' "$js_file" 2>/dev/null | \
        sed "s/^/$filename: /" >> "${secrets_dir}/passwords.txt"
        
        # Database connection strings
        grep -oE '(mysql|postgresql|mongodb|redis)://[^"\s]+' "$js_file" 2>/dev/null | \
        sed "s/^/$filename: /" >> "${secrets_dir}/urls.txt"
        
        # Email addresses
        grep -oE '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' "$js_file" 2>/dev/null | \
        sed "s/^/$filename: /" >> "${secrets_dir}/emails.txt"
        
    done
    
    # Remove duplicates and empty files
    for file in "${secrets_dir}"/*.txt; do
        if [[ -f "$file" ]]; then
            sort -u "$file" -o "$file"
            sed -i '/^$/d' "$file" 2>/dev/null || sed -i.bak '/^$/d' "$file"
            
            # Remove file if empty
            if [[ ! -s "$file" ]]; then
                rm -f "$file"
            fi
        fi
    done
    
    # Summary
    local total_secrets=0
    for file in "${secrets_dir}"/*.txt; do
        if [[ -f "$file" ]]; then
            local count=$(wc -l < "$file" 2>/dev/null || echo "0")
            total_secrets=$((total_secrets + count))
            log_info "$(basename "$file"): $count findings"
        fi
    done
    
    log_message "Secret extraction: $total_secrets total sensitive findings"
    
    commit_step "JavaScript Secret Extraction"
    return 0
}

consolidate_javascript_results() {
    log_message "Consolidating JavaScript analysis results"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local js_dir="${base_dir}/analysis/javascript"
    
    # Combine all discovered endpoints
    local endpoint_sources=(
        "${js_dir}/endpoints/api-endpoints.txt"
        "${js_dir}/endpoints/relative-paths.txt"
        "${js_dir}/endpoints/full-urls.txt"
        "${js_dir}/endpoints/generated-urls.txt"
    )
    
    smart_combine "${endpoint_sources[@]}" "${base_dir}/javascript-endpoints.txt"
    
    # Combine all discovered URLs
    local url_sources=(
        "${js_dir}/endpoints/full-urls.txt"
        "${js_dir}/endpoints/generated-urls.txt"
    )
    
    smart_combine "${url_sources[@]}" "${base_dir}/javascript-urls.txt"
    
    # Create comprehensive summary
    local downloaded_files=$(wc -l < "${js_dir}/downloaded-files.txt" 2>/dev/null || echo "0")
    local total_endpoints=$(wc -l < "${base_dir}/javascript-endpoints.txt" 2>/dev/null || echo "0")
    local total_urls=$(wc -l < "${base_dir}/javascript-urls.txt" 2>/dev/null || echo "0")
    local api_endpoints=$(wc -l < "${js_dir}/endpoints/api-endpoints.txt" 2>/dev/null || echo "0")
    local parameters=$(wc -l < "${js_dir}/endpoints/parameters.txt" 2>/dev/null || echo "0")
    
    # Count secrets
    local total_secrets=0
    if [[ -d "${js_dir}/secrets" ]]; then
        for secret_file in "${js_dir}/secrets"/*.txt; do
            if [[ -f "$secret_file" ]]; then
                local count=$(wc -l < "$secret_file" 2>/dev/null || echo "0")
                total_secrets=$((total_secrets + count))
            fi
        done
    fi
    
    cat > "${js_dir}/analysis-summary.txt" << EOF
JAVASCRIPT ANALYSIS SUMMARY
============================

Target Domain: $DOMAIN
Analysis Date: $(date)
Scope Type: ${SCOPE_TYPE:-auto}

JAVASCRIPT FILES:
• Downloaded: $downloaded_files files
• Successfully Analyzed: $(find "${js_dir}/downloaded" -name "*.js" 2>/dev/null | wc -l)

EXTRACTED DATA:
• Total Endpoints: $total_endpoints
• API Endpoints: $api_endpoints  
• Full URLs: $total_urls
• Parameters: $parameters
• Secrets Found: $total_secrets

ANALYSIS MODULES:
✓ File Collection & Download
✓ Endpoint Extraction
✓ Secret Discovery

FILES CREATED:
📁 ${js_dir}/downloaded-files.txt
📁 ${js_dir}/endpoints/api-endpoints.txt
📁 ${js_dir}/endpoints/parameters.txt
📁 ${base_dir}/javascript-endpoints.txt
📁 ${base_dir}/javascript-urls.txt

EOF
    
    # Clean up downloaded files to save space
    if [[ "${CLEANUP_JS_FILES:-true}" == "true" ]]; then
        log_info "Cleaning up downloaded JavaScript files to save space"
        rm -rf "${js_dir}/downloaded" 2>/dev/null
    fi
    
    log_message "JavaScript analysis: $total_endpoints endpoints, $total_secrets secrets found"
    
    commit_step "JavaScript Analysis Consolidation"
    return 0
}

# =============================================================================
# MAIN JAVASCRIPT ANALYSIS EXECUTION
# =============================================================================

main_javascript() {
    log_message "Starting JavaScript analysis module"
    
    # Initialize JavaScript analysis environment
    if ! initialize_javascript; then
        log_error "Failed to initialize JavaScript analysis"
        return 1
    fi
    
    # Execute JavaScript analysis functions
    if ! collect_javascript_files; then
        log_warning "No JavaScript files found for analysis"
        return 1
    fi
    
    download_javascript_files
    extract_endpoints_from_js
    extract_secrets_from_js
    consolidate_javascript_results
    
    log_message "JavaScript analysis completed"
    return 0
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_javascript "$@"
fi