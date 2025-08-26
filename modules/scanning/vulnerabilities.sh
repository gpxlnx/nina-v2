#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Vulnerability Scanning Module
# Advanced vulnerability detection and security analysis
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
# VULNERABILITY SCANNING FUNCTIONS
# =============================================================================

initialize_vulnerability_scanning() {
    log_message "Initializing vulnerability scanning for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local vuln_dir="${base_dir}/vulnerabilities"
    
    # Create specialized subdirectories
    local subdirs=(
        "nuclei"
        "custom"
        "web_vulns"
        "ssl_tls"
        "subdomain_takeover"
        "secrets"
        "misconfigurations"
        "apis"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${vuln_dir}/${subdir}" 2>/dev/null
    done
    
    # Check if we have URLs to scan
    if [[ ! -f "${base_dir}/live-hosts.txt" ]] || [[ ! -s "${base_dir}/live-hosts.txt" ]]; then
        log_warning "No live hosts found for vulnerability scanning"
        return 1
    fi
    
    return 0
}

nuclei_vulnerability_scanning() {
    log_message "Running Nuclei vulnerability scanning"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local vuln_dir="${base_dir}/vulnerabilities"
    local nuclei_dir="${vuln_dir}/nuclei"
    
    if ! tool_available nuclei; then
        log_warning "Nuclei not available, skipping vulnerability scanning"
        return 0
    fi
    
    # Prepare target list
    local targets="${nuclei_dir}/scan-targets.txt"
    
    # Combine various URL sources for comprehensive scanning
    cat "${base_dir}/live-hosts.txt" \
        "${base_dir}/all-urls.txt" 2>/dev/null | \
    sort -u | \
    head -1000 > "$targets"
    
    local target_count=$(wc -l < "$targets")
    log_info "Scanning $target_count targets with Nuclei"
    
    # Update nuclei templates
    log_info "Updating Nuclei templates"
    nuclei -update-templates -silent 2>/dev/null || true
    
    # Run comprehensive Nuclei scan with different severity levels
    local nuclei_args=(
        "-l" "$targets"
        "-t" "/root/nuclei-templates/"
        "-severity" "$NUCLEI_SEVERITY"
        "-exclude-tags" "$NUCLEI_EXCLUDED"
        "-rate-limit" "$NUCLEI_RATE_LIMIT"
        "-timeout" "$NUCLEI_TIMEOUT"
        "-retries" "2"
        "-bulk-size" "25"
        "-project-path" "$nuclei_dir"
        "-markdown-export" "${nuclei_dir}/nuclei-report.md"
        "-json-export" "${nuclei_dir}/nuclei-results.json"
        "-silent"
    )
    
    # Run main scan
    nuclei "${nuclei_args[@]}" -o "${nuclei_dir}/nuclei-all.txt" 2>/dev/null || true
    
    # Run specialized scans
    log_info "Running specialized Nuclei scans"
    
    # CVE scan
    nuclei -l "$targets" -t "/root/nuclei-templates/cves/" \
    -severity "critical,high,medium" \
    -rate-limit "$NUCLEI_RATE_LIMIT" \
    -silent -o "${nuclei_dir}/nuclei-cves.txt" 2>/dev/null || true
    
    # Misconfiguration scan
    nuclei -l "$targets" -t "/root/nuclei-templates/misconfiguration/" \
    -severity "critical,high,medium,low" \
    -rate-limit "$NUCLEI_RATE_LIMIT" \
    -silent -o "${nuclei_dir}/nuclei-misconfig.txt" 2>/dev/null || true
    
    # Technology-specific scans
    nuclei -l "$targets" -t "/root/nuclei-templates/technologies/" \
    -rate-limit "$NUCLEI_RATE_LIMIT" \
    -silent -o "${nuclei_dir}/nuclei-technologies.txt" 2>/dev/null || true
    
    # Exposed panels
    nuclei -l "$targets" -t "/root/nuclei-templates/exposed-panels/" \
    -rate-limit "$NUCLEI_RATE_LIMIT" \
    -silent -o "${nuclei_dir}/nuclei-panels.txt" 2>/dev/null || true
    
    # File exposure
    nuclei -l "$targets" -t "/root/nuclei-templates/exposures/" \
    -rate-limit "$NUCLEI_RATE_LIMIT" \
    -silent -o "${nuclei_dir}/nuclei-exposures.txt" 2>/dev/null || true
    
    # Process Nuclei results
    process_nuclei_results "$nuclei_dir"
    
    commit_step "Nuclei Vulnerability Scanning"
    return 0
}

subdomain_takeover_check() {
    log_message "Checking for subdomain takeover vulnerabilities"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local vuln_dir="${base_dir}/vulnerabilities"
    local takeover_dir="${vuln_dir}/subdomain_takeover"
    
    # Use subzy for subdomain takeover detection
    if tool_available subzy; then
        log_info "Running subzy for subdomain takeover detection"
        
        subzy run --targets "${base_dir}/recon/subdomains-all.txt" \
        --hide_fails \
        --output "${takeover_dir}/subzy-results.txt" 2>/dev/null || true
        
        # Also check specific URLs
        if [[ -f "${base_dir}/live-hosts.txt" ]]; then
            subzy run --targets "${base_dir}/live-hosts.txt" \
            --hide_fails \
            --output "${takeover_dir}/subzy-urls.txt" 2>/dev/null || true
        fi
    fi
    
    # Use subjack for additional checking
    if tool_available subjack; then
        log_info "Running subjack for subdomain takeover detection"
        
        subjack -w "${base_dir}/recon/subdomains-all.txt" \
        -t 100 -timeout 30 -ssl \
        -c /root/subjack/fingerprints.json \
        -v 2>/dev/null | tee "${takeover_dir}/subjack-results.txt" || true
    fi
    
    # Custom CNAME checking
    log_info "Performing custom CNAME analysis"
    
    while IFS= read -r subdomain; do
        local cname=$(dig +short CNAME "$subdomain" 2>/dev/null | head -1)
        if [[ -n "$cname" ]]; then
            echo "$subdomain -> $cname" >> "${takeover_dir}/cnames.txt"
            
            # Check for common takeover indicators
            if echo "$cname" | grep -qE "(amazonaws|azurewebsites|cloudfront|github\.io|heroku|pantheon|surge\.sh|bitbucket\.io|fastly|shopify)"; then
                echo "$subdomain -> $cname [POTENTIAL TAKEOVER]" >> "${takeover_dir}/potential-takeovers.txt"
            fi
        fi
    done < "${base_dir}/recon/subdomains-all.txt"
    
    # Check for dangling CNAMEs by trying to resolve them
    if [[ -f "${takeover_dir}/cnames.txt" ]]; then
        while IFS=' -> ' read -r subdomain cname; do
            if ! dig +short "$cname" 2>/dev/null | grep -E '^[0-9]+\.' >/dev/null; then
                echo "$subdomain -> $cname [DANGLING CNAME]" >> "${takeover_dir}/dangling-cnames.txt"
            fi
        done < "${takeover_dir}/cnames.txt"
    fi
    
    local takeover_count=$(wc -l < "${takeover_dir}/potential-takeovers.txt" 2>/dev/null || echo "0")
    local dangling_count=$(wc -l < "${takeover_dir}/dangling-cnames.txt" 2>/dev/null || echo "0")
    
    log_message "Subdomain takeover check: $takeover_count potential, $dangling_count dangling CNAMEs"
    
    commit_step "Subdomain Takeover Check"
    return 0
}

ssl_tls_analysis() {
    log_message "Analyzing SSL/TLS configurations"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local vuln_dir="${base_dir}/vulnerabilities"
    local ssl_dir="${vuln_dir}/ssl_tls"
    
    # Extract HTTPS URLs
    grep "^https://" "${base_dir}/live-hosts.txt" 2>/dev/null | \
    head -50 > "${ssl_dir}/https-targets.txt" || true
    
    if [[ ! -s "${ssl_dir}/https-targets.txt" ]]; then
        log_info "No HTTPS URLs found for SSL/TLS analysis"
        return 0
    fi
    
    # Use sslscan if available
    if tool_available sslscan; then
        log_info "Running sslscan for SSL/TLS analysis"
        
        while IFS= read -r url; do
            local host=$(echo "$url" | sed 's|^https://||' | cut -d'/' -f1)
            local port="443"
            
            if [[ "$host" =~ :[0-9]+$ ]]; then
                port=$(echo "$host" | cut -d':' -f2)
                host=$(echo "$host" | cut -d':' -f1)
            fi
            
            local safe_filename=$(echo "${host}_${port}" | sed 's|[^a-zA-Z0-9._-]|_|g')
            
            sslscan --show-certificate --show-client-cas --show-ciphers \
            "${host}:${port}" > "${ssl_dir}/sslscan-${safe_filename}.txt" 2>/dev/null || true
            
        done < "${ssl_dir}/https-targets.txt"
        
        # Analyze sslscan results for vulnerabilities
        grep -l -E "(SSLv[23]|TLSv1\.0|TLSv1\.1|RC4|MD5|SHA1|NULL|EXPORT|DES)" \
        "${ssl_dir}"/sslscan-*.txt 2>/dev/null | \
        sed 's|.*/sslscan-||; s|\.txt$||' > "${ssl_dir}/weak-ssl-hosts.txt" || true
    fi
    
    # Use testssl.sh if available
    if tool_available testssl.sh; then
        log_info "Running testssl.sh for comprehensive SSL analysis"
        
        # Test a few key hosts with testssl.sh (more comprehensive but slower)
        head -5 "${ssl_dir}/https-targets.txt" | while IFS= read -r url; do
            local host=$(echo "$url" | sed 's|^https://||' | cut -d'/' -f1)
            local safe_filename=$(echo "$host" | sed 's|[^a-zA-Z0-9._-]|_|g')
            
            testssl.sh --quiet --jsonfile "${ssl_dir}/testssl-${safe_filename}.json" \
            --logfile "${ssl_dir}/testssl-${safe_filename}.log" \
            "$host" 2>/dev/null || true
        done
    fi
    
    # Use tlsx for certificate analysis
    if tool_available tlsx; then
        log_info "Running tlsx for certificate analysis"
        
        tlsx -l "${ssl_dir}/https-targets.txt" \
        -json -silent \
        -cn -san -so -expired -self-signed -mismatched \
        -o "${ssl_dir}/tlsx-analysis.json" 2>/dev/null || true
        
        # Extract certificate issues
        if [[ -f "${ssl_dir}/tlsx-analysis.json" ]]; then
            jq -r 'select(.expired == true or .self_signed == true or .mismatched == true) | .host + " - " + (.expired // false | tostring) + " " + (.self_signed // false | tostring) + " " + (.mismatched // false | tostring)' \
            "${ssl_dir}/tlsx-analysis.json" > "${ssl_dir}/certificate-issues.txt" 2>/dev/null || true
        fi
    fi
    
    # Check for common SSL/TLS vulnerabilities with Nuclei
    if tool_available nuclei; then
        log_info "Running Nuclei SSL/TLS vulnerability checks"
        
        nuclei -l "${ssl_dir}/https-targets.txt" \
        -t "/root/nuclei-templates/ssl/" \
        -severity "critical,high,medium" \
        -rate-limit 50 \
        -silent -o "${ssl_dir}/nuclei-ssl-vulns.txt" 2>/dev/null || true
    fi
    
    local ssl_issues=$(wc -l < "${ssl_dir}/certificate-issues.txt" 2>/dev/null || echo "0")
    local weak_ssl=$(wc -l < "${ssl_dir}/weak-ssl-hosts.txt" 2>/dev/null || echo "0")
    
    log_message "SSL/TLS analysis: $ssl_issues certificate issues, $weak_ssl weak configurations"
    
    commit_step "SSL/TLS Analysis"
    return 0
}

web_vulnerability_scanning() {
    log_message "Scanning for common web vulnerabilities"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local vuln_dir="${base_dir}/vulnerabilities"
    local web_dir="${vuln_dir}/web_vulns"
    
    # Prepare URLs for web vulnerability scanning
    local web_targets="${web_dir}/web-scan-targets.txt"
    
    # Include various URL types
    cat "${base_dir}/live-hosts.txt" \
        "${base_dir}/all-urls.txt" 2>/dev/null | \
    grep -E "^https?://" | \
    head -200 > "$web_targets"
    
    if [[ ! -s "$web_targets" ]]; then
        log_warning "No web targets for vulnerability scanning"
        return 0
    fi
    
    # XSS Detection
    log_info "Scanning for XSS vulnerabilities"
    
    if tool_available dalfox; then
        dalfox file "$web_targets" \
        --silence \
        --format json \
        --output "${web_dir}/dalfox-xss.json" 2>/dev/null || true
    fi
    
    # SQL Injection Detection
    log_info "Scanning for SQL injection vulnerabilities"
    
    if tool_available sqlmap; then
        # Create a limited list for sqlmap (it's slow)
        head -20 "$web_targets" | while IFS= read -r url; do
            timeout 300 sqlmap -u "$url" \
            --batch --random-agent --level 1 --risk 1 \
            --output-dir "${web_dir}/sqlmap" 2>/dev/null || true
        done
    fi
    
    # CRLF Injection
    log_info "Scanning for CRLF injection"
    
    if tool_available crlfuzz; then
        crlfuzz -l "$web_targets" \
        -o "${web_dir}/crlf-vulnerabilities.txt" 2>/dev/null || true
    fi
    
    # Open Redirect Detection
    log_info "Scanning for open redirect vulnerabilities"
    
    # Use a simple approach with curl to test for redirects
    while IFS= read -r url; do
        local test_url="${url}?redirect=http://evil.com"
        local response=$(curl -s -I -L --max-redirs 1 "$test_url" 2>/dev/null | grep -i "location:" | head -1)
        if echo "$response" | grep -qi "evil.com"; then
            echo "$url" >> "${web_dir}/open-redirects.txt"
        fi
    done < <(head -50 "$web_targets")
    
    # Directory Traversal
    log_info "Testing for directory traversal"
    
    local traversal_payloads=(
        "../../../etc/passwd"
        "....//....//....//etc/passwd"
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
    )
    
    for payload in "${traversal_payloads[@]}"; do
        while IFS= read -r url; do
            local test_url="${url}?file=${payload}"
            local response=$(curl -s "$test_url" 2>/dev/null)
            if echo "$response" | grep -qE "(root:|daemon:|bin:|sys:)"; then
                echo "$url - $payload" >> "${web_dir}/directory-traversal.txt"
            fi
        done < <(head -20 "$web_targets")
    done
    
    # Local File Inclusion (LFI)
    log_info "Testing for Local File Inclusion"
    
    local lfi_payloads=(
        "/etc/passwd"
        "../../../../etc/passwd"
        "..%2f..%2f..%2f..%2fetc%2fpasswd"
        "php://filter/read=convert.base64-encode/resource=/etc/passwd"
    )
    
    for payload in "${lfi_payloads[@]}"; do
        while IFS= read -r url; do
            if [[ "$url" =~ \? ]]; then
                local test_url="${url}&file=${payload}"
            else
                local test_url="${url}?file=${payload}"
            fi
            
            local response=$(curl -s "$test_url" 2>/dev/null)
            if echo "$response" | grep -qE "(root:|daemon:|bin:|sys:)"; then
                echo "$url - $payload" >> "${web_dir}/lfi-vulnerabilities.txt"
            fi
        done < <(head -20 "$web_targets")
    done
    
    commit_step "Web Vulnerability Scanning"
    return 0
}

api_security_testing() {
    log_message "Testing API security"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local vuln_dir="${base_dir}/vulnerabilities"
    local api_dir="${vuln_dir}/apis"
    
    # Find API endpoints
    local api_targets="${api_dir}/api-targets.txt"
    
    grep -E "(api|rest|graphql|v[0-9]+)" "${base_dir}/all-urls.txt" 2>/dev/null | \
    head -100 > "$api_targets" || true
    
    if [[ ! -s "$api_targets" ]]; then
        log_info "No API endpoints found for security testing"
        return 0
    fi
    
    local api_count=$(wc -l < "$api_targets")
    log_info "Testing $api_count API endpoints for security issues"
    
    # Test for common API vulnerabilities
    log_info "Testing API authentication bypass"
    
    while IFS= read -r api_url; do
        # Test without authentication
        local response=$(curl -s -w "%{http_code}" -o /dev/null "$api_url" 2>/dev/null)
        if [[ "$response" == "200" ]]; then
            echo "$api_url - No authentication required" >> "${api_dir}/unauth-apis.txt"
        fi
        
        # Test with fake/invalid tokens
        local fake_response=$(curl -s -H "Authorization: Bearer fake-token" \
        -w "%{http_code}" -o /dev/null "$api_url" 2>/dev/null)
        if [[ "$fake_response" == "200" ]]; then
            echo "$api_url - Accepts fake token" >> "${api_dir}/weak-auth-apis.txt"
        fi
        
        # Test for verbose error messages
        local error_response=$(curl -s -X POST "$api_url" \
        -H "Content-Type: application/json" \
        -d '{"test": "invalid"}' 2>/dev/null)
        if echo "$error_response" | grep -qE "(stack|trace|error|exception|debug)" -i; then
            echo "$api_url - Verbose error messages" >> "${api_dir}/verbose-error-apis.txt"
        fi
        
    done < "$api_targets"
    
    # Test for CORS misconfigurations
    log_info "Testing for CORS misconfigurations"
    
    while IFS= read -r api_url; do
        local cors_response=$(curl -s -H "Origin: https://evil.com" \
        -I "$api_url" 2>/dev/null | grep -i "access-control-allow-origin")
        
        if echo "$cors_response" | grep -qE "(\*|evil\.com)"; then
            echo "$api_url - Weak CORS: $cors_response" >> "${api_dir}/cors-issues.txt"
        fi
    done < "$api_targets"
    
    # Use Nuclei for API-specific checks
    if tool_available nuclei; then
        log_info "Running Nuclei API security checks"
        
        nuclei -l "$api_targets" \
        -t "/root/nuclei-templates/misconfiguration/" \
        -t "/root/nuclei-templates/exposures/" \
        -tags "api,cors,auth" \
        -rate-limit 50 \
        -silent -o "${api_dir}/nuclei-api-vulns.txt" 2>/dev/null || true
    fi
    
    commit_step "API Security Testing"
    return 0
}

secrets_detection() {
    log_message "Detecting exposed secrets and sensitive information"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local vuln_dir="${base_dir}/vulnerabilities"
    local secrets_dir="${vuln_dir}/secrets"
    
    # Use truffleHog if available
    if tool_available trufflehog; then
        log_info "Running truffleHog for secrets detection"
        
        # Scan URLs for secrets
        while IFS= read -r url; do
            timeout 60 trufflehog "$url" \
            --json 2>/dev/null >> "${secrets_dir}/trufflehog-raw.json" || true
        done < <(head -20 "${base_dir}/live-hosts.txt")
        
        # Parse truffleHog results
        if [[ -f "${secrets_dir}/trufflehog-raw.json" ]]; then
            jq -r '.Raw + " - " + .DetectorName + " - " + .SourceMetadata.Data.Http.uri' \
            "${secrets_dir}/trufflehog-raw.json" 2>/dev/null > \
            "${secrets_dir}/trufflehog-secrets.txt" || true
        fi
    fi
    
    # Manual secrets detection using regex patterns
    log_info "Running manual secrets detection"
    
    # Download sample pages for analysis
    local pages_dir="${secrets_dir}/pages"
    mkdir -p "$pages_dir" 2>/dev/null
    
    head -50 "${base_dir}/all-urls.txt" | while IFS= read -r url; do
        local safe_filename=$(echo "$url" | sed 's|[^a-zA-Z0-9.-]|_|g')
        curl -s -L --max-time 30 "$url" > "${pages_dir}/${safe_filename}.html" 2>/dev/null || true
    done
    
    # Search for common secrets patterns
    local secret_patterns=(
        'api[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9_-]{10,}'
        'secret[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9_-]{10,}'
        'access[_-]?token["\s]*[:=]["\s]*[a-zA-Z0-9_-]{10,}'
        'password["\s]*[:=]["\s]*[a-zA-Z0-9_!@#$%^&*()-]{6,}'
        'AKIA[0-9A-Z]{16}'  # AWS Access Key
        'sk_live_[0-9a-zA-Z]{24}'  # Stripe Live Key
        'sk_test_[0-9a-zA-Z]{24}'  # Stripe Test Key
        'pk_live_[0-9a-zA-Z]{24}'  # Stripe Publishable Key
        'pk_test_[0-9a-zA-Z]{24}'  # Stripe Test Publishable Key
        'AIza[0-9A-Za-z\\-_]{35}'  # Google API Key
        'ya29\\.[0-9A-Za-z\\-_]+'  # Google OAuth
        'ghp_[0-9a-zA-Z]{36}'  # GitHub Personal Access Token
        'xox[baprs]-[0-9a-zA-Z-]{10,48}'  # Slack Token
    )
    
    for pattern in "${secret_patterns[@]}"; do
        grep -rEoh "$pattern" "${pages_dir}/" 2>/dev/null | \
        head -20 >> "${secrets_dir}/potential-secrets.txt" || true
    done
    
    # Look for exposed .env files and config files
    log_info "Checking for exposed configuration files"
    
    local config_paths=(
        "/.env"
        "/.env.local"
        "/.env.production"
        "/.env.development"
        "/config.json"
        "/config.yaml"
        "/config.yml"
        "/app.json"
        "/package.json"
        "/composer.json"
        "/web.config"
        "/app.config"
        "/.git/config"
        "/.svn/entries"
        "/backup.sql"
        "/database.sql"
        "/dump.sql"
    )
    
    for base_url in $(head -10 "${base_dir}/live-hosts.txt"); do
        for config_path in "${config_paths[@]}"; do
            local test_url="${base_url}${config_path}"
            local response=$(curl -s -w "%{http_code}" "$test_url" 2>/dev/null)
            local status_code="${response: -3}"
            
            if [[ "$status_code" == "200" ]]; then
                echo "$test_url" >> "${secrets_dir}/exposed-configs.txt"
                
                # Download and analyze the config file
                local content=$(curl -s "$test_url" 2>/dev/null)
                if echo "$content" | grep -qE "(password|secret|key|token)" -i; then
                    echo "$test_url - Contains sensitive keywords" >> "${secrets_dir}/sensitive-configs.txt"
                fi
            fi
        done
    done
    
    # Clean up downloaded pages to save space
    rm -rf "$pages_dir" 2>/dev/null
    
    local secrets_count=$(wc -l < "${secrets_dir}/potential-secrets.txt" 2>/dev/null || echo "0")
    local configs_count=$(wc -l < "${secrets_dir}/exposed-configs.txt" 2>/dev/null || echo "0")
    
    log_message "Secrets detection: $secrets_count potential secrets, $configs_count exposed configs"
    
    commit_step "Secrets Detection"
    return 0
}

consolidate_vulnerability_results() {
    log_message "Consolidating vulnerability scan results"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local vuln_dir="${base_dir}/vulnerabilities"
    
    # Combine all vulnerability findings
    local vuln_files=(
        "${vuln_dir}/nuclei/nuclei-all.txt"
        "${vuln_dir}/subdomain_takeover/potential-takeovers.txt"
        "${vuln_dir}/ssl_tls/certificate-issues.txt"
        "${vuln_dir}/web_vulns/crlf-vulnerabilities.txt"
        "${vuln_dir}/web_vulns/open-redirects.txt"
        "${vuln_dir}/web_vulns/directory-traversal.txt"
        "${vuln_dir}/web_vulns/lfi-vulnerabilities.txt"
        "${vuln_dir}/apis/unauth-apis.txt"
        "${vuln_dir}/apis/cors-issues.txt"
        "${vuln_dir}/secrets/exposed-configs.txt"
        "${vuln_dir}/secrets/sensitive-configs.txt"
    )
    
    # Create consolidated vulnerability report
    : > "${base_dir}/vulnerabilities.txt"
    
    for vuln_file in "${vuln_files[@]}"; do
        if [[ -f "$vuln_file" && -s "$vuln_file" ]]; then
            echo "=== $(basename "$(dirname "$vuln_file")")/$(basename "$vuln_file") ===" >> "${base_dir}/vulnerabilities.txt"
            cat "$vuln_file" >> "${base_dir}/vulnerabilities.txt"
            echo "" >> "${base_dir}/vulnerabilities.txt"
        fi
    done
    
    # Count vulnerabilities by severity/type
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    local info_count=0
    
    if [[ -f "${vuln_dir}/nuclei/nuclei-all.txt" ]]; then
        critical_count=$(grep -c "\[critical\]" "${vuln_dir}/nuclei/nuclei-all.txt" 2>/dev/null || echo "0")
        high_count=$(grep -c "\[high\]" "${vuln_dir}/nuclei/nuclei-all.txt" 2>/dev/null || echo "0")
        medium_count=$(grep -c "\[medium\]" "${vuln_dir}/nuclei/nuclei-all.txt" 2>/dev/null || echo "0")
        low_count=$(grep -c "\[low\]" "${vuln_dir}/nuclei/nuclei-all.txt" 2>/dev/null || echo "0")
        info_count=$(grep -c "\[info\]" "${vuln_dir}/nuclei/nuclei-all.txt" 2>/dev/null || echo "0")
    fi
    
    local total_vulns=$(wc -l < "${base_dir}/vulnerabilities.txt" 2>/dev/null || echo "0")
    local takeover_count=$(wc -l < "${vuln_dir}/subdomain_takeover/potential-takeovers.txt" 2>/dev/null || echo "0")
    local ssl_issues=$(wc -l < "${vuln_dir}/ssl_tls/certificate-issues.txt" 2>/dev/null || echo "0")
    local secrets_count=$(wc -l < "${vuln_dir}/secrets/exposed-configs.txt" 2>/dev/null || echo "0")
    
    # Create comprehensive summary
    cat > "${vuln_dir}/vulnerability-summary.txt" << EOF
VULNERABILITY SCAN SUMMARY
==========================

Domain: $DOMAIN
Total Findings: $total_vulns
Date: $(date)

Severity Breakdown (Nuclei):
- Critical: $critical_count
- High: $high_count
- Medium: $medium_count
- Low: $low_count
- Info: $info_count

Security Issues by Category:
- Subdomain Takeover: $takeover_count potential
- SSL/TLS Issues: $ssl_issues
- Exposed Secrets/Configs: $secrets_count
- Web Vulnerabilities: Found in web_vulns directory
- API Security Issues: Found in apis directory

Scan Coverage:
- Nuclei Templates: All categories
- Subdomain Takeover: subzy, subjack, custom checks
- SSL/TLS: sslscan, testssl.sh, tlsx
- Web Vulnerabilities: XSS, SQLi, CRLF, LFI, Directory Traversal
- API Security: Authentication, CORS, Error Handling
- Secrets Detection: truffleHog, regex patterns, config files

High-Priority Issues:
$(head -20 "${base_dir}/vulnerabilities.txt" 2>/dev/null | grep -E "\[critical\]|\[high\]|TAKEOVER|DANGLING" || echo "None found")

Recommendations:
1. Review and remediate critical and high severity findings immediately
2. Check potential subdomain takeover vulnerabilities
3. Fix SSL/TLS configuration issues
4. Remove or secure exposed configuration files
5. Implement proper API authentication and CORS policies
6. Regular vulnerability scanning should be implemented

Tools Used:
- Nuclei (comprehensive vulnerability scanning)
- Subzy/Subjack (subdomain takeover)
- SSLScan/TestSSL (SSL/TLS analysis)
- Custom scripts (web vulnerabilities)
- TruffleHog (secrets detection)
EOF
    
    log_message "Vulnerability scanning completed"
    log_message "Total findings: $total_vulns | Critical: $critical_count | High: $high_count | Medium: $medium_count"
    
    return 0
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

process_nuclei_results() {
    local nuclei_dir="$1"
    
    if [[ ! -f "${nuclei_dir}/nuclei-all.txt" ]]; then
        return 0
    fi
    
    # Extract findings by severity
    grep "\[critical\]" "${nuclei_dir}/nuclei-all.txt" 2>/dev/null > "${nuclei_dir}/critical-findings.txt" || true
    grep "\[high\]" "${nuclei_dir}/nuclei-all.txt" 2>/dev/null > "${nuclei_dir}/high-findings.txt" || true
    grep "\[medium\]" "${nuclei_dir}/nuclei-all.txt" 2>/dev/null > "${nuclei_dir}/medium-findings.txt" || true
    grep "\[low\]" "${nuclei_dir}/nuclei-all.txt" 2>/dev/null > "${nuclei_dir}/low-findings.txt" || true
    
    # Extract unique vulnerability types
    grep -oE '\[.*\]' "${nuclei_dir}/nuclei-all.txt" 2>/dev/null | \
    sort | uniq -c | sort -nr > "${nuclei_dir}/vulnerability-types.txt" || true
    
    # Extract affected hosts
    awk '{print $1}' "${nuclei_dir}/nuclei-all.txt" 2>/dev/null | \
    sort | uniq -c | sort -nr > "${nuclei_dir}/affected-hosts.txt" || true
}

# =============================================================================
# MAIN VULNERABILITY SCANNING EXECUTION
# =============================================================================

main_vulns() {
    show_module_info "VULNERABILITY SCANNING" "Advanced vulnerability detection and security analysis"
    
    notify_slack "🔍 [${DOMAIN}] Starting vulnerability scanning"
    
    # Initialize
    initialize_vulnerability_scanning || {
        log_error "Failed to initialize vulnerability scanning"
        return 1
    }
    
    # Execute vulnerability scanning steps
    local vuln_steps=(
        "nuclei_vulnerability_scanning"
        "subdomain_takeover_check"
        "ssl_tls_analysis"
        "web_vulnerability_scanning"
        "api_security_testing"
        "secrets_detection"
        "consolidate_vulnerability_results"
    )
    
    local total_steps=${#vuln_steps[@]}
    local current_step=0
    local failed_steps=()
    
    for step in "${vuln_steps[@]}"; do
        ((current_step++))
        
        log_message "[$current_step/$total_steps] Executing: $step"
        
        if ! "$step"; then
            log_warning "Step failed: $step"
            failed_steps+=("$step")
        fi
        
        show_progress "$current_step" "$total_steps" "Vulnerability scanning"
    done
    
    # Report results
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local total_vulns=$(wc -l < "${base_dir}/vulnerabilities.txt" 2>/dev/null || echo "0")
    
    if [[ $total_vulns -gt 0 ]]; then
        log_message "Vulnerability scanning completed successfully"
        log_message "Total findings: $total_vulns"
        
        # Show critical/high severity findings
        local critical_high=$(grep -E "\[critical\]|\[high\]" "${base_dir}/vulnerabilities.txt" 2>/dev/null | wc -l || echo "0")
        if [[ $critical_high -gt 0 ]]; then
            echo -e "\n${RED}Critical/High severity findings:${NC}"
            grep -E "\[critical\]|\[high\]" "${base_dir}/vulnerabilities.txt" 2>/dev/null | head -5 | \
            while read -r finding; do
                echo "  🚨 $finding"
            done
        fi
        
        # Show potential takeovers
        local takeovers="${base_dir}/vulnerabilities/subdomain_takeover/potential-takeovers.txt"
        if [[ -f "$takeovers" && -s "$takeovers" ]]; then
            echo -e "\n${YELLOW}Potential subdomain takeovers:${NC}"
            head -3 "$takeovers" | while read -r takeover; do
                echo "  ⚠️  $takeover"
            done
        fi
    else
        log_message "Vulnerability scanning completed with no major findings"
    fi
    
    # Report failed steps
    if [[ ${#failed_steps[@]} -gt 0 ]]; then
        log_warning "Some steps failed: ${failed_steps[*]}"
    fi
    
    # Final notification
    local critical_count=$(grep -c "\[critical\]" "${base_dir}/vulnerabilities.txt" 2>/dev/null || echo "0")
    local high_count=$(grep -c "\[high\]" "${base_dir}/vulnerabilities.txt" 2>/dev/null || echo "0")
    
    notify_slack "🔍 [${DOMAIN}] Vulnerability scanning completed - Found $total_vulns total findings ($critical_count critical, $high_count high)"
    
    commit_step "Vulnerability Scanning"
    return 0
}

# Execute main vulnerability scanning function
main_vulns
