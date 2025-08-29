#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Active Reconnaissance Module
# Advanced DNS bruteforce and active subdomain discovery
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
# ACTIVE RECONNAISSANCE FUNCTIONS
# =============================================================================

initialize_active_recon() {
    log_message "Initializing active reconnaissance for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local recon_dir="${base_dir}/recon/active"
    
    # Create specialized subdirectories
    local subdirs=(
        "bruteforce"
        "mutations"
        "permutations"
        "dns_resolution"
        "wildcards"
        "zone_transfers"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${recon_dir}/${subdir}" 2>/dev/null
    done
    
    # Check if we have passive results to work with
    if [[ ! -f "${base_dir}/recon/subdomains-passive.txt" ]]; then
        log_warning "No passive results found. Active reconnaissance will be limited."
        log_warning "Consider running passive reconnaissance first for better results."
        
        # Create minimal seed with just the target domain
        echo "$DOMAIN" > "${base_dir}/recon/subdomains-passive.txt"
    fi
    
    return 0
}

wildcard_detection() {
    log_message "Detecting and analyzing wildcards for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local wildcard_dir="${base_dir}/recon/active/wildcards"
    
    # Generate random subdomains for testing
    local test_subdomains=()
    for i in {1..10}; do
        local random_sub=$(openssl rand -hex 8)
        test_subdomains+=("${random_sub}.${DOMAIN}")
    done
    
    # Test for wildcards using dig
    log_info "Testing for wildcard DNS responses"
    local wildcard_ips=()
    
    for test_sub in "${test_subdomains[@]}"; do
        local ip=$(dig +short "$test_sub" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        if [[ -n "$ip" ]]; then
            wildcard_ips+=("$ip")
            echo "$test_sub -> $ip" >> "${wildcard_dir}/wildcard-tests.txt"
        fi
    done
    
    # Analyze wildcard patterns
    if [[ ${#wildcard_ips[@]} -gt 0 ]]; then
        log_warning "Wildcard detected for $DOMAIN"
        printf '%s\n' "${wildcard_ips[@]}" | sort | uniq > "${wildcard_dir}/wildcard-ips.txt"
        
        # Save wildcard configuration
        cat > "${wildcard_dir}/wildcard-config.json" << EOF
{
    "domain": "$DOMAIN",
    "wildcard_detected": true,
    "wildcard_ips": $(printf '%s\n' "${wildcard_ips[@]}" | sort | uniq | jq -R . | jq -s .),
    "test_date": "$(date -Iseconds)",
    "mitigation": "filter_wildcard_ips"
}
EOF
        
        export WILDCARD_DETECTED=true
        export WILDCARD_IPS="${wildcard_dir}/wildcard-ips.txt"
    else
        log_message "No wildcard detected for $DOMAIN"
        echo '{"domain": "'$DOMAIN'", "wildcard_detected": false}' > "${wildcard_dir}/wildcard-config.json"
        export WILDCARD_DETECTED=false
    fi
    
    commit_step "Wildcard Detection"
    return 0
}

dns_bruteforce_puredns() {
    log_message "Running PureDNS bruteforce"
    
    if ! tool_available puredns; then
        log_warning "PureDNS not available, skipping DNS bruteforce"
        return 0
    fi
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local bruteforce_dir="${base_dir}/recon/active/bruteforce"
    
    # Prepare wordlist based on scope type and findings
    local wordlist="${bruteforce_dir}/combined-wordlist.txt"
    prepare_bruteforce_wordlist "$wordlist"
    
    if [[ ! -s "$wordlist" ]]; then
        log_warning "No wordlist available for bruteforce"
        return 0
    fi
    
    local wordlist_size=$(wc -l < "$wordlist")
    log_info "Starting PureDNS with $wordlist_size subdomains"
    
    # Use full wordlist without limits
    log_info "Using full wordlist with $wordlist_size entries (no limit applied)"
    
    # Run PureDNS with appropriate settings
    local puredns_args=()
    puredns_args+=("-r" "${DNS_RESOLVERS}")
    puredns_args+=("--wildcard-tests" "$WILDCARD_TESTS")
    
    if [[ "$WILDCARD_DETECTED" == "true" ]]; then
        puredns_args+=("--wildcard-batch" "25")
        puredns_args+=("--write-wildcards" "${bruteforce_dir}/wildcards-found.txt")
    fi
    
    # Execute PureDNS
    timeout 3600 puredns bruteforce "$wordlist" "$DOMAIN" \
    "${puredns_args[@]}" 2>/dev/null | \
    tee "${bruteforce_dir}/puredns-raw.txt" | \
    filter_wildcard_results > "${bruteforce_dir}/puredns-filtered.txt" || true
    
    # Process results
    if [[ -f "${bruteforce_dir}/puredns-filtered.txt" ]]; then
        local found_count=$(wc -l < "${bruteforce_dir}/puredns-filtered.txt")
        log_message "PureDNS found $found_count subdomains"
        
        # Copy to final results
        cp "${bruteforce_dir}/puredns-filtered.txt" "${base_dir}/recon/puredns-results.txt"
    else
        touch "${base_dir}/recon/puredns-results.txt"
    fi
    
    # No cleanup needed - using original wordlist
    
    commit_step "PureDNS Bruteforce"
    return 0
}

dns_bruteforce_shuffledns() {
    log_message "Running ShuffleDNS bruteforce"
    
    if ! tool_available shuffledns; then
        log_warning "ShuffleDNS not available, skipping"
        return 0
    fi
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local bruteforce_dir="${base_dir}/recon/active/bruteforce"
    
    # Use same wordlist as PureDNS
    local wordlist="${bruteforce_dir}/combined-wordlist.txt"
    if [[ ! -s "$wordlist" ]]; then
        prepare_bruteforce_wordlist "$wordlist"
    fi
    
    if [[ ! -s "$wordlist" ]]; then
        log_warning "No wordlist available for ShuffleDNS"
        return 0
    fi
    
    # Use full wordlist without limits
    local wordlist_size=$(wc -l < "$wordlist")
    log_info "Running ShuffleDNS with $wordlist_size subdomains (no limit applied)"
    
    # Run ShuffleDNS
    timeout 1800 shuffledns -silent -d "$DOMAIN" \
    -r "${DNS_RESOLVERS}" \
    -w "$wordlist" \
    -mode bruteforce \
    -o "${bruteforce_dir}/shuffledns-raw.txt" 2>/dev/null || true
    
    # Filter results
    if [[ -f "${bruteforce_dir}/shuffledns-raw.txt" ]]; then
        filter_wildcard_results < "${bruteforce_dir}/shuffledns-raw.txt" > \
        "${bruteforce_dir}/shuffledns-filtered.txt"
        
        local found_count=$(wc -l < "${bruteforce_dir}/shuffledns-filtered.txt" 2>/dev/null || echo "0")
        log_message "ShuffleDNS found $found_count subdomains"
        
        # Copy to final results
        cp "${bruteforce_dir}/shuffledns-filtered.txt" "${base_dir}/recon/shuffledns-results.txt"
    else
        touch "${base_dir}/recon/shuffledns-results.txt"
    fi
    
    # No cleanup needed - using original wordlist
    
    commit_step "ShuffleDNS Bruteforce"
    return 0
}

subdomain_mutations() {
    log_message "Running subdomain mutations"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local mutation_dir="${base_dir}/recon/active/mutations"
    
    # Check if we have passive results for mutations
    if [[ ! -s "${base_dir}/recon/subdomains-passive.txt" ]]; then
        log_warning "No passive results for mutations"
        return 0
    fi
    
    # DNSGen mutations
    if tool_available dnsgen; then
        log_info "Generating mutations with DNSGen"
        
        cat "${base_dir}/recon/subdomains-passive.txt" | \
        head -1000 | \
        dnsgen - | \
        head -"$PERMUTATION_LIMIT" > "${mutation_dir}/dnsgen-mutations.txt" 2>/dev/null || true
        
        # Resolve mutations
        if [[ -s "${mutation_dir}/dnsgen-mutations.txt" ]] && tool_available puredns; then
            log_info "Resolving DNSGen mutations"
            puredns resolve "${mutation_dir}/dnsgen-mutations.txt" \
            -r "${DNS_RESOLVERS}" --skip-sanitize 2>/dev/null | \
            filter_wildcard_results > "${mutation_dir}/dnsgen-resolved.txt" || true
        fi
    fi
    
    # AltDNS mutations
    if tool_available altdns; then
        log_info "Generating mutations with AltDNS"
        
        # Create mutations wordlist
        local altdns_words="${mutation_dir}/altdns-words.txt"
        cat > "$altdns_words" << 'EOF'
admin
api
app
dev
test
stage
prod
new
old
backup
temp
beta
alpha
demo
sandbox
qa
uat
staging
development
production
www1
www2
mail1
mail2
cdn
img
static
assets
files
media
mobile
m
portal
dashboard
panel
secure
vpn
support
help
docs
blog
shop
store
news
forum
chat
wiki
internal
external
private
public
guest
partner
vendor
client
customer
legacy
v1
v2
v3
edge
gateway
proxy
load
balance
cluster
node
service
microservice
EOF
        
        # Generate mutations
        altdns -i "${base_dir}/recon/subdomains-passive.txt" \
        -w "$altdns_words" \
        -o "${mutation_dir}/altdns-mutations.txt" 2>/dev/null || true
        
        # Resolve mutations (limit to avoid overwhelming)
        if [[ -s "${mutation_dir}/altdns-mutations.txt" ]] && tool_available puredns; then
            log_info "Resolving AltDNS mutations"
            head -10000 "${mutation_dir}/altdns-mutations.txt" | \
            puredns resolve - -r "${DNS_RESOLVERS}" 2>/dev/null | \
            filter_wildcard_results > "${mutation_dir}/altdns-resolved.txt" || true
        fi
    fi
    
    # Custom permutations based on discovered patterns
    generate_custom_mutations "${base_dir}/recon/subdomains-passive.txt" \
    "${mutation_dir}/custom-mutations.txt"
    
    # Resolve custom mutations
    if [[ -s "${mutation_dir}/custom-mutations.txt" ]] && tool_available puredns; then
        log_info "Resolving custom mutations"
        puredns resolve "${mutation_dir}/custom-mutations.txt" \
        -r "${DNS_RESOLVERS}" 2>/dev/null | \
        filter_wildcard_results > "${mutation_dir}/custom-resolved.txt" || true
    fi
    
    # Combine all mutation results
    cat "${mutation_dir}"/*-resolved.txt 2>/dev/null | \
    sort -u > "${base_dir}/recon/mutations-results.txt"
    
    local mutations_count=$(wc -l < "${base_dir}/recon/mutations-results.txt" 2>/dev/null || echo "0")
    log_message "Subdomain mutations: $mutations_count new subdomains found"
    
    commit_step "Subdomain Mutations"
    return 0
}

zone_transfer_attempts() {
    log_message "Attempting DNS zone transfers"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local zt_dir="${base_dir}/recon/active/zone_transfers"
    
    # Get name servers for the domain
    local nameservers=()
    mapfile -t nameservers < <(dig +short NS "$DOMAIN" 2>/dev/null | grep -v '^$')
    
    if [[ ${#nameservers[@]} -eq 0 ]]; then
        log_info "No name servers found for $DOMAIN"
        return 0
    fi
    
    log_info "Testing zone transfers against ${#nameservers[@]} name servers"
    
    # Test each name server
    for ns in "${nameservers[@]}"; do
        log_info "Testing zone transfer from $ns"
        
        # Remove trailing dot if present
        ns="${ns%.}"
        
        # Attempt AXFR
        dig @"$ns" "$DOMAIN" AXFR 2>/dev/null | \
        grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | \
        awk '{print $1}' | \
        sed 's/\.$//' | \
        grep -E "\.${DOMAIN}$|^${DOMAIN}$" > "${zt_dir}/axfr-${ns}.txt" || true
        
        # Check if we got results
        if [[ -s "${zt_dir}/axfr-${ns}.txt" ]]; then
            local transfer_count=$(wc -l < "${zt_dir}/axfr-${ns}.txt")
            log_warning "Zone transfer successful from $ns: $transfer_count records"
        else
            log_info "Zone transfer denied by $ns"
        fi
    done
    
    # Combine zone transfer results
    cat "${zt_dir}"/axfr-*.txt 2>/dev/null | \
    sort -u > "${base_dir}/recon/zone-transfer-results.txt"
    
    local zt_count=$(wc -l < "${base_dir}/recon/zone-transfer-results.txt" 2>/dev/null || echo "0")
    if [[ $zt_count -gt 0 ]]; then
        log_warning "Zone transfers found $zt_count subdomains"
    else
        log_message "No zone transfers successful"
    fi
    
    commit_step "Zone Transfer Attempts"
    return 0
}

dns_resolution_validation() {
    log_message "Validating DNS resolution for discovered subdomains"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local resolution_dir="${base_dir}/recon/active/dns_resolution"
    
    # Combine all active results so far
    local active_sources=(
        "${base_dir}/recon/puredns-results.txt"
        "${base_dir}/recon/shuffledns-results.txt"
        "${base_dir}/recon/mutations-results.txt"
        "${base_dir}/recon/zone-transfer-results.txt"
    )
    
    log_info "Combining active results from: ${active_sources[*]}"
    cat "${active_sources[@]}" 2>/dev/null | \
    sort -u > "${resolution_dir}/all-active-subdomains.txt"
    
    if [[ ! -s "${resolution_dir}/all-active-subdomains.txt" ]]; then
        log_info "No active subdomains to validate"
        touch "${base_dir}/recon/subdomains-active.txt"
        return 0
    fi
    
    local total_subs=$(wc -l < "${resolution_dir}/all-active-subdomains.txt")
    log_info "Validating DNS resolution for $total_subs subdomains"
    
    # Use dnsx for validation if available
    if tool_available dnsx; then
        log_info "Using dnsx for DNS validation with threads: ${DNS_THREADS:-1000}, retries: ${DNS_RETRIES:-3}"
        
        dnsx -l "${resolution_dir}/all-active-subdomains.txt" \
        -t "${DNS_THREADS:-1000}" \
        -retry "${DNS_RETRIES:-3}" -nc -silent \
        -o "${resolution_dir}/validated-subdomains.txt" 2>/dev/null || {
            log_warning "dnsx failed, using fallback validation"
            # Fallback to basic dig validation
            while IFS= read -r subdomain; do
                if dig +short "$subdomain" 2>/dev/null | grep -E '^[0-9]+\.' >/dev/null; then
                    echo "$subdomain" >> "${resolution_dir}/validated-subdomains.txt"
                fi
            done < "${resolution_dir}/all-active-subdomains.txt"
        }
    else
        log_info "dnsx not available, using dig fallback"
        # Fallback to basic dig validation
        while IFS= read -r subdomain; do
            if dig +short "$subdomain" 2>/dev/null | grep -E '^[0-9]+\.' >/dev/null; then
                echo "$subdomain" >> "${resolution_dir}/validated-subdomains.txt"
            fi
        done < "${resolution_dir}/all-active-subdomains.txt"
    fi
    
    # Check if validation produced results
    if [[ -s "${resolution_dir}/validated-subdomains.txt" ]]; then
        local validated_subs=$(wc -l < "${resolution_dir}/validated-subdomains.txt")
        log_info "DNS validation found $validated_subs live subdomains"
        
        # Apply wildcard filtering
        if [[ "$WILDCARD_DETECTED" == "true" ]]; then
            log_info "Applying wildcard filtering"
            filter_wildcard_results < "${resolution_dir}/validated-subdomains.txt" > \
            "${resolution_dir}/validated-filtered.txt"
            
            # Final active results
            cp "${resolution_dir}/validated-filtered.txt" \
               "${base_dir}/recon/subdomains-active.txt"
        else
            # No wildcard filtering needed
            cp "${resolution_dir}/validated-subdomains.txt" \
               "${base_dir}/recon/subdomains-active.txt"
        fi
    else
        log_warning "No subdomains passed DNS validation"
        touch "${base_dir}/recon/subdomains-active.txt"
    fi
    
    local final_count=$(wc -l < "${base_dir}/recon/subdomains-active.txt" 2>/dev/null || echo "0")
    log_message "DNS resolution validation completed: $final_count live subdomains confirmed"
    
    commit_step "DNS Resolution Validation"
    return 0
}

consolidate_active_results() {
    log_message "Consolidating active reconnaissance results"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    
    # Combine passive and active results
    local all_sources=(
        "${base_dir}/recon/subdomains-passive.txt"
        "${base_dir}/recon/subdomains-active.txt"
    )
    
    cat "${all_sources[@]}" 2>/dev/null | \
    sort -u > "${base_dir}/recon/subdomains-all.txt"
    
    # Generate comprehensive statistics
    local passive_count=$(wc -l < "${base_dir}/recon/subdomains-passive.txt" 2>/dev/null || echo "0")
    local active_count=$(wc -l < "${base_dir}/recon/subdomains-active.txt" 2>/dev/null || echo "0")
    local total_count=$(wc -l < "${base_dir}/recon/subdomains-all.txt" 2>/dev/null || echo "0")
    
    # Update wordlists with new findings
    if [[ $active_count -gt 0 ]]; then
        cat "${base_dir}/recon/subdomains-active.txt" | \
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
    
    # Create comprehensive summary
    cat > "${base_dir}/recon/active-summary.txt" << EOF
ACTIVE RECONNAISSANCE SUMMARY
=============================

Domain: $DOMAIN
Passive Subdomains: $passive_count
Active Subdomains: $active_count
Total Unique Subdomains: $total_count
Date: $(date)

Scope Type: ${SCOPE_TYPE:-auto}
Wildcard Detected: ${WILDCARD_DETECTED:-false}

Active Techniques Used:
- DNS Bruteforce (PureDNS/ShuffleDNS)
- Subdomain Mutations (DNSGen/AltDNS)
- Zone Transfer Attempts
- DNS Resolution Validation

New Subdomains from Active Recon:
$(comm -23 <(sort "${base_dir}/recon/subdomains-active.txt" 2>/dev/null || echo "") \
           <(sort "${base_dir}/recon/subdomains-passive.txt" 2>/dev/null || echo "") | head -20)

Top 20 All Subdomains:
$(head -20 "${base_dir}/recon/subdomains-all.txt" 2>/dev/null || echo "None found")
EOF
    
    log_message "Active reconnaissance completed"
    log_message "Passive: $passive_count | Active: $active_count | Total: $total_count"
    
    return 0
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

prepare_bruteforce_wordlist() {
    local output_wordlist="$1"
    
    # Use only the specified wordlist source
    local wordlist_source="${DIR_NINA_LISTS}/wordlist-gpxlnx-subs.txt"
    
    # Check if wordlist exists
    if [[ ! -f "$wordlist_source" ]]; then
        log_error "Wordlist not found: $wordlist_source"
        return 1
    fi
    
    # Start with base wordlist (no limit)
    cat "$wordlist_source" 2>/dev/null | \
    grep -v '^$' | \
    sort -u > "$output_wordlist.tmp"
    
    # Final processing - no limit applied
    sort -u "$output_wordlist.tmp" | \
    grep -E '^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$' > "$output_wordlist"
    
    rm -f "$output_wordlist.tmp"
    
    local final_size=$(wc -l < "$output_wordlist" 2>/dev/null || echo "0")
    log_info "Prepared bruteforce wordlist with $final_size entries"
}

filter_wildcard_results() {
    if [[ "$WILDCARD_DETECTED" != "true" ]] || [[ ! -f "$WILDCARD_IPS" ]]; then
        # No filtering needed
        cat
        return 0
    fi
    
    # Filter out wildcard IPs
    while IFS= read -r subdomain; do
        # Resolve the subdomain
        local ip=$(dig +short "$subdomain" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        
        # Check if IP is in wildcard list
        if [[ -n "$ip" ]] && ! grep -Fxq "$ip" "$WILDCARD_IPS" 2>/dev/null; then
            echo "$subdomain"
        fi
    done
}

generate_custom_mutations() {
    local input_file="$1"
    local output_file="$2"
    
    if [[ ! -f "$input_file" ]]; then
        touch "$output_file"
        return 0
    fi
    
    # Extract common patterns from existing subdomains
    local patterns=()
    
    # Get first parts of subdomains
    while IFS= read -r subdomain; do
        local first_part=$(echo "$subdomain" | cut -d'.' -f1)
        [[ ${#first_part} -gt 2 ]] && patterns+=("$first_part")
    done < "$input_file"
    
    # Generate mutations with common prefixes/suffixes
    local prefixes=("new-" "old-" "dev-" "test-" "stage-" "prod-" "beta-" "alpha-")
    local suffixes=("-new" "-old" "-dev" "-test" "-stage" "-prod" "-beta" "-alpha" "1" "2" "3")
    
    : > "$output_file"  # Clear output file
    
    # Limit to avoid too many permutations
    printf '%s\n' "${patterns[@]}" | sort -u | head -20 | while IFS= read -r pattern; do
        # Add prefixes
        for prefix in "${prefixes[@]}"; do
            echo "${prefix}${pattern}.${DOMAIN}" >> "$output_file"
        done
        
        # Add suffixes
        for suffix in "${suffixes[@]}"; do
            echo "${pattern}${suffix}.${DOMAIN}" >> "$output_file"
        done
    done
    
    # Limit total mutations
    sort -u "$output_file" | head -"$PERMUTATION_LIMIT" > "$output_file.tmp"
    mv "$output_file.tmp" "$output_file"
}

# =============================================================================
# MAIN ACTIVE RECONNAISSANCE EXECUTION
# =============================================================================

main_active() {
    show_module_info "ACTIVE RECONNAISSANCE" "Advanced DNS bruteforce and active subdomain discovery"
    
    notify_progress "$DOMAIN" "Active Recon" "Starting active reconnaissance with DNS bruteforce"
    
    # Initialize
    initialize_active_recon || {
        log_error "Failed to initialize active reconnaissance"
        return 1
    }
    
    # Execute active reconnaissance steps
    local recon_steps=(
        "wildcard_detection"
        "dns_bruteforce_puredns"
        "dns_bruteforce_shuffledns"
        "subdomain_mutations"
        "zone_transfer_attempts"
        "dns_resolution_validation"
        "consolidate_active_results"
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
        
        show_progress "$current_step" "$total_steps" "Active reconnaissance"
    done
    
    # Report results
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local active_found=$(wc -l < "${base_dir}/recon/subdomains-active.txt" 2>/dev/null || echo "0")
    local total_found=$(wc -l < "${base_dir}/recon/subdomains-all.txt" 2>/dev/null || echo "0")
    
    if [[ $active_found -gt 0 ]]; then
        log_message "Active reconnaissance completed successfully"
        log_message "New subdomains from active recon: $active_found"
        log_message "Total subdomains: $total_found"
        
        # Show sample new results
        echo -e "\n${YELLOW}New subdomains from active reconnaissance:${NC}"
        comm -23 <(sort "${base_dir}/recon/subdomains-active.txt" 2>/dev/null || echo "") \
                 <(sort "${base_dir}/recon/subdomains-passive.txt" 2>/dev/null || echo "") | \
        head -10 | while read -r subdomain; do
            echo "  • $subdomain"
        done
    else
        log_message "Active reconnaissance completed with no new subdomains found"
    fi
    
    # Report failed steps
    if [[ ${#failed_steps[@]} -gt 0 ]]; then
        log_warning "Some steps failed: ${failed_steps[*]}"
    fi
    
    # Final notification
    notify_module_complete "$DOMAIN" "Active Recon" "$active_found new subdomains found (Total: $total_found)"
    
    commit_step "Active Reconnaissance"
    return 0
}

# Execute main active reconnaissance function
main_active
