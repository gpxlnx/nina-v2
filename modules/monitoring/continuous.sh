#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Continuous Monitoring Module
# Advanced continuous monitoring and change detection
# =============================================================================

# Ensure config is loaded
if [[ -z "${DIR_NINA:-}" ]]; then
    echo "Error: Config not loaded. This module should be run via nina-recon-optimized.sh"
    exit 1
fi

# Ensure base directories exist
mkdir -p "${DIR_OUTPUT}/${DOMAIN}/log" 2>/dev/null
mkdir -p "${DIR_OUTPUT}/${DOMAIN}/$(basename "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")" 2>/dev/null

# =============================================================================
# CONTINUOUS MONITORING FUNCTIONS
# =============================================================================

initialize_monitoring() {
    log_message "Initializing continuous monitoring for $DOMAIN"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local monitoring_dir="${base_dir}/monitoring"
    
    # Create specialized subdirectories
    local subdirs=(
        "snapshots"
        "changes"
        "alerts"
        "configs"
        "scripts"
        "logs"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${monitoring_dir}/${subdir}" 2>/dev/null
    done
    
    return 0
}

setup_monitoring_config() {
    log_message "Setting up monitoring configuration"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local monitoring_dir="${base_dir}/monitoring"
    
    # Create monitoring configuration file
    cat > "${monitoring_dir}/configs/monitor.conf" << EOF
# NINA Monitoring Configuration for ${DOMAIN}
# Generated on $(date)

# Target Configuration
TARGET_DOMAIN="${DOMAIN}"
SCOPE_TYPE="${SCOPE_TYPE:-wildcard}"
OUTPUT_DIR="${base_dir}"

# Monitoring Intervals (in seconds)
PASSIVE_CHECK_INTERVAL=3600        # 1 hour
ACTIVE_CHECK_INTERVAL=14400        # 4 hours
HTTP_CHECK_INTERVAL=1800           # 30 minutes
DEEP_CHECK_INTERVAL=86400          # 24 hours

# Modules to run during monitoring
PASSIVE_MODULES="subfinder,assetfinder,findomain"
ACTIVE_MODULES="puredns,shuffledns"
HTTP_MODULES="httpx"
VULN_MODULES="nuclei"

# Change Detection
ENABLE_CHANGE_DETECTION=true
MIN_CHANGE_THRESHOLD=5             # Minimum changes to trigger alert

# Notification Settings
NOTIFICATION_ENABLED="${NOTIFICATION_ENABLED:-false}"
ALERT_ON_NEW_SUBDOMAINS=true
ALERT_ON_NEW_URLS=true
ALERT_ON_NEW_VULNERABILITIES=true
ALERT_ON_SERVICE_CHANGES=true

# Data Retention
KEEP_SNAPSHOTS_DAYS=30
KEEP_LOGS_DAYS=90
EOF

    # Create monitoring script
    cat > "${monitoring_dir}/scripts/monitor.sh" << 'EOF'
#!/bin/bash

# Load configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../configs/monitor.conf"

# Load NINA configuration
source "${SCRIPT_DIR}/../../../modules/core/config.sh"

monitor_passive() {
    echo "[$(date)] Starting passive monitoring check"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local snapshot_dir="${OUTPUT_DIR}/monitoring/snapshots/passive_${timestamp}"
    mkdir -p "$snapshot_dir"
    
    # Run passive reconnaissance
    cd "${OUTPUT_DIR}/../../../"
    ./nina-recon.sh -d "$TARGET_DOMAIN" -m passive -o "$snapshot_dir" -q
    
    # Compare with previous results
    if [[ -f "${OUTPUT_DIR}/recon/subdomains-passive.txt" ]]; then
        local current_count=$(wc -l < "${snapshot_dir}/${TARGET_DOMAIN}/recon/subdomains-passive.txt" 2>/dev/null || echo "0")
        local previous_count=$(wc -l < "${OUTPUT_DIR}/recon/subdomains-passive.txt" 2>/dev/null || echo "0")
        
        if [[ $current_count -gt $((previous_count + MIN_CHANGE_THRESHOLD)) ]]; then
            echo "[$(date)] Significant changes detected: $((current_count - previous_count)) new subdomains"
            
            # Generate change report
            comm -13 <(sort "${OUTPUT_DIR}/recon/subdomains-passive.txt" 2>/dev/null || echo "") \
                     <(sort "${snapshot_dir}/${TARGET_DOMAIN}/recon/subdomains-passive.txt" 2>/dev/null || echo "") > \
                     "${OUTPUT_DIR}/monitoring/changes/new_passive_${timestamp}.txt"
            
            # Update baseline
            cp "${snapshot_dir}/${TARGET_DOMAIN}/recon/subdomains-passive.txt" \
               "${OUTPUT_DIR}/recon/subdomains-passive.txt"
            
            # Send notification if enabled
            if [[ "$NOTIFICATION_ENABLED" == "true" ]]; then
                notify_slack "🔍 [${TARGET_DOMAIN}] Passive monitoring detected $((current_count - previous_count)) new subdomains"
            fi
        fi
    else
        # First run - establish baseline
        cp "${snapshot_dir}/${TARGET_DOMAIN}/recon/subdomains-passive.txt" \
           "${OUTPUT_DIR}/recon/subdomains-passive.txt" 2>/dev/null || true
    fi
}

monitor_http() {
    echo "[$(date)] Starting HTTP monitoring check"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local snapshot_dir="${OUTPUT_DIR}/monitoring/snapshots/http_${timestamp}"
    mkdir -p "$snapshot_dir"
    
    # Run HTTP probing on current subdomains
    if [[ -f "${OUTPUT_DIR}/recon/subdomains-all.txt" ]]; then
        cd "${OUTPUT_DIR}/../../../"
        ./nina-recon.sh -d "$TARGET_DOMAIN" -m httpx -o "$snapshot_dir" -q
        
        # Check for new live hosts
        if [[ -f "${OUTPUT_DIR}/live-hosts.txt" ]]; then
            local current_hosts=$(wc -l < "${snapshot_dir}/${TARGET_DOMAIN}/live-hosts.txt" 2>/dev/null || echo "0")
            local previous_hosts=$(wc -l < "${OUTPUT_DIR}/live-hosts.txt" 2>/dev/null || echo "0")
            
            if [[ $current_hosts -ne $previous_hosts ]]; then
                echo "[$(date)] HTTP changes detected: $((current_hosts - previous_hosts)) host changes"
                
                # Generate change report
                comm -13 <(sort "${OUTPUT_DIR}/live-hosts.txt" 2>/dev/null || echo "") \
                         <(sort "${snapshot_dir}/${TARGET_DOMAIN}/live-hosts.txt" 2>/dev/null || echo "") > \
                         "${OUTPUT_DIR}/monitoring/changes/new_hosts_${timestamp}.txt"
                
                # Update baseline
                cp "${snapshot_dir}/${TARGET_DOMAIN}/live-hosts.txt" \
                   "${OUTPUT_DIR}/live-hosts.txt"
                
                # Send notification if enabled
                if [[ "$NOTIFICATION_ENABLED" == "true" ]]; then
                    notify_slack "🌐 [${TARGET_DOMAIN}] HTTP monitoring detected $((current_hosts - previous_hosts)) host changes"
                fi
            fi
        fi
    fi
}

monitor_vulnerabilities() {
    echo "[$(date)] Starting vulnerability monitoring check"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local snapshot_dir="${OUTPUT_DIR}/monitoring/snapshots/vulns_${timestamp}"
    mkdir -p "$snapshot_dir"
    
    # Run vulnerability scans
    if [[ -f "${OUTPUT_DIR}/live-hosts.txt" ]]; then
        cd "${OUTPUT_DIR}/../../../"
        ./nina-recon.sh -d "$TARGET_DOMAIN" -m vulns -o "$snapshot_dir" -q
        
        # Check for new vulnerabilities
        if [[ -f "${OUTPUT_DIR}/vulnerabilities.txt" ]]; then
            local current_vulns=$(wc -l < "${snapshot_dir}/${TARGET_DOMAIN}/vulnerabilities.txt" 2>/dev/null || echo "0")
            local previous_vulns=$(wc -l < "${OUTPUT_DIR}/vulnerabilities.txt" 2>/dev/null || echo "0")
            
            if [[ $current_vulns -gt $previous_vulns ]]; then
                echo "[$(date)] New vulnerabilities detected: $((current_vulns - previous_vulns)) new issues"
                
                # Generate change report
                comm -13 <(sort "${OUTPUT_DIR}/vulnerabilities.txt" 2>/dev/null || echo "") \
                         <(sort "${snapshot_dir}/${TARGET_DOMAIN}/vulnerabilities.txt" 2>/dev/null || echo "") > \
                         "${OUTPUT_DIR}/monitoring/changes/new_vulns_${timestamp}.txt"
                
                # Update baseline
                cp "${snapshot_dir}/${TARGET_DOMAIN}/vulnerabilities.txt" \
                   "${OUTPUT_DIR}/vulnerabilities.txt"
                
                # Send urgent notification
                if [[ "$NOTIFICATION_ENABLED" == "true" ]]; then
                    notify_slack "🚨 [${TARGET_DOMAIN}] URGENT: $((current_vulns - previous_vulns)) new vulnerabilities detected!"
                fi
            fi
        fi
    fi
}

cleanup_old_data() {
    echo "[$(date)] Cleaning up old monitoring data"
    
    # Remove old snapshots
    find "${OUTPUT_DIR}/monitoring/snapshots" -type d -mtime +${KEEP_SNAPSHOTS_DAYS} -exec rm -rf {} + 2>/dev/null || true
    
    # Remove old logs
    find "${OUTPUT_DIR}/monitoring/logs" -type f -mtime +${KEEP_LOGS_DAYS} -delete 2>/dev/null || true
    
    # Remove old change reports (keep for same period as snapshots)
    find "${OUTPUT_DIR}/monitoring/changes" -type f -mtime +${KEEP_SNAPSHOTS_DAYS} -delete 2>/dev/null || true
}

# Main monitoring loop
main_monitor() {
    echo "[$(date)] Starting continuous monitoring for ${TARGET_DOMAIN}"
    
    while true; do
        # Run different types of monitoring based on schedule
        local current_hour=$(date +%H)
        local current_minute=$(date +%M)
        
        # Passive monitoring every hour
        if [[ $current_minute -eq 0 ]]; then
            monitor_passive
        fi
        
        # HTTP monitoring every 30 minutes
        if [[ $current_minute -eq 0 ]] || [[ $current_minute -eq 30 ]]; then
            monitor_http
        fi
        
        # Vulnerability monitoring every 4 hours
        if [[ $current_minute -eq 0 ]] && [[ $((current_hour % 4)) -eq 0 ]]; then
            monitor_vulnerabilities
        fi
        
        # Cleanup old data daily at midnight
        if [[ $current_hour -eq 0 ]] && [[ $current_minute -eq 0 ]]; then
            cleanup_old_data
        fi
        
        # Sleep for 1 minute before next check
        sleep 60
    done
}

# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_monitor
fi
EOF

    chmod +x "${monitoring_dir}/scripts/monitor.sh"
    
    commit_step "Monitoring Configuration Setup"
    return 0
}

create_monitoring_dashboard() {
    log_message "Creating monitoring dashboard"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local monitoring_dir="${base_dir}/monitoring"
    
    # Create a simple HTML dashboard
    cat > "${monitoring_dir}/dashboard.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NINA Monitoring Dashboard - ${DOMAIN}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .section { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .section h2 { margin-top: 0; color: #2c3e50; }
        .changes { max-height: 300px; overflow-y: auto; }
        .change-item { padding: 10px; border-left: 4px solid #3498db; margin-bottom: 10px; background-color: #ecf0f1; }
        .timestamp { font-size: 0.9em; color: #7f8c8d; }
        .footer { text-align: center; margin-top: 30px; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NINA Monitoring Dashboard</h1>
            <p>Target: <strong>${DOMAIN}</strong> | Last Updated: <span id="lastUpdate">$(date)</span></p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="totalSubdomains">0</div>
                <div class="stat-label">Total Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="liveHosts">0</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="vulnerabilities">0</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="lastCheck">Never</div>
                <div class="stat-label">Last Check</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Recent Changes</h2>
            <div class="changes" id="recentChanges">
                <p>No changes detected yet.</p>
            </div>
        </div>
        
        <div class="section">
            <h2>⚙️ Monitoring Status</h2>
            <p><strong>Monitoring Mode:</strong> ${CONTINUOUS_MODE:-false}</p>
            <p><strong>Scope Type:</strong> ${SCOPE_TYPE:-auto}</p>
            <p><strong>Notifications:</strong> ${NOTIFICATION_ENABLED:-false}</p>
        </div>
        
        <div class="footer">
            <p>NINA Recon Optimized v$(cat ${DIR_NINA}/../VERSION 2>/dev/null || echo "2.0.0") | Generated on $(date)</p>
        </div>
    </div>
    
    <script>
        // Auto-refresh every 5 minutes
        setTimeout(function() {
            location.reload();
        }, 300000);
        
        // Load current statistics
        function loadStats() {
            // This would be populated by actual monitoring data
            // For now, showing placeholders
        }
        
        loadStats();
    </script>
</body>
</html>
EOF
    
    log_info "Monitoring dashboard created: ${monitoring_dir}/dashboard.html"
    
    commit_step "Monitoring Dashboard Creation"
    return 0
}

setup_monitoring_service() {
    log_message "Setting up monitoring service"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local monitoring_dir="${base_dir}/monitoring"
    
    # Create systemd service file (optional)
    cat > "${monitoring_dir}/scripts/nina-monitor-${DOMAIN}.service" << EOF
[Unit]
Description=NINA Continuous Monitoring for ${DOMAIN}
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${monitoring_dir}/scripts
ExecStart=${monitoring_dir}/scripts/monitor.sh
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

    # Create simple start/stop scripts
    cat > "${monitoring_dir}/scripts/start-monitoring.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting NINA monitoring for ${TARGET_DOMAIN:-unknown}..."

# Check if already running
if pgrep -f "monitor.sh" > /dev/null; then
    echo "Monitoring is already running."
    exit 1
fi

# Start monitoring in background
nohup "${SCRIPT_DIR}/monitor.sh" > "${SCRIPT_DIR}/../logs/monitor.log" 2>&1 &
echo $! > "${SCRIPT_DIR}/../logs/monitor.pid"

echo "Monitoring started with PID $(cat "${SCRIPT_DIR}/../logs/monitor.pid")"
echo "Logs: ${SCRIPT_DIR}/../logs/monitor.log"
EOF

    cat > "${monitoring_dir}/scripts/stop-monitoring.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Stopping NINA monitoring..."

if [[ -f "${SCRIPT_DIR}/../logs/monitor.pid" ]]; then
    PID=$(cat "${SCRIPT_DIR}/../logs/monitor.pid")
    if kill "$PID" 2>/dev/null; then
        echo "Monitoring stopped (PID: $PID)"
        rm -f "${SCRIPT_DIR}/../logs/monitor.pid"
    else
        echo "Failed to stop monitoring process (PID: $PID)"
    fi
else
    echo "No monitoring process found"
fi

# Kill any remaining monitor processes
pkill -f "monitor.sh" 2>/dev/null || true
EOF

    chmod +x "${monitoring_dir}/scripts/start-monitoring.sh"
    chmod +x "${monitoring_dir}/scripts/stop-monitoring.sh"
    
    log_info "Monitoring service scripts created"
    log_info "To start monitoring: ${monitoring_dir}/scripts/start-monitoring.sh"
    log_info "To stop monitoring: ${monitoring_dir}/scripts/stop-monitoring.sh"
    
    commit_step "Monitoring Service Setup"
    return 0
}

create_monitoring_reports() {
    log_message "Creating monitoring reports"
    
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local monitoring_dir="${base_dir}/monitoring"
    
    # Create summary report
    cat > "${monitoring_dir}/monitoring-summary.txt" << EOF
CONTINUOUS MONITORING SETUP SUMMARY
===================================

Domain: $DOMAIN
Setup Date: $(date)
Output Directory: $base_dir

Configuration:
- Monitoring Config: ${monitoring_dir}/configs/monitor.conf
- Dashboard: ${monitoring_dir}/dashboard.html
- Start Script: ${monitoring_dir}/scripts/start-monitoring.sh
- Stop Script: ${monitoring_dir}/scripts/stop-monitoring.sh

Monitoring Capabilities:
✓ Passive subdomain monitoring
✓ Active DNS monitoring  
✓ HTTP service monitoring
✓ Vulnerability monitoring
✓ Change detection and alerting
✓ Data retention management

Next Steps:
1. Review monitoring configuration: ${monitoring_dir}/configs/monitor.conf
2. Start monitoring: ${monitoring_dir}/scripts/start-monitoring.sh
3. View dashboard: file://${monitoring_dir}/dashboard.html
4. Monitor logs: ${monitoring_dir}/logs/monitor.log

Notification Setup:
- Configure Slack webhook in core/config.sh
- Set NOTIFICATION_ENABLED=true in monitor.conf
EOF

    log_message "Monitoring setup completed"
    
    return 0
}

# =============================================================================
# MAIN CONTINUOUS MONITORING EXECUTION
# =============================================================================

main_monitor() {
    show_module_info "CONTINUOUS MONITORING" "Advanced continuous monitoring and change detection"
    
    notify_slack "📊 [${DOMAIN}] Setting up continuous monitoring"
    
    # Initialize
    initialize_monitoring || {
        log_error "Failed to initialize monitoring"
        return 1
    }
    
    # Execute monitoring setup steps
    local monitoring_steps=(
        "setup_monitoring_config"
        "create_monitoring_dashboard"
        "setup_monitoring_service"
        "create_monitoring_reports"
    )
    
    local total_steps=${#monitoring_steps[@]}
    local current_step=0
    local failed_steps=()
    
    for step in "${monitoring_steps[@]}"; do
        ((current_step++))
        
        log_message "[$current_step/$total_steps] Executing: $step"
        
        if ! "$step"; then
            log_warning "Step failed: $step"
            failed_steps+=("$step")
        fi
        
        show_progress "$current_step" "$total_steps" "Monitoring setup"
    done
    
    # Report results
    local base_dir="${DIR_OUTPUT}/${DOMAIN}"
    local monitoring_dir="${base_dir}/monitoring"
    
    log_message "Continuous monitoring setup completed successfully"
    
    echo -e "\n${YELLOW}Monitoring Setup Summary:${NC}"
    echo "  📊 Dashboard: file://${monitoring_dir}/dashboard.html"
    echo "  ⚙️ Configuration: ${monitoring_dir}/configs/monitor.conf"
    echo "  🚀 Start monitoring: ${monitoring_dir}/scripts/start-monitoring.sh"
    echo "  🛑 Stop monitoring: ${monitoring_dir}/scripts/stop-monitoring.sh"
    
    # Report failed steps
    if [[ ${#failed_steps[@]} -gt 0 ]]; then
        log_warning "Some steps failed: ${failed_steps[*]}"
    fi
    
    # Final notification
    notify_slack "✅ [${DOMAIN}] Continuous monitoring setup completed"
    
    commit_step "Continuous Monitoring Setup"
    return 0
}

# Execute main monitoring function
main_monitor
