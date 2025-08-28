#!/bin/bash

# =============================================================================
# NINA-v2 Notification Setup Script
# =============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if notify is installed
check_notify_installation() {
    log_info "Checking notify installation..."
    
    if command -v notify >/dev/null 2>&1; then
        log_info "✅ notify tool is already installed"
        notify -version
    else
        log_warning "notify tool not found. Installing..."
        
        # Check if Go is installed
        if ! command -v go >/dev/null 2>&1; then
            log_error "Go is not installed. Please install Go first."
            exit 1
        fi
        
        # Install notify
        log_info "Installing notify tool..."
        go install -v github.com/projectdiscovery/notify/cmd/notify@latest
        
        # Check if installed successfully
        if command -v notify >/dev/null 2>&1; then
            log_info "✅ notify tool installed successfully"
        else
            log_error "Failed to install notify tool"
            exit 1
        fi
    fi
}

# Setup notify configuration
setup_notify_config() {
    local config_dir="$HOME/.config/notify"
    local config_file="$config_dir/provider-config.yaml"
    
    log_info "Setting up notify configuration..."
    
    # Create config directory
    mkdir -p "$config_dir"
    
    if [[ -f "$config_file" ]]; then
        log_warning "Configuration file already exists at: $config_file"
        read -p "Do you want to overwrite it? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Skipping configuration setup"
            return 0
        fi
    fi
    
    # Get user input for Telegram configuration
    echo
    log_info "Setting up Telegram notifications..."
    echo "You'll need:"
    echo "1. A Telegram Bot Token (get from @BotFather)"
    echo "2. Your Telegram Chat ID (get from @userinfobot)"
    echo
    
    read -p "Enter your Telegram Bot Token: " telegram_token
    read -p "Enter your Telegram Chat ID: " telegram_chat_id
    
    if [[ -z "$telegram_token" || -z "$telegram_chat_id" ]]; then
        log_error "Both Telegram token and chat ID are required"
        exit 1
    fi
    
    # Create configuration file
    cat > "$config_file" << EOF
# NINA-v2 Notify Configuration
# Generated on $(date)

providers:
  - id: "nina-result"
    telegram_api_key: "$telegram_token"
    telegram_chat_id: "$telegram_chat_id"
    telegram_format: "{{data}}"
    telegram_parsemode: "Markdown"
EOF
    
    log_info "✅ Configuration file created at: $config_file"
}

# Test notification
test_notification() {
    log_info "Testing notification..."
    
    local test_message="🧪 **NINA-v2 Test**\n\nNotifications are working correctly!\nTime: \`$(date)\`"
    
    if echo -e "$test_message" | notify -id nina-result 2>/dev/null; then
        log_info "✅ Test notification sent successfully!"
        log_info "Check your Telegram for the test message"
    else
        log_error "❌ Failed to send test notification"
        log_error "Please check your configuration and try again"
        exit 1
    fi
}

# Main setup function
main() {
    echo "=================================================="
    echo "       NINA-v2 Notification Setup Script"
    echo "=================================================="
    echo
    
    check_notify_installation
    echo
    setup_notify_config
    echo
    test_notification
    echo
    
    log_info "🎉 Notification setup completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Run NINA-v2 scans and you'll receive notifications"
    echo "2. You can disable notifications by setting NOTIFY_ENABLED=false"
    echo "3. Configuration file: ~/.config/notify/provider-config.yaml"
    echo
}

# Run main function
main "$@"
