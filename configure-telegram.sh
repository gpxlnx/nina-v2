#!/bin/bash

# =============================================================================
# Configuração Automática do Telegram para NINA-v2
# =============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Suas credenciais do Telegram
TELEGRAM_BOT_TOKEN="8142001762:AAFH42XVvVkDeKhE-1KBj4JKHV9vehdDcCs"
TELEGRAM_CHAT_ID="176232878"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

main() {
    echo "=================================================="
    echo "    Configuração Automática do Telegram - NINA-v2"
    echo "=================================================="
    echo
    
    log_step "1. Verificando instalação do notify..."
    
    # Verificar se notify está instalado
    if command -v notify >/dev/null 2>&1; then
        log_info "✅ notify já está instalado"
    else
        log_warning "notify não encontrado. Instalando..."
        
        # Verificar se Go está instalado
        if ! command -v go >/dev/null 2>&1; then
            echo "❌ Go não está instalado. Instalando..."
            sudo apt update && sudo apt install -y golang-go
        fi
        
        # Instalar notify
        go install -v github.com/projectdiscovery/notify/cmd/notify@latest
        
        # Adicionar ao PATH se necessário
        export PATH=$PATH:$(go env GOPATH)/bin
        echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
        
        log_info "✅ notify instalado com sucesso"
    fi
    
    echo
    log_step "2. Criando configuração do Telegram..."
    
    # Criar diretório de configuração
    local config_dir="$HOME/.config/notify"
    local config_file="$config_dir/provider-config.yaml"
    
    mkdir -p "$config_dir"
    
    # Criar arquivo de configuração
    cat > "$config_file" << EOF
# NINA-v2 Telegram Configuration
# Auto-generated on $(date)

providers:
  - id: "nina-result"
    telegram_api_key: "$TELEGRAM_BOT_TOKEN"
    telegram_chat_id: "$TELEGRAM_CHAT_ID"
    telegram_format: "{{data}}"
    telegram_parsemode: "Markdown"
EOF
    
    log_info "✅ Configuração criada em: $config_file"
    
    echo
    log_step "3. Configurando variáveis de ambiente..."
    
    # Configurar no NINA-v2
    export NOTIFY_ENABLED=true
    export NOTIFY_PROVIDER_ID="nina-result"
    export NOTIFY_CONFIG="$config_file"
    
    log_info "✅ Variáveis configuradas"
    
    echo
    log_step "4. Testando notificação..."
    
    local test_message="🧪 **NINA-v2 Configuração**

✅ **Telegram configurado com sucesso!**

Bot Token: \`${TELEGRAM_BOT_TOKEN:0:10}...\`
Chat ID: \`$TELEGRAM_CHAT_ID\`
Horário: \`$(date '+%Y-%m-%d %H:%M:%S')\`

Agora você receberá notificações dos scans!"
    
    # Tentar enviar notificação de teste
    if echo -e "$test_message" | notify -id nina-result 2>/dev/null; then
        log_info "🎉 Notificação de teste enviada com sucesso!"
        echo
        echo "✅ Configuração completa! Verifique o Telegram para a mensagem de teste."
    else
        log_warning "❌ Falha ao enviar notificação de teste"
        echo
        echo "Possíveis problemas:"
        echo "1. Verificar se o bot token está correto"
        echo "2. Verificar se você iniciou conversa com o bot no Telegram"
        echo "3. Verificar se o chat ID está correto"
        echo
        echo "Para testar manualmente:"
        echo "echo 'Teste' | notify -id nina-result"
    fi
    
    echo
    echo "=================================================="
    echo "               Configuração Finalizada"
    echo "=================================================="
    echo
    echo "🎯 Para usar com NINA-v2:"
    echo "   ./nina-recon.sh -d example.com --notifications"
    echo
    echo "🔧 Para desabilitar:"
    echo "   ./nina-recon.sh -d example.com --no-notifications"
    echo
    echo "📁 Arquivos criados:"
    echo "   - $config_file"
    echo
    echo "📱 Tipos de notificação que você receberá:"
    echo "   - Início do scan"
    echo "   - Progresso dos módulos"
    echo "   - Vulnerabilidades encontradas"
    echo "   - Conclusão com estatísticas"
    echo
}

# Executar configuração
main "$@"
