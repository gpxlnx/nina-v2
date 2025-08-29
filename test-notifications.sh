#!/bin/bash

# =============================================================================
# Script de Diagnóstico das Notificações NINA-v2
# =============================================================================

set -e

# Load config
source "$(dirname "$0")/modules/core/config.sh"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

echo "=================================================="
echo "     Diagnóstico do Sistema de Notificações"
echo "=================================================="
echo

log_step "1. Verificando variáveis de ambiente..."
echo "NOTIFY_ENABLED: ${NOTIFY_ENABLED:-not set}"
echo "NOTIFY_PROVIDER_ID: ${NOTIFY_PROVIDER_ID:-not set}"
echo "NOTIFY_CONFIG: ${NOTIFY_CONFIG:-not set}"
echo

log_step "2. Verificando se notify está instalado..."
if command -v notify >/dev/null 2>&1; then
    log_info "✅ notify encontrado: $(which notify)"
    notify -version 2>/dev/null || log_warning "Erro ao verificar versão"
else
    log_error "❌ notify não encontrado"
    echo "Para instalar: go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
    exit 1
fi
echo

log_step "3. Verificando arquivo de configuração..."
if [[ -f "$NOTIFY_CONFIG" ]]; then
    log_info "✅ Arquivo de config encontrado: $NOTIFY_CONFIG"
    echo "Conteúdo do arquivo:"
    cat "$NOTIFY_CONFIG"
else
    log_error "❌ Arquivo de config não encontrado: $NOTIFY_CONFIG"
    echo
    echo "Para criar a configuração, execute:"
    echo "./configure-telegram.sh"
    exit 1
fi
echo

log_step "4. Testando função check_notify_setup..."
if check_notify_setup; then
    log_info "✅ check_notify_setup passou"
else
    log_error "❌ check_notify_setup falhou"
    exit 1
fi
echo

log_step "5. Testando notify manualmente..."
echo "Enviando mensagem de teste com notify direto..."
test_message="🧪 **Teste Manual**

Esta é uma mensagem de teste enviada diretamente pelo notify.
Horário: \`$(date '+%Y-%m-%d %H:%M:%S')\`"

echo "Comando que será executado:"
echo "echo -e \"$test_message\" | notify -provider-config \"$NOTIFY_CONFIG\" -id \"$NOTIFY_PROVIDER_ID\""
echo

if echo -e "$test_message" | notify -provider-config "$NOTIFY_CONFIG" -id "$NOTIFY_PROVIDER_ID" 2>&1; then
    log_info "✅ Comando notify executado (verifique Telegram)"
else
    log_error "❌ Falha ao executar notify"
    exit 1
fi
echo

log_step "6. Testando função send_notification..."
echo "Testando função send_notification do NINA..."
if send_notification "🔧 **Teste da Função**\n\nTeste da função send_notification do NINA-v2\nHorário: \`$(date '+%Y-%m-%d %H:%M:%S')\`" "info"; then
    log_info "✅ send_notification executada"
else
    log_error "❌ send_notification falhou"
fi
echo

log_step "7. Testando todas as funções de notificação..."

# Teste notify_start
echo "Testando notify_start..."
notify_start "test.com" "deep"
sleep 2

# Teste notify_progress  
echo "Testando notify_progress..."
notify_progress "test.com" "Passive Recon" "Iniciando coleta de dados"
sleep 2

# Teste notify_module_complete
echo "Testando notify_module_complete..."
notify_module_complete "test.com" "Test Module" "42 resultados encontrados"
sleep 2

# Teste notify_vulnerability_found
echo "Testando notify_vulnerability_found..."
notify_vulnerability_found "test.com" "Critical" "3"
sleep 2

# Teste notify_scan_complete
echo "Testando notify_scan_complete..."
stats="**📊 Resultados de Teste:**\n• Subdomínios: \`123\`\n• URLs: \`456\`\n• Vulnerabilidades: \`7\`"
notify_scan_complete "test.com" "$stats" "1h 23m"
sleep 2

echo
log_info "🎉 Diagnóstico completo!"
echo
echo "Se você recebeu as mensagens no Telegram, o sistema está funcionando."
echo "Se não recebeu, verifique:"
echo "1. ✅ Bot token correto"
echo "2. ✅ Chat ID correto" 
echo "3. ✅ Você iniciou conversa com o bot"
echo "4. ✅ Bot não foi bloqueado"
echo
echo "Para testar com um scan real:"
echo "./nina-recon.sh -d example.com -p quick --notifications"
