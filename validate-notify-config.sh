#!/bin/bash

# =============================================================================
# Script para Validar Configuração do Notify
# =============================================================================

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

# Carregar configuração NINA
source "$(dirname "$0")/modules/core/config.sh"

echo "=================================================="
echo "      Validação da Configuração do Notify"
echo "=================================================="
echo

log_step "1. Verificando variáveis de ambiente..."
echo "NOTIFY_ENABLED: ${NOTIFY_ENABLED}"
echo "NOTIFY_PROVIDER_ID: ${NOTIFY_PROVIDER_ID}"
echo "NOTIFY_CONFIG: ${NOTIFY_CONFIG}"
echo

log_step "2. Verificando arquivo de configuração..."
if [[ -f "$NOTIFY_CONFIG" ]]; then
    log_info "✅ Arquivo encontrado: $NOTIFY_CONFIG"
    
    echo "Conteúdo do arquivo:"
    echo "----------------------------------------"
    cat "$NOTIFY_CONFIG"
    echo "----------------------------------------"
    echo
    
    # Verificar se contém nina-result
    if grep -q "nina-result" "$NOTIFY_CONFIG"; then
        log_info "✅ Configuração 'nina-result' encontrada"
    else
        log_error "❌ Configuração 'nina-result' não encontrada"
    fi
    
    # Verificar sintaxe YAML básica
    if grep -q "providers:" "$NOTIFY_CONFIG"; then
        log_info "✅ Estrutura YAML válida (providers:)"
    else
        log_warning "⚠️ Estrutura YAML pode estar incorreta"
    fi
    
else
    log_error "❌ Arquivo não encontrado: $NOTIFY_CONFIG"
    echo "Execute: ./configure-telegram.sh"
    exit 1
fi

log_step "3. Verificando notify..."
if command -v notify >/dev/null 2>&1; then
    log_info "✅ notify encontrado: $(which notify)"
    
    # Verificar versão
    local version=$(notify -version 2>/dev/null | head -1 || echo "unknown")
    log_info "Versão: $version"
else
    log_error "❌ notify não encontrado"
    echo "Instale com: go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
    exit 1
fi

echo
log_step "4. Teste de configuração..."

# Teste simples
echo "Testando notify com configuração atual..."
test_message="🧪 **Teste de Validação**

Arquivo: \`$NOTIFY_CONFIG\`
Provider: \`$NOTIFY_PROVIDER_ID\`
Horário: \`$(date '+%Y-%m-%d %H:%M:%S')\`

Se você receber esta mensagem, a configuração está correta! ✅"

echo "Comando sendo executado:"
echo "echo -e \"$test_message\" | notify -provider-config \"$NOTIFY_CONFIG\" -id \"$NOTIFY_PROVIDER_ID\""
echo

if echo -e "$test_message" | notify -provider-config "$NOTIFY_CONFIG" -id "$NOTIFY_PROVIDER_ID" 2>&1; then
    log_info "✅ Comando executado com sucesso"
    echo
    echo "Se você recebeu a mensagem no Telegram, a configuração está funcionando!"
else
    log_error "❌ Falha ao executar comando"
    echo
    echo "Possíveis problemas:"
    echo "1. Token do bot inválido"
    echo "2. Chat ID incorreto"
    echo "3. Você não iniciou conversa com o bot"
    echo "4. Sintaxe YAML incorreta"
fi

echo
log_info "🎯 Para corrigir problemas, execute: ./configure-telegram.sh"
