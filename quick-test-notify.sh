#!/bin/bash

# Test quick das notificações
echo "=== Teste Rápido das Notificações ==="

# Configurar debug
export DEBUG_NOTIFY=true

# Carregar config
source "$(dirname "$0")/modules/core/config.sh"

echo "1. Variáveis:"
echo "   NOTIFY_ENABLED: $NOTIFY_ENABLED"
echo "   NOTIFY_CONFIG: $NOTIFY_CONFIG"
echo "   NOTIFY_PROVIDER_ID: $NOTIFY_PROVIDER_ID"
echo

echo "2. Verificando notify..."
if command -v notify >/dev/null 2>&1; then
    echo "   ✅ notify encontrado: $(which notify)"
else
    echo "   ❌ notify não encontrado"
    exit 1
fi
echo

echo "3. Verificando config..."
if [[ -f "$NOTIFY_CONFIG" ]]; then
    echo "   ✅ Config encontrado: $NOTIFY_CONFIG"
else
    echo "   ❌ Config não encontrado: $NOTIFY_CONFIG"
    echo "   Execute: ./configure-telegram.sh"
    exit 1
fi
echo

echo "4. Testando notificação simples..."
send_notification "🧪 Teste do NINA-v2\n\nSe você receber esta mensagem, as notificações estão funcionando!\nHorário: \`$(date)\`" "info"

echo
echo "5. Testando notify direto..."
echo "🔧 Teste direto com notify" | notify -id "$NOTIFY_PROVIDER_ID" -provider-config "$NOTIFY_CONFIG"

echo
echo "Teste concluído! Verifique seu Telegram."
