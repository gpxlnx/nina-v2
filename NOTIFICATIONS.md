# 📱 NINA-v2 Notificações

O NINA-v2 agora suporta notificações em tempo real via Telegram usando o [notify](https://github.com/projectdiscovery/notify) do Project Discovery.

## 🚀 Configuração Rápida

### 1. Execute o script de setup automático:
```bash
./setup-notifications.sh
```

### 2. Configure manualmente (alternativa):

#### Instalar o notify:
```bash
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
```

#### Criar configuração:
```bash
mkdir -p ~/.config/notify
cat > ~/.config/notify/provider-config.yaml << 'EOF'
providers:
  - id: "nina-result"
    telegram_api_key: "8142001762:AAFH42XVvVkDeKhE-1KBj4JKHV9vehdDcCs"
    telegram_chat_id: "176232878"
    telegram_format: "{{data}}"
    telegram_parsemode: "Markdown"
EOF
```

## 📋 Tipos de Notificações

### 🚀 **Início do Scan**
- Enviada quando o scan é iniciado
- Inclui: domínio alvo, perfil utilizado, horário de início

### ⏳ **Progresso dos Módulos**
- **Passive Recon**: Quando inicia a coleta de dados OSINT
- **Active Recon**: Quando inicia DNS bruteforce
- **Web Crawler**: Quando inicia descoberta de URLs
- **Vulnerability Scan**: Quando inicia análise de segurança

### ✅ **Conclusão dos Módulos**
- **Passive Recon**: Quantos subdomínios foram descobertos
- **Active Recon**: Novos subdomínios encontrados via bruteforce
- **Web Crawler**: Total de URLs descobertas
- **Vulnerability Scan**: Vulnerabilidades encontradas por severidade

### 🚨 **Alertas de Segurança**
- Disparadas automaticamente quando vulnerabilidades críticas são encontradas
- Inclui tipo e quantidade de vulnerabilidades

### 🎯 **Conclusão Completa**
- Enviada ao final do scan
- Inclui estatísticas completas:
  - Subdomínios passivos/ativos
  - Live hosts
  - Total de URLs
  - Vulnerabilidades encontradas
  - Tempo de execução

## 🎛️ Controle via Linha de Comando

### Habilitar notificações:
```bash
./nina-recon.sh -d example.com --notifications
```

### Desabilitar notificações:
```bash
./nina-recon.sh -d example.com --no-notifications
```

### Por padrão (baseado em NOTIFY_ENABLED):
```bash
./nina-recon.sh -d example.com  # usa config padrão
```

## 🔧 Configuração Avançada

### Variáveis de Ambiente:
```bash
export NOTIFY_ENABLED=true                    # Habilita/desabilita
export NOTIFY_PROVIDER_ID="nina-result"       # ID do provider
export NOTIFY_CONFIG="~/.config/notify/provider-config.yaml"  # Config file
```

### Múltiplos Providers:
```yaml
providers:
  - id: "nina-result"
    telegram_api_key: "SEU_BOT_TOKEN"
    telegram_chat_id: "SEU_CHAT_ID"
    telegram_format: "{{data}}"
    telegram_parsemode: "Markdown"
    
  - id: "nina-alerts"
    discord_webhook_url: "SEU_DISCORD_WEBHOOK"
    discord_username: "NINA Bot"
    
  - id: "nina-slack"
    slack_webhook_url: "SEU_SLACK_WEBHOOK"
    slack_username: "NINA Recon"
    slack_channel: "#security"
```

## 📱 Configuração do Telegram

### 1. Criar Bot:
1. Acesse [@BotFather](https://t.me/BotFather) no Telegram
2. Digite `/newbot`
3. Escolha um nome e username para o bot
4. Copie o **Bot Token**

### 2. Obter Chat ID:
1. Acesse [@userinfobot](https://t.me/userinfobot) no Telegram
2. Digite `/start`
3. Copie o **Chat ID** (número que aparece)

### 3. Teste a configuração:
```bash
echo "🧪 Teste do NINA-v2" | notify -id nina-result
```

## 🎨 Formato das Mensagens

### Exemplo de Notificação de Início:
```
🚀 **NINA Recon**

🚀 **Scan Started**

Target: `example.com`
Profile: `deep`
Time: `2024-12-19 15:30:22`
```

### Exemplo de Vulnerabilidades Encontradas:
```
🚨 **NINA Recon**

🚨 **Vulnerabilities Found**

Target: `example.com`
Type: `Critical`
Count: `3`
```

### Exemplo de Conclusão:
```
🎯 **NINA Recon**

🎯 **Scan Complete**

Target: `example.com`
Duration: `2h 45m`

**📊 Results:**
• Passive Subdomains: `245`
• Active Subdomains: `67`
• Live Hosts: `89`
• Total URLs: `1,234`
• Vulnerabilities: `12`
```

## 🐛 Troubleshooting

### Notify não encontrado:
```bash
# Instalar Go se necessário
sudo apt install golang-go

# Instalar notify
go install -v github.com/projectdiscovery/notify/cmd/notify@latest

# Verificar se está no PATH
echo $PATH | grep go/bin
```

### Configuração não encontrada:
```bash
# Verificar se existe
ls -la ~/.config/notify/provider-config.yaml

# Criar diretório se necessário
mkdir -p ~/.config/notify
```

### Teste falha:
```bash
# Testar manualmente
echo "Teste" | notify -id nina-result -v

# Verificar logs
notify -id nina-result -v < /dev/null
```

### Notificações não aparecem:
1. ✅ Verificar se o bot token está correto
2. ✅ Verificar se o chat ID está correto
3. ✅ Verificar se você iniciou conversa com o bot no Telegram
4. ✅ Testar com: `echo "teste" | notify -id nina-result`

## 💡 Dicas

### Para scans longos:
- Use notificações para monitorar progresso remotamente
- Vulnerabilidades críticas são alertadas imediatamente
- Receba resumo completo ao final

### Para múltiplos domínios:
- Cada scan enviará notificações separadas
- Use o nome do domínio para identificar qual scan

### Para debugging:
- Use `--no-notifications` se houver problemas
- Teste configuração com script de setup
- Verifique logs em caso de erro

---

🎯 **Agora você receberá notificações em tempo real do progresso dos seus scans NINA-v2!**
