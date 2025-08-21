#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Smart File Creation
# Implementa criação inteligente de arquivos (só quando há dados)
# =============================================================================

echo "🧠 Implementando criação inteligente de arquivos..."

# Adicionar função no config.sh para criação inteligente
if ! grep -q "smart_save" modules-optimized/core/config.sh; then
    echo "📝 Adicionando funções de criação inteligente..."
    
cat >> modules-optimized/core/config.sh << 'EOF'

# =============================================================================
# SMART FILE CREATION
# =============================================================================

# Salva arquivo apenas se não estiver vazio
smart_save() {
    local temp_file="$1"
    local output_file="$2" 
    local description="${3:-data}"
    
    if [[ -s "$temp_file" ]]; then
        mv "$temp_file" "$output_file"
        local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
        log_info "💾 Saved $count lines of $description"
        return 0
    else
        rm -f "$temp_file" 2>/dev/null
        log_info "📭 No $description found - skipping file creation"
        return 1
    fi
}

# Processa múltiplos arquivos e salva apenas se houver resultado
smart_combine() {
    local output_file="${@: -1}"
    local input_files=("${@:1:$#-1}")
    local temp_file="${output_file}.tmp"
    
    cat "${input_files[@]}" 2>/dev/null | grep -v '^$' | sort -u > "$temp_file"
    smart_save "$temp_file" "$output_file" "combined results"
}

# Executa comando e salva apenas se houver saída
smart_run() {
    local command="$1"
    local output_file="$2"
    local description="${3:-command output}"
    local temp_file="${output_file}.tmp"
    
    eval "$command" > "$temp_file" 2>/dev/null
    smart_save "$temp_file" "$output_file" "$description"
}

EOF

echo "✅ Funções inteligentes adicionadas ao config.sh"
fi

# Criar exemplos de uso
echo "📚 Criando exemplos de uso das funções inteligentes..."

cat > modules-optimized/core/smart-examples.txt << 'EOF'
EXEMPLOS DE USO DAS FUNÇÕES INTELIGENTES:

1. SMART_SAVE - Salva apenas se arquivo não estiver vazio:
   # Ao invés de:
   sort -u > results.txt
   
   # Use:
   sort -u > results.tmp
   smart_save results.tmp results.txt "subdomains"

2. SMART_COMBINE - Combina arquivos e salva apenas se houver resultado:
   # Ao invés de:
   cat file1.txt file2.txt | sort -u > combined.txt
   
   # Use:
   smart_combine file1.txt file2.txt combined.txt

3. SMART_RUN - Executa comando e salva apenas se houver saída:
   # Ao invés de:
   curl -s "https://api.example.com" | jq -r '.data[]' > api-results.txt
   
   # Use:
   smart_run 'curl -s "https://api.example.com" | jq -r ".data[]"' api-results.txt "API results"

VANTAGENS:
- ✅ Não cria arquivos vazios
- ✅ Logs informativos sobre o que foi encontrado
- ✅ Estrutura de diretórios mais limpa
- ✅ Fácil identificação de onde há dados reais
EOF

echo "📋 Demonstrando diferença no comportamento:"
echo

echo "🔴 ANTES (cria arquivos vazios):"
echo "  sort -u > results.txt  # Sempre cria arquivo, mesmo vazio"
echo "  ls -la results.txt     # -rw-r--r-- 1 user user 0 date results.txt"
echo

echo "🟢 DEPOIS (só cria se há dados):"
echo "  sort -u > results.tmp"
echo "  smart_save results.tmp results.txt 'subdomains'"
echo "  # Output: 📭 No subdomains found - skipping file creation"
echo "  # OU:    💾 Saved 25 lines of subdomains"
echo

echo "✅ Configuração concluída!"
echo
echo "🎯 Para usar as funções inteligentes:"
echo "  1. Substitua redirecionamentos diretos por smart_save"
echo "  2. Use smart_combine para combinar múltiplos arquivos"  
echo "  3. Use smart_run para comandos com saída variável"
echo
echo "📖 Veja exemplos em: modules-optimized/core/smart-examples.txt"

