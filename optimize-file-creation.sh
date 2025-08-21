#!/bin/bash

# =============================================================================
# NINA RECON OPTIMIZED - Otimização de Criação de Arquivos
# Modifica módulos para só criar arquivos quando há dados
# =============================================================================

echo "📁 Otimizando criação de arquivos - só criar quando há dados..."

# Função para otimizar criação de arquivos
optimize_file_creation() {
    local file="$1"
    echo "🔧 Processando: $file"
    
    # Backup original
    cp "$file" "${file}.bak"
    
    # Padrão 1: sort -u > file.txt 
    # Trocar por: criar temp, verificar se não está vazio, então mover
    sed -i 's/sort -u > "\([^"]*\)"/sort -u > "\1.tmp" \&\& [[ -s "\1.tmp" ]] \&\& mv "\1.tmp" "\1" || rm -f "\1.tmp"/g' "$file"
    
    # Padrão 2: cat ... > file.txt
    # Trocar por versão com verificação
    sed -i 's/cat \([^>]*\) > "\([^"]*\)"/cat \1 > "\2.tmp" \&\& [[ -s "\2.tmp" ]] \&\& mv "\2.tmp" "\2" || rm -f "\2.tmp"/g' "$file"
    
    # Padrão 3: grep ... > file.txt
    sed -i 's/grep \([^>]*\) > "\([^"]*\)"/grep \1 > "\2.tmp" \&\& [[ -s "\2.tmp" ]] \&\& mv "\2.tmp" "\2" || rm -f "\2.tmp"/g' "$file"
    
    # Padrão 4: echo single line (manter como está, pois é intencional)
    # Não modificar echo de uma linha
}

# Lista de arquivos para otimizar
files_to_optimize=(
    "modules-optimized/recon/passive.sh"
    "modules-optimized/recon/active.sh" 
    "modules-optimized/probing/httpx.sh"
    "modules-optimized/discovery/fuzzing.sh"
    "modules-optimized/scanning/vulnerabilities.sh"
)

echo "Criando versão inteligente que só cria arquivos com dados..."
echo

for file in "${files_to_optimize[@]}"; do
    if [[ -f "$file" ]]; then
        optimize_file_creation "$file"
    else
        echo "⚠️  Arquivo não encontrado: $file"
    fi
done

echo
echo "📝 Criando função auxiliar para criação inteligente de arquivos..."

# Adicionar função auxiliar no config.sh
cat >> modules-optimized/core/config.sh << 'EOF'

# =============================================================================
# SMART FILE CREATION FUNCTIONS
# =============================================================================

# Função para salvar dados apenas se não estiver vazio
save_if_not_empty() {
    local temp_file="$1"
    local final_file="$2"
    local description="${3:-data}"
    
    if [[ -s "$temp_file" ]]; then
        mv "$temp_file" "$final_file"
        local count=$(wc -l < "$final_file" 2>/dev/null || echo "0")
        log_info "Saved $count lines of $description to $(basename "$final_file")"
        return 0
    else
        rm -f "$temp_file" 2>/dev/null
        log_info "No $description found - file not created"
        return 1
    fi
}

# Função para processar e salvar resultados com verificação
process_and_save() {
    local input_files=("${@:1:$#-2}")
    local output_file="${@: -2:1}"
    local description="${@: -1}"
    
    local temp_file="${output_file}.tmp"
    
    # Processar arquivos de entrada
    cat "${input_files[@]}" 2>/dev/null | \
    grep -v '^$' | \
    sort -u > "$temp_file"
    
    # Salvar apenas se não estiver vazio
    save_if_not_empty "$temp_file" "$output_file" "$description"
}

# Função para executar comando e salvar resultado apenas se não vazio
run_and_save() {
    local command="$1"
    local output_file="$2"
    local description="${3:-output}"
    
    local temp_file="${output_file}.tmp"
    
    # Executar comando
    eval "$command" > "$temp_file" 2>/dev/null || true
    
    # Salvar apenas se não estiver vazio
    save_if_not_empty "$temp_file" "$output_file" "$description"
}

EOF

echo "✅ Otimização concluída!"
echo
echo "🎯 Principais melhorias:"
echo "  • Arquivos só são criados se contiverem dados"
echo "  • Logs informativos indicam quando não há dados"
echo "  • Funções auxiliares para criação inteligente"
echo "  • Backup dos arquivos originais criado (.bak)"
echo
echo "📋 Para reverter mudanças (se necessário):"
echo "for f in modules-optimized/*/*.sh.bak; do mv \"\$f\" \"\${f%.bak}\"; done"
echo
echo "🧪 Teste o sistema agora:"
echo "./nina-recon-optimized.sh -d example.com -s closed -p quick"

