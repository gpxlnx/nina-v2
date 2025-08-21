# 📁 NINA Recon Optimized - Referência de Arquivos de Saída

## 🎯 Estrutura de Saída

Todos os arquivos são organizados em: `/root/out/DOMAIN/`

```
output/DOMAIN/
├── 📁 recon/              # Dados de reconnaissance
├── 📁 probing/            # HTTP probing e análises
├── 📁 discovery/          # Descoberta de conteúdo
├── 📁 analysis/           # Análises avançadas
├── 📁 vulnerabilities/    # Vulnerabilidades encontradas
├── 📁 monitoring/         # Monitoramento contínuo
├── 📁 log/               # Logs de execução
├── 📁 manual/            # Notas manuais
├── 📁 screenshots/       # Capturas de tela
└── 📄 Arquivos principais...
```

---

## 🔍 MÓDULO: RECONNAISSANCE (recon/)

### 📂 `recon/passive/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `crt-subdomains.txt` | Subdomínios via Certificate Transparency | Lista de subdomínios encontrados em certificados SSL |
| `shodan-subdomains.txt` | Subdomínios via Shodan | Subdomínios descobertos na base do Shodan |
| `wayback-subdomains.txt` | Subdomínios via Wayback Machine | Subdomínios históricos do Internet Archive |
| `github-subdomains.txt` | Subdomínios via GitHub | Subdomínios encontrados em repositórios públicos |
| `threatintel-subdomains.txt` | Threat Intelligence | Subdomínios de fontes de threat intelligence |
| `subfinder-results.txt` | Resultados do Subfinder | Output completo da ferramenta Subfinder |
| `amass-passive.txt` | Resultados do Amass | Reconnaissance passivo com Amass |
| `assetfinder-results.txt` | Resultados do Assetfinder | Subdomínios encontrados pelo Assetfinder |

### 📂 `recon/active/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `wildcard-detection.txt` | Detecção de Wildcards | Análise de wildcards DNS do domínio |
| `puredns-results.txt` | Bruteforce DNS (PureDNS) | Subdomínios descobertos via bruteforce DNS |
| `shuffledns-results.txt` | Bruteforce DNS (ShuffleDNS) | Resultados de bruteforce com shuffling |
| `dnsgen-mutations.txt` | Mutações de Domínios | Permutações geradas pelo DNSGen |
| `altdns-mutations.txt` | Mutações Alternativas | Permutações criadas pelo AltDNS |
| `gobuster-dns.txt` | Bruteforce Gobuster | Subdomínios encontrados pelo Gobuster |
| `zone-transfer-results.txt` | Transferências de Zona | Tentativas de zone transfer DNS |

### 📂 `recon/certificates/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `certificate-transparency.txt` | Logs CT completos | Dados completos de Certificate Transparency |
| `certificate-analysis.json` | Análise detalhada | Análise JSON dos certificados |
| `san-domains.txt` | Subject Alternative Names | Domínios encontrados em SAN dos certificados |
| `expired-certificates.txt` | Certificados Expirados | Lista de certificados vencidos |

### 📄 `recon/` (Arquivos principais)
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `subdomains-passive.txt` | Todos subdomínios passivos | Consolidação de todas as fontes passivas |
| `subdomains-active.txt` | Todos subdomínios ativos | Consolidação de bruteforce e mutações |
| `subdomains-all.txt` | **PRINCIPAL** - Todos subdomínios | Lista final de todos os subdomínios únicos |
| `passive-summary.txt` | Resumo do recon passivo | Estatísticas e métricas do reconnaissance |
| `active-summary.txt` | Resumo do recon ativo | Estatísticas do bruteforce e mutações |

---

## 🌐 MÓDULO: HTTP PROBING (probing/)

### 📂 `probing/http/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `http-hosts.txt` | Hosts HTTP (porta 80) | URLs que respondem em HTTP |
| `http-redirects.txt` | Redirecionamentos HTTP | Análise de redirects HTTP |
| `http-errors.txt` | Erros HTTP | Hosts com erros de conexão HTTP |

### 📂 `probing/https/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `https-hosts.txt` | Hosts HTTPS (porta 443) | URLs que respondem em HTTPS |
| `https-certificates.txt` | Certificados HTTPS | Informações dos certificados SSL |
| `https-redirects.txt` | Redirecionamentos HTTPS | Análise de redirects HTTPS |

### 📂 `probing/ports/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `port-80.txt` | Serviços porta 80 | Hosts respondendo na porta 80 |
| `port-443.txt` | Serviços porta 443 | Hosts respondendo na porta 443 |
| `port-8080.txt` | Serviços porta 8080 | Hosts respondendo na porta 8080 |
| `port-8443.txt` | Serviços porta 8443 | Hosts respondendo na porta 8443 |
| `alt-ports.txt` | Portas alternativas | 3000, 5000, 8000, 8888 |
| `discovered-ports.txt` | Todas as portas | Consolidação de todas as portas |

### 📂 `probing/technologies/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `web-technologies.txt` | Tecnologias detectadas | Framework, CMS, linguagens |
| `server-headers.txt` | Headers de servidor | Server, X-Powered-By, etc. |
| `content-types.txt` | Tipos de conteúdo | Content-Type dos responses |
| `status-codes.txt` | Códigos de status | Distribuição de códigos HTTP |
| `technology-summary.txt` | Resumo de tecnologias | Estatísticas por tecnologia |

### 📂 `probing/responses/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `response-sizes.txt` | Tamanhos de response | Análise de Content-Length |
| `large-responses.txt` | Responses grandes | Responses > 10KB |
| `redirects-3xx.txt` | Códigos 3xx | Redirects e moved |
| `errors-4xx.txt` | Códigos 4xx | Client errors |
| `errors-5xx.txt` | Códigos 5xx | Server errors |
| `success-2xx.txt` | Códigos 2xx | Responses bem-sucedidos |

### 📂 `probing/screenshots/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `{domain}-{port}.png` | Screenshots individuais | Captura de tela de cada host |
| `screenshot-urls.txt` | URLs capturadas | Lista de URLs com screenshots |
| `screenshot-failed.txt` | Falhas de captura | URLs que falharam no screenshot |

### 📂 `probing/certificates/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `certificate-info.txt` | Informações detalhadas | Dados completos dos certificados |
| `certificate-chains.txt` | Cadeias de certificados | Análise das certificate chains |
| `problematic-certificates.txt` | Certificados problemáticos | Self-signed, expirados, inválidos |
| `certificate-issuers.txt` | Emissores de certificados | CAs que emitiram os certificados |

### 📄 `probing/` (Arquivos principais)
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `live-hosts.txt` | **PRINCIPAL** - Hosts ativos | Lista final de todos os hosts que respondem |
| `live-urls-final.txt` | URLs finais ativas | URLs completas com protocolos |
| `httpx-comprehensive.txt` | Output completo HTTPX | Dados brutos do HTTPX |
| `discovered-ips.txt` | IPs descobertos | Endereços IP únicos encontrados |
| `special-endpoints.txt` | Endpoints especiais | /.well-known/, /robots.txt, etc. |
| `unique-hosts.txt` | Hosts únicos | Lista de hostnames únicos |
| `probing-summary.txt` | Resumo do probing | Estatísticas completas |

---

## 🕷️ MÓDULO: DISCOVERY (discovery/)

### 📂 `discovery/archive_urls/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `wayback-urls.txt` | URLs do Wayback Machine | URLs históricas do Internet Archive |
| `gau-urls.txt` | URLs do GAU | URLs agregadas de múltiplas fontes |
| `commoncrawl-urls.txt` | URLs do CommonCrawl | URLs do projeto CommonCrawl |
| `otx-urls.txt` | URLs do AlienVault OTX | URLs de threat intelligence |
| `archive-consolidated.txt` | URLs de arquivo consolidadas | Todas as URLs de arquivo únicas |

### 📂 `discovery/crawl/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `katana-urls.txt` | URLs do Katana | URLs descobertas pelo web crawler |
| `katana-forms.txt` | Formulários encontrados | Forms HTML descobertos |
| `katana-apis.txt` | APIs descobertas | Endpoints de API encontrados |
| `crawl-statistics.txt` | Estatísticas do crawl | Métricas do web crawling |

### 📂 `discovery/content/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `all-directories.txt` | Todos os diretórios | Diretórios descobertos por todas as ferramentas |
| `all-files.txt` | Todos os arquivos | Arquivos descobertos por todas as ferramentas |
| `fuzzing-consolidated.txt` | Fuzzing consolidado | Resultados únicos de content discovery |

### 📂 `discovery/directories/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `ffuf-directories.txt` | Diretórios FFUF | Resultados do FFUF para diretórios |
| `feroxbuster-dirs.txt` | Diretórios Feroxbuster | Scan recursivo de diretórios |
| `gobuster-directories.txt` | Diretórios Gobuster | Bruteforce de diretórios |
| `dirsearch-results.txt` | Diretórios Dirsearch | Resultados do Dirsearch |

### 📂 `discovery/files/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `discovered-files.txt` | Arquivos descobertos | Todos os arquivos encontrados |
| `config-files.txt` | Arquivos de configuração | .env, config.php, web.config |
| `log-files.txt` | Arquivos de log | access.log, error.log, debug.log |
| `database-files.txt` | Arquivos de banco | .sql, .db, .sqlite |
| `code-files.txt` | Arquivos de código | .php, .asp, .jsp, .py |
| `document-files.txt` | Documentos | .pdf, .doc, .xls, .txt |

### 📂 `discovery/backups/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `backup-files.txt` | Arquivos de backup | .bak, .old, .backup, .orig |
| `zip-archives.txt` | Arquivos compactados | .zip, .rar, .tar.gz |
| `version-control.txt` | Controle de versão | .git/, .svn/, .hg/ |
| `temp-files.txt` | Arquivos temporários | .tmp, .temp, ~ |

### 📂 `discovery/parameters/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `get-parameters.txt` | Parâmetros GET | Parâmetros de URL descobertos |
| `post-parameters.txt` | Parâmetros POST | Parâmetros de formulário |
| `parameter-wordlist.txt` | Wordlist de parâmetros | Lista de parâmetros para fuzzing |
| `arjun-parameters.txt` | Parâmetros Arjun | Descoberta de parâmetros HTTP |

### 📂 `discovery/endpoints/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `api-endpoints.txt` | Endpoints de API | /api/, /v1/, /rest/, /graphql |
| `admin-endpoints.txt` | Endpoints administrativos | /admin/, /dashboard/, /panel/ |
| `auth-endpoints.txt` | Endpoints de autenticação | /login/, /auth/, /signin/ |
| `special-endpoints.txt` | Endpoints especiais | /.well-known/, /robots.txt |

### 📂 `discovery/js_endpoints/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `js-discovered-urls.txt` | URLs de JavaScript | URLs extraídas de arquivos JS |
| `js-api-endpoints.txt` | APIs de JavaScript | Endpoints de API encontrados em JS |
| `js-forms.txt` | Formulários JS | Forms descobertos em JavaScript |

### 📂 `discovery/api_endpoints/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `rest-apis.txt` | APIs REST | Endpoints REST descobertos |
| `graphql-endpoints.txt` | GraphQL | Endpoints GraphQL |
| `swagger-docs.txt` | Documentação Swagger | APIs documentadas |
| `api-versions.txt` | Versões de API | /v1/, /v2/, /api/v3/ |

### 📂 `discovery/wordlists/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `custom-wordlist.txt` | Wordlist personalizada | Lista baseada nas descobertas |
| `domain-wordlist.txt` | Wordlist do domínio | Palavras específicas do target |
| `technology-wordlist.txt` | Wordlist por tecnologia | Baseada nas tecnologias detectadas |

### 📄 `discovery/` (Arquivos principais)
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `all-discovered-urls.txt` | **PRINCIPAL** - Todas URLs | Lista consolidada de todas as URLs |
| `all-fuzzing-results.txt` | **PRINCIPAL** - Fuzzing | Resultados consolidados de fuzzing |
| `crawler-summary.txt` | Resumo do crawler | Estatísticas de web crawling |
| `fuzzing-summary.txt` | Resumo do fuzzing | Estatísticas de content discovery |

---

## 📜 MÓDULO: ANALYSIS (analysis/)

### 📂 `analysis/javascript/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `all-js-files.txt` | Lista de arquivos JS | Todos os arquivos JavaScript encontrados |
| `downloaded-files.txt` | Arquivos baixados | JS files baixados para análise |
| `js-analysis-log.txt` | Log de análise | Processo de análise dos arquivos |

### 📂 `analysis/javascript/endpoints/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `api-endpoints.txt` | APIs em JavaScript | Endpoints de API extraídos |
| `relative-paths.txt` | Paths relativos | Caminhos relativos encontrados |
| `full-urls.txt` | URLs completas | URLs completas extraídas |
| `parameters.txt` | Parâmetros JS | Parâmetros descobertos |
| `generated-urls.txt` | URLs geradas | URLs construídas dinamicamente |

### 📂 `analysis/javascript/secrets/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `api-keys.txt` | Chaves de API | API keys encontradas em JS |
| `tokens.txt` | Tokens | Access tokens, JWT tokens |
| `passwords.txt` | Senhas | Senhas hardcoded |
| `emails.txt` | Endereços de email | Emails encontrados |
| `sensitive-patterns.txt` | Padrões sensíveis | Outros dados sensíveis |
| `database-urls.txt` | URLs de banco | Strings de conexão |
| `internal-urls.txt` | URLs internas | URLs de desenvolvimento |

### 📂 `analysis/technologies/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `framework-analysis.txt` | Análise de frameworks | Detalhes dos frameworks |
| `version-analysis.txt` | Análise de versões | Versões de software detectadas |
| `security-headers.txt` | Headers de segurança | HSTS, CSP, X-Frame-Options |
| `technology-stack.txt` | Stack tecnológico | Stack completo da aplicação |

### 📄 `analysis/` (Arquivos principais)
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `javascript-endpoints.txt` | **PRINCIPAL** - Endpoints JS | Todos endpoints de JavaScript |
| `javascript-urls.txt` | **PRINCIPAL** - URLs JS | Todas URLs de JavaScript |
| `javascript-secrets.txt` | **PRINCIPAL** - Secrets JS | Todos secrets encontrados |
| `analysis-summary.txt` | Resumo da análise | Estatísticas de análise |

---

## 🔒 MÓDULO: VULNERABILITIES (vulnerabilities/)

### 📂 `vulnerabilities/nuclei/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `nuclei-all.txt` | Todas vulnerabilidades | Output completo do Nuclei |
| `critical-findings.txt` | Vulnerabilidades críticas | Severidade crítica |
| `high-findings.txt` | Vulnerabilidades altas | Severidade alta |
| `medium-findings.txt` | Vulnerabilidades médias | Severidade média |
| `low-findings.txt` | Vulnerabilidades baixas | Severidade baixa |
| `info-findings.txt` | Descobertas informativas | Severidade info |
| `vulnerability-types.txt` | Tipos de vulnerabilidades | Estatísticas por tipo |
| `affected-hosts.txt` | Hosts afetados | Hosts com vulnerabilidades |

### 📂 `vulnerabilities/subdomain_takeover/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `subzy-results.txt` | Resultados Subzy | Análise de subdomain takeover |
| `subjack-results.txt` | Resultados Subjack | Verificação alternativa |
| `potential-takeovers.txt` | Takeovers potenciais | Subdomínios vulneráveis |
| `dangling-cnames.txt` | CNAMEs órfãos | CNAMEs apontando para serviços inexistentes |
| `cnames.txt` | Todos CNAMEs | Mapeamento de CNAMEs |

### 📂 `vulnerabilities/ssl_tls/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `certificate-issues.txt` | Problemas de certificado | Certificados problemáticos |
| `weak-ssl-hosts.txt` | SSL fraco | Hosts com configuração SSL fraca |
| `sslscan-results/` | Resultados SSLScan | Análises detalhadas por host |
| `tlsx-analysis.json` | Análise TLSX | Dados JSON dos certificados |
| `nuclei-ssl-vulns.txt` | Vulnerabilidades SSL | Vulns SSL detectadas pelo Nuclei |

### 📂 `vulnerabilities/web_vulns/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `crlf-vulnerabilities.txt` | CRLF Injection | Vulnerabilidades de CRLF |
| `open-redirects.txt` | Open Redirects | Redirecionamentos abertos |
| `directory-traversal.txt` | Directory Traversal | Path traversal vulnerabilities |
| `lfi-vulnerabilities.txt` | Local File Inclusion | LFI vulnerabilities |
| `xss-findings.txt` | Cross-Site Scripting | XSS vulnerabilities |

### 📂 `vulnerabilities/apis/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `unauth-apis.txt` | APIs sem autenticação | APIs acessíveis sem auth |
| `weak-auth-apis.txt` | APIs com auth fraca | APIs com autenticação fraca |
| `verbose-error-apis.txt` | APIs com erros verbosos | APIs que expõem informações |
| `cors-issues.txt` | Problemas de CORS | Configurações CORS inseguras |
| `nuclei-api-vulns.txt` | Vulnerabilidades API | Vulns de API pelo Nuclei |

### 📂 `vulnerabilities/secrets/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `potential-secrets.txt` | Secrets potenciais | Possíveis credenciais expostas |
| `exposed-configs.txt` | Configurações expostas | Arquivos de config acessíveis |
| `sensitive-configs.txt` | Configs sensíveis | Arquivos com dados sensíveis |
| `git-repositories.txt` | Repositórios Git | .git/ directories expostos |

### 📂 `vulnerabilities/misconfigurations/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `server-misconfigs.txt` | Misconfig de servidor | Configurações inseguras |
| `security-headers.txt` | Headers de segurança | Headers faltando/incorretos |
| `directory-listings.txt` | Listagem de diretórios | Diretórios com listing habilitado |
| `backup-exposures.txt` | Backups expostos | Arquivos de backup acessíveis |

### 📄 `vulnerabilities/` (Arquivos principais)
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `vulnerability-summary.txt` | **PRINCIPAL** - Resumo | Resumo completo de vulnerabilidades |
| `high-priority-vulns.txt` | Vulnerabilidades prioritárias | Critical + High severity |
| `vulnerability-report.txt` | Relatório detalhado | Relatório formatado |

---

## 📊 MÓDULO: MONITORING (monitoring/)

### 📂 `monitoring/changes/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `subdomain-changes.txt` | Mudanças em subdomínios | Novos/removidos subdomínios |
| `url-changes.txt` | Mudanças em URLs | Novas/removidas URLs |
| `tech-changes.txt` | Mudanças tecnológicas | Alterações no stack |
| `vuln-changes.txt` | Mudanças em vulns | Novas/corrigidas vulnerabilidades |

### 📂 `monitoring/new-subdomains/`
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `new-subdomains.txt` | Novos subdomínios | Subdomínios descobertos recentemente |
| `new-subdomain-analysis.txt` | Análise de novos | Análise dos novos subdomínios |

### 📄 `monitoring/` (Arquivos principais)
| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `monitoring-summary.txt` | Resumo do monitoramento | Estatísticas de mudanças |
| `baseline.json` | Baseline inicial | Estado inicial para comparação |

---

## 📋 ARQUIVOS PRINCIPAIS (Raiz do output/)

| Arquivo | Descrição | Importância | Conteúdo |
|---------|-----------|-------------|----------|
| `live-hosts.txt` | **🎯 CRÍTICO** | ⭐⭐⭐⭐⭐ | Todos os hosts que respondem HTTP/HTTPS |
| `all-discovered-urls.txt` | **🎯 CRÍTICO** | ⭐⭐⭐⭐⭐ | Todas as URLs descobertas |
| `all-fuzzing-results.txt` | **🎯 CRÍTICO** | ⭐⭐⭐⭐ | Todos os resultados de content discovery |
| `javascript-endpoints.txt` | **🎯 ALTO** | ⭐⭐⭐⭐ | Endpoints extraídos de JavaScript |
| `javascript-urls.txt` | **🎯 ALTO** | ⭐⭐⭐⭐ | URLs extraídas de JavaScript |
| `subdomains-all.txt` | **🎯 ALTO** | ⭐⭐⭐⭐ | Lista final de todos os subdomínios |
| `vulnerabilities.txt` | **🎯 CRÍTICO** | ⭐⭐⭐⭐⭐ | Consolidação de todas as vulnerabilidades |
| `unique-hosts.txt` | **🎯 MÉDIO** | ⭐⭐⭐ | Hostnames únicos descobertos |

---

## 📁 LOGS E CONTROLE (log/)

| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `nina-recon.log` | Log principal | Log completo da execução |
| `errors.log` | Log de erros | Erros encontrados durante execução |
| `performance.log` | Métricas de performance | Tempos de execução, recursos |
| `notifications.log` | Log de notificações | Notificações Slack enviadas |
| `modules-execution.log` | Execução de módulos | Status de cada módulo |

---

## 📸 SCREENSHOTS (screenshots/)

| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `{hostname}-80.png` | Screenshot HTTP | Captura da página em HTTP |
| `{hostname}-443.png` | Screenshot HTTPS | Captura da página em HTTPS |
| `{hostname}-{port}.png` | Screenshots customizados | Outras portas descobertas |

---

## 📝 NOTAS MANUAIS (manual/)

| Arquivo | Descrição | Conteúdo |
|---------|-----------|----------|
| `findings.txt` | Descobertas manuais | Anotações do analista |
| `todo.txt` | Lista de tarefas | Próximos passos |
| `interesting-urls.txt` | URLs interessantes | URLs que merecem investigação |
| `notes.txt` | Notas gerais | Observações durante o teste |

---

## 🎯 ARQUIVO DE CONFIGURAÇÃO (.nina-config.json)

```json
{
    "target": "example.com",
    "scope": "closed",
    "profile": "standard",
    "execution_time": "2025-01-15 10:30:00",
    "modules_executed": ["setup", "passive", "active", "httpx", "fuzzing"],
    "statistics": {
        "subdomains_found": 156,
        "urls_discovered": 2341,
        "vulnerabilities": 12
    }
}
```

---

## 📊 RESUMO DE PRIORIDADES

### 🔥 **ARQUIVOS CRÍTICOS** (Verificar primeiro)
1. `live-hosts.txt` - Hosts ativos
2. `vulnerabilities.txt` - Vulnerabilidades encontradas
3. `all-discovered-urls.txt` - URLs descobertas
4. `javascript-endpoints.txt` - Endpoints JavaScript

### ⚡ **ARQUIVOS IMPORTANTES** (Verificar segundo)
1. `subdomains-all.txt` - Todos subdomínios
2. `all-fuzzing-results.txt` - Resultados de fuzzing
3. `vulnerability-summary.txt` - Resumo de vulnerabilidades
4. `technology-summary.txt` - Tecnologias detectadas

### 📋 **ARQUIVOS DE SUPORTE**
1. Logs de execução
2. Screenshots
3. Análises específicas por ferramenta
4. Dados brutos para investigação posterior

---

*📅 Última atualização: $(date)*  
*🔢 Total de tipos de arquivos: 150+*  
*📁 Estrutura baseada em: NINA Recon Optimized v2.0.0*
