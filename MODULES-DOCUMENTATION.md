# 📋 **NINA RECON - Documentação Completa dos Módulos**

## 🎯 **Visão Geral**

O NINA Recon é um framework modular de reconhecimento para bug bounty, organizado em módulos especializados que trabalham de forma integrada para fornecer reconhecimento abrangente de alvos.

---

## 🔍 **MÓDULO: RECONNAISSANCE PASSIVO**
**Arquivo:** `modules/recon/passive.sh`

### 🛠️ **Ferramentas Utilizadas:**
- **Subfinder** - Descoberta via APIs e DNS
- **Assetfinder** - Descoberta via fontes públicas
- **Findomain** - Descoberta via múltiplas fontes
- **Amass** - Inteligência OSINT avançada
- **crt.sh** - Certificate Transparency logs
- **Shodan** - Engine de busca para dispositivos
- **Wayback Machine** - Arquivo histórico da internet

### 🎯 **Funcionalidades Principais:**

#### **1. 🌐 Descoberta via Certificate Transparency (`crt_subdomains()`)**
**O que faz:**
- Consulta logs de Certificate Transparency
- Extrai subdomínios de certificados SSL/TLS
- Busca certificados históricos e atuais

**Arquivos gerados:**
- `recon/passive/crt-subdomains.txt`

#### **2. 🔍 Subfinder Discovery (`subfinder_enum()`)**
**O que faz:**
- Utiliza múltiplas APIs (VirusTotal, SecurityTrails, etc.)
- Descoberta passiva sem interação com o alvo
- Rate limiting inteligente para evitar bloqueios

**Configurações por escopo:**
- **Closed**: Timeout 15s, sources específicas
- **Wildcard**: Timeout 20s, all sources
- **Open**: Timeout 25s, aggressive mode

**Arquivos gerados:**
- `recon/passive/subfinder-subdomains.txt`

#### **3. 🎯 Assetfinder Discovery (`assetfinder_enum()`)**
**O que faz:**
- Busca em múltiplas fontes públicas
- Descobre assets relacionados
- Cross-references com outras fontes

**Arquivos gerados:**
- `recon/passive/assetfinder-subdomains.txt`

#### **4. 🌍 Amass OSINT (`amass_enum()`)**
**O que faz:**
- Inteligência OSINT avançada
- Descoberta de relacionamentos entre domains
- Análise de infraestrutura

**Arquivos gerados:**
- `recon/passive/amass-subdomains.txt`

#### **5. 📊 Shodan Intelligence (`shodan_enum()`)**
**O que faz:**
- Busca dispositivos e serviços expostos
- Identifica portas e serviços abertos
- Coleta informações de infraestrutura

**Arquivos gerados:**
- `recon/passive/shodan-subdomains.txt`
- `recon/passive/shodan-ips.txt`

### 📊 **Estrutura de Saída:**
```
recon/passive/
├── crt-subdomains.txt           # Certificate Transparency
├── subfinder-subdomains.txt     # Subfinder results
├── assetfinder-subdomains.txt   # Assetfinder results
├── amass-subdomains.txt         # Amass OSINT
├── shodan-subdomains.txt        # Shodan discovery
├── shodan-ips.txt              # IPs descobertos
└── passive-summary.txt         # Resumo consolidado
```

**Arquivo consolidado:** `recon/subdomains-passive.txt`

---

## 🔨 **MÓDULO: RECONNAISSANCE ATIVO**
**Arquivo:** `modules/recon/active.sh`

### 🛠️ **Ferramentas Utilizadas:**
- **PureDNS** - Validação DNS em massa
- **ShuffleDNS** - Bruteforce DNS otimizado
- **DNSGen** - Geração de mutações
- **AltDNS** - Permutações de subdomínios
- **dnsx** - Validação DNS rápida

### 🎯 **Funcionalidades Principais:**

#### **1. 🌐 Wildcard Detection (`wildcard_detection()`)**
**O que faz:**
- Detecta respostas wildcard DNS
- Gera subdomínios aleatórios para teste
- Cria filtros para wildcards

**Arquivos gerados:**
- `recon/active/wildcards/wildcard-config.json`
- `recon/active/wildcards/wildcard-ips.txt`

#### **2. 💥 DNS Bruteforce (`dns_bruteforce_puredns()`, `dns_bruteforce_shuffledns()`)**
**O que faz:**
- Bruteforce DNS em massa com wordlists
- Resolução paralela com múltiplos threads
- Filtragem de wildcards automática

**Configurações por escopo:**
- **Closed**: 500 threads, 10k limit
- **Wildcard**: 10k threads, 200k limit
- **Open**: 5k threads, 100k limit

**Arquivos gerados:**
- `recon/active/bruteforce/puredns-filtered.txt`
- `recon/active/bruteforce/shuffledns-filtered.txt`

#### **3. 🧬 Subdomain Mutations (`subdomain_mutations()`)**
**O que faz:**
- Gera mutações inteligentes baseadas em padrões
- Usa DNSGen e AltDNS para variações
- Resolve mutações com validação DNS

**Arquivos gerados:**
- `recon/active/mutations/dnsgen-resolved.txt`
- `recon/active/mutations/altdns-resolved.txt`
- `recon/active/mutations/custom-resolved.txt`

#### **4. 🔄 Zone Transfer Attempts (`zone_transfer_attempts()`)**
**O que faz:**
- Tenta transferências de zona DNS
- Testa todos os nameservers encontrados
- Extrai registros DNS completos

**Arquivos gerados:**
- `recon/active/zone_transfers/axfr-[nameserver].txt`

#### **5. ✅ DNS Resolution Validation (`dns_resolution_validation()`)**
**O que faz:**
- Valida todos os subdomínios descobertos
- Remove entradas inválidas e wildcards
- Confirma resolução DNS atual

**Arquivos gerados:**
- `recon/active/dns_resolution/validated-subdomains.txt`

### 📊 **Estrutura de Saída:**
```
recon/active/
├── bruteforce/
│   ├── puredns-filtered.txt     # PureDNS results
│   └── shuffledns-filtered.txt  # ShuffleDNS results
├── mutations/
│   ├── dnsgen-resolved.txt      # DNSGen mutations
│   ├── altdns-resolved.txt      # AltDNS mutations
│   └── custom-resolved.txt      # Custom mutations
├── wildcards/
│   ├── wildcard-config.json     # Wildcard configuration
│   └── wildcard-ips.txt        # Wildcard IPs
├── zone_transfers/
│   └── axfr-*.txt              # Zone transfer results
└── dns_resolution/
    └── validated-subdomains.txt # Validated results
```

**Arquivo consolidado:** `recon/subdomains-active.txt`

---

## 🌐 **MÓDULO: HTTP PROBING**
**Arquivo:** `modules/probing/httpx.sh`

### 🛠️ **Ferramentas Utilizadas:**
- **HTTPX** - HTTP probing em massa
- **tlsx** - Análise de certificados SSL/TLS
- **nuclei** - Detecção de tecnologias

### 🎯 **Funcionalidades Principais:**

#### **1. 🚀 Basic HTTP Probing (`basic_http_probing()`)**
**O que faz:**
- Testa conectividade HTTP/HTTPS
- Identifica códigos de status
- Detecta redirecionamentos

**Configurações por escopo:**
- **Closed**: 1k threads, timeout 10s
- **Wildcard**: 50k threads, timeout 5s
- **Open**: 20k threads, timeout 8s

**Arquivos gerados:**
- `probing/basic/httpx-basic.txt`
- `probing/basic/live-urls.txt`

#### **2. 🔍 Technology Detection (`technology_detection()`)**
**O que faz:**
- Identifica tecnologias web (frameworks, CMS)
- Detecta servidores e versões
- Analisa headers HTTP

**Arquivos gerados:**
- `probing/technologies/technology-summary.txt`
- `probing/technologies/servers.txt`
- `probing/technologies/content-types.txt`

#### **3. 📜 Certificate Analysis (`certificate_analysis()`)**
**O que faz:**
- Analisa certificados SSL/TLS
- Extrai SANs para novos subdomínios
- Identifica problemas de certificados

**Arquivos gerados:**
- `probing/certificates/certificate-details.json`
- `probing/certificates/certificate-sans.txt`
- `probing/certificates/problematic-certificates.txt`

### 📊 **Estrutura de Saída:**
```
probing/
├── basic/
│   ├── httpx-basic.txt          # Resultados básicos
│   └── live-urls.txt           # URLs funcionais
├── technologies/
│   ├── technology-summary.txt   # Resumo de tecnologias
│   ├── servers.txt             # Servidores identificados
│   └── content-types.txt       # Tipos de conteúdo
├── certificates/
│   ├── certificate-details.json # Detalhes dos certificados
│   ├── certificate-sans.txt    # SANs extraídos
│   └── problematic-certificates.txt # Certificados problemáticos
└── probing-summary.txt         # Resumo consolidado
```

**Arquivo consolidado:** `live-hosts.txt`

---

## 🕷️ **MÓDULO: WEB CRAWLING**
**Arquivo:** `modules/discovery/crawler.sh`

### 🛠️ **Ferramentas Utilizadas:**
- **Katana** - Web crawler moderno
- **Waybackurls** - URLs do Wayback Machine
- **GAU** - GetAllURLs
- **GoSpider** - Spider em Go

### 🎯 **Funcionalidades Principais:**

#### **1. 🕸️ Katana Crawler (`katana_crawler()`)**
**O que faz:**
- Crawling profundo de aplicações web
- Extração de JavaScript endpoints
- Descoberta de URLs dinâmicas

**Configurações por escopo:**
- **Closed**: Depth 3, JS crawling enabled, 100 req/s
- **Wildcard**: Depth 2, JS crawling enabled, 200 req/s
- **Open**: Depth 1, JS crawling disabled, 300 req/s

**Arquivos gerados:**
- `discovery/crawl/katana-urls.txt`
- `discovery/api_endpoints/katana-api-endpoints.txt`
- `discovery/parameters/katana-parameters.txt`

#### **2. 📚 Wayback Discovery (`wayback_discovery()`)**
**O que faz:**
- Busca URLs históricas no Wayback Machine
- Descobre endpoints antigos e esquecidos
- Identifica mudanças na aplicação

**Arquivos gerados:**
- `discovery/crawl/wayback-urls.txt`
- `discovery/api_endpoints/wayback-api-endpoints.txt`

#### **3. 🌐 GetAllURLs (`gau_discovery()`)**
**O que faz:**
- Coleta URLs de múltiplas fontes
- Busca em Common Crawl, Wayback, etc.
- Filtra URLs relevantes

**Arquivos gerados:**
- `discovery/crawl/gau-urls.txt`

### 📊 **Estrutura de Saída:**
```
discovery/crawl/
├── katana-urls.txt             # URLs do Katana
├── wayback-urls.txt           # URLs históricas
├── gau-urls.txt              # URLs do GAU
└── all-crawled-urls.txt      # Todas as URLs
```

**Arquivo consolidado:** `all-urls.txt`

---

## 🔍 **MÓDULO: CONTENT FUZZING**
**Arquivo:** `modules/discovery/fuzzing.sh`

### 🛠️ **Ferramentas Utilizadas:**
- **FFUF** - Fast web fuzzer
- **Dirsearch** - Directory discovery
- **Feroxbuster** - Rust-based fuzzer
- **Gobuster** - Go-based fuzzer

### 🎯 **Funcionalidades Principais:**

#### **1. 📁 Directory Fuzzing (`directory_fuzzing()`)**
**O que faz:**
- Busca diretórios ocultos
- Testa múltiplas wordlists
- Descoberta recursiva

**Configurações por escopo:**
- **Closed**: 20 threads, 50 req/s, timeout 15s
- **Wildcard**: 30 threads, 75 req/s, timeout 12s
- **Open**: 50 threads, 150 req/s, timeout 8s

**Arquivos gerados:**
- `discovery/content/all-directories.txt`

#### **2. 📄 File Fuzzing (`file_fuzzing()`)**
**O que faz:**
- Busca arquivos específicos
- Testa extensões comuns
- Identifica arquivos sensíveis

**Arquivos gerados:**
- `discovery/content/all-files.txt`
- `discovery/files/interesting-files.txt`

#### **3. 🔧 Parameter Discovery (`parameter_discovery()`)**
**O que faz:**
- Descobre parâmetros GET/POST
- Testa injeção de parâmetros
- Identifica formulários ocultos

**Arquivos gerados:**
- `discovery/parameters/found-parameters.txt`

### 📊 **Estrutura de Saída:**
```
discovery/
├── content/
│   ├── all-directories.txt      # Diretórios encontrados
│   └── all-files.txt           # Arquivos encontrados
├── parameters/
│   └── found-parameters.txt    # Parâmetros descobertos
└── fuzzing-summary.txt         # Resumo dos resultados
```

**Arquivo consolidado:** `all-fuzzing-results.txt`

---

## 🔒 **MÓDULO: SENSITIVE FILES**
**Arquivo:** `modules/discovery/sensitive.sh`

### 🛠️ **Ferramentas Utilizadas:**
- **FFUF** - Fuzzing de endpoints
- **Gobuster** - Directory enumeration
- **Dirb** - Classic directory scanner

### 🎯 **Funcionalidades Principais:**

#### **1. 🎯 Sensitive Endpoints (`discover_sensitive_endpoints()`)**
**O que faz:**
- Busca endpoints administrativos
- Testa APIs e configurações
- Identifica painéis de controle

**Arquivos gerados:**
- `discovery/sensitive/endpoints/discovered-endpoints.txt`

#### **2. 📋 Configuration Analysis (`analyze_configuration_files()`)**
**O que faz:**
- Testa arquivos de configuração comuns
- Busca .env, config.php, etc.
- Identifica exposição de secrets

**Arquivos gerados:**
- `discovery/sensitive/configs/accessible-configs.txt`

#### **3. 🔍 Secret Search (`search_for_secrets()`)**
**O que faz:**
- Busca API keys expostas
- Identifica tokens de autenticação
- Procura credenciais hardcoded

**Arquivos gerados:**
- `discovery/sensitive/secrets/potential-secrets.txt`

### 📊 **Estrutura de Saída:**
```
discovery/sensitive/
├── endpoints/
│   └── discovered-endpoints.txt # Endpoints sensíveis
├── configs/
│   └── accessible-configs.txt   # Arquivos de config
├── secrets/
│   └── potential-secrets.txt    # Secrets encontrados
└── sensitive-summary.txt        # Resumo dos achados
```

**Arquivo consolidado:** `sensitive-files.txt`

---

## 📜 **MÓDULO: JAVASCRIPT ANALYSIS**
**Arquivo:** `modules/analysis/javascript.sh`

### 🛠️ **Ferramentas Utilizadas:**
- **LinkFinder** - Extração de endpoints de JS
- **SecretFinder** - Busca de secrets em JS
- **JSParser** - Análise de código JavaScript
- **GetJS** - Coleta de arquivos JS

### 🎯 **Funcionalidades Principais:**

#### **1. 🔗 Endpoint Extraction (`extract_js_endpoints()`)**
**O que faz:**
- Analisa arquivos JavaScript
- Extrai URLs e endpoints
- Identifica APIs ocultas

**Arquivos gerados:**
- `analysis/javascript/js-endpoints.txt`

#### **2. 🔐 Secret Detection (`find_js_secrets()`)**
**O que faz:**
- Busca API keys em código JS
- Identifica tokens expostos
- Procura credenciais hardcoded

**Arquivos gerados:**
- `analysis/javascript/js-secrets.txt`

#### **3. 📊 JS File Analysis (`analyze_js_files()`)**
**O que faz:**
- Mapeia arquivos JavaScript
- Identifica frameworks e bibliotecas
- Analisa estrutura da aplicação

**Arquivos gerados:**
- `analysis/javascript/js-files.txt`
- `analysis/javascript/js-analysis-summary.txt`

### 📊 **Estrutura de Saída:**
```
analysis/javascript/
├── js-endpoints.txt            # Endpoints extraídos
├── js-secrets.txt             # Secrets encontrados
├── js-files.txt              # Arquivos JS
└── js-analysis-summary.txt   # Resumo da análise
```

---

## 🚨 **MÓDULO: VULNERABILITY SCANNING**
**Arquivo:** `modules/scanning/vulnerabilities.sh`

### 🛠️ **Ferramentas Utilizadas:**
- **Nuclei** - Template-based scanner
- **tlsx** - SSL/TLS analysis
- **Custom scripts** - Verificações específicas

### 🎯 **Funcionalidades Principais:**

#### **1. 🎯 Nuclei Scanning (`run_nuclei_scans()`)**
**O que faz:**
- Executa templates de vulnerabilidades
- Categoriza por severidade
- Gera relatórios detalhados

**Categorias:**
- **Critical**: RCE, SQLi, etc.
- **High**: XSS, SSRF, etc.
- **Medium**: Information disclosure
- **Low**: Misconfigurations

**Arquivos gerados:**
- `vulnerabilities/nuclei/critical-vulns.txt`
- `vulnerabilities/nuclei/high-vulns.txt`
- `vulnerabilities/nuclei/medium-vulns.txt`
- `vulnerabilities/nuclei/low-vulns.txt`

#### **2. 🔒 SSL/TLS Checks (`ssl_tls_analysis()`)**
**O que faz:**
- Analisa configurações SSL/TLS
- Identifica certificados problemáticos
- Verifica configurações de segurança

**Arquivos gerados:**
- `vulnerabilities/ssl/certificate-issues.txt`
- `vulnerabilities/ssl/ssl-misconfigurations.txt`

### 📊 **Estrutura de Saída:**
```
vulnerabilities/
├── nuclei/
│   ├── critical-vulns.txt      # Vulnerabilidades críticas
│   ├── high-vulns.txt         # Alta severidade
│   ├── medium-vulns.txt       # Média severidade
│   └── low-vulns.txt          # Baixa severidade
├── ssl/
│   ├── certificate-issues.txt  # Problemas de certificado
│   └── ssl-misconfigurations.txt # Configurações SSL
└── vulnerability-summary.txt   # Resumo consolidado
```

**Arquivo consolidado:** `vulnerabilities.txt`

---

## 📊 **MÓDULO: CONTINUOUS MONITORING**
**Arquivo:** `modules/monitoring/continuous.sh`

### 🛠️ **Funcionalidades Principais:**

#### **1. 📋 Monitoring Setup (`setup_monitoring_config()`)**
**O que faz:**
- Configura monitoramento contínuo
- Cria scripts de automação
- Define intervalos de verificação

#### **2. 🖥️ Dashboard Creation (`create_monitoring_dashboard()`)**
**O que faz:**
- Gera dashboard HTML interativo
- Mostra estatísticas em tempo real
- Exibe mudanças detectadas

#### **3. 🔔 Alert System (`setup_monitoring_service()`)**
**O que faz:**
- Configura sistema de alertas
- Monitora mudanças significativas
- Envia notificações automáticas

### 📊 **Estrutura de Saída:**
```
monitoring/
├── configs/
│   └── monitor.conf           # Configuração do monitor
├── scripts/
│   ├── monitor.sh            # Script principal
│   ├── start-monitoring.sh   # Iniciar serviço
│   └── stop-monitoring.sh    # Parar serviço
├── snapshots/               # Snapshots históricos
├── changes/                # Mudanças detectadas
└── dashboard.html          # Dashboard web
```

---

## 🎯 **FLUXO DE EXECUÇÃO DOS MÓDULOS**

### **Quick Profile:**
1. `setup` → `passive` → `httpx`

### **Standard Profile:**
1. `setup` → `passive` → `active` → `httpx` → `crawler` → `fuzzing` → `vulns`

### **Deep Profile:**
1. `setup` → `passive` → `active` → `httpx` → `crawler` → `fuzzing` → `js` → `sensitive` → `vulns`

---

## 📈 **MÉTRICAS E RESULTADOS**

### **Arquivos Principais de Saída:**
- `recon/subdomains-all.txt` - Todos os subdomínios
- `live-hosts.txt` - Hosts ativos
- `all-urls.txt` - Todas as URLs descobertas
- `vulnerabilities.txt` - Vulnerabilidades encontradas
- `sensitive-files.txt` - Arquivos sensíveis

### **Estrutura Completa de Saída:**
```
output/DOMAIN/
├── 📁 recon/              # Reconnaissance results
├── 📁 probing/            # HTTP probing data
├── 📁 discovery/          # Content discovery
├── 📁 analysis/           # Advanced analysis
├── 📁 vulnerabilities/    # Security issues
├── 📁 monitoring/         # Continuous monitoring
├── 📁 log/               # Execution logs
├── 📄 live-hosts.txt     # Active hosts
├── 📄 all-urls.txt       # All discovered URLs
├── 📄 vulnerabilities.txt # All vulnerabilities
└── 📄 sensitive-files.txt # Sensitive content
```

---

## 🚀 **Como Usar**

```bash
# Executar módulo específico
./nina-recon.sh -d exemplo.com -m passive

# Executar múltiplos módulos
./nina-recon.sh -d exemplo.com -m passive,active,httpx

# Executar perfil completo
./nina-recon.sh -d exemplo.com -p deep

# Monitoramento contínuo
./nina-recon.sh -d exemplo.com --continuous
```

Cada módulo é independente mas se integra perfeitamente com os outros, criando um pipeline completo de reconhecimento para bug bounty! 🎯
