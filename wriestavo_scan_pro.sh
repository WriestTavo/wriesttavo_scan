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

# ─── ESTADO INTELIGENTE COMPARTIDO ──────────────────────────────
# Cada módulo escribe aquí sus descubrimientos.
# Módulos posteriores leen esto y ajustan su comportamiento.
INTEL_OS=""                  # linux | windows | unknown
INTEL_WAF_DETECTED=false     # true si hay WAF activo
INTEL_WAF_NAME=""            # Nombre del WAF
INTEL_CMS=""                 # wordpress | joomla | drupal | ""
INTEL_FRAMEWORK_JS=""        # react | angular | vue | nextjs | ""
INTEL_SERVICES=()            # "puerto:servicio:version"
INTEL_INJECTABLE_URLS=()     # URLs con parámetros GET para SQLi/XSS
INTEL_API_ENDPOINTS=()       # Endpoints API encontrados por JS/ffuf
INTEL_SENSITIVE_PATHS=()     # Rutas sensibles encontradas
INTEL_TECHNOLOGIES=()        # php, nodejs, python, java...
INTEL_SUBDOMAINS=()          # Subdominios encontrados
INTEL_SQLI_FOUND=false
INTEL_XSS_FOUND=false
INTEL_GRAPHQL_URL=""
INTEL_SWAGGER_URL=""
INTEL_JS_SECRETS=()
INTEL_WORDLIST_EXTRA=""      # Wordlist específica según CMS/tech
INTEL_SCAN_DELAY=0           # Delay entre requests (se ajusta con WAF)
INTEL_NIKTO_FINDINGS=""

intel_log() {
    echo -e "${C_PUR}  [INTEL]${C_RST} $1"
}

trap 'echo -e "\n\n${C_YEL}[!] Abortado por el usuario.${C_RST}"; exit 1' INT

# ─── UTILS ──────────────────────────────────────────────────────
log()    { echo -e "${C_BLU}[*]${C_RST} $1"; }
ok()     { echo -e "${C_GRN}[+]${C_RST} $1"; }
warn()   { echo -e "${C_YEL}[!]${C_RST} $1"; }
err()    { echo -e "${C_RED}[-]${C_RST} $1"; }
tip()    { echo -e "${C_PUR}[TIP]${C_RST} $1"; }
cmd_show(){ echo -e "  ${C_DIM}CMD:${C_RST} ${C_CYN}$1${C_RST}\n"; }

add_finding() {
    # add_finding "SEVERIDAD" "TÍTULO" "DETALLE"
    FINDINGS+=("$1|||$2|||$3")
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
            grep -qi "java\|tomcat\|jboss\|spring" "$nmap_txt" && INTEL_TECHNOLOGIES+=("java") && intel_log "Java/Tomcat detectado"
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
        echo "$ww_out" | grep -qi "react\|next.js\|nuxt\|gatsby" && INTEL_TECHNOLOGIES+=("spa") && intel_log "SPA detectada → módulo JS analizará bundles"
        echo "$ww_out" | grep -qi "jquery"     && INTEL_TECHNOLOGIES+=("jquery")
        echo "$ww_out" | grep -qi "bootstrap"  && INTEL_TECHNOLOGIES+=("bootstrap")
        echo "$ww_out" | grep -qi "x-powered-by.*asp\|asp.net" && INTEL_TECHNOLOGIES+=("aspnet") && intel_log "ASP.NET detectado → buscar viewstate, RCE payloads"

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
    intel_summary_html+="</div></div>"

    local critical_count=0 high_count=0 medium_count=0 low_count=0 info_count=0
    local findings_html=""

    for finding in "${FINDINGS[@]}"; do
        local severity title detail
        severity=$(echo "$finding" | cut -d'|' -f1)
        title=$(echo "$finding" | cut -d'|' -f4)
        detail=$(echo "$finding" | cut -d'|' -f7)

        case "$severity" in
            "CRÍTICO") ((critical_count++)); color="#ff2d2d" ;;
            "ALTO")    ((high_count++));     color="#ff6b35" ;;
            "MEDIO")   ((medium_count++));   color="#ffd23f" ;;
            "BAJO")    ((low_count++));      color="#57cc99" ;;
            *)         ((info_count++));     color="#5bc0de" ;;
        esac

        local sev_class
        sev_class=$(echo "$severity" | tr '[:upper:]' '[:lower:]' | \
            sed 's/ítico/itico/g; s/é/e/g; s/ó/o/g; s/ /_/g')
        findings_html+="<div class='finding finding-${sev_class}'>"
        findings_html+="<div class='finding-header'>"
        findings_html+="<span class='badge' style='background:${color};'>${severity}</span>"
        findings_html+="<span class='finding-title'>${title}</span>"
        findings_html+="</div>"
        findings_html+="<div class='finding-detail'>${detail}</div>"
        findings_html+="</div>"

    done

    cat > "${REPORT_FILE}" << HTMLEOF
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WriestTavo Report :: ${TARGET}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #161b22 0%, #1f2937 100%); padding: 30px; border-bottom: 2px solid #30363d; }
        .header h1 { color: #58a6ff; font-size: 28px; margin-bottom: 5px; }
        .header .subtitle { color: #8b949e; font-size: 14px; }
        .header .meta { display: flex; gap: 20px; margin-top: 15px; flex-wrap: wrap; }
        .meta-item { background: #21262d; padding: 8px 15px; border-radius: 6px; border: 1px solid #30363d; font-size: 13px; }
        .meta-item span { color: #58a6ff; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        /* Summary Cards */
        .summary { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
        .card { flex: 1; min-width: 120px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }
        .card .count { font-size: 36px; font-weight: bold; }
        .card .label { font-size: 12px; color: #8b949e; margin-top: 5px; text-transform: uppercase; letter-spacing: 1px; }
        .card.critical { border-top: 3px solid #ff2d2d; } .card.critical .count { color: #ff2d2d; }
        .card.high     { border-top: 3px solid #ff6b35; } .card.high .count { color: #ff6b35; }
        .card.medium   { border-top: 3px solid #ffd23f; } .card.medium .count { color: #ffd23f; }
        .card.low      { border-top: 3px solid #57cc99; } .card.low .count { color: #57cc99; }
        .card.info     { border-top: 3px solid #5bc0de; } .card.info .count { color: #5bc0de; }

        /* Findings */
        .section-title { font-size: 20px; color: #58a6ff; margin: 25px 0 15px; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
        .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
        .finding-header { display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; user-select: none; }
        .finding-header:hover { background: #1f2937; }
        .badge { padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #000; min-width: 70px; text-align: center; }
        .finding-title { font-weight: 600; font-size: 15px; color: #e6edf3; }
        .finding-detail { padding: 15px 16px; background: #0d1117; border-top: 1px solid #30363d; font-size: 13px; }
        pre { background: #161b22; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px; color: #7ee787; }
        
        /* Files */
        .files-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px; margin-top: 15px; }
        .file-item { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; font-size: 13px; }
        .file-item a { color: #58a6ff; text-decoration: none; }
        .file-item a:hover { text-decoration: underline; }
        
        .footer { text-align: center; padding: 20px; color: #484f58; font-size: 12px; margin-top: 40px; border-top: 1px solid #21262d; }
        /* Intel Summary Box */
        .intel-box { background: #0d1117; border: 1px solid #1f6feb; border-radius: 8px; padding: 16px 20px; margin: 20px 0; }
        .intel-box h3 { color: #58a6ff; margin-bottom: 12px; font-size: 16px; }
        .intel-grid { display: flex; flex-wrap: wrap; gap: 10px; }
        .intel-item { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 6px 12px; font-size: 13px; }
        .intel-label { color: #8b949e; margin-right: 6px; }
        .intel-val { color: #e6edf3; font-weight: 600; }
        
        /* Vuln Tables */
        .vuln-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }
        .vuln-table th { background: #21262d; color: #8b949e; padding: 8px 10px; text-align: left; border: 1px solid #30363d; }
        .vuln-table td { padding: 7px 10px; border: 1px solid #21262d; vertical-align: top; word-break: break-all; }
        .vuln-table tr:hover td { background: #161b22; }
        td.critical, td.crítico { color: #ff2d2d; font-weight: bold; }
        td.high, td.alto { color: #ff6b35; font-weight: bold; }
        td.medium, td.medio { color: #ffd23f; font-weight: bold; }
        td.low, td.bajo { color: #57cc99; }
        td.vuln { color: #ff6b35; font-weight: bold; }
        
        /* Collapse toggle */
        .finding-detail { display: block; }
    </style>
</head>
<body>
<div class="header">
    <div class="container">
        <h1>⚡ WriestTavo Security Report</h1>
        <p class="subtitle">Generado por WriestTavo v2.0 :: WRIΞSTTAV0</p>
        <div class="meta">
            <div class="meta-item">Target: <span>${TARGET}</span></div>
            <div class="meta-item">Fecha: <span>${TIMESTAMP}</span></div>
            <div class="meta-item">Modo: <span>${SCAN_MODE}</span></div>
        </div>
    </div>
</div>

<div class="container">
    ${intel_summary_html}
    <h2 class="section-title">📊 Resumen Ejecutivo</h2>
    <div class="summary">
        <div class="card critical"><div class="count">${critical_count}</div><div class="label">Crítico</div></div>
        <div class="card high">    <div class="count">${high_count}</div>    <div class="label">Alto</div></div>
        <div class="card medium">  <div class="count">${medium_count}</div>  <div class="label">Medio</div></div>
        <div class="card low">     <div class="count">${low_count}</div>     <div class="label">Bajo</div></div>
        <div class="card info">    <div class="count">${info_count}</div>    <div class="label">Info</div></div>
    </div>

    <h2 class="section-title">🔍 Hallazgos Detallados</h2>
    ${findings_html}

    <h2 class="section-title">📁 Archivos Generados</h2>
    <div class="files-grid">
        $(find "${OUTPUT_DIR}" -type f ! -name "*.html" 2>/dev/null | sort | while read f; do
            echo "<div class='file-item'><a href='${f}'>${f}</a></div>"
        done)
    </div>

    <div class="footer">
        WriestTavo v2.0 by WRIΞSTTAV0 &nbsp;|&nbsp; Solo para uso en sistemas con autorización explícita &nbsp;|&nbsp; ${TIMESTAMP}
    </div>
</div>
</body>
</html>
HTMLEOF

    ok "Reporte generado: ${C_YEL}${REPORT_FILE}${C_RST}"
}

# ─── MENÚ INTERACTIVO ───────────────────────────────────────────
menu_modulos() {
    echo -e "${C_BLU}╔══════════════════════════════════════╗${C_RST}"
    echo -e "${C_BLU}║     Selecciona módulos a ejecutar    ║${C_RST}"
    echo -e "${C_BLU}╚══════════════════════════════════════╝${C_RST}"
    echo
    echo -e "  ${C_GRN}[1]${C_RST} Full Scan (todos los módulos)"
    echo -e "  ${C_GRN}[2]${C_RST} Recon + Ports + Services (sin web)"
    echo -e "  ${C_GRN}[3]${C_RST} Web-Only (headers, nikto, gobuster, whatweb)"
    echo -e "  ${C_GRN}[4]${C_RST} Bug Bounty Pack (recon + web + subdominios)"
    echo -e "  ${C_GRN}[5]${C_RST} Vuln Scan + Searchsploit"
    echo -e "  ${C_GRN}[6]${C_RST} Injection Pack (SQLi + XSS + Endpoints + JS)"
    echo -e "  ${C_GRN}[7]${C_RST} Custom (elegir módulos)"
    echo
    echo -ne "${C_YEL}Opción [1-7]: ${C_RST}"
    read -r opcion

    case "$opcion" in
        1) run_full_scan ;;
        2) modulo_ttl_os; modulo_port_scan; modulo_version_scan; modulo_smb ;;
        3) modulo_waf; modulo_http_headers; modulo_whatweb; modulo_nikto; modulo_gobuster ;;
        4) modulo_ttl_os; modulo_port_scan; modulo_version_scan; modulo_waf; modulo_http_headers; modulo_whatweb; modulo_nikto; modulo_gobuster; modulo_subdominios ;;
        5) modulo_port_scan; modulo_version_scan; modulo_vuln_scan; modulo_searchsploit ;;
        6) modulo_waf; modulo_http_headers; modulo_sqli; modulo_xss; modulo_endpoints; modulo_js_analysis ;;
        7) menu_custom ;;
        *) warn "Opción inválida. Ejecutando Full Scan."; run_full_scan ;;
    esac
}

menu_custom() {
    echo
    echo -e "Módulos disponibles (escribe los números separados por espacio):"
    echo -e "  1) TTL/OS      2) Port Scan    3) Version Scan   4) WAF"
    echo -e "  5) HTTP Headers  6) WhatWeb    7) Nikto          8) Gobuster"
    echo -e "  9) Subdominios  10) SMB        11) Vuln Scan    12) Searchsploit"
    echo -e " 13) SQLi         14) XSS        15) Endpoints    16) JS Analysis"
    echo
    echo -ne "${C_YEL}Selección: ${C_RST}"
    read -r seleccion

    for num in $seleccion; do
        case "$num" in
            1)  modulo_ttl_os ;;
            2)  modulo_port_scan ;;
            3)  modulo_version_scan ;;
            4)  modulo_waf ;;
            5)  modulo_http_headers ;;
            6)  modulo_whatweb ;;
            7)  modulo_nikto ;;
            8)  modulo_gobuster ;;
            9)  modulo_subdominios ;;
            10) modulo_smb ;;
            11) modulo_vuln_scan ;;
            12) modulo_searchsploit ;;
            13) modulo_sqli ;;
            14) modulo_xss ;;
            15) modulo_endpoints ;;
            16) modulo_js_analysis ;;
        esac
    done
}

run_full_scan() {
    modulo_ttl_os
    modulo_port_scan
    modulo_version_scan
    modulo_waf
    modulo_http_headers
    modulo_whatweb
    modulo_nikto
    modulo_gobuster
    modulo_subdominios
    modulo_smb
    modulo_vuln_scan
    modulo_searchsploit
    modulo_sqli
    modulo_xss
    modulo_endpoints
    modulo_js_analysis
}

# ─── HELP ───────────────────────────────────────────────────────
show_help() {
    echo
    echo -e "${C_BOLD}WriestTavo v2.0${C_RST} :: Pentesting & Bug Bounty Scanner"
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
