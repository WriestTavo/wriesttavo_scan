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
FINDINGS=()          # Array de hallazgos para el reporte

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
    echo
}

# ─── MÓDULO 2: PORT DISCOVERY ───────────────────────────────────
modulo_port_scan() {
    log "MÓDULO 2: Port Discovery (SYN Scan)"

    local min_rate=3000
    local extra_flags="-n -Pn"
    [[ "$SCAN_MODE" == "stealth" ]]     && min_rate=200  && extra_flags="-n -Pn -T2"
    [[ "$SCAN_MODE" == "aggressive" ]]  && min_rate=5000 && extra_flags="-n -Pn -T5"

    local cmd="nmap ${extra_flags} -sS --open -p- --min-rate ${min_rate} ${TARGET}"
    cmd_show "$cmd"

    local nmap_out
    nmap_out=$(nmap ${extra_flags} -sS --open -p- --min-rate ${min_rate} "${TARGET}" 2>/dev/null)

    local puertos_nl
    puertos_nl=$(echo "${nmap_out}" | grep '^[0-9]' | cut -d'/' -f1)

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
    else
        ok "No se detectó WAF."
        add_finding "INFO" "WAF" "No se detectó WAF activo. El target puede ser más permisivo."
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

    # Detectar wordlist disponible
    local wordlist="/usr/share/wordlists/dirb/common.txt"
    [[ -f "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" ]] && \
        wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"

    if [[ ! -f "$wordlist" ]]; then
        warn "Wordlist no encontrada. Instala: sudo apt install seclists dirb"
        return
    fi

    local proto="http"
    local port="${WEB_PORTS[0]}"
    [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
    local url="${ORIGINAL_URL:-${proto}://${TARGET}:${port}}"
    local output_file="${OUTPUT_DIR}/web/gobuster_${port}.txt"

    cmd_show "gobuster dir -u ${url} -w ${wordlist} -t 30 -x php,html,txt,bak,old,zip -o ${output_file} -q"

    gobuster dir -u "${url}" \
        -w "${wordlist}" \
        -t 30 \
        -x php,html,txt,bak,old,zip,js,json,config,conf,xml,asp,aspx \
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
    fi
    echo
}

# ─── REPORTE HTML PROFESIONAL ────────────────────────────────────
generar_reporte_html() {
    log "Generando Reporte HTML Profesional..."

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

        findings_html+="
        <div class='finding finding-$(echo $severity | tr '[:upper:]' '[:lower:]' | tr 'Á' 'a' | sed 's/ítico/itico/g' | sed 's/é/e/g' | sed 's/ó/o/g')'>
            <div class='finding-header'>
                <span class='badge' style='background:${color};'>${severity}</span>
                <span class='finding-title'>${title}</span>
            </div>
            <div class='finding-detail'>${detail}</div>
        </div>"
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
    echo -e "  ${C_GRN}[6]${C_RST} Custom (elegir módulos)"
    echo
    echo -ne "${C_YEL}Opción [1-6]: ${C_RST}"
    read -r opcion

    case "$opcion" in
        1) run_full_scan ;;
        2) modulo_ttl_os; modulo_port_scan; modulo_version_scan; modulo_smb ;;
        3) modulo_waf; modulo_http_headers; modulo_whatweb; modulo_nikto; modulo_gobuster ;;
        4) modulo_ttl_os; modulo_port_scan; modulo_version_scan; modulo_waf; modulo_http_headers; modulo_whatweb; modulo_nikto; modulo_gobuster; modulo_subdominios ;;
        5) modulo_port_scan; modulo_version_scan; modulo_vuln_scan; modulo_searchsploit ;;
        6) menu_custom ;;
        *) warn "Opción inválida. Ejecutando Full Scan."; run_full_scan ;;
    esac
}

menu_custom() {
    local modulos=("ttl" "ports" "version" "waf" "headers" "whatweb" "nikto" "gobuster" "subdominios" "smb" "vulns" "searchsploit")
    echo
    echo -e "Módulos disponibles (escribe los números separados por espacio):"
    echo -e "  1) TTL/OS    2) Port Scan   3) Version Scan  4) WAF"
    echo -e "  5) HTTP Headers  6) WhatWeb  7) Nikto  8) Gobuster"
    echo -e "  9) Subdominios  10) SMB   11) Vuln Scan  12) Searchsploit"
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
