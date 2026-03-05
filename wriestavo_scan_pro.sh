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
# Colores ANSI — compatibles con echo, printf y variables
C_RST=$'\033[0m';  C_RED=$'\033[31m'; C_GRN=$'\033[32m'
C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_CYN=$'\033[36m'
C_PUR=$'\033[35m'; C_BOLD=$'\033[1m';  C_DIM=$'\033[2m'

# ─── CONFIGURACIÓN GLOBAL ───────────────────────────────────────
TARGET=""
OUTPUT_DIR="wriestTavo_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OPEN_PORTS_CSV=""
WEB_PORTS=()
SESSION_FILE=""
SESSION_LOADED=false
# ── Pipeline de port scanning progresivo ─────────────
WAVE2_PID=0;      WAVE3_PID=0
WAVE2_FILE="";    WAVE3_FILE=""
PORTS_WAVE1=();   PORTS_WAVE2=();  PORTS_WAVE3=()
PORTS_VERSION_DONE=()   # puertos ya procesados por version scan
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
    # Deduplicar: no agregar si ya existe mismo título+severidad
    local _dedup_key="${sev}|||${title}"
    local _e; for _e in "${FINDINGS[@]:-}"; do
        [[ "$_e" == "${_dedup_key}|||"* ]] && return
    done
    FINDINGS+=("${sev}|||${title}|||${detail}|||${cvss}|||${remediation}|||${next_step}")
    # Notificar hallazgo en vivo al sistema de progreso
    case "$sev" in
        CRÍTICO|ALTO) prog_hallazgo "$sev" "$title" ;;
    esac
}

is_domain() {
    [[ "$1" =~ ^[a-zA-Z] ]] && return 0 || return 1
}

is_web_port() {
    local p="$1"
    [[ "$p" == "80" || "$p" == "443" || "$p" == "8080" || "$p" == "8443" || "$p" == "8000" || "$p" == "8888" || "$p" == "8888" || "$p" == "3000" || "$p" == "5000" ]]
}

# ════════════════════════════════════════════════════════════════
# SISTEMA DE PROGRESO EN VIVO v2.0
# Muestra barra, spinner, módulo actual, tiempo y payloads en tiempo real
# ════════════════════════════════════════════════════════════════

# ── Variables de estado de progreso ─────────────────────────────
PROG_TOTAL=45          # total módulos a ejecutar
PROG_CURRENT=0         # módulo en curso (0-based)
PROG_MODULE_NAME=""    # nombre del módulo actual
PROG_MODULE_START=0    # timestamp inicio del módulo
PROG_SCAN_START=0      # timestamp inicio del scan completo
PROG_FASE=""           # fase actual
PROG_SPINNER_PID=0     # PID del spinner en background
PROG_LAST_ACTION=""    # última acción reportada (payload/test)
PROG_FINDINGS_SO_FAR=0 # hallazgos críticos/altos hasta ahora
PROG_STATUS_FILE="/tmp/.wriestavo_status_$$"  # archivo de estado IPC

# ── Colores ya definidos en el script principal ──────────────────
# C_RED C_GRN C_YEL C_BLU C_PUR C_CYN C_DIM C_RST C_BOLD (ya existen)

# ── Iniciar sistema de progreso ──────────────────────────────────
prog_init() {
    PROG_SCAN_START=$(date +%s)
    PROG_CURRENT=0
    # Detectar si el terminal soporta colores y tput
    PROG_HAS_TPUT=false
    command -v tput &>/dev/null && [[ -t 1 ]] && PROG_HAS_TPUT=true
    # Crear archivo de estado
    echo "INIT|$(date +%s)|${TARGET}" > "$PROG_STATUS_FILE"
    # Limpiar al salir
    trap '_prog_cleanup' EXIT INT TERM
}

_prog_cleanup() {
    _spinner_stop
    [[ -f "$PROG_STATUS_FILE" ]] && rm -f "$PROG_STATUS_FILE"
    # Restaurar cursor si lo ocultamos
    $PROG_HAS_TPUT && tput cnorm 2>/dev/null || true
}

# ── Calcular tiempo transcurrido ─────────────────────────────────
_elapsed() {
    local start_ts="${1:-$PROG_SCAN_START}"
    local now_ts; now_ts=$(date +%s)
    local secs=$(( now_ts - start_ts ))
    local h=$(( secs / 3600 ))
    local m=$(( (secs % 3600) / 60 ))
    local s=$(( secs % 60 ))
    (( h > 0 )) && printf "%dh%02dm%02ds" $h $m $s || printf "%dm%02ds" $m $s
}

# ── Barra de progreso visual ─────────────────────────────────────
_draw_progress_bar() {
    local current="${1:-$PROG_CURRENT}"
    local total="${2:-$PROG_TOTAL}"
    local bar_width=30
    local pct=0
    (( total > 0 )) && pct=$(( current * 100 / total ))
    local filled=$(( current * bar_width / total ))
    local empty=$(( bar_width - filled ))
    local bar=""
    # Filled part con gradiente de color
    local bar_color="$C_GRN"
    (( pct < 30 )) && bar_color="$C_BLU"
    (( pct >= 30 && pct < 70 )) && bar_color="$C_CYN"
    (( pct >= 70 )) && bar_color="$C_GRN"
    # Construir barra
    local bar="${bar_color}"
    local i
    for (( i=0; i<filled; i++ )); do bar+="█"; done
    for (( i=0; i<empty;  i++ )); do bar+="░"; done
    bar+="${C_RST}"
    printf "%s" "$bar"
}

# ── Header de fase ───────────────────────────────────────────────
prog_fase() {
    local fase_nombre="$1"
    local fase_num="${2:-}"
    PROG_FASE="$fase_nombre"
    _spinner_stop
    echo
    echo -e "${C_BLU}  ┌─────────────────────────────────────────────┐${C_RST}"
    echo -e "${C_BLU}  │ ${C_BOLD}⚡ ${fase_nombre}${C_RST}${C_BLU} $([ -n "$fase_num" ] && echo "— Fase ${fase_num}/7")$(printf '%*s' $((30 - ${#fase_nombre})) '') │${C_RST}"
    echo -e "${C_BLU}  └─────────────────────────────────────────────┘${C_RST}"
    echo
}

# ── Anuncio de módulo con barra de progreso ──────────────────────
prog_modulo() {
    local num="$1"     # número del módulo (ej: 6)
    local nombre="$2"  # nombre descriptivo (ej: "whatweb — Tech Fingerprinting")
    local total="${3:-$PROG_TOTAL}"

    _spinner_stop
    PROG_CURRENT="$num"
    PROG_MODULE_NAME="$nombre"
    PROG_MODULE_START=$(date +%s)
    PROG_LAST_ACTION=""

    # Actualizar archivo de estado
    echo "MODULE|$(date +%s)|${num}/${total}|${nombre}|${TARGET}" > "$PROG_STATUS_FILE"

    local bar; bar=$(_draw_progress_bar "$num" "$total")
    local elapsed; elapsed=$(_elapsed "$PROG_SCAN_START")
    local findings_badge=""
    (( PROG_FINDINGS_SO_FAR > 0 )) && findings_badge=" ${C_RED}[🎯 ${PROG_FINDINGS_SO_FAR} hallazgos]${C_RST}"

    echo
    echo -e "  ${C_DIM}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RST}"
    printf "  ${C_BLU}[*]${C_RST} ${C_BOLD}[%02d/%02d]${C_RST} %s\n" "$num" "$total" "$nombre"
    printf "  [%s] %s%s %s\n" \
        "$(printf '%02d%%' $(( num * 100 / total )))" \
        "$bar" \
        "$findings_badge" \
        "${C_DIM}⏱ ${elapsed}${C_RST}"
    echo -e "  ${C_DIM}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RST}"
}

# ── OK del módulo con tiempo ─────────────────────────────────────
prog_modulo_ok() {
    local extra_info="${1:-}"
    _spinner_stop
    local dur; dur=$(_elapsed "$PROG_MODULE_START")
    local msg="  ${C_GRN}[✓]${C_RST} ${C_BOLD}${PROG_MODULE_NAME}${C_RST} completado"
    [[ -n "$dur" ]] && msg+=" ${C_DIM}(${dur})${C_RST}"
    [[ -n "$extra_info" ]] && msg+=" → ${C_YEL}${extra_info}${C_RST}"
    echo -e "$msg"
}

# ── Spinner asíncrono para comandos lentos ───────────────────────
_spinner_loop() {
    local msg="$1"
    local delay=0.12
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    local elapsed_s=0
    local start_t; start_t=$(date +%s)

    # Ocultar cursor
    $PROG_HAS_TPUT && tput civis 2>/dev/null

    while true; do
        local now_t; now_t=$(date +%s)
        local secs=$(( now_t - start_t ))
        local m=$(( secs / 60 ))
        local s=$(( secs % 60 ))
        local time_str
        (( m > 0 )) && time_str="${m}m${s}s" || time_str="${s}s"

        # Leer última acción del archivo de estado
        local last_action=""
        if [[ -f "$PROG_STATUS_FILE" ]]; then
            local status_line
            status_line=$(tail -1 "$PROG_STATUS_FILE" 2>/dev/null)
            [[ "$status_line" == ACTION* ]] && last_action=" ${C_DIM}→ ${C_RST}"
        fi

        # Warning de tiempo si tarda mucho
        local time_color="$C_DIM"
        (( secs > 60 )) && time_color="$C_YEL"
        (( secs > 180 )) && time_color="$C_RED"

        printf "\r  ${C_CYN}%s${C_RST}  %-45s  [${time_color}⏱ %s${C_RST}]%s     " \
            "${frames[$i]}" "$msg" "$time_str" "$last_action"

        i=$(( (i+1) % ${#frames[@]} ))
        sleep "$delay"
    done
}

spinner_start() {
    local msg="${1:-Trabajando...}"
    # Matar spinner previo si quedó huérfano
    [[ ${PROG_SPINNER_PID:-0} -gt 0 ]] && kill "$PROG_SPINNER_PID" 2>/dev/null
    _SPINNER_PID=0; PROG_SPINNER_PID=0
    _spinner_loop "$msg" &
    PROG_SPINNER_PID=$!
    _SPINNER_PID=$PROG_SPINNER_PID
    # Sin disown — el trap EXIT necesita poder matarlo
}

_spinner_stop() {
    if [[ $PROG_SPINNER_PID -gt 0 ]]; then
        kill "$PROG_SPINNER_PID" 2>/dev/null
        wait "$PROG_SPINNER_PID" 2>/dev/null
        PROG_SPINNER_PID=0
        printf "\r%-80s\r" " "  # Limpiar la línea del spinner
        $PROG_HAS_TPUT && tput cnorm 2>/dev/null || true
    fi
}

# ── Reportar acción en curso (payload siendo probado, etc.) ──────
prog_accion() {
    # Escribe en el archivo de estado para que el spinner lo lea
    echo "ACTION|$1" >> "$PROG_STATUS_FILE"
    PROG_LAST_ACTION="$1"
}

# ── Reportar que se encontró algo (afecta hallazgo counter) ──────
prog_hallazgo() {
    local sev="$1"  # CRÍTICO | ALTO | MEDIO | BAJO
    local titulo="$2"
    _spinner_stop
    local icon="ℹ" color="$C_DIM"
    case "$sev" in
        CRÍTICO) icon="💀" color="$C_RED";   ((PROG_FINDINGS_SO_FAR++)) ;;
        ALTO)    icon="🔥" color="${C_YEL}";  ((PROG_FINDINGS_SO_FAR++)) ;;
        MEDIO)   icon="⚠" color="$C_YEL"  ;;
        BAJO)    icon="→" color="$C_GRN"   ;;
    esac
    echo -e "  ${color}${icon}  [${sev}]${C_RST} ${titulo}"
}

# ── Info de payload siendo probado ───────────────────────────────
prog_payload() {
    local tipo="$1"    # SQLi | XSS | LFI | SSRF
    local payload="$2" # el payload en sí (truncado a 50 chars)
    local url="${3:-}"
    local short_payload="${payload:0:55}"
    [[ ${#payload} -gt 55 ]] && short_payload+="…"
    prog_accion "${tipo}: ${short_payload}"
}

# ── Mostrar comando siendo ejecutado ─────────────────────────────
prog_cmd() {
    _spinner_stop
    local cmd="${1:0:90}"
    [[ ${#1} -gt 90 ]] && cmd+="…"
    echo -e "  ${C_DIM}▶ CMD: ${cmd}${C_RST}"
}

# ── Resumen final al terminar ────────────────────────────────────
prog_final() {
    _spinner_stop
    local total_time; total_time=$(_elapsed "$PROG_SCAN_START")
    local bar; bar=$(_draw_progress_bar "$PROG_TOTAL" "$PROG_TOTAL")
    echo
    echo -e "  ${C_GRN}┌──────────────────────────────────────────────────┐${C_RST}"
    echo -e "  ${C_GRN}│  ✅  SCAN COMPLETADO                              │${C_RST}"
    echo -e "  ${C_GRN}│  [100%] ${bar}  │${C_RST}"
    echo -e "  ${C_GRN}│  ⏱  Tiempo total : ${C_BOLD}${total_time}${C_RST}${C_GRN}$(printf '%*s' $((28 - ${#total_time})) '')│${C_RST}"
    echo -e "  ${C_GRN}│  🎯  Hallazgos   : ${C_BOLD}${#FINDINGS[@]}${C_RST}${C_GRN} (Crítico+Alto: ${PROG_FINDINGS_SO_FAR})$(printf '%*s' $((14 - ${#FINDINGS[@]})) '')│${C_RST}"
    echo -e "  ${C_GRN}└──────────────────────────────────────────────────┘${C_RST}"
    echo
}

# ── Wrapper para comandos lentos con spinner ─────────────────────
# Uso: run_with_spinner "Descripción" comando arg1 arg2...
run_with_spinner() {
    local desc="$1"; shift
    spinner_start "$desc"
    "$@"
    local exit_code=$?
    _spinner_stop
    return $exit_code
}


# ════════════════════════════════════════════════════════════════
# SISTEMA DE SESIÓN PERSISTENTE — .wtsession
#
#  Genera: target_fecha.wtsession  (bash sourceable + JSON embed)
#  Carga:  --session archivo.wtsession
#
#  Ciclo de vida:
#    Scan 1 → genera diablos.com.mx_20260304.wtsession
#    Scan 2 → --session diablos.com.mx_20260304.wtsession
#             → carga todo, salta lo conocido, prioriza payloads
#             → al terminar actualiza el mismo archivo
# ════════════════════════════════════════════════════════════════

SESSION_FILE=""           # path al .wtsession activo
SESSION_LOADED=false      # true si cargamos una sesión previa
SESSION_SKIP_MODULES=()   # módulos a saltarse (ya tienen resultado)
SESSION_NEW_FINDINGS=0    # hallazgos nuevos vs sesión anterior

# ── Variables que se RESTAURAN desde sesión ──────────────────────
# (se inicializan vacías, se llenan con session_load si hay archivo)
SES_PREV_PORTS=""
SES_PREV_STACK=()
SES_PREV_VULNS=()
SES_PREV_PARAMS=()
SES_PREV_FINDINGS_COUNT=0
SES_PRIORITY_SQLI=()
SES_PRIORITY_XSS=()
SES_PRIORITY_LFI=()
SES_PRIORITY_SSRF=()
SES_PREV_SUBDOMAINS=()
SES_PREV_HEADERS=()
SES_PREV_WAF=""
SES_PREV_OS=""
SES_PREV_SSL_OK=false
SES_SCAN_COUNT=0

# ════════════════════════════════════════════════════════════════
# CARGAR SESIÓN PREVIA
# ════════════════════════════════════════════════════════════════
session_load() {
    local ses_file="$1"
    [[ ! -f "$ses_file" ]] && { warn "Sesión no encontrada: $ses_file"; return 1; }

    SESSION_FILE="$ses_file"

    # ── Validar que la sesión corresponde al target actual ───────
    local ses_target
    ses_target=$(grep '^SES_TARGET=' "$ses_file" | head -1 | cut -d'"' -f2)
    if [[ -n "$ses_target" && -n "$TARGET" && "$ses_target" != "$TARGET" ]]; then
        echo -e "  ${C_YEL}[!] ADVERTENCIA: Sesión es de '${ses_target}' pero target actual es '${TARGET}'${C_RST}"
        echo -ne "  ${C_YEL}¿Continuar de todas formas? [s/N]: ${C_RST}"
        read -r confirm
        if [[ ! "${confirm,,}" =~ ^(s|si|y|yes)$ ]]; then
            warn "Sesión cancelada. Iniciando scan limpio."
            SESSION_FILE=""
            return 1
        fi
        warn "Cargando sesión de target diferente (${ses_target}) → datos pueden ser inexactos"
    fi

    SESSION_LOADED=true

    echo
    echo -e "  ${C_PUR}╔══════════════════════════════════════════════════════╗${C_RST}"
    echo -e "  ${C_PUR}║  📂 CARGANDO SESIÓN PREVIA                          ║${C_RST}"
    echo -e "  ${C_PUR}║  ${ses_file##*/}$(printf '%*s' $((51 - ${#ses_file##*/})) '')║${C_RST}"
    echo -e "  ${C_PUR}╚══════════════════════════════════════════════════════╝${C_RST}"

    # La sesión es un bash script sourceable — cargar variables
    source "$ses_file" 2>/dev/null || { warn "Error leyendo sesión"; return 1; }

    # Validar que el target de la sesión coincide con el target actual
    if [[ -n "$SES_TARGET" && "$SES_TARGET" != "$TARGET" ]]; then
        warn "⚠️  SESIÓN de target diferente: sesión=${SES_TARGET}, actual=${TARGET}"
        warn "   Cargando datos de contexto (ports/stack) pero ignorando payloads específicos"
        SES_PRIORITY_SQLI=(); SES_PRIORITY_XSS=(); SES_PRIORITY_LFI=(); SES_PRIORITY_SSRF=()
    fi

    # Las variables SES_* ya están cargadas por el source
    # Ahora aplicarlas al INTEL actual

    # ── Restaurar puertos conocidos ──────────────────────────────
    if [[ -n "$SES_PREV_PORTS" ]]; then
        OPEN_PORTS_CSV="$SES_PREV_PORTS"
        intel_log "Sesión: puertos conocidos → ${OPEN_PORTS_CSV}"
        ok "Puertos restaurados: ${C_YEL}${OPEN_PORTS_CSV}${C_RST} ${C_DIM}(de sesión previa — Wave 1 confirmará cambios)${C_RST}"
    fi

    # ── Restaurar stack tecnológico ──────────────────────────────
    if [[ ${#SES_PREV_STACK[@]} -gt 0 ]]; then
        for t in "${SES_PREV_STACK[@]}"; do
            [[ -n "$t" ]] && INTEL_TECHNOLOGIES+=("$t")
        done
        intel_log "Sesión: stack conocido → ${SES_PREV_STACK[*]}"
    fi

    # ── Restaurar OS, WAF ────────────────────────────────────────
    [[ -n "$SES_PREV_OS"  ]] && INTEL_OS="$SES_PREV_OS"
    [[ -n "$SES_PREV_WAF" ]] && { INTEL_WAF_DETECTED=true; INTEL_WAF_NAME="$SES_PREV_WAF"; }

    # ── Priorizar payloads exitosos (van al INICIO de la cola) ───
    if [[ ${#SES_PRIORITY_SQLI[@]} -gt 0 ]]; then
        INTEL_EXTRA_PAYLOADS_SQLI=("${SES_PRIORITY_SQLI[@]}" "${INTEL_EXTRA_PAYLOADS_SQLI[@]}")
        ok "Payloads SQLi exitosos previos: ${C_YEL}${#SES_PRIORITY_SQLI[@]}${C_RST} → al frente de la cola"
    fi
    if [[ ${#SES_PRIORITY_XSS[@]} -gt 0 ]]; then
        INTEL_EXTRA_PAYLOADS_XSS=("${SES_PRIORITY_XSS[@]}" "${INTEL_EXTRA_PAYLOADS_XSS[@]}")
        ok "Payloads XSS exitosos previos: ${C_YEL}${#SES_PRIORITY_XSS[@]}${C_RST} → al frente"
    fi
    if [[ ${#SES_PRIORITY_LFI[@]} -gt 0 ]]; then
        INTEL_EXTRA_PAYLOADS_LFI=("${SES_PRIORITY_LFI[@]}" "${INTEL_EXTRA_PAYLOADS_LFI[@]}")
        ok "Payloads LFI exitosos previos: ${C_YEL}${#SES_PRIORITY_LFI[@]}${C_RST} → al frente"
    fi
    if [[ ${#SES_PRIORITY_SSRF[@]} -gt 0 ]]; then
        INTEL_EXTRA_PAYLOADS_SSRF=("${SES_PRIORITY_SSRF[@]}" "${INTEL_EXTRA_PAYLOADS_SSRF[@]}")
        ok "Payloads SSRF exitosos previos: ${C_YEL}${#SES_PRIORITY_SSRF[@]}${C_RST} → al frente"
    fi

    # ── Determinar qué módulos SALTAR (ya tenemos resultado) ────
    _session_calc_skip_modules

    # Mostrar resumen de lo que sabemos vs lo que es nuevo
    echo
    echo -e "  ${C_DIM}┄ Sesión #${SES_SCAN_COUNT} — ${SES_PREV_FINDINGS_COUNT} hallazgos previos conocidos ┄${C_RST}"
    if [[ ${#SES_PREV_VULNS[@]} -gt 0 ]]; then
        echo -e "  ${C_RED}  Vulns confirmadas en scans anteriores: ${SES_PREV_VULNS[*]}${C_RST}"
    fi
    echo
}

# ── Calcular qué módulos saltarse ─────────────────────────────────
_session_calc_skip_modules() {
    SESSION_SKIP_MODULES=()

    # Si el SSL no cambió y fue OK, saltarlo
    [[ "$SES_PREV_SSL_OK" == "true" ]] && SESSION_SKIP_MODULES+=("sslscan")

    # Si conocemos los subdominios y no han pasado más de 7 días, saltar crt.sh
    if [[ ${#SES_PREV_SUBDOMAINS[@]} -gt 0 ]]; then
        # TODO: comparar fecha — por ahora siempre re-escanea subdominios
        : # SESSION_SKIP_MODULES+=("crtsh")
    fi

    if [[ ${#SESSION_SKIP_MODULES[@]} -gt 0 ]]; then
        intel_log "Sesión: módulos que se acelerarán por datos previos: ${SESSION_SKIP_MODULES[*]}"
    fi
}

# ── Verificar si un módulo debe saltarse ─────────────────────────
session_should_skip() {
    local modulo="$1"
    for m in "${SESSION_SKIP_MODULES[@]}"; do
        [[ "$m" == "$modulo" ]] && return 0  # 0 = true en bash
    done
    return 1  # 1 = false
}

# ════════════════════════════════════════════════════════════════
# GUARDAR SESIÓN AL TERMINAR
# ════════════════════════════════════════════════════════════════
session_save() {
    local outdir="${OUTPUT_DIR:-wriestTavo_results}"
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local safe_target; safe_target=$(echo "$TARGET" | tr '/:.' '_' | tr -cd '[:alnum:]_-')
    local ses_path="${outdir}/${safe_target}.wtsession"

    # Si cargamos una sesión previa, actualizar ESE mismo archivo
    [[ "$SESSION_LOADED" == "true" && -n "$SESSION_FILE" ]] && ses_path="$SESSION_FILE"

    local new_scan_num=$(( SES_SCAN_COUNT + 1 ))

    # ── Recolectar payloads exitosos de este scan ────────────────
    local eff_sqli=() eff_xss=() eff_lfi=() eff_ssrf=()
    for entry in "${EFFECTIVE_PAYLOADS[@]}"; do
        local tipo payload
        IFS='|||' read -r tipo payload _ _ <<< "$entry"
        case "${tipo,,}" in
            sqli) eff_sqli+=("$payload") ;;
            xss)  eff_xss+=("$payload")  ;;
            lfi)  eff_lfi+=("$payload")  ;;
            ssrf) eff_ssrf+=("$payload") ;;
        esac
    done

    # ── Merge con payloads previos (sesión cargada) ──────────────
    # Los nuevos van al frente (más relevantes), eliminar duplicados
    local merged_sqli=(); _merge_arrays merged_sqli eff_sqli[@] SES_PRIORITY_SQLI[@]
    local merged_xss=();  _merge_arrays merged_xss  eff_xss[@]  SES_PRIORITY_XSS[@]
    local merged_lfi=();  _merge_arrays merged_lfi  eff_lfi[@]  SES_PRIORITY_LFI[@]
    local merged_ssrf=(); _merge_arrays merged_ssrf eff_ssrf[@] SES_PRIORITY_SSRF[@]

    # ── Vulns acumuladas ─────────────────────────────────────────
    local vulns_this=()
    [[ "$INTEL_SQLI_FOUND"  == "true" ]] && vulns_this+=("SQLi")
    [[ "$INTEL_XSS_FOUND"   == "true" ]] && vulns_this+=("XSS")
    [[ "$INTEL_LFI_FOUND"   == "true" ]] && vulns_this+=("LFI")
    [[ "$INTEL_SSRF_FOUND"  == "true" ]] && vulns_this+=("SSRF")
    [[ "$INTEL_SSTI_FOUND"  == "true" ]] && vulns_this+=("SSTI")
    [[ "$INTEL_CORS_VULN"   == "true" ]] && vulns_this+=("CORS")
    [[ "$INTEL_XXE_FOUND"   == "true" ]] && vulns_this+=("XXE")
    [[ "$INTEL_IDOR_FOUND"  == "true" ]] && vulns_this+=("IDOR")
    # Merge con vulns previas
    local all_vulns=("${vulns_this[@]}" "${SES_PREV_VULNS[@]}")
    IFS=$'\n' read -r -d '' -a all_vulns < <(printf '%s\n' "${all_vulns[@]}" | sort -u && printf '\0')

    local total_findings=${#FINDINGS[@]}

    # ── Escribir el archivo .wtsession ───────────────────────────
    cat > "$ses_path" << SESFILE
#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  WriestTavo Session File — usar con: --session este_archivo  ║
# ║  Target  : ${TARGET}                                         
# ║  Scan #  : ${new_scan_num}                                   
# ║  Fecha   : $(date '+%Y-%m-%d %H:%M')                        
# ║  Hallazgos acumulados: ${total_findings}                     
# ╚══════════════════════════════════════════════════════════════╝
# NO editar manualmente — se regenera automáticamente en cada scan

# ── Metadata ─────────────────────────────────────────────────────
SES_TARGET="${TARGET}"
SES_SCAN_COUNT=${new_scan_num}
SES_LAST_SCAN="$(date '+%Y-%m-%d %H:%M')"
SES_FIRST_SCAN="${SES_FIRST_SCAN:-$(date '+%Y-%m-%d')}"
SES_PREV_FINDINGS_COUNT=${total_findings}

# ── Infraestructura ───────────────────────────────────────────────
SES_PREV_PORTS="${OPEN_PORTS_CSV}"
SES_PREV_OS="${INTEL_OS}"
SES_PREV_WAF="${INTEL_WAF_NAME}"
SES_PREV_SSL_OK="${SES_PREV_SSL_OK:-false}"

# ── Arrays — escritura segura con python3 (escapa comillas y chars especiales)
_write_bash_array() {
    # _write_bash_array VARNAME item1 item2 ...
    local varname="$1"; shift
    printf '%s=(' "$varname"
    for item in "$@"; do
        # Escapar comillas simples en el item
        local escaped="${item//\'/\'\\\'\'}"
        printf " '%s'" "$escaped"
    done
    printf ')\n'
}
$(_write_bash_array SES_PREV_STACK     "${INTEL_TECHNOLOGIES[@]}")
$(_write_bash_array SES_PREV_VULNS     "${all_vulns[@]}")
$(_write_bash_array SES_PREV_PARAMS    "${INTEL_INJECTABLE_URLS[@]:0:20}")
$(_write_bash_array SES_PREV_SUBDOMAINS "${INTEL_SUBDOMAINS[@]:0:50}")
$(_write_bash_array SES_PRIORITY_SQLI  "${merged_sqli[@]:0:15}")
$(_write_bash_array SES_PRIORITY_XSS   "${merged_xss[@]:0:15}")
$(_write_bash_array SES_PRIORITY_LFI   "${merged_lfi[@]:0:15}")
$(_write_bash_array SES_PRIORITY_SSRF  "${merged_ssrf[@]:0:15}")
$(_write_bash_array SES_PREV_ENDPOINTS "${INTEL_API_ENDPOINTS[@]:0:30}")
$(_write_bash_array SES_PREV_SENSITIVE "${INTEL_SENSITIVE_PATHS[@]:0:20}")

# ── Historial de hallazgos ────────────────────────────────────────
# $(date '+%Y-%m-%d %H:%M') | scan #${new_scan_num} | ${#vulns_this[@]} vulns | ${total_findings} hallazgos
# $([ "$SESSION_LOADED" == "true" ] && grep '^#.*scan #' "$SESSION_FILE" 2>/dev/null | tail -5)
SESFILE

    chmod +x "$ses_path"

    # ── Mostrar en pantalla ───────────────────────────────────────
    echo
    echo -e "  ${C_PUR}┌──────────────────────────────────────────────────────┐${C_RST}"
    echo -e "  ${C_PUR}│  💾 SESIÓN GUARDADA                                  │${C_RST}"
    echo -e "  ${C_PUR}│  ${ses_path##*/}$(printf '%*s' $((53 - ${#ses_path##*/})) '')│${C_RST}"
    echo -e "  ${C_PUR}│  Scan #${new_scan_num} | Vulns: ${all_vulns[*]} $(printf '%*s' $((35 - ${#all_vulns[*]})) '')│${C_RST}"
    echo -e "  ${C_PUR}│                                                      │${C_RST}"
    echo -e "  ${C_PUR}│  Próximo scan:                                       │${C_RST}"
    echo -e "  ${C_PUR}│  ${C_YEL}sudo ./wriestTavo.sh --session ${ses_path##*/}${C_RST}$(printf '%*s' $((18 - ${#ses_path##*/})) '')${C_PUR}│${C_RST}"
    echo -e "  ${C_PUR}└──────────────────────────────────────────────────────┘${C_RST}"

    SESSION_FILE="$ses_path"
}

# ── Merge dos arrays sin duplicados ──────────────────────────────
_merge_arrays() {
    local result_var="$1" a_name="$2" b_name="$3"
    local seen=() merged=()
    # bash 3.x compatible — sin nameref
    local item
    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        local dup=false
        local s; for s in "${seen[@]:-}"; do [[ "$s" == "$item" ]] && dup=true && break; done
        $dup || { seen+=("$item"); merged+=("$item"); }
    done < <(eval "printf '%s
' "\${${a_name}[@]:-}" "\${${b_name}[@]:-}"" 2>/dev/null)
    eval "${result_var}=("\${merged[@]:-}")"
}


# ─── TRAP: limpieza al interrumpir ──────────────────────────────
_cleanup_on_exit() {
    local exit_code=$?
    # Matar procesos background de waves si siguen vivos
    [[ ${WAVE2_PID:-0} -gt 0 ]] && kill "$WAVE2_PID" 2>/dev/null && wait "$WAVE2_PID" 2>/dev/null
    [[ ${WAVE3_PID:-0} -gt 0 ]] && kill "$WAVE3_PID" 2>/dev/null && wait "$WAVE3_PID" 2>/dev/null
    # Matar spinner si sigue vivo
    [[ ${_SPINNER_PID:-0} -gt 0 ]] && kill "$_SPINNER_PID" 2>/dev/null
    # Restaurar cursor si estaba oculto
    tput cnorm 2>/dev/null || true
    printf "
[K" 2>/dev/null || true
    # Guardar sesión parcial si el scan llegó al menos a Fase 2
    if [[ -n "$TARGET" && -n "$OPEN_PORTS_CSV" ]]; then
        echo -e "
  ${C_YEL}[!] Scan interrumpido — guardando sesión parcial…${C_RST}"
        session_save 2>/dev/null || true
    fi
    [[ $exit_code -ne 0 && $exit_code -ne 130 ]] && echo -e "  ${C_RED}Exit code: ${exit_code}${C_RST}"
}
trap '_cleanup_on_exit' EXIT
trap 'echo -e "
  ${C_YEL}[Ctrl+C] Interrumpido — limpiando…${C_RST}"; exit 130' INT TERM

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
# ── Tracking de evidencia para 3 reportes ────────────────────────
EFFECTIVE_PAYLOADS=()   # "tipo|||payload|||url|||evidencia"
ATTACK_ROUTES=()        # rutas de ataque encadenadas
REPORT_CLIENT=""
REPORT_CENSORED=""
REPORT_PENTESTER=""
INTEL_EXTRA_PAYLOADS_XSS=()
INTEL_EXTRA_PAYLOADS_SSRF=()  # cargados desde update/custom
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
    log "══ WriestTavo — Intel & Exploit Updater ══════════"

    init_update_system

    local last_update="nunca"
    [[ -f "$LAST_UPDATE_FILE" ]] && last_update=$(cat "$LAST_UPDATE_FILE")
    echo -e "  Última actualización: ${C_CYN}${last_update}${C_RST}"
    echo -e "  ${C_DIM}Fuentes: NVD · CISA KEV · Exploit-DB · GitHub Advisories · Packet Storm${C_RST}"
    echo -e "  ${C_DIM}         EPSS · OSV · VulnCheck · WPScan · Nuclei · SecLists · PayloadsAllTheThings${C_RST}"
    echo

    local update_errors=0
    local update_ok=0

    # ════════════════════════════════════════════════════════════
    # [1/11] NUCLEI TEMPLATES
    # Fuente: github.com/projectdiscovery/nuclei-templates
    # Qué da: 9000+ templates CVE, exposures, misconfiguraciones
    # ════════════════════════════════════════════════════════════
    log "  [01/11] Nuclei templates…"
    if command -v nuclei &>/dev/null; then
        spinner_start "Nuclei: actualizando templates…"
        nuclei -update-templates -silent 2>/dev/null
        _spinner_stop
        local tpl_count; tpl_count=$(find "${HOME}/nuclei-templates" -name "*.yaml" 2>/dev/null | wc -l)
        ok "Nuclei: ${tpl_count} templates ($(nuclei -version 2>&1 | grep -oP 'v[\d.]+' | head -1))"
        ((update_ok++))
    else
        warn "Nuclei no instalado. Instalar: sudo apt install nuclei"
        ((update_errors++))
    fi

    # ════════════════════════════════════════════════════════════
    # [2/11] NVD — NIST National Vulnerability Database
    # Fuente: services.nvd.nist.gov/rest/json/cves/2.0
    # Qué da: CVSS scores, CWE, CPE, descripción oficial de CVEs
    # ════════════════════════════════════════════════════════════
    log "  [02/11] NVD (NIST) — CVEs últimas 48h…"
    local nvd_cache="${CVE_CACHE}/nvd_recent.json"
    local two_days_ago; two_days_ago=$(date -d "2 days ago" +%Y-%m-%dT%H:%M:%S 2>/dev/null || echo "2024-01-01T00:00:00")
    local today; today=$(date +%Y-%m-%dT%H:%M:%S)

    local nvd_resp
    nvd_resp=$(curl -skL --max-time 20 \
        "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${two_days_ago}&pubEndDate=${today}&resultsPerPage=20" \
        2>/dev/null)

    if echo "$nvd_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('vulnerabilities',[])),'CVEs')" 2>/dev/null; then
        echo "$nvd_resp" > "$nvd_cache"
        python3 - << PYNVD
import json
try:
    with open("${nvd_cache}") as f: data = json.load(f)
    critical = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        desc = cve.get("descriptions", [{}])[0].get("value", "")[:100]
        metrics = cve.get("metrics", {})
        score = 0
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                score = metrics[key][0].get("cvssData", {}).get("baseScore", 0)
                break
        if score >= 9.0:
            critical.append(f"  {cve_id} CVSS:{score} — {desc}")
    if critical:
        print(f"  CVEs CRÍTICOS (CVSS≥9.0) últimas 48h: {len(critical)}")
        for c in critical[:5]: print(c)
    else:
        print("  Sin CVEs críticos nuevos en las últimas 48h")
except Exception as e:
    print(f"  Error: {e}")
PYNVD
        ((update_ok++))
    else
        warn "NVD API no disponible."
        ((update_errors++))
    fi

    # ════════════════════════════════════════════════════════════
    # [3/11] CISA KEV — Known Exploited Vulnerabilities
    # Fuente: cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    # Qué da: CVEs que están siendo EXPLOTADOS ACTIVAMENTE en la wild
    #         Obligatorio parchear en agencias US — la lista más crítica
    # ════════════════════════════════════════════════════════════
    log "  [03/11] CISA KEV — Vulnerabilidades explotadas activamente…"
    local kev_cache="${CVE_CACHE}/cisa_kev.json"
    local kev_resp
    kev_resp=$(curl -skL --max-time 20 \
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
        2>/dev/null)

    if echo "$kev_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('vulnerabilities',[])),'KEV')" 2>/dev/null; then
        echo "$kev_resp" > "$kev_cache"
        python3 - << PYKEV
import json
from datetime import datetime, timedelta
try:
    with open("${kev_cache}") as f: data = json.load(f)
    total = len(data.get("vulnerabilities", []))
    cutoff = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    recent = [v for v in data["vulnerabilities"] if v.get("dateAdded","") >= cutoff]
    print(f"  CISA KEV total: {total} CVEs | Añadidos último mes: {len(recent)}")
    for v in recent[:5]:
        print(f"  {v.get('cveID','')} — {v.get('vendorProject','')} {v.get('product','')} — {v.get('shortDescription','')[:80]}")
except Exception as e:
    print(f"  Error: {e}")
PYKEV
        ok "CISA KEV actualizado: ${kev_cache}"
        ((update_ok++))
    else
        warn "CISA KEV no disponible."
        ((update_errors++))
    fi

    # ════════════════════════════════════════════════════════════
    # [4/11] EPSS — Exploit Prediction Scoring System
    # Fuente: api.first.org/epss
    # Qué da: Probabilidad (0-1) de que un CVE sea explotado en 30 días
    #         Creado por FIRST.org — el mejor predictor de riesgo real
    # ════════════════════════════════════════════════════════════
    log "  [04/11] EPSS — Puntuaciones de probabilidad de explotación…"
    local epss_cache="${CVE_CACHE}/epss_top.json"
    local epss_resp
    epss_resp=$(curl -skL --max-time 15 \
        "https://api.first.org/data/v1/epss?order=!epss&limit=20" \
        2>/dev/null)

    if echo "$epss_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null | grep -q "OK"; then
        echo "$epss_resp" > "$epss_cache"
        python3 - << PYEPSS
import json
try:
    with open("${epss_cache}") as f: data = json.load(f)
    print(f"  Top CVEs por probabilidad de explotación (EPSS):")
    for v in data.get("data", [])[:5]:
        pct = float(v.get("epss", 0)) * 100
        print(f"  {v.get('cve','')} — {pct:.1f}% probabilidad ({v.get('percentile','')[:5]} percentil)")
except Exception as e:
    print(f"  Error: {e}")
PYEPSS
        ok "EPSS top-20 actualizado"
        ((update_ok++))
    else
        warn "EPSS API no disponible (first.org)"
        ((update_errors++))
    fi

    # ════════════════════════════════════════════════════════════
    # [5/11] EXPLOIT-DB — RSS + CSV database
    # Fuente: exploit-db.com/rss.xml + gitlab exploitdb CSV
    # Qué da: PoCs listos para usar, shellcodes, papers
    # ════════════════════════════════════════════════════════════
    log "  [05/11] Exploit-DB — exploits recientes…"
    local edb_cache="${CVE_CACHE}/exploitdb_recent.txt"
    local edb_feed
    edb_feed=$(curl -skL --max-time 15 \
        "https://www.exploit-db.com/rss.xml" 2>/dev/null | \
        grep -oP '(?<=<title>)[^<]+' | grep -v "^Exploit" | head -10)

    if [[ -n "$edb_feed" ]]; then
        echo "$edb_feed" > "$edb_cache"
        echo -e "  ${C_YEL}Últimos exploits publicados:${C_RST}"
        echo "$edb_feed" | head -5 | while IFS= read -r line; do
            echo -e "    ${C_DIM}•${C_RST} $line"
        done
        ok "Exploit-DB feed actualizado"
        ((update_ok++))
    else
        warn "Exploit-DB RSS no disponible"
        ((update_errors++))
    fi

    # ════════════════════════════════════════════════════════════
    # [6/11] PACKET STORM SECURITY
    # Fuente: packetstormsecurity.com/feeds/
    # Qué da: Advisories, exploits, tools, whitepapers
    #         Más rápido que EDB para 0-days recientes
    # ════════════════════════════════════════════════════════════
    log "  [06/11] Packet Storm Security — advisories recientes…"
    local pss_cache="${CVE_CACHE}/packetstorm_recent.txt"
    local pss_feed
    pss_feed=$(curl -skL --max-time 15 \
        "https://rss.packetstormsecurity.com/files/exploits/" 2>/dev/null | \
        grep -oP '(?<=<title>)[^<]+' | grep -v "^Exploit Files" | head -10)

    if [[ -n "$pss_feed" ]]; then
        echo "$pss_feed" > "$pss_cache"
        echo -e "  ${C_YEL}Últimos exploits en Packet Storm:${C_RST}"
        echo "$pss_feed" | head -5 | while IFS= read -r line; do
            echo -e "    ${C_DIM}•${C_RST} $line"
        done
        ok "Packet Storm feed actualizado"
        ((update_ok++))
    else
        warn "Packet Storm RSS no disponible"
        ((update_errors++))
    fi

    # ════════════════════════════════════════════════════════════
    # [7/11] GITHUB ADVISORY DATABASE (GHSA)
    # Fuente: api.github.com/advisories
    # Qué da: CVEs en librerías open source (npm, pip, gem, maven…)
    #         Ideal para encontrar vulns en dependencias de apps web
    # ════════════════════════════════════════════════════════════
    log "  [07/11] GitHub Advisory Database — librerías vulnerables…"
    local ghsa_cache="${CVE_CACHE}/ghsa_recent.json"
    local ghsa_resp
    ghsa_resp=$(curl -skL --max-time 15 \
        "https://api.github.com/advisories?per_page=10&sort=updated&type=reviewed&severity=critical,high" \
        -H "Accept: application/vnd.github+json" \
        2>/dev/null)

    if echo "$ghsa_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d),'advisories')" 2>/dev/null; then
        echo "$ghsa_resp" > "$ghsa_cache"
        python3 - << PYGHSA
import json
try:
    with open("${ghsa_cache}") as f: data = json.load(f)
    print(f"  GitHub Advisories CRITICAL/HIGH recientes:")
    for v in data[:5]:
        ecosystems = [p.get("package",{}).get("ecosystem","?") for p in v.get("vulnerabilities",[])[:1]]
        eco = ecosystems[0] if ecosystems else "?"
        print(f"  {v.get('ghsa_id','')} [{eco}] — {v.get('summary','')[:80]}")
except Exception as e:
    print(f"  Error: {e}")
PYGHSA
        ok "GitHub GHSA actualizado"
        ((update_ok++))
    else
        warn "GitHub GHSA no disponible"
        ((update_errors++))
    fi

    # ════════════════════════════════════════════════════════════
    # [8/11] OSV — Open Source Vulnerabilities (Google)
    # Fuente: api.osv.dev/v1/query
    # Qué da: Vulns en ecosistemas: PyPI, npm, Maven, Go, Rust, PHP…
    #         Cruzado con GHSA, CVE, GSD — la más completa para OSS
    # ════════════════════════════════════════════════════════════
    log "  [08/11] OSV (Google) — vulnerabilidades en ecosistemas OSS…"
    local osv_cache="${CVE_CACHE}/osv_recent.json"
    # Query: vulns recientes en los ecosistemas más comunes en web
    local osv_resp
    osv_resp=$(curl -skL --max-time 15 -X POST \
        "https://api.osv.dev/v1/query" \
        -H "Content-Type: application/json" \
        -d '{"package":{"name":"","ecosystem":"PyPI"},"version":""}' \
        2>/dev/null)

    # Alternativa más útil: buscar por ecosistemas web
    local osv_summary=""
    for ecosystem in "npm" "PyPI" "Packagist" "Maven"; do
        local count
        count=$(curl -skL --max-time 8 \
            "https://api.osv.dev/v1/vulns?page_size=5" \
            -X POST -H "Content-Type: application/json" \
            -d "{\"query\":{\"package\":{\"ecosystem\":\"${ecosystem}\"}}}" \
            2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total','?'))" 2>/dev/null)
        [[ -n "$count" ]] && osv_summary+="${ecosystem}:${count} "
    done

    if [[ -n "$osv_summary" ]]; then
        ok "OSV disponible — totales por ecosistema: ${osv_summary}"
        echo "$osv_summary" > "${CVE_CACHE}/osv_totals.txt"
        ((update_ok++))
    else
        # Fallback: solo verificar que la API responde
        if curl -skL --max-time 10 "https://api.osv.dev/v1/vulns" &>/dev/null; then
            ok "OSV API disponible (api.osv.dev)"
            ((update_ok++))
        else
            warn "OSV API no disponible"
            ((update_errors++))
        fi
    fi

    # ════════════════════════════════════════════════════════════
    # [9/11] WPSCAN VULNERABILITY DATABASE
    # Fuente: wpscan.com/api/v3 (requiere API key gratuita)
    # Qué da: Vulns específicas de WordPress: plugins, themes, core
    #         Solo aplica si INTEL_CMS=wordpress
    # ════════════════════════════════════════════════════════════
    log "  [09/11] WPScan Vulnerability DB — plugins/themes WordPress…"
    local wpscan_key_file="${UPDATE_DIR}/wpscan_api_key.txt"
    if [[ -f "$wpscan_key_file" ]]; then
        local wp_key; wp_key=$(cat "$wpscan_key_file")
        local wp_resp
        wp_resp=$(curl -skL --max-time 15 \
            "https://wpscan.com/api/v3/status" \
            -H "Authorization: Token token=${wp_key}" \
            2>/dev/null)
        if echo "$wp_resp" | grep -q '"success"'; then
            ok "WPScan API activa (key: ${wp_key:0:8}…)"
            echo "$(date +%Y-%m-%d) WPScan API OK" >> "${CVE_CACHE}/wpscan_status.txt"
            ((update_ok++))
        else
            warn "WPScan API key inválida o límite alcanzado"
            ((update_errors++))
        fi
    else
        echo -e "  ${C_DIM}WPScan API key no configurada.${C_RST}"
        echo -e "  ${C_DIM}Registro gratuito (25 req/día): https://wpscan.com/register${C_RST}"
        echo -e "  ${C_DIM}Guardar key: echo 'TU_KEY' > ${wpscan_key_file}${C_RST}"
        ((update_errors++))
    fi

    # ════════════════════════════════════════════════════════════
    # [10/11] SECLISTS + PAYLOADSALLTHETHINGS
    # Fuente: github.com/danielmiessler/SecLists
    #         github.com/swisskyrepo/PayloadsAllTheThings
    # Qué da: Wordlists, payloads de ataque actualizados por la comunidad
    # ════════════════════════════════════════════════════════════
    log "  [10/11] SecLists + PayloadsAllTheThings…"

    # SecLists
    if [[ -d "/usr/share/seclists/.git" ]]; then
        git -C /usr/share/seclists pull --quiet 2>/dev/null && \
            ok "SecLists actualizado (/usr/share/seclists)" || warn "Error SecLists"
        ((update_ok++))
    elif [[ -d "${HOME}/SecLists/.git" ]]; then
        git -C "${HOME}/SecLists" pull --quiet 2>/dev/null && ok "SecLists actualizado"
        ((update_ok++))
    else
        warn "SecLists no instalado: sudo apt install seclists"
        ((update_errors++))
    fi

    # PayloadsAllTheThings
    local patt_dir="${UPDATE_DIR}/PayloadsAllTheThings"
    if [[ -d "${patt_dir}/.git" ]]; then
        git -C "${patt_dir}" pull --quiet 2>/dev/null && \
            ok "PayloadsAllTheThings actualizado" || warn "Error PayloadsAllTheThings"
        ((update_ok++))
    else
        echo -e "  ${C_DIM}Descargando PayloadsAllTheThings (primera vez)…${C_RST}"
        spinner_start "Clonando PayloadsAllTheThings…"
        git clone --depth=1 --quiet \
            "https://github.com/swisskyrepo/PayloadsAllTheThings.git" \
            "${patt_dir}" 2>/dev/null
        _spinner_stop
        if [[ -d "${patt_dir}" ]]; then
            ok "PayloadsAllTheThings descargado: ${patt_dir}"
            # Cargar algunos payloads automáticamente
            _sync_patt_payloads "${patt_dir}"
            ((update_ok++))
        else
            warn "No se pudo clonar PayloadsAllTheThings (¿sin internet?)"
            ((update_errors++))
        fi
    fi

    # ════════════════════════════════════════════════════════════
    # [11/11] SCRIPT AUTO-UPDATE
    # Fuente: GitHub del script (si el usuario configuró la URL)
    # ════════════════════════════════════════════════════════════
    log "  [11/11] Verificando actualizaciones del script…"
    _check_script_update
    ((update_ok++))

    # ── Guardar timestamp y resumen ───────────────────────────────
    date '+%Y-%m-%d %H:%M' > "$LAST_UPDATE_FILE"
    echo
    echo -e "  ${C_GRN}┌──────────────────────────────────────────┐${C_RST}"
    echo -e "  ${C_GRN}│  Update completo                          │${C_RST}"
    echo -e "  ${C_GRN}│  ✅ OK: ${update_ok}/11   ❌ Errores: ${update_errors}/11$(printf '%*s' $((16 - ${#update_ok} - ${#update_errors})) '')│${C_RST}"
    echo -e "  ${C_GRN}│  Siguiente: --update cuando quieras       │${C_RST}"
    echo -e "  ${C_GRN}└──────────────────────────────────────────┘${C_RST}"
    echo
}

# ── Helper: importar payloads de PayloadsAllTheThings ────────────
_sync_patt_payloads() {
    local patt_dir="$1"
    [[ ! -d "$patt_dir" ]] && return

    local loaded=0
    # SQLi
    local sqli_f="${patt_dir}/SQL Injection/Intruder/Auth_Bypass.txt"
    if [[ -f "$sqli_f" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_SQLI+=("$line")
        done < "$sqli_f"
        ((loaded++))
    fi
    # XSS
    local xss_f="${patt_dir}/XSS Injection/Intruder/xss.txt"
    if [[ -f "$xss_f" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_XSS+=("$line")
        done < "$xss_f"
        ((loaded++))
    fi
    # LFI
    local lfi_f="${patt_dir}/File Inclusion/Intruder/deep_traversal.txt"
    if [[ -f "$lfi_f" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_LFI+=("$line")
        done < "$lfi_f"
        ((loaded++))
    fi
    [[ $loaded -gt 0 ]] && intel_log "PayloadsAllTheThings: ${loaded} archivos importados automáticamente"
}


# ─── CARGAR PAYLOADS CUSTOM DEL USUARIO ─────────────────────────
_load_custom_payloads() {
    local loaded=0

    # ── 1. Archivos _extra.txt del usuario (via --add-payload o manual) ──
    # Cargar cada archivo _extra.txt del usuario
    local _f
    for _f in "${CUSTOM_PAYLOADS}/sqli_extra.txt"; do
        [[ -s "$_f" ]] && while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            INTEL_EXTRA_PAYLOADS_SQLI+=("$line"); ((loaded++))
        done < "$_f"; done
    for _f in "${CUSTOM_PAYLOADS}/xss_extra.txt"; do
        [[ -s "$_f" ]] && while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            INTEL_EXTRA_PAYLOADS_XSS+=("$line"); ((loaded++))
        done < "$_f"; done
    for _f in "${CUSTOM_PAYLOADS}/lfi_extra.txt"; do
        [[ -s "$_f" ]] && while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            INTEL_EXTRA_PAYLOADS_LFI+=("$line"); ((loaded++))
        done < "$_f"; done
    for _f in "${CUSTOM_PAYLOADS}/ssrf_extra.txt"; do
        [[ -s "$_f" ]] && while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            INTEL_EXTRA_PAYLOADS_SSRF+=("$line"); ((loaded++))
        done < "$_f"; done

    # ── 2. PayloadsAllTheThings (descargado por --update) ────────────────
    local patt_dir="${UPDATE_DIR}/PayloadsAllTheThings"
    if [[ -d "$patt_dir" ]]; then
        # SQLi
        for f in             "${patt_dir}/SQL Injection/Intruder/Auth_Bypass.txt"             "${patt_dir}/SQL Injection/Intruder/MSSQL_Stacked_Queries.txt"             "${patt_dir}/SQL Injection/Intruder/MySQL_Stacked_Queries.txt"; do
            [[ -f "$f" ]] && while IFS= read -r line; do
                [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_SQLI+=("$line") && ((loaded++))
            done < "$f"
        done
        # XSS
        for f in             "${patt_dir}/XSS Injection/Intruder/xss.txt"             "${patt_dir}/XSS Injection/Intruder/dom-xss.txt"; do
            [[ -f "$f" ]] && while IFS= read -r line; do
                [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_XSS+=("$line") && ((loaded++))
            done < "$f"
        done
        # LFI
        for f in             "${patt_dir}/File Inclusion/Intruder/deep_traversal.txt"             "${patt_dir}/File Inclusion/Intruder/Linux-files.txt"             "${patt_dir}/File Inclusion/Intruder/Windows-files.txt"; do
            [[ -f "$f" ]] && while IFS= read -r line; do
                [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_LFI+=("$line") && ((loaded++))
            done < "$f"
        done
        # SSRF
        for f in             "${patt_dir}/Server Side Request Forgery/Intruder/SSRF.txt"             "${patt_dir}/Server Side Request Forgery/Intruder/cloud_metadata.txt"; do
            [[ -f "$f" ]] && while IFS= read -r line; do
                [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_SSRF+=("$line") && ((loaded++))
            done < "$f"
        done
        [[ $loaded -gt 0 ]] && intel_log "PayloadsAllTheThings: payloads cargados en memoria"
    fi

    # ── 3. SecLists (si está instalado) ─────────────────────────────────
    local seclists_base=""
    [[ -d "/usr/share/seclists" ]] && seclists_base="/usr/share/seclists"
    [[ -d "${HOME}/SecLists" ]]    && seclists_base="${HOME}/SecLists"

    if [[ -n "$seclists_base" ]]; then
        # SQLi
        local sl_sqli="${seclists_base}/Fuzzing/SQLi/Generic-SQLi.txt"
        [[ -f "$sl_sqli" ]] && while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_SQLI+=("$line") && ((loaded++))
        done < "$sl_sqli"
        # XSS
        local sl_xss="${seclists_base}/Fuzzing/XSS/XSS-Jhaddix.txt"
        [[ -f "$sl_xss" ]] && while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_XSS+=("$line") && ((loaded++))
        done < "$sl_xss"
        # LFI
        local sl_lfi="${seclists_base}/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt"
        [[ -f "$sl_lfi" ]] && while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && INTEL_EXTRA_PAYLOADS_LFI+=("$line") && ((loaded++))
        done < "$sl_lfi"
        [[ $loaded -gt 0 ]] && intel_log "SecLists: payloads integrados desde ${seclists_base}"
    fi

    # ── Resumen final ─────────────────────────────────────────────────────
    if [[ $loaded -gt 0 ]]; then
        intel_log "Payloads extra en memoria: SQLi=${#INTEL_EXTRA_PAYLOADS_SQLI[@]} XSS=${#INTEL_EXTRA_PAYLOADS_XSS[@]} LFI=${#INTEL_EXTRA_PAYLOADS_LFI[@]} SSRF=${#INTEL_EXTRA_PAYLOADS_SSRF[@]}"
    fi
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
    prog_modulo 1 "TTL / OS Fingerprinting"
    spinner_start "TTL / OS Fingerprinting"
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
# ════════════════════════════════════════════════════════════════
# MÓDULO 2: PORT SCAN — PIPELINE PROGRESIVO (3 WAVES)
#
#  Wave 1 → top-100  (sync,  ~2s)   → arrancan módulos de inmediato
#  Wave 2 → top-1000 (bg,    ~5s)   → merge al final de Fase 3
#  Wave 3 → 1-65535  (bg, masscan)  → merge al final de Fase 5
#
#  El scan web empieza con los puertos de Wave 1.
#  Cada merge añade puertos nuevos y corre version scan solo en ellos.
# ════════════════════════════════════════════════════════════════

# ── Helper: extraer puertos de output nmap ───────────────────────
_parse_nmap_ports() {
    grep '^[0-9]' "$1" 2>/dev/null | cut -d'/' -f1 | sort -un
}

# ── Helper: registrar puertos web desde lista ────────────────────
_register_web_ports() {
    local p
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        is_web_port "$p" && WEB_PORTS+=("$p")
    done <<< "$1"
    # Deduplicar WEB_PORTS
    IFS=$'\n' read -r -d '' -a WEB_PORTS < <(printf '%s\n' "${WEB_PORTS[@]}" | sort -un && printf '\0')
}

# ── Helper: version scan SOLO en puertos nuevos ──────────────────
_version_scan_new_ports() {
    local wave_label="$1"; shift
    local new_ports=("$@")
    [[ ${#new_ports[@]} -eq 0 ]] && return

    # Filtrar los que ya procesamos
    local pending=()
    for p in "${new_ports[@]}"; do
        local already=false
        for done_p in "${PORTS_VERSION_DONE[@]}"; do
            [[ "$p" == "$done_p" ]] && already=true && break
        done
        $already || pending+=("$p")
    done
    [[ ${#pending[@]} -eq 0 ]] && return

    local csv; csv=$(printf '%s,' "${pending[@]}"); csv="${csv%,}"
    local base="${OUTPUT_DIR}/nmap/version_scan_${wave_label}"

    echo
    echo -e "  ${C_BLU}[↻]${C_RST} ${C_BOLD}Version scan${C_RST} — ${wave_label} puertos nuevos: ${C_YEL}${csv}${C_RST}"
    spinner_start "nmap -sV puertos nuevos: ${csv}"

    nmap -n -Pn -sV -sC --min-rate 2000 \
        -p"${csv}" -oA "${base}" "${TARGET}" 2>/dev/null

    _spinner_stop

    # Actualizar INTEL con versiones detectadas
    local nmap_out; nmap_out=$(cat "${base}.nmap" 2>/dev/null)
    _parse_intel_from_nmap_version "${nmap_out}" 2>/dev/null || true

    # Marcar como procesados
    PORTS_VERSION_DONE+=("${pending[@]}")
    OPEN_PORTS_CSV=$(printf '%s,' "${PORTS_VERSION_DONE[@]}" | sed 's/,$//')
    ok "Version scan ${wave_label}: completado (${#pending[@]} puertos)"
}

# ── Helper: merge wave background → detecta puertos nuevos ───────
_merge_wave() {
    local wave_num="$1"
    local wave_pid_var="WAVE${wave_num}_PID"
    local wave_file_var="WAVE${wave_num}_FILE"
    local wave_ports_var="PORTS_WAVE${wave_num}"

    local pid="${!wave_pid_var}"
    local file="${!wave_file_var}"

    [[ $pid -eq 0 ]] && return   # wave no lanzada
    [[ -z "$file" ]] && return

    echo
    echo -e "  ${C_CYN}[W${wave_num}]${C_RST} Verificando Wave ${wave_num}…"

    # Esperar si todavía corre (máximo 30s para no bloquear)
    local waited=0
    while kill -0 "$pid" 2>/dev/null && (( waited < 30 )); do
        sleep 2; ((waited+=2))
        printf "\r  ${C_DIM}  Wave ${wave_num} aún corriendo… ${waited}s${C_RST}   "
    done
    printf "\r%-60s\r" " "

    if kill -0 "$pid" 2>/dev/null; then
        warn "Wave ${wave_num} todavía corriendo (PID ${pid}). Se usará cuando termine."
        return
    fi

    # Parsear resultados
    local raw_ports
    if [[ "$wave_num" == "3" ]]; then
        # masscan output format: "Discovered open port X/tcp on IP"
        raw_ports=$(grep -oP 'port \K[0-9]+' "$file" 2>/dev/null | sort -un)
    else
        raw_ports=$(_parse_nmap_ports "$file")
    fi

    [[ -z "$raw_ports" ]] && ok "Wave ${wave_num}: sin puertos nuevos." && return

    # Detectar realmente nuevos
    local new_ports=()
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        local seen=false
        for done_p in "${PORTS_VERSION_DONE[@]}"; do
            [[ "$p" == "$done_p" ]] && seen=true && break
        done
        $seen || new_ports+=("$p")
    done <<< "$raw_ports"

    eval "${wave_ports_var}=(\"\${new_ports[@]}\")"

    if [[ ${#new_ports[@]} -gt 0 ]]; then
        local csv; csv=$(printf '%s,' "${new_ports[@]}"); csv="${csv%,}"
        ok "Wave ${wave_num} — ${#new_ports[@]} puertos nuevos: ${C_YEL}${csv}${C_RST}"
        _register_web_ports "$(printf '%s\n' "${new_ports[@]}")"
        _version_scan_new_ports "wave${wave_num}" "${new_ports[@]}"
    else
        ok "Wave ${wave_num} — sin puertos adicionales a los ya conocidos."
    fi

    # Limpiar PID para no re-procesar
    eval "${wave_pid_var}=0"
}

modulo_port_scan() {
    prog_modulo 2 "Port Discovery — Pipeline Progresivo (3 waves)"

    # ── Tasas según modo ────────────────────────────────────────
    local rate_w1 rate_w2 rate_w3 nmap_timing
    case "$SCAN_MODE" in
        stealth)    rate_w1=500;   rate_w2=300;   rate_w3=3000;  nmap_timing="-T2 -n -Pn" ;;
        aggressive) rate_w1=8000;  rate_w2=6000;  rate_w3=200000; nmap_timing="-T5 -n -Pn" ;;
        *)          rate_w1=3000;  rate_w2=2000;  rate_w3=50000; nmap_timing="-T4 -n -Pn" ;;
    esac

    # ── WAVE 1: top-100 ports — SÍNCRONO (~2s) ─────────────────
    echo -e "\n  ${C_GRN}▶ Wave 1${C_RST} — top-100 puertos ${C_DIM}(síncrono, resultado inmediato)${C_RST}"
    local w1_file="${OUTPUT_DIR}/nmap/wave1_top100.txt"
    cmd_show "nmap ${nmap_timing} -sS --open --top-ports 100 --min-rate ${rate_w1} ${TARGET}"
    spinner_start "Wave 1 — top-100…"

    nmap ${nmap_timing} -sS --open \
        --top-ports 100 --min-rate ${rate_w1} \
        "${TARGET}" > "${w1_file}" 2>/dev/null
    _spinner_stop

    local raw1; raw1=$(_parse_nmap_ports "${w1_file}")
    if [[ -n "$raw1" ]]; then
        while IFS= read -r p; do PORTS_WAVE1+=("$p"); done <<< "$raw1"
        OPEN_PORTS_CSV=$(printf '%s,' "${PORTS_WAVE1[@]}"); OPEN_PORTS_CSV="${OPEN_PORTS_CSV%,}"
        _register_web_ports "$raw1"
        ok "Wave 1 — Puertos: ${C_YEL}${OPEN_PORTS_CSV}${C_RST}  ${C_DIM}→ módulos web arrancan ya${C_RST}"
        PORTS_VERSION_DONE+=("${PORTS_WAVE1[@]}")
    else
        # Nada en top-100 — inferir de URL si hay
        if [[ -n "$ORIGINAL_URL" ]]; then
            warn "Wave 1: 0 puertos. Infiriendo desde URL..."
            [[ "$ORIGINAL_URL" =~ ^https:// ]] && { WEB_PORTS=(443); OPEN_PORTS_CSV="443"; } \
                                                || { WEB_PORTS=(80);  OPEN_PORTS_CSV="80"; }
            PORTS_VERSION_DONE+=("${WEB_PORTS[@]}")
            ok "Puerto asumido: ${C_YEL}${OPEN_PORTS_CSV}${C_RST}"
        else
            warn "Wave 1: 0 puertos abiertos encontrados."
        fi
    fi

    add_finding "INFO" "Puertos TCP (Wave 1)" "${OPEN_PORTS_CSV:-ninguno}"

    # ── WAVE 2: top-1000 — BACKGROUND (~5-10s) ─────────────────
    echo -e "\n  ${C_YEL}▶ Wave 2${C_RST} — top-1000 puertos ${C_DIM}(background, merge al final de Fase 3)${C_RST}"
    WAVE2_FILE="${OUTPUT_DIR}/nmap/wave2_top1000.txt"
    cmd_show "nmap ${nmap_timing} -sS --open --top-ports 1000 --min-rate ${rate_w2} ${TARGET}"

    nmap ${nmap_timing} -sS --open \
        --top-ports 1000 --min-rate ${rate_w2} \
        "${TARGET}" > "${WAVE2_FILE}" 2>/dev/null &
    WAVE2_PID=$!
    echo -e "  ${C_DIM}  [PID ${WAVE2_PID}] Wave 2 corriendo… resultado disponible en ~5-10s${C_RST}"

    # ── WAVE 3: 1-65535 — BACKGROUND (masscan si disponible) ───
    echo -e "\n  ${C_YEL}▶ Wave 3${C_RST} — todos los puertos ${C_DIM}(background, merge al final de Fase 5)${C_RST}"
    WAVE3_FILE="${OUTPUT_DIR}/nmap/wave3_full.txt"

    if command -v masscan &>/dev/null && [[ "$SCAN_MODE" != "stealth" ]]; then
        cmd_show "masscan -p1-65535 --rate ${rate_w3} ${TARGET}"
        masscan -p1-65535 --rate "${rate_w3}" \
            "${TARGET}" > "${WAVE3_FILE}" 2>/dev/null &
        WAVE3_PID=$!
        echo -e "  ${C_DIM}  [PID ${WAVE3_PID}] masscan @ ${rate_w3} pkt/s — ~15-30s${C_RST}"
    else
        cmd_show "nmap ${nmap_timing} -sS --open -p- --min-rate ${rate_w3} --stats-every 15s ${TARGET}"
        nmap ${nmap_timing} -sS --open -p- \
            --min-rate ${rate_w3} --stats-every 15s \
            "${TARGET}" > "${WAVE3_FILE}" 2>/dev/null &
        WAVE3_PID=$!
        echo -e "  ${C_DIM}  [PID ${WAVE3_PID}] nmap -p- corriendo (instala masscan para ~15s)${C_RST}"
    fi
    # FIX: solo un proceso Wave3 — el if/else garantiza exactamente uno

    echo
    prog_modulo_ok "${OPEN_PORTS_CSV:-pendiente}"
}


# ─── MÓDULO 3: SERVICE & VERSION ────────────────────────────────
# ── Helper: extraer INTEL de output de nmap version scan ────────
_parse_intel_from_nmap_version() {
    local nmap_out="$1"
    [[ -z "$nmap_out" ]] && return
    # OS
    echo "$nmap_out" | grep -qi 'windows'     && INTEL_OS="windows"
    echo "$nmap_out" | grep -qi 'linux\|unix' && [[ -z "$INTEL_OS" ]] && INTEL_OS="linux"
    # Servicios → INTEL_TECHNOLOGIES
    echo "$nmap_out" | grep -qi 'mysql'        && INTEL_TECHNOLOGIES+=("mysql")
    echo "$nmap_out" | grep -qi 'postgresql'   && INTEL_TECHNOLOGIES+=("postgresql")
    echo "$nmap_out" | grep -qi 'redis'        && INTEL_TECHNOLOGIES+=("redis")
    echo "$nmap_out" | grep -qi 'mongodb'      && INTEL_TECHNOLOGIES+=("mongodb")
    echo "$nmap_out" | grep -qi 'apache'       && INTEL_TECHNOLOGIES+=("apache")
    echo "$nmap_out" | grep -qi 'nginx'        && INTEL_TECHNOLOGIES+=("nginx")
    echo "$nmap_out" | grep -qi 'iis'          && INTEL_TECHNOLOGIES+=("iis") && INTEL_OS="windows"
    echo "$nmap_out" | grep -qi 'openssl\|ssl' && INTEL_TECHNOLOGIES+=("ssl")
    echo "$nmap_out" | grep -qi 'smb\|samba'   && INTEL_TECHNOLOGIES+=("smb")
    echo "$nmap_out" | grep -qi 'ssh'          && INTEL_TECHNOLOGIES+=("ssh")
    # Deduplicar
    IFS=$'
' read -r -d '' -a INTEL_TECHNOLOGIES < <(printf '%s
' "${INTEL_TECHNOLOGIES[@]}" | sort -u && printf '