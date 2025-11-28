#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
exec > >(tee /tmp/user-data.log) 2>&1

# Timezone y NTP Uruguay
timedatectl set-timezone America/Montevideo
apt-get install -y systemd-timesyncd
echo "NTP=0.uy.pool.ntp.org 1.uy.pool.ntp.org" >> /etc/systemd/timesyncd.conf
systemctl enable systemd-timesyncd
systemctl restart systemd-timesyncd

# System setup
apt-get update && # Nota: apt-get upgrade removido porque puede fallar por paquetes 404 en repos
apt-get install -y git curl wget apt-transport-https lsb-release gnupg2 build-essential libpcre3-dev zlib1g-dev libssl-dev libgeoip-dev libgd-dev libxml2-dev libyajl-dev automake libtool pkg-config postgresql postgresql-contrib libmodsecurity3 libmodsecurity-dev
hostnamectl set-hostname waf-kong
mkdir -p /opt/fosil/scripts

# Clonar repo
cd /opt
if [ -d "fosil/.git" ]; then
  echo "Repo already exists, pulling latest changes..."
  cd fosil
  git pull origin main
else
  echo "Cloning repository..."
  rm -rf fosil  # Remove if exists but not a git repo
  git clone https://github.com/lr251516/obligatorio-seguridad-aws.git fosil
  cd fosil
fi
chown -R ubuntu:ubuntu /opt/fosil
cat >> /etc/hosts <<H
10.0.1.10 waf-kong waf
10.0.1.20 wazuh-siem wazuh
10.0.1.30 vpn-iam vpn keycloak
10.0.1.40 hardening-vm hardening
H

# Wazuh Agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH|apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main">/etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get remove --purge -y postfix 2>/dev/null||true
WAZUH_MANAGER="10.0.1.20" WAZUH_AGENT_NAME="waf-kong" apt-get install -y wazuh-agent=4.13.1-1
sed -i '/<\/ossec_config>$/i <syscheck><disabled>no</disabled><frequency>300</frequency><alert_new_files>yes</alert_new_files><directories check_all="yes" realtime="yes" report_changes="yes">/etc/kong</directories><directories check_all="yes" realtime="yes">/etc/nginx</directories><ignore type="sregex">\\.log$</ignore></syscheck>' /var/ossec/etc/ossec.conf
systemctl enable wazuh-agent && systemctl start wazuh-agent

# PostgreSQL
sudo -u postgres psql <<P
CREATE DATABASE kong;
CREATE USER kong WITH ENCRYPTED PASSWORD 'kong_password';
GRANT ALL PRIVILEGES ON DATABASE kong TO kong;
ALTER DATABASE kong OWNER TO kong;
P

# Kong
curl -1sLf 'https://packages.konghq.com/public/gateway-34/setup.deb.sh'|bash
apt-get install -y kong
cat >/etc/kong/kong.conf <<K
database=postgres
pg_host=localhost
pg_port=5432
pg_user=kong
pg_password=kong_password
pg_database=kong
proxy_listen=0.0.0.0:8000,0.0.0.0:8443 ssl
admin_listen=0.0.0.0:8001,0.0.0.0:8444 ssl
log_level=notice
proxy_access_log=/var/log/kong/access.log
proxy_error_log=/var/log/kong/error.log
admin_access_log=/var/log/kong/admin_access.log
admin_error_log=/var/log/kong/admin_error.log
plugins=bundled,request-termination
nginx_worker_processes=auto
K
mkdir -p /var/log/kong && chown kong:kong /var/log/kong
kong migrations bootstrap -c /etc/kong/kong.conf
systemctl enable kong
systemctl start kong

# Nginx + ModSecurity
cd /opt

# Clonar OWASP CRS (versión compatible con ModSecurity v3)
git clone https://github.com/coreruleset/coreruleset.git
cd coreruleset
git checkout v3.3.5
cp crs-setup.conf.example crs-setup.conf

# Fix: Deshabilitar regla incompatible con libmodsecurity3 3.0.6
mv rules/REQUEST-922-MULTIPART-ATTACK.conf rules/REQUEST-922-MULTIPART-ATTACK.conf.disabled 2>/dev/null || true

# Clonar ModSecurity v3 (biblioteca completa) para obtener archivos de config
cd /opt
git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity.git
cd ModSecurity
git submodule init
git submodule update

# Clonar módulo Nginx de ModSecurity
cd /opt
git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git

# Compilar Nginx con ModSecurity
cd /opt
wget -q http://nginx.org/download/nginx-1.24.0.tar.gz && tar -xzf nginx-1.24.0.tar.gz && cd nginx-1.24.0
./configure --user=www-data --group=www-data --with-pcre-jit --with-http_ssl_module --with-http_realip_module --with-http_geoip_module --add-dynamic-module=/opt/ModSecurity-nginx --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/run/nginx.pid >/dev/null 2>&1
make -j$(nproc) >/dev/null 2>&1 && make install >/dev/null 2>&1

# Configurar ModSecurity
mkdir -p /etc/nginx/modsec /var/log/nginx
cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
cp /opt/ModSecurity/unicode.mapping /etc/nginx/modsec/
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
sed -i 's|SecAuditLog /var/log/modsec_audit.log|SecAuditLog /var/log/nginx/modsec_audit.log|' /etc/nginx/modsec/modsecurity.conf
echo -e "Include /etc/nginx/modsec/modsecurity.conf\nInclude /opt/coreruleset/crs-setup.conf\nInclude /opt/coreruleset/rules/*.conf">/etc/nginx/modsec/main.conf
touch /var/log/nginx/modsec_audit.log /var/log/nginx/modsec_debug.log && chmod 644 /var/log/nginx/modsec_*.log && chown www-data:adm /var/log/nginx/modsec_*.log

# Custom ModSecurity Rules
cat >/opt/coreruleset/rules/REQUEST-900-CUSTOM-RULES.conf <<'R'
# Custom Rules - Fósil Energías Renovables
# Regla 900001: Bloquear acceso a /admin desde IPs externas (fuera de VPC)
SecRule REQUEST_URI "@beginsWith /admin" \
    "id:900001,\
    phase:1,\
    deny,\
    status:403,\
    t:none,\
    msg:'Admin panel access blocked - external IP',\
    logdata:'IP: %{REMOTE_ADDR} - URI: %{REQUEST_URI}',\
    severity:CRITICAL,\
    chain"
    SecRule REMOTE_ADDR "!@ipMatch 10.0.1.0/24" \
        "t:none,\
        setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# Regla 900002: Path Traversal
SecRule REQUEST_URI "@rx (?i)(?:\.\.\/|\.\.\\|etc\/passwd|boot\.ini|windows\/system)" \
    "id:900002,\
    phase:1,\
    deny,\
    status:403,\
    t:none,t:urlDecodeUni,\
    msg:'Path Traversal attempt detected',\
    logdata:'IP: %{REMOTE_ADDR} - URI: %{REQUEST_URI}',\
    severity:CRITICAL,\
    tag:'attack-lfi',\
    tag:'OWASP_TOP_10',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# Regla 900003: XSS básico (complementa OWASP CRS)
SecRule ARGS "@rx (?i)(?:<script|onerror=|javascript:)" \
    "id:900003,\
    phase:2,\
    deny,\
    status:403,\
    t:none,t:urlDecodeUni,\
    msg:'XSS básico detectado',\
    logdata:'IP: %{REMOTE_ADDR} - Param: %{MATCHED_VAR}',\
    severity:CRITICAL,\
    tag:'attack-xss',\
    tag:'OWASP_TOP_10',\
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"

# Regla 900004: SQL Injection básico (complementa OWASP CRS)
SecRule ARGS "@rx (?i)(?:' OR |UNION SELECT|DROP TABLE|--)" \
    "id:900004,\
    phase:2,\
    deny,\
    status:403,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection básico detectado',\
    logdata:'IP: %{REMOTE_ADDR} - Param: %{MATCHED_VAR}',\
    severity:CRITICAL,\
    tag:'attack-sqli',\
    tag:'OWASP_TOP_10',\
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"

# Regla 900006: Detectar credenciales en URL
SecRule ARGS_NAMES "@rx (?i)(?:password|passwd|pwd|api_key|apikey|token|secret|auth)" \
    "id:900006,\
    phase:2,\
    deny,\
    status:403,\
    t:none,\
    msg:'Credentials detected in URL parameters',\
    logdata:'IP: %{REMOTE_ADDR} - Param: %{MATCHED_VAR_NAME}',\
    severity:ERROR,\
    tag:'security-misconfiguration',\
    setvar:'tx.anomaly_score_pl2=+%{tx.error_anomaly_score}'"

# Regla 900007: Detectar scanners de seguridad
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(?:nikto|sqlmap|nmap|masscan|acunetix|burp|metasploit|havij)" \
    "id:900007,\
    phase:1,\
    deny,\
    status:403,\
    t:none,t:lowercase,\
    msg:'Security scanner detected',\
    logdata:'IP: %{REMOTE_ADDR} - User-Agent: %{REQUEST_HEADERS.User-Agent}',\
    severity:CRITICAL,\
    tag:'security-scanner',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# Configuración de respuesta personalizada para bloqueos por anomaly score
SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" \
    "id:900999,\
    phase:5,\
    deny,\
    status:403,\
    t:none,\
    msg:'Solicitud bloqueada por WAF de Fósil Energías',\
    logdata:'Anomaly Score: %{TX.ANOMALY_SCORE} - IP: %{REMOTE_ADDR}',\
    tag:'FOSIL-WAF'"
R

# Nginx config
cat >/etc/nginx/nginx.conf <<'N'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
load_module modules/ngx_http_modsecurity_module.so;
events{worker_connections 1024;}
http{
include /etc/nginx/mime.types;
log_format main '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent';
access_log /var/log/nginx/access.log main;
error_log /var/log/nginx/error.log warn;
sendfile on;
include /etc/nginx/conf.d/*.conf;
}
N
mkdir -p /etc/nginx/conf.d
cat >/etc/nginx/conf.d/waf.conf <<'W'
upstream kong_backend{server 127.0.0.1:8000;}
server{
listen 80 default_server;
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
add_header X-Frame-Options "SAMEORIGIN" always;
location /{
proxy_pass http://kong_backend;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
}
location /health{return 200 "WAF OK\n";}
}
W
cat >/etc/systemd/system/nginx.service <<S
[Unit]
Description=Nginx with ModSecurity
After=network.target
[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s QUIT \$MAINPID
[Install]
WantedBy=multi-user.target
S
systemctl daemon-reload && systemctl enable nginx && systemctl start nginx

# Wazuh integration
sed -i '/<\/ossec_config>$/i <localfile><log_format>syslog</log_format><location>/var/log/nginx/access.log</location></localfile><localfile><log_format>audit</log_format><location>/var/log/nginx/modsec_audit.log</location></localfile><localfile><log_format>syslog</log_format><location>/var/log/kong/access.log</location></localfile><localfile><log_format>syslog</log_format><location>/var/log/nginx/error.log</location></localfile>' /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent

# Configure Kong services automatically
sleep 10
cd /opt/fosil/WAF/scripts
chmod +x configure-kong-services.sh
bash configure-kong-services.sh 2>&1 | tee -a /tmp/user-data.log || echo "Warning: configure-kong-services.sh failed" >> /tmp/user-data.log

echo "WAF deployment complete">/tmp/user-data-completed.log
