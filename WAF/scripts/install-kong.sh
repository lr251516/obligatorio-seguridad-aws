#!/bin/bash
# Instalación de Kong API Gateway + ModSecurity WAF en VM1 (10.0.1.10)

set -e

echo "[+] Instalando Kong API Gateway + ModSecurity WAF"

# Actualizar sistema
sudo apt update
sudo apt install -y curl wget apt-transport-https lsb-release gnupg2

# Instalar PostgreSQL para Kong
echo "[+] Instalando PostgreSQL..."
sudo apt install -y postgresql postgresql-contrib

# Configurar base de datos para Kong
echo "[+] Configurando base de datos..."
sudo -u postgres psql <<EOF
CREATE DATABASE kong;
CREATE USER kong WITH ENCRYPTED PASSWORD 'kong_password';
GRANT ALL PRIVILEGES ON DATABASE kong TO kong;
\q
EOF

# Instalar Kong
echo "[+] Instalando Kong Gateway..."
KONG_VERSION="3.4.1"
# Descargar Kong desde el repo oficial
curl -Lo kong.deb "https://packages.konghq.com/public/gateway-34/deb/ubuntu/pool/jammy/main/k/ko/kong_${KONG_VERSION}/kong_${KONG_VERSION}_amd64.deb"
sudo dpkg -i kong.deb || {
    echo "[!] Error instalando Kong, intentando método alternativo..."
    # Método alternativo: usar el script de instalación oficial
    curl -sL https://get.konghq.com/install | sudo bash -s -- -v ${KONG_VERSION}
}
rm -f kong.deb

# Configurar Kong
sudo tee /etc/kong/kong.conf > /dev/null <<EOF
# Database
database = postgres
pg_host = localhost
pg_port = 5432
pg_user = kong
pg_password = kong_password
pg_database = kong

# Proxy
proxy_listen = 0.0.0.0:8000, 0.0.0.0:8443 ssl
admin_listen = 10.0.1.10:8001, 10.0.1.10:8444 ssl

# Logging
log_level = notice
proxy_access_log = /var/log/kong/access.log
proxy_error_log = /var/log/kong/error.log
admin_access_log = /var/log/kong/admin_access.log
admin_error_log = /var/log/kong/admin_error.log

# Plugins
plugins = bundled,oidc,request-termination

# Nginx
nginx_worker_processes = auto
EOF

# Crear directorios de logs
sudo mkdir -p /var/log/kong
sudo chown kong:kong /var/log/kong

# Migrar base de datos
echo "[+] Migrando base de datos de Kong..."
sudo kong migrations bootstrap -c /etc/kong/kong.conf

# Instalar ModSecurity + OWASP CRS
echo "[+] Instalando ModSecurity..."
sudo apt install -y libmodsecurity3 libmodsecurity-dev

# Clonar OWASP CRS
cd /opt
sudo git clone https://github.com/coreruleset/coreruleset.git
cd coreruleset
sudo cp crs-setup.conf.example crs-setup.conf

# Configurar ModSecurity para Kong
sudo tee /etc/modsecurity/modsecurity.conf > /dev/null <<'MODSEC'
# ModSecurity Core Rules Configuration
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
SecResponseBodyLimit 524288
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecTmpDir /tmp/
SecDataDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLog /var/log/modsec_audit.log
SecAuditLogParts ABIJDEFHZ
SecArgumentSeparator &
SecCookieFormat 0
SecDebugLog /var/log/modsec_debug.log
SecDebugLogLevel 0

# OWASP CRS
Include /opt/coreruleset/crs-setup.conf
Include /opt/coreruleset/rules/*.conf
MODSEC

# Iniciar Kong
echo "[+] Iniciando Kong..."
sudo kong start -c /etc/kong/kong.conf

# Esperar que Kong esté listo
sleep 10

# Configurar servicios de ejemplo
echo "[+] Configurando servicios de ejemplo..."

# Servicio backend de prueba (apuntando a Wazuh Dashboard)
curl -i -X POST http://localhost:8001/services/ \
  --data "name=wazuh-backend" \
  --data "url=https://10.0.1.20"

# Ruta para el servicio
curl -i -X POST http://localhost:8001/services/wazuh-backend/routes \
  --data "paths[]=/wazuh" \
  --data "strip_path=false"

# Plugin de rate limiting
curl -i -X POST http://localhost:8001/services/wazuh-backend/plugins \
  --data "name=rate-limiting" \
  --data "config.minute=100" \
  --data "config.policy=local"

# Integración con Keycloak (OIDC)
echo "[+] Configurando integración con Keycloak..."
curl -i -X POST http://localhost:8001/plugins \
  --data "name=openid-connect" \
  --data "config.issuer=http://10.0.1.30:8080/realms/fosil-energias" \
  --data "config.client_id=kong-api" \
  --data "config.client_secret=kong-secret-2024"

echo "[✓] Kong + ModSecurity instalado correctamente"
echo ""
echo "=== Información de Acceso ==="
echo "Kong Proxy: http://10.0.1.10:8000"
echo "Kong Admin: http://10.0.1.10:8001"
echo "ModSecurity Logs: /var/log/modsec_audit.log"
echo ""
echo "Probar servicio:"
echo "  curl http://10.0.1.10:8000/wazuh"
echo ""
echo "Ver plugins:"
echo "  curl http://localhost:8001/plugins"