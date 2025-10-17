#!/bin/bash
# Instalación de Keycloak en VM3 (10.0.1.30)

set -e

echo "[+] Instalando Keycloak Identity Provider"

sudo apt update
sudo apt install -y openjdk-17-jdk postgresql postgresql-contrib

echo "[+] Configurando base de datos PostgreSQL..."
sudo -u postgres psql <<EOF
CREATE DATABASE keycloak;
CREATE USER keycloak WITH ENCRYPTED PASSWORD 'keycloak_password';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
\q
EOF

KEYCLOAK_VERSION="23.0.0"
cd /opt
sudo wget https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz
sudo tar -xzf keycloak-${KEYCLOAK_VERSION}.tar.gz
sudo mv keycloak-${KEYCLOAK_VERSION} keycloak
sudo rm keycloak-${KEYCLOAK_VERSION}.tar.gz

sudo useradd -r -s /bin/false keycloak
sudo chown -R keycloak:keycloak /opt/keycloak

sudo tee /opt/keycloak/conf/keycloak.conf > /dev/null <<EOF
# Database
db=postgres
db-url=jdbc:postgresql://localhost:5432/keycloak
db-username=keycloak
db-password=keycloak_password

# Hostname
hostname=10.0.1.30
hostname-strict=false
hostname-strict-https=false

# HTTP
http-enabled=true
http-port=8080

# HTTPS (producción debería usar certificados reales)
https-port=8443

# Logging
log-level=INFO
log=console,file

# Features
features=token-exchange,admin-fine-grained-authz

# Métricas para monitoreo
metrics-enabled=true
EOF

cd /opt/keycloak
sudo -u keycloak bin/kc.sh build

sudo tee /opt/keycloak/conf/jvm-opts.conf > /dev/null <<'JVMEOF'
-Xms512m
-Xmx1024m
-XX:MetaspaceSize=128m
-XX:MaxMetaspaceSize=256m
-Dfile.encoding=UTF-8
JVMEOF

echo "[+] Creando usuario administrador..."
sudo -u keycloak KEYCLOAK_ADMIN=admin KEYCLOAK_ADMIN_PASSWORD=admin bin/kc.sh start &
KC_PID=$!
sleep 30
kill $KC_PID

sudo tee /etc/systemd/system/keycloak.service > /dev/null <<'EOF'
[Unit]
Description=Keycloak Identity Provider
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=keycloak
Group=keycloak
WorkingDirectory=/opt/keycloak
Environment="KEYCLOAK_ADMIN=admin"
Environment="KEYCLOAK_ADMIN_PASSWORD=admin"
ExecStart=/opt/keycloak/bin/kc.sh start
StandardOutput=journal
StandardError=journal
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable keycloak
sudo systemctl start keycloak

echo "[+] Esperando que Keycloak esté listo..."
sleep 20

cd /opt/keycloak
sudo -u keycloak bin/kcadm.sh config credentials \
    --server http://10.0.1.30:8080 \
    --realm master \
    --user admin \
    --password admin

echo "[✓] Keycloak instalado correctamente"
echo ""
echo "=== Información de Acceso ==="
echo "Admin Console: http://10.0.1.30:8080/admin"
echo "Usuario: admin"
echo "Password: admin"
echo ""
echo "Siguiente paso: Ejecutar create-fosil-realm.sh"