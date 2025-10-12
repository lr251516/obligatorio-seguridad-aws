#!/bin/bash
# Instalación de Wazuh Manager, Indexer y Dashboard en VM2 (10.0.1.20)

set -e

echo "[+] Iniciando instalación de Wazuh Stack"

echo "[+] Verificando recursos..."
MEM_TOTAL=$(free -g | awk '/^Mem:/{print $2}')
if [ $MEM_TOTAL -lt 4 ]; then
    echo "[!] ADVERTENCIA: Se recomiendan al menos 4GB RAM"
fi

sudo apt install -y curl apt-transport-https lsb-release gnupg

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

echo "[+] Instalando Wazuh Indexer..."
sudo apt install -y wazuh-indexer

sudo tee /etc/wazuh-indexer/opensearch.yml > /dev/null <<EOF
network.host: "10.0.1.20"
node.name: "node-1"
cluster.name: "wazuh-cluster"
cluster.initial_master_nodes:
  - "node-1"
plugins.security.disabled: false
EOF

sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh

sudo systemctl daemon-reload
sudo systemctl enable wazuh-indexer
sudo systemctl start wazuh-indexer

echo "[+] Esperando a que Indexer esté listo..."
sleep 30

echo "[+] Instalando Wazuh Manager..."
sudo apt install -y wazuh-manager

sudo sed -i 's/<connection>secure<\/connection>/<connection>secure<\/connection>\n    <port>1514<\/port>\n    <protocol>tcp<\/protocol>/' /var/ossec/etc/ossec.conf

sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

echo "[+] Instalando Filebeat..."
sudo apt install -y filebeat

sudo tee /etc/filebeat/filebeat.yml > /dev/null <<EOF
output.elasticsearch:
  hosts: ["10.0.1.20:9200"]
  protocol: https
  username: admin
  password: admin
  ssl.verification_mode: none

setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
EOF

sudo systemctl enable filebeat
sudo systemctl start filebeat

echo "[+] Instalando Wazuh Dashboard..."
sudo apt install -y wazuh-dashboard

sudo tee /etc/wazuh-dashboard/opensearch_dashboards.yml > /dev/null <<EOF
server.host: "10.0.1.20"
server.port: 443
opensearch.hosts: ["https://10.0.1.20:9200"]
opensearch.ssl.verificationMode: none
opensearch.username: admin
opensearch.password: admin
EOF

sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard

echo "[✓] Instalación completada"
echo ""
echo "=== Información de Acceso ==="
echo "Dashboard: https://10.0.1.20"
echo "Usuario: admin"
echo "Password: admin"
echo "Manager IP: 10.0.1.20"
echo "Manager Port: 1514"
echo ""
echo "[+] Para registrar agentes, usar esta clave:"
sudo cat /var/ossec/etc/authd.pass