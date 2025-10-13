#!/bin/bash
# Integración de Kong + ModSecurity con Wazuh SIEM
# Ejecutar en VM1 (WAF) después de instalar Kong y Wazuh agent

set -e

WAZUH_MANAGER="10.0.1.20"

echo "[+] Integrando Kong/ModSecurity con Wazuh SIEM"

# Verificar que Wazuh agent esté instalado
if ! command -v /var/ossec/bin/wazuh-control &> /dev/null; then
    echo "[!] Error: Wazuh agent no instalado"
    echo "Instalar primero: /opt/fosil/scripts/wazuh-agent-install.sh vm-waf waf"
    exit 1
fi

# Configurar logs personalizados en Wazuh agent
echo "[+] Configurando monitoreo de logs de Kong y ModSecurity..."

# Backup de configuración
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

# Agregar configuración de logs al ossec.conf
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<'EOF'

  <!-- Kong Access Logs -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/kong/access.log</location>
  </localfile>

  <!-- Kong Error Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kong/error.log</location>
  </localfile>

  <!-- Kong Admin Logs -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/kong/admin_access.log</location>
  </localfile>

  <!-- ModSecurity Audit Log -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/modsec_audit.log</location>
  </localfile>

  <!-- ModSecurity Debug Log (solo para troubleshooting) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/modsec_debug.log</location>
    <only-future-events>yes</only-future-events>
  </localfile>

EOF

# Configurar logrotate para ModSecurity
echo "[+] Configurando rotación de logs..."
sudo tee /etc/logrotate.d/modsecurity > /dev/null <<'EOF'
/var/log/modsec_audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        # Reiniciar Kong para que use el nuevo archivo
        systemctl reload kong || true
    endscript
}

/var/log/modsec_debug.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    size 100M
}
EOF

# Asegurar que los archivos de log existen con permisos correctos
echo "[+] Creando archivos de log..."
sudo touch /var/log/modsec_audit.log
sudo touch /var/log/modsec_debug.log
sudo chown www-data:adm /var/log/modsec_*.log
sudo chmod 640 /var/log/modsec_*.log

# Agregar usuario ossec al grupo adm para leer logs
sudo usermod -a -G adm ossec

# Configurar Kong para logging extendido
echo "[+] Configurando Kong para logging extendido..."

# Plugin de logging a syslog
curl -i -X POST http://localhost:8001/plugins \
  --data "name=syslog" \
  --data "config.successful_severity=info" \
  --data "config.log_level=info" \
  --data "config.facility=local7" || true

# Reiniciar Wazuh agent
echo "[+] Reiniciando Wazuh agent..."
sudo systemctl restart wazuh-agent

# Esperar un momento
sleep 5

# Verificar estado
echo "[+] Verificando conexión con Wazuh Manager..."
sudo /var/ossec/bin/wazuh-control status

# Test de logs
echo "[+] Generando eventos de prueba..."

# Test 1: Request normal
echo "Test 1: Request normal..."
curl -s http://localhost:8000/wazuh > /dev/null

# Test 2: SQL Injection (bloqueado por WAF)
echo "Test 2: SQL Injection attempt (debería ser bloqueado)..."
curl -s "http://localhost:8000/wazuh?id=1' OR '1'='1" > /dev/null || true

# Test 3: XSS (bloqueado por WAF)
echo "Test 3: XSS attempt (debería ser bloqueado)..."
curl -s "http://localhost:8000/wazuh?search=<script>alert(1)</script>" > /dev/null || true

# Test 4: Path Traversal (bloqueado por regla personalizada)
echo "Test 4: Path Traversal attempt (debería ser bloqueado)..."
curl -s "http://localhost:8000/../../../etc/passwd" > /dev/null || true

echo ""
echo "[✓] Integración completada"
echo ""
echo "=== Verificación ==="
echo ""
echo "1. Ver logs locales de ModSecurity:"
echo "   sudo tail -f /var/log/modsec_audit.log"
echo ""
echo "2. Ver logs de Kong:"
echo "   sudo tail -f /var/log/kong/access.log"
echo "   sudo tail -f /var/log/kong/error.log"
echo ""
echo "3. Ver estado del agente Wazuh:"
echo "   sudo /var/ossec/bin/wazuh-control status"
echo "   sudo tail -f /var/ossec/logs/ossec.log"
echo ""
echo "4. En el Wazuh Manager (VM2), verificar que llegan eventos:"
echo "   SSH a 10.0.1.20"
echo "   sudo tail -f /var/ossec/logs/alerts/alerts.log"
echo ""
echo "5. Acceder a Wazuh Dashboard:"
echo "   https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):443"
echo "   Buscar alertas con rule.id entre 100010 y 100014 (ataques web)"
echo ""
echo "=== Probar manualmente más ataques ==="
echo ""
echo "# SQL Injection variants"
echo "curl -v 'http://localhost:8000/api?id=1 UNION SELECT password FROM users'"
echo ""
echo "# XSS variants"
echo "curl -v 'http://localhost:8000/search?q=<img src=x onerror=alert(1)>'"
echo ""
echo "# RCE attempt"
echo "curl -v 'http://localhost:8000/api?cmd=;cat /etc/passwd'"
echo ""
echo "# Admin access desde IP no autorizada (si no estás en 10.0.1.x)"
echo "curl -v http://localhost:8000/admin"
echo ""
echo "# Escaneo de directorios"
echo "curl -v http://localhost:8000/../../etc/passwd"