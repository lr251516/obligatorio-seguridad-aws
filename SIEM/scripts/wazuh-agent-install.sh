#!/bin/bash
# Instalar agente Wazuh
WAZUH_MANAGER="10.0.1.20"
AGENT_NAME=$1
AGENT_GROUP=${2:-default}

[ -z "$AGENT_NAME" ] && { echo "Uso: $0 <nombre-agente> [grupo]"; exit 1; }

echo "Instalando agente Wazuh: $AGENT_NAME"

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

# Instalar agente
sudo WAZUH_MANAGER="$WAZUH_MANAGER" \
     WAZUH_AGENT_NAME="$AGENT_NAME" \
     apt install -y wazuh-agent

# Configurar agente
sudo tee /var/ossec/etc/ossec.conf > /dev/null <<EOF
<ossec_config>
  <client>
    <server>
      <address>${WAZUH_MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu22, ubuntu22.04</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Logging configuration -->
  <logging>
    <log_format>plain</log_format>
  </logging>

  <!-- File Integrity Monitoring (FIM) -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <alert_new_files>yes</alert_new_files>

    <!-- Archivos críticos del sistema -->
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/passwd</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/shadow</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/group</directories>

    <!-- Sudo configuration -->
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers.d</directories>

    <!-- SSH configuration -->
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssh/sshd_config</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/root/.ssh</directories>

    <!-- Firewall -->
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ufw</directories>

    <!-- Exclusiones -->
    <ignore>/etc/mtab</ignore>
    <ignore type="sregex">\.log$</ignore>
    <ignore type="sregex">\.swp$</ignore>
  </syscheck>

    <!-- Security Configuration Assessment (SCA) -->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
    
    <!-- Políticas CIS para Ubuntu 22.04 -->
    <policies>
      <policy>cis_ubuntu22-04.yml</policy>
      <policy>sca_unix_audit.yml</policy>
    </policies>
  </sca>

  <!-- Active response -->

  <!-- Log collection - Ajustar según la VM -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kern.log</location>
  </localfile>

  <!-- Rootcheck configuration -->
  <rootcheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
  </rootcheck>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
  </active-response>

</ossec_config>
EOF

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo "[+] Esperando conexión con manager..."
sleep 5

sudo systemctl status wazuh-agent --no-pager

echo ""
echo "[✓] Agente instalado: $AGENT_NAME"
echo "[+] Verificar en el Manager con: sudo /var/ossec/bin/agent_control -l"
echo ""
echo "Para agregar logs específicos, editar:"
echo "  /var/ossec/etc/ossec.conf"
echo ""

case $AGENT_GROUP in
    waf)
        echo "=== Configuración adicional para WAF ==="
        echo "Agregar estos bloques en /var/ossec/etc/ossec.conf:"
        cat <<'EOF_WAF'

  <!-- Kong logs -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/kong/access.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/kong/error.log</location>
  </localfile>

  <!-- ModSecurity logs -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/modsec_audit.log</location>
  </localfile>
EOF_WAF
        ;;
    vpn)
        echo "=== Configuración adicional para VPN ==="
        echo "Agregar estos bloques en /var/ossec/etc/ossec.conf:"
        cat <<'EOF_VPN'

  <!-- OpenVPN logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/openvpn/openvpn.log</location>
  </localfile>

  <!-- Keycloak logs -->
  <localfile>
    <log_format>multi-line</log_format>
    <location>/opt/keycloak/data/log/keycloak.log</location>
  </localfile>

  <!-- WireGuard via syslog -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
EOF_VPN
        ;;
    hardening)
        echo "=== Configuración adicional para Hardening VM ==="
        echo "Agregar estos bloques en /var/ossec/etc/ossec.conf:"
        cat <<'EOF_HARD'

  <!-- auditd logs -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <!-- UFW logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/ufw.log</location>
  </localfile>
EOF_HARD
        ;;
esac

echo ""
echo "Después de modificar ossec.conf, reiniciar:"
echo "  sudo systemctl restart wazuh-agent"