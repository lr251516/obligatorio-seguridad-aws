#!/bin/bash
# create-fosil-realm.sh
# Crear y configurar el realm de Fósil Energías Renovables

set -e

KC_CLI="/opt/keycloak/bin/kcadm.sh"
SERVER="http://10.0.1.30:8080"

echo "[+] Configurando realm fosil-energias"

# Autenticar
sudo -u keycloak $KC_CLI config credentials \
    --server $SERVER \
    --realm master \
    --user admin \
    --password admin

# Crear realm
echo "[+] Creando realm..."
sudo -u keycloak $KC_CLI create realms -s realm=fosil-energias \
    -s enabled=true \
    -s registrationAllowed=false \
    -s resetPasswordAllowed=true \
    -s rememberMe=true \
    -s loginWithEmailAllowed=true \
    -s duplicateEmailsAllowed=false \
    -s sslRequired=NONE \
    -s 'displayName=Fósil Energías Renovables' \
    -s 'displayNameHtml=<b>Fósil Energías Renovables S.A.</b>'

# Configurar políticas de password
sudo -u keycloak $KC_CLI update realms/fosil-energias -s 'passwordPolicy=length(8) and digits(1) and lowerCase(1) and upperCase(1) and specialChars(1) and notUsername(undefined)'

# Crear roles
echo "[+] Creando roles..."
sudo -u keycloak $KC_CLI create roles -r fosil-energias -s name=admin-sistemas -s 'description=Administradores de Sistemas'
sudo -u keycloak $KC_CLI create roles -r fosil-energias -s name=admin-redes -s 'description=Administradores de Redes'
sudo -u keycloak $KC_CLI create roles -r fosil-energias -s name=operador-telemetria -s 'description=Operadores de Telemetría'
sudo -u keycloak $KC_CLI create roles -r fosil-energias -s name=auditor -s 'description=Auditores de Seguridad'

# Crear usuarios de prueba
echo "[+] Creando usuarios de prueba..."

# Admin de Sistemas
ADMIN_SYS_ID=$(sudo -u keycloak $KC_CLI create users -r fosil-energias \
    -s username=admin.sistemas \
    -s email=admin.sistemas@fosil.uy \
    -s firstName=Admin \
    -s lastName=Sistemas \
    -s enabled=true \
    -i)
sudo -u keycloak $KC_CLI set-password -r fosil-energias --username admin.sistemas --new-password Admin123!
sudo -u keycloak $KC_CLI add-roles -r fosil-energias --uusername admin.sistemas --rolename admin-sistemas

# Admin de Redes
ADMIN_RED_ID=$(sudo -u keycloak $KC_CLI create users -r fosil-energias \
    -s username=admin.redes \
    -s email=admin.redes@fosil.uy \
    -s firstName=Admin \
    -s lastName=Redes \
    -s enabled=true \
    -i)
sudo -u keycloak $KC_CLI set-password -r fosil-energias --username admin.redes --new-password Redes123!
sudo -u keycloak $KC_CLI add-roles -r fosil-energias --uusername admin.redes --rolename admin-redes

# Operador Telemetría
OPE_TEL_ID=$(sudo -u keycloak $KC_CLI create users -r fosil-energias \
    -s username=operador.telemetria \
    -s email=operador@fosil.uy \
    -s firstName=Operador \
    -s lastName=Telemetría \
    -s enabled=true \
    -i)
sudo -u keycloak $KC_CLI set-password -r fosil-energias --username operador.telemetria --new-password Oper123!
sudo -u keycloak $KC_CLI add-roles -r fosil-energias --uusername operador.telemetria --rolename operador-telemetria

# Auditor
AUDITOR_ID=$(sudo -u keycloak $KC_CLI create users -r fosil-energias \
    -s username=auditor.seguridad \
    -s email=auditor@fosil.uy \
    -s firstName=Auditor \
    -s lastName=Seguridad \
    -s enabled=true \
    -i)
sudo -u keycloak $KC_CLI set-password -r fosil-energias --username auditor.seguridad --new-password Audit123!
sudo -u keycloak $KC_CLI add-roles -r fosil-energias --uusername auditor.seguridad --rolename auditor

# ============ CLIENTES OAUTH2/OIDC ============

echo "[+] Creando clientes OAuth2/OIDC..."

# Cliente: Kong API Gateway
KONG_CLIENT_ID=$(sudo -u keycloak $KC_CLI create clients -r fosil-energias \
    -s clientId=kong-api \
    -s 'name=Kong API Gateway' \
    -s enabled=true \
    -s clientAuthenticatorType=client-secret \
    -s secret=kong-secret-2024 \
    -s publicClient=false \
    -s protocol=openid-connect \
    -s 'redirectUris=["http://10.0.1.10:8000/*","http://10.0.1.10:8443/*"]' \
    -s 'webOrigins=["*"]' \
    -s directAccessGrantsEnabled=true \
    -s serviceAccountsEnabled=true \
    -s authorizationServicesEnabled=true \
    -s standardFlowEnabled=true \
    -s implicitFlowEnabled=false \
    -s 'defaultClientScopes=["profile","email","roles"]' \
    -i)

echo "Kong Client ID: $KONG_CLIENT_ID"

# Cliente: Wazuh Dashboard
WAZUH_CLIENT_ID=$(sudo -u keycloak $KC_CLI create clients -r fosil-energias \
    -s clientId=wazuh-dashboard \
    -s 'name=Wazuh Dashboard' \
    -s enabled=true \
    -s clientAuthenticatorType=client-secret \
    -s secret=wazuh-secret-2024 \
    -s publicClient=false \
    -s protocol=openid-connect \
    -s 'redirectUris=["https://10.0.1.20/*"]' \
    -s 'webOrigins=["*"]' \
    -s standardFlowEnabled=true \
    -s 'defaultClientScopes=["profile","email","roles"]' \
    -i)

echo "Wazuh Client ID: $WAZUH_CLIENT_ID"

# Cliente: OpenVPN
OPENVPN_CLIENT_ID=$(sudo -u keycloak $KC_CLI create clients -r fosil-energias \
    -s clientId=openvpn \
    -s 'name=OpenVPN Access Server' \
    -s enabled=true \
    -s publicClient=false \
    -s protocol=openid-connect \
    -s 'redirectUris=["https://10.0.1.30:943/*"]' \
    -s standardFlowEnabled=true \
    -s 'defaultClientScopes=["profile","email","roles"]' \
    -i)

echo "OpenVPN Client ID: $OPENVPN_CLIENT_ID"

# ============ EVENTOS PARA WAZUH ============

echo "[+] Configurando eventos para SIEM..."

# Habilitar todos los eventos
sudo -u keycloak $KC_CLI update events/config -r fosil-energias \
    -s eventsEnabled=true \
    -s eventsListeners='["jboss-logging"]' \
    -s 'enabledEventTypes=["LOGIN","LOGIN_ERROR","LOGOUT","REGISTER","REMOVE_TOTP","UPDATE_PASSWORD","UPDATE_PROFILE"]'

# Guardar eventos de admin
sudo -u keycloak $KC_CLI update events/config -r fosil-energias \
    -s adminEventsEnabled=true \
    -s adminEventsDetailsEnabled=true

echo "[✓] Realm configurado correctamente"
echo ""
echo "=== RESUMEN DE CONFIGURACIÓN ==="
echo ""
echo "Realm: fosil-energias"
echo "URL: http://10.0.1.30:8080/realms/fosil-energias"
echo ""
echo "Usuarios creados:"
echo "  - admin.sistemas / Admin123!"
echo "  - admin.redes / Redes123!"
echo "  - operador.telemetria / Oper123!"
echo "  - auditor.seguridad / Audit123!"
echo ""
echo "Clientes OAuth2:"
echo "  - kong-api (secret: kong-secret-2024)"
echo "  - wazuh-dashboard (secret: wazuh-secret-2024)"
echo "  - openvpn"
echo ""
echo "Exportar realm:"
echo "  sudo -u keycloak /opt/keycloak/bin/kc.sh export --realm fosil-energias --file /tmp/fosil-realm.json"