#!/bin/bash
# create-fosil-realm.sh
# Crear y configurar el realm de Fósil Energías Renovables
# Con roles específicos para VPN con políticas granulares

set -e

KC_CLI="/opt/keycloak/bin/kcadm.sh"
SERVER="http://localhost:8080"
REALM="fosil"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Keycloak Realm Setup - Fósil Energías Renovables        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Verificar que Keycloak esté corriendo
if ! curl -s "$SERVER" > /dev/null; then
    echo "❌ ERROR: Keycloak no está accesible en $SERVER"
    echo "   Verificar: sudo systemctl status keycloak"
    exit 1
fi

echo "✅ Keycloak accesible en $SERVER"
echo ""

# Autenticar
echo "[1/6] Autenticando en Keycloak..."
sudo -u keycloak $KC_CLI config credentials \
    --server $SERVER \
    --realm master \
    --user admin \
    --password admin

echo "✅ Autenticación exitosa"
echo ""

# Verificar si el realm ya existe
if sudo -u keycloak $KC_CLI get realms/$REALM &> /dev/null; then
    echo "⚠️  El realm '$REALM' ya existe"
    read -p "¿Deseas eliminarlo y recrearlo? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        echo "[+] Eliminando realm existente..."
        sudo -u keycloak $KC_CLI delete realms/$REALM
        echo "✅ Realm eliminado"
    else
        echo "ℹ️  Manteniendo realm existente. Solo se crearán roles y usuarios faltantes."
    fi
fi

# Crear realm
echo ""
echo "[2/6] Creando/Actualizando realm '$REALM'..."
sudo -u keycloak $KC_CLI create realms -s realm=$REALM \
    -s enabled=true \
    -s registrationAllowed=false \
    -s resetPasswordAllowed=true \
    -s rememberMe=true \
    -s loginWithEmailAllowed=true \
    -s duplicateEmailsAllowed=false \
    -s sslRequired=NONE \
    -s 'displayName=Fósil Energías Renovables' \
    -s 'displayNameHtml=<b>Fósil Energías Renovables S.A.</b>' \
    2>/dev/null || echo "ℹ️  Realm ya existe, continuando..."

# Configurar políticas de password
echo "[+] Configurando políticas de contraseña..."
sudo -u keycloak $KC_CLI update realms/$REALM \
    -s 'passwordPolicy=length(8) and digits(1) and lowerCase(1) and upperCase(1) and specialChars(1) and notUsername(undefined)'

# Habilitar event logging (para analítica de comportamiento)
echo "[+] Habilitando event logging..."
sudo -u keycloak $KC_CLI update events/config -r $REALM \
    -s eventsEnabled=true \
    -s 'eventsListeners=["jboss-logging","file"]' \
    -s adminEventsEnabled=true \
    -s adminEventsDetailsEnabled=true \
    -s 'enabledEventTypes=["LOGIN","LOGIN_ERROR","LOGOUT","REGISTER","UPDATE_PASSWORD","UPDATE_PROFILE","SEND_RESET_PASSWORD"]' \
    2>/dev/null || echo "ℹ️  Event config ya aplicado"

echo "✅ Realm configurado"
echo ""

# Crear roles específicos para VPN
echo "[3/6] Creando roles para políticas de VPN..."

# Rol 1: Infraestructura Admin (acceso completo)
sudo -u keycloak $KC_CLI create roles -r $REALM \
    -s name=infraestructura-admin \
    -s 'description=Administradores de Infraestructura - Acceso completo VPN a toda la VPC (10.0.1.0/24)' \
    2>/dev/null || echo "ℹ️  Rol 'infraestructura-admin' ya existe"

# Rol 2: DevOps (acceso a SIEM y WAF)
sudo -u keycloak $KC_CLI create roles -r $REALM \
    -s name=devops \
    -s 'description=DevOps - Acceso VPN a Wazuh SIEM (10.0.1.20) y WAF/Kong (10.0.1.10)' \
    2>/dev/null || echo "ℹ️  Rol 'devops' ya existe"

# Rol 3: Viewer (solo lectura SIEM)
sudo -u keycloak $KC_CLI create roles -r $REALM \
    -s name=viewer \
    -s 'description=Viewer - Acceso VPN de solo lectura a Wazuh Dashboard (10.0.1.20)' \
    2>/dev/null || echo "ℹ️  Rol 'viewer' ya existe"

# Roles adicionales para contexto empresarial
sudo -u keycloak $KC_CLI create roles -r $REALM \
    -s name=operador-telemetria \
    -s 'description=Operadores de Telemetría IoT - Acceso a APIs de telemetría' \
    2>/dev/null || echo "ℹ️  Rol 'operador-telemetria' ya existe"

sudo -u keycloak $KC_CLI create roles -r $REALM \
    -s name=auditor \
    -s 'description=Auditores de Seguridad - Acceso de solo lectura a logs' \
    2>/dev/null || echo "ℹ️  Rol 'auditor' ya existe"

echo "✅ Roles creados"
echo ""

# Crear usuarios de prueba
echo "[4/6] Creando usuarios de prueba..."

# Función helper para crear usuario
create_user() {
    local username=$1
    local email=$2
    local firstname=$3
    local lastname=$4
    local role=$5
    local password=$6

    echo "[+] Creando usuario: $username ($role)"

    # Crear usuario
    USER_ID=$(sudo -u keycloak $KC_CLI create users -r $REALM \
        -s username=$username \
        -s email=$email \
        -s firstName="$firstname" \
        -s lastName="$lastname" \
        -s enabled=true \
        -s emailVerified=true \
        -i 2>/dev/null) || {
        echo "    ℹ️  Usuario ya existe, obteniendo ID..."
        USER_ID=$(sudo -u keycloak $KC_CLI get users -r $REALM -q username=$username --fields id | jq -r '.[0].id')
    }

    if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
        echo "    ❌ Error obteniendo ID del usuario"
        return 1
    fi

    # Establecer contraseña
    sudo -u keycloak $KC_CLI set-password -r $REALM \
        --username $username \
        --new-password "$password" \
        2>/dev/null || echo "    ℹ️  Contraseña ya establecida"

    # Asignar rol
    sudo -u keycloak $KC_CLI add-roles -r $REALM \
        --uusername $username \
        --rolename $role \
        2>/dev/null || echo "    ℹ️  Rol ya asignado"

    echo "    ✅ Usuario $username creado/actualizado"
}

# Usuario 1: Administrador de Infraestructura
create_user \
    "jperez" \
    "jperez@fosil.uy" \
    "Juan" \
    "Pérez" \
    "infraestructura-admin" \
    "Admin123!"

# Usuario 2: DevOps
create_user \
    "mgonzalez" \
    "mgonzalez@fosil.uy" \
    "María" \
    "González" \
    "devops" \
    "DevOps123!"

# Usuario 3: Viewer
create_user \
    "arodriguez" \
    "arodriguez@fosil.uy" \
    "Ana" \
    "Rodríguez" \
    "viewer" \
    "Viewer123!"

# Usuario 4: Operador Telemetría
create_user \
    "cmartinez" \
    "cmartinez@fosil.uy" \
    "Carlos" \
    "Martínez" \
    "operador-telemetria" \
    "Telemetria123!"

# Usuario 5: Auditor
create_user \
    "lsanchez" \
    "lsanchez@fosil.uy" \
    "Laura" \
    "Sánchez" \
    "auditor" \
    "Auditor123!"

echo ""
echo "✅ Usuarios creados"
echo ""

# Crear clientes OAuth2/OIDC
echo "[5/6] Creando clientes OAuth2/OIDC..."

# Cliente: Kong API Gateway
echo "[+] Cliente: Kong API Gateway"
sudo -u keycloak $KC_CLI create clients -r $REALM \
    -s clientId=kong-api \
    -s 'name=Kong API Gateway' \
    -s enabled=true \
    -s clientAuthenticatorType=client-secret \
    -s secret=kong-secret-2024 \
    -s publicClient=false \
    -s protocol=openid-connect \
    -s 'redirectUris=["http://10.0.1.10:8000/*","http://10.0.1.10:8443/*","https://10.0.1.10:8443/*"]' \
    -s 'webOrigins=["*"]' \
    -s directAccessGrantsEnabled=true \
    -s serviceAccountsEnabled=true \
    -s standardFlowEnabled=true \
    -s implicitFlowEnabled=false \
    2>/dev/null || echo "ℹ️  Cliente 'kong-api' ya existe"

# Cliente: Wazuh Dashboard (opcional para futuras integraciones)
echo "[+] Cliente: Wazuh Dashboard"
sudo -u keycloak $KC_CLI create clients -r $REALM \
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
    2>/dev/null || echo "ℹ️  Cliente 'wazuh-dashboard' ya existe"

echo "✅ Clientes OAuth2 creados"
echo ""

# Resumen final
echo "[6/6] Configuración completada"
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  ✅ REALM CONFIGURADO EXITOSAMENTE                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "📋 RESUMEN DE CONFIGURACIÓN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔗 Realm: $REALM"
echo "🌐 URL: $SERVER/realms/$REALM"
echo ""
echo "👥 USUARIOS CREADOS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  1. jperez@fosil.uy         | Admin123!        | infraestructura-admin"
echo "  2. mgonzalez@fosil.uy      | DevOps123!       | devops"
echo "  3. arodriguez@fosil.uy     | Viewer123!       | viewer"
echo "  4. cmartinez@fosil.uy      | Telemetria123!   | operador-telemetria"
echo "  5. lsanchez@fosil.uy       | Auditor123!      | auditor"
echo ""
echo "🔑 CLIENTES OAUTH2/OIDC:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  - kong-api         | Secret: kong-secret-2024"
echo "  - wazuh-dashboard  | Secret: wazuh-secret-2024"
echo ""
echo "📊 EVENT LOGGING:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Eventos habilitados (LOGIN, LOGIN_ERROR, LOGOUT, etc.)"
echo "  ✅ Eventos de admin habilitados"
echo "  ℹ️  Configurar logs → Wazuh para analítica de comportamiento"
echo ""
echo "🔧 PRÓXIMOS PASOS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  1. Configurar event logging → Wazuh SIEM"
echo "  2. Integrar Kong con OIDC plugin"
echo "  3. Generar configs VPN con: ./vpn-config-generator.sh <email>"
echo ""
echo "💡 GENERAR CONFIG VPN EJEMPLO:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  export VPN_SERVER_PUBLIC_IP=\$(terraform output -raw vpn_public_ip)"
echo "  ./vpn-config-generator.sh jperez@fosil.uy"
echo ""
