#!/bin/bash
# create-fosil-realm.sh
# Crear y configurar el realm de Fósil Energías Renovables
# Con roles específicos para VPN con políticas granulares

set -e

KC_CLI="/opt/keycloak/bin/kcadm.sh"
SERVER="http://localhost:8080"
REALM="fosil"

# Modo automático (no interactivo) para user-data scripts
AUTO_MODE=false
if [ "$1" = "--auto" ]; then
    AUTO_MODE=true
fi

echo ""
echo "  Keycloak Realm Setup - Fósil Energías Renovables        "
echo ""
echo ""

# Verificar que Keycloak esté corriendo
if ! curl -s "$SERVER" > /dev/null; then
    echo "[ERROR] ERROR: Keycloak no está accesible en $SERVER"
    echo "   Verificar: sudo systemctl status keycloak"
    exit 1
fi

echo "[OK] Keycloak accesible en $SERVER"
echo ""

# Autenticar
echo "[1/6] Autenticando en Keycloak..."
sudo -u keycloak $KC_CLI config credentials \
    --server $SERVER \
    --realm master \
    --user admin \
    --password admin

echo "[OK] Autenticación exitosa"
echo ""

# Verificar si el realm ya existe
if sudo -u keycloak $KC_CLI get realms/$REALM &> /dev/null; then
    echo "[WARN]  El realm '$REALM' ya existe"

    if [ "$AUTO_MODE" = true ]; then
        # Modo automático: eliminar y recrear sin preguntar
        echo "[AUTO] Modo automático: eliminando y recreando realm..."
        sudo -u keycloak $KC_CLI delete realms/$REALM 2>/dev/null || true
        echo "[OK] Realm eliminado automáticamente"
    else
        # Modo interactivo: preguntar al usuario
        read -p "¿Deseas eliminarlo y recrearlo? (s/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Ss]$ ]]; then
            echo "[+] Eliminando realm existente..."
            sudo -u keycloak $KC_CLI delete realms/$REALM
            echo "[OK] Realm eliminado"
        else
            echo "ℹ️  Manteniendo realm existente. Solo se crearán roles y usuarios faltantes."
        fi
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

echo "[OK] Realm configurado"
echo ""

# Crear roles para Grafana
echo "[3/6] Creando roles..."

# Rol 1: Admin (acceso completo a Grafana)
sudo -u keycloak $KC_CLI create roles -r $REALM \
    -s name=infraestructura-admin \
    -s 'description=Administradores - Acceso completo a Grafana (Admin)' \
    2>/dev/null || echo "ℹ️  Rol 'infraestructura-admin' ya existe"

# Rol 2: Editor (crear/editar dashboards)
sudo -u keycloak $KC_CLI create roles -r $REALM \
    -s name=devops \
    -s 'description=Editores - Crear y editar dashboards en Grafana (Editor)' \
    2>/dev/null || echo "ℹ️  Rol 'devops' ya existe"

# Rol 3: Viewer (solo lectura)
sudo -u keycloak $KC_CLI create roles -r $REALM \
    -s name=viewer \
    -s 'description=Visualizadores - Solo lectura de dashboards en Grafana (Viewer)' \
    2>/dev/null || echo "ℹ️  Rol 'viewer' ya existe"

echo "[OK] Roles creados"
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
        echo "    [ERROR] Error obteniendo ID del usuario"
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

    echo "    [OK] Usuario $username creado/actualizado"
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

echo ""
echo "[OK] Usuarios creados"
echo ""

# Crear clientes OAuth2/OIDC
echo "[5/6] Creando cliente OAuth2 para Grafana..."

# Cliente: Grafana Dashboard
echo "[+] Cliente: Grafana Dashboard"
sudo -u keycloak $KC_CLI create clients -r $REALM \
    -s clientId=grafana-oauth \
    -s 'name=Grafana Dashboard' \
    -s enabled=true \
    -s clientAuthenticatorType=client-secret \
    -s secret=grafana-secret-2024 \
    -s publicClient=false \
    -s protocol=openid-connect \
    -s 'redirectUris=["http://*:3000/*","http://10.0.1.50:3000/*"]' \
    -s 'webOrigins=["*"]' \
    -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=true \
    -s implicitFlowEnabled=false \
    -s 'defaultClientScopes=["email","profile","roles","offline_access"]' \
    2>/dev/null || echo "ℹ️  Cliente 'grafana-oauth' ya existe"

echo "[OK] Cliente OAuth2 creado"

# Obtener ID del cliente para agregar mapper
CLIENT_ID=$(sudo -u keycloak $KC_CLI get clients -r $REALM -q clientId=grafana-oauth 2>/dev/null | jq -r '.[0].id')

if [ -n "$CLIENT_ID" ] && [ "$CLIENT_ID" != "null" ]; then
  echo "[+] Configurando mapper de roles para Grafana..."
  sudo -u keycloak $KC_CLI create clients/$CLIENT_ID/protocol-mappers/models -r $REALM \
    -s name=roles \
    -s protocol=openid-connect \
    -s protocolMapper=oidc-usermodel-realm-role-mapper \
    -s 'config."claim.name"=roles' \
    -s 'config."jsonType.label"=String' \
    -s 'config."id.token.claim"=true' \
    -s 'config."access.token.claim"=true' \
    -s 'config."userinfo.token.claim"=true' \
    -s 'config."multivalued"=true' \
    2>/dev/null || echo "ℹ️  Mapper 'roles' ya existe"
  echo "[OK] Mapper de roles configurado"
fi
echo ""

# Resumen final
echo "[6/6] Configuración completada"
echo ""
echo ""
echo "  [OK] REALM CONFIGURADO EXITOSAMENTE                        "
echo ""
echo ""
echo " RESUMEN DE CONFIGURACIÓN"
echo ""
echo ""
echo "🔗 Realm: $REALM"
echo "🌐 URL: $SERVER/realms/$REALM"
echo ""
echo "👥 USUARIOS CREADOS:"
echo ""
echo "  1. jperez@fosil.uy         | Admin123!   | infraestructura-admin (Grafana Admin)"
echo "  2. mgonzalez@fosil.uy      | DevOps123!  | devops (Grafana Editor)"
echo "  3. arodriguez@fosil.uy     | Viewer123!  | viewer (Grafana Viewer)"
echo ""
echo "🔑 CLIENTE OAUTH2:"
echo ""
echo "  - grafana-oauth    | Secret: grafana-secret-2024"
echo ""
echo "📊 GRAFANA:"
echo ""
echo "  URL: http://10.0.1.40:3000"
echo "  Autenticación: Click 'Sign in with Keycloak'"
echo ""
echo "  Mapeo de roles:"
echo "    infraestructura-admin → Grafana Admin (full access)"
echo "    devops                → Grafana Editor (crear/editar dashboards)"
echo "    viewer                → Grafana Viewer (solo lectura)"
echo ""
echo " PRÓXIMOS PASOS:"
echo ""
echo "  1. Instalar Grafana:"
echo "     cd /opt/fosil/VPN-IAM/scripts"
echo "     sudo ./install-grafana.sh"
echo ""
echo "  2. Acceder a Grafana:"
echo "     http://10.0.1.40:3000"
echo "     Click 'Sign in with Keycloak'"
echo ""
echo "  3. Probar con usuarios:"
echo "     jperez@fosil.uy (Admin), mgonzalez@fosil.uy (Editor), arodriguez@fosil.uy (Viewer)"
echo ""
