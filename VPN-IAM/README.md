# Maqueta 3: VPN + IAM

## Componentes

- WireGuard (VPN site-to-site)
- Keycloak (Identity Provider)

## Instalación

\`\`\`bash
# Keycloak
cd scripts
./install-keycloak.sh
./create-realm.sh

# WireGuard
./setup-wireguard.sh server 10.0.1.40
\`\`\`
