# Arquitectura del Sistema

## Componentes

### Maqueta 1: WAF + API Gateway
- **Kong Gateway**: API Gateway y reverse proxy
- **ModSecurity**: Web Application Firewall
- **OWASP CRS**: Reglas de seguridad

### Maqueta 2: SIEM (Wazuh)
- **Wazuh Manager**: Motor de análisis
- **Wazuh Indexer**: Base de datos de eventos
- **Wazuh Dashboard**: Visualización

### Maqueta 3: VPN + IAM
- **WireGuard**: VPN site-to-site
- **Keycloak**: Identity Provider

### Maqueta 4: Hardening
- **Ubuntu 22.04**: Sistema endurecido
- **CIS Benchmarks**: Estándares de seguridad
- **Lynis**: Auditoría

## Flujo de Comunicación

\`\`\`
Usuario → Kong (WAF) → Backend APIs
    ↓
  Wazuh (Logs)
    ↑
VPN + IAM (Autenticación)
    ↑
Hardening VM (Monitoreo)
\`\`\`
