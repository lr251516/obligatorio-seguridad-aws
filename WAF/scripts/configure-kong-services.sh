#!/bin/bash
# Configurar servicios Kong para testing de reglas WAF
# Este script debe ejecutarse en la VM WAF después del deployment

set -e

KONG_ADMIN="http://10.0.1.10:8001"

echo "============================================"
echo "Configurando servicios Kong para testing WAF"
echo "============================================"
echo ""

# Verificar que Kong esté corriendo
if ! curl -s "$KONG_ADMIN" > /dev/null; then
    echo "❌ ERROR: Kong Admin API no responde en $KONG_ADMIN"
    exit 1
fi

echo "✅ Kong Admin API disponible"
echo ""

# ============================================
# SERVICIO 1: API de Telemetría (Mock)
# ============================================
echo "[1/3] Creando servicio: API Telemetría..."

# Crear servicio apuntando a httpbin.org (servicio público de testing)
SERVICE_ID=$(curl -s -X POST "$KONG_ADMIN/services/" \
    -d "name=telemetria-api" \
    -d "url=https://httpbin.org" \
    | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$SERVICE_ID" ]; then
    echo "   Servicio ya existe, obteniendo ID..."
    SERVICE_ID=$(curl -s "$KONG_ADMIN/services/telemetria-api" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

echo "   Service ID: $SERVICE_ID"

# Crear rutas
curl -s -X POST "$KONG_ADMIN/services/telemetria-api/routes" \
    -d "paths[]=/api/telemetria" \
    -d "methods[]=GET" \
    -d "methods[]=POST" > /dev/null

curl -s -X POST "$KONG_ADMIN/services/telemetria-api/routes" \
    -d "paths[]=/api/energia" \
    -d "methods[]=GET" > /dev/null

echo "   ✅ Rutas creadas: /api/telemetria, /api/energia"

# Rate limiting (20 req/min según regla 900003-5)
curl -s -X POST "$KONG_ADMIN/services/telemetria-api/plugins" \
    -d "name=rate-limiting" \
    -d "config.minute=20" \
    -d "config.policy=local" \
    -d "config.limit_by=ip" > /dev/null

echo "   ✅ Rate limiting: 20 req/min (por IP)"
echo ""

# ============================================
# SERVICIO 2: Admin Panel
# ============================================
echo "[2/3] Creando servicio: Admin Panel..."

SERVICE_ID=$(curl -s -X POST "$KONG_ADMIN/services/" \
    -d "name=admin-panel" \
    -d "url=https://httpbin.org/status/200" \
    | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$SERVICE_ID" ]; then
    echo "   Servicio ya existe, obteniendo ID..."
    SERVICE_ID=$(curl -s "$KONG_ADMIN/services/admin-panel" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

# Ruta de admin (bloqueada por WAF regla 900001 desde IPs externas)
curl -s -X POST "$KONG_ADMIN/services/admin-panel/routes" \
    -d "paths[]=/admin" \
    -d "methods[]=GET" \
    -d "methods[]=POST" > /dev/null

echo "   ✅ Ruta creada: /admin (bloqueada por WAF regla 900001)"
echo ""

# ============================================
# SERVICIO 3: Public API
# ============================================
echo "[3/3] Creando servicio: Public API..."

SERVICE_ID=$(curl -s -X POST "$KONG_ADMIN/services/" \
    -d "name=public-api" \
    -d "url=https://httpbin.org" \
    | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$SERVICE_ID" ]; then
    echo "   Servicio ya existe, obteniendo ID..."
    SERVICE_ID=$(curl -s "$KONG_ADMIN/services/public-api" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

# Rutas públicas para testing de ataques
curl -s -X POST "$KONG_ADMIN/services/public-api/routes" \
    -d "paths[]=/api/public" \
    -d "strip_path=false" > /dev/null

curl -s -X POST "$KONG_ADMIN/services/public-api/routes" \
    -d "paths[]=/" \
    -d "strip_path=false" > /dev/null

echo "   ✅ Rutas creadas: /api/public, /"
echo ""

# ============================================
# RESUMEN
# ============================================
echo "============================================"
echo "✅ Servicios Kong configurados"
echo "============================================"
echo ""
echo "📋 Endpoints disponibles:"
echo ""
echo "1. API Telemetría (Rate Limited 20/min):"
echo "   GET  http://$(hostname -I | awk '{print $1}')/api/telemetria"
echo "   POST http://$(hostname -I | awk '{print $1}')/api/telemetria"
echo "   GET  http://$(hostname -I | awk '{print $1}')/api/energia"
echo ""
echo "2. Admin Panel (Bloqueado desde IPs externas):"
echo "   GET  http://$(hostname -I | awk '{print $1}')/admin"
echo ""
echo "3. Public API (Para testing de ataques):"
echo "   GET  http://$(hostname -I | awk '{print $1}')/api/public"
echo "   GET  http://$(hostname -I | awk '{print $1}')/"
echo ""
echo "🧪 Testing de reglas WAF:"
echo ""
echo "# SQL Injection (regla OWASP CRS + custom 900004)"
echo "curl 'http://$(hostname -I | awk '{print $1}')/api/public?id=1' OR '1'='1'"
echo ""
echo "# XSS (regla OWASP CRS + custom 900003)"
echo "curl 'http://$(hostname -I | awk '{print $1}')/api/public?search=<script>alert(1)</script>'"
echo ""
echo "# Path Traversal (regla custom 900002)"
echo "curl 'http://$(hostname -I | awk '{print $1}')/api/public?file=../../etc/passwd'"
echo ""
echo "# Credenciales en URL (regla custom 900006)"
echo "curl 'http://$(hostname -I | awk '{print $1}')/api/public?password=123456&token=abc'"
echo ""
echo "# Scanner detection (regla custom 900007)"
echo "curl -A 'nikto/2.1.6' http://$(hostname -I | awk '{print $1}')/api/public"
echo ""
echo "# Admin panel desde IP externa (regla custom 900001)"
echo "curl http://$(hostname -I | awk '{print $1}')/admin"
echo ""
echo "# Rate limiting (20 req/min en /api/telemetria)"
echo "for i in {1..25}; do curl -s http://$(hostname -I | awk '{print $1}')/api/telemetria; done"
echo ""
echo "🔍 Ver logs en tiempo real:"
echo "sudo tail -f /var/log/nginx/error.log | grep ModSecurity"
echo ""
