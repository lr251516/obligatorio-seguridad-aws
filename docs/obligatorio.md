# Seguridad en Redes y Datos - Obligatorio N6A

**Facultad de Ingeniería - Universidad ORT Uruguay**  
**Fecha:** 08-Sep-2025  
**Materia:** Seguridad en Redes y Datos  
**Carrera:** Analista en Infraestructura Informática

---

## Introducción

### Sobre la Empresa

**Fósil Energías Renovables S.A. (fosil.uy)** es una empresa uruguaya del sector energético con más de cinco décadas de trayectoria.

**Historia:**
- **Década de 1970:** Fundada como **Fósil S.A.**, dedicada a la importación, almacenamiento y distribución de hidrocarburos en el mercado nacional
- Durante varias décadas fue actor relevante en la cadena de suministro de combustibles fósiles, atendiendo clientes industriales y residenciales
- **Año 2015:** En el marco de la transición energética global y los compromisos del Uruguay en materia de energías limpias, adoptó un nuevo modelo de negocio y cambió su identidad corporativa a **Fósil Energías Renovables**

**Infraestructura Actual:**

La empresa combina:
- **Infraestructuras tradicionales:** Oleoductos, plantas de almacenamiento y distribución de combustibles
- **Energías renovables:** Parques solares y aerogeneradores ubicados principalmente en el interior del país

**Características Organizacionales:**
- ~500 colaboradores
- Centro de datos en Montevideo para sistemas de gestión
- Plataformas en la nube orientadas a clientes corporativos y usuarios residenciales
- Soluciones de telemetría e IoT para control de generación renovable

---

## Alcance del Proyecto

Su equipo es el responsable de la implementación de los controles de seguridad que se detallan a continuación.

### 1. Redes Privadas Virtuales (VPN)

#### a) Interconexión Datacenter - Nube
- Implementar la interconexión entre el centro de datos de Montevideo y la infraestructura en nube
- **Nota:** No es necesario tener en cuenta la redundancia

#### b) Acceso Administrativo Seguro
- Implementar acceso administrativo seguro para administradores de red y sistemas (usuarios privilegiados)
- **Requisitos:**
  - La protección debe tener en cuenta los desafíos y riesgos actuales de autenticación e identidad digital
  - La solución debe permitir asignar políticas granulares de acceso dependiendo de la identidad de quien se conecte

---

### 2. Protección de Aplicaciones Web (WAF y API Gateway)

#### a) API Gateway
- Implementar una solución de API Gateway que permita proteger la infraestructura de soporte de telemetría y aplicaciones

#### b) Web Application Firewall (WAF)
- Configurar una solución WAF que pueda detectar y detener los ataques comunes del **OWASP Top Ten** en tiempo real sin afectar la funcionalidad del portal web
- **Requisitos:**
  - Integración con el SIEM
  - Configurar al menos **dos reglas personalizadas**

---

### 3. Monitoreo y Respuesta (SIEM)

- Desplegar un SIEM para monitoreo, detección y respuesta
- **Integraciones requeridas:**
  - Debe integrarse con el resto de la maqueta, recibiendo alertas de:
    - Soluciones WAF
    - VPN
    - Plantilla GNU/Linux endurecida
- **Casos de uso:**
  - Configurar **3 casos de uso personalizados**
  - Al menos uno de ellos relacionado con **autenticación**

---

### 4. Gestión de Identidad y Accesos (IAM)

- Implementar o configurar un proveedor de identidad centralizado para los usuarios de la organización (interno)
- **Requisitos:**
  - Debe poder proveer un punto de autenticación y autorización utilizando protocolos estándares (**OAuth2 u OpenIDC**)
  - Debe poder integrarse o soportar analítica de comportamiento de usuarios para detectar patrones de uso (autenticación) anómalos

---

### 5. Plantilla de Servidor Endurecida

- Proponer una forma de estandarizar el proceso de endurecimiento del sistema operativo **GNU/Linux** utilizado como base para el despliegue de la infraestructura

#### Requisitos

- **Referencia:** CIS CSC Benchmark L1
- **Entregable:** Scripts que puedan replicarse con cada despliegue de servidor (NO una plantilla o imagen)
- **El endurecimiento debe contemplar como mínimo:**
  1. Firewall local
  2. Auditoría del sistema
  3. Acceso administrativo seguro
  4. Integración con el SIEM

---

## Requisitos de Entrega

Cada parte del trabajo entregado debe estar:
- ✅ Justificado
- ✅ Fundamentado
- ✅ Documentado

**Objetivo:** Tener siempre como norte la **seguridad de la información**

### Entregables Esperados

1. **Maqueta funcional**
2. **Despliegue para validación**
3. **Configuración de la solución**

### Puntaje Adicional

Se dará **puntaje específico** para configuraciones que permitan **despliegue automatizado**:
- Terraform
- Ansible
- ShellScript
- Otros

> **Importante:** No hay una única solución válida. La solución correcta es la correctamente justificada técnicamente con la información y supuestos del momento en que se tomaron las decisiones.

---

## Criterios de Evaluación

Se evaluará:

### 📋 Prolijidad de la documentación
- Títulos, subtítulos, tipo de letra, índice
- Coherencia de formatos

### ✍️ Ortografía
- Ausencia de faltas de ortografía

### 📚 Profundidad
- Profundidad de los temas tratados

### 🎯 Autogestión
- Autogestión de conocimiento

### 🔗 Referencias
- Correcta cita de fuentes de información

### 📐 Estándares
- Uso y paralelismo contra estándares o buenas prácticas reconocidas

### ✅ Completitud
- **Completitud de la solución**
- Considere **todos los aspectos** relacionados con la seguridad de la infraestructura propuesta, aún cuando no se pidan explícitamente
- **Recuerde:** El experto es Ud.

### 💡 Innovación
- Soluciones ingeniosas
- Propuestas innovadoras (pero probadas)

---
