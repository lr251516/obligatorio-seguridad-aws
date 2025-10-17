# Hardening con SCA

## Componentes

- Ubuntu 22.04 LTS hardened
- CIS Benchmarks Level 1
- Wazuh Agent con SCA habilitado
- Auditoría con auditd
- Firewall UFW + Fail2ban

## Aplicar Hardening

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@10.0.1.40
cd /opt/fosil/Hardening/scripts
chmod +x apply-cis-hardening.sh
sudo ./apply-cis-hardening.sh
sudo reboot
```

El agente Wazuh con FIM se instala automáticamente via user-data.

## Ver Score en Dashboard

1. Acceder a Wazuh Dashboard: `https://<wazuh-ip>`
2. Ir a: **Security Configuration Assessment**
3. Seleccionar agente: **hardening-vm**
4. Ver score y checks fallados

## Score Esperado

- **Sin hardening:** 40-50%
- **Con hardening CIS L1:** 80-85%
- **Con política personalizada:** 85-90%
