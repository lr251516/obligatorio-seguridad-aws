# Hardening con SCA

VM Ubuntu 22.04 hardenizada según CIS Benchmark Level 1 con Security Configuration Assessment automático via `terraform/user-data/hardening-init.sh`.

## Instalado Automáticamente

- Wazuh Agent con FIM configurado
- auditd (auditoría del sistema)
- fail2ban (protección brute force)
- UFW firewall configurado
- unattended-upgrades (actualizaciones automáticas)
- FIM en archivos críticos: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`

## Aplicar Hardening CIS (Opcional)

**El script está listo pero debe ejecutarse manualmente:**

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw hardening_public_ip)
cd /opt/fosil/Hardening/scripts
chmod +x apply-cis-hardening.sh
sudo ./apply-cis-hardening.sh
sudo reboot
```

## Ver Score en Dashboard

1. Acceder a Wazuh Dashboard: `https://<wazuh-ip>`
2. Ir a: **Security Configuration Assessment**
3. Seleccionar agente: **hardening-vm**
4. Ver score y checks fallados

## Score Esperado

- **Sin hardening:** 40-50%
- **Con hardening CIS L1:** 80-85%
- **Con política personalizada:** 85-90%
