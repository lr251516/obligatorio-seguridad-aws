output "wazuh_public_ip" {
  value = aws_eip.wazuh.public_ip
}

output "wazuh_dashboard_url" {
  value = "https://${aws_eip.wazuh.public_ip}"
}

output "vpn_public_ip" {
  value = aws_eip.vpn.public_ip
}

output "keycloak_url" {
  value = "http://${aws_eip.vpn.public_ip}:8080"
}

output "waf_public_ip" {
  value = aws_eip.waf.public_ip
}

output "kong_proxy_url" {
  value = "http://${aws_eip.waf.public_ip}:8000"
}

output "hardening_private_ip" {
  value = aws_instance.hardening.private_ip
}

output "ssh_commands" {
  value = {
    wazuh     = "ssh -i ~/.ssh/obligatorio-srd ubuntu@${aws_eip.wazuh.public_ip}"
    vpn       = "ssh -i ~/.ssh/obligatorio-srd ubuntu@${aws_eip.vpn.public_ip}"
    waf       = "ssh -i ~/.ssh/obligatorio-srd ubuntu@${aws_eip.waf.public_ip}"
  }
}

output "architecture_summary" {
  value = <<-EOT
  
  ================================================
  ARQUITECTURA DESPLEGADA
  ================================================
  
  VM1: WAF/Kong        - 10.0.1.10 - t3.micro (1GB)   - GRATIS
  VM2: Wazuh SIEM      - 10.0.1.20 - m7i-flex.large (8GB) - ~$0.15/hora
  VM3: VPN/IAM         - 10.0.1.30 - t3.small (2GB)   - ~$0.02/hora
  VM4: Hardening       - 10.0.1.40 - t3.micro (1GB)   - GRATIS
  
  Costo combinado: ~$0.17/hora cuando están corriendo
  
  Proyecto completo (160 horas):
    - Wazuh: $24.00
    - VPN/IAM: $3.32
    - Total: $27.32
  
  Tus créditos: $118.13
  Restante después del proyecto: $90.81
  
  ================================================
  EOT
}