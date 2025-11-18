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

output "hardening_public_ip" {
  value = aws_eip.hardening.public_ip
}

output "ssh_commands" {
  value = {
    wazuh     = "ssh -i ~/.ssh/obligatorio-srd ubuntu@${aws_eip.wazuh.public_ip}"
    vpn       = "ssh -i ~/.ssh/obligatorio-srd ubuntu@${aws_eip.vpn.public_ip}"
    waf       = "ssh -i ~/.ssh/obligatorio-srd ubuntu@${aws_eip.waf.public_ip}"
    hardening = "ssh -i ~/.ssh/obligatorio-srd ubuntu@${aws_eip.hardening.public_ip}"
  }
}

output "infrastructure_summary" {
  value = <<-EOT

  ================================================
  INFRAESTRUCTURA DESPLEGADA
  ================================================

  WAF/Kong:     ${aws_eip.waf.public_ip}    (10.0.1.10 - t3.micro)
  Wazuh SIEM:   ${aws_eip.wazuh.public_ip}  (10.0.1.20 - m7i-flex.large 8GB)
  VPN/IAM:      ${aws_eip.vpn.public_ip}    (10.0.1.30 - c7i-flex.large 4GB)
  Hardening:    ${aws_eip.hardening.public_ip}    (10.0.1.40 - t3.micro)

  URLs:
    - Wazuh:    https://${aws_eip.wazuh.public_ip}
    - Keycloak: http://${aws_eip.vpn.public_ip}:8080
    - Kong:     http://${aws_eip.waf.public_ip}:8000

  ================================================
  EOT
}