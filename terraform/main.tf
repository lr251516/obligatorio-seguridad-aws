# Infraestructura completa para Obligatorio SRD en AWS

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project    = "Obligatorio-SRD"
      University = "ORT-Uruguay"
      Group      = "N6A"
      ManagedBy  = "Terraform"
    }
  }
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "fosil-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "fosil-igw"
  }
}

# Subnet pública
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = var.availability_zone != "" ? var.availability_zone : data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "fosil-public-subnet"
  }
}

# Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  # Ruta para datacenter via IPSec tunnel (VPN VM)
  route {
    cidr_block           = "10.100.0.0/24"
    network_interface_id = aws_instance.vpn.primary_network_interface_id
  }

  tags = {
    Name = "fosil-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Group - Wazuh (SIEM)
resource "aws_security_group" "wazuh" {
  name        = "fosil-wazuh-sg"
  description = "Security group for Wazuh SIEM"
  vpc_id      = aws_vpc.main.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
    description = "SSH from my IP"
  }

  # Wazuh Dashboard (HTTPS)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Wazuh Dashboard"
  }

  # Wazuh Agent communication
  ingress {
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Wazuh agents"
  }

  # ICMP from datacenter (via IPSec tunnel)
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["10.100.0.0/24"]
    description = "ICMP from datacenter"
  }

  # Permitir tráfico interno VPC
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Internal VPC traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "fosil-wazuh-sg"
  }
}

# Security Group - VPN/IAM
resource "aws_security_group" "vpn" {
  name        = "fosil-vpn-sg"
  description = "Security group for VPN and Keycloak"
  vpc_id      = aws_vpc.main.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
    description = "SSH from my IP"
  }

  # Keycloak
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Keycloak"
  }

  # WireGuard
  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "WireGuard VPN"
  }

  # IPSec - IKE (phase 1)
  ingress {
    from_port   = 500
    to_port     = 500
    protocol    = "udp"
    cidr_blocks = ["104.30.133.214/32"]
    description = "IPSec IKE from datacenter"
  }

  # IPSec - NAT Traversal (phase 2)
  ingress {
    from_port   = 4500
    to_port     = 4500
    protocol    = "udp"
    cidr_blocks = ["104.30.133.214/32"]
    description = "IPSec NAT-T from datacenter"
  }

  # IPSec - ESP protocol
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "50"
    cidr_blocks = ["104.30.133.214/32"]
    description = "IPSec ESP from datacenter"
  }

  # ICMP for testing (ping from datacenter)
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["104.30.133.214/32"]
    description = "ICMP from datacenter"
  }

  # Tráfico interno
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "fosil-vpn-sg"
  }
}

# Security Group - WAF/Kong
resource "aws_security_group" "waf" {
  name        = "fosil-waf-sg"
  description = "Security group for WAF and Kong"
  vpc_id      = aws_vpc.main.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
    description = "SSH from my IP"
  }

  # Kong Admin API
  ingress {
    from_port   = 8001
    to_port     = 8001
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
    description = "Kong Admin API"
  }

  # Kong Admin GUI
  ingress {
    from_port   = 8002
    to_port     = 8002
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
    description = "Kong Admin GUI"
  }

  # HTTP for WAF (Nginx with ModSecurity)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP for WAF testing"
  }

  # Kong Proxy HTTP
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Kong Proxy HTTP"
  }

  # Kong Proxy HTTPS
  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Kong Proxy HTTPS"
  }

  # ICMP from datacenter (via IPSec tunnel)
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["10.100.0.0/24"]
    description = "ICMP from datacenter"
  }

  # Tráfico interno
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "fosil-waf-sg"
  }
}

# Security Group - Hardening
resource "aws_security_group" "hardening" {
  name        = "fosil-hardening-sg"
  description = "Security group for Hardening VM"
  vpc_id      = aws_vpc.main.id

  # SSH puerto 22
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
    description = "SSH port 22 from my IP (backup)"
  }

  # SSH puerto 2222 (post-hardening)
  ingress {
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
    description = "SSH port 2222 from my IP (hardened)"
  }

  # SSH desde VPN
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.vpn.id]
    description     = "SSH from VPN"
  }

  # WireGuard
  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "WireGuard VPN"
  }

  # ICMP from datacenter (via IPSec tunnel)
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["10.100.0.0/24"]
    description = "ICMP from datacenter"
  }

  # Tráfico interno
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "fosil-hardening-sg"
  }
}

# Security Group - Grafana
resource "aws_security_group" "grafana" {
  name        = "fosil-grafana-sg"
  description = "Security group for Grafana Dashboard"
  vpc_id      = aws_vpc.main.id

  # SSH desde mi IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
    description = "SSH from my IP"
  }

  # Grafana HTTP (puerto 3000) desde internet
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Grafana Dashboard HTTP"
  }

  # Tráfico interno VPC (para comunicación con Keycloak)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Internal VPC traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name = "fosil-grafana-sg"
  }
}

# Data source para obtener la AMI de Ubuntu más reciente
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Key Pair (necesitas crear tu propia key)
resource "aws_key_pair" "deployer" {
  key_name   = "fosil-deployer-key"
  public_key = file(var.public_key_path)

  tags = {
    Name = "fosil-deployer-key"
  }
}

# EC2 Instance - Wazuh SIEM
resource "aws_instance" "wazuh" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.wazuh_instance_type
  key_name      = aws_key_pair.deployer.key_name
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [aws_security_group.wazuh.id]

  private_ip = "10.0.1.20"

  root_block_device {
    volume_size = 40
    volume_type = "gp3"
  }

  user_data = file("${path.module}/user-data/wazuh-init.sh")

  tags = {
    Name = "fosil-wazuh-siem"
    Role = "SIEM"
  }
}

# EC2 Instance - VPN/IAM
resource "aws_instance" "vpn" {
  ami               = data.aws_ami.ubuntu.id
  instance_type     = var.vpn_instance_type
  key_name          = aws_key_pair.deployer.key_name
  subnet_id         = aws_subnet.public.id
  source_dest_check = false # Requerido para NAT/routing VPN

  vpc_security_group_ids = [aws_security_group.vpn.id]

  private_ip = "10.0.1.30"

  root_block_device {
    volume_size = 25
    volume_type = "gp3"
  }

  user_data = file("${path.module}/user-data/vpn-init.sh")

  tags = {
    Name = "fosil-vpn-iam"
    Role = "VPN-IAM"
  }
}

# EC2 Instance - WAF/Kong
resource "aws_instance" "waf" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  key_name      = aws_key_pair.deployer.key_name
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [aws_security_group.waf.id]

  private_ip = "10.0.1.10"

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = file("${path.module}/user-data/waf-init.sh")

  tags = {
    Name = "fosil-waf-kong"
    Role = "WAF"
  }
}

# EC2 Instance - Hardening
resource "aws_instance" "hardening" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  key_name      = aws_key_pair.deployer.key_name
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [aws_security_group.hardening.id]

  private_ip = "10.0.1.40"

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = file("${path.module}/user-data/hardening-init.sh")

  tags = {
    Name = "fosil-hardening"
    Role = "Hardening"
  }
}

# VM Grafana (10.0.1.50)
resource "aws_instance" "grafana" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  key_name      = aws_key_pair.deployer.key_name
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [aws_security_group.grafana.id]

  private_ip = "10.0.1.50"

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = file("${path.module}/user-data/grafana-init.sh")

  tags = {
    Name = "fosil-grafana"
    Role = "Grafana"
  }
}

# Elastic IP - Grafana
resource "aws_eip" "grafana" {
  instance = aws_instance.grafana.id
  domain   = "vpc"

  tags = {
    Name = "fosil-grafana-eip"
  }
}

# Elastic IP - Hardening (para testing/configuración inicial)
resource "aws_eip" "hardening" {
  instance = aws_instance.hardening.id
  domain   = "vpc"

  tags = {
    Name = "fosil-hardening-eip"
  }
}

# Elastic IP para Wazuh (dashboard accesible)
resource "aws_eip" "wazuh" {
  instance = aws_instance.wazuh.id
  domain   = "vpc"

  tags = {
    Name = "fosil-wazuh-eip"
  }
}

# Elastic IP para VPN (punto de entrada)
resource "aws_eip" "vpn" {
  instance = aws_instance.vpn.id
  domain   = "vpc"

  tags = {
    Name = "fosil-vpn-eip"
  }
}

# Elastic IP para WAF
resource "aws_eip" "waf" {
  instance = aws_instance.waf.id
  domain   = "vpc"

  tags = {
    Name = "fosil-waf-eip"
  }
}