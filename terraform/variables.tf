variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "availability_zone" {
  description = "Specific AZ (try us-east-1b or us-east-1c if fails)"
  type        = string
  default     = ""
}

variable "my_ip" {
  description = "Your public IP address for SSH access (CIDR format)"
  type        = string
  default     = "104.30.133.214/32"
}

variable "public_key_path" {
  description = "Path to your SSH public key"
  type        = string
  default     = "~/.ssh/obligatorio-srd.pub"
}

variable "wazuh_instance_type" {
  description = "Instance type for Wazuh"
  type        = string
  default     = "m7i-flex.large"
}

variable "vpn_instance_type" {
  description = "Instance type for VPN/IAM"
  type        = string
  default     = "c7i-flex.large"
}

variable "github_repo" {
  description = "GitHub repository URL"
  type        = string
}

variable "github_branch" {
  description = "GitHub branch"
  type        = string
  default     = "main"
}
