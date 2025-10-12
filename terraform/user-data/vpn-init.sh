#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl wireguard-tools
hostnamectl set-hostname vpn-iam
mkdir -p /opt/fosil/scripts
echo "VPN init completed" > /tmp/user-data-completed.log
