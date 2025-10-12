#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl wireguard-tools lynis auditd
hostnamectl set-hostname hardening-vm
mkdir -p /opt/fosil/scripts
echo "Hardening init completed" > /tmp/user-data-completed.log
