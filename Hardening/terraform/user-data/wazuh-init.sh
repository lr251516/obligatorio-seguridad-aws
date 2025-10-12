#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl
hostnamectl set-hostname wazuh-siem
mkdir -p /opt/fosil/scripts
echo "Wazuh init completed" > /tmp/user-data-completed.log
