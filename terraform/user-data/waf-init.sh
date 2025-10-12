#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl
hostnamectl set-hostname waf-kong
mkdir -p /opt/fosil/scripts
echo "WAF init completed" > /tmp/user-data-completed.log
