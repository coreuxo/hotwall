#!/bin/bash

# Firewall rule setup script
# This adds basic NAT and filtering rules

echo "Setting up firewall rules..."

# Get external IP
EXT_IP=$(curl -s ifconfig.me)
if [ -z "$EXT_IP" ]; then
    EXT_IP="1.2.3.4"
fi

# Build firewall with NAT support
make clean
make

# Create basic rule set
cat > /tmp/firewall_rules.txt << EOF
# Basic firewall rules
# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Allow SSH
-A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Allow DNS
-A INPUT -p udp --dport 53 -j ACCEPT
-A OUTPUT -p udp --dport 53 -j ACCEPT

# Allow ICMP
-A INPUT -p icmp -j ACCEPT

# Default drop
-A INPUT -j DROP
-A FORWARD -j DROP

# NAT rules
# Masquerade outbound traffic
-A POSTROUTING -o eth0 -j MASQUERADE

# Port forward HTTP to internal server
-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.10:80
EOF

echo "Rule template created at /tmp/firewall_rules.txt"
echo "External IP: $EXT_IP"
echo "Firewall setup complete"
