#!/bin/bash
# One-shot VPS bootstrap for SatGateway
# Run as root on a fresh Ubuntu 24.04 VPS

set -e

DOMAIN=${1:-""}
EMAIL=${2:-""}

echo "=== SatGateway VPS Bootstrap ==="
echo "Mode: Neutrino (light client)"
echo ""

# Update system
apt update && apt upgrade -y

# Install essentials
apt install -y curl wget git ufw fail2ban

# Install Docker
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker root
    systemctl enable docker
fi

# Install Caddy for HTTPS
if ! command -v caddy &> /dev/null; then
    apt install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt update
    apt install -y caddy
fi

# Firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 9735/tcp   # Lightning P2P
ufw --force enable

# Clone SatGateway (adjust to your repo)
mkdir -p /opt/satgateway
cd /opt/satgateway
if [ ! -d ".git" ]; then
    git clone https://github.com/webcatchdev/satgateway.git . 2>/dev/null || echo "Please clone your repo manually to /opt/satgateway"
fi

# Create data dirs
mkdir -p lnd-data bitcoin-data

# Start with Neutrino
cd /opt/satgateway
docker compose -f docker-compose.neutrino.yml up -d --build

# Configure Caddy if domain provided
if [ -n "$DOMAIN" ]; then
    cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    reverse_proxy localhost:9026
}
EOF
    systemctl reload caddy
    echo "HTTPS configured for $DOMAIN"
fi

echo ""
echo "=== Bootstrap Complete ==="
echo ""
echo "Next steps:"
echo "  1. Create LND wallet:   docker exec -it lnd lncli create"
echo "  2. Check node info:     docker exec lnd lncli getinfo"
echo "  3. API status:          curl http://localhost:9026/api/status"
echo "  4. Get testnet sats:    https://coinfaucet.eu/en/btc-testnet/"
echo ""
echo "For mainnet: buy inbound liquidity after your first channel is open."
echo "Backup your 24-word seed OFFLINE."
