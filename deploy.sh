#!/bin/bash
# SatGateway VPS deploy script
# Usage: ./deploy.sh [neutrino|fullnode]

set -e

MODE=${1:-neutrino}

echo "🚀 Deploying SatGateway in $MODE mode..."

# Pull latest images
docker compose -f docker-compose.$MODE.yml pull 2>/dev/null || true

# Start services
docker compose -f docker-compose.$MODE.yml up -d --build

echo ""
echo "✅ SatGateway is running!"
echo ""
echo "Next steps:"
echo "  1. Check LND status:  docker compose -f docker-compose.$MODE.yml logs -f lnd"
echo "  2. Create wallet:     docker exec -it lnd lncli create"
echo "  3. Get node info:     docker exec lnd lncli getinfo"
echo "  4. API endpoint:      http://$(curl -s ifconfig.me):9026/api/status"
echo ""
echo "For testnet, edit lnd-neutrino.conf and set bitcoin.testnet=true"
