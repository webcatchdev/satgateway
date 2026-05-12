# SatGateway VPS Deployment Guide

## Recommended VPS Providers
- **Hetzner CX21**: €5.35/mo, 2 vCPU, 4GB RAM, 40GB SSD (Europe)
- **Vultr Cloud Compute**: $6/mo, 1 vCPU, 1GB RAM, 25GB SSD (Global)
- **DigitalOcean Basic**: $6/mo, 1 vCPU, 512MB RAM, 10GB SSD
- **AWS Lightsail**: $5/mo, 1 vCPU, 1GB RAM, 40GB SSD

For Neutrino (Path B): Any of these work.
For Full Node (Path C): You need at least 800GB SSD. Hetzner CPX31 (€12, 4 vCPU, 8GB, 160GB) + attach volume, or Contabo VPS S SSD (€4, 4 vCPU, 8GB, 200GB) — though Contabo is oversubscribed.

---

## Path A: Hosted Lightning (Fastest — 5 min)

### Option 1: Voltage.cloud
1. Sign up at [voltage.cloud](https://voltage.cloud)
2. Create a node (Testnet first, then Mainnet)
3. Get your **REST endpoint** (e.g. `https://your-node.voltageapp.io`), **macaroon** (hex), and **TLS cert**
4. Set these env vars in SatGateway:
   ```bash
   LND_HOST=https://your-node.voltageapp.io
   LND_MACAROON=<hex_macaroon>
   LND_TLS_CERT_PATH=/app/lnd/tls.cert
   ```

### Option 2: Alby (Free tier available)
1. Get an Alby account + wallet at [getalby.com](https://getalby.com)
2. Use their **Developer Dashboard** → create an API key
3. SatGateway would need a small adapter (Alby uses REST, not LND native)

**Best for:** Getting to market fast, testing demand.
**Downside:** You're dependent on their uptime. Fees are higher.

---

## Path B: LND + Neutrino (Recommended — 30 min setup)

Neutrino lets LND run without a full Bitcoin node. It downloads only block **headers** (~50MB) and uses BIP157/158 filters to find your transactions. You can receive and send real Lightning payments.

### 1. Provision VPS (Ubuntu 24.04)
```bash
# SSH into your VPS
ssh root@your-vps-ip

# Update
apt update && apt upgrade -y

# Install Docker
apt install -y docker.io docker-compose-plugin
systemctl enable docker

# Create app user
useradd -m -s /bin/bash satgateway
usermod -aG docker satgateway
su - satgateway
```

### 2. Deploy LND + SatGateway
Copy these files to `/home/satgateway/`:

**docker-compose.neutrino.yml**
```yaml
version: "3.8"

services:
  lnd:
    image: lightninglabs/lnd:v0.18.0-beta
    container_name: lnd
    restart: unless-stopped
    ports:
      - "9735:9735"       # P2P Lightning
      - "8080:8080"       # REST API
    volumes:
      - ./lnd-data:/root/.lnd
      - ./lnd-neutrino.conf:/root/.lnd/lnd.conf
    command: >
      lnd
      --configfile=/root/.lnd/lnd.conf

  satgateway:
    build: .
    container_name: satgateway
    restart: unless-stopped
    ports:
      - "9026:9026"
    environment:
      - SATGATEWAY_KEY=${SATGATEWAY_KEY:-dev}
      - SATGATEWAY_FEE_BPS=${SATGATEWAY_FEE_BPS:-50}
      - SATGATEWAY_DB=/app/data/satgateway.db
      - REDIS_HOST=redis
      - LND_HOST=http://lnd:8080
      - LND_MACAROON_PATH=/lnd-macaroons/admin.macaroon
      - LND_TLS_CERT_PATH=/lnd-macaroons/tls.cert
      - LND_NETWORK=mainnet
    volumes:
      - ./lnd-data/data/chain/bitcoin/mainnet:/lnd-macaroons:ro
      - ./data:/app/data
    depends_on:
      - lnd
```

**lnd-neutrino.conf**
```ini
[Application Options]
listen=0.0.0.0:9735
restlisten=0.0.0.0:8080
tlsautorefresh=true

[Bitcoin]
bitcoin.active=true
bitcoin.mainnet=true
bitcoin.node=neutrino

[Neutrino]
neutrino.addpeer=btcd-mainnet.lightning.computer
neutrino.addpeer=mainnet1-btcd.zaphq.io
neutrino.addpeer=mainnet2-btcd.zaphq.io
neutrino.addpeer=bb1.breez.technology
neutrino.addpeer=node.blixtwallet.com
```

### 3. Start Services
```bash
docker compose -f docker-compose.neutrino.yml up -d

# Check LND logs
docker logs -f lnd

# Wait for "Finished resuming from historical sync" (5-15 min)
```

### 4. Create Wallet & Get Macaroon
```bash
# Create wallet (save the 24-word seed!)
docker exec -it lnd lncli create

# After wallet is ready, copy macaroon to host
docker cp lnd:/root/.lnd/data/chain/bitcoin/mainnet/admin.macaroon ./admin.macaroon
docker cp lnd:/root/.lnd/tls.cert ./tls.cert

# Get node info
docker exec lnd lncli getinfo
```

### 5. Fund Your Node (Real Sats)
To receive payments, you need **inbound liquidity**:
- **Option A:** Buy a channel from [LightningPool](https://pool.lightning.engineering) or [Amboss](https://amboss.space)
- **Option B:** Open a channel TO an existing node (you need on-chain BTC)
- **Option C:** Use [Lightning Terminal](https://terminal.lightning.engineering) to find peers
- **Option D (Testing):** Use [Bitcoin Testnet Faucet](https://coinfaucet.eu/en/btc-testnet/) + testnet config instead

### 6. Configure SatGateway
```bash
# On your VPS, SatGateway auto-connects via docker network
# From your local dev machine, test the API:
curl https://your-vps-ip:9026/payments/api/status
```

---

## Path C: Full Bitcoin Node + LND (Sovereign — 4+ hr sync)

Use this when you're doing serious volume and want zero trust.

**docker-compose.fullnode.yml**
```yaml
version: "3.8"

services:
  redis:
    image: redis:7-alpine
    container_name: satgateway-redis
    restart: unless-stopped

  bitcoind:
    image: bitcoin/bitcoin:28.0
    container_name: bitcoind
    restart: unless-stopped
    ports:
      - "8333:8333"       # Bitcoin P2P
      - "127.0.0.1:8332:8332"  # RPC (localhost only)
    volumes:
      - ./bitcoin-data:/bitcoin/.bitcoin
    command: >
      -chain=main
      -prune=550
      -rpcuser=satgateway
      -rpcpassword=CHANGE_ME_STRONG_PASSWORD
      -rpcbind=0.0.0.0
      -rpcallowip=0.0.0.0/0
      -server=1
      -txindex=0
      -dbcache=512
      -maxmempool=300
      -maxconnections=40

  lnd:
    image: lightninglabs/lnd:v0.18.0-beta
    container_name: lnd
    restart: unless-stopped
    ports:
      - "9735:9735"
      - "8080:8080"
    volumes:
      - ./lnd-data:/root/.lnd
      - ./lnd-fullnode.conf:/root/.lnd/lnd.conf
    command: >
      lnd
      --configfile=/root/.lnd/lnd.conf
    depends_on:
      - bitcoind

  satgateway:
    image: ghcr.io/webcatchdev/satgateway:latest
    container_name: satgateway
    restart: unless-stopped
    ports:
      - "9026:9026"
    environment:
      - SATGATEWAY_KEY=${SATGATEWAY_KEY:-dev}
      - SATGATEWAY_FEE_BPS=${SATGATEWAY_FEE_BPS:-50}
      - SATGATEWAY_DB=/app/data/satgateway.db
      - REDIS_HOST=redis
      - LND_HOST=http://lnd:8080
      - LND_MACAROON_PATH=/lnd-macaroons/admin.macaroon
      - LND_TLS_CERT_PATH=/lnd-macaroons/tls.cert
      - LND_NETWORK=mainnet
    volumes:
      - ./lnd-data/data/chain/bitcoin/mainnet:/lnd-macaroons:ro
      - ./data:/app/data
    depends_on:
      - lnd
      - redis
```

**lnd-fullnode.conf**
```ini
[Application Options]
listen=0.0.0.0:9735
restlisten=0.0.0.0:8080
tlsautorefresh=true

[Bitcoin]
bitcoin.active=true
bitcoin.mainnet=true
bitcoin.node=bitcoind

[Bitcoind]
bitcoind.rpchost=bitcoind:8332
bitcoind.rpcuser=satgateway
bitcoind.rpcpass=CHANGE_ME_STRONG_PASSWORD
bitcoind.zmqpubrawblock=tcp://bitcoind:28332
bitcoind.zmqpubrawtx=tcp://bitcoind:28333
```

**Storage note:** Even with `prune=550`, Bitcoin needs ~50GB. LND needs another ~10GB. Get a VPS with 100GB+ SSD minimum.

---

## Security Checklist

- [ ] **Firewall**: `ufw allow 22; ufw allow 9735; ufw allow 9026; ufw enable`
- [ ] **TLS**: Use Caddy or Nginx reverse proxy with Let's Encrypt for SatGateway API
- [ ] **Macaroons**: Never commit `admin.macaroon` to git. Use `invoice.macaroon` for read-only if possible.
- [ ] **Backups**: `lncli exportchanbackup --all` daily. Store the 24-word seed offline.
- [ ] **Updates**: Subscribe to [LND security alerts](https://groups.google.com/a/lightning.engineering/g/lnd-channels)

---

## Monitoring

Add to docker-compose:
```yaml
  watchtower:
    image: containrrr/watchtower
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --interval 3600 --cleanup
```

---

## Cost Comparison (Monthly)

| Setup | VPS Cost | Service Fees | Total | Best For |
|-------|----------|--------------|-------|----------|
| Voltage Hosted Node | $0 | ~$10-20 | $10-20 | Zero setup, testing |
| Neutrino (Hetzner CX21) | €5.35 | $0 | ~$6 | Real payments, low volume |
| Full Node (Hetzner CPX41 + Volume) | ~€25 | $0 | ~$28 | High volume, sovereignty |

---

## Next Steps

1. **Buy a Hetzner/Vultr VPS** (5 min)
2. **Start with Neutrino** (copy files above, 30 min)
3. **Create wallet, save seed** (5 min)
4. **Test with Testnet** first (change `bitcoin.mainnet=true` to `bitcoin.testnet=true` and `neutrino.addpeer` to testnet peers)
5. **Point SatGateway to your VPS**
6. **Buy inbound liquidity** when ready for mainnet

Want me to generate an Ansible playbook to automate the entire VPS setup?
