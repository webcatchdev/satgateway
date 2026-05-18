# Configuration

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SATGATEWAY_KEY` | Yes | — | API key for authentication |
| `SATGATEWAY_FEE_BPS` | No | 50 | Fee basis points (0.5%) |
| `LND_HOST` | No* | — | LND REST endpoint |
| `LND_MACAROON` | No* | — | LND macaroon hex |
| `LND_MACAROON_PATH` | No* | — | Path to macaroon file |
| `LND_TLS_CERT_PATH` | No* | — | Path to LND TLS cert |
| `LND_VERIFY_TLS` | No | true | Verify LND TLS certificate |
| `ALLOWED_ORIGINS` | No | — | Comma-separated CORS origins |
| `MOCK_BACKEND` | No | — | Set to `1` for mock backend (dev only) |

\* Required for production with LND backend. Use `MOCK_BACKEND=1` for development.

## Self-hosted with LND

```python
from satgateway.core import SatGateway, GatewayConfig, LndBackend
from satgateway.middleware import init_gateway

backend = LndBackend(
    host="https://localhost:8080",
    macaroon_hex="0201036c...",
    cert_path="~/.lnd/tls.cert",
    verify_tls=True
)

init_gateway(
    backend=backend,
    config=GatewayConfig(api_key="prod", fee_basis_points=50)
)
```
