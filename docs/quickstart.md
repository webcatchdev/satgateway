# Quick Start

## Install

```bash
pip install satgateway
```

## Gate a FastAPI endpoint

```python
from fastapi import FastAPI
from satgateway import require_payment

app = FastAPI()

@app.get("/api/premium")
@require_payment(amount_sats=100, description="Access premium API")
def premium_data():
    return {"secret": "value"}
```

## Add a website paywall

```html
<script src="https://your-server.com/static/paywall.js"
        data-amount="100"
        data-resource="/api/premium">
</script>
```

## Run the server

```bash
export SATGATEWAY_KEY="your-api-key"
export MOCK_BACKEND=1  # Use mock backend for development
uvicorn main:app --host 0.0.0.0 --port 9026
```
