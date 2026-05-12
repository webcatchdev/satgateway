"""Pytest fixtures for SatGateway tests."""

import os
import tempfile
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from satgateway.core import MockBackend, GatewayConfig, SatGateway
from satgateway.middleware import init_gateway, PaymentGateway, require_payment


@pytest.fixture
def temp_db():
    """Provide a temporary database path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    os.unlink(path)


@pytest.fixture
def mock_backend():
    return MockBackend()


@pytest.fixture
def gateway(mock_backend, temp_db):
    """Fresh SatGateway with MockBackend and temp DB."""
    gw = SatGateway(
        backend=mock_backend,
        config=GatewayConfig(api_key="test-key"),
        db_path=temp_db
    )
    return gw


@pytest.fixture
def app(gateway):
    """FastAPI app with PaymentGateway router mounted."""
    # Initialize global gateway for decorator
    init_gateway(
        backend=gateway.backend,
        config=gateway.config,
        db_path=gateway.store.db_path
    )

    application = FastAPI()

    @application.get("/payments/api/secret")
    @require_payment(amount_sats=100, description="Access secret message")
    async def secret_message(request: Request):
        return {"message": "secret data"}

    @application.get("/payments/api/cheap")
    @require_payment(amount_sats=1, description="Cheap access")
    async def cheap_route(request: Request):
        return {"message": "cheap data"}

    @application.get("/payments/api/crash")
    @require_payment(amount_sats=50, description="Crash test")
    async def crash_route(request: Request):
        raise RuntimeError("intentional crash")

    # Include router directly since TestClient lifespan is tricky
    pg = PaymentGateway(sat_gateway=gateway)
    application.include_router(pg.router, prefix="/payments")

    return application


@pytest.fixture
def client(app):
    return TestClient(app)
