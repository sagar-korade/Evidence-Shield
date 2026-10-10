"""Pytest fixtures for EvidenceShield AI Backend."""

import os
import sys

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./evidenceshield_test.db"
os.environ["DATABASE_SYNC_URL"] = "sqlite:///./evidenceshield_test.db"

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../crypto")))

from backend.app.main import app
from backend.app.core.database import init_db, async_engine
from backend.seed import seed_all


@pytest_asyncio.fixture(scope="session", autouse=True)
async def prepare_database():
    """Initializes and seeds database once for test session."""
    if os.path.exists("evidenceshield_test.db"):
        try:
            os.remove("evidenceshield_test.db")
        except PermissionError:
            pass
    await seed_all()
    yield
    if os.path.exists("evidenceshield_test.db"):
        try:
            os.remove("evidenceshield_test.db")
        except PermissionError:
            pass


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
