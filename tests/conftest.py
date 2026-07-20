"""Fast, isolated test configuration for the control plane."""
import os
from pathlib import Path
from tempfile import gettempdir

TEST_DB = Path(gettempdir()) / "scanpod-enterprise-tests.db"
os.environ["SCANPOD_DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["SCANPOD_BOOTSTRAP_ENABLED"] = "true"
os.environ["SCANPOD_BOOTSTRAP_TOKEN"] = "test-bootstrap-token"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from scanpod_enterprise.db import Base, engine  # noqa: E402
from scanpod_enterprise.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-bootstrap-token"}
