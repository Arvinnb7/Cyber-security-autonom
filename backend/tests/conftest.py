import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.models  # noqa: F401 - register tables


@pytest.fixture(autouse=True)
def _reset_runtime_mode():
    # The runtime data mode is a module global; reset it between tests so a test
    # that switches to "live" can't leak into the next one.
    from app.core import runtime

    runtime._mode = None
    yield
    runtime._mode = None


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
