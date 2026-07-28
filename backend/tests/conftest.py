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


@pytest.fixture(autouse=True)
def _clear_caches():
    # In-process caches and rate-limit counters are module globals too — state
    # from one test must not be served to, or throttle, the next.
    from app.api import routes
    from app.services import analytics

    def reset():
        analytics.invalidate_sla_cache()
        routes._login_limiter.reset()
        try:
            from app import main

            main._general_limiter.reset()
            main._ai_limiter.reset()
        except ImportError:  # pragma: no cover - main not imported in some runs
            pass

    reset()
    yield
    reset()


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
