import os
import tempfile
import pytest


@pytest.fixture(scope="session")
def _db_uri():
    tmpdir = tempfile.TemporaryDirectory()
    path = os.path.join(tmpdir.name, "test.db")
    uri = f"sqlite:///{path}"
    os.environ["DATABASE_URL"] = uri
    yield uri
    tmpdir.cleanup()


@pytest.fixture(scope="session")
def app(_db_uri):
    # Import after setting DATABASE_URL so the app binds to the temp DB
    from src import app as appmod
    app = appmod.app
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        LOGIN_DISABLED=False,
        RATELIMIT_ENABLED=False,
    )
    with app.app_context():
        appmod.db.drop_all()
        appmod.db.create_all()
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db_session(app):
    from src import app as appmod
    with app.app_context():
        yield appmod.db


# Ensure SQLite handles are released on Windows after the test session
@pytest.fixture(scope="session", autouse=True)
def _dispose_engine(app):
    yield
    from src import app as appmod
    with app.app_context():
        try:
            appmod.db.session.close()
        finally:
            appmod.db.engine.dispose()
