"""Regression tests for the SECRET_KEY fail-closed behaviour (V-04)."""
import pytest
import server


def test_app_refuses_to_start_without_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        server.create_app()


def test_app_refuses_the_legacy_default_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "dev-secret-change-me")
    with pytest.raises(RuntimeError):
        server.create_app()


def test_app_refuses_short_secret_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "short")
    with pytest.raises(RuntimeError):
        server.create_app()


def test_app_starts_with_strong_secret_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 40)
    app = server.create_app()
    assert app.config["SECRET_KEY"] == "s" * 40
