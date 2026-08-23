"""Provider selection and graceful degradation for differential screening.

No network calls — these cover the configuration logic, which is what
decides whether the layer runs at all.
"""
from __future__ import annotations

import pytest

from resumeshield import differential

PROVIDER_VARS = [env for env, _ in differential.PROVIDERS]


@pytest.fixture(autouse=True)
def clear_provider_env(monkeypatch):
    """Start every test from an unconfigured environment."""
    for env_var in PROVIDER_VARS:
        monkeypatch.delenv(env_var, raising=False)
    monkeypatch.delenv("RESUMESHIELD_SCREENER_MODEL", raising=False)


def test_no_provider_means_unavailable():
    assert differential.has_credentials() is False
    assert differential.active_provider() is None


def test_scan_degrades_with_a_useful_message():
    result = differential.run("raw text here", "sanitized text here")
    assert result.available is False
    assert "ANTHROPIC_API_KEY" in result.note
    assert "OPENAI_API_KEY" in result.note


@pytest.mark.parametrize("env_var,expected_model", differential.PROVIDERS)
def test_each_provider_selects_its_model(monkeypatch, env_var, expected_model):
    monkeypatch.setenv(env_var, "test-key")
    assert differential.has_credentials() is True
    assert differential._model() == expected_model


def test_first_configured_provider_wins(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("GROQ_API_KEY", "k")
    # Anthropic is absent, so OpenAI (earlier in the list than Groq) wins.
    assert differential._model() == "gpt-4o-mini"
    assert differential.active_provider() == "openai"


def test_explicit_model_overrides_every_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("RESUMESHIELD_SCREENER_MODEL", "gemini/gemini-2.0-flash")
    assert differential._model() == "gemini/gemini-2.0-flash"
    assert differential.active_provider() == "explicit"


def test_local_model_needs_no_key(monkeypatch):
    """Ollama and local proxies have no API key to detect, so an explicit
    model must be sufficient on its own."""
    monkeypatch.setenv("RESUMESHIELD_SCREENER_MODEL", "ollama/llama3.2")
    assert differential.has_credentials() is True
    assert differential._model() == "ollama/llama3.2"


def test_identical_texts_skip_the_call(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    result = differential.run("same text", "same   text")
    assert result.available is False
    assert "identical" in result.note.lower()


def test_verdict_parsing_tolerates_surrounding_prose():
    score, rec, reason = differential._parse_screener_reply(
        'Sure! {"score": 82, "recommendation": "advance", "reason": "strong"}'
    )
    assert score == 82
    assert rec == "advance"


def test_unparseable_verdict_returns_none():
    assert differential._parse_screener_reply("no json here")[0] is None
