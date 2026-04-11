"""Tests for demo feedback footer helpers."""

from __future__ import annotations

import sys

from assay.commands import _feedback_url_for_source, _should_show_feedback_footer


def test_feedback_url_defaults_to_discussions_with_source(monkeypatch):
    monkeypatch.delenv("ASSAY_FEEDBACK_URL", raising=False)
    assert _feedback_url_for_source("demo-challenge") == (
        "https://github.com/Haserjian/assay/discussions?src=demo-challenge"
    )


def test_feedback_url_respects_env_override(monkeypatch):
    monkeypatch.setenv("ASSAY_FEEDBACK_URL", "https://assay.sh/why")
    assert _feedback_url_for_source("demo-challenge") == (
        "https://assay.sh/why?src=demo-challenge"
    )


def test_feedback_footer_hidden_in_ci(monkeypatch):
    monkeypatch.setenv("CI", "1")
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert _should_show_feedback_footer() is False


def test_feedback_footer_hidden_when_not_tty(monkeypatch):
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    assert _should_show_feedback_footer() is False


def test_feedback_footer_shown_for_human_tty(monkeypatch):
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert _should_show_feedback_footer() is True
