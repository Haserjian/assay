"""Tests for demo feedback footer helpers."""

from __future__ import annotations

import sys

from assay.commands import _feedback_url_for_source, _should_show_feedback_footer


def test_feedback_url_defaults_to_structured_discussion_with_source(monkeypatch):
    monkeypatch.delenv("ASSAY_FEEDBACK_URL", raising=False)
    url = _feedback_url_for_source("demo-challenge")
    # Points at the "new discussion" form so responses land in a structured place,
    # not just the bare Discussions list.
    assert url.startswith("https://github.com/Haserjian/assay/discussions/new")
    assert "category=general" in url
    assert "title=First-run+feedback" in url
    # Source attribution is in the body so it survives the form-submit redirect
    # (GitHub drops unknown query params after the discussion is created).
    # URL-encoded "Source: demo-challenge" is "Source%3A+demo-challenge".
    assert "Source%3A+demo-challenge" in url
    # Belt-and-suspenders: ?src= is also kept for destinations that retain it.
    assert "src=demo-challenge" in url


def test_feedback_url_tags_try_source(monkeypatch):
    monkeypatch.delenv("ASSAY_FEEDBACK_URL", raising=False)
    url = _feedback_url_for_source("try")
    assert url.startswith("https://github.com/Haserjian/assay/discussions/new")
    assert "Source%3A+try" in url
    assert "src=try" in url


def test_feedback_url_respects_env_override(monkeypatch):
    monkeypatch.setenv("ASSAY_FEEDBACK_URL", "https://assay.sh/why")
    url = _feedback_url_for_source("demo-challenge")
    # Custom forms still get the source via both channels: a body= param
    # (created if it didn't exist) and the ?src= belt fallback.
    assert url.startswith("https://assay.sh/why?")
    assert "Source%3A+demo-challenge" in url
    assert "src=demo-challenge" in url


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
