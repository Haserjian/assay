"""Tests for assay cards list / assay cards show CLI commands."""

import json

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app

runner = CliRunner()


class TestCardsList:
    def test_list_human(self):
        result = runner.invoke(assay_app, ["cards", "list"])
        assert result.exit_code == 0
        assert "receipt_completeness" in result.output
        assert "guardian_enforcement" in result.output
        assert "coverage_contract" in result.output

    def test_list_json(self):
        result = runner.invoke(assay_app, ["cards", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["command"] == "cards list"
        ids = [c["card_id"] for c in data["cards"]]
        assert "receipt_completeness" in ids
        assert "guardian_enforcement" in ids
        assert len(data["cards"]) == 6

    def test_list_json_card_shape(self):
        result = runner.invoke(assay_app, ["cards", "list", "--json"])
        data = json.loads(result.output)
        for card in data["cards"]:
            assert set(card.keys()) == {"card_id", "name", "description", "claims"}
            assert isinstance(card["claims"], int)
            assert card["claims"] >= 1


class TestCardsShow:
    def test_show_human(self):
        result = runner.invoke(assay_app, ["cards", "show", "receipt_completeness"])
        assert result.exit_code == 0
        assert "Receipt Completeness" in result.output
        assert "min_receipt_count" in result.output
        assert "model_call_present" in result.output
        assert "Claim set hash" in result.output

    def test_show_json(self):
        result = runner.invoke(assay_app, ["cards", "show", "receipt_completeness", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["card_id"] == "receipt_completeness"
        assert data["name"] == "Receipt Completeness"
        assert len(data["claims"]) == 2
        assert "claim_set_hash" in data

    def test_show_json_claim_shape(self):
        result = runner.invoke(assay_app, ["cards", "show", "coverage_contract", "--json"])
        data = json.loads(result.output)
        claim = data["claims"][0]
        assert set(claim.keys()) == {"claim_id", "description", "check", "params", "severity"}
        assert claim["severity"] in ("critical", "warning")

    def test_show_unknown_card(self):
        result = runner.invoke(assay_app, ["cards", "show", "nonexistent"])
        assert result.exit_code == 3
        assert "Unknown card" in result.output

    def test_show_unknown_card_json(self):
        result = runner.invoke(assay_app, ["cards", "show", "nonexistent", "--json"])
        assert result.exit_code == 3
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "nonexistent" in data["error"]

    @pytest.mark.parametrize("card_id", [
        "guardian_enforcement",
        "receipt_completeness",
        "no_breakglass",
        "timestamp_ordering",
        "schema_consistency",
        "coverage_contract",
    ])
    def test_show_all_builtin_cards(self, card_id):
        result = runner.invoke(assay_app, ["cards", "show", card_id, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["card_id"] == card_id
        assert len(data["claims"]) >= 1

    def test_show_claim_set_hash_stable(self):
        """Claim set hash is deterministic across invocations."""
        r1 = runner.invoke(assay_app, ["cards", "show", "receipt_completeness", "--json"])
        r2 = runner.invoke(assay_app, ["cards", "show", "receipt_completeness", "--json"])
        h1 = json.loads(r1.output)["claim_set_hash"]
        h2 = json.loads(r2.output)["claim_set_hash"]
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex
