"""Shared fixtures: load the mock account once per test session."""

import os

import pytest

from analyzer.ingestion import load_inventory

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MOCK = os.path.join(_REPO, "data", "mock_account.json")


@pytest.fixture(scope="session")
def mock_inventory():
    return load_inventory(_MOCK)
