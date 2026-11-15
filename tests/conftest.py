"""Shared test guard: no test may reach a timestamp authority or any outside service.

A test that forgets to pass a fake transport to a reopened vault would otherwise send a
real RFC 3161 request (vault.transport None means HTTP). The guard replaces urlopen for
the whole run; a test that exercises http_transport monkeypatches urlopen itself.
"""
import urllib.request

import pytest


def _no_network(*args, **kwargs):
    raise AssertionError("a test tried to open a network connection (urllib.request.urlopen)")


@pytest.fixture(autouse=True)
def _forbid_network(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _no_network)
