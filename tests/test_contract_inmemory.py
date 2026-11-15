import pytest

from empreinte.testing import InMemoryVault, stepping_clock
from vault_contract import *  # noqa: F401,F403


@pytest.fixture
def vault():
    return InMemoryVault(clock=stepping_clock())
