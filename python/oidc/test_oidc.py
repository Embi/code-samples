import pytest

from auth.oidc import get_oidc_client
from tools.utils.mock_config_util import MockDictConfigUtil


def test_get_oidc_client():
    oidc_config = {
        'provider': 'auth0',
        'client_id': 'id1',
        'client_secret': 'secret',
        'url': 'oidc.example.com/',
    }

    oidc2_config = {
        'provider': 'auth0',
        'client_id': 'id2',
        'client_secret': 'secret',
        'url': 'oidc.example.com/',
    }

    oidc3_config = {
        'provider': 'auth0',
        'client_id': 'id3',
        'client_secret': 'secret',
        'url': 'oidc.example.com',
    }

    # Test singleton per client_id
    with MockDictConfigUtil('oidc', oidc_config):
        first_oidc_instance = get_oidc_client()
        second_oidc_instance = get_oidc_client('oidc')
    assert first_oidc_instance == second_oidc_instance

    with MockDictConfigUtil('oidc2', oidc2_config):
        other_cl_id_instance = get_oidc_client('oidc2')

    assert second_oidc_instance != other_cl_id_instance

    # Fail on missing backslash in the end of url
    with pytest.raises(AssertionError):
        with MockDictConfigUtil('oidc3', oidc3_config):
            get_oidc_client('oidc3')
