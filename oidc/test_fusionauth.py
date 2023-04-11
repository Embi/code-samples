from flexmock import flexmock
import pytest
from requests import HTTPError, get, post

from auth.oidc import oidc_client
from auth.oidc.fusionauth import FusionAuth
from auth.oidc.oidc_client import OIDCFailure, PKCEFlow, Unauthorized
from tools.utils.mock_config_util import MockDictConfigUtil


FUSIONAUTH_OIDC_CONFIG = {
    'provider': 'fusionauth',
    'client_id': 'id1',
    'client_secret': 'secret',
    'url': 'oidc.example.com/',
    'management_api_key': 'secure-api-key',
}

FUSIONAUTH_OIDC_DICT_CONFIG = {
    'clientId': 'id1',
    'clientSecret': 'secret',
    'OIDCUrl': 'oidc.example.com/',
}


def test_userinfo():
    oidc = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)
    with pytest.raises(NotImplementedError):
        oidc.userinfo('access-token')


def test_token():
    fusionauth = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)
    expected_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    expected_paylod = {'payload_key': 'payload_value'}
    flexmock(oidc_client).should_receive('request_retried') \
        .with_args(post, 'oidc.example.com/oauth2/token',
                   headers=expected_headers, data=expected_paylod) \
        .and_return(flexmock(json=lambda: {'access': 'token'})) \
        .once()
    response = fusionauth.token({'payload_key': 'payload_value'})
    assert response == {'access': 'token'}


def test_refresh_token():
    oidc = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)
    flexmock(oidc).should_receive('token') \
        .with_args({
            'grant_type': 'refresh_token',
            'client_id': 'id1',
            'refresh_token': 'refresh-token'
        }).and_return({
            'access_token': 'access-token',
            'id_token': 'id-token',
        }).once()
    tokens = oidc.refresh_tokens('refresh-token')
    assert tokens.access_token == 'access-token'
    assert tokens.id_token == 'id-token'
    assert tokens.refresh_token == 'refresh-token'


def test_pkce_get_tokens():
    oidc = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)
    flexmock(oidc).should_receive('token') \
        .with_args({
            'grant_type': 'authorization_code',
            'code': 'auth-code',
            'code_verifier': 'code-verifier',
            'client_id': 'id1',
            'redirect_uri': 'redirect-uri',
        }).and_return({
            'access_token': 'access-token',
            'id_token': 'id-token',
            'refresh_token': 'refresh-token'
        }).once()
    flow = PKCEFlow('auth-url', 'redirect-uri', 'state', 'code-verifier')
    tokens = oidc.pkce_get_tokens('auth-code', flow)
    assert tokens.access_token == 'access-token'
    assert tokens.id_token == 'id-token'
    assert tokens.refresh_token == 'refresh-token'


def test_pkce_init():
    oidc = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)
    flexmock(oidc_client).should_receive('_generate_code_verifier') \
        .and_return('code-verifier') \
        .once()
    flexmock(oidc_client).should_receive('_generate_sha256_code_challenge') \
        .and_return('challenge') \
        .once()

    flow = oidc.pkce_init('redirect-uri')

    assert isinstance(flow.state, str)
    # 32-octet entropy must be at least 43 Base64 characters
    assert len(flow.state) >= 43
    assert flow.code_verifier == 'code-verifier'
    assert flow.redirect_uri == 'redirect-uri'

    expected_auth_url = (f"oidc.example.com/oauth2/authorize/?scope=openid"
                         f"%20offline_access%20email&response_type=code&client"
                         f"_id=id1&code_challenge=challenge&code_challenge_met"
                         f"hod=S256&state={flow.state}&redirect_uri="
                         f"redirect-uri")
    assert flow.authorize_url == expected_auth_url


def test_ropc_get_tokens():
    oidc = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)
    flexmock(oidc).should_receive('token') \
        .with_args({
            'grant_type': 'password',
            'scope': 'openid offline_access email',
            'client_id': 'id1',
            'client_secret': 'secret',
            'username': 'username',
            'password': 'password',
        }).and_return({
            'access_token': 'access-token',
            'id_token': 'id-token',
            'refresh_token': 'refresh-token'
        }).once()

    tokens = oidc.ropc_get_tokens('username', 'password')
    assert tokens.access_token == 'access-token'
    assert tokens.id_token == 'id-token'
    assert tokens.refresh_token == 'refresh-token'


def test_get_user():
    with MockDictConfigUtil('oidc', FUSIONAUTH_OIDC_CONFIG):
        oidc = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)

        # Test creation of three users where one of them does not exist (i.e.
        # 404 code is raised)
        expected_headers = {'Authorization': 'secure-api-key'}

        user_data = {
            'user': {
                'data': {
                    'groups': ['g1', 'g2'],
                },
                'id': 'oidc|id',
                'email': 'doe@example.com',
                'fullName': 'John Doe',
            }
        }

        processed_user_data = {
            'id': 'oidc|id',
            'email': 'doe@example.com',
            'name': 'John Doe',
            'groups': ['g1', 'g2'],
            'accounting': 'commercial',
        }

        flexmock(oidc_client).should_receive('request_retried') \
            .with_args(get, 'oidc.example.com/api/user/user1',
                       headers=expected_headers) \
            .and_return(flexmock(json=lambda: user_data)) \
            .once()

        exception_response = flexmock(status_code=404)

        user = oidc.get_user('user1')
        assert user == processed_user_data

        # Test non-existent user (401 response)
        flexmock(oidc_client).should_receive('request_retried') \
            .with_args(get, 'oidc.example.com/api/user/user2',
                       headers=expected_headers) \
            .and_raise(HTTPError(response=exception_response)) \
            .once()

        user = oidc.get_user('user2')
        assert user is None

        # Raise other than 404 exception
        exception_response = flexmock(status_code=401)

        flexmock(oidc_client).should_receive('request_retried') \
            .with_args(get, 'oidc.example.com/api/user/user1',
                       headers=expected_headers) \
            .and_raise(HTTPError(response=exception_response)) \
            .once()

        with pytest.raises(HTTPError):
            user = oidc.get_user('user1')


def test_process_user_get_data():
    oidc = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)

    user_info = {
        'user': {
            'data': {
                'groups': ['g1', 'g2'],
            },
            'id': 'oidc|id',
            'email': 'doe@example.com',
            'fullName': 'John Doe',
        }
    }
    expected_result = {
        'id': 'oidc|id',
        'email': 'doe@example.com',
        'name': 'John Doe',
        'groups': ['g1', 'g2'],
        'accounting': 'commercial',
    }
    result = oidc._process_user_get_data(user_info)
    assert result == expected_result


def test_get_management_auth_header():
    with MockDictConfigUtil('oidc', FUSIONAUTH_OIDC_CONFIG):
        oidc = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)
        auth_header = oidc.get_management_auth_header()
        assert auth_header == 'secure-api-key'


def test_call_oidc_endpoint():
    oidc = FusionAuth(FUSIONAUTH_OIDC_DICT_CONFIG)
    headers = {'Authorization': 'Bearer super-duper-access-token'}
    payload = {'payload_key': 'payload_value'}

    exception_response = flexmock(status_code=400, text='Access denied.')
    flexmock(oidc_client).should_receive('request_retried') \
        .with_args(post, 'oidc.example.com/oauth2/token',
                   headers=headers, json=payload) \
        .and_raise(HTTPError(response=exception_response)) \
        .once()

    with pytest.raises(Unauthorized) as e:
        oidc._call_oidc_endpoint('token', headers, payload)
    assert str(e.value) == 'Access denied.'

    exception_response = flexmock(status_code=500, text='Internal error.')
    flexmock(oidc_client).should_receive('request_retried') \
        .with_args(post, 'oidc.example.com/oauth2/token',
                   headers=headers, json=payload) \
        .and_raise(HTTPError(response=exception_response)) \
        .once()

    with pytest.raises(OIDCFailure) as e:
        oidc._call_oidc_endpoint('token', headers, payload)
    assert str(e.value) == 'Internal error.'
