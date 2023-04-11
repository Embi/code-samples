import time

from flexmock import flexmock
import pytest
from requests import HTTPError, get, post

from auth.oidc import oidc_client
from auth.oidc.auth0 import Auth0
from auth.oidc.oidc_client import OIDCFailure, PKCEFlow, Unauthorized


AUTH0_OIDC_CONF = {
    'clientId': 'id1',
    'clientSecret': 'secret',
    'OIDCUrl': 'oidc.example.com/',
}


def test_userinfo():
    auth0 = Auth0(AUTH0_OIDC_CONF)
    with pytest.raises(NotImplementedError):
        auth0.userinfo('access-token')


def test_token():
    auth0 = Auth0(AUTH0_OIDC_CONF)
    expected_headers = {'Content-Type': 'application/json'}
    expected_paylod = {'payload_key': 'payload_value'}
    flexmock(oidc_client).should_receive('request_retried') \
        .with_args(post, 'oidc.example.com/oauth/token',
                   headers=expected_headers, json=expected_paylod) \
        .and_return(flexmock(json=lambda: {'access': 'token'})).once()
    response = auth0.token({'payload_key': 'payload_value'})
    assert response == {'access': 'token'}


def test_get_user():
    auth0_client = Auth0(AUTH0_OIDC_CONF)

    # Test creation of three users where one of them does not exist (i.e.
    # 404 code is raised)
    flexmock(auth0_client).should_receive('_get_management_token') \
        .and_return('management-token').once()

    expected_headers = {'Authorization': 'Bearer management-token'}

    user_data = {
        'app_metadata': {
            'groups': ['g1', 'g2'],
        },
        'user_id': 'oidc|user1',
        'email': 'doe@example.com',
        'name': 'John Doe',
    }

    processed_user_data = {
        'id': 'oidc|user1',
        'email': 'doe@example.com',
        'name': 'John Doe',
        'groups': ['g1', 'g2', 'accounting-commercial'],
        'accounting': 'commercial',
    }

    flexmock(oidc_client).should_receive('request_retried') \
        .with_args(get, 'oidc.example.com/api/v2/users/user1',
                   headers=expected_headers) \
        .and_return(flexmock(json=lambda: user_data)).once()

    exception_response = flexmock(status_code=404)

    user = auth0_client.get_user('user1')
    assert user == processed_user_data

    # Test non-existent user (401 response)
    flexmock(auth0_client).should_receive('_get_management_token') \
        .and_return('management-token').once()

    flexmock(oidc_client).should_receive('request_retried') \
        .with_args(get, 'oidc.example.com/api/v2/users/user2',
                   headers=expected_headers) \
        .and_raise(HTTPError(response=exception_response)).once()

    user = auth0_client.get_user('user2')
    assert user is None

    # Raise other than 404 exception
    flexmock(auth0_client).should_receive('_get_management_token') \
        .and_return('management-token').once()

    exception_response = flexmock(status_code=401)

    flexmock(oidc_client).should_receive('request_retried') \
        .with_args(get, 'oidc.example.com/api/v2/users/user1',
                   headers=expected_headers) \
        .and_raise(HTTPError(response=exception_response)).once()

    with pytest.raises(HTTPError):
        user = auth0_client.get_user('user1')


def test_get_management_auth_header():
    oidc = Auth0(AUTH0_OIDC_CONF)
    flexmock(oidc).should_receive('_get_management_token') \
        .and_return('access-token') \
        .once()
    auth_header = oidc.get_management_auth_header()
    assert auth_header == 'Bearer access-token'


def test_get_management_token():
    auth0_client = Auth0(AUTH0_OIDC_CONF)

    expected_grant = {
        'grant_type': 'client_credentials',
        'client_id': 'id1',
        'client_secret': 'secret',
        'audience': 'oidc.example.com/api/v2/',
    }

    # Test that a token is taken from cache before its expiration
    # and renewd after the expiration.

    # Note that the real expiration is offseted by a specified number
    # of seconds.
    expires_in = auth0_client._MANAGEMENT_TOKEN_EXPIRATION_OFFSET + 2
    flexmock(auth0_client).should_receive('token') \
        .with_args(expected_grant) \
        .and_return({
            'access_token': 'access-token1',
            'expires_in': expires_in,
        },
        {
            'access_token': 'access-token2',
            'expires_in': expires_in,
        }).one_by_one()

    token_1 = auth0_client._get_management_token()
    token_2 = auth0_client._get_management_token()
    time.sleep(3)
    token_3 = auth0_client._get_management_token()

    assert token_1 == 'access-token1'
    assert token_1 == token_2
    assert token_3 == 'access-token2'


def test_refresh_token():
    oidc = Auth0(AUTH0_OIDC_CONF)
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
    oidc = Auth0(AUTH0_OIDC_CONF)
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
    oidc = Auth0(AUTH0_OIDC_CONF)
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

    expected_auth_url = (f"oidc.example.com/authorize/?scope=openid"
                         f"%20offline_access%20email&response_type=code&client"
                         f"_id=id1&code_challenge=challenge&code_challenge_met"
                         f"hod=S256&state={flow.state}&redirect_uri="
                         f"redirect-uri")
    assert flow.authorize_url == expected_auth_url


def test_ropc_get_tokens():
    oidc = Auth0(AUTH0_OIDC_CONF)
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


def test_process_user_get_data():
    oidc = Auth0(AUTH0_OIDC_CONF)

    user_info = {
        'app_metadata': {
            'groups': ['g1', 'g2'],
        },
        'user_id': 'oidc|id',
        'email': 'doe@example.com',
        'name': 'John Doe',
    }
    expected_result = {
        'id': 'oidc|id',
        'email': 'doe@example.com',
        'name': 'John Doe',
        'groups': ['g1', 'g2', 'accounting-commercial'],
        'accounting': 'commercial',
    }
    result = oidc._process_user_get_data(user_info)
    assert result == expected_result


def test_call_oidc_endpoint():
    auth0 = Auth0(AUTH0_OIDC_CONF)
    headers = {'Authorization': 'Bearer super-duper-access-token'}
    payload = {'payload_key': 'payload_value'}

    exception_response = flexmock(status_code=403, text='Access denied.')
    flexmock(oidc_client).should_receive('request_retried') \
        .with_args(post, 'oidc.example.com/oauth/token',
                   headers=headers, json=payload) \
        .and_raise(HTTPError(response=exception_response)).once()

    with pytest.raises(Unauthorized) as e:
        auth0._call_oidc_endpoint('token', headers, payload)

    assert str(e.value) == 'Access denied.'

    exception_response = flexmock(status_code=500, text='Internal error.')
    flexmock(oidc_client).should_receive('request_retried') \
        .with_args(post, 'oidc.example.com/oauth/token',
                   headers=headers, json=payload) \
        .and_raise(HTTPError(response=exception_response)).once()

    with pytest.raises(OIDCFailure) as e:
        auth0._call_oidc_endpoint('token', headers, payload)

    assert str(e.value) == 'Internal error.'
