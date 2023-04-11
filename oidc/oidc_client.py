from abc import ABCMeta, abstractmethod, abstractproperty
from base64 import urlsafe_b64encode
from hashlib import sha256
import secrets
from typing import NamedTuple

from requests import HTTPError, get, post

from tools.utils.retry import request_retried


class Unauthorized(Exception):
    pass


class OIDCFailure(Exception):
    pass


class OIDCTokens(NamedTuple):
    """OIDC recognises three tokens - ID, access and refresh.
    Access token is used by client to access resources (i.e. call API
    endpoints). ID token is only used to obtain some additional claims (in our
    case used to obtain email) about the authorized user. And refresh token is
    used to refresh ID and access tokens once they get expired."""
    access_token: str
    id_token: str
    refresh_token: str


class PKCEFlow(NamedTuple):
    """Class represents one OIDC PKCE grant flow.
    https://tools.ietf.org/html/rfc6749#section-4.1
    """
    authorize_url: str
    redirect_uri: str
    state: str
    code_verifier: str


class OIDCClient(metaclass=ABCMeta):
    """Client implements use-cases for communication with an OpenId Connect &
    OAuth 2.0 complient authorization server. Which primarily consists of
    three use-cases - /authorize, /token, /userinfo

    For OAuth 2.0 see https://tools.ietf.org/html/rfc6749 (primarily section 3)
    For OIDC see https://openid.net/specs/openid-connect-core-1_0.html

    Client also implements some management use-cases (e.g., get_user) which
    are not described by any specification.
    """

    # This is a singleton (per client_id) class
    _instances = {}
    _OIDC_ENDPOINTS = abstractproperty()
    _MANAGEMENT_ENDPOINTS = abstractproperty()
    _AUTHORIZE_QUERY_TEMPLATE = (
        '/?scope={scope}&'
        'response_type=code&'
        'client_id={client_id}&'
        'code_challenge={code_challenge}&'
        'code_challenge_method=S256&'
        'state={state}&'
        'redirect_uri={redirect_uri}'
    )
    _UNAUTHORIZED_CODES = abstractproperty()

    def __new__(cls, oidc_conf: dict) -> 'OIDCClient':
        client_id = oidc_conf.get('clientId')
        if cls._instances.get(client_id) is None:
            cls._instances[client_id] = super().__new__(cls)
        return cls._instances.get(client_id)

    def __init__(self, oidc_conf: dict):
        self.base_url = oidc_conf.get('OIDCUrl')
        self.client_id = oidc_conf.get('clientId')
        self.client_secret = oidc_conf.get('clientSecret')
        assert self.base_url.endswith('/')

    def userinfo(self, access_token: str) -> dict:
        """Call userinfo endpoint. Serves for obtaining claims (i.e. basic
        user information) related to an access_token.
        See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

        INFO: This endpoint is currently not used - user information is being
        obtained via get_user method (that calls an OIDC server's management
        endpoint). The reason for that is the ammount of data (primarily list
        of user's permissions) that would have to be included in the /userinfo
        reponse (and therefore also included in the ID Token) is too big
        which would (in case of Auth0) result in error for ID token being too
        big.
        """
        raise NotImplementedError()

    def token(self, grant_payload: dict) -> dict:
        """Call token endpoint. This serves for obtaining and refreshing JWT
        access and ID tokens. Either as the last step of PKCE flow or directly
        via ROPC/Client Credentials flow. Also serves for refreshing tokens.
        See:
        https://tools.ietf.org/html/rfc6749#section-3.2
        """
        headers = {'Content-Type': 'application/json'}
        return self._call_oidc_endpoint('token', headers, grant_payload)

    def get_user(self, user_id: str) -> dict:
        """Obtain data about specified user via managment endpoint.
        """
        headers = {'Authorization': self.get_management_auth_header()}
        url_path = self._MANAGEMENT_ENDPOINTS['getUser'].format(uid=user_id)
        url = self.base_url + url_path
        try:
            user = request_retried(get, url, headers=headers).json()
            user = self._process_user_get_data(user)
        except HTTPError as e:
            if e.response.status_code != 404:
                raise
            user = None
        return user

    def ropc_get_tokens(self, username, password) -> OIDCTokens:
        """Exchange user credentials for tokens via ROPC flow."""
        ropc_payload = {
            'grant_type': 'password',
            'scope': 'openid offline_access email',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': username,
            'password': password,
        }
        tokens = self.token(ropc_payload)
        return OIDCTokens(tokens['access_token'], tokens['id_token'],
                          tokens['refresh_token'])

    def pkce_init(self, redirect_uri: str) -> PKCEFlow:
        """Initialize PKCE flow."""
        state = secrets.token_urlsafe(32)
        code_verifier = _generate_code_verifier()
        code_challenge = _generate_sha256_code_challenge(code_verifier)
        authorize_url = self._get_authorize_url(state, code_challenge,
                                                redirect_uri)
        return PKCEFlow(authorize_url, redirect_uri, state, code_verifier)

    def pkce_get_tokens(self, auth_code: str,
                        pkce_flow: PKCEFlow) -> OIDCTokens:
        """Finalize PKCE flow by exchanging auth code for tokens."""
        pkce_token_payload = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'code_verifier': pkce_flow.code_verifier,
            'client_id': self.client_id,
            'redirect_uri': pkce_flow.redirect_uri,
        }
        tokens = self.token(pkce_token_payload)
        return OIDCTokens(tokens['access_token'], tokens['id_token'],
                          tokens['refresh_token'])

    def refresh_tokens(self, refresh_token: str) -> OIDCTokens:
        """Exchange refresh token for fresh new access and ID tokens."""
        refresh_tokens_payload = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'refresh_token': refresh_token,
        }
        fresh_tokens = self.token(refresh_tokens_payload)
        return OIDCTokens(fresh_tokens['access_token'],
                          fresh_tokens['id_token'], refresh_token)

    def _get_authorize_url(self, state, code_challenge, redirect_uri) -> str:
        """Generate authorization url for PKCE (Authorization Code) grant flow.
        The generated url is then opened by the end user in her browser.
        See:
        https://tools.ietf.org/html/rfc6749#section-3.1
        """
        # * `openid' to get OIDC tokens (ID and access token)
        # * `email` to get e-mail as part of the ID token
        # * `offline_access' to get refresh token
        scopes = ['openid', 'offline_access', 'email']
        # After successful authorization the user is redirected to
        # the redirect_uri to finalize the code challange.
        query = self._AUTHORIZE_QUERY_TEMPLATE.format(
            scope='%20'.join([s for s in scopes]),
            client_id=self.client_id,
            code_challenge=code_challenge,
            state=state,
            redirect_uri=redirect_uri,
        )
        endpoint_path = self._OIDC_ENDPOINTS['authorize']
        return self.base_url + endpoint_path + query

    @abstractmethod
    def _process_user_get_data(self, user_data: dict) -> dict:
        """Process response from getUser management endpoint. This method MUST
        return user information in this format:
        {
            'id': str,
            'email': str,
            'name': str,
            'groups': List[str],
            'accounting': str
        }
        """

    def _call_oidc_endpoint(
            self, endpoint_name: str, headers: dict, payload: dict = None,
            as_query_string: bool = False) -> dict:
        endpoint_path = self._OIDC_ENDPOINTS[endpoint_name]
        try:
            if as_query_string:
                # Send payload as application/x-www-form-urlencoded
                # instead of application/json
                payload = {'data': payload}
            else:
                payload = {'json': payload}
            response = request_retried(
                post, self.base_url + endpoint_path, headers=headers,
                **payload)
        except HTTPError as e:
            if e.response.status_code in self._UNAUTHORIZED_CODES:
                raise Unauthorized(e.response.text) from e
            raise OIDCFailure(e.response.text) from e
        return response.json()

    @abstractmethod
    def get_management_auth_header(self) -> str:
        """Get authorization header used for calling OIDC server's
        management endpoints.
        """


def _generate_code_verifier() -> str:
    """Generate a code verifier according to
    https://tools.ietf.org/html/rfc7636#section-4.1"""
    # Code Verifier should have at least 32-octet of entropy.
    return secrets.token_urlsafe(32)


def _generate_sha256_code_challenge(code_verifier: str) -> str:
    """Generate a code challenge from a code verifier according to
    https://tools.ietf.org/html/rfc7636#section-4.2
    """
    code_verifier_ascii = code_verifier.encode('ascii')
    code_challenge_binary = sha256(code_verifier_ascii).digest()
    # Code Challenge must be a URL-safe Base64 encoded with trailing `=`
    # stripped. See https://tools.ietf.org/html/rfc7636#section-3
    code_challenge_b64 = urlsafe_b64encode(code_challenge_binary).rstrip(b'=')
    return code_challenge_b64.decode('ascii')
