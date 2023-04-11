import time
from typing import NamedTuple

from auth.oidc.oidc_client import OIDCClient


class Auth0ManagementTokenInfo(NamedTuple):
    token: str
    expiration: int


class Auth0(OIDCClient):

    _OIDC_ENDPOINTS = {
        'userinfo': 'userinfo',
        'authorize': 'authorize',
        'token': 'oauth/token',
    }
    _MANAGEMENT_ENDPOINTS = {
        'getUser': 'api/v2/users/{uid}',
    }
    # If a management token is less than 60 seconds from expiration, request a
    # new one
    _MANAGEMENT_TOKEN_EXPIRATION_OFFSET = 60
    _management_tokens = {}

    _UNAUTHORIZED_CODES = (401, 403)

    def get_management_auth_header(self) -> str:
        management_token = self._get_management_token()
        return f'Bearer {management_token}'

    def _get_management_token(self) -> str:
        """Get Auth0 Management API token using client credentials flow. Take
        token from cache if already exist.
        """
        token_info = self._management_tokens.get(self.client_id)
        if token_info is not None and token_info.expiration - \
                self._MANAGEMENT_TOKEN_EXPIRATION_OFFSET > time.time():
            return token_info.token

        client_credentials_grant = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'audience': self.base_url + 'api/v2/',
        }
        response_dict = self.token(client_credentials_grant)
        token = response_dict['access_token']
        expiration = int(time.time() + response_dict['expires_in'])

        token_info = Auth0ManagementTokenInfo(token, expiration)
        self._management_tokens[self.client_id] = token_info
        return token_info.token

    def _process_user_get_data(self, user_data: dict) -> dict:
        app_metadata = user_data.get('app_metadata', {})
        groups = app_metadata.get('groups', [])
        return {
            'id': user_data.get('user_id'),
            'email': user_data.get('email'),
            'name': user_data.get('name'),
            'groups': groups,
        }
