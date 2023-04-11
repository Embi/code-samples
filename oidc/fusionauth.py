from auth.oidc.oidc_client import OIDCClient
from tools.utils import config_util


class FusionAuth(OIDCClient):

    _OIDC_ENDPOINTS = {
        'userinfo': 'oauth2/userinfo',
        'authorize': 'oauth2/authorize',
        'token': 'oauth2/token',
    }
    _MANAGEMENT_ENDPOINTS = {
        'getUser': 'api/user/{uid}',
    }

    _UNAUTHORIZED_CODES = (400,)

    def get_management_auth_header(self) -> str:
        """Returns API key for accessing Fusionauth management API"""
        return config_util.get('oidc').get('management_api_key')

    def _process_user_get_data(self, user_data: dict) -> dict:
        user_data = user_data['user']
        data = user_data.get('data', {})
        groups = data.get('groups', [])
        return {
            'id': user_data.get('id'),
            'email': user_data.get('email'),
            'name': user_data.get('fullName'),
            'groups': data.get('groups', []),
            'accounting': accounting,
        }

    def token(self, grant_payload: dict) -> dict:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        return self._call_oidc_endpoint(
            'token', headers, grant_payload, as_query_string=True)
