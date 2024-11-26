from auth.oidc.auth0 import Auth0
from auth.oidc.fusionauth import FusionAuth
from auth.oidc.oidc_client import OIDCClient
from tools.utils import config_util


_OIDC_IMPLEMENTATION = {
    'auth0': Auth0,
    'fusionauth': FusionAuth,
}


def get_oidc_client(conf_namespace: str = 'oidc') -> OIDCClient:
    oidc_conf = {
        'clientId': config_util.get(conf_namespace).get('client_id'),
        'clientSecret': config_util.get(conf_namespace).get('client_secret'),
        'OIDCUrl': config_util.get(conf_namespace).get('url'),
        'OIDCProvider': config_util.get(conf_namespace).get('provider'),
    }
    return get_oidc_client_from_dict(oidc_conf)


def get_oidc_client_from_dict(oidc_conf: dict) -> OIDCClient:
    provider = oidc_conf.get('OIDCProvider')
    return _OIDC_IMPLEMENTATION[provider](oidc_conf)
