from loginpass._core import UserInfo, OAuthBackend
# OAuthBackend is just a subclass of authlib.integrations._client.RemoteApp
class ShamOIDC(OAuthBackend):
    OAUTH_TYPE ="2.0,oidc"
    OAUTH_NAME = "sham_oidc"
    # from http://localhost:4000/openid/.well-known/openid-configuration
    OAUTH_CONFIG = {
        'api_base_url': 'http://localhost:4000/openid',
        'authorize_url': 'http://localhost:4000/openid/authorize',
        'access_token_url': 'http://localhost:4000/openid/token',
        'userinfo_url': 'http://localhost:4000/openid/userinfo',
        'server_metadata_url': 'http://localhost:4000/openid/.well-known/openid-configuration',
        'client_kwargs': {'scope': 'openid email profile'},
    }
    JWK_SET_URL = 'http://localhost:4000/openid/jwks'

    def profile(self, **kwargs):
        resp = self.get(self.OAUTH_CONFIG['userinfo_url'], **kwargs)
        resp.raise_for_status()
        return UserInfo(resp.json())

    def parse_openid(self, token, nonce=None):
        return self.profile(token=token)

