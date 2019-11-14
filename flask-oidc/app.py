import flask

app = flask.Flask(__name__)
app.config.from_pyfile('config.py')

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

def handle_authorize(remote, token, user_info):
    # token, userinfo can be None on failure
    # demo of what to do with that info, currently just returns it for display
    return flask.jsonify(token, user_info)


@app.route('/')
def index():
    tpl = '<li><a href="/{}/login">{}</a></li>'
    lis = [tpl.format(b.OAUTH_NAME, b.OAUTH_NAME) for b in [ShamOIDC]]
    return '<ul>{}</ul>'.format(''.join(lis))


from zope.openid_connect.authlib_integration import RemoteApp, OAuth
from zope.openid_connect.authlib_integration.flask import FlaskIntegration

# REFACT this needs to be a persistent cache, that saves this data server side.
# Could be on the user object, could be a server side session
# Just something that isn't exposed to the user
class Cache(object):
    def __init__(self):
        self._data = {}

    def get(self, k):
        return self._data.get(k)

    def set(self, k, v, timeout=None):
        self._data[k] = v

    def delete(self, k):
        if k in self._data:
            del self._data[k]

flask_integration = FlaskIntegration()
flask_integration.app = app
flask_integration.cache = Cache()

oauth = OAuth(framework_integration=flask_integration)

backend_cls = ShamOIDC
config = backend_cls.OAUTH_CONFIG.copy()
class FlaskRemoteApp(RemoteApp, backend_cls):
    pass

config['client_cls'] = FlaskRemoteApp
remote = oauth.register(backend_cls.OAUTH_NAME, overwrite=True, **config)
remote.framework_integration = flask_integration


@app.route('/{}/auth'.format(backend_cls.OAUTH_NAME), methods=('GET', 'POST'))
def auth():
    # REFACT consider how much of this can go into a function on the RemoteApp
    id_token = flask.request.values.get('id_token')
    if flask.request.values.get('code'):
        token = remote.authorize_access_token()
        if id_token:
            token['id_token'] = id_token
    elif id_token:
        token = {'id_token': id_token}
    elif request.values.get('oauth_verifier'):
        # OAuth 1
        token = remote.authorize_access_token()
    else:
        # handle failed
        return handle_authorize(remote, None, None)
    if 'id_token' in token:
        nonce = remote.get_nonce_from_session()
        user_info = remote.parse_openid(token, nonce)
    else:
        user_info = remote.profile(token=token)
    return handle_authorize(remote, token, user_info)

@app.route('/{}/login'.format(backend_cls.OAUTH_NAME))
def login():
    redirect_uri = flask.url_for('.auth', _external=True)
    conf_key = '{}_AUTHORIZE_PARAMS'.format(backend_cls.OAUTH_NAME.upper())
    params = flask.current_app.config.get(conf_key, {})
    if 'oidc' in backend_cls.OAUTH_TYPE:
        params['nonce'] = remote.generate_session_stored_nonce()
    return remote.authorize_redirect(redirect_uri, **params)
