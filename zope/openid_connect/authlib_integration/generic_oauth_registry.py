import uuid
from authlib.integrations._client import OAuth as _OAuth

from .generic_remote_app import RemoteApp

__all__ = ['OAuth']
_req_token_tpl = '_{}_authlib_req_token_'


class OAuth(_OAuth):
    """A Flask OAuth registry for oauth clients.

    Create an instance with Flask::

        oauth = OAuth(app, cache=cache)

    You can also pass the instance of Flask later::

        oauth = OAuth()
        oauth.init_app(app, cache=cache)

    :param app: Flask application instance
    :param cache: A cache instance that has .get .set and .delete methods
    :param fetch_token: a shared function to get current user's token
    :param update_token: a share function to update current user's token
    """
    remote_app_class = RemoteApp
    
    framework_integration = None
    
    def __setstate__(self, instance_dict):
        self.__dict__.update(instance_dict)
    
    def __init__(self, framework_integration, fetch_token=None, update_token=None):
        super(OAuth, self).__init__(fetch_token, update_token)
        
        self.framework_integration = framework_integration
        if self.framework_integration.is_fully_configured():
            self.init_app()
    
    # REFACT this could be inverted, basically init_app() should be on the framework_integration and call back here / or just do the setup itself directly
    def init_app(self, fetch_token=None, update_token=None):
        """Initialize lazy for Flask app. This is usually used for Flask application
        factory pattern.
        """
        
        if fetch_token:
            self.fetch_token = fetch_token
        if update_token:
            self.update_token = update_token
        
        self.framework_integration.finish_registry_setup(self)

    def create_client(self, name):
        self.framework_integration.assert_is_fully_configured()
        return super(OAuth, self).create_client(name)

    def register(self, name, overwrite=False, **kwargs):
        if not self.oauth1_client_cls or not self.oauth2_client_cls:
            self.use_oauth_clients()

        self._registry[name] = (overwrite, kwargs)
        if self.framework_integration.is_fully_configured():
            return self.create_client(name)
        
        return self.framework_integration.create_delayed_proxy_for_function(
            lambda: self.create_client(name)
        )

    def load_config(self, name, params):
        rv = {}
        for k in params:
            conf_key = '{}_{}'.format(name, k).upper()
            v = self.framework_integration.get_config(conf_key, None)
            if v is not None:
                rv[k] = v
        return rv

    def generate_client_kwargs(self, name, overwrite, **kwargs):
        kwargs = super(OAuth, self).generate_client_kwargs(name, overwrite, **kwargs)

        if kwargs.get('request_token_url'):
            if self.framework_integration.has_user_invisible_persistent_cache():
                _add_cache_request_token(self.framework_integration, name, kwargs)
            else:
                _add_session_request_token(self.framework_integration, name, kwargs)
        return kwargs


def _add_cache_request_token(framework_integration, name, kwargs):
    if not kwargs.get('fetch_request_token'):
        def fetch_request_token():
            key = _req_token_tpl.format(name)
            sid = framework_integration.pop_session_value(key, None)
            if not sid:
                return None
            
            token = framework_integration.cache.get(sid)
            framework_integration.cache.cache.delete(sid)
            return token

        kwargs['fetch_request_token'] = fetch_request_token

    if not kwargs.get('save_request_token'):
        def save_request_token(token):
            key = _req_token_tpl.format(name)
            sid = uuid.uuid4().hex
            framework_integration.set_session_value(key, sid)
            framework_integration.cache.set(sid, token, 600)

        kwargs['save_request_token'] = save_request_token
    return kwargs


def _add_session_request_token(framework_integration, name, kwargs):
    if not kwargs.get('fetch_request_token'):
        def fetch_request_token():
            key = _req_token_tpl.format(name)
            return framework_integration.pop_session_value(key, None)

        kwargs['fetch_request_token'] = fetch_request_token

    if not kwargs.get('save_request_token'):
        def save_request_token(token):
            key = _req_token_tpl.format(name)
            framework_integration.set_session_value(key, token)

        kwargs['save_request_token'] = save_request_token

    return kwargs
