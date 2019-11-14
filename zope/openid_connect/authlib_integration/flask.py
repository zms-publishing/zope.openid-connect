from werkzeug.local import LocalProxy

import flask
from flask import request, url_for, current_app, session
from flask import redirect, session
from flask import request as flask_req
from flask.signals import Namespace
from flask import _app_ctx_stack

from .framework_integration import FrameworkIntegration
from . import RemoteApp, OAuth


# REFACT consider to change the control flow, the FrameworkIntegration is initialized
# Then it creates the remote app and oauth registry as needed
# That would allow calling methods on there, instead of being a delegate only
# On the other hand: pure delegates are simpler
class FlaskIntegration(FrameworkIntegration):
    
    app = None
    cache = None
    
    _signal = Namespace()
    #: signal when token is updated
    token_update = _signal.signal('token_update')
    
    def send_token_update(self, remote_app, name, token, refresh_token, access_token):
        self.token_update.send(
            remote_app,
            name=name,
            token=token,
            refresh_token=refresh_token,
            access_token=access_token,
        )
    
    def get_query_arguments_dict(self, request):
        return request.args.to_dict(flat=True)
    
    def get_form_dict(self, request):
        return request.form.to_dict(flat=True)
    
    # REFACT should probably get request as argument
    def set_request_global_value(self, name, value):
        # These values are not exposed to the user (e.g. through a cookie based session)
        # Never shared between requests, but can be setup even without a request
        # but are not shared between different flask apps active at the same time
        ctx = _app_ctx_stack.top
        setattr(ctx, name, value)
    
    # REFACT should probably get request as argument
    def get_request_global_value(self, name, default_value=None):
        # These values are not exposed to the user (e.g. through a cookie based session)
        ctx = _app_ctx_stack.top
        return getattr(ctx, name, default_value)
    
    def set_session_value(self, name, value):
        flask.session[name] = value
    
    def get_session_value(self, name, default_value):
        return flask.session.get(name, default_value)
    
    # REFACT is this really neccessary?
    # The BaseApp uses session.pop() in _get_session_value() - but why?
    def delete_session_value(self, name):
        flask.session.pop(name, None)
    
    def pop_session_value(self, name, default_value):
        value = self.get_session_value(name, default_value)
        self.delete_session_value(name)
        return value
    
    # REFACT this should go away, probably more complex though
    def get_current_request(self):
        return flask.request
    
    # REFACT this should go away, or return a proxy that adapts the interface of the local session to something
    # authlib expects
    def get_current_session(self):
        return flask.session
    
    def create_redirect_for_url(self, url):
        return flask.redirect(url)
    
    # OAuthRegistry support
    
    def is_fully_configured(self):
        return self.app is not None
    
    def assert_is_fully_configured(self):
        if not self.app:
            raise RuntimeError('FramworkIntegration is not init with Flask app.')
    
    # REFACT consider rename did_finish_oauth_registry_setup
    def finish_registry_setup(self, registry):
        self.app.extensions = getattr(self.app, 'extensions', {})
        self.app.extensions['authlib.integrations.flask_client'] = registry
    
    def get_config(self, name, default_value):
        return self.app.config.get(name, default_value)
    
    def has_user_invisible_persistent_cache(self):
        return self.cache is not None
    
    def create_delayed_proxy_for_function(self, a_function):
        return LocalProxy(a_function)
