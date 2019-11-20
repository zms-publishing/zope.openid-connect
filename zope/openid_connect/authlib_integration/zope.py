from zExceptions import Redirect

from .framework_integration import FrameworkIntegration

class ZopeIntegration(FrameworkIntegration):
    
    def send_token_update(self, remote_app, name, token, refresh_token, access_token):
        pass
    
    def get_query_arguments_dict(self, request):
        return dict(request.form)
    
    def get_form_dict(self, request):
        return dict(request.form)
    
    # REFACT should probably get request as argument
    def set_request_global_value(self, name, value):
        # These values are not exposed to the user (e.g. through a cookie based session)
        # Never shared between requests, but can be setup even without a request
        # but are not shared between different flask apps active at the same time
        self.get_current_session()[name] = value
    
    # REFACT should probably get request as argument
    def get_request_global_value(self, name, default_value=None):
        # These values are not exposed to the user (e.g. through a cookie based session)
        return self.get_current_session().get(name, default_value)
    
    def set_session_value(self, name, value):
        self.get_current_session()[name] = value
    
    def get_session_value(self, name, default_value=None):
        return self.get_current_session().get(name, default_value)
    
    # REFACT is this really neccessary?
    # The BaseApp uses session.pop() in _get_session_value() - but why?
    def delete_session_value(self, name):
        return self.pop_session_value(name)
    
    # REFACT same, really neccessary?
    def pop_session_value(self, name, default_value=None):
        value = self.get_session_value(name, default_value)
        
        if name in self.get_current_session():
            del self.get_current_session()[name]
        
        return value
    
    # REFACT this should go away, probably more complex though
    def get_current_request(self):
        from zope.globalrequest import getRequest
        return getRequest()
    
    # REFACT this should go away, or return a proxy that adapts the interface of the local session to something
    # authlib expects
    def get_current_session(self):
        return self.get_current_request().SESSION
    
    def create_redirect_for_url(self, url):
        return Redirect(url)
    
    # OAuthRegistry support
    
    def is_fully_configured(self):
        return True # no half configured state supported for this plugin
    
    def assert_is_fully_configured(self):
        pass # no half configured state supported for this integration
    
    # REFACT consider rename did_finish_oauth_registry_setup
    def finish_registry_setup(self, registry):
        pass
    
    def get_config(self, name, default_value):
        value = self.config.get(name, default_value)
        return value
    
    def has_user_invisible_persistent_cache(self):
        return True
    
    def create_delayed_proxy_for_function(self, a_function):
        # Only required if self.assert_is_fully_configured() can return False
        breakpoint()
