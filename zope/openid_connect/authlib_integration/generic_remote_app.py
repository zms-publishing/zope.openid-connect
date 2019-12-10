from authlib.common.security import generate_token
from authlib.integrations._client import UserInfoMixin
from authlib.integrations._client import RemoteApp as _RemoteApp

class RemoteApp(_RemoteApp, UserInfoMixin):
    """Flask integrated RemoteApp of :class:`~authlib.client.OAuthClient`.
    It has built-in hooks for OAuthClient. The only required configuration
    is token model.
    """

    def __init__(self, name, fetch_token=None, **kwargs):
        fetch_request_token = kwargs.pop('fetch_request_token', None)
        save_request_token = kwargs.pop('save_request_token', None)
        super(RemoteApp, self).__init__(name, fetch_token, **kwargs)

        self._fetch_request_token = fetch_request_token
        self._save_request_token = save_request_token

    def _send_token_update(self, token, refresh_token=None, access_token=None):
        self.token = token
        super(RemoteApp, self)._send_token_update(
            token, refresh_token, access_token
        )
        self.framework_integration.send_token_update(
            self,
            name=self.name,
            token=token,
            refresh_token=refresh_token,
            access_token=access_token,
        )
    
    def _set_session_data(self, request, key, value):
        sess_key = '_{}_authlib_{}_'.format(self.name, key)
        # request.session[sess_key] = value
        self.framework_integration.set_session_value(sess_key, value)

    def _get_session_data(self, request, key):
        sess_key = '_{}_authlib_{}_'.format(self.name, key)
        # Seems fishy, pop() will remove the key from the session
        # return request.session.pop(sess_key, None)
        return self.framework_integration.pop_session_value(sess_key, None)
    
    def _generate_access_token_params(self, request):
        if self.request_token_url:
            return self.framework_integration.dict_from_request_query_arguments(request)

        if request.method == 'GET':
            args = self.framework_integration.get_query_arguments_dict(request)
            params = {
                'code': args['code'],
                'state': args.get('state'),
            }
        else: # POST
            form = self.framework_integration.get_form_dict(request)
            params = {
                'code': form['code'],
                'state': form.get('state'),
            }
        return params

    @property
    def token(self):
        attr = 'authlib_oauth_token_{}'.format(self.name)
        token = self.framework_integration.get_request_global_value(attr)
        if token:
            return token
        
        # FIXME this fails if fetch_token is None
        if self._fetch_token:
            token = self._fetch_token()
            self.token = token
            return token

    @token.setter
    def token(self, token):
        attr = 'authlib_oauth_token_{}'.format(self.name)
        self.framework_integration.set_request_global_value(attr, token)

    def request(self, method, url, token=None, **kwargs):
        # REFACT seems redundant, superclass already does this?
        if token is None and not kwargs.get('withhold_token'):
            token = self.token
        return super(RemoteApp, self).request(
            method, url, token=token, **kwargs)

    def save_authorize_state(self, redirect_uri=None, state=None, **kwargs):
        """Save ``redirect_uri``, ``state`` and other temporary data into
        session during authorize step.
        """
        request = self.framework_integration.get_current_request()
        session = self.framework_integration.get_current_session()
        # make it compatible with previous design
        # superclass requires the request to have a session parameter
        # REFACT should go through framework_integration.{set,get}_session_value
        # And the superclass already has this interface, but it can only be overridden
        request.session = session
        self.save_authorize_data(
            request,
            redirect_uri=redirect_uri,
            state=state,
            **kwargs
        )

    def authorize_redirect(self, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        rv = self.create_authorization_url(redirect_uri, **kwargs)

        if self.request_token_url:
            request_token = rv.pop('request_token', None)
            self._save_request_token(request_token)

        self.save_authorize_state(redirect_uri, **rv)
        return self.framework_integration.create_redirect_for_url(rv['url'])

    def authorize_access_token(self, **kwargs):
        """Authorize access token."""
        if self.request_token_url:
            request_token = self._fetch_request_token()
        else:
            request_token = None
        
        request = self.framework_integration.get_current_request()
        session = self.framework_integration.get_current_session()
        # FIXME superclass should go through framework_integration.{get,set}_session_value()
        request.session = session
        params = self.retrieve_access_token_params(request, request_token)
        params.update(kwargs)
        token = self.fetch_access_token(**params)
        self.token = token
        return token

    def parse_id_token(self, token, claims_options=None):
        request = self.framework_integration.get_current_request()
        session = self.framework_integration.get_current_session()
        request.session = session
        return self._parse_id_token(request, token, claims_options)
    
    def generate_nonce_key(self):
        return '_{}:nonce'.format(self.name)
    
    def generate_session_stored_nonce(self, length=20):
        from authlib.common.security import generate_token
        nonce = generate_token(length)
        self.framework_integration.set_session_value(self.generate_nonce_key(), nonce)
        return nonce
    
    def get_nonce_from_session(self):
        return self.framework_integration.get_session_value(self.generate_nonce_key(), None)
    

