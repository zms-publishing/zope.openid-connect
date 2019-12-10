from __future__ import absolute_import

from functools import wraps
import logging

from Acquisition import aq_parent
from AccessControl.SecurityInfo import ClassSecurityInfo
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins import (
    IExtractionPlugin, IAuthenticationPlugin, IChallengePlugin
)
from zExceptions import Redirect
import transaction
import six

# from openid.yadis.discover import DiscoveryFailure
# from openid.consumer.consumer import Consumer, SUCCESS

from ..store import ZopeStore
from ..sham_oidc import ShamOIDC

manage_addOpenIdPlugin = PageTemplateFile("../www/openidAdd", globals(),
                __name__="manage_addOpenIdPlugin")

logger = logging.getLogger("PluggableAuthService")


def log_exceptions(wrapped):
    @wraps(wrapped)
    def wrapper(*args, **kwargs):
        try:
            return wrapped(*args, **kwargs)
        except Exception as e:
            logger.exception('an exception happened in one of the PluggableAuth methods')
            raise
    return wrapper

def addOpenIdPlugin(self, id, title='', REQUEST=None):
    """Add a OpenID Connect Plugin to a Pluggable Authentication Service.
    """
    p=OpenIdPlugin(id, title)
    self._setObject(p.getId(), p)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect("%s/manage_workspace"
                "?manage_tabs_message=OpenID+plugin+added." %
                self.absolute_url())


from zope.openid_connect.authlib_integration import RemoteApp, OAuth
from zope.openid_connect.authlib_integration.zope import ZopeIntegration

class ZopeRemoteApp(RemoteApp, ShamOIDC):
    pass


class OpenIdPlugin(BasePlugin):
    """OpenID authentication plugin.
    """

    meta_type = "OpenID Connect Plugin"
    security = ClassSecurityInfo()

    def __init__(self, id, title=None):
        self._setId(id)
        self.title=title
        self.store=ZopeStore()
        
        self.initializeAuthlib()
    
    def initializeAuthlib(self):
        # FIXME it probably makes sense _not_ to store the ZopeIntegration, OAuth and remote client in the plugin and thus in the ZODB but instead create instances on demand
        self.integration = ZopeIntegration()
        self.integration.plugin = self
        
        # FIXME this needs to come from the config obviously, cannot be hardcoded in here
        self.integration.config = dict(
            SHAM_OIDC_CLIENT_ID='328993',
            SHAM_OIDC_CLIENT_SECRET='94d83f9b5686af2d0d2c2b3bc02d0296d3f9df4659dc5cdff5408f22',
        )
        
        self.oauth = OAuth(framework_integration=self.integration)
        
        backend_cls = ShamOIDC
        config = backend_cls.OAUTH_CONFIG.copy()
        config['client_cls'] = ZopeRemoteApp
        self.remote = self.oauth.register(backend_cls.OAUTH_NAME, overwrite=True, **config)
        self.remote.framework_integration = self.integration
    
    # This seems to have been used to get an absolute URL for the response, to ensure
    # that all redirects back to us are on a canonical url.
    # TODO need to enable this again, or OIDC registration will be impossible
    def getTrustRoot(self):
        pas=self._getPAS()
        site=aq_parent(pas)
        return site.absolute_url()
    
    # IChallengePlugin
    @log_exceptions
    def challenge(self, request, response):
        login_form = PageTemplateFile("../www/openid_login_form.zpt", globals()).__of__(self)
        response.setBody(login_form())
        return True # We took responsibility for the challenge
    
    def extractOpenIdServerResponse(self, request, credentials):
        # REFACT consider how much of this can go into a function on the RemoteApp
        # The framwork integration could easily handle all the accessor needs
        id_token = request.form.get('id_token')
        if request.form.get('code'):
            token = self.remote.authorize_access_token()
            if id_token:
                token['id_token'] = id_token
        elif id_token:
            token = {'id_token': id_token}
        elif request.form.get('oauth_verifier'):
            # OAuth 1
            token = self.remote.authorize_access_token()
        else:
            # handle failed
            return handle_authorize(credentials, None, None)
        if 'id_token' in token:
            nonce = self.remote.get_nonce_from_session()
            user_info = self.remote.parse_openid(token, nonce)
        else:
            user_info = self.remote.profile(token=token)
        return self.handle_authorize(credentials, token, user_info)
    
    def handle_authorize(self, credentials, token, user_info):
        if token is None or user_info is None:
            logger.info("OpenIDConnect authentication failed")
            return
            
        # print(token, user_info)
        # See https://docs.authlib.org/en/latest/client/oauth2.html#oidc-session
        # how to decode the id_token contained in token
        # user authenticated
        credentials['oidc_token'] = token
        credentials['oidc_user_info'] = user_info
    
    def initiateChallenge(self):
        # TODO This is a problem, since open id connect requires a hardcoded 
        # pre/configured URL to return to (AFAIK)
        redirect_uri = self.REQUEST.form.get("came_from", None)
        
        conf_key = '{}_AUTHORIZE_PARAMS'.format(self.remote.OAUTH_NAME.upper())
        params = self.integration.get_config(conf_key, {})
        if 'oidc' in self.remote.OAUTH_TYPE:
            params['nonce'] = self.remote.generate_session_stored_nonce()
        
        redirect = self.remote.authorize_redirect(redirect_uri, **params)
        
        # There is evilness here: we can not use a normal RESPONSE.redirect
        # since further processing of the request will happily overwrite
        # our redirect. So instead we raise a Redirect exception, However
        # raising an exception aborts all transactions, which means our
        # session changes are not stored. So we do a commit ourselves to
        # get things working.
        # XXX this also f**ks up ZopeTestCase
        transaction.commit()
        
        raise redirect
    
    # IExtractionPlugin implementation
    @log_exceptions
    def extractCredentials(self, request):
        """This method performs the PAS credential extraction.

        It takes either the zope cookie and extracts openid credentials
        from it, or a redirect from an OpenID server.
        """
        
        if request.form.get('login_with_open_id_connect'):
            self.initiateChallenge() # raises Redirect
        
        credentials = dict()
        oidc_reply_identifiers = ['id_token', 'code', 'oauth_verifier']
        if any(each in request.form for each in oidc_reply_identifiers):
            self.extractOpenIdServerResponse(request, credentials)
        
        return credentials


    # IAuthenticationPlugin implementation
    @log_exceptions
    def authenticateCredentials(self, credentials):
        "maps credentials to (user_id, login) or None"
        
        if 'oidc_token' not in credentials or 'oidc_user_info' not in credentials:
            return None # not authenticated
        
        user_id = credentials['oidc_token']['id_token']
        login = credentials['oidc_user_info']['nickname']
        self._getPAS().updateCredentials(self.REQUEST, self.REQUEST.RESPONSE, login, "")
        logging.info('OpenIDConnect authentication complete, user_id=%s nickname=%s', user_id, login)
        print('OpenIDConnect authentication complete, user_id=%s nickname=%s' % (user_id, login))
        return (user_id, login)


# REFACT use decorator? zope.interface.implements
classImplements(OpenIdPlugin,
    IExtractionPlugin,
    IAuthenticationPlugin,
    IChallengePlugin,
)


