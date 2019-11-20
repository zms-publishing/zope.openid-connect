from __future__ import absolute_import

from functools import wraps
import logging

from Acquisition import aq_parent
from AccessControl.SecurityInfo import ClassSecurityInfo
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins \
                import IAuthenticationPlugin, IUserEnumerationPlugin, IChallengePlugin
from zExceptions import Redirect
import transaction
import six

# from openid.yadis.discover import DiscoveryFailure
# from openid.consumer.consumer import Consumer, SUCCESS

from ..interfaces import IOpenIdExtractionPlugin
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
    
    # TODO what is this 
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
            return handle_authorize(self.remote, None, None)
        if 'id_token' in token:
            nonce = self.remote.get_nonce_from_session()
            user_info = self.remote.parse_openid(token, nonce)
        else:
            user_info = self.remote.profile(token=token)
        return self.handle_authorize(token, user_info)
    
    def handle_authorize(self, token, user_info):
        breakpoint()
    
    # REFACT Does this interface make any sense? We're the only one to implement it anyway
    # IOpenIdExtractionPlugin implementation
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
        if "openid.source" not in credentials:
            return None

        if credentials["openid.source"]=="server":
            consumer=self.getConsumer()

            # remove the extractor key that PAS adds to the credentials,
            # or python-openid will complain
            query = credentials.copy()
            del query['extractor']
            if 'login' in query and query['login'] is None:
                # PAS has tried to lowercase the login, but login was not in
                # the credentials, so it is now None.
                # This would result in an AttributeError in consumer.complete,
                # so we remove it.
                del query['login']

            result=consumer.complete(query, self.REQUEST.ACTUAL_URL)
            identity=result.identity_url

            if result.status==SUCCESS:
                self._getPAS().updateCredentials(self.REQUEST,
                        self.REQUEST.RESPONSE, identity, "")
                return (identity, identity)
            else:
                logger.info("OpenId Authentication for %s failed: %s",
                                identity, result.message)

        return None


    # IUserEnumerationPlugin implementation
    @log_exceptions
    def enumerateUsers(self, id=None, login=None, exact_match=False, sort_by=None, max_results=None, **kw):
        """Slightly evil enumerator.

        This is needed to be able to get PAS to return a user which it should
        be able to handle but who can not be enumerated.

        We do this by checking for the exact kind of call the PAS getUserById
        implementation makes
        """
        if id and login and id!=login:
            return None

        if (id and not exact_match) or kw:
            return None

        key=id and id or login

        if not (key.startswith("http:") or key.startswith("https:")):
            return None

        return [ {
                    "id" : key,
                    "login" : key,
                    "pluginid" : self.getId(),
                } ]


# REFACT use decorator? zope.interface.implements
classImplements(OpenIdPlugin,
    IOpenIdExtractionPlugin,
    IAuthenticationPlugin,
    IUserEnumerationPlugin,
    IChallengePlugin,
)


