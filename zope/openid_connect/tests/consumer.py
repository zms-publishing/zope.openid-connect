from __future__ import absolute_import
from openid.consumer.consumer import FAILURE, SUCCESS

class MockAuthRequest:
    """Amock OpenID AuthRequest.
    """
    def __init__(self, status=None, identity_url=None, message=None):
        self.status=status
        self.identity_url=identity_url
        self.message=message


    def redirectURL(self, trust_root, return_to):
        return return_to


class MockConsumer:
    """A mock OpenID consumerclass.
    """

    def begin(self, identity):
        self.identity=identity
        return MockAuthRequest()

    def complete(self, credentials, current_url):
        status=SUCCESS
        message="authentication completed succesfully"

        if "openid.identity" in credentials and credentials["openid.identity"] == "":
            # if the python openid is passed an identity of an empty string
            # an IndexError is raised in the depths of its XRI identification
            # see: http://www.oasis-open.org/committees/tc_home.php?wg_abbrev=xri

            # an empty string is common when the submit button of the
            # openid login is clicked prior to providing an identity url
            # we simulate openid's response here in our mock object
            message="invalid identity"
            status=FAILURE
        else:
            for field in [ "openid.source", "nonce", "openid.identity",
                    "openid.assoc_handle", "openid.return_to", "openid.signed",
                    "openid.sig", "openid.invalidate_handle", "openid.mode"]:
                if field not in credentials:
                    message="field missing"
                    status=FAILURE


        return MockAuthRequest(status=status,
                                message=message,
                                identity_url=credentials["openid.identity"])

def PatchPlugin(plugin):
    def getConsumer(self):
        return MockConsumer()

    plugin.getConsumer=getConsumer

