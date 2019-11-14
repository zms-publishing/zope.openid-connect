from __future__ import absolute_import
from persistent.list import PersistentList
from BTrees.OOBTree import OOBTree
from BTrees.OIBTree import OITreeSet
import time

# from openid.store.interface import OpenIDStore
# from openid.store.nonce import SKEW
# from openid.association import Association

# class ZopeStore(OpenIDStore):
class ZopeStore(object):
    """Zope OpenID store.

    This class implements an OpenID store which uses the ZODB.
    """
    def __init__(self):
        self.cache = OOBTree()
        self.session = OOBTree()
