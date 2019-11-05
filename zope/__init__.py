# https://packaging.python.org/guides/packaging-namespace-packages/
# Doing just what the other zope packages are doing for maximum compatibility
__import__('pkg_resources').declare_namespace(__name__)
