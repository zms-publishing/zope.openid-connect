from setuptools import setup, find_packages

version = '0.1.dev0'

setup(
    name='zope.openid-connect',
    version=version,
    description="OpenID Connect authentication support for PAS",
    long_description=(open("README.rst").read() + '\n' +
                      open("CHANGES.rst").read()),
    classifiers=[
        "Environment :: Web Environment",
        "Framework :: Zope",
        "Framework :: Zope :: 4",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    keywords='PAS openid-connect authentication',
    author='Martin Häcker',
    author_email='spamfaenger@gmx.de', # TODO
    url='https://github.com/zms-publishing/zope.openid-connect', # TODO
    license='BSD',
    packages=find_packages(),
    namespace_packages=['zope'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'zope > 4',
        'transaction',
        'acquisition',
        'zodb',
        'persistent',
        'btrees',
        'Products.PluggableAuthService',
        'authlib',
    ],
    )
