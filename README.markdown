ckanext-oauth2waad
==================

A CKAN extension that lets you log in to a CKAN site using
[Windows Azure Active Directory's implementation of OAuth 2.0](http://msdn.microsoft.com/en-us/library/azure/dn645545.aspx).

Traditional username-and-password registration and login are still enabled when
this plugin is active, the user is given the choice of Azure or traditional
login.


Installation
------------

ckanext-oauth2waad has been tested against the CKAN 2.3 development version.

To install, activate your CKAN virtualenv and then do:

    git clone 'https://github.com/ckan/ckanext-oauth2waad.git'
    cd ckanext-persona
    python setup.py develop

Add 'oauth2waad' to the `ckan.plugins` line in your CKAN config file, for
example:

    ckan.plugins = resource_proxy stats datastore oauth2waad

Add the following settings to the `[app:main]` section of your config file:

    ckanext.oauth2waad.client_id = <YOUR_CLIENT_ID>
    ckanext.oauth2waad.redirect_uri = <YOUR_REDIRECT_URI>
    ckanext.oauth2waad.auth_endpoint = https://login.windows.net/common/oauth2/authorize
    ckanext.oauth2waad.auth_token_endpoint = https://login.windows.net/common/oauth2/token
    ckanext.oauth2waad.resource = <YOUR_RESUORCE_URL>

Finally, restart your web server.

**Note:** If your `redirect_uri` is an `https://` URI your CKAN site will have
to be setup rto respond to HTTPS requests.


Access token and refresh token
------------------------------

When a user is logged-in via WAAD, the oauth2waad plugin adds the access token
and refresh token from WAAD to the session. Other code can use these tokens to
access the WAAD resource:

    access_token = pylons.session.get('ckanext-oauth2waad-access-token')
    refresh_token = pylons.session.get('ckanext-oauth2waad-refresh-token')
