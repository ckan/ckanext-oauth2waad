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
    cd ckanext-oauth2waad
    python setup.py develop
    pip install -r requirements.txt

Add 'oauth2waad' to the `ckan.plugins` line in your CKAN config file, for
example:

    ckan.plugins = resource_proxy stats datastore oauth2waad

Add the following settings to the `[app:main]` section of your config file:

    ckanext.oauth2waad.client_id = <YOUR_CLIENT_ID>
    ckanext.oauth2waad.redirect_uri = <YOUR_REDIRECT_URI>
    ckanext.oauth2waad.auth_endpoint = https://login.windows.net/common/oauth2/authorize
    ckanext.oauth2waad.auth_token_endpoint = https://login.windows.net/common/oauth2/token
    ckanext.oauth2waad.resource = <YOUR_RESOURCE_URL>

Finally, restart your web server.

**Note:** If your `redirect_uri` is an `https://` URI your CKAN site will have
to be setup to respond to HTTPS requests.

A quick way of doing this for a local instance served by paste (ie `https://localhost:5000/_your_redirect_uri`) is
the following:

1. Install `libffi-dev`:

    sudo apt-get install libffi-dev

2. Install pyOpenSSL on your virtualenv:

    pip install pyopenssl

3. Add the following to the `[server:main]` section of your configuration ini file:

    [server:main]
    ssl_pem = *

    ...

You can now serve CKAN on https://localhost:5000. Your browser will obviously complain about
a wrong certificate being used. **Do not** do this on a production site.



Access token and refresh token
------------------------------

When a user is logged-in via WAAD, the oauth2waad plugin adds the access token
and refresh token from WAAD to the session. Other code can use these tokens to
access the WAAD resource:

    access_token = pylons.session.get('ckanext-oauth2waad-access-token')
    refresh_token = pylons.session.get('ckanext-oauth2waad-refresh-token')

You generally want to use the `access_token` as part of the headers of your
requests to the resource, following the Bearer scheme:

    Authorization: Bearer <auth_token>

Check the Microsoft Azure documentation for more details:

 * [Authorization Code Grant Flow](http://msdn.microsoft.com/en-us/library/azure/dn645542.aspx)
 * [Best Practices for OAuth 2.0 in Azure AD](http://msdn.microsoft.com/en-us/library/azure/dn645536.aspx)
