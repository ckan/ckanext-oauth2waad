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

Add `oauth2waad` to the `ckan.plugins` line in your CKAN config file, for
example:

    ckan.plugins = resource_proxy stats datastore oauth2waad

Add the following settings to the `[app:main]` section of your config file:

    [app:main]
    ckanext.oauth2waad.client_id = <YOUR_CLIENT_ID>
    ckanext.oauth2waad.redirect_uri = <YOUR_REDIRECT_URI>
    ckanext.oauth2waad.auth_endpoint = https://login.windows.net/<YOUR_TENANT_ID>/oauth2/authorize
    ckanext.oauth2waad.auth_token_endpoint = https://login.windows.net/<YOUR_TENANT_ID>/oauth2/token
    ckanext.oauth2waad.resource = <YOUR_RESOURCE_URL>
    ckanext.oauth2waad.csrf_secret = <YOUR_SECRET_KEY>
    ckanext.oauth2waad.servicetoservice.auth_token_endpoint = https://login.windows.net/<SERVICE_TO_SERVICE_TENANT_ID>/oauth2/token
    ckanext.oauth2waad.servicetoservice.client_id = <YOUR_CLIENT_ID_FOR_SERVICE_TO_SERVICE_REQUESTS>
    ckanext.oauth2waad.servicetoservice.client_secret = <YOUR_CLIENT_SECRET_FOR_SERVICE_TO_SERVICE_REQUESTS>
    ckanext.oauth2waad.servicetoservice.resource = <YOUR_RESOURCE_FOR_SERVICE_TO_SERVICE_REQUESTS>

The value for the `ckanext.oauth2waad.csrf_secret` setting should be a long and
difficult to guess string. This secret key is used to sign a cookie that is
used for CSRF (cross-site request forgery) protection.

One way to generate a suitable secret key is to generate a UUID. Type the
following command in a terminal:

    python -c 'import uuid; print uuid.uuid4()'

Copy the command's output and paste it into your config file, for example:

    ckanext.oauth2waad.csrf_secret = 9bda3f56-833d-4005-94fb-090b12e399ef

The `ckanext.oauth2waad.servicetoservice.*` config settings are optional -
they're only needed if you're also using another plugin that needs to make
[service-to-service calls](http://msdn.microsoft.com/en-us/library/azure/dn645543.aspx)
to a WAAD-authorized resource.

Finally, restart your web server.


SSL
---

When using this plugin, your CKAN site should be setup to serve the login
and redirect_uri pages (or simply all pages) over SSL and the
`ckanext.oauth2waad.redirect_uri` setting in your config file should be an
`https://` URL.

A quick way of doing this for a local instance served by paste
(ie `https://localhost:5000/_your_redirect_uri`) is the following:

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


Accessing the WAAD access token
-------------------------------

When a user is logged-in via WAAD, the oauth2waad plugin adds the WAAD access
token to the Pylons session. Code from other plugins can use this token to
access the WAAD resource:

    access_token = pylons.session.get('ckanext-oauth2waad-access-token')

You generally want to use the `access_token` as part of the headers of your
requests to the resource, following the Bearer scheme:

    Authorization: Bearer <access_token>

Check the Microsoft Azure documentation for more details:

 * [Authorization Code Grant Flow](http://msdn.microsoft.com/en-us/library/azure/dn645542.aspx)
 * [Best Practices for OAuth 2.0 in Azure AD](http://msdn.microsoft.com/en-us/library/azure/dn645536.aspx)


Refreshing the WAAD access token
--------------------------------

The oauth2waad plugin will automatically try to refresh the WAAD access token
when it's due to expire by using the refresh token as described in the
[WAAD OAuth 2.0 docs](http://msdn.microsoft.com/en-us/library/azure/dn645542.aspx).

If some code from another plugin wants to force an access token refresh attempt
(for example, because an API request to the WAAD resource seems to be failing)
it can do so by calling the `refresh_access_token()` function:

    import ckanext.oauth2waad.plugin

    try:
        ckanext.oauth2waad.plugin.refresh_access_token()
    except ckanext.oauth2waad.plugin.CannotRefreshAccessTokenError:
        # Well, we tried.
        pass


Accessing the service-to-service access token
---------------------------------------------

If another plugin needs to make [service-to-service calls](http://msdn.microsoft.com/en-us/library/azure/dn645543.aspx)
using a WAAD OAuth 2.0 service-to-service access token, it can get the token
from the `ckanext-oauth2waad` plugin's `service_to_service_access_token()`
function:

    import ckanext.oauth2waad.plugin as oauth2waad_plugin

    try:
        access_token = oauth2waad_plugin.service_to_service_access_token()
    except oauth2waad_plugin.ServiceToServiceAccessTokenError:
        # Well, we tried.
        pass

The `oauth2waad` plugin caches the access token and only requests a new one if
there's no cached access token or if the cached token has expired.

To force the plugin to request a new access token (for example, because the
cached one doesn't seem to be working) call
`request_service_to_service_access_token()`:

    import ckanext.oauth2waad.plugin as oauth2waad_plugin

    try:
        access_token = oauth2waad_plugin.request_service_to_service_access_token()
    except oauth2waad_plugin.ServiceToServiceAccessTokenError:
        # Well, we tried.
        pass
