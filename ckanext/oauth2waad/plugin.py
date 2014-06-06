'''This extension's plugin classes and their immediate helper functions.'''
import uuid
import urllib

import requests

import pylons
import jwt

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit


def _get_config_setting_or_crash(key):
    try:
        return pylons.config[key]
    except KeyError:
        message = "ckanext-oauth2waad: missing '{key}' config setting".format(
            key=key)
        raise Exception(message)


def _waad_client_id():
    '''Return the WAAD client_id from the config file, or crash.'''
    return _get_config_setting_or_crash('ckanext.oauth2waad.client_id')


def _waad_redirect_uri():
    '''Return the WAAD redirect_uri from the config file, or crash.'''
    return _get_config_setting_or_crash('ckanext.oauth2waad.redirect_uri')


def _waad_auth_endpoint():
    '''Return the WAAD auth_endpoint from the config file, or crash.'''
    return _get_config_setting_or_crash('ckanext.oauth2waad.auth_endpoint')


def _waad_auth_token_endpoint():
    '''Return the WAAD auth token endpoint from the config file, or crash.'''
    return _get_config_setting_or_crash(
        'ckanext.oauth2waad.auth_token_endpoint')


def _waad_resource():
    '''Return the WAAD resource from the config file, or crash.'''
    return _get_config_setting_or_crash('ckanext.oauth2waad.resource')


def _waad_auth_code_request_url():
    '''Return the WAAD auth code request URL.'''
    params = {
        'redirect_uri': _waad_redirect_uri(),
        'response_type': 'code',
        'client_id': _waad_client_id(),
    }
    query_string = urllib.urlencode(params)
    return _waad_auth_endpoint() + '?' + query_string


class OAuth2WAADPlugin(plugins.SingletonPlugin):

    '''A plugin for logging into CKAN using WAAD's implementation of OAuth 2.0.

    WAAD is Windows Azure Active Directory. See their OAuth 2.0 docs here:

    http://msdn.microsoft.com/en-us/library/azure/dn645545.aspx

    '''

    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.ITemplateHelpers)

    def update_config(self, config):
        '''Update CKAN's config with settings needed by this plugin.'''
        toolkit.add_template_directory(config, 'templates')

    def configure(self, config):
        '''Read this plugin's config settings from the config file.'''
        # We don't actually need to get the config settings here,
        # this is just so that we crash on startup if they aren't in the config
        # file.
        _waad_client_id()
        _waad_redirect_uri()
        _waad_auth_endpoint()
        _waad_auth_token_endpoint()
        _waad_resource()

    def before_map(self, map_):

        # Get just the path part (after the domain name and port) of the
        # redirect_uri.
        # FIXME: This assumes that the path part is the part following the
        # third / in the URI, which is not very robust.
        path = '/' + _waad_redirect_uri().split('/', 3)[-1]

        # Route requests for our WAAD redirect URI to a custom controller.
        map_.connect(
            'waad_redirect_uri', path,
            controller='ckanext.oauth2waad.plugin:WAADRedirectController',
            action='login')

        return map_

    def after_map(self, map_):
        return map_

    def login(self):
        '''IAuthenticator requires this method but this plugin doesn't use it.

        '''
        pass

    def identify(self):
        '''Identify which user (if any) is logged-in via WAAD.

        CKAN calls this on each page load.

        If a logged-in user is found, set toolkit.c.user to be their user name.

        '''
        user = pylons.session.get('ckanext-oauth2waad-user')
        if user:
            toolkit.c.user = user

    def _delete_session_items(self):
        '''Delete any session items created by this plugin.'''
        keys_to_delete = [key for key in pylons.session
                          if key.startswith('ckanext-oauth2waad')]
        if keys_to_delete:
            for key in keys_to_delete:
                del pylons.session[key]
            pylons.session.save()

    def logout(self):
        '''Handle a logout request.'''
        self._delete_session_items()

    def abort(self, status_code, detail, headers, comment):
        '''Handle an abort.'''
        self._delete_session_items()

    def get_helpers(self):
        '''Return this plugin's template helper functions.'''
        return {
            'waad_auth_code_request_url': _waad_auth_code_request_url,
            }


def _get_user(name):
    '''Return the CKAN user with the given user name, or None.'''
    try:
        user = toolkit.get_action('user_show')(data_dict = {'id': name})
        return user
    except toolkit.ObjectNotFound:
        return None


def _generate_password():
    '''Generate a random password.'''
    # FIXME: We don't actually need to store passwords in CKAN for the users
    # we create (they will always login via WAAD), but CKAN requires every
    # user to have a password.
    return str(uuid.uuid4())


def _get_user_details_from_waad(waad_auth_code):
    '''Use an auth code to get an access token and user details from WAAD.'''
    data = {
        'client_id': _waad_client_id(),
        'code': waad_auth_code,
        'grant_type': 'authorization_code',
        'redirect_uri': _waad_redirect_uri(),
        'resource': _waad_resource(),
        }

    # TODO: Handle timeouts, failed requests.
    response = requests.post(_waad_auth_token_endpoint(), data=data)
    waad_access_token = response.json().get('access_token')
    waad_refresh_token = response.json().get('refresh_token')
    waad_id_token = response.json().get('id_token')

    jwt_payload = jwt.decode(waad_id_token, waad_access_token, verify=False)
    family_name = jwt_payload.get('family_name')
    given_name = jwt_payload.get('given_name')
    oid = jwt_payload.get('oid')

    return waad_access_token, waad_refresh_token, oid, given_name, family_name


def _log_the_user_in(access_token, refresh_token, oid, given_name,
                     family_name):
    '''Log the user into CKAN, creating an account for them if necessary.

    :param access_token: The user's OAuth 2.0 access token from WAAD.
        If logging the user in succeeds this will be saved in the session for
        other code to access.

    :param refresh_token: The user's OAuth 2.0 refresh token from WAAD.
        If logging the user in succeeds this will be saved in the session for
        other code to access.

    :param oid: The user's OID (object identifier) from WAAD. This will be used
        as the unique user name for the user's CKAN account.

    :param given_name: The user's given name. This will be used for the full
        name in the user's CKAN account.

    :param family_name: The user's family name. This will be used for the full
        name in the user's CKAN account.

    :returns: the logged-in user
    :rtype: dictionary

    '''
    user = _get_user(oid)

    if user:
        # TODO: If the user has changed their given name, family name, or
        # anything in WAAD, update it in CKAN? (But what if they've also
        # changed it in CKAN? We may overwrite changes.)
        pass

    else:
        # The user doesn't exist in CKAN yet, create it.

        fullname = '{given_name} {family_name}'.format(
            given_name=given_name, family_name=family_name)

        # FIXME: CKAN requires emails for user accounts, but we don't have an
        # email for the user from WAAD. Can we get one somehow?
        email = 'foo'

        # TODO: Handle exceptions.
        user = toolkit.get_action('user_create')(
            context={'ignore_auth': True},
            data_dict={'name': oid,
                       'fullname': fullname,
                       'password': _generate_password(),
                       'email': 'foo'})

    pylons.session['ckanext-oauth2waad-user'] = user['name']
    pylons.session['ckanext-oauth2waad-access-token'] = access_token
    pylons.session['ckanext-oauth2waad-refresh-token'] = refresh_token
    pylons.session.save()

    return user


class WAADRedirectController(toolkit.BaseController):

    '''A custom home controller for receiving WAAD authorization responses.'''

    def login(self):
        '''Handle request to the WAAD redirect_uri.'''
        params = pylons.request.params

        if 'code' in params:
            waad_auth_code = params.get('code')

            access_token, refresh_token, oid, given_name, family_name = (
                _get_user_details_from_waad(waad_auth_code))

            user = _log_the_user_in(access_token, refresh_token, oid,
                                    given_name, family_name)

            toolkit.redirect_to(controller='user', action='dashboard',
                                id=user['name'])