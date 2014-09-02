'''This extension's plugin classes and their immediate helper functions.'''
import logging
import uuid
import urllib
import calendar
import time
import urlparse

import requests
import simplejson

import pylons
import jwt

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.lib.helpers as helpers

import ckanext.oauth2waad.model as model


log = logging.getLogger(__name__)
requests.packages.urllib3.add_stderr_logger()


class OAuth2WAADConfigError(Exception):
    '''Exception that's raised if an oauth2waad config setting is missing.'''
    pass


def _get_config_setting_or_crash(key):
    try:
        return pylons.config[key]
    except KeyError:
        message = "ckanext-oauth2waad: missing '{key}' config setting".format(
            key=key)
        raise OAuth2WAADConfigError(message)


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


def _csrf_secret():
    '''Return the secret key used to sign our CSRF-protection cookie.'''
    return _get_config_setting_or_crash('ckanext.oauth2waad.csrf_secret')


def _service_to_service_auth_token_endpoint():
    '''Return the WAAD auth token endpoint to be used for service to service
       calls.'''
    return _get_config_setting_or_crash(
            'ckanext.oauth2waad.servicetoservice.auth_token_endpoint')


def _service_to_service_client_id():
    '''Return the WAAD service-to-service client_id from the config file.'''
    return _get_config_setting_or_crash(
            'ckanext.oauth2waad.servicetoservice.client_id')


def _service_to_service_client_secret():
    '''Return the service-to-service client_secret from the config file.'''
    return _get_config_setting_or_crash(
            'ckanext.oauth2waad.servicetoservice.client_secret')


def _service_to_service_resource(resource=None):
    '''Return the WAAD service-to-service resource from the config file.'''
    # return the first in the list if no resource is provided
    if not resource:
        return _get_config_setting_or_crash(
            'ckanext.oauth2waad.servicetoservice.resource').split()[0]

    resources = dict(zip(
        _get_config_setting_or_crash(
            'ckanext.oauth2waad.servicetoservice.resource_names').split(),
        _get_config_setting_or_crash(
             'ckanext.oauth2waad.servicetoservice.resource').split()
        )
    )
    try:
        return resources[resource]
    except KeyError:
        message = ("ckanext-oauth2waad: no resource '{resource}' in"
                   "ckanext.oauth2waad.servicetoservice_resource_name")
        raise OAuth2WAADConfigError(message.format(resource=resource))


def _generate_state_param():
    '''Return a state parameter for an authorization code request.

    Returns a unique, randomly generated value for use as the state parameter
    for CSRF (cross-site request forgery) protection in an authorization code
    request.

    '''
    return str(uuid.uuid4())


def _get_domain_name_from_url(url):
    '''Return just the domain name part (e.g. stackoverflow.com) from the given
    URL (e.g. http://stackoverflow.com/foo/bar).'''
    return urlparse.urlparse(url).netloc


def _get_path_from_url(url):
    '''Return just the path part of the given URL.

    For example for https://demo.ckan.org/_waad_redirect_uri returns just
    /_waad_redirect_uri.

    '''
    return urlparse.urlparse(url).path


def _waad_auth_code_request_url():
    '''Return the WAAD auth code request URL.

    The URL contains a UUID (in a URL param) that is different each time this
    function is called - each time the login page it loaded and the auth code
    request link rendered, a new UUID is generated. This UUID is used in
    cross-site request forgery (CSRF) protection.

    This function also saves the CSRF UUID in a cookie each time it's called,
    so that it can be retrieved later when the same browser makes a request to
    our redirect_uri.

    '''
    state = _generate_state_param()

    # We save the state param in a cookie, because we'll need to retrieve it
    # later.
    pylons.response.signed_cookie(
        'oauth2waad-state', state, secure=True, secret=_csrf_secret(),
        path=_get_path_from_url(_waad_redirect_uri()))

    params = {
        'redirect_uri': _waad_redirect_uri(),
        'response_type': 'code',
        'client_id': _waad_client_id(),
        'state': state,
    }
    query_string = urllib.urlencode(params)
    return _waad_auth_endpoint() + '?' + query_string


class CannotRefreshAccessTokenError(Exception):
    '''The exception that is raised when refreshing the access token using the
    refresh token fails for any reason.'''
    pass


def _refresh_access_token(session, client_id, resource, endpoint):
    '''Refresh the WAAD access token using the refresh token.

    This is a private helper function for refresh_access_token() and
    _refresh_access_token_if_expiring() that handles the actual refresh
    request and response with the WAAD server.

    '''
    refresh_token = session.get('ckanext-oauth2waad-refresh-token')
    if not refresh_token:
        raise CannotRefreshAccessTokenError(
            "Couldn't find refresh_token in session")

    data = {
        'client_id': client_id,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'resource': resource,
        }
    try:
        response = requests.post(endpoint, data=data)
    except requests.exceptions.ConnectionError:
        raise CannotRefreshAccessTokenError

    try:
        response_json = response.json()
    except simplejson.scanner.JSONDecodeError:
        raise CannotRefreshAccessTokenError(
            "Couldn't parse the response body as JSON")

    try:
        new_access_token = response_json['access_token']
    except Exception:
        raise CannotRefreshAccessTokenError("No access_token in response JSON")

    try:
        new_refresh_token = response_json['refresh_token']
    except Exception:
        raise CannotRefreshAccessTokenError(
            "No refresh_token in response JSON")

    try:
        new_expires_on = response_json['expires_on']
    except Exception:
        raise CannotRefreshAccessTokenError("No expires_on in response JSON")

    session['ckanext-oauth2waad-access-token'] = new_access_token
    session['ckanext-oauth2waad-refresh-token'] = new_refresh_token
    session['ckanext-oauth2waad-expires-on'] = new_expires_on
    session.save()


# This is a public function for code from other plugins to call to refresh the
# access token, regardless of whether it's due to expire or not.
def refresh_access_token():
    '''Refresh the WAAD access token using the refresh token.

    Send an access token refresh request to the WAAD server, and updates the
    'ckanext-oauth2waad-access-token', 'ckanext-oauth2waad-refresh-token',
    and 'ckanext-oauth2waad-expires-on' in the Pylons session.

    :raises: :py:class:`CannotRefreshAccessTokenError` if refreshing the access
        token fails for any reason.

    '''
    return _refresh_access_token(
        pylons.session, _waad_client_id(), _waad_resource(),
        _waad_auth_token_endpoint())


def _refresh_access_token_if_expiring(session, client_id, resource, endpoint):
    '''Refresh the WAAD access token, if it has expired or will expire soon.

    Makes a request to the WAAD server to get a new access_token and
    refresh_token using the existing refresh_token.

    If the existing access_token is not due to expire, no request is made.

    :param session: The pylons.session object for the current request, the
        refresh_token and expires_on time will be taken from this

    :param client_id: The WAAD client ID

    :param resource: The WAAD resource

    :param endpoint: The WAAD endpoint to make the request to

    :raises: :py:class:`CannotRefreshAccessTokenError` if refreshing the
        access token fails for any reason

    '''
    expires_on = session.get('ckanext-oauth2waad-expires-on')
    if not expires_on:
        raise CannotRefreshAccessTokenError(
            "Couldn't find expires_on time in session")

    now = calendar.timegm(time.gmtime())
    five_minutes = 60*5

    try:
        expires_on_int = int(expires_on)
    except ValueError:
        raise CannotRefreshAccessTokenError(
            "Couldn't convert expires_on time to int")

    if now > expires_on_int - five_minutes:
        _refresh_access_token(session, client_id, resource, endpoint)


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

        # Create the DB tables on startup if not there
        model.setup()


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
        _csrf_secret()
        _service_to_service_auth_token_endpoint()
        _service_to_service_resource()
        _service_to_service_client_id()
        _service_to_service_client_secret()

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
            endpoint = _waad_auth_token_endpoint()
            try:
                _refresh_access_token_if_expiring(pylons.session,
                                                  _waad_client_id(),
                                                  _waad_resource(),
                                                  endpoint)
            except CannotRefreshAccessTokenError:
                domain_name = _get_domain_name_from_url(endpoint)
                logout_url = toolkit.url_for(controller='user',
                                             action='logout')
                message = toolkit._(
                    "Refreshing your Windows Azure Active Directory OAuth 2.0 "
                    "access token with {domain} failed. Some functionality "
                    "may not be available. You can try "
                    '<a href="{logout}">logging out</a> and logging in again '
                    "to fix the issue.").format(domain=domain_name,
                                                logout=logout_url)
                helpers.flash(message, category='alert-error', allow_html=True,
                              ignore_duplicate=True)

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
        return (status_code, detail, headers, comment)

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


class InvalidAccessTokenResponse(Exception):
    pass


def _get_user_details_from_waad(auth_code, client_id, redirect_uri, resource,
                                endpoint):
    '''Use an auth code to get an access token and user details from WAAD.

    :param auth_code: The WAAD authorization code

    :param client_id: The WAAD client ID

    :param redirect_uri: The WAAD redirect URI

    :param resource: The WAAD resource

    :param endpoint: The WAAD endpoint URL to post the access token request to

    :returns: A dictionary containing the access token, refresh token, expiry
        time of the access token, and details of the authorized user from WAAD

    :raises: :py:class:`InvalidAccessTokenResponse` if there's anything wrong
        with the response from the WAAD server

    '''
    data = {
        'client_id': client_id,
        'code': auth_code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
        'resource': resource,
        }

    # TODO: Handle timeouts, failed requests.
    response = requests.post(endpoint, data=data)
    try:
        response.raise_for_status()
    except requests.exceptions.RequestExceptions, e:
        log.debug('request url: {}'.format(endpoint))
        log.debug('request data: {}'.format(str(data)))
        raise e

    try:
        response_json = response.json()
    except simplejson.scanner.JSONDecodeError:
        raise InvalidAccessTokenResponse(
            "The response body could not be decoded as JSON")

    try:
        waad_access_token = response_json['access_token']
    except Exception:
        raise InvalidAccessTokenResponse(
            'access_token was missing from the response body')

    try:
        waad_refresh_token = response_json['refresh_token']
    except Exception:
        raise InvalidAccessTokenResponse(
            'refresh_token was missing from the response body')

    try:
        waad_expires_on = response_json['expires_on']
    except Exception:
        raise InvalidAccessTokenResponse(
            'expires_on was missing from the response body')

    try:
        waad_id_token = response_json['id_token']
    except Exception:
        raise InvalidAccessTokenResponse(
            'id_token was missing from the response body')

    try:
        jwt_payload = jwt.decode(waad_id_token, waad_access_token, verify=False)
    except Exception:
        raise InvalidAccessTokenResponse("Couldn't decode the JWT payload")
    family_name = jwt_payload.get('family_name')
    given_name = jwt_payload.get('given_name')
    upn = jwt_payload.get('upn')

    return {
        'access_token': waad_access_token,
        'refresh_token': waad_refresh_token,
        'expires_on': waad_expires_on,
        'upn': upn,
        'given_name': given_name,
        'family_name': family_name,

        }


class CouldNotCreateUserException(Exception):
    '''The exception that is raised when creating a new CKAN user for a given
    WAAD user fails.'''
    pass


def _log_the_user_in(access_token, refresh_token, expires_on, upn, given_name,
                     family_name, session):
    '''Log the user into CKAN, creating an account for them if necessary.

    :param access_token: The user's OAuth 2.0 access token from WAAD.
        If logging the user in succeeds this will be saved in the session for
        other code to access.

    :param refresh_token: The user's OAuth 2.0 refresh token from WAAD.
        If logging the user in succeeds this will be saved in the session for
        other code to access.

    :param expires_on: The time when the access token expires, given in seconds
        since the UNIX epoch

    :param upn: The user's OID (object identifier) from WAAD. This will be used
        as the unique user name for the user's CKAN account.

    :param given_name: The user's given name. This will be used for the full
        name in the user's CKAN account.

    :param family_name: The user's family name. This will be used for the full
        name in the user's CKAN account.

    :param session: The Pylons session for this thread, items will be added to
        it that let other code know that a user is logged-in via WAAD.

    :returns: the logged-in user
    :rtype: dictionary

    :raises: :py:class:`CouldNotCreateUserException` if creating a new CKAN
        user for the authorized WAAD user fails.

    '''
    user = _get_user(upn)

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

        try:
            user = toolkit.get_action('user_create')(
                context={'ignore_auth': True},
                data_dict={'name': upn,
                        'fullname': fullname,
                        'password': _generate_password(),
                        'email': 'foo'})
        except Exception as e:
            raise CouldNotCreateUserException(e)

    session['ckanext-oauth2waad-user'] = user['name']
    session['ckanext-oauth2waad-access-token'] = access_token
    session['ckanext-oauth2waad-refresh-token'] = refresh_token
    session['ckanext-oauth2waad-expires-on'] = expires_on
    session.save()

    return user


def _csrf_check(request, response, secret):
    '''Return True if the request passes our CSRF check, False otherwise.'''
    cookie_state = request.signed_cookie('oauth2waad-state', secret)
    response.delete_cookie('oauth2waad-state',
                           path=_get_path_from_url(_waad_redirect_uri()))
    request_state = request.params.get('state')
    if cookie_state and (request_state == cookie_state):
        return True
    else:
        return False


class WAADRedirectController(toolkit.BaseController):

    '''A custom home controller for receiving WAAD authorization responses.'''

    def login(self):
        '''Handle request to the WAAD redirect_uri.'''
        params = pylons.request.params
        waad_auth_code = params.get('code')

        if not waad_auth_code:
            toolkit.abort(401)

        if not _csrf_check(pylons.request, pylons.response, _csrf_secret()):
            toolkit.abort(401)

        # TODO: Handle InvalidAccessTokenResponse exceptions.
        details = _get_user_details_from_waad(
            waad_auth_code, _waad_client_id(), _waad_redirect_uri(),
            _waad_resource(), _waad_auth_token_endpoint())

        try:
            user = _log_the_user_in(session=pylons.session, **details)
        except CouldNotCreateUserException as exc:
            message = toolkit._(
                "Creating your CKAN user account failed: {error}".format(
                    error=exc))
            helpers.flash(message, category='alert-error', allow_html=True,
                            ignore_duplicate=True)
            toolkit.redirect_to(controller='user', action='login')

        toolkit.redirect_to(controller='user', action='dashboard',
                            id=user['name'])


class ServiceToServiceAccessTokenError(Exception):
    '''Exception that is raised if anything goes wrong when requesting a
    service-to-service access token from WAAD.'''
    pass


def _request_service_to_service_access_token(endpoint, client_id,
                                             client_secret, resource):
    '''Request a service-to-service access token from WAAD.

    :returns: the access token and its expires_on time.
    :rtype: 2-tuple of two strings

    :raises: ServiceToServiceAccessTokenError if anything goes wrong when
        requesting the access token

    '''
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': resource,
        }
    try:
        response = requests.post(endpoint, data=data)
    except requests.exceptions.ConnectionError:
        raise ServiceToServiceAccessTokenError(
            "ConnectionError when requesting access token")

    try:
        response_json = response.json()
    except simplejson.scanner.JSONDecodeError:
        raise ServiceToServiceAccessTokenError(
            "Couldn't parse the response body as JSON")

    try:
        response_json = response.json()
    except simplejson.scanner.JSONDecodeError:
        raise ServiceToServiceAccessTokenError(
            "Couldn't parse the response body as JSON")
    try:
        access_token = response_json['access_token']
    except Exception:
        raise ServiceToServiceAccessTokenError("No access_token in response")

    try:
        expires_on = response_json['expires_on']
    except Exception:
        raise ServiceToServiceAccessTokenError("No expires_on in response")

    return (access_token, expires_on)


def request_service_to_service_access_token(resource):
    '''Get a service-to-service access token from WAAD and return it.

    This function will re-do the access token request each time it's called.

    :raises: ServiceToServiceAccessTokenError if anything goes wrong when
        requesting the access token

    '''
    # Get a new token from WAAD.
    access_token, expires_on = _request_service_to_service_access_token(
        _service_to_service_auth_token_endpoint(),
        _service_to_service_client_id(),
        _service_to_service_client_secret(),
        _service_to_service_resource(resource))

    # Cache the token, overwriting any already-cached copy.
    model.save_service_to_service_access_token(resource, access_token, 
                                               expires_on)

    return access_token


def service_to_service_access_token(resource):
    '''Return the WAAD service-to-service access token.

    This function will cache the access token, and only re-do the access token
    request if we don't already have a cached access token or if the cached
    access token has expired.

    :raises: ServiceToServiceAccessTokenError if anything goes wrong when
        requesting the access token

    '''
    # Get the token from the cache.
    token_obj = model.service_to_service_access_token(resource)

    if token_obj is None:
        # There's no cached access token yet.
        token = request_service_to_service_access_token(resource)
    else:
        token = token_obj.token
        expires_on = token_obj.expires_on
        now = calendar.timegm(time.gmtime())
        five_minutes = 60*5
        try:
            expires_on_int = int(expires_on)
        except ValueError:
            raise ServiceToServiceAccessTokenError(
                "Couldn't convert expires_on time to int")

        if now > (expires_on_int - five_minutes):
            # The cached token is expired, or expiring within 5 minutes.
            token = request_service_to_service_access_token(resource)

    return token
