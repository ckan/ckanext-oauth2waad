import json
import UserDict
import calendar
import time

import httpretty
import jwt
import nose.tools
import mock
import pylons
import pylons.config as config
import webtest
import requests

import ckan.plugins.toolkit as toolkit
import ckan.new_tests.factories as factories

import ckanext.oauth2waad.plugin as plugin


def _jwt_payload():
    '''Mock JWT payload of an access token response from the WAAD server.

    The WAAD server puts this dict (as JSON) as the payload in a JWT Web Token
    with key "id_token" in the response body.

    '''
    return {
        'family_name': 'fake family_name',
        'given_name': 'fake given_name',
        'oid': 'fake_oid',
        }


def _access_token_response_dict(payload):
    '''Mock values for an access token response from the WAAD server.

    The server puts these in the response body as JSON.

    '''
    params = {}
    params['access_token'] = 'fake access token'
    params['refresh_token'] = 'fake refesh token'
    params['expires_on'] = 'fake expires on'
    params['id_token'] = jwt.encode(payload, params['access_token'])
    return params


@httpretty.activate
def test_get_user_details_post_params():
    '''Test that _get_user_details_from_waad() posts the right params to the
    WAAD server.

    '''
    # Fake params to post to the mock WAAD server.
    auth_code = 'fake auth code'
    client_id = 'fake client id'
    redirect_uri = 'fake redirect uri'
    resource = 'resource'

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'

    callback_was_called = [False]  # We have to use a list here because
                                   # Python 2 doesn't have nonlocal.

    def request_callback(request, url, headers):
        '''Our mock WAAD server response.'''
        callback_was_called[0] = True

        # Parse the params out of the request.
        # Would be good if we didn't do this manually.
        params = {}
        for param in request.body.split('&'):
            key, value = param.split('=', 1)
            value = value.replace('+', ' ')
            params[key] = value

        # Check that the plugin posted the right params.
        assert params.get('client_id') == client_id
        assert params.get('code') == auth_code
        assert params.get('grant_type') == 'authorization_code'
        assert params.get('redirect_uri') == redirect_uri
        assert params.get('resource') == resource

        body = json.dumps(_access_token_response_dict(_jwt_payload()))
        return (200, headers, body)

    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    plugin._get_user_details_from_waad(auth_code, client_id, redirect_uri,
                                       resource, endpoint)

    assert callback_was_called[0]


@httpretty.activate
def test_get_user_details_from_waad():
    '''Test getting an access token and user details from WAAD.'''
    payload = _jwt_payload()
    response_params = _access_token_response_dict(payload)

    def request_callback(request, url, headers):
        '''Our mock WAAD server response.'''
        body = json.dumps(response_params)
        return (200, headers, body)

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    details = plugin._get_user_details_from_waad(
        'fake auth code', 'fake client id', 'fake redirect uri',
        'fake resource', endpoint)

    assert details.get('access_token') == response_params['access_token']
    assert details.get('refresh_token') == response_params['refresh_token']
    assert details.get('expires_on') == response_params['expires_on']
    assert details.get('oid') == payload['oid']
    assert details.get('given_name') == payload['given_name']
    assert details.get('family_name') == payload['family_name']


@httpretty.activate
def test_get_user_details_from_waad_with_missing_access_token():
    '''Test _get_user_details_from_waad() when the access_token is missing
    from the JSON that the WAAD server returns.

    '''
    payload = _jwt_payload()
    response_params = _access_token_response_dict(payload)

    def request_callback(request, url, headers):
        '''Our mock WAAD server response.'''
        # Remove access_token, so that the response is invalid.
        params = response_params.copy()
        del params['access_token']
        body = json.dumps(params)
        return (200, headers, body)

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    nose.tools.assert_raises(plugin.InvalidAccessTokenResponse,
                             plugin._get_user_details_from_waad,
                             'fake auth code', 'fake client id',
                             'fake redirect_uri', 'fake resource',
                             endpoint)

# TODO: Tests for other missing keys in response JSON.

@httpretty.activate
def test_get_user_details_from_waad_with_no_json():
    '''Test _get_user_details_from_waad() when there's no JSON in the response
    body.

    '''
    def request_callback(request, url, headers):
        '''Our mock WAAD server response.'''
        # Return a response with no body.
        return (200, headers, '')

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    nose.tools.assert_raises(plugin.InvalidAccessTokenResponse,
                             plugin._get_user_details_from_waad,
                             'fake auth_code', 'fake client_id',
                             'fake redirect_uri', 'fake resource',
                             endpoint)


@httpretty.activate
def test_get_user_details_from_waad_when_json_is_not_a_dict():
    '''Test _get_user_details_from_waad() when there is a JSON response body
    but it's not a top-level JSON object.

    '''
    def request_callback(request, url, headers):
        '''Our mock WAAD server response.'''
        # Return a response with no body.
        return (200, headers, json.dumps([1,2,3]))

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    nose.tools.assert_raises(plugin.InvalidAccessTokenResponse,
                             plugin._get_user_details_from_waad,
                             'fake auth_code', 'fake client_id',
                             'fake redirect_uri', 'fake resource',
                             endpoint)


@httpretty.activate
def test_get_user_details_from_waad_with_bad_jwt_payload():
    '''Test _get_user_details_from_waad() when the JWT token from the WAAD
    server is bad.'''
    response_params = _access_token_response_dict(_jwt_payload())

    def request_callback(request, url, headers):
        '''Our mock WAAD server response.'''
        # Replace the JWT token with a bad one.
        response_params['id_token'] = 'bad token'
        return (200, headers, json.dumps(response_params))

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    nose.tools.assert_raises(plugin.InvalidAccessTokenResponse,
                             plugin._get_user_details_from_waad,
                             'fake auth_code', 'fake client_id',
                             'fake redirect_uri', 'fake resource',
                             endpoint)



# FIXME: This mock should require save() to be called for changes to take
# effect, like the real pylons session does.
class MockPylonsSession(UserDict.DictMixin):

    def __init__(self):
        self._dict = {}

    def __getitem__(self, key):
        return self._dict[key]

    def __setitem__(self, key, item):
        self._dict[key] = item

    def __delitem__(self, key):
        del self._dict[key]

    def keys(self):
        return self._dict.keys()

    def save(self):
        pass


def _now():
    '''Return the current time, in seconds since the UNIX epoch.'''
    return calendar.timegm(time.gmtime())


@mock.patch('ckanext.oauth2waad.plugin._refresh_access_token')
@mock.patch('pylons.session')
@mock.patch('ckanext.oauth2waad.plugin._waad_client_id')
@mock.patch('ckanext.oauth2waad.plugin._waad_resource')
@mock.patch('ckanext.oauth2waad.plugin._waad_auth_token_endpoint')
def test_refresh_access_token(
        mock_endpoint_function, mock_resource_function,
        mock_client_id_function, mock_session, mock_refresh_function):
    '''Quick test that the refresh_access_token() public function calls
    _refresh_access_token() correctly.'''

    mock_refresh_function.return_value = 'mock return value'
    mock_client_id_function.return_value = 'mock client id'
    mock_resource_function.return_value = 'mock resource'
    mock_endpoint_function.return_value = 'mock endpoint'

    return_value = plugin.refresh_access_token()

    assert mock_refresh_function.called_once_with(
        mock_session, 'mock client id', 'mock resource', 'mock endpoint')
    assert return_value == 'mock return value'


@mock.patch('ckanext.oauth2waad.plugin._refresh_access_token')
@mock.patch('pylons.session')
@mock.patch('ckanext.oauth2waad.plugin._waad_client_id')
@mock.patch('ckanext.oauth2waad.plugin._waad_resource')
@mock.patch('ckanext.oauth2waad.plugin._waad_auth_token_endpoint')
def test_refresh_access_token_with_exception(
        mock_endpoint_function, mock_resource_function,
        mock_client_id_function, mock_session, mock_refresh_function):
    '''refresh_access_token() should not catch a CannotRefreshAccessTokenError
    raised by _refresh_access_token().'''

    mock_refresh_function.side_effect = plugin.CannotRefreshAccessTokenError
    mock_client_id_function.return_value = 'mock client id'
    mock_resource_function.return_value = 'mock resource'
    mock_endpoint_function.return_value = 'mock endpoint'

    nose.tools.assert_raises(plugin.CannotRefreshAccessTokenError,
                             plugin.refresh_access_token)


@httpretty.activate
def test_refresh_access_token_when_not_expiring():
    '''Test _refresh_access_token_if_expiring() when the access token is
    *not* due to expire.'''

    def request_callback(request, url, headers):
        assert False, ("_refresh_access_token_if_expiring() should not post "
            "to the WAAD server if the access_token is not due to expire")

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    mock_session = MockPylonsSession()
    mock_session['ckanext-oauth2waad-refresh-token'] = 'old refresh token'
    ten_minutes = 60 * 10
    mock_session['ckanext-oauth2waad-expires-on'] = str(_now() + ten_minutes)

    plugin._refresh_access_token_if_expiring(mock_session, 'fake client id',
                                             'fake resource', endpoint)

@httpretty.activate
def _test_refresh_access_token(mock_session):

    def request_callback(request, url, headers):
        params = {
            'access_token': 'new access_token',
            'refresh_token': 'new refresh_token',
            'expires_on': 'new expires_on',
            }
        body = json.dumps(params)
        return (200, headers, body)

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    plugin._refresh_access_token_if_expiring(mock_session, 'fake client id',
                                             'fake resource', endpoint)

    assert mock_session['ckanext-oauth2waad-access-token'] == 'new access_token'
    assert mock_session['ckanext-oauth2waad-refresh-token'] == 'new refresh_token'
    assert mock_session['ckanext-oauth2waad-expires-on'] == 'new expires_on'


def test_refresh_access_token_when_expiring_soon():
    '''Test _refresh_access_token_if_expiring() when the access token is
    due to expire in the next 5 minutes.'''

    mock_session = MockPylonsSession()
    mock_session['ckanext-oauth2waad-refresh-token'] = 'old refresh token'
    four_and_a_half_minutes = (60 * 4) + 30
    mock_session['ckanext-oauth2waad-expires-on'] = str(
        _now() + four_and_a_half_minutes)
    _test_refresh_access_token(mock_session)


def test_refresh_access_token_when_expired():
    '''Test _refresh_access_token_if_expiring() when the access token is
    already expired.'''

    mock_session = MockPylonsSession()
    mock_session['ckanext-oauth2waad-refresh-token'] = 'old refresh token'
    four_and_a_half_minutes = (60 * 4) + 30
    mock_session['ckanext-oauth2waad-expires-on'] = str(
        _now() - four_and_a_half_minutes)
    _test_refresh_access_token(mock_session)


def test_refresh_access_token_server_not_reachable():
    '''Test _refresh_access_token_if_expiring() when the WAAD server doesn't
    respond.'''
    mock_session = MockPylonsSession()
    mock_session['ckanext-oauth2waad-refresh-token'] = 'old refresh token'
    one_minute = 60
    mock_session['ckanext-oauth2waad-expires-on'] = str(
        _now() + one_minute)

    nose.tools.assert_raises(plugin.CannotRefreshAccessTokenError,
                             plugin._refresh_access_token_if_expiring,
                             mock_session, 'fake client id', 'fake resource',
                             'http://this.website.does.not.exist')


@httpretty.activate
def test_refresh_access_token_403():
    '''Test _refresh_access_token_if_expiring() when the WAAD server returns a
    403 Forbidden.'''

    def request_callback(request, url, headers):
        return (403, headers, '')

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    mock_session = MockPylonsSession()
    mock_session['ckanext-oauth2waad-refresh-token'] = 'old refresh token'
    one_minute = 60
    mock_session['ckanext-oauth2waad-expires-on'] = str(
        _now() + one_minute)

    nose.tools.assert_raises(
        plugin.CannotRefreshAccessTokenError,
        plugin._refresh_access_token_if_expiring,
        mock_session, 'fake client id', 'fake resource', endpoint)


@httpretty.activate
def test_refresh_access_token_with_missing_key():
    '''Test _refresh_access_token_if_expiring() when the WAAD server returns a
    JSON object with one of the necessary keys missing.'''

    for key_to_remove in ('refresh_token', 'access_token', 'expires_on'):

        def request_callback(request, url, headers):
            params = {
                'refresh_token': 'new refresh_token',
                'access_token': 'new access_token',
                'expires_on': 'new expires_on',
                }

            del params[key_to_remove]

            body = json.dumps(params)
            return (200, headers, body)

        # The WAAD auth token endpoint to post to. We will mock this.
        endpoint = 'https://fake.waad.auth/token/endpoint'
        httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

        mock_session = MockPylonsSession()
        mock_session['ckanext-oauth2waad-refresh-token'] = 'old refresh token'
        one_minute = 60
        mock_session['ckanext-oauth2waad-expires-on'] = str(
            _now() + one_minute)

        nose.tools.assert_raises(
            plugin.CannotRefreshAccessTokenError,
            plugin._refresh_access_token_if_expiring,
            mock_session, 'fake client id', 'fake resource', endpoint)


@httpretty.activate
def test_refresh_access_token_when_JSON_is_not_an_object():
    '''Test _refresh_access_token_if_expiring() when the WAAD server response
    body is valid JSON but not with a top-level object.'''

    def request_callback(request, url, headers):
        return (200, headers, json.dumps([1,2,3]))

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    mock_session = MockPylonsSession()
    mock_session['ckanext-oauth2waad-refresh-token'] = 'old refresh token'
    one_minute = 60
    mock_session['ckanext-oauth2waad-expires-on'] = str(
        _now() + one_minute)

    nose.tools.assert_raises(
        plugin.CannotRefreshAccessTokenError,
        plugin._refresh_access_token_if_expiring,
        mock_session, 'fake client id', 'fake resource', endpoint)


@httpretty.activate
def test_refresh_access_token_with_missing_session_key():
    '''Test _refresh_access_token_if_expiring() when one of the necessary keys
    is missing from the session.'''

    def request_callback(request, url, headers):
        assert False, "We don't expect to get this far, in this test."

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    for key_to_remove in (
        'ckanext-oauth2waad-refresh-token', 'ckanext-oauth2waad-expires-on'):

        mock_session = MockPylonsSession()
        mock_session['ckanext-oauth2waad-refresh-token'] = 'old refresh token'
        one_minute = 60
        mock_session['ckanext-oauth2waad-expires-on'] = str(
            _now() + one_minute)

        del mock_session[key_to_remove]

        nose.tools.assert_raises(
            plugin.CannotRefreshAccessTokenError,
            plugin._refresh_access_token_if_expiring,
            mock_session, 'fake client id', 'fake resource', endpoint)


@httpretty.activate
def test_refresh_access_token_with_invalid_expires_on():
    '''Test _refresh_access_token_if_expiring() when the expires_on time in
    the session is invalid.'''

    def request_callback(request, url, headers):
        assert False, "We don't expect to get this far, in this test."

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://fake.waad.auth/token/endpoint'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    mock_session = MockPylonsSession()
    mock_session['ckanext-oauth2waad-refresh-token'] = 'old refresh token'
    mock_session['ckanext-oauth2waad-expires-on'] = 'invalid'

    nose.tools.assert_raises(
        plugin.CannotRefreshAccessTokenError,
        plugin._refresh_access_token_if_expiring,
        mock_session, 'fake client id', 'fake resource', endpoint)


class TestOAuth2WAADPlugin():

    '''Functional tests for the OAuth2WAADPlugin class.'''

    @classmethod
    def setup_class(cls):
        import ckan.config.middleware
        cls.app = ckan.config.middleware.make_app(config['global_conf'],
                                                  **config)
        cls.app = webtest.TestApp(cls.app)

    def setup(self):
        import ckan.model as model
        model.Session.close_all()
        model.repo.rebuild_db()

    # We want to mock pylons.session in this test so we can insert an
    # authorized WAAD user into it. Unfortunately pylons.session has many
    # names in CKAN, and we have to mock each one of them that our request
    # hits or we get crashes.
    @mock.patch('ckanext.oauth2waad.plugin._refresh_access_token_if_expiring')
    @mock.patch('pylons.session')
    @mock.patch('ckan.lib.helpers.session')
    @mock.patch('ckan.lib.base.session')
    def test_identify_should_call_refresh_access_token(
        self, mock_base_session, mock_helpers_session, mock_session,
        mock_refresh_function):
        '''When a user is logged in via WAAD identify() should call
        _refresh_access_token_if_expiring().'''

        user = factories.User()

        session_dict = {'ckanext-oauth2waad-user': user['name']}
        def getitem(name):
            return session_dict[name]
        def get(name):
            return session_dict.get(name)
        def setitem(name, val):
            session_dict[name] = val
        mock_session.__getitem__.side_effect = getitem
        mock_session.get.side_effect = get
        mock_session.__setitem__.side_effect = setitem

        extra_environ = {'REMOTE_USER': str(user['name'])}

        response = self.app.get('/', extra_environ=extra_environ)

        mock_refresh_function.assert_called_once_with(
            pylons.session, config['ckanext.oauth2waad.client_id'],
            config['ckanext.oauth2waad.resource'],
            config['ckanext.oauth2waad.auth_token_endpoint'])

    @mock.patch('ckanext.oauth2waad.plugin._refresh_access_token_if_expiring')
    def test_identify_should_not_call_refresh_access_token(
            self, mock_refresh_function):
        '''When no user is logged in via WAAD identify() should not call
        _refresh_access_token_if_expiring().'''

        # We'll have a normal logged-in user.
        user = factories.User()
        extra_environ = {'REMOTE_USER': str(user['name'])}

        response = self.app.get('/', extra_environ=extra_environ)

        assert not mock_refresh_function.called

    # We want to mock pylons.session in this test so we can insert an
    # authorized WAAD user into it. Unfortunately pylons.session has many
    # names in CKAN, and we have to mock each one of them that our request
    # hits or we get crashes.
    @mock.patch('ckan.lib.helpers.flash')
    @mock.patch('ckanext.oauth2waad.plugin._refresh_access_token_if_expiring')
    @mock.patch('pylons.session')
    @mock.patch('ckan.lib.helpers.session')
    @mock.patch('ckan.lib.base.session')
    def test_identify_when_refresh_fails(
        self, mock_base_session, mock_helpers_session, mock_session,
        mock_refresh_function, mock_flash_function):
        '''Test identify()'s behaviour when _refresh_access_token_if_expiring()
        raises an exception.'''

        user = factories.User()

        mock_refresh_function.side_effect = (
            plugin.CannotRefreshAccessTokenError("Boom!"))

        # We need a mock session so we can insert ckanext-oauth2waad-user into
        # it.
        session_dict = {'ckanext-oauth2waad-user': user['name']}
        def getitem(name):
            return session_dict[name]
        def get(name):
            return session_dict.get(name)
        def setitem(name, val):
            session_dict[name] = val
        mock_session.__getitem__.side_effect = getitem
        mock_session.get.side_effect = get
        mock_session.__setitem__.side_effect = setitem

        extra_environ = {'REMOTE_USER': str(user['name'])}

        response = self.app.get('/', extra_environ=extra_environ)

        mock_refresh_function.assert_called_once_with(
            pylons.session, config['ckanext.oauth2waad.client_id'],
            config['ckanext.oauth2waad.resource'],
            config['ckanext.oauth2waad.auth_token_endpoint'])

        mock_flash_function.assert_called_once_with(
            'Refreshing your Windows Azure Active Directory OAuth 2.0 access '
            'token with fake.waad.auth failed. Some functionality may not be '
            'available. You can try <a href="/user/_logout">logging out</a> '
            'and logging in again to fix the issue.', ignore_duplicate=True,
            category='alert-error', allow_html=True)

    # We want to mock pylons.session in this test so we can insert an
    # authorized WAAD user into it. Unfortunately pylons.session has many
    # names in CKAN, and we have to mock each one of them that our request
    # hits or we get crashes.
    @mock.patch('ckan.plugins.toolkit.c', new_callable=mock.PropertyMock)
    @mock.patch('pylons.session')
    @mock.patch('ckan.lib.helpers.session')
    @mock.patch('ckan.lib.base.session')
    def test_identify_should_set_user(
        self, mock_base_session, mock_helpers_session, mock_session, mock_c):
        '''Test that identify() sets toolkit.c.user if a user is logged-in
        via WAAD.'''

        user = factories.User()

        session_dict = {'ckanext-oauth2waad-user': user['name']}
        def getitem(name):
            return session_dict[name]
        def get(name):
            return session_dict.get(name)
        mock_session.__getitem__.side_effect = getitem
        mock_session.get.side_effect = get

        extra_environ = {'REMOTE_USER': str(user['name'])}

        response = self.app.get('/', extra_environ=extra_environ)

        assert mock_c.user == user['name']

    @mock.patch('ckan.plugins.toolkit.c', new_callable=mock.PropertyMock)
    @mock.patch('ckanext.oauth2waad.plugin._refresh_access_token_if_expiring')
    def test_identify_should_not_set_user(
            self, mock_refresh_function, mock_c):
        '''When no user is logged in via WAAD identify() should not set c.user.

        '''
        mock_c.user = None
        response = self.app.get('/')
        assert mock_c.user is None

    # We want to mock pylons.session in this test so we can insert an
    # authorized WAAD user into it. Unfortunately pylons.session has many
    # names in CKAN, and we have to mock each one of them that our request
    # hits or we get crashes.
    @mock.patch('pylons.session')
    @mock.patch('ckan.lib.helpers.session')
    @mock.patch('ckan.lib.base.session')
    def test_logout(self, mock_base_session, mock_helpers_session,
                    mock_session):

        session_dict = {}
        def getitem(name):
            return session_dict[name]
        def get(name):
            return session_dict.get(name)
        def setitem(name, value):
            session_dict[name] = value
        def delitem(name):
            del session_dict[name]
        def iter_():
            return session_dict.__iter__()
        def contains(name):
            return (name in session_dict)
        mock_session.__getitem__.side_effect = getitem
        mock_session.get.side_effect = get
        mock_session.__setitem__.side_effect = setitem
        mock_session.__delitem__.side_effect = delitem
        mock_session.__iter__.side_effect = iter_
        mock_session.__contains__.side_effect = contains

        _do_login(self.app)

        self.app.get(toolkit.url_for(controller='user', action='logout'))

        assert 'ckanext-oauth2waad-user' not in mock_session
        assert 'ckanext-oauth2waad-refresh-token' not in mock_session
        assert 'ckanext-oauth2waad-expires-on' not in mock_session
        assert 'ckanext-oauth2waad-access-token' not in mock_session


@mock.patch('ckan.plugins.toolkit.get_action')
def test_log_the_user_in_when_user_account_exists(mock_get_action):
    '''Test _log_the_user_in() when the user account already exists in CKAN.

    '''
    # The fake CKAN user.
    fake_user = {
        'name': 'fake_user',
        'fullname': 'Fake User',
        }
    fake_given_name = 'Fake'
    fake_family_name = 'User'

    # We need to mock get_action and user_show to avoid hitting CKAN.
    mock_user_show = mock.MagicMock()
    mock_user_show.return_value = fake_user

    def get_action(name):
        if name == 'user_show':
            return mock_user_show
        else:
            assert False, "No action other than user_show should be called"
    mock_get_action.side_effect = get_action

    mock_session = MockPylonsSession()

    user_dict = plugin._log_the_user_in(
        'fake access token', 'fake refresh token', 'fake expires on',
        fake_user['name'], fake_given_name, fake_family_name, mock_session)

    # Assert that the right stuff was added into the session.
    assert mock_session['ckanext-oauth2waad-user'] == fake_user['name']
    assert mock_session['ckanext-oauth2waad-access-token'] == (
        'fake access token')
    assert mock_session['ckanext-oauth2waad-refresh-token'] == (
        'fake refresh token')
    assert mock_session['ckanext-oauth2waad-expires-on'] == 'fake expires on'

    # Assert the _log_the_user_in() returned the right value.
    assert user_dict['name'] == fake_user['name']
    assert user_dict['fullname'] == fake_user['fullname']


@mock.patch('ckan.plugins.toolkit.get_action')
def test_log_the_user_in_when_user_account_does_not_exist(mock_get_action):
    '''Test _log_the_user_in() when the user account does not yet exist.'''

    # The fake CKAN user that we expect to be created.
    fake_user = {
        'name': 'fake_user',
        'fullname': 'Fake User',
        }
    fake_given_name = 'Fake'
    fake_family_name = 'User'

    # We need to mock get_action, user_show and user_create to avoid hitting
    # CKAN.
    mock_user_show = mock.MagicMock()
    mock_user_show.side_effect = toolkit.ObjectNotFound
    mock_user_create = mock.MagicMock()
    mock_user_create.return_value = fake_user

    def get_action(name):
        if name == 'user_show':
            return mock_user_show
        elif name == 'user_create':
            return mock_user_create
        else:
            assert False, ("This mock expects that no actions except "
                           "user_show and user_create will be called")
    mock_get_action.side_effect = get_action

    mock_session = MockPylonsSession()

    user_dict = plugin._log_the_user_in(
        'fake access token', 'fake refresh token', 'fake expires on',
        fake_user['name'], fake_given_name, fake_family_name, mock_session)

    # Assert that user_create was called as expected.
    assert mock_user_create.call_count == 1
    positional_args, keyword_args = mock_user_create.call_args
    assert keyword_args['context'] == {'ignore_auth': True}
    assert keyword_args['data_dict']['name'] == fake_user['name']
    assert keyword_args['data_dict']['fullname'] == fake_user['fullname']

    # Assert that the right stuff was added into the session.
    assert mock_session['ckanext-oauth2waad-user'] == fake_user['name']
    assert mock_session['ckanext-oauth2waad-access-token'] == (
        'fake access token')
    assert mock_session['ckanext-oauth2waad-refresh-token'] == (
        'fake refresh token')
    assert mock_session['ckanext-oauth2waad-expires-on'] == 'fake expires on'

    # Assert the _log_the_user_in() returned the right value.
    assert user_dict['name'] == fake_user['name']
    assert user_dict['fullname'] == fake_user['fullname']


@mock.patch('ckan.plugins.toolkit.get_action')
def test_log_the_user_in_validation_error(mock_get_action):
    '''Test _log_the_user_in() when user_create raises a ValidationError.'''

    # The fake CKAN user that we'll try to creatre.
    # The user name is not a valid user name (not that it matters - we'll use
    # a mock user_create to raise the ValidationError anyway.
    fake_user = {
        'name': 'this is not a valid user name because it has spaces in it',
        'fullname': 'Fake User',
        }
    fake_given_name = 'Fake'
    fake_family_name = 'User'

    # We need to mock get_action, user_show and user_create to avoid hitting
    # CKAN.
    mock_user_show = mock.MagicMock()
    mock_user_show.side_effect = toolkit.ObjectNotFound
    mock_user_create = mock.MagicMock()
    def raise_validation_error(*args, **kwargs):
        raise toolkit.ValidationError('Error!')
    mock_user_create.side_effect = raise_validation_error

    def get_action(name):
        if name == 'user_show':
            return mock_user_show
        elif name == 'user_create':
            return mock_user_create
        else:
            assert False, ("This mock expects that no actions except "
                           "user_show and user_create will be called")
    mock_get_action.side_effect = get_action

    mock_session = mock.MagicMock()

    nose.tools.assert_raises(plugin.CouldNotCreateUserException,
                             plugin._log_the_user_in, 'fake access token',
                             'fake refresh token', 'fake expires on',
                             fake_user['name'], fake_given_name,
                             fake_family_name, mock_session)

    # Assert that user_create was called as expected.
    assert mock_user_create.call_count == 1
    positional_args, keyword_args = mock_user_create.call_args
    assert keyword_args['context'] == {'ignore_auth': True}
    assert keyword_args['data_dict']['name'] == fake_user['name']
    assert keyword_args['data_dict']['fullname'] == fake_user['fullname']

    # Nothing should have been added into the session.
    assert not mock_session.called


@httpretty.activate
def _do_login(app,
              params='?code=fake_auth_code&session_state=fake_session_state'):
    '''Do a login via the web UI and return the user dashboard HTML page
    response that we finally get.'''

    # Load the CKAN login page and find the WAAD login link.
    login_url = toolkit.url_for(controller='user', action='login')
    response = app.get(login_url)
    soup = response.html
    link = soup.find(id='waad-login-link')

    # Mock the WAAD server.
    location = '/' + config['ckanext.oauth2waad.redirect_uri'].split('/', 3)[-1]
    location = location + params
    endpoint = config['ckanext.oauth2waad.auth_endpoint']
    httpretty.register_uri(httpretty.GET, endpoint, body='', status=302,
                           adding_headers={'location': location})

    # Mock the WAAD server.
    endpoint = config['ckanext.oauth2waad.auth_token_endpoint']
    httpretty.register_uri(
        httpretty.POST, endpoint, status=200,
        body=json.dumps(_access_token_response_dict(_jwt_payload())))

    # Click on the WAAD login link.
    response = requests.get(link['href'], allow_redirects=False)

    # Mock the browser redirect.
    response = app.get(response.headers['location'])

    # Sometimes we get redirected to the user dashboard.
    if response.status_int == 302:
        response = response.follow()

    return response


class TestWAADRedirectController:

    '''Functional tests for the WAADRedirectController class.'''

    @classmethod
    def setup_class(cls):
        import ckan.config.middleware
        cls.app = ckan.config.middleware.make_app(config['global_conf'],
                                                  **config)
        cls.app = webtest.TestApp(cls.app)

    def setup(self):
        import ckan.model as model
        model.Session.close_all()
        model.repo.rebuild_db()

    def test_login(self):
        response = _do_login(self.app)
        assert response.html.find('a', title='View profile').find(
            class_='username').text == 'fake given_name fake family_name'

    @mock.patch('ckan.plugins.toolkit.get_action')
    def test_login_with_user_create_exception(self, mock_get_action):

        mock_user_show = mock.MagicMock()
        mock_user_show.side_effect = toolkit.ObjectNotFound
        mock_user_create = mock.MagicMock()
        def raise_validation_error(*args, **kwargs):
            raise toolkit.ValidationError('Error!')
        mock_user_create.side_effect = raise_validation_error
        def get_action(name):
            if name == 'user_show':
                return mock_user_show
            elif name == 'user_create':
                return mock_user_create
            else:
                assert False, ("This mock expects that no actions except "
                            "user_show and user_create will be called")
        mock_get_action.side_effect = get_action

        response = _do_login(self.app)
        response.mustcontain("Creating your CKAN user account failed")

    def test_login_with_no_code(self):
        '''Test login() when there's no code in the redirect_uri request
        params.'''
        response = _do_login(self.app, params='')
        assert response.status_int == 200
        assert not response.body
