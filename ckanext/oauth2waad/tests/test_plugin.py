import json
import UserDict
import calendar
import time

import httpretty
import jwt
import nose.tools

import ckanext.oauth2waad.plugin as plugin


def _jwt_payload():
    '''Mock JWT payload of an access token response from the WAAD server.

    The WAAD server puts this dict (as JSON) as the payload in a JWT Web Token
    with key "id_token" in the response body.

    '''
    return {
        'family_name': 'fake family_name',
        'given_name': 'fake given_name',
        'oid': 'fake oid',
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
