import json

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
    endpoint = 'https://login.windows.net/common/oauth2/token'

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
    endpoint = 'https://login.windows.net/common/oauth2/token'
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
    endpoint = 'https://login.windows.net/common/oauth2/token'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    nose.tools.assert_raises(plugin.InvalidAccessTokenResponse,
                             plugin._get_user_details_from_waad,
                             'fake auth code', 'fake client id',
                             'fake redirect_uri', 'fake resource',
                             endpoint)

# TODO: Tests for other missing keys in response JSON.

def test_get_user_details_from_waad_with_no_json():
    '''Test _get_user_details_from_waad() when there's no JSON in the response
    body.

    '''
    def request_callback(request, url, headers):
        '''Our mock WAAD server response.'''
        # Return a response with no body.
        return (200, headers)

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://login.windows.net/common/oauth2/token'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    nose.tools.assert_raises(plugin.InvalidAccessTokenResponse,
                             plugin._get_user_details_from_waad,
                             'fake auth_code', 'fake client_id',
                             'fake redirect_uri', 'fake resource',
                             endpoint)


def test_get_user_details_from_waad_when_json_is_not_a_dict():
    '''Test _get_user_details_from_waad() when there is a JSON response body
    but it's not a top-level JSON object.

    '''
    def request_callback(request, url, headers):
        '''Our mock WAAD server response.'''
        # Return a response with no body.
        return (200, headers, json.dumps([1,2,3]))

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://login.windows.net/common/oauth2/token'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    nose.tools.assert_raises(plugin.InvalidAccessTokenResponse,
                             plugin._get_user_details_from_waad,
                             'fake auth_code', 'fake client_id',
                             'fake redirect_uri', 'fake resource',
                             endpoint)


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
    endpoint = 'https://login.windows.net/common/oauth2/token'
    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    nose.tools.assert_raises(plugin.InvalidAccessTokenResponse,
                             plugin._get_user_details_from_waad,
                             'fake auth_code', 'fake client_id',
                             'fake redirect_uri', 'fake resource',
                             endpoint)
