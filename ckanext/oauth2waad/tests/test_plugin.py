import json

import httpretty
import jwt

import ckanext.oauth2waad.plugin as plugin


@httpretty.activate
def test_get_user_details_from_waad():
    '''Test getting an access token and user details from WAAD.'''

    # Fake params to post to the mock WAAD server.
    auth_code = 'fake auth code'
    client_id = 'fake client id'
    redirect_uri = 'fake redirect uri'
    resource = 'resource'

    # The WAAD auth token endpoint to post to. We will mock this.
    endpoint = 'https://login.windows.net/common/oauth2/token'

    # Fake params that the mock WAAD server will return.
    access_token = 'fake access token'
    refresh_token = 'fake refesh token'
    expires_on = 'fake expires on'
    family_name = 'fake family name'
    given_name = 'fake given name'
    oid = 'fake oid'
    payload = {
        'family_name': family_name,
        'given_name': given_name,
        'oid': oid,
        }
    id_token = jwt.encode(payload, access_token)

    def request_callback(request, url, headers):
        '''Our mock WAAD server response.'''

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

        body = json.dumps({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_on': expires_on,
            'id_token': id_token,
            })
        return (200, headers, body)

    httpretty.register_uri(httpretty.POST, endpoint, body=request_callback)

    details = plugin._get_user_details_from_waad(
        auth_code, client_id, redirect_uri, resource, endpoint)

    assert details.get('access_token') == access_token
    assert details.get('refresh_token') == refresh_token
    assert details.get('expires_on') == expires_on
    assert details.get('oid') == oid
    assert details.get('given_name') == given_name
    assert details.get('family_name') == family_name
