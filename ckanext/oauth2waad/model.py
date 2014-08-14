import sqlalchemy
import sqlalchemy.types as types
import sqlalchemy.orm.exc

import ckan.model
import ckan.model.meta


service_to_service_access_token_table = sqlalchemy.Table(
    'service_to_service_access_token', ckan.model.meta.metadata,
    sqlalchemy.Column('resource', types.UnicodeText, primary_key=True),
    sqlalchemy.Column('token', types.UnicodeText),
    sqlalchemy.Column('expires_on', types.UnicodeText))


class ServiceToServiceAccessToken(object):
    def __init__(self, resource, token, expires_on):
        self.resource = resource
        self.token = token
        self.expires_on = expires_on


ckan.model.meta.mapper(ServiceToServiceAccessToken,
                       service_to_service_access_token_table)


def setup():
    if not service_to_service_access_token_table.exists():
        service_to_service_access_token_table.create()


def service_to_service_access_token(resource):
    '''Return the service-to-service access token cached in the db, or None.'''

    try:
        query = ckan.model.Session.query(ServiceToServiceAccessToken) \
            .filter(ServiceToServiceAccessToken.resource==resource)
        token = query.one()
    except sqlalchemy.orm.exc.NoResultFound:
        token = None
    return token


def save_service_to_service_access_token(resource, token, expires_on):

    token_obj = service_to_service_access_token(resource)
    if token_obj is None:
        token_obj = ServiceToServiceAccessToken(resource, token, expires_on)
        ckan.model.Session.add(token_obj)
    else:
        token_obj.token = token
        token_obj.expires_on = expires_on
    ckan.model.Session.commit()
