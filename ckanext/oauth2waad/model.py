import sqlalchemy
import sqlalchemy.types as types
import sqlalchemy.orm.exc

import ckan.model
import ckan.model.meta


service_to_service_access_token_table = sqlalchemy.Table(
    'service_to_service_access_token', ckan.model.meta.metadata,
    sqlalchemy.Column('token', types.UnicodeText, primary_key=True),
    sqlalchemy.Column('expires_on', types.UnicodeText))


class ServiceToServiceAccessToken(object):
    def __init__(self, token, expires_on):
        self.token = token
        self.expires_on = expires_on


ckan.model.meta.mapper(ServiceToServiceAccessToken,
                       service_to_service_access_token_table)


def service_to_service_access_token():
    '''Return the service-to-service access token cached in the db, or None.'''

    try:
        query = ckan.model.Session.query(ServiceToServiceAccessToken)
        token = query.one()
    except sqlalchemy.exc.ProgrammingError as exc:
        if exc.orig.pgcode == '42P01':
            service_to_service_access_token_table.create()
            ckan.model.Session.commit()
            token = None
        else:
            raise
    except sqlalchemy.orm.exc.NoResultFound:
        token = None
    return token


def save_service_to_service_access_token(token, expires_on):

    token_obj = service_to_service_access_token()
    if token_obj is None:
        token_obj = ServiceToServiceAccessToken(token, expires_on)
        ckan.model.Session.add(token_obj)
    else:
        token_obj.token = token
        token_obj.expires_on = expires_on
    ckan.model.Session.commit()
