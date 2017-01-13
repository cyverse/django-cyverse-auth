"""
Authentication Backends and validation methods
"""
from urlparse import urlparse

from django.contrib.auth.backends import ModelBackend
from django.conf import settings
from django.contrib.auth import get_user_model

from libcloud.common.openstack_identity import OpenStackIdentity_3_0_Connection, OpenStackIdentityTokenScope

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client


from .settings import auth_settings
from .models import get_or_create_user
from .models import Token
from .protocol.ldap import ldap_validate, ldap_formatAttrs
from .protocol.ldap import lookupUser as ldap_lookupUser
from .protocol.cas import cas_validateUser
from .protocol.globus import (
    globus_validate_code, _extract_first_last_name,
    globus_profile_for_token,
    create_user_token_from_globus_profile)
from caslib import OAuthClient as CAS_OAuthClient
#From troposphere
import ldap
import logging

logger = logging.getLogger(__name__)


from rest_framework import authentication, exceptions
from uuid import uuid4


class SAMLLoginBackend(ModelBackend):

    """
    Implemting an AuthenticationBackend
    (Used by Django for logging in to admin, storing session info)
    """

    def authenticate(self, username=None, password=None, request=None):
        """
        Return user if validated by CAS
        Return None otherwise.
        """
        # logger.debug("SAMLBackend-- U:%s P:%s R:%s"
        #              % (username, password, request))
        if not request:
            logger.debug("SAML Authentication skipped - No request.")
            return None
        # TODO: See if you were the auth backend used to originate the request.
        # TODO: Look at request session for a token and see if its still valid.
        if False:
            logger.debug("SAML Authentication failed - " + username)
            return None


class CASLoginBackend(ModelBackend):

    """
    Implemting an AuthenticationBackend
    (Used by Django for logging in to admin, storing session info)
    """

    def authenticate(self, username=None, password=None, request=None):
        """
        Return user if validated by CAS
        Return None otherwise.
        """
        # logger.debug("CASBackend -- U:%s P:%s R:%s"
        #              % (username, password, request))
        if not username:
            logger.debug("CAS Authentication skipped - No Username.")
            return None
        (success, cas_response) = cas_validateUser(username)
        logger.info("Authenticate by CAS: %s - %s %s"
                    % (username, success, cas_response))
        if not success:
            logger.debug("CAS Authentication failed - " + username)
            return None
        attributes = cas_response.attributes
        return get_or_create_user(username, attributes)


class LDAPLoginBackend(ModelBackend):

    """
    AuthenticationBackend for LDAP logins
    (Logging in from admin or Django REST framework login)
    """

    def authenticate(self, username=None, password=None, request=None):
        """
        Return user if validated by LDAP.
        Return None otherwise.
        """
        # logger.debug("LDAPBackend-- U:%s P:%s R:%s"
        #              % (username, password, request))
        if not ldap_validate(username, password):
            logger.debug("LDAP Authentication failed - " + username)
            return None
        ldap_attrs = ldap_lookupUser(username)
        attributes = ldap_formatAttrs(ldap_attrs)
        logger.debug("[LDAP] Authentication Success - " + username)
        return get_or_create_user(username, attributes)


class AuthTokenLoginBackend(ModelBackend):

    """
    AuthenticationBackend for OAuth authorizations
    (Authorize user from Third party (web) clients via OAuth)
    """
    def __init__(self, *args, **kwargs):
        super(AuthTokenLoginBackend, self).__init__(*args, **kwargs)

    def authenticate(self, username=None, password=None, auth_token=None,
                     request=None):
        """
        Return user if validated by their auth_token
        Return None otherwise.
        """
        try:
            valid_token = Token.objects.get(key=auth_token)
        except Token.DoesNotExist:
            return None
        if valid_token.is_expired():
            logger.debug(
                "[AUTHTOKEN] Token %s is expired. (User:%s)"
                % (valid_token.key, valid_token.user))
            return None
        logger.debug(
            "[AUTHTOKEN] Valid Token %s (User:%s)"
            % (valid_token.key, valid_token.user))
        valid_user = valid_token.user
        return get_or_create_user(valid_user.username, {})

#### Troposphere needs

cas_oauth_client = CAS_OAuthClient(auth_settings.CAS_SERVER,
                                   auth_settings.OAUTH_CLIENT_CALLBACK,
                                   auth_settings.OAUTH_CLIENT_KEY,
                                   auth_settings.OAUTH_CLIENT_SECRET,
                                   auth_prefix=auth_settings.CAS_AUTH_PREFIX)


def create_user_token_from_cas_profile(profile, access_token):
    profile_dict = dict()
    username = profile['id']
    for attr in profile['attributes']:
        key = attr.keys()[0]
        value = attr[key]
        profile_dict[key] = value

    user = get_or_create_user(username, profile_dict)
    user_token = Token.objects.create(key=access_token, user=user)
    return user_token

def generate_token(user, issued_token=None):
    if not issued_token:
        issued_token = uuid4()
    user_token = Token.objects.create(user=user, key=str(issued_token))
    return user_token


class GlobusOAuthLoginBackend(object):
    """
    Globus OAuth Authentication Backend

    Exchanges an access_token for a user, creates if does not exist
    """

    def authenticate(self, key=None):
        user_token = None
        try:
            user_token = Token.objects.get(key=key)
        except Token.DoesNotExist:
            user_profile = globus_profile_for_token(key)
            user_token = create_user_token_from_globus_profile(user_profile, key)
        if not user_token:
            return None
        user = user_token.user
        return user

    def get_user(self, user_id):
        """
        Get a User object from the username.
        """
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class OAuthLoginBackend(object):
    """
    CAS OAuth Authentication Backend

    Exchanges an access_token for a user, creates if does not exist
    """

    def authenticate(self, access_token=None):
        try:
            user_token = Token.objects.get(key=access_token)

        except Token.DoesNotExist:
            profile = cas_oauth_client.get_profile(access_token=access_token)
            # todo: handle [profile.get('error') = 'expired_accessToken'] error
            user_token = create_user_token_from_cas_profile(profile, access_token)

        user = user_token.user
        return user

    def get_user(self, user_id):
        """
        Get a User object from the username.
        """
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class OAuthTokenLoginBackend(authentication.BaseAuthentication):
    """
    CAS OAuth Authentication Backend

    Exchanges an access_token for a user, creates if does not exist
    """

    def authenticate(self, request):
        access_token = None
        auth = request.META.get('HTTP_AUTHORIZATION', '').split()
        if len(auth) == 2 and auth[0].lower() == "token":
            access_token = auth[1]
        else:
            return None

        try:
            user_token = Token.objects.get(key=access_token)

        except Token.DoesNotExist:
            profile = cas_oauth_client.get_profile(access_token=access_token)
            error = profile.get('error')

            if error:
                raise exceptions.AuthenticationFailed(error)

            user_token = create_user_token_from_cas_profile(profile, access_token)

        user = user_token.user
        return (user, user_token)


class MockLoginBackend(authentication.BaseAuthentication):
    """
    AuthenticationBackend for Testing login
    (Logging in from admin or Django REST framework login)
    """
    def authenticate(self, username=None, password=None, request=None):
        """
        Return user if Always
        Return None Never.
        """
        return get_or_create_user(settings.ALWAYS_AUTH_USER, {
            'username':settings.ALWAYS_AUTH_USER,
            'firstName':"Mocky Mock",
            'lastName':"MockDoodle",
            'email': '%s@iplantcollaborative.org' % settings.ALWAYS_AUTH_USER,
            'entitlement': []
        })

    def get_user(self, user_id):
        """
        Get a User object from the username.
        """
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class OpenstackLoginBackend(ModelBackend):
    """
    Libcloud OpenstackIdentity 3.0 Login for Atmosphere
    """
    def authenticate(self, username, password, project_name=None, auth_url=None, request=None):
        if not project_name:
            project_name = username

        if not auth_url:
            auth_url = auth_settings.KEYSTONE_SERVER
        if '/v' not in auth_url:
            auth_url += "/v3"  # Assume v3

        driver = OpenStackIdentity_3_0_Connection(auth_url=auth_url+"/auth/tokens", user_id=username, key=password, token_scope=OpenStackIdentityTokenScope.PROJECT, tenant_name=project_name)

        try:
            conn = driver.authenticate()
            auth_token = driver.auth_token
            if request:
                request.session['token_key'] = auth_token
        except:
            return None

        parsed_auth_url = urlparse(auth_url)
        hostname = parsed_auth_url.hostname

        return get_or_create_user(username, {
            'username': username,
            'firstName': username,
            'lastName': "",
            'email': "%s@%s" % (username, hostname),
            'entitlement': []
        })

class KeystoneLoginBackend(ModelBackend):
    """
    Keystone Auth Login for Atmosphere
    """
    def authenticate(self, username, password, request=None):
        auth_url = auth_settings.KEYSTONE_SERVER
        user_domain_name  = auth_settings.KEYSTONE_DOMAIN_NAME
        parsed_auth_url = urlparse(auth_url)
        hostname = parsed_auth_url.hostname
        unscoped_auth=v3.Password(username=username,password=password,auth_url=auth_url,user_domain_name=user_domain_name, unscoped=True)
        unscoped_sess=session.Session(auth=unscoped_auth)
        try:
            unscoped_token=unscoped_sess.get_token()
            try:
                auth=v3.Token(auth_url=auth_url,token=unscoped_token)
                sess=session.Session(auth=auth)
                scoped_token=sess.get_token()
                # Without modification of OpenStack's default user-role permissions,
                # it is impossible to introspect further for user information.
                # As a result, any accounts created this way will not have a valid: [firstName, lastName, email] attribute.
                # Openstack only stores e-mail, anyway...
                return get_or_create_user(username, {
                    'username': username,
                    'firstName': username,
                    'lastName': "",
                    'email': "%s@%s" % (username, hostname),
                    'entitlement': []
                })
            except:
                return None
        except:
            return None
