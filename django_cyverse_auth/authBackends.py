"""
Authentication Backends and validation methods
"""
from urlparse import urlparse

from django.contrib.auth.backends import ModelBackend
from django.conf import settings
from django.contrib.auth import get_user_model

from libcloud.common.openstack_identity import OpenStackIdentity_3_0_Connection, OpenStackIdentityTokenScope
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client


from .settings import auth_settings
from .models import get_or_create_user, create_user_and_token
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
            logger.debug("SAML Authentication failed - %s" % username)
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
            logger.debug("CAS Authentication failed - %s" % username)
            return None
        attributes = cas_response.attributes
        return get_or_create_user(username, attributes)


class LDAPLoginBackend(ModelBackend):

    """
    AuthenticationBackend for LDAP logins
    (Logging in from admin or Django REST framework login)
    """

    def authenticate(self, username=None, password=None, token=None, request=None):
        """
        Return user if validated by LDAP.
        Return None otherwise.
        """
        # logger.debug("LDAPBackend-- U:%s P:%s R:%s"
        #              % (username, password, request))
        if not ldap_validate(username, password):
            logger.debug("LDAP Authentication failed - %s" % username)
            return None
        ldap_attrs = ldap_lookupUser(username)
        attributes = ldap_formatAttrs(ldap_attrs)
        attributes['username'] = username
        logger.debug("[LDAP] Authentication Success - " + username)
        return self._update_token(attributes, token, request)

    def _update_token(self, user_profile, token, request=None):
        auth_token = create_user_and_token(user_profile, token, issuer="LDAPLoginBackend")
        user = auth_token.user
        if request:
            request.session['token_key'] = auth_token.key
        return user



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
    Keystone Login for Atmosphere
    Includes optional libcloud setup if/when keystone client stops working.
    """
    strategy = "keystone"

    def authenticate(self, username, password, project_name=None, auth_url=None, token=None, domain=None, request=None):
        if not project_name:
            project_name = username

        if not auth_url:
            auth_url = auth_settings.KEYSTONE_SERVER
        if not domain:
            domain = auth_settings.KEYSTONE_DOMAIN_NAME
        if '/v' not in auth_url:
            auth_url += "/v3"  # Assume v3
        #TODO: If necessary, create a auth_setting 'feature' to select 'libcloud' or 'keystone' as the strategy and then validate token/auth the same way.
        if self.strategy == 'libcloud':
            user = self.auth_by_libcloud(auth_url, project_name, domain, username, password, token, request)
        else:
            user = self.auth_by_keystone(auth_url, project_name, domain, username, password, token, request)
        return user

    def auth_by_keystone(self, auth_url, project_name, domain, username, password=None, token=None, request=None):
        """
        Given username/password or username/token
        return user
        """
        if token:
            user = self.keystone_validate_token(auth_url, username, token, project_name, domain, request)
            return user
        return self.keystone_validate_auth(auth_url, username, password, project_name, domain, request)

    def keystone_validate_auth(self, auth_url, username, password, project_name, domain_name, request):
        """
        Given username,password -- validate with keystone
        """
        password_auth = v3.Password(
            auth_url=auth_url,
            username=username, password=password,
            user_domain_id=domain_name,
            project_name=project_name, project_domain_id=domain_name)
        try:
            token = self._keystone_auth_to_token(password_auth, username, project_name)
            return self._update_token(auth_url, username, token, request)
        except:
            logger.exception("Error validating keystone auth by password")
            return None

    def keystone_validate_token(self, auth_url, username, token, project_name, project_domain, request):
        """
        Given token -- validate with keystone
        """
        token_auth=v3.Token(
            auth_url=auth_url,
            token=token,
            project_name=project_name,
            project_domain_id=project_domain)
        try:
            self._keystone_auth_to_token(token_auth, username, project_name)
            return self._update_token(auth_url, username, token, request)
        except:
            logger.exception("Error validating keystone auth by token")
            return None

    def _keystone_auth_to_token(self, keystone_auth_obj, username, project_name):
        """
        Validates a keystone auth (v3.Password or v3.Token) to determine if its valid
        if valid, it should match the username/project_name
        """
        ks_session = session.Session(auth=keystone_auth_obj)
        ks_client = client.Client(session=ks_session)
        # Validate the driver by requesting token data from keystone
        try:
            token_key = ks_session.get_token()
        except:
            raise Exception("Keystone client could not validate authentication")

        # Validate the token_data returned from keystone
        try:
            token_data = ks_client.tokens.get_token_data(token_key)
            token_username = token_data['token']['user']['name']
            token_project_name = token_data['token']['project']['name']
        except (KeyError, ValueError):
            logger.exception("DATA CHANGED -- update value to match new token_data: %s" % token_data)
            raise

        if token_project_name != project_name:
            raise Exception("Token %s does not match expected project name - %s" % token_key, project_name)
        if token_username != username:
            raise Exception("Token %s does not match expected username - %s" % token_key, username)
        return token_key
    #Alternative method -- libcloud 'strategy'

    def auth_by_libcloud(self, auth_url, project_name, domain, username, password=None, token=None, request=None):
        """
        Given username/password or username/token
        return user
        """
        if token:
            user = self.libcloud_validate_token(auth_url, username, token, project_name, domain, request)
            return user
        return self.libcloud_validate_auth(auth_url, username, password, project_name, domain, request)

    def libcloud_validate_token(self, auth_url, username, token, project_name, domain, request):
        OpenStack = get_driver(Provider.OPENSTACK)
        driver = OpenStack(username, "",
                   ex_force_base_url=auth_url.replace(":5000/v3",":8774/v2"),
                   ex_force_auth_url=auth_url,
                   ex_tenant_name=project_name, ex_domain_name=domain,
                   ex_force_auth_version='3.x_password',
                   ex_force_service_region='RegionOne',
                   ex_force_auth_token=token)
        try:
            sizes = driver.list_sizes()
            return self._update_token(auth_url, username, token, request)
        except Exception as exc:
            logger.exception("Error validating libcloud auth by token")
            return None


    def libcloud_validate_auth(self, auth_url, username, password, project_name, domain, request):
        driver = OpenStackIdentity_3_0_Connection(
            auth_url=auth_url+"/auth/tokens",
            user_id=username, key=password,  #TODO: add domain
            token_scope=OpenStackIdentityTokenScope.PROJECT, tenant_name=project_name)

        try:
            conn = driver.authenticate()
            auth_token = driver.auth_token
            return self._update_token(auth_url, username, auth_token, request)
        except:
            logger.exception("Error validating libcloud auth by password")
            return None

    # Private helper methods -- commonly used

    def _user_profile_for_auth(self, auth_url, username):
        parsed_auth_url = urlparse(auth_url)
        hostname = parsed_auth_url.hostname
        user_profile = {
            'username': username,
            'firstName': username,
            'lastName': "",
            'email': "%s@%s" % (username, hostname),
            'entitlement': []
        }
        return user_profile

    def _update_token(self, auth_url, username, token, request=None):
        user_profile = self._user_profile_for_auth(auth_url, username)
        auth_token = create_user_and_token(user_profile, token, issuer="OpenstackLoginBackend")
        user = auth_token.user
        if request:
            request.session['token_key'] = auth_token.key
        return user

    def _grant_access(self, auth_url, username):
        user_profile = self._user_profile_for_auth(auth_url, username)
        return get_or_create_user(username, user_profile)
