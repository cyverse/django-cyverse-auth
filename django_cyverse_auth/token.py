# -*- coding: utf-8 -*-
"""
Token based authentication
"""
from urlparse import urlparse

from django.conf import settings
from django.contrib.auth import get_user_model
from requests.exceptions import ConnectionError
from rest_framework.authentication import BaseAuthentication
from .settings import auth_settings
from .models import (
    Token as AuthToken,
    get_or_create_user,
    get_or_create_token
)
from .protocol.cas import cas_validateUser
from .protocol.cas import cas_profile_for_token
from .protocol.globus import (
    globus_profile_for_token, create_user_token_from_globus_profile
)
from .protocol.wso2 import WSO2_JWT

import logging
logger = logging.getLogger(__name__)

User = get_user_model()


def getRequestParams(request):
    """
    Extracts paramters from GET/POST in a Django Request object
    """
    if request.META['REQUEST_METHOD'] == 'GET':
        try:
            # Will only succeed if a GET method with items
            return dict(request.GET.items())
        except:
            pass
    elif request.META['REQUEST_METHOD'] == 'POST':
        try:
            # Will only succeed if a POST method with items
            return dict(request.POST.items())
        except:
            pass
    logger.debug("REQUEST_METHOD is neither GET or POST.")


def getRequestVars(request):
    """
    Extracts parameters from a Django Request object
    Expects ALL or NOTHING. You cannot mix data!
    """
    username = None
    token = None
    api_server = None
    emulate = None
    try:
        # Attempt #1 - SessionStorage - Most reliable
        logger.debug(request.session.items())
        username = request.session['username']
        token = request.session['token']
        api_server = request.session['api_server']
        emulate = request.session.get('emulate', None)
        return {'username': username, 'token': token, 'api_server': api_server,
                'emulate': emulate}
    except KeyError:
        pass
    try:
        # Attempt #2 - Header/META values, this is DEPRECATED as of v2!
        logger.debug(request.META.items())
        username = request.META['HTTP_X_AUTH_USER']
        token = request.META['HTTP_X_AUTH_TOKEN']
        api_server = request.META['HTTP_X_API_SERVER']
        emulate = request.META.get('HTTP_X_AUTH_EMULATE', None)
        return {'username': username, 'token': token,
                'api_server': api_server, 'emulate': emulate}
    except KeyError:
        pass
    try:
        # Final attempt - GET/POST values
        params = getRequestParams(request)
        logger.debug(params.items())
        username = params['HTTP_X_AUTH_USER']
        token = params['HTTP_X_AUTH_TOKEN']
        api_server = params['HTTP_X_API_SERVER']
        emulate = params.get('HTTP_X_AUTH_EMULATE', None)
        return {'username': username, 'token': token,
                'api_server': api_server, 'emulate': emulate}
    except KeyError:
        pass
    return None


class TokenAuthentication(BaseAuthentication):

    """
    Atmosphere 'AuthToken' based authentication.
    To authenticate, pass the token key in the "Authorization"
    HTTP header, prepended with the string "Token ". For example:
        Authorization: Token 098f6bcd4621d373cade4e832627b4f6
    """
    model = AuthToken

    def authenticate(self, request):
        token_key = None
        auth = request.META.get('HTTP_AUTHORIZATION', '').split()
        if len(auth) == 2 and auth[0].lower() == "token":
            token_key = auth[1]

        if not token_key and 'token' in request.session:
            token_key = request.session['token']
        if validate_token(token_key):
            token = self.model.objects.get(key=token_key)
            if token.user.is_active:
                return (token.user, token)
        return None


class JWTTokenAuthentication(TokenAuthentication):

    """
    JWTTokenAuthentication:
    To authenticate, pass the token key in the "Authorization" HTTP header,
    prepend with the string "Bearer ". For example:
        Authorization: Bearer 098f6bcd4621d373cade4e832627b4f6
    """

    def authenticate(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', '').split()
        jwt_assertion = request.META.get('HTTP_ASSERTION')
        if jwt_assertion:
            sp = WSO2_JWT(auth_settings.JWT_SP_PUBLIC_KEY_FILE)
            auth_token = sp.create_token_from_jwt(jwt_assertion)
            if auth_token.user.is_active:
                return (auth_token.user, auth_token)
        return None


class GlobusOAuthTokenAuthentication(TokenAuthentication):

    """
    GlobusOAuthTokenAuthentication:
    To authenticate, pass the token key in the "Authorization" HTTP header,
    prepend with the string "Token ". For example:
        Authorization: Token <777-char string>
    """

    def authenticate(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', '').split()
        if len(auth) == 2 and auth[0].lower() == "token":
            oauth_token = auth[1]
            if validate_globus_oauth_token(oauth_token):
                try:
                    token = self.model.objects.get(key=oauth_token)
                except self.model.DoesNotExist:
                    return None
                if token and token.user.is_active:
                    return (token.user, token)
        return None

def validate_globus_oauth_token(token, request=None):
    """
    Validates the token attached to the request (SessionStorage, GET/POST)
    On every request, ask OAuth to authorize the token
    """
    # Attempt to contact globus
    try:
        user_profile = globus_profile_for_token(token)
    except Exception:
        logger.exception("Globus could not find profile information for token %s" % token)
        user_profile = None

    if not user_profile:
        return False
    # Attempt to 'read' the user_profile
    try:
        auth_token = create_user_token_from_globus_profile(user_profile, token)
    except Exception:
        logger.exception("The method for which to 'read' a globus token has changed. Check the code for more details")
        auth_token = None
    if not auth_token:
        return False
    return True


class OpenstackTokenAuthentication(TokenAuthentication):

    """
    OpenstackTokenAuthentication:
    To authenticate, pass the token key in the "Authorization" HTTP header,
    prepend with the string "Token ". For example:
        Authorization: Token <Keystone_Token>
    """

    def authenticate(self, request):
        """
        TODO: This method might take an already-logged in user who possesses a KEYSTONE TOKEN -- one could then determine if the token was still 'valid' and use that truth-value to authenticate the request.
        The entire user-object would need to be returned, and the dependencies for this method would have to include rtwo/openstacksdk which might make this entire process out-of-scope for django-cyverse-auth
        TODO: Ideally, more things would be passed through headers to tell us:
            - What KEYSTONE_SERVER to authenticate with
            - What the username or other information is *expected* to be..
            - ??
        """
        auth = request.META.get('HTTP_AUTHORIZATION', '').split()
        auth_url = auth_settings.KEYSTONE_SERVER
        region_name = "RegionOne"  # This could be passed in via header _OR_ as an auth_settings.KEYSTONE_REGION_NAME
        domain_name = "Default"  # This could be passed in via header _OR_ as an auth_settings.KEYSTONE_DOMAIN_NAME
        parsed_auth_url = urlparse(auth_url)
        hostname = parsed_auth_url.hostname
        token_key = None
        if len(auth) == 2 and auth[0].lower() == "token":
            token_key = auth[1]
        if not token_key:
            return None
        try:
            from rtwo.drivers.common import _connect_to_openstack_sdk
        except ImportError:
            logger.exception(
                "Cannot use OpenstackTokenAuthentication without `rtwo`."
                " Please `pip install rtwo` and try again!")
            return None

        sdk_args = {
            'auth_url': auth_url.replace('5000', '35357'),
            'ex_force_base_url': auth_url.replace(":5000/v3", ":8774/v2/"),
            'identity_api_version': 3,
            'project_domain_name': domain_name,
            'region_name': region_name,
            'user_domain_name': domain_name,
            "auth_plugin": "token",
            "token": token_key
        }
        stack_sdk = _connect_to_openstack_sdk(**sdk_args)
        try:
            stack_sdk.authorize()
            whoami = stack_sdk.session.auth.auth_ref
            username = whoami.username
            new_profile = {
                'username': username,
                'firstName': username,
                'lastName': "",
                'email': "%s@%s" % (username, hostname),
            }
            logger.debug("Openstack Profile: %s", new_profile)
            user = get_or_create_user(new_profile['username'], new_profile)
            auth_token = get_or_create_token(
                user, token_key, issuer="OpenstackTokenAuthentication")
            return auth_token
        except:
            return None


class OAuthTokenAuthentication(TokenAuthentication):

    """
    OAuthTokenAuthentication:
    To authenticate, pass the token key in the "Authorization" HTTP header,
    prepend with the string "Token ". For example:
        Authorization: Token 098f6bcd4621d373cade4e832627b4f6
    """

    def _mock_oauth_login(self, oauth_token):
        username = settings.ALWAYS_AUTH_USER
        user = get_or_create_user(username, {
            'firstName': "Mocky Mock",
            'lastName': "MockDoodle",
            'email': '%s@iplantcollaborative.org' % settings.ALWAYS_AUTH_USER,
            })
        _, token = self.model.objects.get_or_create(key=oauth_token, user=user)
        return user, token

    def authenticate(self, request):
        all_backends = settings.AUTHENTICATION_BACKENDS
        auth = request.META.get('HTTP_AUTHORIZATION', '').split()
        if len(auth) == 2 and auth[0].lower() == "token":
            oauth_token = auth[1]
            if 'django_cyverse_auth.authBackends.MockLoginBackend' in all_backends:
                user, token = self._mock_oauth_login(oauth_token)
                return (user, token)
            if validate_oauth_token(oauth_token):
                try:
                    token = self.model.objects.get(key=oauth_token)
                except self.model.DoesNotExist:
                    return None
                if token and token.user.is_active:
                    return (token.user, token)
        return None


def validate_oauth_token(token, request=None):
    """
    Validates the token attached to the request (SessionStorage, GET/POST)
    On every request, ask OAuth to authorize the token
    """
    # Attempt to contact CAS
    try:
        user_profile = cas_profile_for_token(token)
    except ConnectionError:
        logger.exception("CAS could not be reached!")
        user_profile = None

    if not user_profile:
        return False
    username = user_profile.get("username")
    if not username:
        logger.warn("Invalid Profile:%s does not have username/attributes"
                    % user_profile)
        return False

    username = username.lower()
    new_profile = {
        'username': username,
        'firstName': user_profile['firstName'],
        'lastName': user_profile['lastName'],
        'email': user_profile['email']
    }
    user = get_or_create_user(new_profile['username'], new_profile)
    auth_token = get_or_create_token(
        user, token, issuer="OAuthTokenAuthentication")
    return auth_token


def validate_token(token):
    if not token:
        return False
    try:
        auth_token = AuthToken.objects.get(key=token)
        user = auth_token.user
    except AuthToken.DoesNotExist:
        all_backends = settings.AUTHENTICATION_BACKENDS
        if 'django_cyverse_auth.authBackends.MockLoginBackend' in all_backends:
            logger.info(
                "IGNORED -- AuthToken Retrieved:%s Does not exist. "
                "-- Validate anyway (Mock enabled)" % (token,))
            mock_user, _ = User.objects.get_or_create(
                username=settings.ALWAYS_AUTH_USER)
            auth_token, _ = AuthToken.objects.get_or_create(key=token, user=mock_user)
            return True
        logger.info("AuthToken Retrieved:%s Does not exist." % (token,))
        return False
    if auth_token.is_expired():
	logger.info("Token %s expired, User %s "
		    "could not be reauthenticated in CAS"
		    % (token, user))
	return False
    else:
        return True
