import requests
import json, os

from base64 import b64encode
from django.http import HttpResponse, HttpResponseRedirect
from django.utils import timezone

from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import Error as OAuthError

from iplantauth.models import (
    get_or_create_user, create_token,
    create_access_token, get_access_token)
from iplantauth.settings import auth_settings

import logging
logger = logging.getLogger(__name__)


def globus_initFlow():
    """
    Retrieve cached/Create a new access token
    and use it to create an OAuth2WebServerFlow
    """
    # Use client_id:client_secret for authorization
    userAndPass = "%s:%s" % (auth_settings.GLOBUS_OAUTH_ID, auth_settings.GLOBUS_OAUTH_SECRET)
    b64_userAndPass = b64encode(userAndPass)
    auth_header = "Basic %s" % b64_userAndPass
    flow = OAuth2WebServerFlow(
        client_id=auth_settings.GLOBUS_OAUTH_ID,
        scope=auth_settings.GLOBUS_OAUTH_ATMOSPHERE_SCOPE,
        authorization_header=auth_header,
        redirect_uri=auth_settings.OAUTH_CLIENT_CALLBACK,
        auth_uri=auth_settings.GLOBUS_AUTH_URL,
        token_uri=auth_settings.GLOBUS_TOKEN_URL)
    return flow

def globus_logout(redirect_uri):
    """
    Redirect to logout of globus
    """
    flow = globus_initFlow()
    auth_uri = flow.auth_uri
    web_logout_url = auth_uri.replace('oauth2/authorize', 'web/logout')
    web_logout_url += "?client_id=%s&redirect_name=%s&redirect_uri=%s"\
            % (flow.client_id, 'Jetstream', redirect_uri)
    logger.info(web_logout_url)
    return HttpResponseRedirect(web_logout_url)

def globus_authorize(request):
    """
    Redirect to the IdP based on 'flow'
    """
    flow = globus_initFlow()
    auth_uri = flow.step1_get_authorize_url()
    auth_uri += '&authentication_hint=xsede'
    auth_uri = auth_uri.replace('access_type=offline','access_type=online')
    logger.warn(auth_uri)
    return HttpResponseRedirect(auth_uri)

def globus_profile_for_token(globus_user_token):
    try:
        logger.info("Request Token Info for key %s" % globus_user_token)
        userAndPass = "%s:%s" % (auth_settings.GLOBUS_OAUTH_ID, auth_settings.GLOBUS_OAUTH_SECRET)
        b64_userAndPass = b64encode(userAndPass)
        auth_header = "Basic %s" % b64_userAndPass
        r = requests.post(
            auth_settings.GLOBUS_TOKENINFO_URL+'?include=effective', verify=False,
            data={'token':globus_user_token},
            headers={'Authorization':auth_header})
        j_data = r.json()
        logger.info(j_data)
        return j_data
    except:
        logger.exception("Error retrieving profile from globus")
        return None

def _extract_expiry_date(epoch_secs):
    if type(epoch_secs) != int:
        try:
            epoch_secs = int(date_int)
        except:
            logger.exception("Expected date to be an integer (Seconds from epoch). This method should be modified to the new use case for globus 'exp'")
            return None
    epoch = timezone.datetime(month=1, day=1, year=1970)
    return epoch + timezone.timedelta(seconds=epoch_secs)

def _extract_first_last_name(user_name):
    if ' ' not in user_name:
        return '', user_name
    split_name = user_name.split()
    return split_name[0], ' '.join(split_name[1:])

def _extract_user_from_email(raw_username):
    """
    Usernames come from the globus provider in the form:
    username@login_authority.com
    """
    if not raw_username:
        return None
    return raw_username.split('@')[0]

def _map_email_to_user(raw_username):
    """
    Input:  test@fake.com
    Output: test
    """
    if not auth_settings.GLOBUS_MAPPING_FILE:
        logger.info("GLOBUS_MAPPING_FILE NOT defined. Check your auth settings!!")
        return raw_username
    if not os.path.exists(auth_settings.GLOBUS_MAPPING_FILE):
        logger.warn("GLOBUS_MAPPING_FILE %s does not exist!" % auth_settings.GLOBUS_MAPPING_FILE)
        return None
    try:
        with open(auth_settings.GLOBUS_MAPPING_FILE) as the_file:
            text = the_file.read()
            user_mapping = json.loads(text)
    except:
        logger.warn("GLOBUS_MAPPING_FILE %s is NOT VALID JSON!" % auth_settings.GLOBUS_MAPPING_FILE)
        user_mapping = {}

    if raw_username not in user_mapping:
        return None
    username = user_mapping[raw_username]
    logger.info("GLOBUS_MAPPING_FILE identified %s -> %s" % (raw_username, username))
    return username


def globus_validate_code(request):
    """
    This flow is used to create a new Token on behalf of a Service Client
    (Like Troposphere)
    Validates 'code' returned from the IdP
    If valid: Return new AuthToken to be passed to the Resource Provider.
        else: Return None
    """
    code = request.GET['code']
    if not code:
        #raise Exception("NO Code found!")
        return None
    if type(code) == list:
        code = code[0]
    flow = globus_initFlow()
    try:
        credentials = flow.step2_exchange(code)
        logger.info(credentials.__dict__)
    except OAuthError as err:
        logger.exception("Error exchanging code w/ globus")
        return None
    # Parsing
    token_profile = credentials.id_token
    user_access_token = credentials.access_token
    expiry_date = credentials.token_expiry
    raw_username = token_profile['preferred_username']
    email = token_profile['email']
    username = _extract_user_from_email(raw_username)
    if not username:
        logger.info("User %s is not part of the 'valid mapping' and will be skipped!" % raw_username)
        return None
    full_name = token_profile['name']
    issuer = token_profile['iss']
    # Creation
    first_name, last_name = _extract_first_last_name(full_name)
    user_profile = {
        'username':username,
        'firstName':first_name,
        'lastName':last_name,
        'email': email,
    }
    user = get_or_create_user(username, user_profile)
    auth_token = create_token(username, user_access_token, expiry_date, issuer)
    return auth_token

def create_user_token_from_globus_profile(profile, access_token):
    """
    Use this method on your Resource Provider (Like Atmosphere)
    to exchange a profile (that was retrieved via a tokeninfo endpoint)
    for a UserToken that can then be internally validated in an 'authorize' authBackend step..
    """

    logger.info(profile)
    expiry = profile['exp'] # This is an 'epoch-int'
    expiry = _extract_expiry_date(expiry)
    issued_at = profile['iat']
    raw_username = profile['username']  # username@login_auth.com
    raw_name = profile['name']
    email = profile['email']
    username = _extract_user_from_email(raw_username)
    first_name, last_name = _extract_first_last_name(raw_name)
    profile_dict = {
        'username':username,
        'firstName':first_name,
        'lastName':last_name,
        'email': email,
    }
    user = get_or_create_user(username, profile_dict)
    user_token = create_token(user.username, access_token, expiry)
    return user_token

