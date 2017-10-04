"""
iPlant authentication models..
"""
from datetime import timedelta
import hashlib
import uuid

import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models, transaction
from django.db import IntegrityError
from django.utils import timezone

from .settings import auth_settings

logger = logging.getLogger(__name__)
AUTH_USER_MODEL = getattr(settings, "AUTH_USER_MODEL", 'auth.User')


def only_current(now_time=None):
    """
    Filter in range using expireTime
    """
    if not now_time:
        now_time = timezone.now()
    return models.Q(expireTime=None) | models.Q(expireTime__gt=now_time)

class AccessToken(models.Model):
    """
    AccessTokens are long running tokens
    at most ONE access token should be active per issuer
    """
    key = models.CharField(max_length=255, primary_key=True)
    issuer = models.TextField(null=True, blank=True)
    expireTime = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(AccessToken, self).save(*args, **kwargs)

    def generate_key(self):
        unique = str(uuid.uuid4())
        hashed_val = hashlib.md5(unique).hexdigest()
        return hashed_val

    def get_expired_time(self):
        if not self.expireTime:
            return None
        return self.expireTime.strftime("%b %d, %Y %H:%M:%S")

    def is_expired(self, now_time=None):
        """
        Returns True if token has expired, False if token is valid
        """
        if not now_time:
            now_time = timezone.now()
        return self.expireTime is not None\
            and self.expireTime <= now_time

    def __unicode__(self):
        return "%s" % (self.key)


class Token(models.Model):

    """
    AuthTokens are issued (or reused if existing)
    each time a user asks for a token using CloudAuth
    """
    key = models.CharField(max_length=255, primary_key=True)
    user = models.ForeignKey(AUTH_USER_MODEL, related_name='auth_tokens')
    api_server_url = models.CharField(max_length=255, null=True, blank=True)
    remote_ip = models.CharField(max_length=128, null=True, blank=True)
    issuer = models.TextField(null=True, blank=True)
    issuedTime = models.DateTimeField(auto_now_add=True)
    expireTime = models.DateTimeField(null=True, blank=True)

    def get_expired_time(self):
        return self.expireTime.strftime("%b %d, %Y %H:%M:%S")

    def is_expired(self, now_time=None):
        """
        Returns True if token has expired, False if token is valid
        """
        if not now_time:
            now_time = timezone.now()
        return self.expireTime is not None\
            and self.expireTime <= now_time

    @staticmethod
    def update_expiration(token_expiration=None):
        """
        Updates expiration by pre-determined amount.. Does not call save.
        """
        if not token_expiration:
            token_expiration = timezone.now() + auth_settings.TOKEN_EXPIRY_TIME
        return token_expiration

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(Token, self).save(*args, **kwargs)

    def generate_key(self):
        unique = str(uuid.uuid4())
        hashed_val = hashlib.md5(unique).hexdigest()
        return hashed_val

    def __unicode__(self):
        return "%s" % (self.key)



class UserProxy(models.Model):

    """
      The UserProxy model
      Maps username+proxyIOU (Returned on serviceValidate+proxy)
      to proxyIOU+proxyTicket(sent to the proxy URL)
    """
    username = models.CharField(max_length=128, blank=True, null=True)
    proxyIOU = models.CharField(max_length=128)
    proxyTicket = models.CharField(max_length=128)
    expiresOn = models.DateTimeField(blank=True, null=True)

    def __unicode__(self):
        return "%s CAS_Proxy" % self.username

    class Meta:
        verbose_name_plural = 'user proxies'


def get_access_token(issuer):
    try:
        token = AccessToken.objects.get(only_current(), issuer=issuer)
        return token
    except AccessToken.DoesNotExist:
        return None


def create_access_token(token_key, token_expire, issuer):
    """
    Generate a Token based on current username
    (And token_key, expiration, issuer.. If available)
    """
    access_token, _ = AccessToken.objects.get_or_create(
        key=token_key, issuer=issuer, expireTime=token_expire)
    return access_token


def get_or_create_token(user, token_key=None, token_expire=None, remote_ip=None, issuer=None):
    """
    Generate a Token based on current username
    (And token_key, expiration, issuer.. If available)
    """
    token_expire = Token.update_expiration(token_expire)
    defaults = {
        "api_server_url": auth_settings.API_SERVER_URL
    }
    if issuer:
        defaults["issuer"] = issuer
    if token_expire:
        defaults["expireTime"] = token_expire
    if remote_ip:
        defaults["remote_ip"] = remote_ip
    auth_user_token, created = Token.objects.update_or_create(
        key=token_key, user=user, defaults=defaults)
    token_key = auth_user_token.key
    logger.info(
        "%s token - %s" ,
        "Created" if created else "Retrieved",
        token_key)
    return auth_user_token


def get_or_create_user(username=None, attributes=None):
    if not attributes:
        attributes = {}
    User = get_user_model()
    defaults = {}
    if attributes.get('firstName'):
        defaults['first_name'] = attributes.get('firstName')
    if attributes.get('lastName'):
        defaults['last_name'] = attributes.get('lastName')
    if attributes.get('email'):
        defaults['email'] = attributes.get('email')
    user, created =  User.objects.update_or_create(
        username=username,
        defaults=defaults)
    logger.info(
        "%s User - %s" ,
        "Created" if created else "Retrieved",
        username)
    return user


def lookupSessionToken(request):
    """
    Retrieve an existing token from the request session.
    """
    token_key = request.session['token']
    try:
        token = Token.objects.get(user=request.user, key=token_key)
        if token.is_expired():
            return None
        return token
    except:
        return None


def validateToken(username, token_key):
    """
    Verify the token belongs to username, and renew it
    """
    auth_user_token = Token.objects.filter(
        user__username=username, key=token_key)
    if not auth_user_token:
        return None
    auth_user_token = auth_user_token[0]
    auth_user_token.expireTime = Token.update_expiration()
    auth_user_token.save()
    return auth_user_token


def userCanEmulate(username):
    """
    Django users marked as 'staff' have emulate permission
    Additional checks can be added later..
    """
    User = get_user_model()
    try:
        user = User.objects.get(username=username)
        return user.is_staff
    except User.DoesNotExist:
        return False
