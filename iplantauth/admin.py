"""
Required for django admin site.
"""
from django.contrib import admin

from iplantauth.models import Token as AuthToken, UserProxy

admin.site.register(AuthToken)
admin.site.register(UserProxy)
