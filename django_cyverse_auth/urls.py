# -*- coding: utf-8 -*-
"""
Routes for authentication services
"""
from django.conf.urls import url
from django_cyverse_auth import views
from django_cyverse_auth.protocol.cas import (
        cas_loginRedirect, cas_validateTicket,
        cas_proxyCallback, cas_storeProxyIOU_ID,
        saml_validateTicket
    )
urlpatterns = [
    url(r'^o_login$', views.o_login_redirect),
    # OAuth Authentication Section:
    url(r'^oauth2.0/callbackAuthorize$', views.o_callback_authorize),
    # GLOBUS Authentication Section:
    url(r'^globus_login$', views.globus_login_redirect),

    # CAS Authentication Section:
    #   CAS +OAuth: see 'OAuth Authentication Section'
    #   CAS+SSO:
    url(r'^CASlogin/(?P<redirect>.*)$', cas_loginRedirect),
    url(r'^CAS_serviceValidater',
        cas_validateTicket,
        name='cas-service-validate-link'),
    #   CAS+SSO (+ProxyTicket):
    url(r'^CAS_proxyCallback',
        cas_proxyCallback,
        name='cas-proxy-callback-link'),
    url(r'^CAS_proxyUrl',
        cas_storeProxyIOU_ID,
        name='cas-proxy-url-link'),
    # CAS + SAML Validation
    url(r'^s_serviceValidater$',
        saml_validateTicket,
        name="saml-service-validate-link")
]
