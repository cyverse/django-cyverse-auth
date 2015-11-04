# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AccessToken',
            fields=[
                ('key', models.CharField(max_length=1024, serialize=False, primary_key=True)),
                ('issuer', models.TextField(null=True, blank=True)),
                ('expireTime', models.DateTimeField(null=True, blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='Token',
            fields=[
                ('key', models.CharField(max_length=1024, serialize=False, primary_key=True)),
                ('api_server_url', models.CharField(max_length=256, null=True, blank=True)),
                ('remote_ip', models.CharField(max_length=128, null=True, blank=True)),
                ('issuer', models.TextField(null=True, blank=True)),
                ('issuedTime', models.DateTimeField(auto_now_add=True)),
                ('expireTime', models.DateTimeField(null=True, blank=True)),
                ('user', models.ForeignKey(related_name='auth_tokens', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserProxy',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('username', models.CharField(max_length=128, null=True, blank=True)),
                ('proxyIOU', models.CharField(max_length=128)),
                ('proxyTicket', models.CharField(max_length=128)),
                ('expiresOn', models.DateTimeField(null=True, blank=True)),
            ],
            options={
                'verbose_name_plural': 'user proxies',
            },
        ),
    ]
