# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('django_cyverse_auth', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accesstoken',
            name='key',
            field=models.CharField(max_length=255, serialize=False, primary_key=True),
        ),
        migrations.AlterField(
            model_name='token',
            name='api_server_url',
            field=models.CharField(max_length=255, null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='token',
            name='key',
            field=models.CharField(max_length=255, serialize=False, primary_key=True),
        ),
    ]
