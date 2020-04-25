# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token


class Organisation(models.Model):
    added = models.DateTimeField(verbose_name=u'Date Added')
    name = models.CharField(max_length=32, verbose_name=u'Customer Name')
    contact = models.CharField(max_length=64, verbose_name=u'Customer Contact')
    domains = ArrayField(models.CharField(max_length=64), verbose_name=u'Domains')
    addresses = ArrayField(models.CharField(max_length=64), verbose_name=u'IP Addresses')
    emails = ArrayField(models.CharField(max_length=64), verbose_name=u'Email Addresses', blank=True, null=True)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return self.name


class Host(models.Model):
    added = models.DateTimeField(verbose_name=u'Date Added')
    lastscanned = models.DateTimeField(verbose_name=u'Last Scanned', blank=True, null=True)
    address = models.CharField(max_length=18, verbose_name=u'IP Address')
    torrentdetected = models.BooleanField(default=False, verbose_name=u'Torrenting Detected')
    organisation = models.ForeignKey('Organisation', on_delete=models.CASCADE)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return '{0} ({1})'.format(self.address, self.organisation)


class Domain(models.Model):
    added = models.DateTimeField(verbose_name=u'Date Added')
    lastscanned = models.DateTimeField(verbose_name=u'Last Scanned', blank=True, null=True)
    domain = models.CharField(max_length=64, verbose_name=u'Domain')
    organisation = models.ForeignKey('Organisation', on_delete=models.CASCADE)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return '{0} ({1})'.format(self.domain, self.organisation)


class Email(models.Model):
    added = models.DateTimeField(verbose_name=u'Date Added')
    lastscanned = models.DateTimeField(verbose_name=u'Last Scanned', blank=True, null=True)
    email = models.CharField(max_length=64, verbose_name=u'Email Address')
    organisation = models.ForeignKey('Organisation', on_delete=models.CASCADE)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return '{0} ({1})'.format(self.email, self.organisation)


class Compromise(models.Model):
    AccountCompromise = 'AccountCompromise'
    MalwareHosting = 'MalwareHosting'
    MalwareCommunication = 'MalwareCommunication'

    categories = (
        (AccountCompromise, 'AccountCompromise'),
        (MalwareHosting, 'MalwareHosting'),
        (MalwareCommunication, 'MalwareCommunication'),
    )

    added = models.DateTimeField(verbose_name=u'Date Added')
    category = models.CharField(
        max_length=32,
        choices=categories,
        verbose_name=u'Category')
    host = models.ForeignKey('Host', on_delete=models.CASCADE, blank=True, null=True)
    domain = models.ForeignKey('Domain', on_delete=models.CASCADE, blank=True, null=True)
    email = models.ForeignKey('Email', on_delete=models.CASCADE, blank=True, null=True)
    description = models.CharField(max_length=2048, verbose_name=u'Description')
    sourcename = models.CharField(max_length=64, verbose_name=u'Source Name')
    sourceurl = models.CharField(max_length=256, verbose_name=u'Source URL')
    organisation = models.ForeignKey('Organisation', on_delete=models.CASCADE)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return '{0} - {1}'.format(self.organisation, self.description)


class SensorHit(models.Model):
    added = models.DateTimeField(verbose_name=u'Date Added')
    host = models.ForeignKey('Host', on_delete=models.CASCADE)
    targetprotocol = models.CharField(max_length=4, verbose_name=u'Target Protocol')
    targetport = models.CharField(max_length=5, verbose_name=u'Target Port')
    payload = models.TextField(verbose_name=u'Payload')
    tags = ArrayField(models.CharField(max_length=16), verbose_name=u'Tags')
    organisation = models.ForeignKey('Organisation', on_delete=models.CASCADE)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return '{0} (Target: {1} {2})'.format(self.host, self.targetprotocol, self.targetport)


class CountryHit(models.Model):
    MalwareHosting = 'MalwareHosting'
    MalwareCommunication = 'MalwareCommunication'

    categories = (
        (MalwareHosting, 'MalwareHosting'),
        (MalwareCommunication, 'MalwareCommunication'),
    )

    added = models.DateTimeField(verbose_name=u'Date Added')
    category = models.CharField(
        max_length=32,
        choices=categories,
        verbose_name=u'Category')
    entity = models.CharField(max_length=64, verbose_name=u'Entity')
    observable = models.CharField(max_length=2048, verbose_name=u'Observable')
    sourcename = models.CharField(max_length=64, verbose_name=u'Source Name')
    sourceurl = models.CharField(max_length=256, verbose_name=u'Source URL')
    country = models.CharField(max_length=64, verbose_name=u'Country')
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return '{0} - {1}'.format(self.country, self.observable)


class OpenPort(models.Model):
    host = models.ForeignKey('Host', on_delete=models.CASCADE)
    port = models.CharField(max_length=5, verbose_name=u'Port')
    service = models.CharField(max_length=64, verbose_name=u'Service', blank=True, null=True)
    banner = models.TextField(verbose_name=u'Banner', blank=True, null=True)
    cve = ArrayField(models.CharField(max_length=32), verbose_name=u'Vulnerabilities', blank=True, null=True)
    organisation = models.ForeignKey('Organisation', on_delete=models.CASCADE)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return '{0}:{1}'.format(self.host, self.port)


class PortCVE(models.Model):
    cve = models.CharField(max_length=16, verbose_name=u'CVE')
    cvss = models.CharField(max_length=4, verbose_name=u'CVSS')
    host = models.ForeignKey('Host', on_delete=models.CASCADE)
    port = models.ForeignKey('OpenPort', on_delete=models.CASCADE)
    organisation = models.ForeignKey('Organisation', on_delete=models.CASCADE)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return '{0}: {1}'.format(self.cve, self.port)


class Paste(models.Model):
    added = models.DateTimeField(verbose_name=u'Date Added')
    title = models.CharField(max_length=64, verbose_name=u'Title')
    body = models.TextField(verbose_name=u'Body')
    key = models.CharField(max_length=32, verbose_name=u'Key')
    matches = ArrayField(models.CharField(max_length=256), verbose_name=u'Matches')
    url = models.CharField(max_length=1024, verbose_name=u'URL')
    organisation = models.ForeignKey('Organisation', on_delete=models.CASCADE)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return '{0}: {1}'.format(self.organisation, self.title)


class Feed(models.Model):
    name = models.CharField(max_length=64, verbose_name=u'Name')
    url = models.CharField(max_length=64, verbose_name=u'URL')
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return self.name


class Setting(models.Model):
    name = models.CharField(max_length=64, verbose_name=u'Name')
    value1 = models.CharField(max_length=256, verbose_name=u'Value 1')
    value2 = models.CharField(max_length=256, verbose_name=u'Value 2', blank=True, null=True)
    notes = models.TextField(verbose_name=u'Notes', blank=True, null=True)

    def __str__(self):
        return self.name


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
