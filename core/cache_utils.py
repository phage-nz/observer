#!/usr/bin/python3

from .log_utils import get_module_logger
from web.models import Organisation, Paste
from django.core.cache import cache
from django.utils import timezone
from itertools import chain

import os

logger = get_module_logger(__name__)

CACHE_SECONDS = 14400

def rebuild_paste_cache():
    try:
        logger.info('Rebuilding paste cache...')

        cache.delete_pattern('paste_*')

        historic_pastes = list(Paste.objects.all().values_list('key', flat=True))

        for key in historic_pastes:
            if not is_cached_paste(key):
                cache.set('paste_{0}'.format(key), timezone.now(), CACHE_SECONDS)

        logger.info('Cache rebuild complete!')

    except Exception as e:
        logger.error('Failed to rebuild cache: {0}'.format(str(e)))


def rebuild_paste_string_cache():
    try:
        logger.info('Rebuilding paste string cache...')

        cache.delete('paste_strings')

        address_list = list(Organisation.objects.all().values_list('addresses',flat=True))
        monitored_addresses = list(chain(*address_list))
        domain_list = list(Organisation.objects.all().values_list('domains', flat=True))
        monitored_domains = list(chain(*domain_list))
        email_list = list(Organisation.objects.all().values_list('emails', flat=True))
        monitored_emails = list(chain(*email_list))

        monitored_list = []
        monitored_list.extend(monitored_addresses)
        monitored_list.extend(monitored_domains)
        monitored_list.extend(monitored_emails)

        logger.info('Setting cache value: {0}'.format(monitored_list))

        cache.set('paste_strings', monitored_list, CACHE_SECONDS)

        logger.info('Cache rebuild complete!')

    except Exception as e:
        logger.error('Failed to rebuild cache: {0}'.format(str(e)))


def is_cached_paste(key):
    if cache.get('paste_{0}'.format(key)) is None:
        return False

    return True


def add_to_paste_cache(key):
    try:
        logger.info('Adding paste to cache: {0}'.format(key))

        cache.set(
            'paste_{0}'.format(key),
            timezone.now(),
            CACHE_SECONDS)

    except Exception as e:
        logger.error('Failed to set cache item: {0}'.format(str(e)))


def get_paste_strings():
    paste_strings = cache.get('paste_strings')

    if paste_strings is not None:
        return paste_strings

    return []


def get_keyword_organisation(keyword):
    try:
        logger.info('Resolving organisation for keyword: {0}'.format(keyword))

        address_match = Organisation.objects.filter(addresses__contains=[keyword])

        if address_match.exists():
            return address_match.first()

        domain_match = Organisation.objects.filter(domains__contains=[keyword])

        if domain_match.exists():
            return domain_match.first()

        email_match = Organisation.objects.filter(emails__contains=[keyword])

        if email_match.exists():
            return email_match.first()

        else:
            logger.error('Problem resolving organisation for match: {0}'.format(keyword))
            return None

    except Exception as e:
        logger.error('Problem resolving organisation {0}'.format(str(e)))


def get_cached_dns(hostname):
    return cache.get('dns_{0}'.format(hostname))


def add_to_dns_cache(hostname, ip_addr):
    try:
        logger.info('Adding to DNS cache: {0} ({1})'.format(hostname, ip_addr))

        cache.set('dns_{0}'.format(hostname), ip_addr, CACHE_SECONDS)

    except Exception as e:
        logger.warning('Failed to set cache item: {0}'.format(str(e)))
