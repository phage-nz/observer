#!/usr/bin/python3

from .geo_utils import is_of_interest, get_home_name, resolve_asn
from .log_utils import get_module_logger
from .string_utils import double_url_encode, defang_url, get_host_from_url, is_valid_url
from django.utils import timezone
from web.models import Feed, Organisation, Host, Domain, Compromise, CountryHit

import iptools
import json
import jsonpickle
import requests
import validators

logger = get_module_logger(__name__)

def process_feed(feed_object, feed_name=None, feed_url=None):
    entry_list = []

    organisation_list = Organisation.objects.all()

    if type(feed_object) is Feed:
        response_items = feed_object

    for organisation in organisation_list:
        logger.info('Checking for {0} items...'.format(organisation.name))

        domain_list = Domain.objects.filter(organisation=organisation)
        host_list = Host.objects.filter(organisation=organisation)

        response_items = []

        for item in response_items:
            if not type(item) is str:
                item = str(item.o_value)
                feed_name = item.ref_name
                feed_url = item.ref_url

            for domain in domain_list:
                if domain.domain in item:
                    logger.info('Found compromise for domain: {0}'.format(domain.domain))

                    compromise_item = defang_url(item)
                    compromise_string = 'OSINT: {0}'.format(compromise_item)

                    if not Compromise.objects.filter(domain=domain, description=compromise_string).exists():
                        new_entry = Compromise(added=timezone.now(), category='MalwareHosting', domain=domain, description=compromise_string, sourcename=feed_name, sourceurl=feed_url, organisation=organisation)
                        entry_list.append(new_entry)

            for host in host_list:
                if host.address in item:
                    logger.info('Found compromise for host: {0}'.format(host.address))

                    compromise_item = defang_url(item)
                    compromise_string = 'OSINT: {0}'.format(compromise_item)

                    if not Compromise.objects.filter(host=host, description=compromise_string).exists():
                        new_entry = Compromise(added=timezone.now(), category='MalwareCommunication', host=host, description=compromise_string, sourcename=feed_name, sourceurl=feed_url, organisation=organisation)
                        entry_list.append(new_entry)

    if len(entry_list) > 0:
        logger.info('Saving items...')
        Compromise.objects.bulk_create(entry_list)

    else:
        logger.info('There are no new items to save.')

    entry_list = []
    country = get_home_name()

    logger.info('Checking for {0} items...'.format(country))

    for item in response_items:
        if not type(item) is str:
            item = str(item.o_value)
            feed_name = item.ref_name
            feed_url = item.ref_url

        if is_of_interest(item):
            if iptools.ipv4.validate_ip(item):
                entity = item
                logger.info('Found compromise for host: {0}'.format(entity))
                category = 'MalwareCommunication'

            elif iptools.ipv4.validate_cidr(item):
                entity = item
                logger.info('Found compromise for block: {0}'.format(entity))
                category = 'MalwareCommunication'

            elif is_valid_url(item):
                entity = get_host_from_url(item)
                logger.info('Found compromise for domain: {0}'.format(entity))
                category = 'MalwareHosting'

            # Only store IP's and URL's for now.
            else:
                continue

            compromise_item = defang_url(item)

            if not CountryHit.objects.filter(observable=compromise_item).exists():
                host_asn = resolve_asn(entity)

                new_entry = CountryHit(added=timezone.now(), category=category, entity=entity, asn=host_asn, observable=compromise_item, sourcename=feed_name, sourceurl=feed_url, country=country)
                entry_list.append(new_entry)

    if len(entry_list) > 0:
        logger.info('Saving items...')
        CountryHit.objects.bulk_create(entry_list)

    else:
        logger.info('There are no new items to save.')


def check_feeds():
    logger.info('Updating all feed data...')

    for feed in Feed.objects.all():
        feed_url = feed.url
        logger.info('Querying {0}...'.format(feed.name))

        response = requests.get(feed_url)

        if response.status_code == 200:
            process_feed(response.text.splitlines(), feed.name, feed.url)

        else:
            logger.error('Failed to query {0}.'.format(feed.name))
            logger.error(response.text)
            return False
