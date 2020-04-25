#!/usr/bin/python3

from .cache_utils import rebuild_paste_cache, rebuild_paste_string_cache
from .binaryedge_utils import update_host_ports, update_honeypot_activity, update_torrent_status, update_domain_leaks, update_email_leaks, find_c2_hosts
from .feed_utils import check_feeds
from .log_utils import get_module_logger
from .shodan_utils import get_shodan_scan_data
from .twitter_utils import check_twitter
from .urlscan_utils import check_urlscan, find_bad_refs
from .virustotal_utils import update_vt_ip_activity, update_vt_domain_activity, enrich_country_hosts
from django.contrib.auth.models import Group, Permission
from django.utils import timezone
from web.models import Host, Domain, Email, Organisation, OpenPort, Setting

import time

logger = get_module_logger(__name__)

def process_host(host, is_weekly):
    logger.info('Processing host: {0}'.format(host.address))

    Host.objects.filter(pk=host.pk).update(lastscanned=timezone.now())

    get_shodan_scan_data(host)
    update_vt_ip_activity(host)

    if is_weekly:
        logger.info('Clearing historic port data...')
        Host.objects.filter(pk=host.pk).update(lastscanned=timezone.now(),torrentdetected=False)
        OpenPort.objects.filter(host=host).delete()
        logger.info('Done.')

        update_host_ports(host)
        update_honeypot_activity(host)
        update_torrent_status(host)

    logger.info('Host complete.')


def process_domain(domain, is_weekly):
    logger.info('Processing domain: {0}'.format(domain.domain))

    Domain.objects.filter(pk=domain.pk).update(lastscanned=timezone.now())

    find_bad_refs(domain)
    update_vt_domain_activity(domain)

    if is_weekly:
        update_domain_leaks(domain)

    logger.info('Domain complete.')


def process_email(email):
    logger.info('Processing email: {0}'.format(email.email))

    Email.objects.filter(pk=email.pk).update(lastscanned=timezone.now())

    update_email_leaks(email)

    logger.info('Email complete.')

def apply_group_permissions(group):
    permission_list = ['Can view compromise', 'Can view country hit', 'Can view domain', 'Can view email', 'Can view host', 'Can view open port', 'Can view organisation', 'Can view paste', 'Can view port cve', 'Can view sensor hit']

    for permission_name in permission_list:
        logger.info('Providing {0} permission: {1}'.format(group.name, permission_name))

        permission = Permission.objects.get(name=permission_name)
        group.permissions.add(permission)


def check_orgs():
    group_list = list(Group.objects.all().values_list('name', flat=True))

    for org in Organisation.objects.all():
        if not org.name in group_list:
            logger.info('Loading new organisation: {0}'.format(org.name))

            new_group, created = Group.objects.get_or_create(name=org.name)

            if created:
                apply_group_permissions(new_group)

                logger.info('Organisation group created. Loading initial data...')

                weekly_operations(org)


def refresh_entities(organisation):
    logger.info('Refreshing entity data...')

    for address in organisation.addresses:
        if not Host.objects.filter(address=address).exists():
            logger.info('Adding new host: {0}'.format(address))
            new_host = Host(added=timezone.now(), address=address, organisation=organisation)
            new_host.save()

    for address in Host.objects.filter(organisation=organisation):
        if not Organisation.objects.filter(addresses__contains=[address.address]):
            logger.info('Removing old host: {0}'.format(address.address))
            address.delete()

    for domain in organisation.domains:
        if not Domain.objects.filter(domain=domain).exists():
            logger.info('Adding new domain: {0}'.format(domain))
            new_domain = Domain(added=timezone.now(), domain=domain, organisation=organisation)
            new_domain.save()

    for domain in Domain.objects.filter(organisation=organisation):
        if not Organisation.objects.filter(domains__contains=[domain.domain]):
            logger.info('Removing old domain: {0}'.format(domain.domain))
            domain.delete()

    for email in organisation.emails:
        if not Email.objects.filter(email=email).exists():
            logger.info('Adding new email: {0}'.format(email))
            new_email = Email(added=timezone.now(), email=email, organisation=organisation)
            new_email.save()

    for email in Email.objects.filter(organisation=organisation):
        if not Organisation.objects.filter(emails__contains=[email.email]):
            logger.info('Removing old email: {0}'.format(email.email))
            email.delete()

    logger.info('Refresh complete.')


def do_country_operations():
    logger.info('Running country operations...')

    for organisation in Organisation.objects.all():
        refresh_entities(organisation)

    check_feeds()
    check_twitter()
    check_urlscan()
    enrich_country_hosts()
    find_c2_hosts()

    logger.info('Country operations complete.')


def organisation_operations(organisation, is_weekly):
    refresh_entities(organisation)

    for host in Host.objects.filter(organisation=organisation):
        process_host(host, is_weekly)

    for domain in Domain.objects.filter(organisation=organisation):
        process_domain(domain, is_weekly)

    if is_weekly:
        for email in Email.objects.filter(organisation=organisation):
            process_email(email)


def do_organisation_operations(is_weekly):
    logger.info('Running organisation operations...')

    for organisation in Organisation.objects.all():
        logger.info('Beginning organisation: {0}'.format(organisation.name))

        organisation_operations(organisation, is_weekly)

    logger.info('Organisation operations complete.')


def start_core():
    logger.info('Starting core worker...')

    run_times = Setting.objects.get(name='Core Run Times').value1.split(',')
    weekly_days = Setting.objects.get(name='Core Weekly Tasks Days').value1.split(',')

    logger.info('Daily tasks will run at: {0}'.format(str(run_times)))
    logger.info('Weekly tasks will run on {0} at: {1}'.format(str(weekly_days), str(run_times[0])))

    while True:
        if time.strftime('%H:%M') in run_times:
            do_country_operations()

            if time.strftime('%H:%M') == run_times[0] and time.strftime('%A').lower() in (day.lower() for day in weekly_days):
                do_organisation_operations(True)

            else:
                do_organisation_operations(False)

        time.sleep(60)

    logger.info('Core worker finished.')


def start_helper():
    logger.info('Starting helper...')

    rebuild_paste_cache()
    rebuild_paste_string_cache()

    while True:
        check_orgs()

        if time.strftime('%M') == '00':
            rebuild_paste_string_cache()

        time.sleep(60)

    logger.info('Helper finished.')
