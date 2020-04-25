#!/usr/bin/python3

from core.core_utils import process_host, refresh_entities, process_domain, process_email
from web.models import Host, Domain, Email, Organisation

ORG_NAME = 'ORG NAME HERE'

def run(*script_args):
    organisation = Organisation.objects.get(name=ORG_NAME)
    refresh_entities(organisation)

    for host in Host.objects.filter(organisation=organisation):
        process_host(host)

    for domain in Domain.objects.filter(organisation=organisation):
        process_domain(domain)

    for email in Email.objects.filter(organisation=organisation):
        process_email(email)
