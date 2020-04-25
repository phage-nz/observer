#!/usr/bin/python3

from .cache_utils import get_cached_dns, add_to_dns_cache
from .log_utils import get_module_logger

logger = get_module_logger(__name__)

import DNS
import validators

def forward_dns_lookup(host_name):
    try:
        ip_list = DNS.dnslookup(host_name, 'A')

        if len(ip_list) > 0:
            for ip_addr in ip_list:
                if validators.ipv4(ip_addr):
                    return ip_addr

    except BaseException:
        logger.warning('DNS lookup of {0} failed.'.format(host_name))
        return None

    return None


def resolve_dns(host):
    if validators.ipv4(host):
        return host

    cached_addr = get_cached_dns(host)

    if cached_addr:
        return cached_addr

    ip_addr = forward_dns_lookup(host)

    if ip_addr is not None:
        add_to_dns_cache(host, ip_addr)
        return ip_addr

    return False
