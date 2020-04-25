#!/usr/bin/python3

from .log_utils import get_module_logger
from defang import defang

import random
import string
import urllib.parse

logger = get_module_logger(__name__)

def random_string(length):
    return ''.join(
        random.choice(
            string.ascii_uppercase +
            string.ascii_lowercase +
            string.digits) for i in range(length))


def double_url_encode(input):
    return urllib.parse.quote(urllib.parse.quote(input))

def defang_url(input):
    return defang(input)

def get_host_from_url(url):
    host_name = urllib.parse.urlparse(url).hostname

    if ':' in host_name:
        host_name = host_name.split(':')[0]

    return host_name

def get_path_from_url(url):
    return urllib.parse.urlparse(url).path

def is_valid_url(input):
    try:
        result = urllib.parse.urlparse(input)
        url_parts = all([result.scheme, result.netloc])
        return url_parts

    except Exception as e:
        logger.error('Error validating URL: {0}'.format(str(e)))

    return False

def clean_url(url):
    if url is None:
        return None

    if '??' in url:
        url = url.split('??')[0]

    if url.endswith('?'):
        url = url[:-1]

    if '`' in url:
        url = url.replace('`', '')

    return url
