#!/usr/bin/python3

# cfscrape requires NodeJS for JS challenge bypass:
# apt install nodejs
from .feed_utils import process_feed
from .geo_utils import get_home_name
from .log_utils import get_module_logger
from .string_utils import clean_url
from cfscrape import create_scraper
from collections import Counter
from datetime import datetime, timedelta
from web.models import Setting

import iocextract
import json
import os
import re
import requests
import time
import tweepy
import validators

logger = get_module_logger(__name__)

CONSUMER_KEY = Setting.objects.get(name='Twitter Consumer Key').value1
CONSUMER_SECRET = Setting.objects.get(name='Twitter Consumer Secret').value1
ACCESS_TOKEN = Setting.objects.get(name='Twitter Access Token').value1
ACCESS_TOKEN_SECRET = Setting.objects.get(name='Twitter Access Token Secret').value1

MINUTES_BACK = 360
MAX_SEARCH_ITEMS = 60
MAX_USER_ITEMS = 20
THROTTLE_REQUESTS = False

USERNAME_LIST = Setting.objects.get(name='Twitter Username List').value1.split(',')
SEARCH_LIST = Setting.objects.get(name='Twitter Search List').value1.split(',')

URL_BLACKLIST = ['//t.co/', 'abuse.ch', 'app.any.run', 'otx.alienvault.com', 'proofpoint.com', 'twitter.com', 'virustotal.com']
IP_BLACKLIST = ['127.0.0.1', '127.0.1.1']

SCRAPER_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.89 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded'
}

CF_SCRAPER = create_scraper()

class TwitterObservable:
  def __init__(self, ref_name, ref_url, o_type, o_value):
    self.ref_name = ref_name
    self.ref_url = ref_url
    self.o_type = o_type
    self.o_value = o_value


def get_api():
    auth = tweepy.auth.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
    auth.set_access_token(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)

    return tweepy.API(auth, wait_on_rate_limit=THROTTLE_REQUESTS)


def get_pastebin_paste(url):
    try:
        paste_search = re.search(r'https://pastebin.com/([a-zA-Z0-9]{8})', url)
        raw_search = re.search(r'https://pastebin.com/raw/([a-zA-Z0-9]{8})', url)

        if paste_search:
            paste_id = paste_search.group(1)
            raw_url = 'https://pastebin.com/raw/{0}'.format(paste_id)

        elif raw_search:
            paste_id = raw_search.group(1)
            raw_url = url

        else:
            logger.warning('Failed to construct raw PasteBin URL from: {0}'.format(url))
            return None

        logger.info('Requesting PasteBin paste with ID: {0}'.format(paste_id))

        paste_request = requests.get(raw_url)

        if paste_request.status_code == 200:
            return paste_request.content

        else:
            logger.warning('Failed to request PasteBin. Status: {0}'.format(paste_request.status_code))

    except Exception as e:
        logger.error('Failed to query PasteBin: {0}'.format(e))

    return None


def get_ghostbin_paste(url):
    try:
        paste_search = re.search(r'https://ghostbin.com/paste/([a-zA-Z0-9]{5})', url)

        if paste_search:
            paste_id = paste_search.group(1)
            raw_url = 'https://ghostbin.com/paste/{0}/raw'.format(paste_id)

            # Delay enforced by CloudFlare.
            logger.info('Requesting GhostBin paste with ID: {0} (this will take a moment)'.format(paste_id))

            paste_request = CF_SCRAPER.get(raw_url, headers=SCRAPER_HEADERS)

            if paste_request.status_code == 200:
                return paste_request.content

            else:
                logger.warning('Failed to request GhostBin. Status: {0}'.format(paste_request.status_code))

        else:
            logger.warning('Failed to construct raw GhostBin URL from: {0}'.format(url))

    except Exception as e:
        logger.error('Failed to query GhostBin: {0}'.format(e))

    return None

def validate_ip(ip):
    if any(s in ip for s in IP_BLACKLIST):
        return False

    return validators.ipv4(ip)


def validate_url(url):
    if any(s in url for s in URL_BLACKLIST):
        return False

    # iocextract can incorrectly match on http://123.123:123
    if re.search(r'http://[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}', url):
        return False

    return validators.url(url)


def extract_paste_observables(username, url):
    if 'pastebin.com' in url:
        paste_text = get_pastebin_paste(url)

        logger.info('Waiting a moment...')
        time.sleep(1)

        if paste_text != None:
            paste_observables = extract_text_obserables(username, paste_text.decode('utf-8'))

            if len(paste_observables) > 0:
                return paste_observables

    elif 'ghostbin.com' in url:
        paste_text = get_ghostbin_paste(url)

        logger.info('Waiting a moment...')
        time.sleep(1)

        if paste_text != None:
            paste_observables = extract_text_obserables(username, paste_text.decode('utf-8'))

            if len(paste_observables) > 0:
                return paste_observables

    return []


def extract_text_obserables(username, text):
    observable_list = []

    user_id = '@{0}'.format(username)
    user_url = 'https://twitter.com/{0}'.format(username)

    try:
        for ip in iocextract.extract_ips(text, refang=True):
            if validate_ip(ip):
                observable_list.append(TwitterObservable(user_id, user_url, 'ip', ip))

        for url in iocextract.extract_urls(text, refang=True):
            if 'ghostbin.com' in url or 'pastebin.com' in url:
                paste_observables = extract_paste_observables(username, url)

                if len(paste_observables) > 0:
                    observable_list.extend(paste_observables)

            elif validate_url(url):
                observable_list.append(TwitterObservable(user_id, user_url, 'url', clean_url(url)))

    except Exception as e:
        logger.warning('Exception parsing text: {0}'.format(e))

    return observable_list


def parse_tweet(tweet):
    observable_list = []

    valid_since = datetime.utcnow() - timedelta(minutes=MINUTES_BACK)

    try:
        if (tweet.created_at > valid_since):
            screen_name = tweet.user.screen_name

            logger.info('Parsing Tweet: {0} (user: {1})'.format(tweet.id, screen_name))
            tweet_observables = extract_text_obserables(screen_name, tweet.text)

            if len(tweet_observables) > 0:
                observable_list.extend(tweet_observables)

            for url in tweet.entities['urls']:
                expanded_url = url['expanded_url']

                if 'ghostbin.com' in expanded_url or 'pastebin.com' in expanded_url:
                    paste_observables = extract_paste_observables(screen_name, expanded_url)

                    if len(paste_observables) > 0:
                        observable_list.extend(paste_observables)

    except Exception as e:
        logger.error('Failed to query Twitter API: {0}'.format(e))

    return observable_list


def process_tweets(api):
    observable_list = []

    for username in USERNAME_LIST:
        logger.info('Processing Tweets for user: {0}...'.format(username))
        recent_tweets = tweepy.Cursor(api.user_timeline, id=username).items(MAX_USER_ITEMS)

        for recent_tweet in recent_tweets:
            tweet_observables = parse_tweet(recent_tweet)

            if len(tweet_observables) > 0:
                observable_list.extend(tweet_observables)

    for search in SEARCH_LIST:
        logger.info('Processing Tweets for search: "{0}"...'.format(search))
        recent_tweets = tweepy.Cursor(api.search, q=search).items(MAX_SEARCH_ITEMS)

        for recent_tweet in recent_tweets:
            tweet_observables = parse_tweet(recent_tweet)

            if len(tweet_observables) > 0:
                observable_list.extend(tweet_observables)

    return observable_list


def check_twitter():
    api = get_api()

    observable_list = process_tweets(api)

    logger.info('Tweets harvested. Processing collected observables...')

    if len(observable_list) > 0:
        process_feed(observable_list)

    else:
        logger.warning('Twitter observable list is empty.')
