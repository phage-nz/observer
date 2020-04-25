#!/usr/bin/python3

from web.models import Setting

DAYS_TO_DISPLAY = '7'
RUN_TIMES = '06:00,18:00'
WEEKLY_TASKS_DAYS = 'Monday,Thursday'
VT_USER = 'YOUR VT USER'
VT_API_KEY = 'YOUR VT API KEY'
VT_REQ_MIN = 'VT REQUEST LIMIT'
BE_API_KEY = 'BINARYEDGE API KEY'
SHODAN_API_KEY = 'SHODAN API KEY'
TWITTER_CONSUMER_KEY = 'TWITTER CONSUMER KEY'
TWITTER_CONSUMER_SECRET = 'TWITTER CONSUMER SECRET'
TWITTER_ACCESS_TOKEN = 'TWITTER ACCESS TOKEN'
TWITTER_ACCESS_TOKEN_SECRET = 'TWITTER ACCESS TOKEN SECRET'
TWITTER_USERNAME_LIST = 'avman1995,bad_packets,Cryptolaemus1,CNMF_VirusAlert,dvk01uk,James_inthe_box,JAMESWT_MHT,Jan0fficial,JRoosen,pollo290987,ps66uk,malwrhunterteam,mesa_matt,Mesiagh,nao_sec,ScumBots,Racco42,shotgunner101,thlnk3r,TrackerEmotet,VK_Intel'
TWITTER_SEARCH_LIST = '#agenttesla,#apt28,#azorult,#banload,#brushaloader,#dridex,#emotet,#fin7,#formbook,#gandcrab,#gozi,#hancitor,#hawkeye,#icedid,#lokibot,#malspam,#nanocore,#nymaim,#ramnit,#remcos,#ryuk#ransomware,#shade#ransomware,#smokeloader,#trickbot,#troldesh,#ursnif'
MAXMIND_CITY_DB_PATH = '/opt/observer/data/GeoLite2-City.mmdb'
MAXMIND_ASN_DB_PATH = '/opt/observer/data/GeoLite2-ASN.mmdb'
HOME_COUNTRY_NAME = 'New Zealand'
HOME_COUNTRY_CODE = 'NZ'

def run(*script_args):
    print('Loading application settings...')

    settings_list = []

    if not Setting.objects.filter(name='Core Run Times').exists():
        print('"Core Run Times" not configured. Inserting...')
        settings_list.append(Setting(name='Core Run Times', value1=RUN_TIMES))

    if not Setting.objects.filter(name='Core Weekly Tasks Days').exists():
        print('"Core Weekly Tasks Days" not configured. Inserting...')
        settings_list.append(Setting(name='Core Weekly Tasks Days', value1=WEEKLY_TASKS_DAYS))

    if not Setting.objects.filter(name='Days to Display').exists():
        print('"Days to Display" not configured. Inserting...')
        settings_list.append(Setting(name='Days to Display', value1=DAYS_TO_DISPLAY))

    if not Setting.objects.filter(name='VirusTotal User').exists():
        print('"VirusTotal User" not configured. Inserting...')
        settings_list.append(Setting(name='VirusTotal User', value1=VT_USER))

    if not Setting.objects.filter(name='VirusTotal API Key').exists():
        print('"VirusTotal API Key" not configured. Inserting...')
        settings_list.append(Setting(name='VirusTotal API Key', value1=VT_API_KEY))

    if not Setting.objects.filter(name='VirusTotal Requests Per Minute').exists():
        print('"VirusTotal Requests Per Minute" not configured. Inserting...')
        settings_list.append(Setting(name='VirusTotal Requests Per Minute', value1=VT_REQ_MIN))

    if not Setting.objects.filter(name='BinaryEdge API Key').exists():
        print('"BinaryEdge API Key" not configured. Inserting...')
        settings_list.append(Setting(name='BinaryEdge API Key', value1=BE_API_KEY))

    if not Setting.objects.filter(name='Shodan API Key').exists():
        print('"Shodan API Key" not configured. Inserting...')
        settings_list.append(Setting(name='Shodan API Key', value1=SHODAN_API_KEY))

    if not Setting.objects.filter(name='Twitter Consumer Key').exists():
        print('"Twitter Consumer Key" not configured. Inserting...')
        settings_list.append(Setting(name='Twitter Consumer Key', value1=TWITTER_CONSUMER_KEY))

    if not Setting.objects.filter(name='Twitter Consumer Secret').exists():
        print('"Twitter Consumer Secret" not configured. Inserting...')
        settings_list.append(Setting(name='Twitter Consumer Secret', value1=TWITTER_CONSUMER_SECRET))

    if not Setting.objects.filter(name='Twitter Access Token').exists():
        print('"Twitter Access Token" not configured. Inserting...')
        settings_list.append(Setting(name='Twitter Access Token', value1=TWITTER_ACCESS_TOKEN))

    if not Setting.objects.filter(name='Twitter Access Token Secret').exists():
        print('"Twitter Access Token Secret" not configured. Inserting...')
        settings_list.append(Setting(name='Twitter Access Token Secret', value1=TWITTER_ACCESS_TOKEN_SECRET))

    if not Setting.objects.filter(name='Twitter Username List').exists():
        print('"Twitter Username List" not configured. Inserting...')
        settings_list.append(Setting(name='Twitter Username List', value1=TWITTER_USERNAME_LIST))

    if not Setting.objects.filter(name='Twitter Search List').exists():
        print('"Twitter Search List" not configured. Inserting...')
        settings_list.append(Setting(name='Twitter Search List', value1=TWITTER_SEARCH_LIST))

    if not Setting.objects.filter(name='MaxMind City Database Path').exists():
        print('"MaxMind City Database Path" not configured. Inserting...')
        settings_list.append(Setting(name='MaxMind City Database Path', value1=MAXMIND_CITY_DB_PATH))

    if not Setting.objects.filter(name='MaxMind ASN Database Path').exists():
        print('"MaxMind ASN Database Path" not configured. Inserting...')
        settings_list.append(Setting(name='MaxMind ASN Database Path', value1=MAXMIND_ASN_DB_PATH))

    if not Setting.objects.filter(name='Home Country').exists():
        print('"Home Country" not configured. Inserting...')
        settings_list.append(Setting(name='Home Country', value1=HOME_COUNTRY_NAME, value2=HOME_COUNTRY_CODE))

    if len(settings_list) > 0:
        print('Saving new values...')
        Setting.objects.bulk_create(settings_list)

    else:
        print('There are no new items to save.')
