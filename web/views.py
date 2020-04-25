from .models import Organisation, Host, Domain, Email, Compromise, SensorHit, CountryHit, OpenPort, PortCVE, Paste, Setting
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import Group
from django.shortcuts import render, redirect
from django.utils import timezone
from datetime import timedelta

import logging
import re

logger = logging.getLogger(__name__)

def get_home_isocode():
    return Setting.objects.get(name='Home Country').value2.upper()

def get_home_name():
    return Setting.objects.get(name='Home Country').value1

def can_see_org(user, org_name):
    group = Group.objects.get(name=org_name)

    if user.is_staff:
        return True

    if group in user.groups.all():
        return True

    return False

def get_org_list(user):
    if user.is_staff:
        return Organisation.objects.all().order_by('name')

    org_names = list(user.groups.values_list('name',flat = True))
    org_list = Organisation.objects.filter(name__in=org_names)

    if org_list:
        return org_list.order_by('name')

    return []

def LoginView(request):
    view_params = {}

    if request.user.is_authenticated:
        return redirect('home country')

    if request.method == 'POST':
        if 'userInput' in request.POST and 'passwordInput' in request.POST:
            username = request.POST['userInput']
            password = request.POST['passwordInput']

            user = authenticate(username=username, password=password)

            if user is not None:
                if user.is_active:
                    login(request, user)

                    return redirect('home country')

            else:
                view_params['error'] = 'Invalid Credentials'

        else:
            view_params['error'] = 'Invalid Request'

    return render(request, 'web/login.html', view_params)

def LogoutView(request):
    if not request.user.is_authenticated:
        return redirect('login')

    logout(request)

    return redirect('login')

def OrgView(request):
    if not request.user.is_authenticated:
        return redirect('login')

    if request.user.groups.filter(name='Country Only').exists():
        return redirect('home country')

    view_params = {}

    view_params['home_country'] = get_home_name()
    org_list = get_org_list(request.user)

    if not org_list:
        view_params['error'] = 'You do not have group membership for any organisation.'

        return render(request, 'web/org.html', view_params)

    else:
        view_params['org_list'] = org_list

    if request.method == 'GET' and 'org' in request.GET:
        org_id = request.GET['org']

        if not re.match(r'^[0-9]{1,64}$', org_id):
           view_params['error'] = 'Invalid organisation ID.'

        else:
            org_search = Organisation.objects.filter(pk=org_id)

            if org_search.exists():
                org = org_search.first()

                if not can_see_org(request.user, org.name):
                    view_params['error'] = 'Invalid organisation ID.'

                    return render(request, 'web/org.html', view_params)

                DAYS_TO_DISPLAY = int(Setting.objects.get(name='Days to Display').value1)

                if 'days' in request.GET:
                    if re.match(r'^([1-9]|1[0-4])$', request.GET['days']):
                        DAYS_TO_DISPLAY = int(request.GET['days'])

                view_params['days'] = DAYS_TO_DISPLAY
                threshold = timezone.now() - timedelta(days=DAYS_TO_DISPLAY)

                host_list = []
                domain_list = []
                email_list = []

                hosts = Host.objects.filter(organisation=org).order_by('address')
                domains = Domain.objects.filter(organisation=org).order_by('domain')
                emails = Email.objects.filter(organisation=org).order_by('email')
                pastes = Paste.objects.filter(organisation=org, added__gte=threshold).order_by('title')

                for host in hosts:
                    ports = OpenPort.objects.filter(host=host).order_by('port')
                    cve = PortCVE.objects.filter(host=host)
                    compromises = Compromise.objects.filter(host=host, added__gte=threshold).order_by('-added')
                    sensor_hits = SensorHit.objects.filter(host=host, added__gte=threshold)
                    host_json = {'host': host, 'ports': ports, 'cve': cve, 'compromises': compromises, 'sensor_hits': sensor_hits}
                    host_list.append(host_json)

                for domain in domains:
                    compromises = Compromise.objects.filter(domain=domain, added__gte=threshold).order_by('-added')
                    domain_json = {'domain': domain, 'compromises': compromises}
                    domain_list.append(domain_json)

                for email in emails:
                    compromises = Compromise.objects.filter(email=email, added__gte=threshold).order_by('-added')
                    email_json = {'email': email, 'compromises': compromises}
                    email_list.append(email_json)

                view_params['paste_list'] = pastes
                view_params['host_list'] = host_list
                view_params['domain_list'] = domain_list
                view_params['email_list'] = email_list

                view_params['org_name'] = org.name

                view_params['compromise_count'] = Compromise.objects.filter(organisation=org, added__gte=threshold).count()
                view_params['cve_count'] = PortCVE.objects.filter(organisation=org).count()
                view_params['sensorhit_count'] = SensorHit.objects.filter(organisation=org, added__gte=threshold).count()
                view_params['paste_count'] = Paste.objects.filter(organisation=org, added__gte=threshold).count()

            else:
                view_params['error'] = 'Invalid organisation ID.'

    else:
       view_params['error'] = 'Please select an organisation.'

    return render(request, 'web/org.html', view_params)

def GeoView(request):
    if not request.user.is_authenticated:
        return redirect('login')

    view_params = {}

    if request.method == 'GET':
        DAYS_TO_DISPLAY = int(Setting.objects.get(name='Days to Display').value1)

        if 'days' in request.GET:
            if re.match(r'^([1-9]|1[0-4])$', request.GET['days']):
                DAYS_TO_DISPLAY = int(request.GET['days'])

        view_params['days'] = DAYS_TO_DISPLAY
        threshold = timezone.now() - timedelta(days=DAYS_TO_DISPLAY)

        host_list = []
        domain_list = []

        unique_host_count = 0
        unique_domain_count = 0

        host_asn = list(CountryHit.objects.filter(category='MalwareCommunication', added__gte=threshold).values_list('asn', flat=True).distinct())
        domain_asn = list(CountryHit.objects.filter(category='MalwareHosting', added__gte=threshold).values_list('asn', flat=True).distinct())

        if len(host_asn) > 0:
            host_asn.sort()

        if len(domain_asn) > 0:
            domain_asn.sort()

        for asn in host_asn:
            asn_entities = list(CountryHit.objects.filter(category='MalwareCommunication', asn=asn, added__gte=threshold).values_list('entity', flat=True).distinct())

            if len(asn_entities) > 0:
                asn_entities.sort()

                entity_list = []
                unique_host_count += len(asn_entities)

                for entity in asn_entities:
                    observables = CountryHit.objects.filter(category='MalwareCommunication', entity=entity, added__gte=threshold).order_by('-added')
                    host_json = {'entity': entity, 'observables': observables}
                    entity_list.append(host_json)

                host_json = {'asn': asn, 'entities': entity_list}
                host_list.append(host_json)

        for asn in domain_asn:
            asn_entities = list(CountryHit.objects.filter(category='MalwareHosting', asn=asn, added__gte=threshold).values_list('entity', flat=True).distinct())

            if len(asn_entities) > 0:
                asn_entities.sort()

                entity_list = []
                unique_domain_count += len(asn_entities)

                for entity in asn_entities:
                    observables = CountryHit.objects.filter(category='MalwareHosting', entity=entity, added__gte=threshold).order_by('-added')
                    domain_json = {'entity': entity, 'observables': observables}
                    entity_list.append(domain_json)

                domain_json = {'asn': asn, 'entities': entity_list}
                domain_list.append(domain_json)

        print(host_list)
        print(domain_list)

        view_params['host_list'] = host_list
        view_params['domain_list'] = domain_list

        view_params['host_entities'] = unique_host_count
        view_params['host_count'] = CountryHit.objects.filter(category='MalwareCommunication', added__gte=threshold).count()
        view_params['domain_entities'] = unique_domain_count
        view_params['domain_count'] = CountryHit.objects.filter(category='MalwareHosting', added__gte=threshold).count()

    else:
       view_params['error'] = 'Invalid request.'

    view_params['home_country'] = get_home_name()
    view_params['org_list'] = get_org_list(request.user)

    print(view_params)

    return render(request, 'web/geo.html', view_params)
