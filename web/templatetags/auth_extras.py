from django import template
from django.contrib.auth.models import Group

register = template.Library()

@register.filter(name='has_group')
def has_group(user, group_name):
    group = Group.objects.get(name=group_name)

    if group in user.groups.all():
        return True

    return False

@register.filter(name='can_see_org')
def can_see_org(user, org_name):
    group = Group.objects.get(name=org_name)

    if user.is_staff:
        return True

    if group in user.groups.all():
        return True

    return False
