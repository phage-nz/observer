from django.contrib import admin
from .models import Organisation, Host, Domain, Email, Compromise, SensorHit, CountryHit, OpenPort, PortCVE, Paste, Feed, Setting

admin.site.register(Organisation)
admin.site.register(Host)
admin.site.register(Domain)
admin.site.register(Email)
admin.site.register(Compromise)
admin.site.register(SensorHit)
admin.site.register(CountryHit)
admin.site.register(OpenPort)
admin.site.register(PortCVE)
admin.site.register(Paste)
admin.site.register(Feed)
admin.site.register(Setting)
