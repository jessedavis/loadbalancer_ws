from django.conf.urls.defaults import *
from piston.resource import Resource
from lb_rest_inf.api.handlers import JSONRequestHandler, MonitoringHandler, LoginHandler, ServerHandler, ServiceHandler, VirtServerHandler, VirtServerServiceHandler, VirtServerPolicyHandler
from piston.authentication import HttpBasicAuthentication

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

import netscaler

auth = HttpBasicAuthentication(realm="LB API")

jsonrequest_handler = Resource(JSONRequestHandler, authentication=auth)
login_handler = Resource(LoginHandler, authentication=auth)
server_handler = Resource(ServerHandler, authentication=auth)
service_handler = Resource(ServiceHandler, authentication=auth)
virtserver_handler = Resource(VirtServerHandler, authentication=auth)
virtserverservice_handler = Resource(VirtServerServiceHandler, authentication=auth)
virtserverpolicy_handler = Resource(VirtServerPolicyHandler, authentication=auth)
monitoring_handler = Resource(MonitoringHandler)

urlpatterns = patterns('',
    # Example:
    # (r'^lb_rest_inf/', include('lb_rest_inf.foo.urls')),

    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/', include(admin.site.urls)),

    url(r'^server/(?P<name>[^/]+)/(?P<method>[^/]+)/$', server_handler),
    url(r'^server/(?P<name>[^/]+)/$', server_handler),
    url(r'^service/(?P<name>[^/]+)/(?P<method>[^/]+)/$', service_handler),
    url(r'^service/(?P<name>[^/]+)/$', service_handler),
    url(r'^virtserver/(?P<name>[^/]+)/resppolicy/(?P<policy_name>[^/]+)/(?P<method>[^/]+)/$', virtserverpolicy_handler), 
    url(r'^virtserver/(?P<name>[^/]+)/service/(?P<service_name>[^/]+)/(?P<method>[^/]+)/$', virtserverservice_handler),
    url(r'^virtserver/(?P<name>[^/]+)/service/(?P<service_name>[^/]+)/$', virtserverservice_handler),
    url(r'^virtserver/(?P<name>[^/]+)/(?P<method>[^/]+)/$', virtserver_handler),
    url(r'^virtserver/(?P<name>[^/]+)/$', virtserver_handler),
    url(r'^jsonrequest/', jsonrequest_handler), 
    url(r'^login/', login_handler), 
    url(r'^status/', monitoring_handler),
)
