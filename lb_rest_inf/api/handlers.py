from piston.handler import BaseHandler
from piston.utils import rc

from django.conf import settings
from django.http import HttpResponse

import logging
import sys

import netscaler
logging.getLogger().manager.disable = 0

from netscaler_helper_lib.wrappers import *
from netscaler_helper_lib.proxies import *

from lb_rest_inf.api.models import NetscalerCredentials

netscaler_helper_lib_proxy = NetscalerWrapperProxy(host=settings.LB_HOST, 
                          username=settings.LB_DEFAULT_USER, 
			  password=settings.LB_DEFAULT_PASS,
                          wsdl_url=settings.LB_DEFAULT_WSDL)
netscaler_json_proxy = NetscalerJSONWrapperProxy(host=settings.LB_HOST, 
                          username=settings.LB_DEFAULT_USER, 
			  password=settings.LB_DEFAULT_PASS,
                          wsdl_url=settings.LB_DEFAULT_WSDL)

class JSONRequestHandler(BaseHandler):
    allowed_methods = ('GET',)
    _client = None

    def __init__(self):
	self._client = netscaler_json_proxy.get_copy()
	self._client.log = logging.getLogger()

    # figure out which method you really want
    #def read(self, request, post_slug):
    def read(self, request):

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err + ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	resp = self._client.run(request.GET['response'])
	if resp:
	    return rc.ALL_OK
	else:
	    return rc.BAD_REQUEST

class ServerHandler(BaseHandler):
    allowed_methods = ('GET', 'PUT',)
    _client = None

    def __init__(self):
	self._client = netscaler_helper_lib_proxy.get_copy()
	self._client.log = logging.getLogger()

    # sort of not using the piston framework here, but we're not
    # using it to its fullest without models anway
    # good exposure to the api anyway
    # would be best to override BaseHandler somehow

    def read(self, request, **kwargs):
	if len(kwargs) != 1:	
	    return rc.BAD_REQUEST
	if 'name' not in kwargs.keys():
	    return rc.BAD_REQUEST

	name = kwargs['name']

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	self._client.log.info("ns_user = %s" % ns_user)
	self._client.log.info("ns_pass = %s" % ns_pass)

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err, ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	server_state = self._client.get_server(name)

	# check for correct response (i.e. exit 0, else BAD_REQUEST
	# and debug?)
	if not server_state:
	    return rc.BAD_REQUEST

	http_resp = rc.ALL_OK
	http_resp.content = http_resp.content + " - Server status: {0}".format(server_state)
	return http_resp

    def update(self, request, **kwargs):
	if len(kwargs) != 2:	
	    return rc.BAD_REQUEST
	# find more pythonic way to do this
	if 'name' not in kwargs.keys() or 'method' not in kwargs.keys():
	    return rc.BAD_REQUEST

	name = kwargs['name']
	method = kwargs['method']

	if method not in ['enable', 'disable']:
	    return rc.BAD_REQUEST

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	self._client.log.info("ns_user = %s" % ns_user)
	self._client.log.info("ns_pass = %s" % ns_pass)

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err + ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	resp = None
	if method == 'enable':
	    resp = self._client.enable_server(name)
	if method == 'disable':
	    resp = self._client.disable_server(name)

	# check for correct response (i.e. exit 0, else BAD_REQUEST
	# and debug?)

	if resp:
	    return rc.ALL_OK
	else:
	    return rc.BAD_REQUEST

class ServiceHandler(BaseHandler):
    allowed_methods = ('GET', 'PUT',)
    _client = None

    def __init__(self):
	self._client = netscaler_helper_lib_proxy.get_copy()
	self._client.log = logging.getLogger()

    # sort of not using the piston framework here, but we're not
    # using it to its fullest without models anway
    # good exposure to the api anyway
    # would be best to override BaseHandler somehow

    def read(self, request, **kwargs):
	if len(kwargs) != 1:	
	    return rc.BAD_REQUEST
	if 'name' not in kwargs.keys():
	    return rc.BAD_REQUEST

	name = kwargs['name']

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	self._client.log.info("ns_user = %s" % ns_user)
	self._client.log.info("ns_pass = %s" % ns_pass)

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err + ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	service_state = self._client.get_service(name)

	# check for correct response (i.e. exit 0, else BAD_REQUEST
	# and debug?)
	if not service_state:
	    return rc.BAD_REQUEST

	http_resp = rc.ALL_OK
	http_resp.content = http_resp.content + " - Service status: {0}".format(service_state)
	return http_resp

    def update(self, request, **kwargs):
	if len(kwargs) != 2:	
	    return rc.BAD_REQUEST
	# find more pythonic way to do this
	if 'name' not in kwargs.keys() or 'method' not in kwargs.keys():
	    return rc.BAD_REQUEST

	name = kwargs['name']
	method = kwargs['method']

	if method not in ['enable', 'disable']:
	    return rc.BAD_REQUEST

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	self._client.log.info("ns_user = %s" % ns_user)
	self._client.log.info("ns_pass = %s" % ns_pass)

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err + ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	resp = None
	if method == 'enable':
	    resp = self._client.enable_service(name)
	if method == 'disable':
	    resp = self._client.disable_service(name)

	# check for correct response (i.e. exit 0, else BAD_REQUEST
	# and debug?)

	if resp:
	    return rc.ALL_OK
	else:
	    return rc.BAD_REQUEST

class VirtServerHandler(BaseHandler):
    allowed_methods = ('GET', 'PUT',)
    _client = None

    def __init__(self):
	self._client = netscaler_helper_lib_proxy.get_copy()
	self._client.log = logging.getLogger()

    # sort of not using the piston framework here, but we're not
    # using it to its fullest without models anway
    # good exposure to the api anyway
    # would be best to override BaseHandler somehow

    def read(self, request, **kwargs):
	if len(kwargs) != 1:	
	    return rc.BAD_REQUEST
	if 'name' not in kwargs.keys():
	    return rc.BAD_REQUEST

	name = kwargs['name']

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	self._client.log.info("ns_user = %s" % ns_user)
	self._client.log.info("ns_pass = %s" % ns_pass)

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err + ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	vserver_state = self._client.get_vserver(name)
	bound_services = self._client.get_services(name)

	# check for correct response (i.e. exit 0, else BAD_REQUEST
	# and debug?)
	if not vserver_state:
	    return rc.BAD_REQUEST

	http_resp = rc.ALL_OK
	http_resp.content = http_resp.content + " - Virtual server status: {0}\n".format(vserver_state)
	http_resp.content = http_resp.content + "Bound services: " + " ".join(str(i) for i in bound_services)
	return http_resp

    def update(self, request, **kwargs):
	if len(kwargs) != 2:	
	    return rc.BAD_REQUEST
	# find more pythonic way to do this
	if 'name' not in kwargs.keys() or 'method' not in kwargs.keys():
	    return rc.BAD_REQUEST

	name = kwargs['name']
	method = kwargs['method']

	if method not in ['enable', 'disable']:
	    return rc.BAD_REQUEST

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	self._client.log.info("ns_user = %s" % ns_user)
	self._client.log.info("ns_pass = %s" % ns_pass)

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err + ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	resp = None
	if method == 'enable':
	    resp = self._client.enable_vserver(name)
	if method == 'disable':
	    resp = self._client.disable_vserver(name)

	# check for correct response (i.e. exit 0, else BAD_REQUEST
	# and debug?)

	if resp:
	    return rc.ALL_OK
	else:
	    return rc.BAD_REQUEST

class VirtServerServiceHandler(BaseHandler):
    allowed_methods = ('GET', 'PUT',)
    _client = None

    def __init__(self):
	self._client = netscaler_helper_lib_proxy.get_copy()
	self._client.log = logging.getLogger()

    # sort of not using the piston framework here, but we're not
    # using it to its fullest without models anway
    # good exposure to the api anyway
    # would be best to override BaseHandler somehow

    def read(self, request, **kwargs):
	if len(kwargs) != 2:	
	    return rc.BAD_REQUEST
	if 'name' not in kwargs.keys() or 'service_name' not in kwargs.keys():
	    return rc.BAD_REQUEST

	name = kwargs['name']
	service_name = kwargs['service_name']

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	self._client.log.info("ns_user = %s" % ns_user)
	self._client.log.info("ns_pass = %s" % ns_pass)

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err + ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	bound_services = self._client.get_services(name)

	# check for correct response (i.e. exit 0, else BAD_REQUEST
	# and debug?)
	http_resp = rc.ALL_OK
	service_status = 'BOUND'
	if service_name not in bound_services:
	    service_status = 'UNBOUND' 

	http_resp.content = http_resp.content + " - Service status in virtual server: {0}".format(service_status)

	return http_resp

    def update(self, request, **kwargs):
	if len(kwargs) != 3:	
	    return rc.BAD_REQUEST
	# find more pythonic way to do this
	if 'name' not in kwargs.keys() or 'service_name' not in kwargs.keys() or 'method' not in kwargs.keys():
	    return rc.BAD_REQUEST

	name = kwargs['name']
	service_name = kwargs['service_name']
	method = kwargs['method']

	if method not in ['enable', 'disable']:
	    return rc.BAD_REQUEST

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	self._client.log.info("ns_user = %s" % ns_user)
	self._client.log.info("ns_pass = %s" % ns_pass)

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err + ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	resp = None
	if method == 'enable':
	    resp = self._client.bind_service_to_vserver(name, service_name)
	if method == 'disable':
	    resp = self._client.unbind_service_from_vserver(name, service_name)

	# check for correct response (i.e. exit 0, else BAD_REQUEST
	# and debug?)

	if resp:
	    return rc.ALL_OK
	else:
	    return rc.BAD_REQUEST

class VirtServerPolicyHandler(BaseHandler):
    allowed_methods = ('PUT',)
    _client = None

    def __init__(self):
	self._client = netscaler_helper_lib_proxy.get_copy()
	self._client.log = logging.getLogger()

    # sort of not using the piston framework here, but we're not
    # using it to its fullest without models anway
    # good exposure to the api anyway
    # would be best to override BaseHandler somehow

#    def read(self, request, **kwargs):
#	if len(kwargs) != 1:	
#	    return rc.BAD_REQUEST
#	if 'name' not in kwargs.keys():
#	    return rc.BAD_REQUEST
#
#	name = kwargs['name']
#
#	service_state = self._client.get_vserver(name)
#
#	# check for correct response (i.e. exit 0, else BAD_REQUEST
#	# and debug?)
#	if not service_state:
#	    return rc.BAD_REQUEST
#
#	http_resp = rc.ALL_OK
#	http_resp.content = http_resp.content + " - Virtual server status: {0}".format(service_state)
#	return http_resp

    def update(self, request, **kwargs):
	if len(kwargs) != 3:	
	    return rc.BAD_REQUEST
	# find more pythonic way to do this
	if 'name' not in kwargs.keys() or 'policy_name' not in kwargs.keys() or 'method' not in kwargs.keys():
	    return rc.BAD_REQUEST

	name = kwargs['name']
	policy_name = kwargs['policy_name']
	method = kwargs['method']

	if method not in ['enable', 'disable']:
	    return rc.BAD_REQUEST

	self._client.log.info("request = %s " % request)
	self._client.log.info("username = %s" % request.user)

	ns_user = ''
	ns_pass = ''
	#ns_user, ns_pass = netscaler_username_map.get(request.user.username, '')
	user = request.user.username + '@example.com'
	lb_creds = NetscalerCredentials.objects.get(ldap_login=user)
	ns_user = lb_creds.username
	ns_pass = lb_creds.password

	self._client.log.info("ns_user = %s" % ns_user)
	self._client.log.info("ns_pass = %s" % ns_pass)

	try:
	    self._client.username = ns_user
	    self._client.password = ns_pass
	    # reset credentials to force suds client rebind
	    self._client.login()
	except InteractionError as err:
	    self._client.log.error(err + ": Check username to Netscaler login mapping.")
	    return rc.BAD_REQUEST 

	resp = None
	if method == 'enable':
	    resp = self._client.bind_responder_policy_to_vserver(name, policy_name)
	if method == 'disable':
	    resp = self._client.unbind_responder_policy_from_vserver(name, policy_name)

	# check for correct response (i.e. exit 0, else BAD_REQUEST
	# and debug?)

	if resp:
	    return rc.ALL_OK
	else:
	    return rc.BAD_REQUEST

# flush this out as we determine better sense of metrics for this
# service
class MonitoringHandler(BaseHandler):
    allowed_methods = ('GET',)

    def __init__(self):
	pass

    def read(self, request, **kwargs):
	return rc.ALL_OK

#--------------

#from piston.authentication import HttpBasicAuthentication

#
# login handler - worry about later
# basic auth for api calls is fine, not really needing a session
# key ala Rightscale right now - only reason to go that route
# is to decrease amount of checks against auth service
# either way is fine, do easy now for proof of concept.
# 
# search stack overflow "can you help me understand this?
# common rest mistakes: sessions are irrelevant"
# to wrap your mind around this
# also http://www.infoq.com/articles/rest-anti-patterns
# or check your bookmarks
#
# idea for token: http://tech.groups.yahoo.com/group/rest-discuss/message/10909
#
# in general, maybe not needed, but might still be good for practice

class LoginHandler(BaseHandler):
    # definately change this once done testing
    allowed_methods = ('GET', 'POST', 'DELETE',)

    def read(self, request):
	return rc.FORBIDDEN

    def create(self, request):
        #if request.META.user.is_active:
	    # saves in session
	    #login(request, user)
	print "request = %s" % request
	print "username = %s" % request.META['USERNAME']
	print "user = %s" % request.user
	print "session = %s" % request.session
	print "session key = %s" % request.session.session_key
	print request.session.keys()
	print request.session.items()
	#response = rc.ALL_OK
	return rc.ALL_OK
	#else:
	#    return rc.FORBIDDEN

    def delete(self, request):
	    #
	    # delete user's session
	    # get cookie id and nuke
	    #
	response = rc.ALL_OK
	#response.delete_cookie("session_id", domain=".example.com")
	# call request.session.flush() - regens sessions key value sent
	# back
        return response
