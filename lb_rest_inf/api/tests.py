# note ordering, bit of work and load on lb to continously setup/teardown
# necessary vips for testing - look into it

# this should probably be moved down into api once api is made its
# own django app

from django.test.client import Client
from django.test import TestCase

import base64
import ConfigParser

class testAPI(TestCase):
    client = None
    # ooh, this'll be cool for the json test
    # fixtures = ['']

    config = ConfigParser.ConfigParser()

    config.read('/home/jdavis/.ns_tools.cfg')
    config_section = 'creds'

    username = config.get(config_section, 'username')
    password = config.get(config_section, 'password')
    # change this approach when you're doing proper login and auth
    auth_string = 'Basic ' + base64.b64encode(':'.join([username, password]))

    def setUp(self):
	self.client = Client()
	#self.client.login(username=self.username, password=self.password)

    def test_get_vserver(self):
	# need to dig deeper to figure out why credentials aren't
	# saved or sent correctly (although we do reinstantiate client 
	# every test, client login should save them during duration 
	# of test, at minimum)
	resp = self.client.get('/api/virtserver/jdavis_webotgtest.st/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_services_bound_to_vserver(self):
	resp = self.client.get('/api/virtserver/jdavis_webotgtest.st/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200
	assert resp.content.find('web3.st-http') != -1

    def test_get_server(self):
	resp = self.client.get('/api/server/web3.st/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_get_service(self):
	resp = self.client.get('/api/service/web3.st-http/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_disable_server(self):
	resp = self.client.put('/api/server/web3.st/disable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_enable_server(self):
	resp = self.client.put('/api/server/web3.st/enable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_disable_service(self):
	resp = self.client.put('/api/service/web3.st-http/disable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_enable_service(self):
	resp = self.client.put('/api/service/web3.st-http/enable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_disable_vserver(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/disable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_enable_vserver(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/enable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_is_service_bound_to_vserver(self):
	resp = self.client.get('/api/virtserver/jdavis_webotgtest.st/service/web4.st-http/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200
	assert resp.content.find(' BOUND') != -1

    def test_unbind_service_from_vserver(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/service/web4.st-http/disable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_unbind_service_from_vserver_already_unbound(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/service/web4.st-http/disable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_bind_service_to_vserver(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/service/web4.st-http/enable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_bind_service_to_vserver_already_bound(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/service/web4.st-http/enable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_bind_responder_policy_to_vserver(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/resppolicy/jdavis_webtest_otg/enable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_bind_responder_policy_to_vserver_already_bound(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/resppolicy/jdavis_webtest_otg/enable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_unbind_responder_policy_from_vserver(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/resppolicy/jdavis_webtest_otg/disable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200

    def test_unbind_responder_policy_from_vserver_already_bound(self):
	resp = self.client.put('/api/virtserver/jdavis_webotgtest.st/resppolicy/jdavis_webtest_otg/disable/',
	                       HTTP_AUTHORIZATION=self.auth_string)
	assert resp.status_code == 200
