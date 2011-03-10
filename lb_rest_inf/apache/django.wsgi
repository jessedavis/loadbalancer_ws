#!/usr/bin/env python

import os
import sys

# change when both django and this project are correctly deployed
# (i.e. /usr/local/python/dist-packages)
# probably only our project, pretty sure dist-packages is on PYTHONPATH
sys.path.append('/home/jdavis/src/svn/loadbalancer_ws/trunk')
sys.path.append('/home/jdavis/src/svn/loadbalancer_ws/trunk/lb_rest_inf')
#sys.path.append('/usr/local/loadbalancer_ws_current')
#sys.path.append('/usr/local/loadbalancer_ws/current/lb_rest_inf')
os.environ['DJANGO_SETTINGS_MODULE'] = 'lb_rest_inf.settings'

import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()
