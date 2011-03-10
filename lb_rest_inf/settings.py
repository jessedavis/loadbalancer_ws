# Django settings for lb_rest_inf project.

DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('Your Name', 'your_email@domain.com'),
)

MANAGERS = ADMINS

# extra configuration, might place somewhere else and import

LB_CONF_FILE='/home/jdavis/lbws.conf'
#LB_CONF_FILE='/usr/local/etc/lbws.conf'

import ConfigParser

lb_config = ConfigParser.ConfigParser()
lb_config.read(LB_CONF_FILE)
config_section = 'lbws'
db_section = 'db'

LB_HOST         = lb_config.get(config_section, 'host')
LB_DEFAULT_USER = lb_config.get(config_section, 'default_user')
LB_DEFAULT_PASS = lb_config.get(config_section, 'default_password')
LB_DEFAULT_WSDL = lb_config.get(config_section, 'default_wsdl_url')

DB_NAME         = lb_config.get(db_section, 'name')
DB_USER         = lb_config.get(db_section, 'user')
DB_PASSWORD     = lb_config.get(db_section, 'password')
DB_HOST         = lb_config.get(db_section, 'host')

# note DATABASE.NAME needs to be absolute pathname when using sqlite3

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql', # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
    }
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'America/Los Angeles'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale
USE_L10N = True

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
# Examples: "http://media.lawrence.com", "http://example.com/media/"
MEDIA_URL = ''

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/media/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = '=&&%%btf2#r@6f$_=h7!lofeaqt$8))=r0gg=fq#9ayiwe-%)b'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)

ROOT_URLCONF = 'lb_rest_inf.urls'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    # Uncomment the next line to enable the admin:
    'django.contrib.admin',
    'django.contrib.admindocs',
    #
    # TODO: figure out better package name for this, make sure
    # it's really its own app (api is, but just make sure it's 
    # organized properly)
    'api',
)

# LDAP configuration

AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
)

import ldap
from django_auth_ldap.config import LDAPSearch

AUTH_LDAP_SERVER_URI = "ldap://example.com"
AUTH_LDAP_BIND_DN = "cn=example,dc=example,dc=com"
AUTH_LDAP_BIND_PASSWORD = "donotuse"
AUTH_LDAP_USER_SEARCH = LDAPSearch("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(sAMAccountName=%(user)s)")
#AUTH_LDAP_START_TLS = True

AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail"
}

from django_auth_ldap.config import ActiveDirectoryGroupType

AUTH_LDAP_GROUP_SEARCH = LDAPSearch("DC=example,DC=com", ldap.SCOPE_SUBTREE, "(objectClass=group)")
AUTH_LDAP_GROUP_TYPE = ActiveDirectoryGroupType()

AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_staff": "CN=staff,DC=example,DC=com",
    "is_superuser": "CN=staff,DC=example,DC=com"
}


# TODO: need to do better than this
# extra logging, should probably be done another way
import log

import logging
logger = logging.getLogger('django_auth_ldap')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


