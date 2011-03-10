from django.db import models

# Create your models here.

class NetscalerCredentials(models.Model):
    ldap_login = models.CharField(max_length=120)
    username = models.CharField(max_length=120)
    password = models.CharField(max_length=120)

    def __unicode__(self):
	return self.ldap_login
