# models.py
from django.db import models
from django.core.validators import validate_comma_separated_integer_list
from django.db.models import Q

class Scan_DB(models.Model):
    nome_scan = models.CharField(max_length=32,null=True)
    port_scan = models.BooleanField(null=True,default=False)
    serv_scan = models.BooleanField(null=True,default=False)
    web_scan = models.BooleanField(null=True,default=False)
    nuclei = models.BooleanField(null=True,default=False)
    web_fuzz = models.BooleanField(null=True,default=False)
    dorks = models.BooleanField(null=True,default=False)

    target = models.CharField(max_length=32,null=True)
    scan_nr = models.IntegerField(null=True)
    data_inicio = models.DateField(null=True)
    comecou = models.BooleanField(default=False)
    velo_nmap=models.CharField(null=True,max_length=6)
    max_agressi=models.BooleanField(null=True)
    pingd = models.BooleanField(null=True)
    acabou  = models.BooleanField(default=False)
    existe=models.BooleanField(default=False)
    todas = models.BooleanField(default=False)
    ja_abertas =  models.BooleanField(default=False)
    op_portas = models.BooleanField(default=False)
    portas_ch= models.CharField(max_length=32,null=True)


class IPAddress(models.Model):
    ip = models.GenericIPAddressField(null=True,unique=True)
    portas = models.CharField(null=True,max_length=999)
    servicos = models.CharField(null=True,max_length=999)
    domain = models.CharField(null=True,max_length=999)