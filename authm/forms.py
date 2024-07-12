from django import forms
from .models import Scan_DB
escolher_scan=(("full","Full Scan"),("web","Web Scan"),("port","Estado das Portas"),('serv','Identificação de Serviços'))

mudanca =( 
    ("t1", "T1 - IDS Evasion"), 
    ("t2", "T2 - IDS Evasion"), 
    ("t3", "T3 - Default"), 
    ("t4", "T4 - Rápido"), 
    ("t5", "T5 - Muito Rápido"), 
) 
scn =( 
    ("1", "Port Scan"), 
    ("2", "Nmap"), 

)


class LoginForm(forms.Form):
    username = forms.CharField(label="Username",max_length=32)
    passw = forms.CharField(widget=forms.PasswordInput(),label="Password")

class Op_Scan(forms.Form):
    choices = forms.MultipleChoiceField(
        widget=forms.CheckboxSelectMultiple,
        choices=[('1', 'Scan de Portos'), ('2', 'Scan Serviços'), ('3', 'Nuclei'),('4','Web Dir Fuzz'),('5','Web Param Fuzz')],)



class agrserv(forms.Form):
    OPTION_CHOICES = [
        ('todas', 'Todas as Portas'),
        ('descobertas', 'Todas as Portas Descobertas Anteriormente'),
        ('portas_op', 'Portas Opcionais'),
    ]
    a = forms.BooleanField(required=False)
    b = forms.BooleanField(required=False)
    option = forms.ChoiceField(required=False,choices=OPTION_CHOICES, widget=forms.RadioSelect(attrs={'name': 'opcoes'}))
    portas_op=forms.CharField(required=False,max_length=9999)
    velo = forms.ChoiceField(required=False,choices=mudanca)