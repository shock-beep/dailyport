from django.contrib import admin
from django.urls import path
from authm import views

urlpatterns = [
    
    path('',views.home,name="home"),
    path('signup',views.signup,name="signup"),
    path('signin',views.signin,name="signin"),
    path('signout/',views.signout,name="signout"),
    path('scan/',views.scan),
    path('criar_scan/',views.criar_scan),
    path('ver_scan/',views.ver_scan),
    path('unico_scan/<id>',views.unico_scan,name="unico_scan"),
    path('nao_comecados/',views.nao_comecados),
    path('comecar',views.comecar),
    path('testar/',views.testar),
    path('eventos/',views.procurar),
    path('ver_output_unico/<str:ip>/<str:tipo>/<str:id>',views.ver_output_unico),
    path('sumario',views.sumario)
]
