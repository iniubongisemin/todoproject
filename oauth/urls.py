from django.urls import path
from .views import *

urlpatterns = [
    path("auth_code/",  AuthCodeView.as_view(), name="auth_code"),      
    path("get_auth_url/",  GetAuthUrlView.as_view(), name="auth_url"),      
]