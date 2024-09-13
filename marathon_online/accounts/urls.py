from django.urls import path
from . import views

urlpatterns = [
    path('register', views.register, name='register'),
    path('login', views.login, name='login'),
    path('password_reset', views.password_reset, name='password_reset'),
    path('password_reset_sent', views.password_reset_sent, name='password_reset_sent')
]