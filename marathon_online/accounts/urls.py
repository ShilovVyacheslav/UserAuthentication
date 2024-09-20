from django.urls import path
from . import views

urlpatterns = [
    path('register', views.register, name='register'),
    path('login', views.login, name='login'),
    path('password_reset', views.password_reset, name='password_reset'),
    path('password_reset/sent', views.password_reset_sent, name='password_reset_sent'),
    path('password_reset/<uidb64>/<token>/',
         views.CustomPasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
]