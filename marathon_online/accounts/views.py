import json

from django.http import JsonResponse

from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.models import User

from django.conf import settings
from django.core.mail import send_mail

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view

TRANSLATIONS = None


def load_translations():
    global TRANSLATIONS
    if TRANSLATIONS is None:
        translations_file_path = settings.BASE_DIR / 'config' / 'translations.json'
        with open(translations_file_path, 'r', encoding='utf-8') as file:
            TRANSLATIONS = json.load(file)
    return TRANSLATIONS


def prepare_translations(request):
    translations = load_translations()
    lang = request.GET.get('lang')
    if not lang:
        lang = request.COOKIES.get('lang', 'ru')
    return translations.get(lang, translations['ru'])


def prepare_response(request, html_file):
    context = {
        'translations': prepare_translations(request)
    }
    response = render(request, html_file, context)
    if request.GET.get('lang'):
        response.set_cookie('lang', request.GET.get('lang'))

    return response


def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists'}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already in use'}, status=400)
        user = User.objects.create_user(username=username, email=email, password=password)
        return redirect('login')

    return prepare_response(request, 'register.html')


def login(request):
    if request.method == 'POST':
        identifier = request.POST['identifier']
        password = request.POST['password']
        if '@' in identifier:
            user = User.objects.filter(email=identifier).first()
        else:
            user = User.objects.filter(username=identifier).first()
        if user and authenticate(request, username=user.username, password=password):
            auth_login(request, user)
            refresh = RefreshToken.for_user(user)
            response = redirect('register')
            response.set_cookie('refresh_token', str(refresh), httponly=True, secure=True)
            response.set_cookie('access_token', str(refresh.access_token), httponly=True, secure=True)
            return response
        return JsonResponse({'error': 'Invalid credentials'}, status=400)

    return prepare_response(request, 'login.html')


@api_view(['POST'])
def reset_request(request):
    email = request.POST['email']
    if User.objects.filter(email=email).exists():
        '''
        user = User.objects.get(email=email)
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.generate_otp()
        send_mail(
            'Password Reset Request',
            f'Your OTP is: {profile.otp}.',
            'marathononline0@gmail.com',
            [user.email],
            fail_silently=False,
        )
        '''
        return redirect('password_reset_sent')

    return JsonResponse({'error': 'Email not found.'}, status=400)


def password_reset(request):
    if request.method == 'POST':
        return reset_request(request)

    return prepare_response(request, 'password_reset.html')


def password_reset_sent(request):
    return prepare_response(request, 'password_reset_sent.html')

