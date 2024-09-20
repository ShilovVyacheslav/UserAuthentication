import json

from django.http import JsonResponse

from django.shortcuts import render, redirect

from django.template.loader import render_to_string

from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str, force_bytes

from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.sites.shortcuts import get_current_site

from django.conf import settings
from django.core.mail import EmailMultiAlternatives

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


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'

    def post(self, request, *args, **kwargs):
        uid = force_str(urlsafe_base64_decode(kwargs['uidb64']))
        user = User.objects.get(pk=uid)
        post_data = {
            'new_password1': request.POST['password'],
            'new_password2': request.POST['confirm_password'],
        }
        form = SetPasswordForm(user, post_data)
        if form.is_valid():
            user = form.save()
            # update_session_auth_hash(request, user)
            return redirect('login')

        return JsonResponse({'error': 'Invalid password'}, status=400)

    def get(self, request, *args, **kwargs):
        return prepare_response(request, self.template_name)


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
        user = User.objects.get(email=email)
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        current_site = get_current_site(request)
        reset_link = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
        reset_url = f"http://{current_site.domain}{reset_link}"
        email_subject = 'Password Reset Request'
        html_content = render_to_string('email/password_reset_email.html', {
            'user': user,
            'reset_url': reset_url,
            'domain': current_site.domain
        })
        text_content = f'Hello {user.username},\n\nYou requested a password reset for your account at {current_site.domain}. Please click the link below to reset your password:\n{reset_url}\n\nIf you didn\'t request this, please ignore this email. Your password will remain unchanged.'
        message = EmailMultiAlternatives(email_subject, html_content, 'marathononline0@gmail.com', [user.email])
        message.attach_alternative(html_content, "text/html")
        message.send()
        return redirect('password_reset_sent')

    return JsonResponse({'error': 'Email not found.'}, status=400)


def password_reset(request):
    if request.method == 'POST':
        return reset_request(request)

    return prepare_response(request, 'password_reset.html')


def password_reset_sent(request):
    return prepare_response(request, 'password_reset_sent.html')

