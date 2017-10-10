#-*- coding: utf-8 -*-

from django.http import JsonResponse, HttpResponsePermanentRedirect
from django.shortcuts import render_to_response

from django_email.system import get_mail_list, get_full_mail

def email_handler(request):
    if 'main.broker_perm' in request.user.get_all_permissions():
        return render_to_response('email/index.html', {'user': request.user})
    return HttpResponsePermanentRedirect('/')

def email_list(request):
    if 'main.broker_perm' in request.user.get_all_permissions():
        return JsonResponse(get_mail_list())
    return HttpResponsePermanentRedirect('/')

def email_with_body(request, uid=1, hash=''):
    if 'main.broker_perm' in request.user.get_all_permissions():
        return JsonResponse(get_full_mail(uid, hash))
    return HttpResponsePermanentRedirect('/')

