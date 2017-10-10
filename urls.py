#-*- coding: utf-8 -*-

from django.conf.urls import url
from django_email import views


urlpatterns = [
    url(r'^email/$', views.email_handler, name='email_handler'),
    url(r'^email/api/list$', views.email_list, name='email_list'),
    url(r'^email/api/(?P<uid>[0-9]+)-(?P<hash>[-0-9a-z]+)/$', views.email_with_body),
]
