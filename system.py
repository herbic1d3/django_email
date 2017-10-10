#-*- coding: utf-8 -*-

from django.conf import settings
from django.core.cache import cache
from django.contrib.auth.models import User

from main.models import Item

import hashlib, re, json
import email, html2text
from imaplib import IMAP4, IMAP4_SSL

from io import BytesIO
import base64

EMAIL_FIELDS = [
    'to', 'date', 'from', 'subject','return-path'
]

class ParseImapMail(object):
    def imap_connect(fun):
        def tmp(self, *args, **kwargs):
            if self.imap_connection is None:
                try:
                    if self.ssl:
                        self.imap_connection = IMAP4_SSL(self.host, self.port)
                    else:
                        self.imap_connection = IMAP4(self.host, self.port)
                except Exception as e:
                    result = {'success': False, 'error': data[0]}

            response, data = self.imap_connection.login(self.user, self.passwd)

            if response == 'OK':
                result = {'success': True, 'response': fun(self, *args, **kwargs)}
            else:
                result = {'success': False, 'error': data[0]}

            return result
        return tmp

    def __init__(self ):
        self.host =  settings.PARSE_EMAIL_BOX['host']
        self.port = settings.PARSE_EMAIL_BOX['port']
        self.ssl  = settings.PARSE_EMAIL_BOX['ssl']
        self.user = settings.PARSE_EMAIL_BOX['user']
        self.passwd = settings.PARSE_EMAIL_BOX['passwd']

        self.imap_connection = None
        self.redis_connection = None
        self.result = []

    @imap_connect
    def get_mail_list(self):
        result = []

        last_uid = 1
        self.imap_connection.select()
        response, data = self.imap_connection.uid('search', 'ALL', 'UID', '{0}:*'.format(last_uid))

        if response != 'OK': return result

        uids = data[0].split()
        uids.reverse()

        for uid in uids:
            response, data = self.imap_connection.fetch(uid, '(RFC822)')

            if response != 'OK':
                self.set_last_uid(uid-1)
                return result
            if data[0] is None: continue

            raw_mail = email.message_from_string(data[0][1])

            parsed_mail = {'images': [], 'text': {}}
            for field in EMAIL_FIELDS:
                parsed_mail[field] = self.field_decode(raw_mail, field)
            parsed_mail['hash'] = hashlib.sha1(json.dumps(parsed_mail)).hexdigest()
            parsed_mail['uid'] = uid

            result.append(parsed_mail)
        return result

    @imap_connect
    def get_mail_by_uid(self, uid):
        self.imap_connection.select()
        response, data = self.imap_connection.fetch(uid, '(RFC822)')

        if response != 'OK':
            return {}
        if data[0] is None:
            return {}

        raw_mail = email.message_from_string(data[0][1])

        parsed_mail = {'images': [], 'text': {}}
        for field in EMAIL_FIELDS:
            parsed_mail[field] = self.field_decode(raw_mail, field)
        parsed_mail['hash'] = hashlib.sha1(json.dumps(parsed_mail)).hexdigest()
        parsed_mail['uid'] = uid

        for content in raw_mail.walk():
            ctype = content.get_content_type()
            csets = content.get_charsets()

            if (ctype in ['image/jpeg', 'image/jpg', 'image/png']):
                ctent = content.get_payload()
                parsed_mail['images'].append([ctype, json.dumps(ctent), ctype.split('/')[1]])
            elif (ctype == 'text/plain'):
                ctent = content.get_payload(decode=True)
                if csets is None:
                    parsed_mail['text']['plain'] = re.sub('<.*?>', '', ctent)
                else:
                    parsed_mail['text']['plain'] = re.sub('<.*?>', '', unicode(ctent, str(csets), "ignore").encode('utf8', 'replace'))
                self.find_tags(parsed_mail['text']['plain'], parsed_mail)
            elif (ctype == 'text/html'):
                ctent = content.get_payload(decode=True)
                if csets is None:
                    parsed_mail['text']['html'] = ctent
                else:
                    parsed_mail['text']['html'] = unicode(ctent, str(csets), "ignore").encode('utf8', 'replace')
                self.find_tags(parsed_mail['text']['html'], parsed_mail)

        parsed_mail['user'] = False
        if User.objects.filter(email=parsed_mail['return-path']).exists():
            parsed_mail['user'] = True

        parsed_mail['advert'] = False
        if Item.objects.filter(email_hash=parsed_mail['hash']).exists():
            parsed_mail['advert'] = True
            item = Item.objects.get(email_hash=parsed_mail['hash'])
            parsed_mail['url'] = "/catalog/{0}/{1}-{2}/".format(item.first_category_slug(),item.id,item.slug)

        return parsed_mail

    def get_mail(self, uid, hash=None):
        response = cache.get(hash)
        if response is None:
            response = self.get_mail_by_uid(uid)
            if response['success']:
                cache.set(response['response']['hash'],response,settings.REDIS_VALUE_EXPIRE)
        return response

    def field_decode(self, mail, field):
        value  = email.Header.decode_header(mail.get(field))
        result = self.list_decode(value)
        return result

    def find_tags(self, message, result):
        if 'tags' in result.keys(): return
        for raw in re.finditer(r'#(.*?)#', message):
            item = raw.group()[1:-1]
            if '</' in item: continue
            if item.find(' ') == -1: continue
            if not 'tags' in result.keys(): result['tags'] = {}

            result['tags'][item[:item.index(' ')].decode('utf-8').upper()] = item[min(item.index(' ')+1,len(item)):]

    def list_decode(self, src):
        result = ""
        for item in src:
            if isinstance(item, list):
                result = result + self.list_decode(item)
            elif isinstance(item, tuple):
                result = result + self.tuple_decode(item)
            else:
                result = result + item
        return result

    def tuple_decode(self, src):
        srcStr  = src[0]
        strType = src[1]
        result  = ""

        if '=?' in srcStr and '?=' in srcStr:
            srcStr = srcStr.replace('\t','')
            for subStr in srcStr.split('\r\n'):
                result = result + self.list_decode(email.header.decode_header(subStr))
        else:
            if strType is None:
                result = result + srcStr
            else:
                result = result + srcStr.decode(strType)
        return result

def get_mail_list():
    m = ParseImapMail()
    return m.get_mail_list()

def get_full_mail(uid, hash):
    m = ParseImapMail()
    return m.get_mail(uid, hash)

def exists_hash_in_cache(hash):
    response = cache.get(hash)
    if response is None:
        return False
    return True

def delete_hash_in_cache(hash):
    cache.delete(hash)

