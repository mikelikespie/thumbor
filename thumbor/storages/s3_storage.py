#!/usr/bin/python
# -*- coding: utf-8 -*-

# thumbor imaging service
# https://github.com/globocom/thumbor/wiki

# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license
# S3 upload code adapted from https://gist.github.com/1436573#gistcomment-67357

import base64
import hashlib
import hmac
import os
import re
import sys
import urlparse
import mimetypes
import hashlib
import itertools
import email

from json import loads, dumps
from datetime import datetime, timedelta

import tornado
import tornado.httpclient
import tornado.stack_context

import logging

logger = logging.basicConfig()

from thumbor.storages import BaseStorage

interesting_headers = ['content-md5', 'content-type', 'date'] # sorted
amazon_header_prefix = 'x-amz-'

amazon_request_params = ['acl', 'logging', 'torrent', 'versionid', 'versioning']

class Storage(BaseStorage):
    def __init__(self, context):
        BaseStorage.__init__(self, context)
        
        if not context.config.S3_BUCKET:
            raise RuntimeError("S3_BUCKET can't be empty if s3_storage specified")
        self.bucket = context.config.S3_BUCKET

        if not context.config.S3_URL:
            raise RuntimeError("S3_URL can't be empty if s3_storage specified")
        self.s3_url = context.config.S3_URL

        if not context.config.S3_SECRET_ACCESS_KEY:
            raise RuntimeError("S3_SECRET_ACCESS_KEY can't be empty if s3_storage specified")
        self.s3_secret_access_key = context.config.S3_SECRET_ACCESS_KEY

        if not context.config.S3_ACCESS_KEY_ID:
            raise RuntimeError("S3_ACCESS_KEY_ID can't be empty if s3_storage specified")
        self.s3_access_key_id = context.config.S3_ACCESS_KEY_ID

    def __key_for(self, url):
        return 'thumbor-crypto-%s' % url

    def __detector_key_for(self, url):
        return 'thumbor-detector-%s' % url

    def put(self, path, bytes):
        def callback(response):
            if response.error is not None:
                # Todo make sure this is caught by something
                logging.error("PUT to %s failed", path)
                response.rethrow()

            else:
                logging.info("PUT to %s succeeded", path)

        self.performs3request(path, 'PUT', body=bytes, callback=callback)

    def get_crypto(self, path):
        if not self.context.config.STORES_CRYPTO_KEY_FOR_EACH_IMAGE:
            return None

        crypto = self.storage.get(self.__key_for(path))

        if not crypto:
            return None
        return crypto

    def get_detector_data(self, path):
        data = self.storage.get(self.__detector_key_for(path))

        if not data:
            return None
        return loads(data)

    def get(self, path):
        raise RuntimeError("GET Not supported for s3_storage")

    ##
    ## The following code is inspired by gist https://gist.github.com/1436573...
    ## but rewritten

    def signature(self, uri, private_key, method='GET', headers={}, expires=None):
        return self.sign(private_key, self.canonical_string(method, uri, headers, expires))
    
    def sign(self, private_key, s):
        digest = hmac.new(private_key, s, hashlib.sha1).digest()
        return base64.encodestring(digest).strip()

    def canonical_string(self, method, url, headers, expires=None):
        lower_headers = dict((k,v)
                             for k,v
                             in ((k.lower(),unicode(v).strip()) for k,v in headers.iteritems())
                             if k in interesting_headers \
                                or k.startswith(amazon_header_prefix))

        if 'x-amz-date' in lower_headers:
            lower_headers['date'] = ''
    
        if expires is not None:
            lower_headers['date'] = unicode(expires)
        
        sign_items = [unicode(method).upper()]
        sign_items += [lower_headers.get(k, '') for k in interesting_headers]
        sign_items += [k + ':' + v 
                       for k,v 
                       in lower_headers.iteritems()
                       if k.startswith(amazon_header_prefix)]

        parsed = urlparse.urlsplit(url)
        canonical_url = parsed.path
        if parsed.query:
            canonical_string += urllib.urlencode(q 
                                                 for q 
                                                 in urlparse.parse_qsl(parsed.query) 
                                                 if q in amazon_request_params)

        sign_items.append(canonical_url)

        return '\n'.join(sign_items)

    def performs3request(self, path, method="GET", body=None, callback=None):
        uri = urlparse.urljoin(self.s3_url, self.bucket, path)
        headers = {
            'Date': email.utils.formatdate(None, False, True),

        }
        if body is not None:
            headers['Content-Md5'] = hashlib.md5(body).hexdigest()

        type = mimetypes.guess_type(uri, False)[0]
        if type is not None:
            headers['Content-Type'] = type

        signed = self.signature(uri, self.s3_secret_access_key, method, headers=headers)
        headers['Authorization'] = 'AWS {k}:{d}'.format(k=self.s3_access_key_id, d=signed)
        from pprint import pprint
        pprint(headers)
        request = tornado.httpclient.HTTPRequest(uri, method=method, headers=headers, body=body)
        http_client = tornado.httpclient.AsyncHTTPClient()
        return http_client.fetch(request, callback=callback)
        
