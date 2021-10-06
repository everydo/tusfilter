# coding: utf-8

import os
import time
import json
import uuid
import webob
import shutil
import hashlib
from collections import namedtuple
from base64 import standard_b64decode, standard_b64encode

try:
    import httplib as http
except ImportError:
    import http.client as http

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


class Error(Exception):
    status_code = 0
    reason = ''


class NotFoundError(Error):
    status_code = http.NOT_FOUND
    reason = 'Not Found'


class NotImplementedError(Error):
    status_code = http.NOT_IMPLEMENTED
    reason = 'Feature Not Implemented'


class InvalidUploadPathError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Invalid Upload Path'


class MethodNotAllowedError(Error):
    status_code = http.METHOD_NOT_ALLOWED
    reason = 'Method Not Allowed'


class MissingVersionError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Missing Tus-Resumable Header'


class UnsupportedVersionError(Error):
    status_code = http.PRECONDITION_FAILED
    reason = 'Precondition Failed'


class InvalidUidError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Invalid Uid Part In Url'


class MissingUidError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Missing Uid Part In Url'


class MaxSizeExceededError(Error):
    status_code = http.REQUEST_ENTITY_TOO_LARGE
    reason = 'Request Entity Too Large'


class InvalidUploadLengthError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Invalid Upload-Length Header'


class ConflictUploadLengthError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Conflict Upload-Length'


class MissingUploadLengthError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Missing Upload-Length Header'


class ExceedUploadLengthError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Exceed Upload-Length'


class InvalidUploadDeferLengthError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Invalid Upload-Defer-Length Header'


class ConflictUploadDeferLengthError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Conflict Upload-Defer-Length Header'


class InvalidUploadOffsetError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Invalid Upload-Offset Header'


class ConflictUploadOffsetError(Error):
    status_code = http.CONFLICT
    reason = 'Conflict'


class MissingUploadOffsetError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Missing Upload-Offset Header'


class InvalidUploadMetadataError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Invalid Upload-Metadata Header'


class InvalidContentTypeError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Invalid Content-Type Header'


class ChecksumAlgorisumsNotSuppertedError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Bad Request'


class ChecksumMismatchError(Error):
    status_code = 460
    reason = 'Checksum Mismatch'


class FileLockedError(Error):
    status_code = http.LOCKED
    reason = 'File Currently Locked'


class UploadNotFinishedError(Error):
    status_code = http.BAD_REQUEST
    reason = 'One Of The Partial Uploads Is Not Finished'


class InvalidConcatError(Error):
    status_code = http.BAD_REQUEST
    reason = 'Invalid Upload-Concat Header'


class InvalidMethodError(Error):
    status_code = http.FORBIDDEN
    reason = 'Forbidden'


class ModifyFinalError(Error):
    status_code = http.FORBIDDEN
    reason = 'Modifying A Final Upload Is Not Allowed'


def b64_encode(s, encoding='utf-8'):
    return standard_b64encode(s.encode(encoding)).decode(encoding)


def b64_decode(s, encoding='utf-8'):
    return standard_b64decode(s.encode(encoding)).decode(encoding)


# req: webob request object
# resp: webob response object
# temp: temp data
# info: upload info, persistent data in info file
Env = namedtuple('Env', ['req', 'resp', 'temp', 'info'])


class TusFilter(object):
    versions = ['1.0.0']
    checksum_algorisums = ['sha1']
    extensions = [
        'creation',
        'expiration',
        'termination',
        'checksum',
        'creation-defer-length',
        # 'checksum-trailer',          # todo
        'concatenation',
        # 'concatenation-unfinished',  # todo
    ]

    def __init__(self, app, upload_path, api_base='', tmp_dir='/tmp/upload', expire=60*60*24*30, send_file=False, max_size=2**30):
        self.app = app
        self.tmp_dir = tmp_dir
        self.api_base = api_base
        self.upload_path = upload_path
        self.expire = expire
        self.send_file = send_file
        self.max_size = max_size

        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)

    def __call__(self, environ, start_response):
        req = webob.Request(environ)
        resp = webob.Response()
        temp = dict(upload_finished=False, info_loaded=False)
        info = dict()
        env = Env(req=req, resp=resp, temp=temp, info=info)
        if not req.path.startswith(self.upload_path):
            return self.app(environ, start_response)
        try:
            self.handle(env)
        except Error as e:
            self.finish_error(env, e)

        if not env.temp['upload_finished']:
            return resp(environ, start_response)

        app_resp = req.get_response(self.app)
        if env.info.get('parts') and app_resp.status == http.OK:
            return resp(environ, start_response)

        return app_resp(environ, start_response)

    def handle(self, env):
        x_method = env.req.headers.get('X-HTTP-Method-Override')
        method = x_method or env.req.method

        uid = self.get_uid_from_url(env.req.url)
        if not uid and method not in ['POST', 'OPTIONS']:
            raise MissingUidError()
        env.temp['uid'] = uid

        version = env.req.headers.get('Tus-Resumable')
        if method != 'OPTIONS':
            if not version:
                raise MissingVersionError()
            if version not in self.versions:
                raise UnsupportedVersionError()
        version = version or self.versions[0]   # OPTIONS version maybe None
        env.temp['version'] = version
        env.resp.headers['Tus-Resumable'] = version

        if method == 'POST':
            self.post(env)
        elif method == 'HEAD':
            self.head(env)
        elif method == 'PATCH':
            self.patch(env)
        elif method == 'OPTIONS':
            self.options(env)
        elif method == 'DELETE':
            self.delete(env)
        else:
            raise MethodNotAllowedError()

    def options(self, env):
        env.resp.headers['Tus-Version'] = ','.join(self.versions)
        env.resp.headers['Tus-Max-Size'] = str(self.max_size)
        env.resp.headers['Tus-Checksum-Algorithm'] = ','.join(self.checksum_algorisums)
        env.resp.headers['Tus-Extension'] = ','.join(self.extensions)
        env.resp.status = http.NO_CONTENT

    def post(self, env):
        if env.temp['uid']:
            raise InvalidUploadPathError()

        self.check_concatenation(env)
        self.check_upload_length(env)
        self.check_metadata(env)
        self.create_files(env)

        env.resp.headers['Upload-Expires'] = self.get_fexpires(env)
        env.resp.headers['Location'] = self.api_base + '/'.join([self.upload_path, env.temp['uid']])
        env.resp.status = http.CREATED

    def head(self, env):
        upload_offset = self.get_current_offset(env)
        upload_length = self.get_end_length(env)
        upload_metadata = self.get_metadata(env)

        env.resp.headers['Upload-Offset'] = str(upload_offset)

        if upload_length == -1:
            env.resp.headers['Upload-Defer-Length'] = '1'
        elif upload_length == -2:
            pass
        else:
            env.resp.headers['Upload-Length'] = str(upload_length)

        if upload_metadata:
            env.resp.headers['Upload-Metadata'] = ','.join(['%s %s' % (k, b64_encode(v))
                                                            for k, v in upload_metadata.items()])
        parts = self.get_parts(env)
        if parts:
            env.resp.headers['Upload-Concat'] = 'final;' + ' '.join([self.get_url_from_uid(env, uid) for uid in parts])

        env.resp.headers['Cache-Control'] = 'no-store'
        env.resp.status = http.OK

    def patch(self, env):
        if env.req.headers.get('Content-Type') != 'application/offset+octet-stream':
            raise InvalidContentTypeError()
        self.check_upload_length(env, post=False)

        upload_checksum = env.req.headers.get('Upload-Checksum')
        if upload_checksum:
            algorisum, checksum_base64 = upload_checksum.split(None, 1)
            if algorisum not in self.checksum_algorisums:
                raise ChecksumAlgorisumsNotSuppertedError()
            checksum = standard_b64decode(checksum_base64.encode('utf-8'))
            body = env.req.body
            if checksum != hashlib.sha1(body).digest():
                raise ChecksumMismatchError()
        current_offset = self.write_data(env)
        if current_offset == self.get_end_length(env):
            self.finish_upload(env)
        if current_offset > env.info['upload_length'] > 0:
            raise ExceedUploadLengthError()

        env.resp.headers['Upload-Offset'] = str(current_offset)
        env.resp.headers['Upload-Expires'] = self.get_fexpires(env)
        env.resp.status = http.NO_CONTENT

    def check_concatenation(self, env):
        upload_concat = env.req.headers.get('Upload-Concat')
        if not upload_concat:
            return
        if upload_concat == 'partial':
            env.info['partial'] = True
        elif upload_concat.startswith('final;'):
            parts = upload_concat[len('final:'):].strip().split()
            env.info['parts'] = [self.get_uid_from_url(p) for p in parts]
        else:
            raise InvalidConcatError()

    def check_upload_length(self, env, post=True):
        '''
        info[upload_length] >= 0 : real upload length
        info[upload_length] == -1 : defer upload length flag
        info[upload_length] == -2 : upload concat final flag
        '''
        upload_length = env.req.headers.get('Upload-Length')
        upload_defer_length = env.req.headers.get('Upload-Defer-Length')
        if upload_length and 'parts' in env.info:
            raise InvalidUploadLengthError()
        if upload_defer_length and upload_length:
            raise ConflictUploadDeferLengthError()
        if post and not (upload_length or upload_defer_length):
            raise MissingUploadLengthError()

        if upload_defer_length:
            if upload_defer_length != '1':
                raise InvalidUploadDeferLengthError()
            env.info['upload_length'] = -1
        elif upload_length:
            try:
                length = int(upload_length)
            except ValueError:
                raise InvalidUploadLengthError()
            if length < 0:
                raise InvalidUploadLengthError()
            if length > self.max_size:
                raise MaxSizeExceededError()
            env.info['upload_length'] = length
        elif 'parts' in env.info:
            env.info['upload_length'] = -2
        elif not post:  # patch method
            env.info['upload_length'] = self.get_end_length(env)

    def check_metadata(self, env):
        upload_metadata_str = env.req.headers.get('Upload-Metadata')
        if not upload_metadata_str:
            return
        upload_metadata_tuples = [t.strip().split() for t in upload_metadata_str.split(',')]
        upload_metadata = dict()
        for t in upload_metadata_tuples:
            try:
                k, v = t
            except ValueError:
                raise InvalidUploadMetadataError()
            try:
                upload_metadata[k] = b64_decode(v)
            except:
                raise InvalidUploadMetadataError()
        env.info['upload_metadata'] = upload_metadata

    def get_uid_from_url(self, url):
        path = urlparse.urlparse(url).path
        uid = os.path.relpath(path, self.upload_path)
        if uid == '.':
            return None
        if '/' in uid:
            raise InvalidUidError()
        return uid

    def get_url_from_uid(self, env, uid=None):
        if not uid:
            uid = env.temp['uid']
        url = '/'.join([self.upload_path, uid])
        return url

    def delete(self, env):
        self.delete_files(env)
        env.resp.status = http.NO_CONTENT

    def finish_upload(self, env):
        info_path = self.get_info_path(env)
        if not os.path.exists(info_path):
            raise NotFoundError()
        with open(info_path, 'r') as f:
            config = json.load(f)
        if config['partial']:
            return
        env.temp['upload_finished'] = True
        if self.send_file:
            env.req.body = open(self.get_fpath(env), 'rb').read()
        else:
            env.req.body = self.get_fpath(env).encode('utf-8')

    def create_files(self, env):
        self.cleanup()
        info = dict()
        info['partial'] = env.info.get('partial', False)
        info['parts'] = env.info.get('parts')
        info['upload_metadata'] = env.info.get('upload_metadata')

        uid = uuid.uuid4().hex
        fpath = self.get_fpath(env, uid)
        while os.path.exists(fpath):
            uid = uuid.uuid4().hex
            fpath = self.get_fpath(uid)
        env.temp['uid'] = uid
        with open(fpath, 'wb') as _:
            pass
        if info['parts']:
            self.concat_parts(env, fpath)

        info['upload_length'] = env.info['upload_length']
        info_path = self.get_info_path(env, uid)
        with open(info_path, 'w') as f:
            json.dump(info, f, indent=4)
        return uid

    def check_parts(self, env):
        parts = env.info['parts']
        for uid in parts:
            info_path = self.get_info_path(env, uid)
            if os.path.exists(info_path):
                raise UploadNotFinishedError()

    def concat_parts(self, env, fpath):
        self.check_parts(env)
        parts = env.info['parts']
        with open(fpath, 'wb') as f:
            for uid in parts:
                uid_fp = open(self.get_fpath(env, uid), 'rb')
                shutil.copyfileobj(uid_fp, f)
        env.info['upload_length'] = os.path.getsize(fpath)

    def delete_files(self, env):
        fpath = self.get_fpath(env)
        info_path = self.get_info_path(env)
        if os.path.exists(fpath):
            os.remove(fpath)
        if os.path.exists(info_path):
            os.remove(info_path)

    def check_files(self, env):
        fpath = self.get_fpath(env)
        info_path = self.get_info_path(env)
        if not os.path.exists(fpath) or not os.path.exists(info_path):
            raise NotFoundError()
        with open(info_path, 'r') as f:
            config = json.load(f)
        modify_flag = False

        length = env.info['upload_length']
        cur_length = config['upload_length']
        if cur_length == -1 and length != -1:
            config['upload_length'] = length
            modify_flag = True
        elif cur_length != -1 and length != cur_length:
            raise ConflictUploadLengthError()

        if config['upload_metadata'] != env.info['upload_metadata']:
            config['upload_metadata'].update(env.info['upload_metadata'])
            modify_flag = True

        if modify_flag:
            with open(info_path, 'w') as f:
                json.dump(config, f, indent=4)

    def get_fpath(self, env, uid=None):
        uid = uid or env.temp['uid']
        return os.path.join(self.tmp_dir, uid)

    def get_info_path(self, env, uid=None):
        fpath = self.get_fpath(env, uid)
        return fpath + '.info'

    def get_current_offset(self, env):
        fpath = self.get_fpath(env)
        if not os.path.exists(fpath):
            raise NotFoundError()
        return os.path.getsize(fpath)

    def get_end_length(self, env):
        self.load_info_data(env)
        parts = env.info['parts']
        if not parts:
            return env.info['upload_length']
        upload_length = 0
        for uid in parts:
            uid_info_path = self.get_info_path(env, uid)
            with open(uid_info_path, 'r') as f:
                uid_info = json.load(f)
                if uid_info['upload_length'] == -1:
                    return -2  # Upload-Concat
                upload_length += uid_info['upload_length']
        return upload_length

    def get_metadata(self, env):
        self.load_info_data(env)
        return env.info['upload_metadata']

    def get_parts(self, env):
        self.load_info_data(env)
        return env.info['parts']

    def is_partial(self, env):
        self.load_info_data(env)
        return env.info['partial']

    def load_info_data(self, env):
        if env.temp['info_loaded']:
            return
        info_path = self.get_info_path(env)
        if not os.path.exists(info_path):
            raise NotFoundError()
        with open(info_path, 'r') as f:
            info = json.load(f)
        env.info.update(info)
        env.temp['info_loaded'] = True

    def get_fexpires(self, env):
        fpath = self.get_fpath(env)
        if not os.path.exists(fpath):
            raise NotFoundError()
        seconds = os.path.getmtime(fpath) + self.expire
        # rfc 7231  datetime format
        return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(seconds))

    def write_data(self, env):
        fpath = self.get_fpath(env)
        info_path = self.get_info_path(env)
        if not os.path.exists(fpath) or not os.path.exists(info_path):
            raise NotFoundError()

        with open(info_path, 'r') as f:
            info = json.load(f)
        cur_length = info['upload_length']
        length = env.info['upload_length']
        if cur_length != -1 and length != cur_length:
            raise ConflictUploadLengthError()

        body = env.req.body_file_seekable
        with open(fpath, 'ab+') as f:
            f.seek(0, os.SEEK_END)
            body.seek(0)
            shutil.copyfileobj(body, f)
            offset = f.tell()

        if cur_length == -1 and length >= 0:
            info['upload_length'] = length
            with open(info_path, 'w') as f:
                json.dump(info, f)
        else:
            os.utime(info_path, None)

        return offset

    def finish_error(self, env, error):
        env.resp.status = '%i %s' % (error.status_code, error.reason)

    def cleanup(self):
        for fname in os.listdir(self.tmp_dir):
            fpath = os.path.join(self.tmp_dir, fname)
            if os.path.isfile(fpath) and time.time() - os.path.getmtime(fpath) > self.expire:
                os.remove(fpath)
