# coding: utf-8

import os
import time
import json
import uuid
import webob
import base64
import hashlib
import httplib
import urlparse
from collections import namedtuple


class Error(Exception):
    status_code = 0
    reason = ''


class NotFoundError(Error):
    status_code = httplib.NOT_FOUND
    reason = 'Not Found'


class NotImplementedError(Error):
    status_code = httplib.NOT_IMPLEMENTED
    reason = 'Feature Not Implemented'


class InvalidUploadPathError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Invalid Upload Path'


class MethodNotAllowedError(Error):
    status_code = httplib.METHOD_NOT_ALLOWED
    reason = 'Method Not Allowed'


class MissingVersionError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Missing Tus-Resumable Header'


class UnsupportedVersionError(Error):
    status_code = httplib.PRECONDITION_FAILED
    reason = 'Precondition Failed'


class InvalidUidError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Invalid Uid Part In Url'


class MissingUidError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Missing Uid Part In Url'


class MaxSizeExceededError(Error):
    status_code = httplib.REQUEST_ENTITY_TOO_LARGE
    reason = 'Request Entity Too Large'


class InvalidUploadLengthError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Invalid Upload-Length Header'


class ConflictUploadLengthError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Conflict Upload-Length'


class MissingUploadLengthError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Missing Upload-Length Header'


class ExceedUploadLengthError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Exceed Upload-Length'


class InvalidUploadDeferLengthError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Invalid Upload-Defer-Length Header'


class ConflictUploadDeferLengthError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Conflict Upload-Defer-Length Header'


class InvalidUploadOffsetError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Invalid Upload-Offset Header'


class ConflictUploadOffsetError(Error):
    status_code = httplib.CONFLICT
    reason = 'Conflict'


class MissingUploadOffsetError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Missing Upload-Offset Header'


class InvalidUploadMetadataError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Invalid Upload-Metadata Header'


class InvalidContentTypeError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Invalid Content-Type Header'


class ChecksumAlgorisumsNotSuppertedError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Bad Request'


class ChecksumMismatchError(Error):
    status_code = 460
    reason = 'Checksum Mismatch'


class FileLockedError(Error):
    status_code = httplib.LOCKED
    reason = 'File Currently Locked'


class UploadNotFinishedError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'One Of The Partial Uploads Is Not Finished'


class InvalidConcatError(Error):
    status_code = httplib.BAD_REQUEST
    reason = 'Invalid Upload-Concat Header'


class ModifyFinalError(Error):
    status_code = httplib.FORBIDDEN
    reason = 'Modifying A Final Upload Is Not Allowed'


Env = namedtuple('Env', ['req', 'resp', 'values'])


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

    def __init__(self, app, upload_path, tmp_dir='/tmp/upload', expire=60*60*60, send_file=False, max_size=2**30):
        self.app = app
        self.tmp_dir = tmp_dir
        self.upload_path = upload_path
        self.expire = expire
        self.send_file = send_file
        self.max_size = max_size

        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)

    def __call__(self, environ, start_response):
        req = webob.Request(environ)
        resp = webob.Response()
        values = dict(upload_finished=False)
        env = Env(req=req, resp=resp, values=values)
        if not req.path.startswith(self.upload_path):
            return self.app(environ, start_response)
        try:
            self.handle(env)
        except Error as e:
            self.finish_error(env, e)

        if not env.values['upload_finished']:
            return resp(environ, start_response)

        app_resp = req.get_response(self.app)
        if env.values.get('parts') and app_resp.status == httplib.OK:
            return resp(environ, start_response)

        self.delete_info_file(env)
        return app_resp(environ, start_response)

    def handle(self, env):
        x_method = env.req.headers.get('X-HTTP-Method-Override')
        method = x_method or env.req.method

        uid = self.get_uid_from_url(env.req.url)
        if method not in ['POST', 'OPTIONS'] and not uid:
            raise MissingUidError()
        env.values['uid'] = uid

        version = env.req.headers.get('Tus-Resumable')
        if method != 'OPTIONS':
            if not version:
                raise MissingVersionError()
            if version not in self.versions:
                raise UnsupportedVersionError()
        version = version or self.versions[0]   # OPTIONS version maybe None
        env.values['version'] = version
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
        env.resp.status = httplib.NO_CONTENT

    def post(self, env):
        if env.values['uid']:
            raise InvalidUploadPathError()

        self.check_upload_length(env)
        self.check_concatenation(env)
        self.check_metadata(env)
        self.create_files(env)

        env.resp.headers['Upload-Expires'] = self.get_fexpires(env)
        env.resp.headers['Location'] = os.path.join(self.upload_path, env.values['uid'])
        env.resp.status = httplib.CREATED

    def head(self, env):
        upload_offset = self.get_current_offset(env)
        upload_length = self.get_end_length(env)
        upload_metadata = self.get_metadata(env)
        env.resp.headers['Upload-Offset'] = str(upload_offset)
        if upload_length == -1:
            env.resp.headers['Upload-Defer-Length'] = '1'
        else:
            env.resp.headers['Upload-Length'] = str(upload_length)
        if upload_metadata:
            env.resp.headers['Upload-Metadata'] = str(','.join(['%s %s' % (t[0], base64.standard_b64encode(t[1]))
                                                                for t in upload_metadata.items()]))
        env.resp.headers['Cache-Control'] = 'no-store'
        env.resp.status = httplib.OK

    def patch(self, env):
        if env.req.headers.get('Content-Type') != 'application/offset+octet-stream':
            raise InvalidContentTypeError()
        self.check_upload_length(env, post=False)

        upload_checksum = env.req.headers.get('Upload-Checksum')
        if upload_checksum:
            algorisum, checksum_base64 = upload_checksum.strip().split(None, 1)
            if algorisum not in self.checksum_algorisums:
                raise ChecksumAlgorisumsNotSuppertedError()
            checksum = base64.standard_b64decode(checksum_base64)
            body = env.req.body
            if checksum != hashlib.sha1(body).digest():
                raise ChecksumMismatchError()
        current_offset = self.write_data(env)
        if current_offset == self.get_end_length(env):
            self.finish_upload(env)
        if current_offset > env.values['upload_length'] > 0:
            raise ExceedUploadLengthError()

        env.resp.headers['Upload-Offset'] = str(current_offset)
        env.resp.headers['Upload-Expires'] = self.get_fexpires(env)
        env.resp.status = httplib.NO_CONTENT

    def check_upload_length(self, env, post=True):
        upload_length = env.req.headers.get('Upload-Length')
        upload_defer_length = env.req.headers.get('Upload-Defer-Length')
        if upload_defer_length and upload_length:
            raise ConflictUploadDeferLengthError()
        if post and not (upload_length or upload_defer_length):
            raise MissingUploadLengthError()

        if upload_defer_length:
            if upload_defer_length != '1':
                raise InvalidUploadDeferLengthError()
            env.values['upload_length'] = -1   # defer flag (== -1) or real length (>= 0)
        elif upload_length:
            try:
                length = int(upload_length)
            except ValueError:
                raise InvalidUploadLengthError()
            if length < 0:
                raise InvalidUploadLengthError()
            if length > self.max_size:
                raise MaxSizeExceededError()
            env.values['upload_length'] = length
        else:
            # in PATCH
            env.values['upload_length'] = self.get_end_length(env)

    def check_concatenation(self, env):
        upload_concat = env.req.headers.get('Upload-Concat')
        if not upload_concat:
            return
        if upload_concat == 'partial':
            env.values['partial'] = True
        elif upload_concat.startswith('final;'):
            parts = upload_concat[len('final:'):].strip().split()
            env.values['parts'] = [self.get_uid_from_url(p) for p in parts]
        else:
            raise InvalidConcatError()

    def check_metadata(self, env):
        upload_metadata = dict()
        upload_metadata_str = env.req.headers.get('Upload-Metadata')
        if not upload_metadata_str:
            return
        upload_metadata_tuples = [v.strip().split() for v in upload_metadata_str.split(',')]
        for t in upload_metadata_tuples:
            if len(t) != 2:
                raise InvalidUploadMetadataError()
            try:
                upload_metadata[t[0]] = base64.standard_b64decode(t[1])
            except:
                raise InvalidUploadMetadataError()
        env.values['upload_metadata'] = upload_metadata

    def get_uid_from_url(self, url):
        path = urlparse.urlparse(url).path
        uid = path[len(self.upload_path):].lstrip('/')
        if not uid:
            return None
        if '/' in uid:
            raise InvalidUidError()
        return uid

    def delete(self, env):
        self.delete_files(env)
        env.resp.status = httplib.NO_CONTENT

    def finish_upload(self, env):
        info_path = self.get_info_path(env)
        if not os.path.exists(info_path):
            raise NotFoundError()
        with open(info_path, 'r') as f:
            config = json.load(f)
        if config['partial']:
            return
        env.values['upload_finished'] = True
        env.req.body = self.get_fpath(env) if not self.send_file else open(self.get_fpath(env), 'rb').read()

    def create_files(self, env):
        self.cleanup()
        config = dict()
        config['partial'] = env.values.get('partial', False)
        config['parts'] = env.values.get('parts', None)
        config['upload_metadata'] = env.values.get('upload_metadata', None)

        uid = uuid.uuid4().hex
        fpath = self.get_fpath(env, uid)
        info_path = self.get_info_path(env, uid)
        while os.path.exists(fpath):
            uid = uuid.uuid4().hex
            fpath = self.get_fpath(uid)
        env.values['uid'] = uid
        with open(fpath, 'wb') as _:
            pass
        if config['parts']:
            self.concat_parts(env, fpath)

        config['upload_length'] = env.values['upload_length']
        with open(info_path, 'w') as f:
            json.dump(config, f, indent=4)
        return uid

    def concat_parts(self, env, fpath):
        parts = env.values['parts']
        for uid in parts:
            info_path = self.get_info_path(env, uid)
            if os.path.exists(info_path):
                raise UploadNotFinishedError()

        with open(fpath, 'wb') as f:
            for uid in parts:
                uid_fp = open(self.get_fpath(env, uid), 'rb')
                f.write(uid_fp.read())

        env.values['upload_length'] = os.path.getsize(fpath)

    def delete_files(self, env):
        fpath = self.get_fpath(env)
        if not os.path.exists(fpath):
            raise NotFoundError()
        os.remove(fpath)
        self.delete_info_file(env)

    def delete_info_file(self, env):
        info_path = self.get_info_path(env)
        if not os.path.exists(info_path):
            raise NotFoundError()
        os.remove(info_path)

    def check_files(self, env):
        fpath = self.get_fpath(env)
        info_path = self.get_info_path(env)
        if not os.path.exists(fpath) or not os.path.exists(info_path):
            raise NotFoundError()
        with open(info_path, 'r') as f:
            config = json.load(f)
        modify_flag = False

        length = env.values['upload_length']
        cur_length = config['upload_length']
        if cur_length == -1 and length != -1:
            config['upload_length'] = length
            modify_flag = True
        elif cur_length != -1 and length != cur_length:
            raise ConflictUploadLengthError()

        if config['upload_metadata'] != env.values['upload_metadata']:
            config['upload_metadata'].update(env.values['upload_metadata'])
            modify_flag = True

        if modify_flag:
            with open(info_path, 'w') as f:
                json.dump(config, f, indent=4)

    def get_fpath(self, env, uid=None):
        uid = uid or env.values['uid']
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
        info_path = self.get_info_path(env)

        if not os.path.exists(info_path):
            raise NotFoundError()
        with open(info_path, 'r') as f:
            config = json.load(f)
        return config['upload_length']

    def get_metadata(self, env):
        info_path = self.get_info_path(env)

        if not os.path.exists(info_path):
            raise NotFoundError()
        with open(info_path, 'r') as f:
            config = json.load(f)
        return config['upload_metadata']

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
        body = env.req.body_file
        if not os.path.exists(fpath) or not os.path.exists(info_path):
            raise NotFoundError()

        with open(info_path, 'r') as f:
            config = json.load(f)
        cur_length = config['upload_length']
        length = env.values['upload_length']
        if cur_length != -1 and length != cur_length:
            raise ConflictUploadLengthError()
        if cur_length == -1 and length >= 0:
            config['upload_length'] = length
            with open(info_path) as f:
                json.dump(config, f)
        else:
            os.utime(info_path, None)

        with open(fpath, 'ab+') as f:
            f.seek(0, os.SEEK_END)
            body.seek(0)
            while True:
                chunk = body.read(2 << 16)
                if not chunk:
                    break
                f.write(chunk)
            offset = f.tell()

        return offset

    def finish_error(self, env, error):
        env.resp.status = '%i %s' % (error.status_code, error.reason)

    def cleanup(self):
        for fname in os.listdir(self.tmp_dir):
            fpath = os.path.join(self.tmp_dir, fname)
            if os.path.isfile(fpath) and time.time() - os.path.getmtime(fpath) > self.expire:
                os.remove(fpath)
