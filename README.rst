=========
tusfilter
=========

python wsgi filter for tus protocol 1.0.0, `the tus resumable upload standard`_.

.. _the tus resumable upload standard: http://tus.io/


install
-------

::

    pip install tusfilter


Arguments
---------

`app`
    required, the wsgi server application

`upload_path`
    `str`, required, path of the upload service

`tmp_dir`
    `str`, optional, directory to store temporary files, default `/upload`

`expire`
    `int`, optional, how long before cleanup old uploads in seconds, default `60*60*60`

`send_file`
    `bool`, optional, `False` for send the absolute filepath in `tmp_dir` in the request body,
    `True` for an actual file uploaded, default `False`


Example
-------

flask ::

    from tusfilter import TusFilter
    from flask import Flask, request

    app = Flask(__name__)


    @app.route("/upload_resumable/<tmpfile>", methods=['POST', 'PATCH'])
    def upload_rev(tmpfile):
        print request.data
        # do something else
        return 'End of upload'


    app = TusFilter(app, upload_path='/upload_resumable', tmp_dir='/tmp/upload')
