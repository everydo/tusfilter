from tusfilter import TusFilter
from flask import Flask

app = Flask(__name__)


@app.route("/upload_resumable/<tmpfile>", methods=['PATCH'])
def upload_resumable(tmpfile):
    # do something else
    return 'End of upload'


app.wsgi_app = TusFilter(
    app.wsgi_app,
    tmp_dir='/tmp/upload',
    upload_path='/upload_resumable',
)
