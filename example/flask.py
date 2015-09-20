from tusfilter import TusFilter
from flask import Flask, request

app = Flask(__name__)


@app.route("/upload_resumable/<tmpfile>", methods=['POST', 'PATCH'])
def upload_rev(tmpfile):
    print request.data
    # do something else
    return 'End of upload'


app = TusFilter(app, tmp_dir='/tmp/upload', upload_path='/upload_resumable')
