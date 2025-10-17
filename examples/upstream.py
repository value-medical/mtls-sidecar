import base64
import json
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    header = request.headers.get('X-Client-TLS-Info', '')
    if header:
        info = json.loads(base64.b64decode(header).decode('utf-8'))
        client_subject = info.get('subject', None)
        return f"Client Subject: {client_subject}"
    return "Unauthorized", 401

app.run(port=8080, debug=True)

