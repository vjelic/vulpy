#!/usr/bin/env python3

from flask import Flask, g, redirect, request
import os

from mod_hello import mod_hello
from mod_user import mod_user
from mod_posts import mod_posts
from mod_mfa import mod_mfa

import libsession

app = Flask('vulpy')
app.config['SECRET_KEY'] = 'aaaaaaa'

app.register_blueprint(mod_hello, url_prefix='/hello')
app.register_blueprint(mod_user, url_prefix='/user')
app.register_blueprint(mod_posts, url_prefix='/posts')
app.register_blueprint(mod_mfa, url_prefix='/mfa')


@app.route('/')
def do_home():
    return redirect('/posts')

@app.before_request
def before_request():
    g.session = libsession.load(request)

# Use secure directory for SSL certificates instead of world-writable /tmp
cert_dir = os.path.join(os.path.dirname(__file__), 'certs')
os.makedirs(cert_dir, exist_ok=True)
cert_path = os.path.join(cert_dir, 'acme.cert')
key_path = os.path.join(cert_dir, 'acme.key')

app.run(debug=True, host='127.0.1.1', ssl_context=(cert_path, key_path))
