import libuser
import random
import hashlib
import re
import jwt
import os
from time import time

from pathlib import Path

# Retrieve JWT secret from environment variable
# This prevents hardcoding sensitive credentials in source code (CWE-798)
secret = os.getenv('JWT_SECRET', '').strip()
if not secret:
    raise ValueError('JWT_SECRET environment variable must be set to a non-empty value for secure JWT token generation')

not_after = 60 # 1 minute

def keygen(username, password=None, login=True):

    if login:
        if not libuser.login(username, password):
            return None

    now = time()
    token = jwt.encode({
        'username': username,
        'nbf': now,
        'exp': now + not_after
        }, secret, algorithm='HS256')

    return token


def authenticate(request):

    if 'authorization' not in request.headers:
        return None

    try:
        authtype, token = request.headers['authorization'].split(' ')
    except Exception as e:
        print(e)
        return None

    if authtype.lower() != 'bearer':
        print('not bearer')
        return None

    try:
        decoded = jwt.decode(token, secret, algorithms=['HS256'])
    except Exception as e:
        print(e)
        return None

    return decoded['username']

