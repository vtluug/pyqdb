# -*- coding: utf-8 -*-
from functools import wraps
from flask import request, Response

class FlaskRealmDigestDB():
    def __init__(self):
        self.users = {}

    def requires_auth(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            if not auth or not self.check_auth(auth.username, auth.password):
                return authenticate()
            return f(*args, **kwargs)
        return decorated

    def authenticate(self):
        return Response(
                'Login Required. RIP.', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})

    def check_auth(self, username, password):
        return self.users[username] == password

    def add_user(self, username, password):
        self.users[username] = password

    def isAuthenticated(self, request):
        return request.authorization
