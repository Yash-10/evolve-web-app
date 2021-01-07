import os
import requests

from flask import render_template, redirect, request,session
from functools import wraps

def login_required(f):
    '''
    Decorates routes to require login
    '''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/home")
        return f(*args, **kwargs)
    return decorated_function