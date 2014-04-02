"""
Example usage for using DiscourseSSOHandler:
- set SSO_SECRET to the same value as sso_secret from the Discourse settings
- setup DISCOURSE_URL
- set enable_sso in Discourse and set sso_url to http://localhost:8080/
"""

import sys
sys.path.insert(0, '..')

import discourse_sso
from google.appengine.api import users
import hashlib
import hmac
import webapp2


class SSOHandler(discourse_sso.DiscourseSSOHandler):
    USER_ID_HMAC_KEY = 'superkalifragilistikexpialigetisch'
    SSO_SECRET = 'secret-secret-secret'
    DISCOURSE_URL = 'https://discourse_host/session/sso_login'

    def getUser(self):
        user = users.get_current_user()
        return {
            # hash the user id to avoid leaking it to the external system
            'id': hmac.new(self.USER_ID_HMAC_KEY, user.user_id(), hashlib.sha256).hexdigest(),
            'username': user.nickname(),
            'email': user.email(),
        }

    def redirectToLogin(self):
        # taken care by app.yaml
        pass


APP = webapp2.WSGIApplication([
    webapp2.Route('/', SSOHandler)
])
