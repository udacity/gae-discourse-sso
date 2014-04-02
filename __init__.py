"""
An implementation of the Discourse SSO protocol [1] using webapp2 handlers.

[1] https://meta.discourse.org/t/official-single-sign-on-for-discourse/13045
"""
import hashlib
import hmac
import itertools
import urllib
import urlparse
import logging

import webapp2


def _equalsSlowly(a, b):
    """Constant time equality of two strings (given a constant length) to prevent timing attacks"""
    diff = len(a) ^ len(b)
    for ca, cb in itertools.izip(a, b):
        diff |= ord(ca) ^ ord(cb)
    return not diff


class DiscourseSSOHandler(webapp2.RequestHandler):
    """Handler to execute the Discourse SSO flow. To use this:
    - extend this class
    - set SSO_SECRET and DISCOURSE_URL
    - implement the getUser and redirectToLogin method
    """

    """The value of sso_secret from Discourse settings"""
    SSO_SECRET = None
    """
    The URL where to redirect back after successful sign-in. Something like:
    https://discourse_site/session/sso_login
    """
    DISCOURSE_URL = None

    def getUser(self):
        """Override this function and return:
        - None if the user is not logged in and redirectToLogin needs to be called
        - A dictionary with information about the current user which needs to be passed back to
        Discourse. The dictionary should have the following keys:
            - id - a unique ID of the user in your system
            - username - the nickname of the user which should be used for the Discourse account
            - email - email of the user
            - name - full name of the user
        """
        raise NotImplementedError()

    def redirectToLogin(self):
        """Override this function to redirect the user to the sign-in page.
        The sign-in page should redirect the user back to the original SSO url to complete the flow.
        """
        raise NotImplementedError()

    def get(self):
        assert self.SSO_SECRET, "SSO_SECRET not set"
        assert self.DISCOURSE_URL, "DISCOURSE_URL not set"

        user = self.getUser()
        if user is None:
            self.redirectToLogin()
            return

        sso = self.request.GET['sso']
        sig = self.request.GET['sig']
        expected_sig = hmac.new(self.SSO_SECRET, sso, hashlib.sha256).hexdigest()
        if not _equalsSlowly(expected_sig, sig):
            logging.error('Discourse SSO: HMACs do not match')
            self.abort(500)
            return

        sso = urlparse.parse_qs(sso.decode('base64'))
        nonce = sso['nonce'][0]

        user_key_mappings = {
            'id': 'external_id',
            'username': 'username',
            'email': 'email',
            'name': 'name',
        }
        user = {user_key_mappings[k]: v for k, v in user.iteritems() if k in user_key_mappings}
        user['nonce'] = nonce

        sso = urllib.urlencode(user).encode('base64')
        sig = hmac.new(self.SSO_SECRET, sso, hashlib.sha256).hexdigest()

        self.redirect(
            '%s?%s' % (
                self.DISCOURSE_URL,
                urllib.urlencode({'sso': sso, 'sig': sig})
            )
        )
