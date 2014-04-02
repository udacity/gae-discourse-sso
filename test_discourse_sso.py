import hashlib
import hmac
import unittest
import urllib

import webapp2

import discourse_sso


class DummyHandler(discourse_sso.DiscourseSSOHandler):
    SSO_SECRET = 'secret'
    DISCOURSE_URL = 'http://example.com'

    def getUser(self):
        return self.user

    def redirectToLogin(self):
        self.redirect_called = True

    def redirect(self, url):
        self.redirected_url = url

    def abort(self, error_code):
        self.abort_error_code = error_code


class TestDiscourseSSOHandler(unittest.TestCase):
    def testCallsRedirectWhenNoUser(self):
        handler = DummyHandler()
        handler.user = None

        handler.get()

        self.assertTrue(handler.redirect_called)

    def _generateValues(self, sso):
        sso = urllib.urlencode(sso).encode('base64')
        sig = hmac.new(DummyHandler.SSO_SECRET, sso, hashlib.sha256).hexdigest()
        return sso, sig

    def testCompleteFlow(self):
        handler = DummyHandler()
        handler.user = {'id': 1}
        handler.request = webapp2.Request.blank('/')
        handler.request.GET['sso'], handler.request.GET['sig'] = self._generateValues({'nonce': 42})

        handler.get()

        expected_sso = urllib.urlencode({'external_id': 1, 'nonce': 42}).encode('base64')
        expected_sig = hmac.new(DummyHandler.SSO_SECRET, expected_sso, hashlib.sha256).hexdigest()

        self.assertEquals(
            '%s?%s' % (
                DummyHandler.DISCOURSE_URL,
                urllib.urlencode({'sso': expected_sso, 'sig': expected_sig})
            ),
            handler.redirected_url
        )

    def testAbortOnInvalidSig(self):
        handler = DummyHandler()
        handler.user = {'id': 1}
        handler.request = webapp2.Request.blank('/')
        handler.request.GET['sso'], _ = self._generateValues({'nonce': 42})
        handler.request.GET['sig'] = 'a'

        handler.redirected_url = None
        handler.get()

        self.assertEquals(500, handler.abort_error_code)
        self.assertIsNone(handler.redirected_url)


if __name__ == '__main__':
    unittest.main()
