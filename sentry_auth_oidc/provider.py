from __future__ import absolute_import, print_function

import requests

from sentry.auth.providers.oauth2 import (
    OAuth2Callback, OAuth2Provider, OAuth2Login
)
from .constants import (
    AUTHORIZATION_ENDPOINT,
    ISSUER, TOKEN_ENDPOINT,
    CLIENT_SECRET,
    CLIENT_ID,
    SCOPE, DATA_VERSION
)
from .views import FetchUser, OIDCConfigureView
import logging
logger = logging.getLogger('sentry.auth.oidc')


class OIDCLogin(OAuth2Login):
    authorize_url = AUTHORIZATION_ENDPOINT
    client_id = CLIENT_ID
    scope = SCOPE

    def __init__(self, domains=None):
        self.domains = domains
        super(OIDCLogin, self).__init__()

    def get_authorize_params(self, state, redirect_uri):
        params = super(OIDCLogin, self).get_authorize_params(
            state, redirect_uri
        )
        # TODO(dcramer): ideally we could look at the current resulting state
        # when an existing auth happens, and if they're missing a refresh_token
        # we should re-prompt them a second time with ``approval_prompt=force``
        params['approval_prompt'] = 'force'
        params['access_type'] = 'offline'
        return params

class OIDCCallback(OAuth2Callback):
    def exchange_token(self, request, helper, code):
        data = self.get_token_params(
            code=code,
            redirect_uri=absolute_uri(helper.get_redirect_url()),
        )
        req = safe_urlopen(self.access_token_url, data=data)
        body = safe_urlread(req)

        logger.info('Response from DEX server',
            extra={
                'body': body,
            }
        )

        if req.headers['Content-Type'].startswith('application/x-www-form-urlencoded'):
            return dict(parse_qsl(body))
        return json.loads(body)

class OIDCProvider(OAuth2Provider):
    name = ISSUER
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET

    def __init__(self, domain=None, domains=None, version=None, **config):
        if domain:
            if domains:
                domains.append(domain)
            else:
                domains = [domain]
        self.domains = domains
        # if a domain is not configured this is part of the setup pipeline
        # this is a bit complex in Sentry's SSO implementation as we don't
        # provide a great way to get initial state for new setup pipelines
        # vs missing state in case of migrations.
        if domains is None:
            version = DATA_VERSION
        else:
            version = None
        self.version = version
        super(OIDCProvider, self).__init__(**config)

    def get_configure_view(self):
        return OIDCConfigureView.as_view()

    def get_auth_pipeline(self):
        return [
            OIDCLogin(domains=self.domains),
            OIDCCallback(
                access_token_url=TOKEN_ENDPOINT,
                client_id=self.client_id,
                client_secret=self.client_secret,
            ),
            FetchUser(
                domains=self.domains,
                version=self.version,
            ),
        ]

    def get_refresh_token_url(self):
        return TOKEN_ENDPOINT

    def build_config(self, state):
        return {
            'domains': [state['domain']],
            'version': DATA_VERSION,
        }

    def build_identity(self, state):
        data = state['data']
        user_data = state['user']
        user_email = user_data.get('email')
        user_name = user_email.split('@')[0]

        return {
            'id': user_data.get('sub'),
            'email': user_data.get('email'),
            'email_verified': user_data.get('email_verified'),
            'nickname': user_name,
            'name': user_name,
            'data': self.get_oauth_data(data),
        }
