import logging
import time

import pytest

from testenv import Env, HAProxy, Httpd
from testenv import ExampleClient


log = logging.getLogger(__name__)


class TestQuicHandshake:

    @pytest.fixture(scope='class')
    def httpd(self, env) -> Httpd:
        httpd = Httpd(env=env)
        assert httpd.exists(), f'httpd not found: {env.httpd}'
        assert httpd.start()
        yield httpd
        httpd.stop()

    @pytest.fixture(scope='class')
    def ha(self, env, httpd) -> HAProxy:
        ha = HAProxy(env=env)
        assert ha.exists(), f'haproxy not found: {ha.path}'
        assert ha.start()
        yield ha
        ha.stop()

    @pytest.fixture(scope='function', params=Env.crypto_libs())
    def client(self, env, request) -> ExampleClient:
        client = ExampleClient(env=env, crypto_lib=request.param)
        assert client.exists()
        yield client

    # naked connection, get
    def test_01_01_get(self, env: Env, client: ExampleClient, ha: HAProxy):
        # run simple GET, no sessions, needs to give full handshake
        cr = client.http_get(url=f'https://{env.example_domain}/data.json')
        assert cr.returncode == 0
        cr.assert_non_resume_handshake()

    # session resumption, get
    def test_01_02(self, env: Env, client: ExampleClient, ha: HAProxy):
        # run GET with sessions but no early data, cleared first, then reused
        client.clear_session()
        cr = client.http_get(url=f'https://{env.example_domain}/data.json',
                             use_session=True,
                             extra_args=['--disable-early-data'])
        assert cr.returncode == 0
        cr.assert_non_resume_handshake()
        # Now do this again and we expect a resumption, meaning no certificate
        cr = client.http_get(url=f'https://{env.example_domain}/data.json',
                             use_session=True,
                             extra_args=['--disable-early-data'])
        assert cr.returncode == 0
        cr.assert_resume_handshake()
        # restart the server, do it again
        ha.restart()
        cr = client.http_get(url=f'https://{env.example_domain}/data.json',
                             use_session=True,
                             extra_args=['--disable-early-data'])
        assert cr.returncode == 0
        cr.assert_non_resume_handshake()

    def test_01_03(self, env: Env, client: ExampleClient, ha: HAProxy):
        # run GET with sessions, cleared first, without a session, early
        # data will not even be attempted
        client.clear_session()
        edata = 'This is the early data. It is not much.'
        cr = client.http_get(url=f'https://{env.example_domain}/data.json',
                             use_session=True, data=edata)
        assert cr.returncode == 0
        cr.assert_non_resume_handshake()
        # resume session, early data is sent and accepted
        cr = client.http_get(url=f'https://{env.example_domain}/data.json',
                             use_session=True, data=edata)
        assert cr.returncode == 0
        cr.assert_resume_handshake()
        assert not cr.early_data_rejected
        # restart the server, resume, early data is attempted but will not work
        ha.restart()
        cr = client.http_get(url=f'https://{env.example_domain}/data.json',
                             use_session=True, data=edata)
        assert cr.returncode == 0
        if not cr.early_data_rejected:
            logging.info('HAProxy did not reject early data after restart')
        cr.assert_non_resume_handshake()
        # restart again, sent data, but not as early data
        ha.restart()
        cr = client.http_get(url=f'https://{env.example_domain}/data.json',
                             use_session=True, data=edata,
                             extra_args=['--disable-early-data'])
        assert cr.returncode == 0
        # we see no rejection, since it was not used
        assert not cr.early_data_rejected
        cr.assert_non_resume_handshake()
