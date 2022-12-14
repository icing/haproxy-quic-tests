import logging
import time

import pytest

from testenv import Env, HAProxy, Httpd, CurlClient, OpensslClient

log = logging.getLogger(__name__)


class TestTlsHandshake:

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

    @pytest.fixture(scope='class')
    def curl(self, env, httpd) -> CurlClient:
        curl = CurlClient(env=env)
        yield curl

    @pytest.fixture(scope='class')
    def openssl(self, env, httpd) -> OpensslClient:
        openssl = OpensslClient(env=env)
        yield openssl

    def test_02_01_openssl(self, env: Env, openssl: OpensslClient, ha: HAProxy):
        # simple connect, no options, expect 1.3 and a session
        url = f'https://{env.example_domain}:{env.haproxy_port}/data.json'
        r = openssl.connect(url=url, intext='blabla')
        assert r.exit_code == 0, f'{r}'
        assert r.response, f'{r}'
        assert r.response['protocol'] == 'TLSv1.3', f'{"".join(r.stdout)}'
        assert r.response['session'], f'{r}'
        assert r.response['session']['ticket'], f'{r}'

    def test_02_02_curl_get(self, env: Env, curl: CurlClient, ha: HAProxy):
        r = curl.http_get(url=f'https://{env.example_domain}:{env.haproxy_port}/data.json')
        assert r.exit_code == 0, f'{r}'
        assert r.response, f'{r}'
        assert r.response['status'] == 200, f'{r}'
        assert r.json, f'{r}'

