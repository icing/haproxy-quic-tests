import logging
import pytest

from testenv import Env


@pytest.mark.usefixtures("env")
def pytest_report_header(config):
    env = Env()
    return [
        f"ngtcp2-httpd: [haproxy {env.haproxy_version}, {env.haproxy_ssl}]",
        f"ngtcp2 example clients: {env.crypto_libs()}",
    ]


@pytest.fixture(scope="package")
def env(pytestconfig) -> Env:
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    env = Env(pytestconfig=pytestconfig)
    level = logging.DEBUG if env.verbose > 0 else logging.INFO
    console.setLevel(level)
    logging.getLogger('').setLevel(level=level)
    env.setup()

    return env
