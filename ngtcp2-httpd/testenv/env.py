import logging
import os
import re
import subprocess
import sys
from configparser import ConfigParser, ExtendedInterpolation
from typing import Dict, Optional

from .certs import CertificateSpec, TestCA, Credentials

log = logging.getLogger(__name__)


def init_config_from(conf_path):
    if os.path.isfile(conf_path):
        config = ConfigParser(interpolation=ExtendedInterpolation())
        config.read(conf_path)
        return config
    return None


TESTS_PATH = os.path.dirname(os.path.dirname(__file__))
DEF_CONFIG = init_config_from(os.path.join(TESTS_PATH, 'config.ini'))

EXAMPLE_CLIENTS = {
    'openssl': 'client',
    'boringssl': 'bsslclient',
    'gnutls': 'gtlssclient',
    'picotls': 'ptlsclient',
    'wolfssl': 'wsslclient',
}


def init_clients(config):
    clients = {}
    examples = os.path.join(config['ngtcp2']['path'], 'examples')
    sys.stderr.write(f'init clients from {examples}\n')
    for libname, cname in EXAMPLE_CLIENTS.items():
        cpath = os.path.join(examples, cname)
        if os.path.exists(cpath):
            clients[libname] = cpath
    return clients


AVAILABLE_CLIENTS = init_clients(DEF_CONFIG)


class Env:

    @staticmethod
    def crypto_libs():
        return sorted(AVAILABLE_CLIENTS.keys())

    @staticmethod
    def client_path(libname):
        if libname in AVAILABLE_CLIENTS:
            return AVAILABLE_CLIENTS[libname]
        return None

    @staticmethod
    def client_name(libname):
        if libname in EXAMPLE_CLIENTS:
            return EXAMPLE_CLIENTS[libname]
        return None

    def __init__(self, pytestconfig=None):
        self._verbose = pytestconfig.option.verbose if pytestconfig is not None else 0
        self._tests_dir = TESTS_PATH
        self._gen_dir = os.path.join(self._tests_dir, 'gen')
        self.config = DEF_CONFIG
        self._haproxy_path = self.config['haproxy']['path']
        self._haproxy = os.path.join(self._haproxy_path, 'haproxy')
        self._haproxy_version = None
        self._ngtcp2_path = self.config['ngtcp2']['path']
        self._haproxy_port = self.config['tests']['haproxy_port']
        self._httpd_port = self.config['tests']['httpd_port']
        self._examples_pem = {
            'key': 'xxx',
            'cert': 'xxx',
        }
        self._htdocs_dir = os.path.join(self._gen_dir, 'htdocs')
        self._tld = 'haproxy-quic-tests.eissing.org'
        self._example_domain = f"one.{self._tld}"
        self._ca = None
        self._cert_specs = [
            CertificateSpec(domains=[self._example_domain], key_type='rsa2048'),
            CertificateSpec(name="clientsX", sub_specs=[
               CertificateSpec(name="user1", client=True),
            ]),
        ]

    def issue_certs(self):
        if self._ca is None:
            self._ca = TestCA.create_root(name=self._tld,
                                          store_dir=os.path.join(self.gen_dir, 'ca'),
                                          key_type="rsa2048")
        self._ca.issue_certs(self._cert_specs)

    def setup(self):
        os.makedirs(self._gen_dir, exist_ok=True)
        os.makedirs(self._htdocs_dir, exist_ok=True)
        self.issue_certs()

    def get_server_credentials(self) -> Optional[Credentials]:
        creds = self.ca.get_credentials_for_name(self._example_domain)
        if len(creds) > 0:
            return creds[0]
        return None

    @property
    def verbose(self) -> int:
        return self._verbose

    @property
    def haproxy_version(self) -> int:
        if self._haproxy_version is None:
            p = subprocess.run(args=[self._haproxy, '-v'], text=True,
                               capture_output=True)
            assert p.returncode == 0
            m = re.match(r'HAProxy version (\S+) .*', p.stdout)
            if m:
                self._haproxy_version = m.group(1)
            else:
                self._haproxy_version = 'unknown'
        return self._haproxy_version

    @property
    def gen_dir(self) -> str:
        return self._gen_dir

    @property
    def ca(self):
        return self._ca

    @property
    def htdocs_dir(self) -> str:
        return self._htdocs_dir

    @property
    def example_domain(self) -> str:
        return self._example_domain

    @property
    def examples_dir(self) -> str:
        return self._examples_dir

    @property
    def examples_port(self) -> int:
        return int(self.config['examples']['port'])

    @property
    def examples_pem(self) -> Dict[str, str]:
        return self._examples_pem

    @property
    def clients(self):
        return self._clients

    @property
    def haproxy(self) -> str:
        return self._haproxy

    @property
    def haproxy_port(self) -> str:
        return self._haproxy_port

    @property
    def httpd_port(self) -> str:
        return self._httpd_port
