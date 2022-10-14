import logging
import os
import subprocess
from json import JSONEncoder

from .env import Env


log = logging.getLogger(__name__)


class Httpd:

    MODULES = [
        'log_config', 'logio', 'unixd', 'version', 'watchdog',
        'authn_core', 'authz_user', 'authz_core',
        'env', 'filter', 'headers', 'mime',
        'rewrite', 'http2', 'ssl',
        'mpm_event',
    ]
    COMMON_MODULES_DIRS = [
        '/usr/lib/apache2/modules',  # debian
        '/usr/libexec/apache2/',     # macos
    ]
    def __init__(self, env: Env):
        self.env = env
        self._cmd = env.apachectl
        self._apache_dir = os.path.join(env.gen_dir, 'apache')
        self._docs_dir = os.path.join(self._apache_dir, 'docs')
        self._conf_dir = os.path.join(self._apache_dir, 'conf')
        self._conf_file = os.path.join(self._conf_dir, 'test.conf')
        self._logs_dir = os.path.join(self._apache_dir, 'logs')
        self._error_log = os.path.join(self._logs_dir, 'error_log')
        self._mods_dir = None
        if env.apxs is not None:
            p = subprocess.run(args=[env.apxs, '-q', 'libexecdir' ],
                               capture_output=True, text=True)
            if p.returncode != 0:
                raise Exception(f'{env.apxs} failed to query libexecdir: {p}')
            self._mods_dir = p.stdout.strip()
        else:
            for md in self.COMMON_MODULES_DIRS:
                if os.path.isdir(md):
                    self._mods_dir = md
        if self._mods_dir is None:
            raise Exception(f'apache modules dir cannot be found')
        self._process = None
        self._rmf(self._error_log)

    def exists(self):
        return os.path.exists(self._cmd)

    def _apachectl(self, cmd: str):
        args = [self.env.apachectl,
                "-d", self._apache_dir,
                "-f", self._conf_file,
                "-k", cmd]
        p = subprocess.run(args=args)
        return p

    def start(self):
        if self._process:
            self.stop()
        self._write_config()
        r = self._apachectl('start')
        if r.returncode != 0:
            log.error(f'failed to start httpd: {r}')
        return r.returncode == 0

    def stop(self):
        self._apachectl('stop')
        return True

    def restart(self):
        self.stop()
        return self.start()

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _write_config(self):
        domain = self.env.example_domain
        self._mkpath(self._conf_dir)
        self._mkpath(self._logs_dir)
        self._mkpath(self._docs_dir)
        with open(os.path.join(self._docs_dir, 'data.json'), 'w') as fd:
            data = {
                'server': f'{domain}',
            }
            fd.write(JSONEncoder().encode(data))
        with open(self._conf_file, 'w') as fd:
            for m in self.MODULES:
                fd.write(f'LoadModule {m}_module   "{self._mods_dir}/mod_{m}.so"\n')
            fd.write("\n".join([
                f'LogLevel trace2',
                f'Listen {self.env.httpd_port}',
                f'<VirtualHost *:{self.env.httpd_port}>',
                f'    ServerName {domain}',
                f'    #SSLEngine on',
                f'    #SSLCertificateFile {self.env.ca.get_first(domain).cert_file}',
                f'    #SSLCertificateKeyFile {self.env.ca.get_first(domain).pkey_file}',
                f'    DocumentRoot "{self._docs_dir}"',
                f'</VirtualHost>',
                f''
            ]))
        with open(os.path.join(self._conf_dir, 'mime.types'), 'w') as fd:
            fd.write("\n".join([
                'text/html             html',
                'application/json      json',
                ''
            ]))
