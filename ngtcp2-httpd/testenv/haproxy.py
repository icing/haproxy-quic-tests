import datetime
import logging
import os
import socket
import subprocess
import time

from .env import Env


log = logging.getLogger(__name__)


class HAProxy:

    def __init__(self, env: Env):
        self.env = env
        self._cmd = env.haproxy
        self._conf_file = os.path.join(env.gen_dir, 'haproxy.cfg')
        self._process = None
        self._logpath = f'{self.env.gen_dir}/haproxy.log'
        self._rmf(self._logpath)
        self._logfile = None
        self._stats_sock = os.path.join(env.gen_dir, 'haproxy.sock')

    def exists(self):
        return os.path.exists(self._cmd)

    def start(self):
        if self._process:
            self.stop()
        self._logfile = open(self._logpath, 'w')
        self._write_config()
        self._rmf(self._stats_sock)
        try:
            sock = socket.create_connection(('127.0.0.1', self.env.haproxy_port))
            sock.close()
            raise Exception(f'another process is listening on '
                            f'{self.env.haproxy_port}, leftover process?')
        except ConnectionRefusedError:
            pass
        self._process = subprocess.Popen(args=[self._cmd, '-f', self._conf_file],
                                         text=True,
                                         stdout=self._logfile,
                                         stderr=self._logfile)
        end = datetime.datetime.now() + datetime.timedelta(seconds=5)
        while self._process.poll() is None \
                and not os.path.exists(self._stats_sock)\
                and datetime.datetime.now() < end:
            time.sleep(.1)
        if os.path.exists(self._stats_sock):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self._stats_sock)
            msg = 'trace quic event +any; trace quic lock listener; '\
                  'trace quic sink stderr; trace quic level developer; '\
                  'trace quic start now; show trace'
            sock.sendall(msg.encode())
            sock.close()
        sock = socket.create_connection(('127.0.0.1', self.env.haproxy_port))
        sock.close()
        return self._process.returncode is None

    def stop(self):
        if self._process:
            self._process.terminate()
            end = datetime.datetime.now() + datetime.timedelta(seconds=5)
            while self._process.poll() is None \
                    and datetime.datetime.now() < end:
                time.sleep(.1)
            self._process = None
        if self._logfile:
            self._logfile.close()
            self._logfile = None
        return True

    def restart(self):
        self.stop()
        return self.start()

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    def _write_config(self):
        with open(self._conf_file, 'w') as fd:
            fd.write("\n".join([
                f"global",
                f"    strict-limits  # refuse to start if insufficient FDs/memory",
                f"    stats socket {self._stats_sock} mode 600 level admin",
                f"    stats timeout 2m",
                f"",
                f"httpclient.ssl.ca-file {self.env.ca.cert_file}",
                f"",
                f"defaults",
                f"    mode http",
                f"    balance random",
                f"    timeout client 60s",
                f"    timeout server 60s",
                f"    timeout connect 1s",
                f"",
                f"frontend front1",
                f"    mode http",
                f"    bind :{self.env.haproxy_port} ssl crt {self.env.get_server_credentials().combined_file} alpn h2,http/1.1",
                f"    log stderr format iso local7",
                f"    option httplog",
                f"    option tcplog",
                f"    option logasap",
                f"    tcp-request content set-log-level debug",
                f"    http-request set-log-level debug",
                f"    http-response set-log-level debug",
                f"    default_backend back1",
                f"",
                f"frontend front2",
                f"    mode http",
                f"    bind quic4@:{self.env.haproxy_port} ssl crt {self.env.get_server_credentials().combined_file} alpn h3",
                f"    log stderr format iso local7",
                f"    option httplog",
                f"    option tcplog",
                f"    option logasap",
                f"    tcp-request content set-log-level debug",
                f"    http-request set-log-level debug",
                f"    http-response set-log-level debug",
                f"    default_backend back1",
                f"",
                f"backend back1",
                f"    mode http",
                f"    server s1 127.0.0.1:{self.env.httpd_port}",
                "",
            ]))
