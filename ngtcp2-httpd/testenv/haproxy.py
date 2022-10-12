import os
import subprocess

from .env import Env


class HAProxy:

    def __init__(self, env: Env):
        self.env = env
        self._cmd = env.haproxy
        self._conf_file = os.path.join(env.gen_dir, 'haproxy.cfg')
        self._process = None
        self._logpath = f'{self.env.gen_dir}/haproxy.log'
        self._logfile = None
        self._stats_sock = os.path.join(env.gen_dir, 'haproxy.sock')

    def exists(self):
        return os.path.exists(self._cmd)

    def start(self):
        if self._process:
            self.stop()
        self._logfile = open(self._logpath, 'w')
        self._write_config()
        self._process = subprocess.Popen(args=[self._cmd, '-f', self._conf_file],
                                         text=True,
                                         stdout=self._logfile,
                                         stderr=self._logfile)
        return True

    def stop(self):
        if self._process:
            self._process.terminate()
            self._process = None
        if self._logfile:
            self._logfile.close()
            self._logfile = None
        return True

    def restart(self):
        self.stop()
        return self.start()

    def _write_config(self):
        with open(self._conf_file, 'w') as fd:
            fd.write("\n".join([
                "global",
                "    strict-limits  # refuse to start if insufficient FDs/memory",
                f"    stats socket {self._stats_sock} mode 600 level admin",
                "    stats timeout 2m",
                "",
                f"httpclient.ssl.ca-file {self.env.ca.cert_file}",
                "",
                "defaults",
                "    mode http",
                "    balance random",
                "    timeout client 60s",
                "    timeout server 60s",
                "    timeout connect 1s",
                "",
                "frontend front1",
                f"    bind :{self.env.haproxy_port} ssl crt {self.env.get_server_credentials().combined_file} alpn h2,http/1.1",
                "    log stderr format iso local7",
                "    option httplog",
                "    option tcplog",
                "    option logasap",
                "    tcp-request content set-log-level debug",
                "    http-request set-log-level debug",
                "    http-response set-log-level debug",
                "    default_backend back1",
                "",
                "frontend front2",
                f"    bind quic4@:{self.env.haproxy_port} ssl crt {self.env.get_server_credentials().combined_file} alpn h3",
                "    log stderr format iso local7",
                "    option httplog",
                "    option tcplog",
                "    option logasap",
                "    tcp-request content set-log-level debug",
                "    http-request set-log-level debug",
                "    http-response set-log-level debug",
                "    default_backend back1",
                "",
                "backend back1",
                "    mode    http",
                "    log stderr format iso local7",
                "    tcp-request content set-log-level debug",
                "    http-request set-log-level debug",
                "    http-response set-log-level debug",
                "    #http-request set-header Host wolfssl.com",
                f"    server s1 127.0.0.1:{self.env.httpd_port} ssl ca-file {self.env.ca.cert_file}",
                "",
            ]))
