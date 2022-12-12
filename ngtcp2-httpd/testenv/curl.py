import json
import logging
import os
import re
import subprocess
from datetime import timedelta, datetime
from typing import List, Optional, Dict
from urllib.parse import urlparse

from .env import Env


log = logging.getLogger(__name__)


class ExecResult:

    def __init__(self, args: List[str], exit_code: int,
                 stdout: bytes, stderr: bytes = None, duration: timedelta = None):
        self._args = args
        self._exit_code = exit_code
        self._stdout = stdout if stdout is not None else b''
        self._stderr = stderr if stderr is not None else b''
        self._duration = duration if duration is not None else timedelta()
        self._response = None
        self._results = {}
        self._assets = []
        # noinspection PyBroadException
        try:
            out = self._stdout.decode()
            self._json_out = json.loads(out)
        except:
            self._json_out = None

    def __repr__(self):
        return f"ExecResult[code={self.exit_code}, args={self._args}, stdout={self._stdout}, stderr={self._stderr}]"

    @property
    def exit_code(self) -> int:
        return self._exit_code

    @property
    def args(self) -> List[str]:
        return self._args

    @property
    def outraw(self) -> bytes:
        return self._stdout

    @property
    def stdout(self) -> str:
        if isinstance(self._stdout, bytes):
            return self._stdout.decode()
        return self._stdout

    @property
    def json(self) -> Optional[Dict]:
        """Output as JSON dictionary or None if not parseable."""
        return self._json_out

    @property
    def stderr(self) -> str:
        if isinstance(self._stderr, bytes):
            return self._stderr.decode()
        return self._stderr

    @property
    def duration(self) -> timedelta:
        return self._duration

    @property
    def response(self) -> Optional[Dict]:
        return self._response

    @property
    def results(self) -> Dict:
        return self._results

    @property
    def assets(self) -> List:
        return self._assets

    def add_response(self, resp: Dict):
        if self._response:
            resp['previous'] = self._response
        self._response = resp

    def add_results(self, results: Dict):
        self._results.update(results)
        if 'response' in results:
            self.add_response(results['response'])

    def add_assets(self, assets: List):
        self._assets.extend(assets)


class CurlClient:

    def __init__(self, env: Env):
        self.env = env
        self._curl = os.environ['CURL'] if 'CURL' in os.environ else 'curl'
        self._headerfile = f'{self.env.gen_dir}/curl.headers'
        self._log_path = f'{self.env.gen_dir}/curl.log'
        if os.path.isfile(self._log_path):
            os.remove(self._log_path)

    def http_get(self, url: str, extra_args: List[str] = None):
        return self._raw(url, extra_args)

    def _run(self, args, intext=''):
        p = subprocess.run(args, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                           input=intext.encode() if intext else None)
        start = datetime.now()
        return ExecResult(args=args, exit_code=p.returncode,
                          stdout=p.stdout, stderr=p.stderr,
                          duration=datetime.now() - start)

    def _raw(self, urls, timeout=10, options=None, insecure=False,
                 force_resolve=True):
        args, headerfile = self._complete_args(
            urls=urls, timeout=timeout, options=options, insecure=insecure,
            force_resolve=force_resolve)
        r = self._run(args)
        if r.exit_code == 0:
            self._parse_headerfile(headerfile, r=r)
            if r.json:
                r.response["json"] = r.json
        if os.path.isfile(headerfile):
            os.remove(headerfile)
        return r

    def _complete_args(self, urls, timeout=None, options=None,
                       insecure=False, force_resolve=True):
        if not isinstance(urls, list):
            urls = [urls]
        u = urlparse(urls[0])

        args = [
            self._curl, "-s", "--path-as-is", "-D", self._headerfile,
        ]
        if u.scheme == 'http':
            pass
        elif insecure:
            args.append('--insecure')
        elif options and "--cacert" in options:
            pass
        elif u.hostname:
            args.extend(["--cacert", self.env.ca.cert_file])

        if force_resolve and u.hostname and u.hostname != 'localhost' \
                and not re.match(r'^(\d+|\[|:).*', u.hostname):
            port = u.port if u.port else 443
            args.extend(["--resolve", f"{u.hostname}:{port}:127.0.0.1"])
        if timeout is not None and int(timeout) > 0:
            args.extend(["--connect-timeout", str(int(timeout))])
        if options:
            args.extend(options)
        args += urls
        return args, self._headerfile

    def _parse_headerfile(self, headerfile: str, r: ExecResult = None) -> ExecResult:
        lines = open(headerfile).readlines()
        if r is None:
            r = ExecResult(args=[], exit_code=0, stdout=b'', stderr=b'')

        response = None
        def fin_response(response):
            if response:
                r.add_response(response)

        expected = ['status']
        for line in lines:
            if re.match(r'^$', line):
                if 'trailer' in expected:
                    # end of trailers
                    fin_response(response)
                    response = None
                    expected = ['status']
                elif 'header' in expected:
                    # end of header, another status or trailers might follow
                    expected = ['status', 'trailer']
                else:
                    assert False, f"unexpected line: {line}"
                continue
            if 'status' in expected:
                log.debug("reading 1st response line: %s", line)
                m = re.match(r'^(\S+) (\d+) (.*)$', line)
                if m:
                    fin_response(response)
                    response = {
                        "protocol": m.group(1),
                        "status": int(m.group(2)),
                        "description": m.group(3),
                        "header": {},
                        "trailer": {},
                        "body": r.outraw
                    }
                    expected = ['header']
                    continue
            if 'trailer' in expected:
                m = re.match(r'^([^:]+):\s*(.*)$', line)
                if m:
                    response['trailer'][m.group(1).lower()] = m.group(2)
                    continue
            if 'header' in expected:
                m = re.match(r'^([^:]+):\s*(.*)$', line)
                if m:
                    response['header'][m.group(1).lower()] = m.group(2)
                    continue
            assert False, f"unexpected line: {line}"

        fin_response(response)
        return r

