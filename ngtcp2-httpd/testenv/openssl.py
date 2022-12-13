import logging
import os
import re
import subprocess
import time
from datetime import datetime
from typing import List
from urllib.parse import urlparse

from . import ExecResult, HSRecord, HandShake
from .env import Env
from .log import HexDumpScanner

log = logging.getLogger(__name__)


class OpensslClient:

    def __init__(self, env: Env):
        self.env = env
        self._openssl = os.environ['OPENSSL'] if 'OPENSSL' in os.environ else 'openssl'
        self._log_path = f'{self.env.gen_dir}/curl.log'
        if os.path.isfile(self._log_path):
            os.remove(self._log_path)

    def connect(self, url: str, extra_args: List[str] = None, intext=None):
        return self._raw(url, extra_args, intext=intext)

    def _run(self, args, intext=''):
        p = subprocess.Popen(args, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE, text=True)
        if intext:
            p.stdin.write(intext)
        time.sleep(.5)  # give session ticket a moment to arrive
        try:
            p.stdin.close()
        except:
            pass  # might have been closed already
        p.wait(timeout=10)
        start = datetime.now()
        sout = p.stdout.readlines()
        serr = p.stderr.readlines()
        return ExecResult(args=args, exit_code=p.returncode,
                          stdout=sout, stderr=serr,
                          duration=datetime.now() - start)

    def _raw(self, url, options=None, intext=None):
        args = self._complete_args(url=url, options=options)
        r = self._run(args, intext=intext)
        r.add_response(self._parse_response(r.stdout))
        return r

    def _complete_args(self, url, options=None):
        if not isinstance(url, list):
            url = [url]
        u = urlparse(url[0])

        args = [
            self._openssl, 's_client',
            '-connect', f'127.0.0.1:{u.port}',
            '-CAfile', self.env.ca.cert_file,
            '-servername', u.hostname,
            '-debug',
        ]

        if options:
            args.extend(options)
        return args

    def _parse_response(self, output):
        r = {}
        in_session = False
        if isinstance(output, str):
            output = output.splitlines(keepends=False)
        for l in output:
            if in_session:
                m = re.match(r'^\s+', l)
                if m:
                    m = re.match(r'^\s+(.+)\s*:\s+(.*)', l)
                    if m:
                        r['session'][m.group(1)] = m.group(2)
                    else:
                        r['session']['ticket'].append(l.strip())
                    continue
                else:
                    in_session = False
            m = re.match(r'^Certificate chain', l)
            if m:
                pass # are we interested in cert details?
            m = re.match(r'^Peer signing digest: (.+)', l)
            if m:
                r['signing-digest'] = m.group(1)
            m = re.match(r'^Peer signature type: (.+)', l)
            if m:
                r['signature-type'] = m.group(1)
            m = re.match(r'^Server Temp Key: (.+)', l)
            if m:
                r['server-temp-key'] = m.group(1)
            m = re.match(r'^Verification: (.+)', l)
            if m:
                r['verification'] = m.group(1)
            m = re.match(r'^New, (\S+), Cipher is (.+)', l)
            if m:
                r['protocol'] = m.group(1)
                r['cipher'] = m.group(2)
            m = re.match(r'^Secure Renegotiation (.+) supported', l)
            if m:
                r['secure-renegotiation'] = m.group(1) != 'IS NOT'
            m = re.match(r'^Compression: (.+)', l)
            if m:
                r['compression'] = m.group(1)
            m = re.match(r'^No ALPN negotiated', l)
            if m:
                r['alpn'] = None
            m = re.match(r'^\s*Max Early Data: (.+)', l)
            if m:
                r['max-early-data'] = m.group(1)
            m = re.match(r'^SSL-Session:', l)
            if m:
                r['session'] = {'ticket': []}
                in_session = True

        hs_out, hs_in = self._handshake(output)
        r['handshake'] = {
            'in': hs_in,
            'out': hs_out,
        }
        return r

    def _handshake(self, output) -> List[HSRecord]:
        write_line = re.compile(r'write to ')
        scanner = HexDumpScanner(source=output, leading_regex=write_line)
        out_recs = [data for data in scanner]
        if self.env.verbose > 1:
            log.debug(f'detected {len(out_recs)} crypto hexdumps sent')
            for idx, r in enumerate(out_recs):
                log.debug(f'data rec {idx}: len={len(r):0x}')
        hs_sent = [hrec for hrec in HandShake(source=out_recs,
                                              skip_rec_header=True,
                                              verbose=self.env.verbose)]

        write_line = re.compile(r'read from ')
        scanner = HexDumpScanner(source=output, leading_regex=write_line)
        in_recs = [data for data in scanner]
        if self.env.verbose > 1:
            log.debug(f'detected {len(in_recs)} crypto hexdumps received')
            for idx, r in enumerate(in_recs):
                log.debug(f'data rec {idx}: len={len(r):0x}')
        hs_recvd = [hrec for hrec in HandShake(source=in_recs,
                                               skip_rec_header=True,
                                               verbose=self.env.verbose)]
        if self.env.verbose > 1:
            log.debug(f'detected {len(hs_recvd)} crypto records received')
        return hs_sent, hs_recvd

