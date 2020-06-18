#!/usr/bin/python3
"""Standalone runner that compares multiple versions of omegajail.

This runs each submission against multiple omegajail versions to identify
behavior differences between them. This is useful when trying to upgrade
compilers / runtimes.
"""
# pylint: disable=too-many-locals,invalid-name,too-few-public-methods

import argparse
import http.client
import json
import logging
import os
import os.path
import random
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import urllib.parse
import zipfile

from typing import Any, Dict, List, NamedTuple, Optional

import OpenSSL.crypto  # type: ignore

_ROOT = os.path.dirname(__file__)

_CONFIGS = {
    'bionic':
    textwrap.dedent("""\
    {
      "Logging": {
        "File": "",
        "Level": "debug"
      },
      "Runner": {
        "RuntimePath": "./runner/bionic",
        "GraderURL": "https://grader.omegaup.com:20896",
        "OmegajailRoot": "/var/lib/omegajail-bionic"
      },
      "TLS": {
        "CertFile": "./certificate.pem",
        "KeyFile": "./key.pem"
      },
      "Tracing": {
        "Enabled": false
      }
    }"""),
    'focal':
    textwrap.dedent("""\
    {
      "Logging": {
        "File": "",
        "Level": "debug"
      },
      "Runner": {
        "RuntimePath": "./runner/focal",
        "GraderURL": "https://grader.omegaup.com:20896",
        "OmegajailRoot": "/var/lib/omegajail-focal"
      },
      "TLS": {
        "CertFile": "./certificate.pem",
        "KeyFile": "./key.pem"
      },
      "Tracing": {
        "Enabled": false
      }
    }"""),
}
_OMEGAUP_RUNNER_URL = ('https://github.com/omegaup/quark/releases/download/'
                       'v1.1.37/omegaup-runner.tar.xz')

_CA_CERT = """\
-----BEGIN CERTIFICATE-----
MIIFZDCCA0wCAQAwDQYJKoZIhvcNAQENBQAwTzELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAldBMTMwMQYDVQQDDCpvbWVnYVVwIHN0YW5kYWxvbmUgZ3JhZGVyIHJvb3Qg
Y2VydGlmaWNhdGUwHhcNMjAwNjE4MDI1NDU3WhcNMzAwNjE2MDI1NDU3WjBPMQsw
CQYDVQQGEwJVUzELMAkGA1UECAwCV0ExMzAxBgNVBAMMKm9tZWdhVXAgc3RhbmRh
bG9uZSBncmFkZXIgcm9vdCBjZXJ0aWZpY2F0ZTCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBALIv7cBCpoBws5E2ayLb+z3nwFRey0TvTtqJe9KJbTV+kZS5
DYssyT+HBlrtegWt78fLD9+54ipmgV+xFQeh7MEcX8TJLeSpArPZW5qcPpXBUCJ4
pOxqYjB59p5of0UGGHojAeiTTCoKHw/b/hScg0J+Xl/SmTy5VQBtZvOAvZruOsED
cXG+cQInaNcCS7CRT74VuVC+nR01ji3g9HW/JexB1wlha04AYnJlkbnzYwF2Cde4
5NkPd47zJqWbtwgSg16wvznBL7tB0IcXJXrHtU5WFe1GmUS14WKrl8hoRxY9iT3p
BCDLY6E3bfy6UFvij7r1Sl7Lb/6z4RN+lUECTEPtKLFOAYgST7oOTRefePVOHlcB
w5i8p2bAH2gri9DC6Sw7VANfd92cpaqAIaJe7mFKIWlOnSkBxoPlfG3cbO7Sgga8
FD4wWPu4dcSDlKcHJ8vr56Xxtpl0Ckn6Y8Sv+uUO0bJL6bV9z7KL9ois7RiwOwsA
nnb4Jh4SiHCnmPtd7XSretAfdjYvFi4VWFngTB4WfGbT2vDfazKFJyprPxG+09wm
c4Dohr0QXz/edM7moaIKMGYgxjJr6NQAdZU4i9BTR+o+y75oyIXgt+/MkCQFmW9X
JSx/c92SWLoqgr4TUSsK+8tnkx9HovRbN2eAGaumqaXYouXIEaGxWQ6uetarAgMB
AAGjUDBOMB0GA1UdDgQWBBSj7p/ip4TQHamZWdnIiT6iEh6eFDAfBgNVHSMEGDAW
gBSj7p/ip4TQHamZWdnIiT6iEh6eFDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
DQUAA4ICAQA7yzbOhWfL5QEi6RLmGeKEWadSW+Q3Z5Js5J5B27TZO19hZsu5slQK
THTvsZb8vhrvZbvL2TucZzFsuespEtrIdIS0ZfaBFCQccvI5DJiULKi1M/Wso13u
p986o5QtVqpCrDmt2oVWSYdo8nVYYnM7CMgaO8kJCOVgFjBSiFBvH9cUZTYHW7G7
IlxBO0rP9cRlXHWuuHmceipFHM/hRboaN4vS5jLoB4m+JR/Ck/D6184WNFj02s8C
/IW/AL74W1TRhn3VuXkXiEWHT+zqH+pfMIiJ7NJMtiNKeVEd3pRukGEQ4+4jEEJB
yfn3o+ehl9qUf10r07amfG+884d0DHePzlJdK6uv1akWogS2Z8leeaPIqoyj5PBr
R/eT2Aemwc9VoLe1bGMecqS/umIfpF5OIKvMXFcZYSEUizf1kudC2sSiz9AqD3w4
owLRyU20ofjn+xg409cSvx43uAppDFJEMFDbwzcOwZ4/ex5d/rwMNh7rWrgbBKEa
5C24s3Fw/KOCRxGJH1DiV8sZ2HAIFESlEwFG0e5DYPkY4l3hZGqOgWZgCxWZX+nt
qie4+B9860XAKxJVeSue6+qFV03LIAvFOo6WofAVfkghXHR0N6LgmLuQ+ZGV9Ha5
4MTY1pW97cF6p63fxg4If+QIA9bD8sACseQkmhhdnlp9E0EAum6U4A==
-----END CERTIFICATE-----
"""

_CA_KEY = """
-----BEGIN PRIVATE KEY-----
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
ZYlc/JVzN1NPwNZ7byd6fyjbx6avW16y
-----END PRIVATE KEY-----
"""


def _download_runner(omegaup_runner_path: str,
                     max_redirects: int = 10) -> None:
    """Downloads the omegaup-runner binary."""
    url = _OMEGAUP_RUNNER_URL
    referer: Optional[str] = None
    with tempfile.NamedTemporaryFile(suffix=os.path.basename(url)) as tar_file:
        for _ in range(max_redirects):
            logging.info('Downloading %s...', url)
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.hostname is None:
                raise ValueError(f'Hostname is None in {url}')
            runner_conn = http.client.HTTPSConnection(parsed_url.hostname,
                                                      port=parsed_url.port)
            runner_conn.request(
                'GET',
                parsed_url.path +
                (f'?{parsed_url.query}' if parsed_url.query else ''),
                headers=({
                    'Referer': referer
                } if referer is not None else {}))
            response = runner_conn.getresponse()
            if response.status == 302:
                response.read()
                url = response.headers['Location']
                continue
            if response.status != 200:
                logging.error('Failed to download %s: HTTP/%d headers=%r', url,
                              response.status, response.headers)
                sys.exit(1)
            while True:
                buf = response.read1(4096)
                if not buf:
                    break
                tar_file.write(buf)
            tar_file.flush()
            break
        else:
            logging.error('Too many redirects for %s', _OMEGAUP_RUNNER_URL)
            sys.exit(1)

        logging.info('Extracting %s...', _OMEGAUP_RUNNER_URL)
        with tarfile.open(tar_file.name, mode='r') as tar:
            with open(omegaup_runner_path, 'wb') as f:
                os.chmod(omegaup_runner_path, 0o755)
                reader = tar.extractfile('./usr/bin/omegaup-runner')
                if reader is None:
                    raise ValueError(
                        './usr/bin/omegaup-runner not found in tar file')
                while True:
                    buf = reader.read(4096)
                    if not buf:
                        break
                    f.write(buf)


def _generate_certificates(certfile_path: str, keyfile_path: str,
                           common_name: str) -> None:
    """Generate the certificate/key pair for this machine."""
    ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                            _CA_KEY)
    ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                              _CA_CERT)

    k = OpenSSL.crypto.PKey()
    k.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)

    cert = OpenSSL.crypto.X509()
    cert.get_subject().C = 'US'
    cert.get_subject().CN = common_name
    cert.set_serial_number(random.randint(0, 2**64))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(ca_key, 'sha512')
    with open(certfile_path, "w") as f:
        f.write(
            OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                            cert).decode("utf-8"))
        f.write(_CA_CERT)
    with open(keyfile_path, "w") as f:
        f.write(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                           k).decode("utf-8"))


class InputEntry(NamedTuple):
    """An entry in the input cache."""
    size: int
    path: str
    version: str


class InputCache:
    """An LRU cache with a size limit.

    Every time entry() is called, it will return the cached entry (if present
    in the filesystem), or fetch the problem from the grader. This will evict
    as many previous input sets as needed to get the total size to be under the
    cache size limit.
    """
    def __init__(self, conn: http.client.HTTPSConnection, path: str,
                 cache_size: int):
        self._conn = conn
        self._path = path
        self._cache_size = cache_size
        self._lru: List[InputEntry] = []
        self._size = 0
        shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path, exist_ok=True)

    def entry(self, version: str) -> InputEntry:
        """Returns an InputEntry for the provided version."""
        output_path = os.path.join(self._path, version)

        for i, entry in enumerate(self._lru):
            if entry.path == output_path:
                self._lru = self._lru[:i] + self._lru[i + 1:] + [self._lru[i]]
                return entry

        logging.info('Getting input %s', version)
        tar_path = f'{output_path}.tar.gz'
        self._conn.request('GET', f'/input/{version}')
        response = self._conn.getresponse()
        if response.status == 404:
            raise FileNotFoundError(version)

        with open(tar_path, 'wb') as f:
            while True:
                chunk = response.read(4096)
                if not chunk:
                    break
                f.write(chunk)
        with tarfile.open(tar_path, mode='r:gz') as tar:
            tar.extractall(output_path)
        os.unlink(tar_path)

        entry_size = 0
        for dirpath, _, filenames in os.walk(output_path):
            for filename in filenames:
                st = os.stat(os.path.join(dirpath, filename))
                entry_size += st.st_size

        while self._lru and self._size + entry_size > self._cache_size:
            entry = self._lru.pop(0)
            logging.info('Evicting input %s', entry.version)
            shutil.rmtree(entry.path)
            self._size -= entry.size

        entry = InputEntry(entry_size, output_path, version)
        self._size += entry.size
        self._lru.append(entry)
        return entry


def _download_run(
        conn: http.client.HTTPSConnection) -> Optional[Dict[str, Any]]:
    try:
        conn.request('GET', '/run/request/')
        response = conn.getresponse()
        data = response.read()
    except (ConnectionRefusedError, http.client.HTTPException):
        logging.exception('Failed to get run')
        return None
    if response.status == 404:
        return None
    with open(os.path.join(_ROOT, 'request.json'), 'wb') as fb:
        fb.write(data)
    request: Dict[str, Any] = json.loads(data.decode('utf-8'))
    with open(os.path.join(_ROOT, 'source'), 'w') as f:
        f.write(request['source'])
    return request


def _run(input_cache: InputCache, request: Dict[str, Any],
         configs: Dict[str, Any], omegaup_runner_path: str) -> str:
    """Run a single submission and return the path of the generated results.zip"""
    entry = input_cache.entry(request['input_hash'])
    cases_zip_path = os.path.join(_ROOT, 'cases.zip')

    result: Dict[str, Any] = {}
    with zipfile.ZipFile(cases_zip_path,
                         mode='w',
                         compression=zipfile.ZIP_DEFLATED) as z:
        for config_name in configs:
            with tempfile.TemporaryDirectory() as d:
                omegaup_runner_args = [
                    omegaup_runner_path,
                    ('-config=' + os.path.join(_ROOT, f'{config_name}.json')),
                    '-oneshot=run',
                    f'-input={entry.path}',
                    '-request=' + os.path.join(_ROOT, 'request.json'),
                    f'-results={d}',
                ]
                logging.info('Running %8s: id=%7s version=%s language=%s: %s',
                             config_name, request['attempt_id'],
                             request['input_hash'], request['language'],
                             ' '.join(omegaup_runner_args))
                run_result = subprocess.run(omegaup_runner_args,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            check=True)
                for rootdir, _, filenames in os.walk(d):
                    for filename in filenames:
                        file_path = os.path.join(rootdir, filename)
                        z.write(file_path,
                                arcname=os.path.join(
                                    config_name, os.path.relpath(file_path,
                                                                 d)))
            result[config_name] = json.loads(run_result.stdout)
            result[config_name]['logs'] = run_result.stderr.decode('utf-8')

    logging.info(
        '%s', ' '.join(
            f'{name} ({meta["verdict"]:3s}, {meta["score"]:.2f}, {meta["time"]:.2f})'
            for (name, meta) in result.items()))
    results_path = os.path.join(_ROOT, 'results.zip')
    with zipfile.ZipFile(results_path,
                         mode='w',
                         compression=zipfile.ZIP_STORED) as z:
        z.write(cases_zip_path, arcname='cases.zip')
        z.writestr('details.json', json.dumps(result))
    return results_path


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'config',
        nargs='+',
        help=
        'Name of an omegaup-runner config profile (one of "focal", "bionic")')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s [%(levelname)-8s] %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s [%(levelname)-8s] %(message)s')

    omegaup_runner_path = os.path.join(_ROOT, 'omegaup-runner')
    if not os.path.isfile(omegaup_runner_path):
        _download_runner(omegaup_runner_path)

    configs: Dict[str, Any] = {}
    for config_name in args.config:
        if config_name not in _CONFIGS:
            raise ValueError(f'Invalid configuration name "{config_name}"')
        config_path = os.path.join(_ROOT, f'{config_name}.json')
        if not os.path.isfile(config_path):
            with open(config_path, 'w') as f:
                f.write(_CONFIGS[config_name])
        configs[config_name] = json.loads(_CONFIGS[config_name])
    first_config = next(iter(configs.values()))
    url = urllib.parse.urlparse(first_config['Runner']['GraderURL'])

    certfile_path = os.path.join(_ROOT, first_config['TLS']['CertFile'])
    keyfile_path = os.path.join(_ROOT, first_config['TLS']['KeyFile'])
    if not os.path.isfile(certfile_path) or not os.path.isfile(keyfile_path):
        _generate_certificates(certfile_path,
                               keyfile_path,
                               common_name=socket.gethostname())

    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_ctx.load_cert_chain(certfile_path, keyfile_path)
    ssl_ctx.load_verify_locations(cafile=certfile_path)
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    conn = http.client.HTTPSConnection(url.hostname,
                                       port=url.port,
                                       context=ssl_ctx)

    input_cache = InputCache(conn, os.path.join(_ROOT, 'inputs'), 1024**3)

    while True:
        request = _download_run(conn)
        if request is None:
            logging.info('No runs found. Sleeping 10s')
            time.sleep(10)
            conn = http.client.HTTPSConnection(url.hostname,
                                               port=url.port,
                                               context=ssl_ctx)
            continue

        results_path = _run(input_cache, request, configs, omegaup_runner_path)

        with open(results_path, 'rb') as results_file:
            conn.request('POST',
                         f'/run/{request["attempt_id"]}/results.zip',
                         body=results_file,
                         headers={
                             'Content-Length':
                             str(os.stat(results_path).st_size),
                             'Content-Type': 'application/zip',
                         })
        response = conn.getresponse()
        data = response.read()
        if response.status != 204:
            logging.error('failed to upload results for %d: HTTP/%d: %s',
                          request['attempt_id'], response.status, data)


if __name__ == '__main__':
    _main()
