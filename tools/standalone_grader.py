#!/usr/bin/python3
"""Standalone grader.

This runs each submission in a SQLite3 database.
"""

import argparse
import configparser
import hashlib
import http.server
import io
import itertools
import json
import logging
import os
import os.path
import queue
import random
import re
import shutil
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import zipfile

from typing import (Any, BinaryIO, Dict, Iterable, List, MutableMapping,
                    NamedTuple, Optional, Sequence, Tuple, Type, Union)

import OpenSSL.crypto  # type: ignore

_ROOT = os.path.dirname(__file__)

_LS_TREE_RE = re.compile(b'(\d+) (\w+) ([0-9a-f]+)\s+(\d+|-)\t([^\x00]+)\x00')
_RUN_RESULTS_RE = re.compile(r'^/run/(\d+)/(results|results.zip)/?$')
_FILENAME_RE = re.compile(r'^.*filename="([^"]+)".*$')

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


class Run(NamedTuple):
    id: int
    alias: str
    guid: str
    language: str
    version: str


def _load_all_runs(database_path: str) -> 'queue.Queue[Run]':
    q = queue.Queue()  # type: queue.Queue[Run]

    with sqlite3.connect(f'file:{database_path}?mode=ro', uri=True) as db:
        cursor = db.cursor()
        cursor.execute('''
        SELECT
            run_id, alias, guid, language, version
        FROM
            Runs
        WHERE
            verdict = 'XX'
            OR new_verdict IS NULL
        ORDER BY
            version ASC;
        ''')
        for run_id, alias, guid, language, version in cursor.fetchall():
            q.put(Run(run_id, alias, guid, language, version))

    logging.info('Found %d runs', q.qsize())
    return q


def _load_runs(database_path: str,
               run_ids: Iterable[int]) -> 'queue.Queue[Run]':
    q = queue.Queue()  # type: queue.Queue[Run]

    with sqlite3.connect(f'file:{database_path}?mode=ro', uri=True) as db:
        cursor = db.cursor()
        cursor.execute('''
        SELECT
            run_id, alias, guid, language, version
        FROM
            Runs
        WHERE
            run_id IN (%s);
        ''' % ', '.join(map(str, run_ids)))
        for run_id, alias, guid, language, version in cursor.fetchall():
            q.put(Run(run_id, alias, guid, language, version))

    logging.info('Found %d runs', q.qsize())
    return q


class ChunkedReader(BinaryIO):
    def __init__(self, r: BinaryIO):
        self._r = r
        self._chunk = b''
        self._eof = False

    def _read_chunk(self) -> None:
        line = b''
        while True:
            c = self._r.read(1)
            if not c:
                logging.error('Stream reached EOF while reading chunk length')
                raise EOFError
            line += c
            if c == b'\n':
                break
        chunklen = int(line.decode('ascii').strip(), 16)
        if not chunklen:
            self._eof = True
        self._chunk = b''
        while chunklen:
            c = self._r.read(chunklen)
            if not c:
                logging.error('Stream reached EOF while reading chunk')
                raise EOFError
            chunklen -= len(c)
            self._chunk += c
        c = self._r.read(2)
        if c != b'\r\n':
            logging.error('Stream reached EOF while reading chunk trailer')
            raise EOFError

    def read(self, size: int = -1) -> bytes:
        if size == -1:
            return self.readall()
        if self._eof:
            return b''
        if not self._chunk:
            self._read_chunk()
        if size >= len(self._chunk):
            result = self._chunk
            self._chunk = b''
            return result
        result = self._chunk[:size]
        self._chunk = self._chunk[size:]
        return result

    def readall(self) -> bytes:
        result = b''
        while True:
            buf = self.read(4096)
            if not buf:
                break
            result += buf
        return result

    def readinto(self, b: bytes) -> Optional[int]:
        raise OSError('Not supported')

    def write(self, b: bytes) -> int:
        raise OSError('Not supported')


def multipart_reader(raw: BinaryIO) -> Iterable[Tuple[Dict[str, str], bytes]]:
    r = io.BufferedReader(raw)

    def _read_line() -> bytes:
        line = []
        while True:
            c = r.read(1)
            if not c:
                logging.error('Stream reached EOF while reading chunk length')
                raise EOFError
            line.append(c)
            if c == b'\n':
                return b''.join(line)

    delimiter = _read_line().rstrip(b'\r\n')
    while True:
        headers: Dict[str, str] = {}
        while True:
            header = _read_line()
            if header == b'\r\n':
                break
            name, value = header.rstrip(b'\r\n').decode('ascii').split(':', 1)
            headers[name.strip()] = value.strip()
        contents: List[bytes] = []
        while True:
            line = _read_line()
            if line.startswith(delimiter):
                break
            contents.append(line)
        yield (headers, b''.join(contents)[:-2])
        if line.endswith(b'--\r\n'):
            break


class InputEntry(NamedTuple):
    size: int
    path: str
    uncompressed_size: int
    hash: str


class InputCache:
    def __init__(self, path: str, cache_size: int):
        self._path = path
        self._cache_size = cache_size
        self._lru: List[InputEntry] = []
        self._size = 0
        self._lock = threading.Lock()
        shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path, exist_ok=True)

    def entry(self, alias: str, version: str) -> InputEntry:
        with self._lock:
            output_path = os.path.join(self._path, '{}.tar.gz'.format(version))

            for i, entry in enumerate(self._lru):
                if entry.path == output_path:
                    self._lru = self._lru[:i] + self._lru[i +
                                                          1:] + [self._lru[i]]
                    return entry

            tmp_output_path = '{}.tmp'.format(output_path)
            problem_path = os.path.join('/var/lib/omegaup/problems.git', alias)
            uncompressed_size = 0
            with tarfile.open(tmp_output_path, mode='w:gz') as tar:
                for mode, objtype, objid, filesize, filepath in _LS_TREE_RE.findall(
                        subprocess.check_output([
                            '/usr/bin/git', 'ls-tree', '-l', '-z', '-t', '-r',
                            version
                        ],
                                                cwd=problem_path)):
                    info = tarfile.TarInfo(filepath.decode('utf-8'))
                    if objtype == b'blob':
                        info.size = int(filesize)
                        info.type = tarfile.REGTYPE
                        info.mode = int(mode, 8)
                        with subprocess.Popen(
                            [b'/usr/bin/git', b'cat-file', b'blob', objid],
                                cwd=problem_path,
                                stdout=subprocess.PIPE) as p:
                            tar.addfile(info, p.stdout)
                        uncompressed_size += info.size
                    elif objtype == b'tree':
                        info.size = 0
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        tar.addfile(info, io.BytesIO(b''))
            size = 0
            h = hashlib.sha1()
            with open(tmp_output_path, 'rb') as f:
                while True:
                    buf = f.read(4096)
                    if not buf:
                        break
                    size += len(buf)
                    h.update(buf)
            self._size += size
            while self._size >= self._cache_size and self._lru:
                entry = self._lru.pop(0)
                os.remove(entry.path)
                self._size -= entry.size
            entry = InputEntry(size, output_path, uncompressed_size,
                               h.hexdigest())
            self._lru.append(entry)
            os.rename(tmp_output_path, output_path)

            return entry


class GraderServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self,
                 server_address: Tuple[str, int],
                 RequestHandlerClass: Type[socketserver.BaseRequestHandler],
                 runs: 'queue.Queue[Run]',
                 cache: InputCache,
                 grade_dir: str,
                 artifacts_dir: str,
                 database_path: str,
                 preserve_artifacts: bool = False):
        super().__init__(server_address, RequestHandlerClass)
        self._runs = runs
        self._version_mapping = {}  # type: MutableMapping[str, str]
        self._cache = cache
        self._grade_dir = grade_dir
        self._artifacts_dir = artifacts_dir
        self._database_path = database_path
        self._preserve_artifacts = preserve_artifacts

    @property
    def grade_dir(self) -> str:
        return self._grade_dir

    @property
    def run(self) -> Optional[Run]:
        try:
            run = self._runs.get_nowait()
        except queue.Empty:
            return None
        if run.version not in self._version_mapping:
            self._version_mapping[run.version] = run.alias
        self._runs.task_done()
        return run

    def entry(self, version: str) -> Optional[InputEntry]:
        if version not in self._version_mapping:
            return None
        return self._cache.entry(self._version_mapping[version], version)

    def update_verdict(self, run_id: int, new_verdict: str, new_score: float,
                       judged_by: str) -> bool:
        with sqlite3.connect(self._database_path) as db:
            cursor = db.cursor()
            cursor.execute('SELECT verdict, score FROM Runs WHERE run_id = ?;',
                           (run_id, ))
            verdict: str = ''
            score: float = 0
            verdict, score = cursor.fetchone()

            cursor.execute(
                '''
            UPDATE
                Runs
            SET
                new_verdict = ?, new_score = ?, judged_by = ?
            WHERE
                run_id = ?;
            ''', (new_verdict, new_score, judged_by, run_id))
            db.commit()

        if verdict != new_verdict or abs(score - new_score) > 5e-3:
            logging.error('%-19s %8d: (%3s, %.2f) changed to (%3s, %.2f)',
                          judged_by, run_id, verdict, score, new_verdict,
                          new_score)
            return new_score < (score - 5e-3)
        logging.info('%-19s %8d: (%3s, %.2f) OK', judged_by, run_id, verdict,
                     score)
        return False

    def delete_missing_run(self, run_id: int) -> None:
        with sqlite3.connect(self._database_path) as db:
            cursor = db.cursor()
            cursor.execute(
                '''
            DELETE FROM
                Runs
            WHERE
                run_id = ?;
            ''', (run_id, ))
            db.commit()

    def process(self, run_id: int, client: str) -> bool:
        filename = os.path.join(self.grade_dir, str(run_id))

        changed_verdict = False
        verdict: Optional[str] = None
        with open(filename, 'rb') as f:
            for headers, contents in multipart_reader(f):
                if headers.get(
                        'Content-Disposition', ''
                ) != 'form-data; name="file"; filename="details.json"':
                    continue

                details = json.loads(contents)
                verdict = details['verdict']
                changed_verdict = self.update_verdict(run_id,
                                                      details['verdict'],
                                                      details['score'], client)
                break
        if verdict is None:
            logging.error('processed run %d but did not find details.json!',
                          run_id)
            return False

        if not self._preserve_artifacts and (not changed_verdict
                                             and changed_verdict != 'CE'):
            os.unlink(filename)
            return True

        artifacts_path = os.path.join(self._artifacts_dir, str(run_id))
        if os.path.isdir(artifacts_path):
            shutil.rmtree(artifacts_path)
        os.makedirs(artifacts_path)
        with sqlite3.connect(self._database_path) as db:
            cursor = db.cursor()
            cursor.execute('SELECT guid FROM Runs WHERE run_id = ?;',
                           (run_id, ))
            (guid, ) = cursor.fetchone()
            os.symlink(
                '/var/lib/omegaup/submissions/{}/{}'.format(
                    guid[:2], guid[2:]), os.path.join(artifacts_path,
                                                      'source'))
        with open(os.path.join(artifacts_path, verdict), 'w') as _:
            pass
        with open(filename, 'rb') as f:
            for headers, contents in multipart_reader(f):
                part_filename_match = _FILENAME_RE.match(
                    headers.get('Content-Disposition', ''))
                if not part_filename_match:
                    continue
                part_filename = part_filename_match.group(1)
                with open(os.path.join(artifacts_path, part_filename),
                          'wb') as pf:
                    pf.write(contents)
        os.unlink(filename)
        return True

    def process_multi(self, run_id: int, client: str) -> None:
        zip_path = os.path.join(self._grade_dir, f'{run_id}.zip')
        with zipfile.ZipFile(zip_path) as zf:
            with zf.open('details.json') as df:
                details = json.load(df)

        artifacts_path = os.path.join(self._artifacts_dir, str(run_id))
        if os.path.isdir(artifacts_path):
            shutil.rmtree(artifacts_path)
        os.makedirs(artifacts_path)
        with open(os.path.join(artifacts_path, 'details.json'), 'w') as af:
            json.dump(details, af)

        with sqlite3.connect(self._database_path) as db:
            cursor = db.cursor()
            cursor.execute('SELECT guid FROM Runs WHERE run_id = ?;',
                           (run_id, ))
            (guid, ) = cursor.fetchone()
            os.symlink(
                '/var/lib/omegaup/submissions/{}/{}'.format(
                    guid[:2], guid[2:]), os.path.join(artifacts_path,
                                                      'source'))
        with open(os.path.join(artifacts_path, details['focal']['verdict']),
                  'w') as f:
            pass

        with sqlite3.connect(self._database_path) as db:
            cursor = db.cursor()
            cursor.execute(
                '''
            UPDATE
                Runs
            SET
                verdict = ?, score = ?, new_verdict = ?, new_score = ?,
                judged_by = ?
            WHERE
                run_id = ?;
            ''', (
                    details['bionic']['verdict'],
                    details['bionic']['score'],
                    details['focal']['verdict'],
                    details['focal']['score'],
                    client,
                    run_id,
                ))
            db.commit()

        changed_verdict: Optional[str] = None
        if (details['bionic']['verdict'] != details['focal']['verdict']
                or abs(details['bionic']['score'] - details['focal']['score'])
                > 5e-3):
            logging.error('%-19s %8d: (%3s, %.2f) changed to (%3s, %.2f)',
                          client, run_id, details['bionic']['verdict'],
                          details['bionic']['score'],
                          details['focal']['verdict'],
                          details['focal']['score'])
            if details['focal']['score'] < details['bionic']['score'] - 5e-3:
                changed_verdict = details['focal']['verdict']
        else:
            logging.info('%-19s %8d: (%3s, %.2f) OK', client, run_id,
                         details['bionic']['verdict'],
                         details['bionic']['score'])

        if self._preserve_artifacts or (changed_verdict is not None
                                        and changed_verdict != 'CE'):
            with zipfile.ZipFile(zip_path) as z:
                z.extractall(artifacts_path)
        os.unlink(zip_path)


class GraderHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self) -> None:
        peer_name = dict(
            itertools.chain(*self.connection.getpeercert()
                            ['subject']))['commonName'].split('.')[0]
        logging.debug('%s: peer %s', self.path, peer_name)

        if self.path == '/run/request/':
            while True:
                try:
                    run = self.server.run
                    if not run:
                        logging.info('%-19s %8s: No more runs', peer_name, '')
                        self.send_response(404)
                        self.send_header('Sync-Id',
                                         str(int(time.time() * 1e6)))
                        self.send_header('Content-Length', '0')
                        self.send_header('Connection', 'close')
                        self.end_headers()
                        return

                    with open(
                            os.path.join(
                                '/var/lib/omegaup/submissions/{}/{}'.format(
                                    run.guid[:2],
                                    run.guid[2:]))) as submission_file:
                        payload = json.dumps({
                            'attempt_id': run.id,
                            'source': submission_file.read(),
                            'language': run.language,
                            'input_hash': run.version,
                            'max_score': 100,
                            'debug': False,
                        }).encode('utf-8')
                    self.send_response(200)
                    self.send_header('Sync-Id', str(int(time.time() * 1e6)))
                    self.send_header('Content-Type', 'text/json')
                    self.send_header('Content-Length', str(len(payload)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    logging.debug('%s: sending %r', self.path, run)

                    self.wfile.write(payload)
                    break
                except FileNotFoundError:
                    logging.exception('Missing source file')
                    self.server.delete_missing_run(run.id)

        elif self.path.startswith('/input/'):
            entry = self.server.entry(self.path.strip('/').split('/')[-1])
            if not entry:
                logging.info('%s: Not found', self.path)
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.send_header('Connection', 'close')
                self.end_headers()
                return
            with open(entry.path, 'rb') as entry_file:
                self.send_response(200)
                self.send_header('Content-Type', 'application/tar+gzip')
                self.send_header('Content-Length', str(entry.size))
                self.send_header('X-Content-Uncompressed-Size',
                                 str(entry.uncompressed_size))
                self.send_header('Content-SHA1', entry.hash)
                self.send_header('Connection', 'close')
                self.end_headers()

                entry_file.seek(0, os.SEEK_SET)
                while True:
                    buf = entry_file.read(4096)
                    if not buf:
                        break
                    self.wfile.write(buf)
        else:
            logging.info('%s: Not found', self.path)
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()

    def do_POST(self) -> None:
        judged_by = dict(
            itertools.chain(*self.connection.getpeercert()
                            ['subject']))['commonName'].split('.')[0]
        match = _RUN_RESULTS_RE.match(self.path)
        if not match:
            logging.info('%s: Not found', self.path)
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
            return

        run_id = int(match.group(1))
        if match.group(2) == 'results.zip':
            with open(os.path.join(self.server.grade_dir, f'{run_id}.zip'),
                      'wb') as run_zip_file:
                buf = self.rfile.read(int(self.headers['Content-Length']))
                run_zip_file.write(buf)
            self.server.process_multi(run_id, judged_by)

            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
        else:
            r = ChunkedReader(self.rfile)
            with open(os.path.join(self.server.grade_dir, str(run_id)),
                      'wb') as run_results_file:
                while True:
                    buf = r.read(4096)
                    if not buf:
                        break
                    run_results_file.write(buf)
            self.server.process(run_id, judged_by)

            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()

    def log_error(self, format_string: str, *args: Any) -> None:
        logging.error(format_string, *args)

    def log_message(self, format_string: str, *args: Any) -> None:
        logging.info(format_string, *args)

    def log_request(self,
                    code: Union[int, str] = '-',
                    size: Union[int, str] = '-') -> None:
        logging.debug('"%s %s %s" %s %s', self.command, self.path,
                      self.request_version, code, size)


def _main() -> None:
    parser = argparse.ArgumentParser('omegaUp fake grader')
    parser.add_argument('--port', type=int, default=20896)
    parser.add_argument('--cert-filename', type=str)
    parser.add_argument('--key-filename', type=str)
    parser.add_argument('--cache-dir',
                        type=str,
                        default=os.path.join(_ROOT, 'cache'))
    parser.add_argument('--cache-size', type=int, default=1024**3)
    parser.add_argument('--grade-dir',
                        type=str,
                        default=os.path.join(_ROOT, 'grade'))
    parser.add_argument('--artifacts-dir',
                        type=str,
                        default=os.path.join(_ROOT, 'artifacts'))
    parser.add_argument('--hostname',
                        type=str,
                        help='Fully-qualified domain name for the certificate')
    parser.add_argument('--preserve-artifacts', action='store_true')
    parser.add_argument('--database', type=str, default='runs.db')
    parser.add_argument('--runs', type=str)
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    os.makedirs(args.grade_dir, exist_ok=True)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s [%(levelname)-8s] %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s [%(levelname)-8s] %(message)s')

    if not args.cert_filename or not args.key_filename:
        args.cert_filename = os.path.join(_ROOT, 'certificate.pem')
        args.key_filename = os.path.join(_ROOT, 'key.pem')
        if not args.hostname:
            raise ValueError(
                '--hostname argument is required when generating certificates')
        _generate_certificates(args.cert_filename,
                               args.key_filename,
                               common_name=args.hostname)

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(args.cert_filename, args.key_filename)
    ssl_ctx.load_verify_locations(cafile=args.cert_filename)
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    cache = InputCache(args.cache_dir, args.cache_size)

    if args.runs:
        runs = _load_runs(args.database,
                          [int(run_id, 10) for run_id in args.runs.split(',')])
    else:
        runs = _load_all_runs(args.database)

    with GraderServer(("", args.port), GraderHandler, runs, cache,
                      args.grade_dir, args.artifacts_dir, args.database,
                      args.preserve_artifacts) as httpd:
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
        logging.info('serving at port %d', args.port)
        httpd.serve_forever()


if __name__ == '__main__':
    _main()
