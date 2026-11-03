"""Native OpenBao Raft recovery experiments against an owned disposable process.

This adapter never attaches to an existing service. Credentials and unseal shares
are transient. The independent policy is an observation oracle, not an access
filter: every probe goes directly to OpenBao's native HTTP API.
"""

from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import html
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from .evidence import sha256, write_json

SCHEMA = 'restoreguard.openbao.v1'
CHECKPOINTS = ('before_revocation', 'after_revocation')
RESOURCE = 'restoreguard/data/fixture'
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024


class AdapterError(ValueError):
    """A sanitized native-adapter failure, never an HTTP credential/body dump."""


def _exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f'{label} requires exactly: {", ".join(sorted(expected))}.')


def _integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f'{label} must be an integer from {minimum} to {maximum}.')


def validate_config(value):
    """Validate the complete executable format; unknown keys fail closed."""
    _exact_keys(value, ('schema_version', 'adapter', 'expected_version', 'repeats',
                        'startup_timeout_seconds', 'request_timeout_seconds', 'scenarios'), 'Config')
    if value['schema_version'] != SCHEMA or value['adapter'] != 'openbao-raft':
        raise ValueError('Unsupported schema_version or adapter.')
    if not isinstance(value['expected_version'], str) or not re.fullmatch(r'\d+\.\d+\.\d+', value['expected_version']):
        raise ValueError('expected_version must be an exact release version, e.g. 2.7.1.')
    _integer(value['repeats'], 1, 3, 'repeats')
    _integer(value['startup_timeout_seconds'], 5, 60, 'startup_timeout_seconds')
    _integer(value['request_timeout_seconds'], 1, 30, 'request_timeout_seconds')
    scenarios = value['scenarios']
    if not isinstance(scenarios, list) or not 1 <= len(scenarios) <= 8:
        raise ValueError('scenarios must contain 1 to 8 scenario objects.')
    identifiers = set()
    for scenario in scenarios:
        _exact_keys(scenario, ('id', 'restore_checkpoint', 'expected_outcome'), 'Scenario')
        identifier = scenario['id']
        if not isinstance(identifier, str) or not re.fullmatch(r'[A-Z][A-Z0-9_-]{1,39}', identifier):
            raise ValueError('Scenario id must be 2 to 40 uppercase letters, digits, hyphens or underscores.')
        if identifier in identifiers:
            raise ValueError('Scenario ids must be unique.')
        identifiers.add(identifier)
        if scenario['restore_checkpoint'] not in CHECKPOINTS:
            raise ValueError('Unknown restore_checkpoint.')
        if scenario['expected_outcome'] not in ('PASS', 'FAIL'):
            raise ValueError('expected_outcome must be PASS or FAIL.')
    return json.loads(json.dumps(value))


def _read_json(path, limit, label):
    # Bound the actual read, not a preceding stat that can become stale.
    with Path(path).open('rb') as stream:
        encoded = stream.read(limit + 1)
    if len(encoded) > limit:
        raise ValueError(f'{label} exceeds its {limit}-byte limit.')
    def no_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f'Duplicate JSON key in {label}.')
            value[key] = item
        return value
    def reject_constant(_):
        raise ValueError('Non-finite JSON number.')
    try:
        return json.loads(encoded.decode('utf-8-sig'), object_pairs_hook=no_duplicates,
                          parse_constant=reject_constant)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError(f'{label} must contain bounded, valid UTF-8 JSON.') from exc


def load_config(path):
    return validate_config(_read_json(path, 64 * 1024, 'Configuration (64 KiB)'))


def _clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.upper().startswith(('BAO_', 'VAULT_'))}


def inspect_executable(executable, expected_version):
    executable = Path(executable).resolve(strict=True)
    if not executable.is_file() or executable.name.lower() not in ('bao', 'bao.exe'):
        raise ValueError('Supply the official local bao or bao.exe executable.')
    try:
        result = subprocess.run([str(executable), 'version'], capture_output=True, text=True,
                                timeout=10, env=_clean_environment(),
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdapterError('Could not inspect the supplied OpenBao executable.') from exc
    match = re.search(r'OpenBao v(\d+\.\d+\.\d+)(?:\s|$)', result.stdout)
    if result.returncode != 0 or not match or match.group(1) != expected_version:
        raise ValueError('OpenBao executable does not match expected_version.')
    return executable, {'product': 'OpenBao', 'version': match.group(1), 'sha256': sha256(executable)}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def classify_read(actor, expected, status, payload, marker):
    """A 2xx without the exact known fixture value is unknown, never allowed."""
    data = payload.get('data') if isinstance(payload, dict) else None
    value = data.get('data') if isinstance(data, dict) else None
    exposed = isinstance(value, dict) and value.get('marker') == marker
    if exposed:
        observed, verdict = 'allowed', 'PASS' if expected == 'allow' else 'FAIL'
    elif status in (401, 403) and isinstance(payload, dict) and isinstance(payload.get('errors'), list):
        observed, verdict = 'denied', 'PASS' if expected == 'deny' else 'FAIL'
    else:
        observed, verdict = 'unknown', 'INCONCLUSIVE'
    return {'actor': actor, 'resource': RESOURCE, 'action': 'read', 'expected': expected,
            'transport_status': status, 'fixture_value_returned': exposed,
            'observed': observed, 'status': verdict}


def experiment_verdict(probes):
    # A demonstrated forbidden read remains a finding even if the positive
    # control is unavailable; a claimed safe result requires both controls.
    if any(probe['status'] == 'FAIL' for probe in probes):
        return 'FAIL'
    complete = {probe['actor'] for probe in probes} == {'revoked-client', 'allowed-client'} and len(probes) == 2
    return 'PASS' if complete and all(probe['status'] == 'PASS' for probe in probes) else 'INCONCLUSIVE'


class OwnedOpenBao:
    def __init__(self, executable, config, trace):
        self.executable, self.config, self.trace = executable, config, trace
        self.process = None
        self.cleanup = None
        self.root_token = self.unseal_key = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def __enter__(self):
        self.cleanup = ExitStack()
        try:
            directory = Path(self.cleanup.enter_context(tempfile.TemporaryDirectory(prefix='restoreguard-bao-')))
            # Keep the cluster port reserved while selecting the separate API port.
            with socket.socket() as cluster_socket, socket.socket() as api_socket:
                cluster_socket.bind(('127.0.0.1', 0))
                api_socket.bind(('127.0.0.1', 0))
                cluster_port, api_port = cluster_socket.getsockname()[1], api_socket.getsockname()[1]
            self.base_url = f'http://127.0.0.1:{api_port}/v1/'
            data = directory / 'raft'
            data.mkdir()
            configuration = {'disable_mlock': True, 'ui': False,
                             'cluster_name': 'restoreguard-' + uuid.uuid4().hex,
                             'api_addr': f'http://127.0.0.1:{api_port}',
                             'cluster_addr': f'https://127.0.0.1:{cluster_port}',
                             'storage': {'raft': {'path': str(data), 'node_id': 'restoreguard-local',
                                                  'performance_multiplier': 1}},
                             'listener': [{'tcp': {'address': f'127.0.0.1:{api_port}',
                                                   'cluster_address': f'127.0.0.1:{cluster_port}',
                                                   'tls_disable': True}}]}
            config_path = directory / 'server.json'
            write_json(config_path, configuration)
            log = self.cleanup.enter_context((directory / 'server.log').open('wb'))
            self.process = subprocess.Popen([str(self.executable), 'server', '-config=' + str(config_path)],
                                            cwd=directory, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                            env=_clean_environment(),
                                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            self.trace.append({'event': 'owned_process_started', 'pid': self.process.pid,
                               'listener': 'loopback-only', 'storage': 'new disposable Raft directory'})
            status = self.wait_for('sys/init', lambda code, body: code == 200)
            if status.get('initialized') is not False:
                raise AdapterError('Refusing to initialize a listener that is already initialized.')
            response = self.json_request('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
            self.root_token = response['root_token']
            self.unseal_key = response['keys_base64'][0]
            self.json_request('POST', 'sys/unseal', {'key': self.unseal_key})
            health = self.wait_for('sys/health', lambda code, body: code == 200 and body.get('sealed') is False)
            if health.get('cluster_name') != configuration['cluster_name']:
                raise AdapterError('Owned service identity check failed.')
            self.trace.append({'event': 'initialized_and_unsealed', 'cluster_name': health['cluster_name']})
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        errors = []
        try:
            if self.process is not None and self.process.poll() is None:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=10)
                except (OSError, subprocess.SubprocessError):
                    # A failed gentle stop must still attempt the owned PID's
                    # forced stop; never kill by executable name or port.
                    self.process.kill()
                    self.process.wait(timeout=10)
            if self.process is not None:
                self.trace.append({'event': 'owned_process_stopped', 'pid': self.process.pid,
                                   'returncode': self.process.returncode})
        except (OSError, subprocess.SubprocessError):
            errors.append('Owned OpenBao process cleanup could not be confirmed.')
            self.trace.append({'event': 'owned_process_cleanup_failed', 'pid': self.process.pid})
        finally:
            self.root_token = self.unseal_key = None
            if self.cleanup is not None:
                try:
                    self.cleanup.close()
                except OSError:
                    errors.append('Temporary OpenBao storage cleanup could not be confirmed.')
                    self.trace.append({'event': 'temporary_storage_cleanup_failed'})
        if errors:
            raise AdapterError(' '.join(errors))

    def request(self, method, path, body=None, token=None, raw=False, timeout=None):
        if self.process is None or self.process.poll() is not None:
            raise AdapterError('Owned OpenBao process exited; no external listener will be contacted.')
        headers = {'Content-Type': 'application/octet-stream' if raw else 'application/json'}
        if token:
            headers['X-Vault-Token'] = token
        data = body if raw else (json.dumps(body).encode() if body is not None else None)
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        budget = self.config['request_timeout_seconds'] if timeout is None else min(timeout, self.config['request_timeout_seconds'])
        if budget <= 0:
            raise AdapterError('Native API request deadline expired.')
        deadline = time.monotonic() + budget
        try:
            try:
                response = self.opener.open(request, timeout=budget)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                blocks, size = [], 0
                while True:
                    if time.monotonic() >= deadline:
                        raise AdapterError('Native API response deadline expired.')
                    # read1 returns currently available buffered data. Reading
                    # the whole response can hide a slow trickle indefinitely.
                    block = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                    if not block:
                        break
                    blocks.append(block)
                    size += len(block)
                    if size > MAX_RESPONSE_BYTES:
                        raise AdapterError('Native response exceeds the 32 MiB disposable-lab limit.')
                payload = b''.join(blocks)
                status = response.status
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            raise AdapterError('Native API request could not complete.') from exc
        self.trace.append({'event': 'http_response', 'method': method, 'path': path,
                           'status': status, 'response_bytes': len(payload)})
        if raw:
            return status, payload
        try:
            return status, json.loads(payload) if payload else {}
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise AdapterError('Native API returned a non-JSON response.') from exc

    def json_request(self, method, path, body=None, token=None, timeout=None):
        code, payload = self.request(method, path, body, token, timeout=timeout)
        if not 200 <= code < 300 or not isinstance(payload, dict):
            raise AdapterError(f'Native API step {method} {path} failed with HTTP {code}.')
        return payload

    def wait_for(self, path, condition, token=None, unseal_if_needed=False):
        deadline = time.monotonic() + self.config['startup_timeout_seconds']
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AdapterError('Owned OpenBao exited before readiness; check binary/runtime compatibility.')
            try:
                if unseal_if_needed:
                    code, body = self.request('GET', 'sys/seal-status', timeout=deadline - time.monotonic())
                    if code == 200 and isinstance(body, dict) and body.get('sealed') is True:
                        self.json_request('POST', 'sys/unseal', {'key': self.unseal_key},
                                          timeout=deadline - time.monotonic())
                code, body = self.request('GET', path, token=token, timeout=deadline - time.monotonic())
                if isinstance(body, dict) and condition(code, body):
                    return body
            except AdapterError:
                pass
            time.sleep(max(0, min(0.15, deadline - time.monotonic())))
        raise AdapterError('Owned OpenBao did not become ready within the configured deadline.')

    def snapshot(self, path):
        status, payload = self.request('GET', 'sys/storage/raft/snapshot', token=self.root_token, raw=True)
        if status != 200 or not payload.startswith(b'\x1f\x8b'):
            raise AdapterError('Native Raft snapshot download failed or was not a gzip archive.')
        Path(path).write_bytes(payload)
        return {'file': Path(path).name, 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}

    def restore(self, path, checkpoint, expected_sha256):
        path = Path(path)
        if _linked(path) or path.stat().st_size > MAX_RESPONSE_BYTES:
            raise AdapterError('Native snapshot is linked or exceeds the supported size.')
        with path.open('rb') as stream:
            snapshot = stream.read(MAX_RESPONSE_BYTES + 1)
        if len(snapshot) > MAX_RESPONSE_BYTES or hashlib.sha256(snapshot).hexdigest() != expected_sha256:
            raise AdapterError('Native snapshot changed after capture; restore refused.')
        # A native restore may return before recovery completes. A fresh barrier
        # value must disappear and the snapshot's distinct marker must return.
        self.json_request('POST', 'restoreguard/data/checkpoint',
                          {'data': {'checkpoint': 'restore-barrier-' + uuid.uuid4().hex}}, self.root_token)
        status, _ = self.request('POST', 'sys/storage/raft/snapshot', snapshot, self.root_token, raw=True)
        if status not in (200, 204):
            raise AdapterError(f'Native snapshot restore returned HTTP {status}.')
        # A restore can seal the same instance; only this initialization's share
        # may be used. Force-restore and foreign snapshots are never supported.
        def checkpoint_matches(code, body):
            data = body.get('data')
            value = data.get('data') if isinstance(data, dict) else None
            return code == 200 and isinstance(value, dict) and value.get('checkpoint') == checkpoint
        self.wait_for('restoreguard/data/checkpoint', checkpoint_matches, token=self.root_token, unseal_if_needed=True)
        self.trace.append({'event': 'restored_checkpoint_verified', 'checkpoint': checkpoint})


def _probe_pair(service, tokens, marker, expected):
    probes = []
    for actor in ('revoked-client', 'allowed-client'):
        try:
            status, payload = service.request('GET', RESOURCE, token=tokens[actor])
            probe = classify_read(actor, expected[actor], status, payload, marker)
        except AdapterError:
            probe = classify_read(actor, expected[actor], None, {}, marker)
        probes.append(probe)
    return probes


def _run_repetition(executable, config, directory, repeat, trace, results):
    snapshots = directory / f'repeat-{repeat}'
    snapshots.mkdir()
    marker = 'synthetic-' + uuid.uuid4().hex
    journal = {'schema_version': 'restoreguard.current-policy.v1', 'resource': RESOURCE,
               'expectations': {'revoked-client': 'deny', 'allowed-client': 'allow'},
               'authority': 'test-defined current security intent; not restored'}
    journal_path = snapshots / 'current-policy.json'
    write_json(journal_path, journal)
    journal_hash = sha256(journal_path)
    with OwnedOpenBao(executable, config, trace) as service:
        root = service.root_token
        service.json_request('POST', 'sys/mounts/restoreguard', {'type': 'kv', 'options': {'version': '2'}}, root)
        # Mount creation can return before KV's versioned backend is ready.
        # Read its native configuration before issuing any fixture writes.
        service.wait_for('restoreguard/config',
                         lambda code, body: code == 200 and isinstance(body.get('data'), dict), token=root)
        service.json_request('POST', 'sys/policies/acl/restoreguard-read',
                             {'policy': 'path "restoreguard/data/fixture" { capabilities = ["read"] }'}, root)
        service.json_request('POST', RESOURCE, {'data': {'marker': marker}}, root)
        service.json_request('POST', 'restoreguard/data/checkpoint', {'data': {'checkpoint': CHECKPOINTS[0]}}, root)
        tokens = {}
        for actor in ('revoked-client', 'allowed-client'):
            response = service.json_request('POST', 'auth/token/create',
                                            {'policies': ['restoreguard-read'], 'no_default_policy': True,
                                             'ttl': '1h', 'explicit_max_ttl': '1h', 'renewable': False,
                                             'type': 'service', 'display_name': actor}, root)
            tokens[actor] = response['auth']['client_token']
        before = _probe_pair(service, tokens, marker, {'revoked-client': 'allow', 'allowed-client': 'allow'})
        trace.append({'event': 'before_revocation_controls', 'repeat': repeat, 'probes': before})
        if experiment_verdict(before) != 'PASS':
            raise AdapterError('Pre-revocation authorization controls did not pass.')
        metadata = {CHECKPOINTS[0]: service.snapshot(snapshots / 'before_revocation.snap')}
        service.json_request('POST', 'auth/token/revoke', {'token': tokens['revoked-client']}, root)
        after = _probe_pair(service, tokens, marker, journal['expectations'])
        trace.append({'event': 'verified_revocation_controls', 'repeat': repeat, 'probes': after})
        if experiment_verdict(after) != 'PASS':
            raise AdapterError('Revocation was not verified with the allowed-client positive control.')
        service.json_request('POST', 'restoreguard/data/checkpoint', {'data': {'checkpoint': CHECKPOINTS[1]}}, root)
        metadata[CHECKPOINTS[1]] = service.snapshot(snapshots / 'after_revocation.snap')
        for scenario in config['scenarios']:
            checkpoint = scenario['restore_checkpoint']
            service.restore(snapshots / f'{checkpoint}.snap', checkpoint, metadata[checkpoint]['sha256'])
            if sha256(journal_path) != journal_hash:
                raise AdapterError('Independent policy changed during restore; result cannot be trusted.')
            probes = _probe_pair(service, tokens, marker, journal['expectations'])
            observed = experiment_verdict(probes)
            results.append({**scenario, 'repeat': repeat, 'observed_outcome': observed,
                            'expectation_matched': observed == scenario['expected_outcome'],
                            'positive_control_passed': probes[1]['status'] == 'PASS',
                            'independent_policy_sha256': journal_hash,
                            'snapshot': metadata[checkpoint], 'probes': probes})
            trace.append({'event': 'restore_probed', 'repeat': repeat, 'scenario_id': scenario['id'],
                           'checkpoint': checkpoint, 'observed_outcome': observed})


def _render_service_report(case):
    rows = ''.join('<tr>' + ''.join('<td>' + html.escape(str(result[key])) + '</td>'
                                  for key in ('id', 'repeat', 'restore_checkpoint', 'expected_outcome',
                                              'observed_outcome', 'positive_control_passed')) + '</tr>'
                   for result in case['results'])
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>RestoreGuard native OpenBao evidence</title>'
            '<style>body{font:16px system-ui;max-width:1100px;margin:48px auto;padding:20px}td,th{padding:12px;border:1px solid #aaa}'
            'table{border-collapse:collapse}pre{white-space:pre-wrap}</style><h1>RestoreGuard: native OpenBao recovery</h1>'
            '<p>Owned disposable single-node Raft service. Direct native authorization probes; no external enforcement proxy.</p>'
            '<p>Security verdict: <strong>' + html.escape(case['security_status']) + '</strong>. Expectations: <strong>'
            + html.escape(case['status']) + '</strong>.</p><table><tr><th>Scenario</th><th>Repeat</th><th>Restored checkpoint</th>'
            '<th>Expected</th><th>Observed</th><th>Allowed control</th></tr>' + rows + '</table><h2>Evidence and limits</h2><pre>'
            + html.escape(json.dumps({'runtime': case['runtime'], 'errors': case['errors'], 'limitations': case['limitations']}, indent=2))
            + '</pre></html>')


def run_openbao(config, executable, output_dir='service-runs'):
    config = validate_config(config)
    executable, runtime = inspect_executable(executable, config['expected_version'])
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    case_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-openbao-' + uuid.uuid4().hex[:10]
    directory = root / case_id
    directory.mkdir()
    trace, results, errors = [], [], []
    try:
        for repeat in range(1, config['repeats'] + 1):
            _run_repetition(executable, config, directory, repeat, trace, results)
    except (AdapterError, OSError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as exc:
        # Native HTTP response bodies, tokens, and key material are never exposed.
        errors.append(str(exc) if isinstance(exc, AdapterError) else 'Native lifecycle failed (' + type(exc).__name__ + ').')
    complete = not errors and len(results) == config['repeats'] * len(config['scenarios'])
    outcomes = [result['observed_outcome'] for result in results]
    security = 'FAIL' if 'FAIL' in outcomes else ('PASS' if complete and all(value == 'PASS' for value in outcomes) else 'INCONCLUSIVE')
    status = ('PASS' if all(result['expectation_matched'] for result in results) else 'FAIL') if complete and 'INCONCLUSIVE' not in outcomes else 'INCONCLUSIVE'
    case = {'schema_version': SCHEMA, 'case_id': case_id, 'created_at': datetime.now(timezone.utc).isoformat(),
            'adapter': 'openbao-raft', 'runtime': runtime, 'config': config,
            'status': status, 'security_status': security, 'complete': complete,
            'directory': str(directory), 'results': results, 'errors': errors,
            'limitations': ['Owned loopback-only single-node service; no production/existing endpoint support.',
                            'Only restricted service-token revocation and two native Raft checkpoints are covered.',
                            'Snapshot rollback is expected historical-state behavior, not a new product vulnerability claim.',
                            'Current policy is an independent oracle; it does not enforce or repair native access.',
                            'No HA, Keycloak, JWT, remote storage, crashes, token expiry, or cross-product restore matrix.',
                            'Root token, probe tokens, and unseal share are discarded; raw snapshots contain encrypted synthetic state.',
                            'Unsigned manifests check integrity relative to the manifest, not authenticity.']}
    write_json(directory / 'service.json', case)
    write_json(directory / 'trace.json', trace)
    (directory / 'report.html').write_text(_render_service_report(case), encoding='utf-8')
    write_json(directory / 'manifest.json', {'schema_version': SCHEMA, 'algorithm': 'sha256',
                                           'files': {p.relative_to(directory).as_posix(): sha256(p)
                                                     for p in sorted(directory.rglob('*')) if p.is_file()}})
    return case


def verify_service(directory):
    try:
        directory = Path(directory).absolute()
        if _linked(directory) or not directory.is_dir():
            raise ValueError('Native evidence directory must be an ordinary local directory.')
        directory = directory.resolve()
        manifest_path = directory / 'manifest.json'
        if _linked(manifest_path):
            raise ValueError('Native evidence manifest must not be a link.')
        manifest = _read_json(manifest_path, MAX_JSON_BYTES, 'Native manifest')
        expected = manifest.get('files')
        if manifest.get('schema_version') != SCHEMA or manifest.get('algorithm') != 'sha256' or not isinstance(expected, dict):
            raise ValueError('Invalid native evidence manifest.')
        if not {'service.json', 'trace.json', 'report.html'}.issubset(expected):
            raise ValueError('Manifest omits required native evidence.')
        errors = []
        for name, digest in expected.items():
            relative = PurePosixPath(name)
            if (relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name
                    or not relative.parts or name == 'manifest.json' or relative.as_posix() != name
                    or any(part.rstrip(' .') != part for part in relative.parts)):
                errors.append('Unsafe manifest path: ' + name)
                continue
            path = directory.joinpath(*relative.parts)
            if any(_linked(directory.joinpath(*relative.parts[:length])) for length in range(1, len(relative.parts) + 1)) or not path.resolve().is_relative_to(directory):
                errors.append('Unsafe evidence path: ' + name)
            elif not path.is_file() or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or sha256(path) != digest:
                errors.append('Missing or changed evidence: ' + name)
        for path in directory.rglob('*'):
            if _linked(path):
                errors.append('Linked evidence entry: ' + path.relative_to(directory).as_posix())
        actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*')
                  if p.is_file() and p != directory / 'manifest.json'}
        errors.extend('Unexpected evidence: ' + name for name in sorted(actual - set(expected)))
        if not errors:
            case = _read_json(directory / 'service.json', MAX_JSON_BYTES, 'Native result')
            if not isinstance(case, dict) or case.get('schema_version') != SCHEMA or type(case.get('complete')) is not bool:
                raise ValueError('Invalid native result contract.')
            if case['complete']:
                configuration = validate_config(case.get('config'))
                required = {f'repeat-{repeat}/{name}'
                            for repeat in range(1, configuration['repeats'] + 1)
                            for name in ('current-policy.json', 'before_revocation.snap', 'after_revocation.snap')}
                if not required.issubset(expected):
                    raise ValueError('Complete native run omits required snapshot or policy evidence.')
                if not isinstance(case.get('results'), list) or len(case['results']) != configuration['repeats'] * len(configuration['scenarios']):
                    raise ValueError('Complete native run has an incomplete result catalogue.')
        return {'status': 'FAIL' if errors else 'PASS', 'checked_files': len(expected), 'errors': errors}
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        return {'status': 'FAIL', 'checked_files': 0, 'errors': [str(exc)]}


def _linked(path):
    """Reject symbolic links and Windows junction/reparse points without following them."""
    try:
        metadata = Path(path).lstat()
        return stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, 'st_file_attributes', 0) & 0x400)
    except FileNotFoundError:
        return False
