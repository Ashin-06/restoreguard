"""Adapter contract/error checks and optional real OpenBao integration.

Set RESTOREGUARD_OPENBAO_EXE to the verified local bao binary to run the
integration class. It always starts and destroys its own loopback instance.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from restoreguard.openbao import (AdapterError, OwnedOpenBao, _clean_environment,
                                  classify_read, experiment_verdict, inspect_executable,
                                  load_config, run_openbao, validate_config, verify_service)


PROJECT = Path(__file__).resolve().parents[1]


def config():
    return load_config(PROJECT / 'examples' / 'openbao-local.json')


class ConfigTests(unittest.TestCase):
    def test_executable_example_is_strict_and_copied(self):
        value = config()
        clone = validate_config(value)
        clone['scenarios'][0]['id'] = 'CHANGED'
        self.assertEqual(value['scenarios'][0]['id'], 'OB001')

    def test_unknown_fields_reject_external_endpoint_and_commands(self):
        for key in ('endpoint', 'command', 'token', 'docker', 'url'):
            value = config()
            value[key] = 'anything'
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_config(value)

    def test_numbers_are_bounded_and_booleans_not_numbers(self):
        for key, invalid in [('repeats', 0), ('repeats', 4), ('repeats', True),
                             ('startup_timeout_seconds', 61), ('request_timeout_seconds', 0)]:
            value = config()
            value[key] = invalid
            with self.subTest(key=key, invalid=invalid), self.assertRaises(ValueError):
                validate_config(value)

    def test_bad_versions_scenarios_and_unknown_steps_fail(self):
        changes = [('expected_version', 'latest'), ('scenarios', []), ('scenarios', [None]),
                   ('adapter', 'remote'), ('schema_version', '0.1-design')]
        for key, invalid in changes:
            value = config()
            value[key] = invalid
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_config(value)
        for key, invalid in [('restore_checkpoint', '../../other'), ('id', 'a/b'),
                             ('expected_outcome', 'INCONCLUSIVE'), ('arbitrary_request', 'DELETE')]:
            value = config()
            value['scenarios'][0][key] = invalid
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_config(value)

    def test_duplicate_scenario_and_json_keys_rejected(self):
        value = config()
        value['scenarios'][1]['id'] = value['scenarios'][0]['id']
        with self.assertRaises(ValueError):
            validate_config(value)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text('{"adapter":"one","adapter":"two"}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'Duplicate JSON'):
                load_config(path)

    def test_large_config_rejected_before_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_bytes(b' ' * 65537)
            with self.assertRaisesRegex(ValueError, '64 KiB'):
                load_config(path)

    def test_runtime_environment_cannot_override_service_configuration(self):
        with patch.dict(os.environ, {'VAULT_ADDR': 'https://remote.invalid', 'BAO_RAFT_PATH': '/real',
                                     'PATH': 'safe-runtime-path'}):
            clean = _clean_environment()
            self.assertNotIn('VAULT_ADDR', clean)
            self.assertNotIn('BAO_RAFT_PATH', clean)
            self.assertEqual(clean['PATH'], 'safe-runtime-path')

    def test_wrong_executable_name_or_version_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / 'anything.cmd'
            wrong.write_bytes(b'')
            with self.assertRaises(ValueError):
                inspect_executable(wrong, '2.7.1')
            executable = Path(tmp) / 'bao.exe'
            executable.write_bytes(b'not run')
            with patch('restoreguard.openbao.subprocess.run', return_value=Mock(returncode=0, stdout='OpenBao v2.6.0')):
                with self.assertRaisesRegex(ValueError, 'expected_version'):
                    inspect_executable(executable, '2.7.1')


class NativeOracleTests(unittest.TestCase):
    def test_exact_secret_read_overrides_denial_response(self):
        result = classify_read('revoked-client', 'deny', 403, {'data': {'data': {'marker': 'known'}}}, 'known')
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['fixture_value_returned'])

    def test_success_status_without_exact_value_is_unknown(self):
        for payload in ({}, {'data': {'data': {'marker': 'wrong'}}}, {'data': []}):
            with self.subTest(payload=payload):
                self.assertEqual(classify_read('allowed-client', 'allow', 200, payload, 'known')['status'], 'INCONCLUSIVE')

    def test_denial_and_unavailable_control_never_pass(self):
        allowed = classify_read('allowed-client', 'allow', 403, {'errors': ['permission denied']}, 'known')
        denied = classify_read('revoked-client', 'deny', 403, {'errors': ['permission denied']}, 'known')
        self.assertEqual(experiment_verdict([denied, allowed]), 'FAIL')
        unknown = classify_read('allowed-client', 'allow', 503, {'errors': ['sealed']}, 'known')
        self.assertEqual(experiment_verdict([denied, unknown]), 'INCONCLUSIVE')
        self.assertEqual(experiment_verdict([denied]), 'INCONCLUSIVE')
        self.assertEqual(experiment_verdict([]), 'INCONCLUSIVE')

    def test_exited_owned_process_never_contacts_another_listener(self):
        service = OwnedOpenBao(Path('bao'), config(), [])
        service.process = Mock()
        service.process.poll.return_value = 1
        service.opener = Mock()
        with self.assertRaises(AdapterError):
            service.request('GET', 'sys/init')
        service.opener.open.assert_not_called()

    def test_cleanup_stops_only_owned_process_and_clears_credentials(self):
        service = OwnedOpenBao(Path('bao'), config(), [])
        service.process = Mock()
        service.process.poll.return_value = None
        service.process.wait.side_effect = [subprocess.TimeoutExpired('bao', 10), 0]
        service.cleanup = Mock()
        service.root_token = service.unseal_key = 'transient'
        service.__exit__(None, None, None)
        service.process.terminate.assert_called_once()
        service.process.kill.assert_called_once()
        service.cleanup.close.assert_called_once()
        self.assertIsNone(service.root_token)
        self.assertIsNone(service.unseal_key)

    def test_failed_lifecycle_is_saved_as_inconclusive_and_verifiable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch('restoreguard.openbao.inspect_executable', return_value=(Path('bao'), {'version': '2.7.1'})), \
                 patch('restoreguard.openbao._run_repetition', side_effect=AdapterError('Native step failed.')):
                result = run_openbao(config(), 'bao', tmp)
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['security_status'], 'INCONCLUSIVE')
            self.assertFalse(result['complete'])
            self.assertEqual(verify_service(result['directory'])['status'], 'PASS')
            directory = Path(result['directory'])
            (directory / 'trace.json').write_text('changed', encoding='utf-8')
            self.assertEqual(verify_service(directory)['status'], 'FAIL')

    def test_later_failure_does_not_erase_completed_finding(self):
        def fail_later(executable, configuration, directory, repeat, trace, results):
            results.append({'id': 'OB001', 'repeat': 1, 'restore_checkpoint': 'before_revocation',
                            'expected_outcome': 'FAIL', 'observed_outcome': 'FAIL',
                            'positive_control_passed': True, 'expectation_matched': True})
            raise AdapterError('Second native step failed.')
        with tempfile.TemporaryDirectory() as tmp:
            with patch('restoreguard.openbao.inspect_executable', return_value=(Path('bao'), {'version': '2.7.1'})), \
                 patch('restoreguard.openbao._run_repetition', side_effect=fail_later):
                result = run_openbao(config(), 'bao', tmp)
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['security_status'], 'FAIL')
            self.assertEqual(len(result['results']), 1)

    def test_manifest_unsafe_paths_missing_files_and_nested_manifest_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'manifest.json').write_text(json.dumps({'schema_version': config()['schema_version'],
                'algorithm': 'sha256', 'files': {'service.json': 'bad', 'trace.json': 'bad',
                                                'report.html': 'bad', '../outside': 'bad'}}), encoding='utf-8')
            result = verify_service(directory)
            self.assertEqual(result['status'], 'FAIL')
            self.assertTrue(any('Unsafe' in error for error in result['errors']))


@unittest.skipUnless(os.environ.get('RESTOREGUARD_OPENBAO_EXE'), 'Set RESTOREGUARD_OPENBAO_EXE for the real disposable-service test.')
class RealOpenBaoTests(unittest.TestCase):
    def test_native_raft_pre_post_revocation_repeated_and_redacted(self):
        credentials = []
        original = OwnedOpenBao.json_request
        def capture(service, *args, **kwargs):
            response = original(service, *args, **kwargs)
            if 'root_token' in response:
                credentials.extend([response['root_token'], *response.get('keys', []), *response.get('keys_base64', [])])
            if isinstance(response.get('auth'), dict):
                credentials.append(response['auth']['client_token'])
            return response
        with tempfile.TemporaryDirectory() as tmp, patch.object(OwnedOpenBao, 'json_request', capture):
            result = run_openbao(config(), os.environ['RESTOREGUARD_OPENBAO_EXE'], tmp)
            self.assertEqual(result['status'], 'PASS', result['errors'])
            self.assertEqual(result['security_status'], 'FAIL')
            self.assertTrue(result['complete'])
            self.assertEqual(len(result['results']), 4)
            for observed in result['results']:
                self.assertTrue(observed['positive_control_passed'])
                self.assertTrue(observed['expectation_matched'])
                self.assertEqual(observed['probes'][0]['transport_status'], 200 if observed['id'] == 'OB001' else 403)
            directory = Path(result['directory'])
            self.assertEqual(verify_service(directory), {'status': 'PASS', 'checked_files': 9, 'errors': []})
            trace = json.loads((directory / 'trace.json').read_text(encoding='utf-8'))
            self.assertEqual(sum(item['event'] == 'owned_process_started' for item in trace), 2)
            self.assertEqual(sum(item['event'] == 'owned_process_stopped' for item in trace), 2)
            self.assertEqual(sum(item['event'] == 'restored_checkpoint_verified' for item in trace), 4)
            snapshots = list(directory.rglob('*.snap'))
            self.assertEqual(len(snapshots), 4)
            self.assertEqual(len({hashlib.sha256(path.read_bytes()).hexdigest() for path in snapshots}), 4)
            text = '\n'.join(path.read_text(encoding='utf-8') for path in directory.rglob('*')
                             if path.is_file() and path.suffix in ('.json', '.html'))
            self.assertGreaterEqual(len(credentials), 8)
            for credential in credentials:
                self.assertNotIn(credential, text)
            (directory / 'extra').mkdir()
            (directory / 'extra' / 'manifest.json').write_text('{}', encoding='utf-8')
            self.assertEqual(verify_service(directory)['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
