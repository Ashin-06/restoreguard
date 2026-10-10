"""Atomic local run storage and verified, portable evidence bundles."""

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import uuid
import zipfile

from . import __version__
from .core import export_fixtures, run_matrix
from .reports import render_report

CASE_ID = re.compile(r'^\d{8}T\d{6}Z-[0-9a-f]{10}$')


def write_json(path, value):
    Path(path).write_bytes((json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode('utf-8'))


def sha256(path):
    with Path(path).open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def case_path(root, case_id):
    if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
        raise ValueError('Invalid run identifier.')
    root = Path(root).resolve()
    path = root / case_id
    if path.is_symlink() or path.resolve().parent != root or not path.is_dir():
        raise FileNotFoundError('Run not found.')
    return path


def run_case(root, mode='vulnerable', max_experiments=27, repeats=2):
    result = run_matrix(mode=mode, max_experiments=max_experiments, repeats=repeats)
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    case_id = now.strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:10]
    work = Path(tempfile.mkdtemp(prefix='.pending-', dir=root))
    try:
        fixture_metadata = export_fixtures(work / 'fixtures')
        write_json(work / 'fixtures.json', fixture_metadata)
        case = {'case_id': case_id, 'created_at': now.isoformat(), 'tool_version': __version__,
                'config': {'mode': mode, 'max_experiments': max_experiments, 'repeats': repeats},
                'result': result, 'artifacts': {kind: f'/api/cases/{case_id}/{kind}' for kind in ('report', 'json', 'bundle')}}
        write_json(work / 'case.json', case)
        (work / 'report.html').write_bytes(render_report(case).encode('utf-8'))
        manifest = {'algorithm': 'sha256', 'case_id': case_id, 'tool_version': __version__,
                    'files': {p.relative_to(work).as_posix(): sha256(p) for p in sorted(work.rglob('*')) if p.is_file()}}
        write_json(work / 'manifest.json', manifest)
        work.rename(root / case_id)
        return case
    except BaseException:
        if work.exists() and work.resolve().parent == root and work.name.startswith('.pending-'):
            shutil.rmtree(work)
        raise


def load_case(root, case_id):
    return json.loads((case_path(root, case_id) / 'case.json').read_text(encoding='utf-8'))


def list_cases(root):
    root = Path(root)
    if not root.exists():
        return []
    cases = []
    for path in sorted(root.iterdir(), reverse=True):
        if not CASE_ID.fullmatch(path.name) or path.is_symlink() or not path.is_dir():
            continue
        try:
            case = load_case(root, path.name)
            cases.append({'case_id': case['case_id'], 'created_at': case['created_at'],
                          'mode': case['result']['mode'], 'status': case['result']['status'], 'summary': case['result']['summary']})
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return cases


def verify_case(directory):
    directory = Path(directory).resolve()
    errors = []
    try:
        manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
        expected = manifest.get('files')
        if manifest.get('algorithm') != 'sha256' or not isinstance(expected, dict) or not expected:
            raise ValueError('Invalid or empty manifest.')
        if not {'case.json', 'report.html', 'fixtures.json'}.issubset(expected):
            raise ValueError('Manifest omits required evidence files.')
        for name, digest in expected.items():
            relative = PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name or not relative.parts:
                errors.append(f'Unsafe manifest path: {name}')
                continue
            path = directory.joinpath(*relative.parts)
            if path.is_symlink() or not path.resolve().is_relative_to(directory):
                errors.append(f'Unsafe evidence path: {name}')
            elif not path.is_file():
                errors.append(f'Missing: {name}')
            elif not isinstance(digest, str) or sha256(path) != digest:
                errors.append(f'Hash mismatch: {name}')
        actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file() and p != directory / 'manifest.json'}
        errors.extend(f'Unexpected: {name}' for name in sorted(actual - set(expected)))
        return {'status': 'FAIL' if errors else 'PASS', 'checked_files': len(expected), 'errors': errors,
                'limitation': 'Unsigned hashes provide integrity relative to a manifest, not authenticity.'}
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        return {'status': 'FAIL', 'checked_files': 0, 'errors': [str(exc)]}


def bundle_case(root, case_id):
    directory = case_path(root, case_id)
    if verify_case(directory)['status'] != 'PASS':
        raise ValueError('Run integrity check failed; modified evidence cannot be exported.')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(directory.rglob('*')):
            if path.is_file() and not path.is_symlink():
                archive.write(path, arcname=case_id + '/' + path.relative_to(directory).as_posix())
    return output.getvalue()
