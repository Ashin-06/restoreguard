"""Command line entry points. Verdict commands use 0/1/2 for pass/fail/unknown."""

import argparse
import json
from pathlib import Path
import sys

from .core import minimize_selection, run_scenarios
from .evidence import bundle_case, run_case, verify_case


def main(argv=None):
    parser = argparse.ArgumentParser(description='RestoreGuard reference and native recovery security lab')
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('serve', help='Open the local workbench server')
    serve.add_argument('--port', type=int, default=8766)
    serve.add_argument('--runs-dir', default='runs')
    matrix = commands.add_parser('matrix', help='Run and preserve the restore selection matrix')
    matrix.add_argument('--mode', choices=['vulnerable', 'protected'], default='vulnerable')
    matrix.add_argument('--budget', type=int, default=27)
    matrix.add_argument('--repeats', type=int, default=2)
    matrix.add_argument('--output-dir', default='runs')
    minimize = commands.add_parser('minimize', help='Reduce a failing selection toward the C baseline')
    minimize.add_argument('--selection', default='A,A,A', help='identity,permissions,secrets checkpoints')
    minimize.add_argument('--mode', choices=['vulnerable', 'protected'], default='vulnerable')
    minimize.add_argument('--target-kind', default='revived_role')
    minimize.add_argument('--target-actor', default='removed-user')
    minimize.add_argument('--budget', type=int, default=100)
    commands.add_parser('scenarios', help='Check the six expected reference outcomes')
    verify = commands.add_parser('verify', help='Verify a saved evidence manifest')
    verify.add_argument('directory')
    bundle = commands.add_parser('bundle', help='Export a verified run as a ZIP')
    bundle.add_argument('directory')
    bundle.add_argument('--output', required=True)
    native = commands.add_parser('openbao', help='Run native Raft restores against a new disposable OpenBao process')
    native.add_argument('--config', required=True, help='Strict executable native scenario JSON')
    native.add_argument('--executable', required=True, help='Path to the official local bao/bao.exe binary')
    native.add_argument('--output-dir', default='service-runs')
    native_verify = commands.add_parser('verify-service', help='Verify native-service evidence integrity')
    native_verify.add_argument('directory')
    args = parser.parse_args(argv)
    try:
        if args.command == 'serve':
            from .server import serve as start
            start(args.port, args.runs_dir)
            return 0
        if args.command == 'openbao':
            from .openbao import load_config, run_openbao
            output = run_openbao(load_config(args.config), args.executable, args.output_dir)
            status = output['status']
        elif args.command == 'verify-service':
            from .openbao import verify_service
            output = verify_service(args.directory)
            status = output['status']
        elif args.command == 'matrix':
            output = run_case(args.output_dir, args.mode, args.budget, args.repeats)
            status = output['result']['status']
        elif args.command == 'minimize':
            values = [v.strip().upper() for v in args.selection.split(',')]
            if len(values) != 3:
                raise ValueError('Selection must contain three checkpoints, e.g. A,A,A.')
            output = minimize_selection(dict(zip(('identity', 'permissions', 'secrets'), values)),
                                        mode=args.mode, target_kind=args.target_kind,
                                        target_actor=args.target_actor, max_evaluations=args.budget)
            status = output['status']
        elif args.command == 'scenarios':
            output = run_scenarios()
            status = output['status']
        elif args.command == 'verify':
            output = verify_case(args.directory)
            status = output['status']
        else:
            directory = Path(args.directory).resolve()
            destination = Path(args.output).resolve()
            if destination.is_relative_to(directory):
                raise ValueError('Save the ZIP outside the evidence directory.')
            if destination.exists():
                raise ValueError('Output file already exists; choose a new filename.')
            payload = bundle_case(directory.parent, directory.name)
            with destination.open('xb') as stream:
                stream.write(payload)
            output, status = {'status': 'PASS', 'bundle': str(destination)}, 'PASS'
        print(json.dumps(output, indent=2, ensure_ascii=True))
        return {'PASS': 0, 'FAIL': 1, 'INCONCLUSIVE': 2}.get(status, 2)
    except (ValueError, OSError, TypeError) as exc:
        print(f'RestoreGuard: {exc}', file=sys.stderr)
        return 2
