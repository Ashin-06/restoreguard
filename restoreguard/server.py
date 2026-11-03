"""Dependency-free workbench API and static file server.

Loopback-only by default. Settings come from RESTOREGUARD_* variables (see ops.py and
docs/runbook.md); with API keys configured every API route needs a key whose role allows it.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import logging
import threading
import time
from urllib.parse import urlsplit

from . import ops
from .evidence import bundle_case, case_path, list_cases, load_case, run_case, verify_case
from .core import minimize_selection, run_scenarios

MAX_BODY = 1024 * 1024
STATIC = {'/': 'index.html', '/index.html': 'index.html', '/styles.css': 'styles.css', '/app.js': 'app.js', '/auth.js': 'auth.js'}
MIME = {'html': 'text/html; charset=utf-8', 'css': 'text/css; charset=utf-8', 'js': 'text/javascript; charset=utf-8'}
PUBLIC = set(STATIC) | {'/api/health', '/healthz', '/readyz'}
access = logging.getLogger('restoreguard.access')


def _route(path):
    """The path with case IDs replaced, so metrics don't grow a series per case."""
    pieces = path.strip('/').split('/')
    if len(pieces) == 4 and pieces[:2] == ['api', 'cases']:
        return f'/api/cases/{{id}}/{pieces[3]}'
    return path if path in PUBLIC or path in ('/metrics', '/api/demo', '/api/cases', '/api/run', '/api/minimize', '/api/scenarios') else 'other'


def create_server(port=None, runs_dir=None, settings=None):
    settings = settings or ops.load_settings()
    port = settings.port if port is None else port
    root = Path(runs_dir or settings.data_dir).resolve()
    static = Path(__file__).with_name('static')
    lock = threading.Lock()
    limiter, metrics = ops.RateLimiter(settings.rate_limit), ops.Metrics()

    class Handler(BaseHTTPRequestHandler):
        server_version = 'RestoreGuard/1.0'

        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def _allowed_host(self):
            return ops.host_allowed(self.headers.get('Host', ''), settings)

        def _send(self, status, body, content_type='application/json; charset=utf-8', filename=None, extra=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False).encode('utf-8')
            elif isinstance(body, str):
                body = body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Request-ID', getattr(self, 'rid', '-'))
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            if filename:
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
            route = _route(urlsplit(self.path).path)
            seconds = time.monotonic() - getattr(self, 't0', time.monotonic())
            metrics.observe(self.command, route, status, seconds)
            access.info('request', extra={'fields': {'method': self.command, 'route': route, 'status': status,
                                                     'ms': round(seconds * 1000, 1), 'user': getattr(self, 'user', '')}})

        def _gate(self, path, permission):
            """Request ID, host check, health, rate limit, API keys and metrics. True when answered here."""
            self.t0, self.rid, self.user = time.monotonic(), ops.new_request_id(self.headers), ''
            ops.request_id.set(self.rid)
            if not self._allowed_host():
                return self._send(403, {'error': 'This host name is not accepted.'}) or True
            if path == '/healthz':  # probes are never rate limited
                return self._send(200, {'status': 'ok'}) or True
            if path == '/readyz':
                ready = root.is_dir() or not root.exists()
                return self._send(200 if ready else 503, {'status': 'ready' if ready else 'not ready',
                                                          'checks': {'storage': ready}}) or True
            ident = ops.identify(self.headers, settings)
            ok, wait = limiter.allow(ident['user'] if ident else self.client_address[0])
            if not ok:
                return self._send(429, {'error': 'Too many requests.'}, extra={'Retry-After': str(wait)}) or True
            if permission and settings.auth:
                if ident is None:
                    return self._send(401, {'error': 'An API key is required.'}, extra={'WWW-Authenticate': 'Bearer'}) or True
                if not ops.permitted(ident, permission):
                    return self._send(403, {'error': 'This key may not do that.'}) or True
                self.user = ident['user']
            if path == '/metrics':
                return self._send(200, metrics.text(), 'text/plain; version=0.0.4; charset=utf-8') or True
            return False

        def do_GET(self):
            path = urlsplit(self.path).path
            if self._gate(path, None if path in PUBLIC else 'metrics' if path == '/metrics' else 'read'):
                return
            try:
                if path in STATIC:
                    name = STATIC[path]
                    return self._send(200, (static / name).read_bytes(), MIME[name.rsplit('.', 1)[1]])
                if path == '/api/health':
                    return self._send(200, {'status': 'ok', 'scope': 'synthetic SQLite recovery security lab'})
                if path == '/api/demo':
                    return self._send(200, {'modes': ['vulnerable', 'protected'], 'components': ['identity', 'permissions', 'secrets'], 'checkpoints': ['A', 'B', 'C'], 'default_selection': {'identity': 'A', 'permissions': 'A', 'secrets': 'A'}})
                if path == '/api/cases':
                    return self._send(200, {'cases': list_cases(root)})
                pieces = path.strip('/').split('/')
                if len(pieces) == 4 and pieces[:2] == ['api', 'cases']:
                    case_id, kind = pieces[2:]
                    directory = case_path(root, case_id)
                    if kind == 'json':
                        return self._send(200, load_case(root, case_id), filename=case_id + '.json')
                    if kind == 'report':
                        return self._send(200, (directory / 'report.html').read_bytes(), 'text/html; charset=utf-8', case_id + '.html')
                    if kind == 'bundle':
                        return self._send(200, bundle_case(root, case_id), 'application/zip', case_id + '.zip')
                    if kind == 'verify':
                        return self._send(200, verify_case(directory))
                return self._send(404, {'error': 'Not found.'})
            except FileNotFoundError:
                return self._send(404, {'error': 'File or case not found.'})
            except ValueError as exc:
                return self._send(400, {'error': str(exc)})
            except OSError:
                return self._send(500, {'error': 'Could not read local case files.'})

        def do_POST(self):
            if self._gate(urlsplit(self.path).path, 'run'):
                return
            origin = self.headers.get('Origin')
            if origin and not ops.origin_allowed(origin, settings):
                return self._send(403, {'error': 'Cross-origin requests are not accepted.'})
            if self.headers.get_content_type() != 'application/json':
                return self._send(415, {'error': 'Use application/json.'})
            if self.headers.get('Transfer-Encoding'):
                return self._send(400, {'error': 'Chunked requests are not supported.'})
            try:
                length = int(self.headers.get('Content-Length', '-1'))
                if length < 0 or length > MAX_BODY:
                    return self._send(413, {'error': 'Request must be at most 1 MiB and include Content-Length.'})
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError('JSON body must be an object.')
                path = urlsplit(self.path).path
                if path not in ('/api/run', '/api/minimize', '/api/scenarios'):
                    return self._send(404, {'error': 'Not found.'})
                if not lock.acquire(blocking=False):
                    return self._send(409, {'error': 'Another experiment is running. Wait for it to finish.'})
                try:
                    if path == '/api/scenarios':
                        metrics.decision('scenarios_run')
                        return self._send(200, run_scenarios())
                    mode = data.get('mode', 'vulnerable')
                    if mode not in ('vulnerable', 'protected'):
                        raise ValueError('Mode must be vulnerable or protected.')
                    if path == '/api/minimize':
                        metrics.decision('selection_minimized')
                        return self._send(200, minimize_selection(
                            data.get('selection', {'identity': 'A', 'permissions': 'A', 'secrets': 'A'}),
                            mode=mode, target_kind=data.get('target_kind', 'revived_role'),
                            target_actor=data.get('target_actor', 'removed-user'),
                            max_evaluations=data.get('max_evaluations', 100)))
                    metrics.decision(f'matrix_run_{mode}')
                    return self._send(200, run_case(root, mode=mode,
                        max_experiments=data.get('max_experiments', 27), repeats=data.get('repeats', 2)))
                finally:
                    lock.release()
            except (ValueError, UnicodeError, TypeError, KeyError) as exc:
                return self._send(400, {'error': str(exc)})
            except OSError:
                return self._send(500, {'error': 'The local experiment could not complete. Check storage permissions and server logs.'})

        def log_message(self, fmt, *args):
            # Access lines are written as JSON in _send, without submitted content or results.
            pass

    return ThreadingHTTPServer((settings.host, port), Handler)


def serve(port=None, runs_dir=None):
    try:
        settings = ops.load_settings()
    except ops.ConfigError as exc:
        raise SystemExit(f'configuration error: {exc}') from None
    ops.setup_logging(settings.log_level)
    server = create_server(port, runs_dir, settings)
    where = f'http://{settings.host}:{server.server_port}'
    logging.getLogger('restoreguard').info('ready', extra={'fields': {'url': where, 'auth': settings.auth,
                                                                      'env': settings.env}})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
