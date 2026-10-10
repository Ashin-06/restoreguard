"""Portable HTML reports with escaped, script-free content."""

from html import escape
import json


def render_report(case):
    result = case['result']
    summary = result['summary']
    rows = []
    for experiment in result['results']:
        selection = ' / '.join(f'{k}: {v}' for k, v in experiment['selection'].items())
        observations = []
        for observation in experiment['observations']:
            observations.append('<tr>' + ''.join('<td>' + escape(str(observation.get(key, ''))) + '</td>'
                for key in ('actor', 'action', 'expected', 'observed', 'transport_status', 'effect_occurred', 'status', 'kind')) + '</tr>')
        rows.append(f'<section><h2>{escape(str(experiment["id"]))} · {escape(experiment["status"])}</h2>'
                    f'<p>{escape(selection)}</p><div class="scroll"><table><thead><tr>'
                    '<th>Actor</th><th>Action</th><th>Expected</th><th>Observed</th><th>HTTP model</th><th>Effect</th><th>Verdict</th><th>Kind</th>'
                    '</tr></thead><tbody>' + ''.join(observations) + '</tbody></table></div></section>')
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' + \
        '<title>RestoreGuard evidence report</title><style>body{font:16px/1.6 system-ui;margin:40px auto;max-width:1100px;padding:0 24px;background:#f5f4ef;color:#152c2c}h1{font-size:40px}section{background:white;padding:24px;margin:20px 0;border:1px solid #ccd7d2;border-radius:12px}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:9px;text-align:left;border-bottom:1px solid #ddd}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#506361}</style>' + \
        f'<small>RESTOREGUARD / CONTROLLED SQLITE REFERENCE LAB</small><h1>Recovery verdict: {escape(result["status"])}</h1>' + \
        f'<p>Run {escape(case["case_id"])} · {escape(case["created_at"])} · Mode: {escape(result["mode"])}</p>' + \
        f'<p>{summary["attempted"]} / {summary["planned"]} selections tested. {summary["passed"]} passed · {summary["failed"]} failed · {summary["inconclusive"]} inconclusive.</p>' + \
        '<p>Verdicts compare an independent current policy journal with observed protected effects. HTTP response codes are supporting evidence only. A passing finite synthetic matrix is not a production recovery certification.</p>' + \
        ''.join(rows) + '<section><h2>Scope and limitations</h2><pre>' + escape(json.dumps(result.get('limitations', []), indent=2)) + \
        '</pre><p>The unsigned SHA-256 manifest detects changes relative to its recorded hashes; it does not prove authenticity if both files and manifest are replaced.</p></section></html>'
