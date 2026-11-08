"""Network-disabled public-distribution cancellation diagnostics; installed wheel and source remain unchanged."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

EVIDENCE = Path('/proof/evidence')
RUNTIME = EVIDENCE / 'cancellation-fixed-v3' / 'runtime'
HOOK = Path('/proof/integration/src/pre_commit_terraform/terraform_iac_guard_v.py')
PRODUCT = '/opt/iac-guard-v/bin/python'
SCANNER = '/opt/iac-guard-v/scanner/checkov'
BAD = '''resource "aws_ebs_volume" "target" {
  availability_zone = "us-east-1a"
  size = 1
  encrypted = false
}
'''


def dump(path, payload):
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')


def proc(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        tail = raw[raw.rfind(')') + 2:].split()
        argv = Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
        return {'pid': pid, 'state': tail[0], 'ppid': int(tail[1]), 'pgrp': int(tail[2]), 'session': int(tail[3]), 'starttime': tail[19], 'argv': argv}
    except (OSError, ValueError):
        return None


def process_table():
    rows = []
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            row = proc(int(path.name))
            if row:
                rows.append(row)
    return rows


def descendants(rows, parent):
    wanted = {parent}
    while True:
        enlarged = wanted | {r['pid'] for r in rows if r['ppid'] in wanted}
        if enlarged == wanted:
            return [r for r in rows if r['pid'] in wanted]
        wanted = enlarged


def wrapper(case):
    directory = RUNTIME / case
    os.chdir(directory)
    spec = importlib.util.spec_from_file_location('reviewed_hook', HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Diagnostic acceleration only: exact source remains read-only. The 600s
    # subprocess.run transport deadline is shortened in memory to 15 seconds.
    module.TIMEOUT = 90 if 'timeout' in case else 600
    args = argparse.Namespace(iacgv_python=Path(PRODUCT), local_trusted=True,
        before=Path('before'), after=Path('after'), framework='terraform',
        target=['CKV_AWS_3=aws_ebs_volume.target'], checkov_executable=Path(SCANNER))
    code = module.invoke_cli_app(args)
    print(json.dumps({'hook_return': code}), flush=True)
    return code


def full_cli_case(case, cancellation):
    directory = RUNTIME / case
    directory.mkdir(parents=True)
    for name, text in [('before', BAD), ('after', BAD.replace('false', 'true'))]:
        (directory / name).mkdir()
        (directory / name / 'main.tf').write_text(text)
    subprocess.run(['git', 'init', '-q', str(directory)], check=True)
    launched_at = time.monotonic()
    with (directory / 'wrapper.stdout.log').open('w') as out, (directory / 'wrapper.stderr.log').open('w') as err:
        wrapper_process = subprocess.Popen([PRODUCT, '-I', '-B', str(Path(__file__)), '--wrapper', case], stdout=out, stderr=err, start_new_session=True)
        tracked = {}
        result = {'case': case, 'cancellation': cancellation, 'outer_timeout_original_seconds': 600, 'outer_timeout_diagnostic_seconds': 90 if 'timeout' in case else 600, 'wrapper_pid': wrapper_process.pid, 'scanner_group_stop': 'Controlled SIGSTOP of exact scanner group after observed spawn, to keep cancellation reproducible; scanner bytes unchanged.'}
        scanner = None
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and wrapper_process.poll() is None:
                tree = descendants(process_table(), wrapper_process.pid)
                for row in tree:
                    tracked[row['pid']] = row
                scanners = [r for r in tree if SCANNER in r['argv'] and 'iac_guard_v.cli' not in r['argv'] and '--wrapper' not in r['argv']]
                if 'scan-stage' in case:
                    scanners = [r for r in scanners if ' -d ' in r['argv']]
                if scanners:
                    scanner = scanners[0]
                    result['at_scanner_spawn'] = tree
                    os.killpg(scanner['pgrp'], signal.SIGSTOP)
                    result['scanner_group_stop_at_seconds'] = round(time.monotonic() - launched_at, 6)
                    break
                time.sleep(0.01)
            if scanner is None:
                raise RuntimeError('No scanner observed before wrapper exited or observation deadline')
            if cancellation == 'SIGINT-wrapper-product-group':
                os.killpg(wrapper_process.pid, signal.SIGINT)
            elif cancellation in {'SIGTERM-wrapper', 'repeated-wrapper'}:
                os.kill(wrapper_process.pid, signal.SIGTERM)
                if cancellation == 'repeated-wrapper':
                    time.sleep(.1)
                    os.kill(wrapper_process.pid, signal.SIGINT)
                    os.kill(wrapper_process.pid, signal.SIGTERM)
            elif cancellation == 'SIGTERM-product':
                products = [r for r in result['at_scanner_spawn'] if 'iac_guard_v.cli verify' in r['argv']]
                if len(products) != 1:
                    raise RuntimeError(f'Expected exactly one product: {products}')
                os.kill(products[0]['pid'], signal.SIGTERM)
            result['wrapper_returncode'] = wrapper_process.wait(timeout=120 if 'timeout' in case else 25)
            result['wrapper_elapsed_seconds'] = round(time.monotonic() - launched_at, 6)
            time.sleep(0.2)
            result['scanner_after_hook_return'] = proc(scanner['pid'])
            result['scanner_group_after_hook_return'] = [r for r in process_table() if r['pgrp'] == scanner['pgrp']]
            result['scanner_alive_after_hook_return'] = bool(result['scanner_after_hook_return'] and result['scanner_after_hook_return']['state'] != 'Z')
            result['reports'] = [str(p.relative_to(directory)) for p in directory.glob('.git/iac-guard-v/runs/run-*/report.json')]
        finally:
            # Signal only currently matching owned identities, never recycled IDs.
            cleanup = []
            for pgid in {r['pgrp'] for r in tracked.values()}:
                matching = [now for old in tracked.values() if (now := proc(old['pid']))
                            and now['starttime'] == old['starttime'] and now['pgrp'] == pgid
                            and now['state'] != 'Z']
                if matching:
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                        cleanup.append({'pgid': pgid, 'signal': 'SIGKILL', 'matching': matching})
                    except ProcessLookupError:
                        pass
            wrapper_process.wait(timeout=5)
            time.sleep(.2)
            result['targeted_cleanup'] = cleanup
            result['post_cleanup_live_processes'] = [now for old in tracked.values()
                if (now := proc(old['pid'])) and now['starttime'] == old['starttime']
                and now['state'] != 'Z']
            dump(directory / 'result.json', result)
    return result


def main():
    RUNTIME.mkdir(parents=True, exist_ok=False)
    import iac_guard_v.process as product_process
    import iac_guard_v.adapters.checkov as checkov
    import iac_guard_v.cli as cli
    identity = {'version': importlib.metadata.version('iac-guard-v'), 'python': sys.version, 'pid': os.getpid(), 'product_files': {str(Path(m.__file__)): hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in [product_process, checkov, cli]}, 'hook_sha256': hashlib.sha256(HOOK.read_bytes()).hexdigest()}
    dump(RUNTIME / 'identity.json', identity)
    results = []
    for case, cancellation in [('full-cli-shortened-timeout', 'subprocess.run-timeout'), ('scan-stage-control-c', 'SIGINT-wrapper-product-group'), ('scan-stage-hook-sigterm', 'SIGTERM-wrapper'), ('full-cli-product-sigterm', 'SIGTERM-product'), ('full-cli-repeated-interrupt', 'repeated-wrapper')]:
        result = full_cli_case(case, cancellation)
        results.append(result)
        print(json.dumps({'case': case, 'hook_returncode': result['wrapper_returncode'], 'scanner_alive_after_hook_return': result['scanner_alive_after_hook_return'], 'post_cleanup_live_count': len(result['post_cleanup_live_processes'])}), flush=True)
    dump(RUNTIME / 'summary.json', results)
    assert all(r['wrapper_returncode'] == 3 and not r['scanner_alive_after_hook_return'] and not r['post_cleanup_live_processes'] and not r['reports'] for r in results)
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--wrapper':
        raise SystemExit(wrapper(sys.argv[2]))
    raise SystemExit(main())
