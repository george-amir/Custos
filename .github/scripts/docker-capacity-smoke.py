#!/usr/bin/env python3
"""Exercise real kernel cleanup only in disposable Docker network namespaces.

Run after `docker build -t custos:ci .`. Requires Docker and Python 3.
"""
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def docker(*args, check=True):
    return subprocess.run(['docker', *args], text=True, capture_output=True, check=check)


def validate(backend):
    name = 'custos-native-' + backend + '-' + uuid.uuid4().hex[:8]
    scratch = Path.cwd() / 'target' / 'native-validation'
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='native-state-', dir=scratch) as folder:
        state = Path(folder)
        (state / 'access.log').write_text('')
        (state / 'config.toml').write_text('''[daemon]
bouncer_listen = "0.0.0.0:8085"
decisions_file = "/state/ledger"
api_token = "native-test-only"
on_decision_capacity = "enforce_existing"
[[logs]]
path = "/state/access.log"
format = "json"
[firewall]
enabled = true
dry_run = false
backend = "''' + backend + '''"
table_name = "custos_native"
[memory]
max_decisions = 257
''')
        created = False
        try:
            docker('run', '-d', '--name', name, '--cap-add=NET_ADMIN', '-p', '127.0.0.1::8085', '-v', folder + ':/state', 'custos:ci', '--config', '/state/config.toml', 'run', '--mock-jev')
            created = True
            root = 'http://' + docker('port', name, '8085/tcp').stdout.strip().splitlines()[0]
            def request(path, method='GET', data=None):
                req = urllib.request.Request(root + path, data=None if data is None else json.dumps(data).encode(), method=method, headers={'Authorization': 'Bearer native-test-only', 'Content-Type': 'application/json'})
                try:
                    with urllib.request.urlopen(req, timeout=5) as response:
                        return response.status, response.read().decode()
                except urllib.error.HTTPError as response:
                    return response.code, response.read().decode()
            def ready():
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    try:
                        if request('/v1/stats')[0] == 200:
                            return
                    except OSError:
                        pass
                    assert docker('inspect', '-f', '{{.State.Running}}', name).stdout.strip() == 'true', 'daemon exited'
                    time.sleep(.1)
                raise AssertionError('startup timed out')
            def metric(key):
                status, text = request('/metrics')
                assert status == 200
                return float(next(line.split()[1] for line in text.splitlines() if line.startswith(key + ' ')))
            def ban(ip, ttl):
                status, body = request('/v1/decisions', 'POST', {'ip': ip, 'ttl_secs': ttl, 'reason': 'native validation'})
                assert status == 201, (backend, status, body)
            ready()
            keeper = '198.51.100.250'
            ban(keeper, 3600)
            expired = [str(ipaddress.ip_address('198.18.0.0') + n) for n in range(1, 129)]
            expired += [str(ipaddress.ip_address('2001:db8::') + n) for n in range(1, 129)]
            for ip in expired:
                ban(ip, 1)
            assert metric('custos_decision_retained') == 257
            assert request('/v1/bouncer/check?ip=' + keeper)[0] == 403
            time.sleep(1.2)
            latencies = []
            for _ in range(25):
                before = time.monotonic()
                assert request('/v1/bouncer/check?ip=203.0.113.20')[0] == 200
                latencies.append(time.monotonic() - before)
            deadline = time.monotonic() + 12
            while metric('custos_decision_retained') != 1 and time.monotonic() < deadline:
                time.sleep(.1)
            assert metric('custos_decision_retained') == 1
            assert metric('custos_decision_cleanup_pending') == 0
            assert request('/v1/bouncer/check?ip=' + keeper)[0] == 403
            fw = json.loads(request('/v1/firewall')[1])
            assert fw['command_errors'] == 0, fw
            assert fw['rules_removed'] == 256, fw
            if backend == 'nftables':
                batches = [c for c in fw['recent_commands'] if c.count('add element') == 1 and 'delete element' in c]
                sets = '\n'.join(docker('exec', name, 'nft', 'list', 'set', 'inet', 'custos_native', family).stdout for family in ['block_v4', 'block_v6'])
            else:
                batches = [c for c in fw['recent_commands'] if c == 'ipset restore -exist']
                sets = '\n'.join(docker('exec', name, 'ipset', 'list', family).stdout for family in ['custos_native_v4', 'custos_native_v6'])
            assert len(batches) == 2, (backend, len(batches))
            assert keeper in sets and all(ip not in sets for ip in expired)
            docker('restart', name)
            root = 'http://' + docker('port', name, '8085/tcp').stdout.strip().splitlines()[0]
            ready()
            assert request('/v1/bouncer/check?ip=' + keeper)[0] == 403
            assert metric('custos_decision_retained') == 1
            if backend == 'ipset':
                for binary in ['iptables', 'ip6tables']:
                    assert docker('exec', name, binary, '-S', 'INPUT').stdout.count('custos_native_') == 1
            newcomer = '203.0.113.30'
            ban(newcomer, 3600)
            assert request('/v1/bouncer/check?ip=' + newcomer)[0] == 403
            for ip in [keeper, newcomer]:
                assert request('/v1/decisions/' + ip, 'DELETE')[0] == 200
            assert metric('custos_decision_retained') == 0
            print(json.dumps({'backend': backend, 'live_kernel': True, 'expired_cleanup': 256, 'unban_processes': len(batches), 'healthy_checks': 25, 'allowed': 25, 'max_check_ms': round(max(latencies) * 1000, 2), 'active_ban_survived_restart': True, 'new_ban_after_cleanup': True}), flush=True)
        except BaseException:
            if created:
                print(docker('logs', '--tail', '15', name, check=False).stderr)
            raise
        finally:
            if created:
                docker('rm', '-f', name, check=False)


# This observed ARM64 runtime panics in nft_rhash_gc when entries expire.
# This preflight does not establish patch status for every vendor kernel.
engine = json.loads(docker('info', '--format', '{{json .}}').stdout)
if engine.get('KernelVersion', '').startswith('6.12.5-orbstack'):
    raise SystemExit('Refusing live timeout tests on the known crashing OrbStack kernel; update the host kernel for CVE-2024-54031 first.')

for backend in ['nftables', 'ipset']:
    validate(backend)
