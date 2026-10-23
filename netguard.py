#!/usr/bin/env python3
"""Read-only, inventory-bounded network monitoring. Python 3 standard library only."""
import argparse
import collections
import datetime
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

import notifications

HOST_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}')
READ_LIMIT = 1024 * 1024
MAX_CHUNKS = 32
COLLECT_SECONDS = 60
SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
PROPOSALS = ['none', 'review_inventory', 'review_ports', 'review_dns', 'review_auth', 'restore_coverage']
DNS_TELEMETRY = {'dns_long_label', 'dns_entropy'}
COVERAGE_MESSAGES = {
    'lan_discovery': 'Local network discovery failed. Next step: check scanner access and retry.',
    'host_discovery': 'Inventory discovery failed. Next step: check network connectivity to the inventory hosts and retry.',
    'host_offline': 'An inventory device did not respond. Next step: check whether it is powered on and connected.',
    'tcp_scan': 'The port scan did not finish. Next step: check scanner access and retry.',
    'log_read': 'A log source could not be read. Next step: check log access and retry; its saved cursor was retained.',
    'log_backlog': 'Some log data remains unread. Next step: let the next run continue; check the source if this persists.',
    'log_rotated': 'A log rotated or was truncated. Next step: review log rotation for a possible coverage gap.',
    'log_history_skipped': 'Monitoring started at the recent log tail. Next step: review older history separately if needed.',
    'dns_parse': 'Some DNS rows could not be parsed. Next step: check the source log format.',
    'model_triage': 'Local model triage is unavailable. Next step: check the model service; the findings below still apply.',
    'state_read': 'Saved monitoring state could not be read. Next step: check the private state file before retrying.',
    'baseline_read': 'The saved network reference could not be read. Next step: review the reference file.',
    'baseline_approval': 'The network reference could not be approved. Next step: obtain a complete matching scan and review it.',
    'configuration_or_io': 'Configuration or report storage failed. Next step: check configuration and private output storage.',
    'overlapping_run': 'Another monitoring run is active. Next step: wait for that run to finish.',
    'notification_delivery': 'Phone notification delivery failed. Next step: check private notification configuration and connectivity; a summary remains pending for retry.',
}


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def config(raw):
    c = dict(raw)
    try:
        lan = ipaddress.IPv4Network(c.get('lan_cidr'))
    except (ValueError, TypeError):
        raise ValueError('lan_cidr must be an IPv4 network in CIDR form') from None
    if lan.is_global or not 16 <= lan.prefixlen <= 30:
        raise ValueError('lan_cidr must be a private IPv4 network between /16 and /30')
    c['_lan'] = lan
    inventory = c.get('hosts')
    if not isinstance(inventory, dict) or not inventory or not all(isinstance(n, str) and HOST_NAME.fullmatch(n) for n in inventory):
        raise ValueError('hosts must map valid host names to IPv4 addresses')
    for address in inventory.values():
        try:
            if ipaddress.IPv4Address(address).is_global:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError('hosts requires exact private or shared-space IPv4 addresses') from None
    if len(set(inventory.values())) != len(inventory):
        raise ValueError('host addresses must be unique')
    c.setdefault('ports', '1-65535')
    ports = set()
    if not isinstance(c['ports'], str) or not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', c['ports']):
        raise ValueError('invalid ports')
    for span in c['ports'].split(','):
        ends = list(map(int, span.split('-')))
        lo, hi = ends[0], ends[-1]
        if not 1 <= lo <= hi <= 65535:
            raise ValueError('invalid ports')
        ports.update(range(lo, hi + 1))
    c['_port_count'] = len(ports)
    c['_ports'] = ports
    c.setdefault('output_dir', '/var/lib/netguard')
    c.setdefault('model', 'dolphin3:8b')
    if not isinstance(c['output_dir'], str) or not Path(c['output_dir']).is_absolute():
        raise ValueError('output_dir must be absolute')
    if not isinstance(c['model'], str) or not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}', c['model']):
        raise ValueError('invalid model')
    c.setdefault('dns_hosts', [])
    c.setdefault('local_host', None)
    c.setdefault('optional_hosts', [])
    c.setdefault('dns_paths', ['/opt/AdGuardHome/data/querylog.json'])
    c.setdefault('auth_paths', ['/var/log/auth.log'])
    c.setdefault('suspicious_domains', [])
    if not isinstance(c['dns_hosts'], list) or not set(c['dns_hosts']) <= set(inventory):
        raise ValueError('dns_hosts must be in hosts')
    if c['local_host'] is not None and c['local_host'] not in inventory:
        raise ValueError('local_host must be in hosts')
    if not isinstance(c['optional_hosts'], list) or not set(c['optional_hosts']) <= set(inventory):
        raise ValueError('optional_hosts must be in hosts')
    for key in ('dns_paths', 'auth_paths'):
        if not isinstance(c[key], list) or not all(isinstance(p, str) and p.startswith('/') and '\x00' not in p for p in c[key]):
            raise ValueError('log paths must be absolute')
    if not isinstance(c['suspicious_domains'], list) or not all(isinstance(d, str) and re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', d) for d in c['suspicious_domains']):
        raise ValueError('invalid suspicious_domains')
    c['suspicious_domains'] = sorted({d.lower().strip('.') for d in c['suspicious_domains']})
    public = {k: v for k, v in c.items() if not k.startswith('_')}
    c['_fingerprint'] = hashlib.sha256(json.dumps(public, sort_keys=True).encode()).hexdigest()
    return c


def finding(category, **fields):
    return dict(category=category, **fields)


def parse_nmap(xml, allowed, port_count=None, permitted_ports=None):
    root = ET.fromstring(xml)
    finished = root.find('runstats/finished')
    if finished is None or finished.get('exit') != 'success':
        raise ValueError('incomplete nmap run')
    snapshot = {}
    for host in root.findall('host'):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            raise ValueError('missing IPv4')
        ip = address.get('addr')
        if ip not in allowed or host.get('timedout') == 'true':
            raise ValueError('unexpected or timed-out host')
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            if port_count is not None:
                raise ValueError('unscanned host')
            continue
        ports = host.findall('ports/port')
        opened = sorted(int(p.get('portid')) for p in ports if p.find('state') is not None and p.find('state').get('state') == 'open')
        if port_count is not None:
            covered = len(ports) + sum(int(e.get('count')) for e in host.findall('ports/extraports'))
            if covered != port_count or any(p.get('protocol') != 'tcp' for p in ports):
                raise ValueError('partial port scan')
            if permitted_ports is not None and any(int(p.get('portid')) not in permitted_ports for p in ports):
                raise ValueError('unexpected port')
        if ip in snapshot:
            raise ValueError('duplicate host')
        snapshot[ip] = opened
    if port_count is not None and set(snapshot) != set(allowed):
        raise ValueError('missing scan targets')
    return snapshot


def command(args, timeout, input=None):
    result = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=True)
    return result.stdout


def scan(c):
    errors = []
    try:
        discovered = parse_nmap(command(['nmap', '-sn', '-n', '-PS22,80,443,445,3389,11434', '-oX', '-', str(c['_lan'])], 90), {str(ip) for ip in c['_lan'].hosts()})
        if not discovered:
            raise ValueError('empty LAN discovery')
    except (OSError, subprocess.SubprocessError, ValueError, ET.ParseError) as error:
        return {}, [finding('coverage', component='lan_discovery', error_type=type(error).__name__)]
    inventory = set(c['hosts'].values())
    try:
        reachable = parse_nmap(command(['nmap', '-sn', '-n', '-PS22,80,443,445,3389,11434', '-oX', '-', *sorted(inventory)], 90), inventory)
    except (OSError, subprocess.SubprocessError, ValueError, ET.ParseError) as error:
        return {}, [finding('coverage', component='host_discovery', error_type=type(error).__name__)]
    for host, ip in sorted(c['hosts'].items()):
        if ip not in reachable:
            errors.append(finding('coverage', component='host_offline', host=host, ip=ip, optional=host in c['optional_hosts']))
    targets = set(discovered) | set(reachable)
    try:
        xml = command(['nmap', '-sT', '-Pn', '-n', '-p', c['ports'], '--max-rate', '5000', '--max-retries', '1', '-oX', '-', *sorted(targets)], 1200)
        return parse_nmap(xml, targets, c['_port_count'], c['_ports']), errors
    except (OSError, subprocess.SubprocessError, ValueError, ET.ParseError) as error:
        return {}, errors + [finding('coverage', component='tcp_scan', error_type=type(error).__name__)]


def differences(snapshot, baseline):
    results = []
    for ip, ports in sorted(snapshot.items()):
        if ip not in baseline:
            results.append(finding('new_device', ip=ip))
        added = sorted(set(ports) - set(baseline.get(ip, [])))
        if added:
            results.append(finding('new_ports', ip=ip, ports=added))
    return results


def dns_category(domain, suffixes):
    domain = domain.lower().rstrip('.')
    if any(domain == s or domain.endswith('.' + s) for s in suffixes):
        return 'dns_suffix'
    for label in domain.split('.'):
        if len(label) >= 40:
            return 'dns_long_label'
        if len(label) >= 24:
            entropy = -sum((n / len(label)) * math.log2(n / len(label)) for n in collections.Counter(label).values())
            if entropy >= 4:
                return 'dns_entropy'
    return None


def summarize_logs(data, kind, suffixes):
    counts = collections.Counter()
    invalid = 0
    for line in data.splitlines():
        if not line.strip():
            continue
        if kind == 'dns':
            try:
                row = json.loads(line)
                domain, client = row['QH'], valid_ip(row.get('IP'))
                if not isinstance(domain, str) or not client:
                    raise ValueError('invalid DNS row')
            except (ValueError, TypeError, KeyError):
                match = re.search(r'query\[[^\]]+\]\s+(\S+)\s+from\s+(\S+)', line)
                if not match:
                    invalid += 1
                    continue
                domain, client = match[1], valid_ip(match[2])
                if not client:
                    invalid += 1
                    continue
            category = dns_category(domain, suffixes)
            if category:
                counts[(category, client)] += 1
        elif re.search(r'Failed (?:password|publickey)|authentication failure|Invalid user', line, re.I):
            match = re.search(r'\bfrom\s+(\S+)|\brhost=(\S+)', line)
            client = valid_ip(next((v for v in match.groups() if v), '')) if match else None
            counts[('auth_failed', client)] += 1
    results = [finding(cat, count=count, **({'client_ip': ip} if ip else {})) for (cat, ip), count in sorted(counts.items(), key=lambda item: str(item[0]))]
    if invalid:
        results.append(finding('coverage', component='dns_parse', count=invalid))
    return results


# Remote stdout is bounded and held in memory only. No raw log data reaches persistence.
REMOTE_READER = r'''
import json, os, sys
p = json.loads(sys.stdin.readline())
with open(p['path'], 'rb') as f:
    st = os.fstat(f.fileno())
    identity = str(st.st_dev) + ':' + str(st.st_ino)
    old = p['checkpoint']
    rotated = bool(old and (old['identity'] != identity or st.st_size < old['offset']))
    history_skipped = not old and st.st_size > p['limit']
    start = old['offset'] if old and not rotated else max(0, st.st_size - p['limit']) if history_skipped else 0
    f.seek(start)
    if history_skipped:
        f.readline(p['limit'])
        start = f.tell()
    chunk = f.read(p['limit'])
    end = chunk.rfind(b'\n') + 1
    data = chunk[:end]
    print(json.dumps({'data': data.decode('utf-8', 'replace'),
        'checkpoint': {'identity': identity, 'offset': start + end},
        'rotated': rotated, 'history_skipped': history_skipped, 'backlog': start + end < st.st_size}))
'''


def collect(c, checkpoints):
    pending, findings = dict(checkpoints), []
    deadline = time.monotonic() + COLLECT_SECONDS
    for host, ip in sorted(c['hosts'].items()):
        paths = [('auth', p) for p in c['auth_paths']] if host == c['local_host'] else []
        if host in c['dns_hosts']:
            paths += [('dns', p) for p in c['dns_paths']]
        for kind, path in paths:
            key = host + ':' + kind + ':' + path
            if time.monotonic() >= deadline:
                findings.append(finding('coverage', component='log_backlog', host=host, kind=kind))
                findings.append(finding('source_summary', host=host, kind=kind, status='partial'))
                continue
            try:
                ssh_config = {}
                if host != c['local_host']:
                    for line in command(['ssh', '-G', host], min(3, deadline - time.monotonic())).decode().splitlines():
                        key_name, _, value = line.partition(' ')
                        ssh_config[key_name] = value
                key_alias = ssh_config.get('hostkeyalias') or ssh_config.get('hostname', host)
                args = ['ssh', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', '-oConnectTimeout=8', '-oConnectionAttempts=1', '-oServerAliveInterval=5', '-oServerAliveCountMax=1', '-oHostname=' + ip, '-oHostKeyAlias=' + key_alias, host,
                        'sudo -n python3 -c ' + shlex.quote(REMOTE_READER)]
                if host == c['local_host']:
                    args = [sys.executable, '-c', REMOTE_READER]
                checkpoint = checkpoints.get(key)
                counts, issues, backlog = collections.Counter(), set(), True
                for _ in range(MAX_CHUNKS):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    request = json.dumps({'path': path, 'checkpoint': checkpoint, 'limit': READ_LIMIT}) + '\n'
                    raw = command(args, min(15, remaining), request.encode())
                    if len(raw) > READ_LIMIT * 7:
                        raise ValueError('oversized SSH response')
                    result = json.loads(raw)
                    next_checkpoint = result['checkpoint']
                    if (not isinstance(next_checkpoint['identity'], str) or type(next_checkpoint['offset']) is not int or next_checkpoint['offset'] < 0 or not isinstance(result['data'], str) or len(result['data'].encode()) > READ_LIMIT * 3 or any(type(result[k]) is not bool for k in ('rotated', 'backlog', 'history_skipped'))):
                        raise ValueError('invalid SSH response')
                    if checkpoint and not result['rotated'] and (next_checkpoint['identity'] != checkpoint['identity'] or not 0 <= next_checkpoint['offset'] - checkpoint['offset'] <= READ_LIMIT):
                        raise ValueError('invalid cursor progress')
                    if result['data'] and next_checkpoint == checkpoint:
                        raise ValueError('data without cursor progress')
                    progress = next_checkpoint != checkpoint and bool(result['data'])
                    for f in summarize_logs(result['data'], kind, c['suspicious_domains']):
                        counts[tuple((k, v) for k, v in f.items() if k != 'count')] += f['count']
                    checkpoint, backlog = next_checkpoint, result['backlog']
                    issues.update(k for k in ('rotated', 'history_skipped') if result[k])
                    if not backlog or not progress:
                        break
                if backlog:
                    issues.add('backlog')
                if checkpoint is not None:
                    pending[key] = checkpoint
                findings.extend(dict(fields, count=count, host=host, kind=kind) for fields, count in counts.items())
                findings.append(finding('source_summary', host=host, kind=kind, status='partial' if issues else 'ok'))
                findings.extend(finding('coverage', component='log_' + issue, host=host, kind=kind) for issue in sorted(issues))
            except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError):
                findings.append(finding('coverage', component='log_read', host=host, kind=kind))
                findings.append(finding('source_summary', host=host, kind=kind, status='partial'))
    return pending, findings


def triage(c, findings):
    findings = [safe_finding(f) for f in findings if f['category'] not in ('source_summary', 'scan_summary', 'baseline_approved', 'baseline_enrolled')]
    if not findings:
        return {'status': 'not_needed', 'severity': 'info', 'proposal': 'none'}
    schema = {'type': 'object', 'properties': {'severity': {'type': 'string', 'enum': SEVERITIES}, 'proposal': {'type': 'string', 'enum': PROPOSALS}}, 'required': ['severity', 'proposal'], 'additionalProperties': False}
    payload = {'model': c['model'], 'stream': False, 'format': schema, 'options': {'num_predict': 100, 'num_ctx': 4096, 'temperature': 0}, 'prompt': 'Return only severity and proposal from the schema. Advisory only; no actions execute. new_ports: medium/review_ports; new_device or baseline issues: review_inventory; DNS: low-confidence/review_dns; auth_failed: review_auth; coverage alone: low/restore_coverage. Prioritize security changes over coverage gaps. DNS heuristics and offline devices do not confirm an attack. Findings: ' + json.dumps(findings)}
    def timed_out(*_):
        raise TimeoutError('model deadline')
    previous_handler = signal.signal(signal.SIGALRM, timed_out)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 120)
    try:
        # Disable redirects so even a local server cannot redirect findings elsewhere.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request('http://127.0.0.1:11434/api/generate', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
        with opener.open(request, timeout=120) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('oversized model response')
        result = json.loads(json.loads(raw)['response'])
        if set(result) != {'severity', 'proposal'} or result['severity'] not in SEVERITIES or result['proposal'] not in PROPOSALS:
            raise ValueError('invalid model classification')
        return result
    except urllib.error.HTTPError as error:
        error.close()
        return {'status': 'unavailable'}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable'}
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def atomic_text(path, text):
    fd, name = tempfile.mkstemp(prefix='.netguard-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def atomic_json(path, value):
    atomic_text(path, json.dumps(value, sort_keys=True) + '\n')


def load_json(path, default=None):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def private_file(path, append=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if append else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'a' if append else 'w')


def safe_finding(f):
    categories = {'new_device', 'new_ports', 'observed_host', 'auth_failed', 'dns_suffix', 'dns_long_label', 'dns_entropy', 'coverage', 'baseline_missing', 'baseline_mismatch', 'baseline_scope_review', 'baseline_approved', 'baseline_enrolled', 'scan_summary', 'source_summary'}
    category = f.get('category')
    result = {'category': category if isinstance(category, str) and category in categories else 'other'}
    for key in ('ip', 'client_ip'):
        if valid_ip(f.get(key)):
            result[key] = valid_ip(f[key])
    if isinstance(f.get('host'), str) and HOST_NAME.fullmatch(f['host']):
        result['host'] = f['host']
    if f.get('optional') is True:
        result['optional'] = True
    if f.get('kind') in ('dns', 'auth'):
        result['kind'] = f['kind']
    if isinstance(f.get('component'), str) and f['component'] in COVERAGE_MESSAGES:
        result['component'] = f['component']
    for key in ('count', 'host_count', 'log_sources', 'approved_hosts'):
        if type(f.get(key)) is int and f[key] >= 0:
            result[key] = f[key]
    if isinstance(f.get('ports'), list):
        result['ports'] = [p for p in f['ports'] if type(p) is int and 1 <= p <= 65535]
    for key in ('network_complete', 'log_coverage_complete'):
        if type(f.get(key)) is bool:
            result[key] = f[key]
    return result


def report_text(findings, classification, stamp):
    safe = [safe_finding(f) for f in findings]
    security, coverage, observations = [], [], []
    attention = any(f['category'] not in DNS_TELEMETRY | {'scan_summary', 'source_summary', 'baseline_approved', 'baseline_enrolled'} for f in safe)
    model_suspicion = any(f['category'] in DNS_TELEMETRY for f in safe) and classification.get('severity') in ('high', 'critical')
    for f in safe:
        category = f['category']
        address = f.get('ip', 'an unlisted address')
        source = ' on ' + f['host'] if 'host' in f else ''
        if 'kind' in f:
            source += ' (' + f['kind'] + ')'
        client = ' from ' + f['client_ip'] if 'client_ip' in f else ''
        count = str(f.get('count', 0))
        if category == 'new_device':
            security.append('New device observed at ' + address + '. Next step: identify it and review inventory before approving it.')
        elif category in ('new_ports', 'observed_host'):
            ports = ', '.join(map(str, f.get('ports', []))) or 'none observed'
            security.append(('New open TCP ports at ' if category == 'new_ports' else 'Observed device at ') + address + ': ' + ports + '. Next step: review these ports and the device owner.')
        elif category in DNS_TELEMETRY | {'dns_suffix', 'auth_failed'}:
            label = {'dns_long_label': 'Long DNS label', 'dns_entropy': 'High-entropy DNS label', 'dns_suffix': 'Configured DNS suffix match', 'auth_failed': 'Failed authentication'}[category]
            line = label + ' events' + source + client + ': ' + count + '. Low-confidence indicator; this count does not confirm an attack.'
            if category in DNS_TELEMETRY:
                observations.append(line)
            else:
                security.append(line + ' Next step: ' + ('review expected sign-in failures.' if category == 'auth_failed' else 'review expected device or application activity.'))
        elif category == 'coverage':
            coverage.append((('Source' + source + '. ') if source else '') + COVERAGE_MESSAGES.get(f.get('component'), 'A monitoring check is incomplete. Next step: review local monitoring configuration.') + ((' Unparsed rows: ' + count + '.') if f.get('component') == 'dns_parse' else ''))
        elif category == 'baseline_missing':
            security.append('No approved network reference exists. Next step: review the observed inventory and explicitly approve a reference.')
        elif category in ('baseline_mismatch', 'baseline_scope_review'):
            security.append('The network reference needs scope review. Next step: compare the approved inventory with the current configuration.')
        elif category == 'baseline_approved':
            security.append('Network reference explicitly approved. Future changes remain monitored.')
        elif category == 'baseline_enrolled':
            security.append('Initial network reference saved. Future changes remain monitored.' + ((' Approved hosts: ' + str(f['approved_hosts']) + '.') if 'approved_hosts' in f else ''))
        elif category == 'scan_summary':
            coverage.append('Scan observed ' + str(f.get('host_count', 0)) + ' hosts. Network scan ' + ('complete' if f.get('network_complete') else 'incomplete') + '; log coverage ' + ('complete' if f.get('log_coverage_complete') else 'incomplete') + ' across ' + str(f.get('log_sources', 0)) + ' sources.')
        elif category != 'source_summary':
            security.append('An additional finding needs review. Next step: review the local monitoring checks.')
    if model_suspicion:
        security.append('The local model suspects a higher-risk pattern in DNS heuristics. Next step: review the device activity. This is model suspicion, not a confirmed attack.')
    text = '# ' + ('Attention needed' if attention or model_suspicion else 'No new security findings') + '\n\nNetguard ' + stamp + '\n\n'
    text += '\n'.join('- ' + line for line in security) if security else 'No new security findings were observed in the completed checks.'
    text += '\n\n## Coverage\n\n' + ('\n'.join('- ' + line for line in coverage) if coverage else 'No coverage issues were reported.')
    if observations:
        text += '\n\n## Informational DNS patterns\n\n' + '\n'.join('- ' + line for line in observations)
    if classification.get('status') == 'not_needed':
        text += '\n\nLocal model triage was not needed.'
    elif classification.get('severity') in SEVERITIES and classification.get('proposal') in PROPOSALS:
        text += '\n\nLocal model advisory severity: ' + classification['severity'] + '.'
        if attention or model_suspicion:
            text += ' Suggested review: ' + classification['proposal'].replace('_', ' ') + '.'
        else:
            text += ' These observations are informational.'
    text += '\n\nProposed actions require human review. No actions executed.\n'
    return text


def report(outdir, findings, classification, notify=None):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    text = report_text(findings, classification, stamp)
    with private_file(outdir / (stamp + '.md')) as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    outcome = None
    if notify is not None:
        directory = os.open(outdir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        # Keep the initial report durable before sending, then finalize this same record.
        outcome = notify()
        if outcome['status'] == 'failed':
            findings.append(finding('coverage', component='notification_delivery'))
        text = report_text(findings, classification, stamp)
        messages = {'accepted': 'Phone notification accepted.', 'failed': COVERAGE_MESSAGES['notification_delivery'],
                    'disabled': 'Phone notifications are disabled.', 'unchanged': 'Phone notification suppressed for an unchanged active incident.',
                    'quiet': 'No phone notification was needed.'}
        text += '\n' + messages[outcome['status']] + '\n'
        atomic_text(outdir / (stamp + '.md'), text)
    with private_file(outdir / 'alerts.jsonl', append=True) as out:
        record = {'timestamp': stamp, 'findings': findings, 'triage': classification}
        if outcome is not None:
            record['notification'] = outcome
        out.write(json.dumps(record, sort_keys=True) + '\n')
        out.flush()
        os.fsync(out.fileno())
    directory = os.open(outdir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    atomic_text(outdir / 'latest.md', text)
    print(text)


def phone_incidents(findings, classification):
    incidents, counts = [], collections.Counter()
    dns_advisory = classification.get('severity') in ('high', 'critical') and not any(f.get('category') == 'new_ports' for f in findings)
    for item in findings:
        item = safe_finding(item)
        category = item['category']
        if category in DNS_TELEMETRY and not dns_advisory:
            continue
        if category == 'coverage':
            if item.get('component') == 'host_offline' and item.get('optional') is True:
                continue
            category = 'coverage_' + item.get('component', '')
        if category not in notifications.EVENTS:
            continue
        counts[category] += item.get('count', 1)
        incidents.append({key: value for key, value in item.items() if key != 'count'})
    signature = hashlib.sha256(json.dumps(sorted(incidents, key=lambda f: json.dumps(f, sort_keys=True)), sort_keys=True).encode()).hexdigest() if incidents else ''
    return signature, notifications.safe_counts(dict(counts))


def deliver_notification(state, findings, classification, save_pending):
    if notifications.TOPIC_ENV not in os.environ:
        return {'status': 'disabled'}
    saved = state.get('notification', {})
    if not isinstance(saved, dict):
        saved = {}
    signature, counts = phone_incidents(findings, classification)
    pending = notifications.safe_counts(saved.get('pending'))
    delayed = bool(pending)
    last = saved.get('last_success', {})
    if not isinstance(last, dict):
        last = {}
    now = int(time.time())
    unchanged = signature and signature == last.get('signature') and type(last.get('sent_at')) is int and 0 <= now - last['sent_at'] < 6 * 60 * 60
    state['notification'] = {'last_success': last if signature else {}, 'pending': pending}
    if not pending and (not counts or unchanged):
        outcome = {'status': 'unchanged' if counts else 'quiet'}
    else:
        pending = {key: max(pending.get(key, 0), counts.get(key, 0)) for key in pending.keys() | counts.keys()}
        state['notification']['pending'] = pending
        # Persist pending evidence without advancing log cursors before the final report.
        save_pending()
        outcome = notifications.send(pending, delayed=delayed)
        if outcome['status'] == 'accepted':
            state['notification']['last_success'] = {'signature': signature, 'sent_at': now} if signature else {}
            state['notification']['pending'] = {}
    state['notification']['delivery'] = outcome
    return outcome


def approved_snapshot(state, c):
    snapshot = state.get('snapshot', {})
    if snapshot.get('fingerprint') != c['_fingerprint'] or snapshot.get('complete') is not True or not snapshot.get('hosts'):
        raise ValueError('no complete matching prior snapshot')
    hosts = snapshot['hosts']
    allowed = {str(ip) for ip in c['_lan'].hosts()} | set(c['hosts'].values())
    if not isinstance(hosts, dict) or not set(hosts) <= allowed:
        raise ValueError('invalid snapshot scope')
    if any(not isinstance(ports, list) or any(type(p) is not int or p not in c['_ports'] for p in ports) for ports in hosts.values()):
        raise ValueError('invalid snapshot ports')
    return {'fingerprint': c['_fingerprint'], 'hosts': hosts, 'offline_inventory': sorted(set(c['hosts'].values()) - set(hosts))}


def run(c, approve=False):
    outdir = Path(c['output_dir'])
    outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if outdir.is_symlink():
        raise ValueError('output directory cannot be a symlink')
    os.chmod(outdir, 0o700)
    lockfd = os.open(outdir / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lockfd, 'w') as lock:
        os.fchmod(lock.fileno(), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('# Netguard\n\n- {"category":"coverage","component":"overlapping_run"}')
            return 2
        findings = []
        try:
            state = load_json(outdir / 'state.json', {})
            if not isinstance(state, dict) or not isinstance(state.get('checkpoints', {}), dict):
                raise ValueError('invalid state')
        except (OSError, ValueError):
            state = {}
            findings.append(finding('coverage', component='state_read'))
        if approve:
            try:
                baseline = approved_snapshot(state, c)
                atomic_json(outdir / 'baseline.json', baseline)
                report(outdir, [finding('baseline_approved')], {'status': 'not_requested'})
                return 0
            except (OSError, ValueError, TypeError, KeyError):
                report(outdir, [finding('coverage', component='baseline_approval')], {'status': 'not_requested'})
                return 2
        snapshot, scan_errors = scan(c)
        findings.extend(scan_errors)
        try:
            baseline = load_json(outdir / 'baseline.json')
            if baseline is None:
                findings.append(finding('baseline_missing'))
                findings.extend(finding('observed_host', ip=ip, ports=ports) for ip, ports in sorted(snapshot.items()))
            elif baseline['fingerprint'] != c['_fingerprint']:
                findings.append(finding('baseline_mismatch'))
            else:
                # Reuse the snapshot validator for the persisted trust boundary.
                approved_snapshot({'snapshot': dict(baseline, complete=True)}, c)
                findings.extend(differences(snapshot, baseline['hosts']))
        except (OSError, ValueError, TypeError, KeyError):
            findings.append(finding('coverage', component='baseline_read'))
        checkpoints, log_findings = collect(c, state.get('checkpoints', {}))
        findings.extend(log_findings)
        classification = triage(c, findings)
        if classification.get('status') == 'unavailable':
            findings.append(finding('coverage', component='model_triage'))
        findings.insert(0, finding('scan_summary', host_count=len(snapshot), network_complete=not any(f.get('component') != 'host_offline' for f in scan_errors), log_sources=sum(f['category'] == 'source_summary' for f in log_findings), log_coverage_complete=not any(f['category'] == 'coverage' for f in log_findings)))
        def notify():
            return deliver_notification(state, findings, classification, lambda: atomic_json(outdir / 'state.json', state))
        report(outdir, findings, classification, notify=notify)
        state.update(checkpoints=checkpoints, snapshot={'fingerprint': c['_fingerprint'], 'complete': not any(f.get('component') != 'host_offline' for f in scan_errors), 'hosts': snapshot})
        # A crash after HTTP acceptance can resend pending evidence on recovery.
        atomic_json(outdir / 'state.json', state)
        return 1 if any(f['category'] not in ('scan_summary', 'source_summary') for f in findings) else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--approve-baseline', action='store_true')
    modes.add_argument('--test-notification', action='store_true')
    modes.add_argument('--notify-failure', action='store_true')
    args = parser.parse_args(argv)
    if args.test_notification or args.notify_failure:
        outcome = notifications.send(mode='test' if args.test_notification else 'failure')
        if outcome['status'] == 'accepted':
            print('Notification accepted.' + (' ID: ' + outcome['id'] if 'id' in outcome else ''))
            return 0
        print('Notification disabled.' if outcome['status'] == 'disabled' else 'Notification failed (' + outcome['error_type'] + ').')
        return 0 if outcome['status'] == 'disabled' else 2
    if not args.config:
        parser.error('--config is required for normal runs')
    try:
        c = config(json.loads(Path(args.config).read_text()))
        return run(c, args.approve_baseline)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        # Never echo exception text, which may contain raw logs or secrets.
        failure = finding('coverage', component='configuration_or_io', error_type=type(error).__name__)
        print('# Netguard\n\n' + json.dumps(failure))
        if 'c' in locals():
            try:
                report(Path(c['output_dir']), [failure], {'status': 'unavailable'})
            except (OSError, ValueError):
                pass
        return 2


if __name__ == '__main__':
    sys.exit(main())
