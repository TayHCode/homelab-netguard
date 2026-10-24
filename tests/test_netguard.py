import contextlib
import io
import email.message
import json
import os
import http.server
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import threading
import unittest
import urllib.response
from unittest.mock import patch

import netguard as n
import notifications as notify


def setUpModule():
    global test_environment
    test_environment = patch.dict(os.environ)
    test_environment.start()
    os.environ.pop(notify.TOPIC_ENV, None)


def tearDownModule():
    test_environment.stop()


def settings(directory='/tmp/netguard-test'):
    return n.config({'lan_cidr': '10.20.30.0/24', 'hosts': {'a-server': '10.20.29.1', 'dns-a': '10.20.29.2'}, 'local_host': 'a-server', 'dns_hosts': ['dns-a'], 'ports': '22,80', 'output_dir': directory})


def xml(hosts, ports=True):
    body = ''
    for ip, opened in hosts.items():
        body += '<host><status state="up"/><address addrtype="ipv4" addr="' + ip + '"/>'
        if ports:
            body += '<ports><extraports state="closed" count="' + str(2 - len(opened)) + '"/>'
            body += ''.join('<port protocol="tcp" portid="' + str(p) + '"><state state="open"/></port>' for p in opened) + '</ports>'
        body += '</host>'
    return '<nmaprun>' + body + '<runstats><finished exit="success"/></runstats></nmaprun>'


class ScopeTests(unittest.TestCase):
    def test_config_rejects_scope_and_options(self):
        base = {'lan_cidr': '10.20.30.0/24', 'hosts': {'a-server': '10.20.29.1'}, 'dns_hosts': []}
        for override in ({'lan_cidr': '8.8.8.0/24'}, {'hosts': {'bad name': '10.20.29.1'}}, {'hosts': {'a-server': '10.20.29.0/24'}}, {'hosts': {'a-server': '8.8.4.4'}}, {'hosts': {'a-server': '::1'}}, {'ports': '22 --script=all'}, {'ports': '0'}, {'ports': '65536'}, {'ports': '80-22'}):
            with self.subTest(override=override), self.assertRaises((ValueError, TypeError)):
                n.config(dict(base, **override))

    def test_xml_diff_and_closed_only_host(self):
        current = n.parse_nmap(xml({'10.20.30.2': [], '10.20.29.1': [22, 80]}), {'10.20.30.2', '10.20.29.1'}, 2, {22, 80})
        self.assertEqual(current, {'10.20.30.2': [], '10.20.29.1': [22, 80]})
        self.assertEqual(n.differences(current, {'10.20.29.1': [22]}), [{'category': 'new_ports', 'ip': '10.20.29.1', 'ports': [80]}, {'category': 'new_device', 'ip': '10.20.30.2'}])
        for document, allowed in ((xml({'8.8.4.4': []}), {'10.20.29.1'}), (xml({}), {'10.20.29.1'}), (xml({'10.20.29.1': [22]}).replace('count="1"', 'count="0"'), {'10.20.29.1'})):
            with self.assertRaises(ValueError):
                n.parse_nmap(document, allowed, 2)

    def test_discovery_excludes_offline_inventory_and_scan_is_bounded(self):
        calls = []
        def fake(args, timeout, input=None):
            calls.append((args, timeout))
            if args[1] == '-sn':
                return xml({'10.20.30.2': []} if args[-1] == '10.20.30.0/24' else {'10.20.29.1': []}, False)
            return xml({'10.20.30.2': [], '10.20.29.1': [22]})
        with patch.object(n, 'command', fake):
            snapshot, failures = n.scan(settings())
        self.assertEqual(snapshot, {'10.20.30.2': [], '10.20.29.1': [22]})
        self.assertEqual(failures, [{'category': 'coverage', 'component': 'host_offline', 'host': 'dns-a', 'ip': '10.20.29.2', 'optional': False}])
        args, timeout = calls[-1]
        self.assertNotIn('10.20.29.2', args)
        self.assertNotIn('--open', args)
        self.assertEqual(args[args.index('--max-rate') + 1], '5000')
        self.assertEqual(timeout, 1200)


class LogTests(unittest.TestCase):
    def local_dns(self, path, outdir):
        return n.config({'lan_cidr': '10.20.30.0/24', 'hosts': {'a-server': '10.20.29.1'}, 'local_host': 'a-server', 'dns_hosts': ['a-server'], 'dns_paths': [str(path)], 'auth_paths': [], 'ports': '22,80', 'output_dir': str(outdir), 'suspicious_domains': ['evil.example']})

    def checkpoint(self, path):
        st = path.stat()
        return {'identity': str(st.st_dev) + ':' + str(st.st_ino), 'offset': 0}

    def test_collect_catches_up_multiple_chunks_without_duplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'dns'
            row = json.dumps({'QH': 'secret.evil.example', 'IP': '10.20.30.20', 'token': 'TOPSECRET'}) + '\n'
            path.write_text((row + row.replace('10.20.30.20', '10.20.30.21')) * 15000)
            c = self.local_dns(path, Path(temp) / 'reports')
            key = 'a-server:dns:' + str(path)
            calls = []
            original = n.command
            def read(args, timeout, input=None):
                calls.append(json.loads(input))
                return original(args, timeout, input)
            with patch.object(n, 'command', read):
                pending, findings = n.collect(c, {key: self.checkpoint(path)})
            self.assertGreater(len(calls), 1)
            self.assertTrue(all(call['limit'] == 1024 * 1024 for call in calls))
            self.assertEqual(pending[key]['offset'], path.stat().st_size)
            self.assertEqual([f for f in findings if f['category'] == 'dns_suffix'], [dict(category='dns_suffix', count=15000, client_ip=ip, host='a-server', kind='dns') for ip in ('10.20.30.20', '10.20.30.21')])
            self.assertFalse(any(f['category'] == 'coverage' for f in findings))
            again, repeated = n.collect(c, pending)
            self.assertEqual(again, pending)
            self.assertFalse(any(f['category'] == 'dns_suffix' for f in repeated))
            root = Path(c['output_dir'])
            root.mkdir(mode=0o700)
            with contextlib.redirect_stdout(io.StringIO()):
                n.report(root, findings, {'status': 'not_needed', 'severity': 'info', 'proposal': 'none'})
            for stored in root.iterdir():
                for secret in ('TOPSECRET', 'secret.evil.example'):
                    self.assertNotIn(secret, stored.read_text())

    def test_collect_stops_at_chunk_budget_and_resumes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'dns'
            row = json.dumps({'QH': 'secret.evil.example', 'IP': '10.20.30.20'}) + '\n'
            path.write_text(row * 50000)
            key = 'a-server:dns:' + str(path)
            c = self.local_dns(path, temp)
            with patch.object(n, 'MAX_CHUNKS', 2):
                pending, findings = n.collect(c, {key: self.checkpoint(path)})
            self.assertGreater(pending[key]['offset'], n.READ_LIMIT)
            self.assertLessEqual(pending[key]['offset'], n.READ_LIMIT * 2)
            self.assertLess(pending[key]['offset'], path.stat().st_size)
            self.assertIn(dict(category='coverage', component='log_backlog', host='a-server', kind='dns'), findings)
            self.assertIn(dict(category='source_summary', host='a-server', kind='dns', status='partial'), findings)
            end, rest = n.collect(c, pending)
            self.assertEqual(end[key]['offset'], path.stat().st_size)
            self.assertEqual(sum(f['count'] for f in findings + rest if f['category'] == 'dns_suffix'), 50000)

    def test_collect_no_progress_and_deadline_are_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'dns'
            path.write_bytes(b'x' * (n.READ_LIMIT + 1))
            key = 'a-server:dns:' + str(path)
            original = {key: self.checkpoint(path)}
            c = self.local_dns(path, temp)
            with patch.object(n, 'command', wraps=n.command) as reader:
                pending, findings = n.collect(c, original)
            self.assertEqual(reader.call_count, 1)
            self.assertEqual(pending, original)
            self.assertIn(dict(category='coverage', component='log_backlog', host='a-server', kind='dns'), findings)
            with patch.object(n.time, 'monotonic', side_effect=[0, 61]), patch.object(n, 'command') as reader:
                pending, findings = n.collect(c, original)
            reader.assert_not_called()
            self.assertEqual(pending, original)
            self.assertIn(dict(category='source_summary', host='a-server', kind='dns', status='partial'), findings)

    def test_collect_later_read_error_preserves_source_checkpoint(self):
        c = self.local_dns(Path('/unused'), '/tmp/netguard-test')
        key = 'a-server:dns:/unused'
        original = {key: {'identity': '1:2', 'offset': 0}}
        data = json.dumps({'QH': 'secret.evil.example', 'IP': '10.20.30.20'}) + '\n'
        chunk = json.dumps({'data': data, 'checkpoint': {'identity': '1:2', 'offset': len(data)}, 'backlog': True, 'rotated': False, 'history_skipped': False}).encode()
        with patch.object(n, 'command', side_effect=[chunk, OSError('TOPSECRET')]):
            pending, findings = n.collect(c, original)
        self.assertEqual(pending, original)
        self.assertIn(dict(category='coverage', component='log_read', host='a-server', kind='dns'), findings)
        self.assertFalse(any(f['category'] == 'dns_suffix' for f in findings))

    def test_collect_deadline_after_progress_preserves_partial_counts(self):
        c = self.local_dns(Path('/unused'), '/tmp/netguard-test')
        key = 'a-server:dns:/unused'
        original = {key: {'identity': '1:2', 'offset': 0}}
        data = json.dumps({'QH': 'secret.evil.example', 'IP': '10.20.30.20'}) + '\n'
        checkpoint = {'identity': '1:2', 'offset': len(data)}
        chunk = json.dumps({'data': data, 'checkpoint': checkpoint, 'backlog': True, 'rotated': False, 'history_skipped': False}).encode()
        with patch.object(n.time, 'monotonic', side_effect=[0, 0, 59, 61]), patch.object(n, 'command', return_value=chunk) as reader:
            pending, findings = n.collect(c, original)
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(reader.call_args.args[1], 1)
        self.assertEqual(pending[key], checkpoint)
        self.assertIn(dict(category='dns_suffix', count=1, client_ip='10.20.30.20', host='a-server', kind='dns'), findings)
        self.assertIn(dict(category='coverage', component='log_backlog', host='a-server', kind='dns'), findings)

    def test_collect_rejects_bad_cursor_without_losing_other_source(self):
        c = settings()
        auth_key = 'a-server:auth:/var/log/auth.log'
        dns_key = 'dns-a:dns:/opt/AdGuardHome/data/querylog.json'
        original = {dns_key: {'identity': '1:2', 'offset': 100}}
        for bad in ({'identity': '1:2', 'offset': 99}, {'identity': 'wrong', 'offset': 150}, {'identity': '1:2', 'offset': 100}):
            def read(args, timeout, input=None):
                if args[:2] == ['ssh', '-G']:
                    return b'hostname dns-a\n'
                is_auth = json.loads(input)['path'] == '/var/log/auth.log'
                return json.dumps({'data': 'Failed password from 8.8.8.8\n', 'checkpoint': {'identity': '3:4', 'offset': 30} if is_auth else bad, 'rotated': False, 'backlog': False, 'history_skipped': False}).encode()
            with self.subTest(checkpoint=bad), patch.object(n, 'command', read):
                pending, findings = n.collect(c, original)
                self.assertEqual(pending[dns_key], original[dns_key])
                self.assertEqual(pending[auth_key], {'identity': '3:4', 'offset': 30})
                self.assertIn(dict(category='coverage', component='log_read', host='dns-a', kind='dns'), findings)

    def test_dns_and_auth_are_redacted(self):
        data = json.dumps({'T': 'private timestamp', 'QH': 'secret.evil.example', 'IP': '10.20.30.20', 'Result': {'token': 'TOPSECRET'}})
        data += '\n' + json.dumps({'QH': 'a' * 45 + '.private.example', 'IP': '10.20.30.20'})
        data += '\nJan 1 query[A] child.evil.example from 10.20.30.20'
        findings = n.summarize_logs(data, 'dns', ['evil.example'])
        self.assertEqual(findings, [{'category': 'dns_long_label', 'count': 1, 'client_ip': '10.20.30.20'}, {'category': 'dns_suffix', 'count': 2, 'client_ip': '10.20.30.20'}])
        auth = n.summarize_logs('Failed password for private-user from 8.8.8.8 port 22\nauthentication failure; user=secret rhost=1.1.1.1\nFailed password for token-user', 'auth', [])
        self.assertEqual(sum(f['count'] for f in auth), 3)
        persisted = json.dumps(findings + auth)
        for secret in ('TOPSECRET', 'secret', 'example', 'private-user', 'token-user'):
            self.assertNotIn(secret, persisted)
        self.assertIsNone(n.dns_category('notevil.example', ['evil.example']))

    def reader(self, path, checkpoint=None, limit=128):
        result = subprocess.run([sys.executable, '-c', n.REMOTE_READER], input=json.dumps({'path': str(path), 'checkpoint': checkpoint, 'limit': limit}).encode(), stdout=subprocess.PIPE, check=True)
        return json.loads(result.stdout)

    def test_reader_offsets_rotation_partial_and_initial_tail(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'log'
            path.write_text('old\nnew\npartial')
            first = self.reader(path)
            self.assertEqual(first['data'], 'old\nnew\n')
            self.assertEqual(first['checkpoint']['offset'], 8)
            with path.open('a') as out:
                out.write('\n')
            second = self.reader(path, first['checkpoint'])
            self.assertEqual(second['data'], 'partial\n')
            path.rename(Path(temp) / 'rotated')
            path.write_text('rotated\n')
            rotation = self.reader(path, second['checkpoint'])
            self.assertTrue(rotation['rotated'])
            self.assertEqual(rotation['data'], 'rotated\n')
            path.write_text('ancient\n' * 50 + 'recent\n')
            tail = self.reader(path, limit=32)
            self.assertTrue(tail['history_skipped'])
            self.assertLessEqual(len(tail['data']), 32)
            self.assertTrue(tail['data'].endswith('recent\n'))

    def test_collect_uses_local_reader_and_preserves_ssh_key_alias(self):
        calls = []
        def fake(args, timeout, input=None):
            calls.append(args)
            if args[:2] == ['ssh', '-G']:
                return b'hostname dns-a.tail.example\nuser root\n'
            return json.dumps({'data': 'Failed password for private from 8.8.8.8\n', 'checkpoint': {'identity': '1:2', 'offset': 50}, 'rotated': False, 'backlog': False, 'history_skipped': False}).encode()
        with patch.object(n, 'command', fake):
            checkpoints, findings = n.collect(settings(), {})
        self.assertEqual(calls[0][:2], [sys.executable, '-c'])
        ssh = next(args for args in calls if '-oBatchMode=yes' in args)
        self.assertIn('-oHostname=10.20.29.2', ssh)
        self.assertIn('-oHostKeyAlias=dns-a.tail.example', ssh)
        self.assertIn('dns-a', ssh)
        self.assertEqual(len(checkpoints), 2)
        self.assertTrue(all('host' in f and 'kind' in f for f in findings))


class PersistenceTests(unittest.TestCase):
    def run_quietly(self, c, approve=False):
        with contextlib.redirect_stdout(io.StringIO()):
            return n.run(c, approve)

    def test_missing_baseline_explicit_approval_and_no_auto_promotion(self):
        with tempfile.TemporaryDirectory() as temp:
            c = settings(temp)
            hosts = {'10.20.30.2': [22], '10.20.29.1': [22]}
            offline = [n.finding('coverage', component='host_offline', host='dns-a', ip='10.20.29.2')]
            with patch.object(n, 'scan', return_value=(hosts, offline)), patch.object(n, 'collect', return_value=({}, [])), patch.object(n, 'triage', return_value={'status': 'unavailable'}):
                self.assertEqual(self.run_quietly(c), 1)
            root = Path(temp)
            self.assertFalse((root / 'baseline.json').exists())
            alert = json.loads((root / 'alerts.jsonl').read_text())
            self.assertIn({'category': 'baseline_missing'}, alert['findings'])
            self.assertIn({'category': 'observed_host', 'ip': '10.20.30.2', 'ports': [22]}, alert['findings'])
            self.assertIn({'category': 'coverage', 'component': 'model_triage'}, alert['findings'])
            self.assertEqual(self.run_quietly(c, True), 0)
            baseline = json.loads((root / 'baseline.json').read_text())
            self.assertEqual(baseline['hosts'], hosts)
            self.assertEqual(baseline['offline_inventory'], ['10.20.29.2'])
            state = json.loads((root / 'state.json').read_text())
            state['snapshot']['complete'] = False
            n.atomic_json(root / 'state.json', state)
            self.assertEqual(self.run_quietly(c, True), 2)
            self.assertEqual(json.loads((root / 'baseline.json').read_text()), baseline)
            self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in root.iterdir()))
            state['snapshot']['complete'] = True
            state['snapshot']['fingerprint'] = 'mismatch'
            n.atomic_json(root / 'state.json', state)
            self.assertEqual(self.run_quietly(c, True), 2)

    def test_discovery_timeout_persists_coverage_and_refuses_approval(self):
        with tempfile.TemporaryDirectory() as temp:
            c = settings(temp)
            with patch.object(n, 'command', side_effect=subprocess.TimeoutExpired('SECRET_COMMAND', 90)), patch.object(n, 'collect', return_value=({}, [])), patch.object(n, 'triage', return_value={'status': 'unavailable'}):
                self.assertEqual(self.run_quietly(c), 1)
            alert_text = (Path(temp) / 'alerts.jsonl').read_text()
            self.assertNotIn('SECRET_COMMAND', alert_text)
            self.assertIn({'category': 'coverage', 'component': 'lan_discovery', 'error_type': 'TimeoutExpired'}, json.loads(alert_text)['findings'])
            self.assertEqual(self.run_quietly(c, True), 2)
            self.assertFalse((Path(temp) / 'baseline.json').exists())

    def test_report_failure_does_not_commit_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            c = settings(temp)
            with patch.object(n, 'scan', return_value=({'10.20.29.1': [22]}, [])), patch.object(n, 'collect', return_value=({'offset': 100}, [])), patch.object(n, 'triage', return_value={'status': 'unavailable'}), patch.object(n, 'report', side_effect=OSError('disk full')):
                with self.assertRaises(OSError):
                    self.run_quietly(c)
            self.assertFalse((Path(temp) / 'state.json').exists())

    def test_model_redirect_is_never_followed(self):
        paths = []
        def redirect(handler, request):
            paths.append(request.selector)
            headers = email.message.Message()
            headers['Location'] = '/sink'
            response = urllib.response.addinfourl(io.BytesIO(b''), headers, request.full_url, 302)
            response.msg = 'Found'
            return response
        with patch.object(n.urllib.request.HTTPHandler, 'http_open', redirect):
            self.assertEqual(n.triage(settings(), [n.finding('coverage', component='log_read')]), {'status': 'unavailable'})
        self.assertEqual(paths, ['/api/generate'])

    def test_model_outage_and_generated_freeform_are_discarded(self):
        findings = [n.finding('coverage', component='log_read')]
        with patch.object(n.urllib.request.OpenerDirector, 'open', side_effect=OSError('secret unavailable')):
            self.assertEqual(n.triage(settings(), findings), {'status': 'unavailable'})
        response = io.BytesIO(json.dumps({'response': json.dumps({'severity': 'high', 'proposal': 'review_dns', 'secret': 'must-not-persist'})}).encode())
        with patch.object(n.urllib.request.OpenerDirector, 'open', return_value=response):
            self.assertEqual(n.triage(settings(), findings), {'status': 'unavailable'})

    def test_model_skips_empty_findings_and_filters_prompt(self):
        summaries = [n.finding('source_summary', host='dns-a', kind='dns', status='ok'), n.finding('scan_summary', host_count=35)]
        with patch.object(n.urllib.request.OpenerDirector, 'open') as model:
            self.assertEqual(n.triage(settings(), []), dict(status='not_needed', severity='info', proposal='none'))
            self.assertEqual(n.triage(settings(), summaries), dict(status='not_needed', severity='info', proposal='none'))
        model.assert_not_called()
        response = io.BytesIO(json.dumps({'response': json.dumps({'severity': 'low', 'proposal': 'review_dns'})}).encode())
        findings = summaries + [n.finding('dns_long_label', host='dns-a', count=4, domain='SECRET.private.example', raw='TOPSECRET')]
        with patch.object(n.urllib.request.OpenerDirector, 'open', return_value=response) as model:
            self.assertEqual(n.triage(settings(), findings), dict(severity='low', proposal='review_dns'))
        prompt = json.loads(model.call_args.args[0].data)['prompt']
        for omitted in ('source_summary', 'scan_summary', 'SECRET', 'TOPSECRET', 'private.example'):
            self.assertNotIn(omitted, prompt)
        self.assertIn('dns_long_label', prompt)

    def test_human_report_heading_coverage_and_private_atomic_latest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            telemetry = [n.finding('dns_long_label', count=9, client_ip='10.20.30.20', host='dns-a', kind='dns')]
            original_replace = os.replace
            replacements = []
            def replace(source, target):
                self.assertEqual(Path(source).stat().st_mode & 0o777, 0o600)
                replacements.append(target)
                return original_replace(source, target)
            with contextlib.redirect_stdout(io.StringIO()), patch.object(n.os, 'replace', replace):
                n.report(root, telemetry, dict(severity='medium', proposal='review_dns'))
            latest = root / 'latest.md'
            first = latest.read_text()
            self.assertTrue(first.startswith('# No new security findings\n'))
            self.assertIn('Low-confidence indicator', first)
            self.assertIn('## Informational DNS patterns', first)
            self.assertNotIn('Next step:', first)
            self.assertNotIn('Suggested review:', first)
            self.assertIn('10.20.30.20: 9', first)
            self.assertIn('## Coverage', first)
            self.assertEqual(replacements, [latest])
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in root.iterdir()))
            with contextlib.redirect_stdout(io.StringIO()):
                n.report(root, telemetry, dict(severity='high', proposal='review_dns'))
                self.assertIn('model suspicion, not a confirmed attack', latest.read_text())
                self.assertTrue(latest.read_text().startswith('# Attention needed\n'))
                n.report(root, telemetry + [n.finding('new_ports', ip='10.20.30.20', ports=[80])], dict(severity='info', proposal='none'))
                self.assertTrue(latest.read_text().startswith('# Attention needed\n'))
                self.assertIn('New open TCP ports at 10.20.30.20: 80', latest.read_text())
                n.report(root, [n.finding('coverage', component='log_backlog', host='dns-a', kind='dns')], dict(severity='low', proposal='restore_coverage'))
                self.assertTrue(latest.read_text().startswith('# Attention needed\n'))
                self.assertIn('Some log data remains unread', latest.read_text())
            self.assertEqual(json.loads((root / 'alerts.jsonl').read_text().splitlines()[0])['findings'], telemetry)
            self.assertEqual(len(list(root.glob('*.md'))), 5)
            self.assertTrue(any(p.read_text() == first for p in root.glob('*.md')))
            self.assertFalse(list(root.glob('.netguard-*')))

    def test_report_attention_rules_do_not_hide_deterministic_findings(self):
        cases = [(n.finding(category, count=2), False) for category in ('dns_long_label', 'dns_entropy')]
        cases += [(n.finding(category), True) for category in ('dns_suffix', 'auth_failed', 'new_device', 'new_ports', 'baseline_missing', 'baseline_mismatch', 'baseline_scope_review', 'coverage')]
        cases += [(n.finding('baseline_enrolled', approved_hosts='TOPSECRET'), False)]
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            for item, attention in cases:
                with self.subTest(category=item['category']):
                    n.report(root, [item], dict(severity='info', proposal='none'))
                    text = (root / 'latest.md').read_text()
                    self.assertEqual(text.splitlines()[0], '# Attention needed' if attention else '# No new security findings')
                    self.assertNotIn('TOPSECRET', text)

    def test_report_unknown_fields_never_appear_in_markdown(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            findings = [n.finding('baseline_enrolled', approved_hosts=35, raw='TOPSECRET'), n.finding('baseline_scope_review', detail='private.example'), n.finding('SECRET_CATEGORY', ip='private.example', count='TOPSECRET'), n.finding('coverage', component='SECRET_COMPONENT'), n.finding(['SECRET_CATEGORY'], host=['TOPSECRET'], component={'secret': 'private.example'})]
            n.report(root, findings, dict(severity='info', proposal='none', raw='MODELSECRET'))
            text = (root / 'latest.md').read_text()
            self.assertIn('Initial network reference saved. Future changes remain monitored. Approved hosts: 35.', text)
            self.assertIn('network reference needs scope review', text)
            for raw in ('TOPSECRET', 'private.example', 'SECRET_CATEGORY', 'SECRET_COMPONENT', 'MODELSECRET', '"category"'):
                self.assertNotIn(raw, text)

    def test_latest_failure_does_not_commit_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            c = settings(temp)
            root = Path(temp)
            state = {'checkpoints': {'saved-source': {'identity': '1:2', 'offset': 50}}}
            n.atomic_json(root / 'state.json', state)
            n.atomic_text(root / 'latest.md', 'previous complete report\n')
            original = os.replace
            def replace(source, target):
                if target == root / 'latest.md':
                    raise OSError('disk full')
                return original(source, target)
            with patch.object(n, 'scan', return_value=({'10.20.29.1': [22]}, [])), patch.object(n, 'collect', return_value=({'offset': 100}, [])), patch.object(n, 'triage', return_value={'status': 'not_needed'}), patch.object(n.os, 'replace', replace):
                with self.assertRaises(OSError):
                    self.run_quietly(c)
            self.assertEqual(json.loads((root / 'state.json').read_text()), state)
            self.assertEqual((root / 'latest.md').read_text(), 'previous complete report\n')
            self.assertFalse(list(root.glob('.netguard-*')))


class NotificationTests(unittest.TestCase):
    topic = 'test-topic-never-production'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.topic_file = self.root / 'topic'
        self.topic_file.write_text(self.topic + '\n')
        self.environment = patch.dict(os.environ, {notify.TOPIC_ENV: str(self.topic_file)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        digest_off = patch.object(n, 'DIGEST_HOUR', 25)
        digest_off.start()
        self.addCleanup(digest_off.stop)

    @contextlib.contextmanager
    def server(self, status=200, body=None):
        calls = []
        payload = body if body is not None else json.dumps({'id': 'AbCdEf123456', 'topic': self.topic}).encode()
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                calls.append((self.path, dict(self.headers), self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(status)
                if status == 302:
                    self.send_header('Location', '/sink')
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        original = notify.urllib.request.OpenerDirector.open
        def loopback(opener, request, timeout):
            self.assertEqual(request.full_url, 'https://ntfy.sh/' + self.topic)
            self.assertEqual(timeout, 8)
            local = notify.urllib.request.Request('http://127.0.0.1:' + str(server.server_port) + '/publish',
                                                 data=request.data, headers=dict(request.header_items()), method='POST')
            return original(opener, local, timeout=timeout)
        try:
            with patch.object(notify.urllib.request.OpenerDirector, 'open', loopback):
                yield calls
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_only_new_devices_ports_and_baseline_problems_page(self):
        pages = {
            'new_device': ('new_device:10.20.30.9', 'New device at 10.20.30.9'),
            'baseline_missing': ('baseline_missing', n.PAGE_NOTES['baseline_missing']),
        }
        for category, (key, text) in pages.items():
            with self.subTest(category=category):
                self.assertEqual(n.notification_items([n.finding(category, ip='10.20.30.9')]), {key: {'text': text, 'count': 1, 'page': True}})
        ports = n.notification_items([n.finding('new_ports', ip='10.20.30.9', ports=[22, 80])])
        self.assertEqual(ports, {'new_ports:10.20.30.9:22, 80': {'text': 'New open ports on 10.20.30.9: 22, 80', 'count': 1, 'page': True}})
        digest = [n.finding('auth_failed', count=3, host='a-server', client_ip='10.20.30.9'), n.finding('dns_entropy', count=8, host='dns-a'),
                  n.finding('dns_long_label', count=2, host='dns-a'), n.finding('dns_suffix', count=1, host='dns-a'), n.finding('coverage', component='tcp_scan')]
        digest += [n.finding('coverage', component='host_offline', host=host) for host in ('a-server', 'dns-a')]
        for found in n.notification_items(digest).values():
            self.assertFalse(found['page'])
        self.assertEqual(len(n.notification_items(digest)), 5 + 2)
        self.assertEqual(n.notification_items([n.finding('auth_failed', count=3, host='a-server', client_ip='10.20.30.9')]),
                         {'auth_failed on a-server from 10.20.30.9': {'text': 'Failed sign-ins on a-server from 10.20.30.9', 'count': 3, 'page': False}})
        routine = [n.finding(category) for category in ('baseline_approved', 'baseline_enrolled', 'observed_host', 'source_summary', 'scan_summary', 'unknown')]
        routine += [n.finding('coverage', component=c) for c in ('log_rotated', 'log_history_skipped', 'notification_delivery')]
        routine.append(n.finding('coverage', component='host_offline', host='laptop-a', optional=True))
        self.assertEqual(n.notification_items(routine), {})

    def test_each_item_pages_once_even_as_devices_come_and_go(self):
        state = {}
        a, b = n.finding('new_device', ip='10.20.30.9'), n.finding('new_device', ip='10.20.30.10')
        def deliver(findings, now):
            return n.deliver_notification(state, findings, lambda: None, now=now)['status']
        with patch.object(notify, 'send', return_value={'status': 'accepted'}) as sender:
            self.assertEqual(deliver([a], 100), 'accepted')
            self.assertEqual(deliver([a, b], 200), 'accepted')
            self.assertEqual(sender.call_args.args[0], ['New device at 10.20.30.10'])
            self.assertEqual(deliver([b], 300), 'unchanged')
            self.assertEqual(deliver([a], 400), 'unchanged')
            self.assertEqual(deliver([], 500), 'quiet')
            self.assertEqual(sender.call_count, 2)
            self.assertEqual(deliver([a], 100 + n.PAGED_TTL + 1), 'accepted')

    def test_digest_sends_once_after_the_morning_hour_and_lists_unreviewed_items(self):
        state = {}
        day = time.mktime((2026, 10, 24, 0, 0, 0, 0, 0, -1))
        findings = [n.finding('new_device', ip='10.20.30.9'), n.finding('dns_entropy', count=8, host='dns-a')]
        with patch.object(n, 'DIGEST_HOUR', 8), patch.object(notify, 'send', return_value={'status': 'accepted'}) as sender:
            n.deliver_notification(state, findings, lambda: None, now=int(day + 3 * 3600))
            self.assertEqual([c.kwargs.get('mode', 'alert') for c in sender.call_args_list], ['alert'])
            n.deliver_notification(state, findings, lambda: None, now=int(day + 8 * 3600))
            self.assertEqual([c.kwargs.get('mode', 'alert') for c in sender.call_args_list], ['alert', 'digest'])
            self.assertEqual(sender.call_args.args[0], ['High-entropy DNS labels on dns-a (x16)', 'New device at 10.20.30.9 (x2)'])
            n.deliver_notification(state, findings, lambda: None, now=int(day + 9 * 3600))
            n.deliver_notification(state, [], lambda: None, now=int(day + 20 * 3600))
            self.assertEqual(sender.call_count, 2)
            self.assertEqual(state['notification']['digest'], {'new_device:10.20.30.9': {'text': 'New device at 10.20.30.9', 'count': 1}, 'dns_entropy on dns-a': {'text': 'High-entropy DNS labels on dns-a', 'count': 8}})
            n.deliver_notification(state, [], lambda: None, now=int(day + 86400 + 9 * 3600))
            self.assertEqual(sender.call_count, 3)
            self.assertEqual(sender.call_args.args[0], ['High-entropy DNS labels on dns-a (x8)', 'New device at 10.20.30.9'])

    def test_quiet_day_still_sends_a_heartbeat_digest_and_failure_retries(self):
        state = {}
        now = int(time.mktime((2026, 10, 24, 9, 0, 0, 0, 0, -1)))
        failure = {'status': 'failed', 'error_type': 'TransportError'}
        with patch.object(n, 'DIGEST_HOUR', 8), patch.object(notify, 'send', side_effect=[failure, {'status': 'accepted'}]) as sender:
            self.assertEqual(n.deliver_notification(state, [], lambda: None, now=now), failure)
            self.assertEqual(n.deliver_notification(state, [], lambda: None, now=now + 1800)['status'], 'accepted')
            self.assertEqual(n.deliver_notification(state, [], lambda: None, now=now + 3600)['status'], 'quiet')
        self.assertEqual(sender.call_count, 2)
        self.assertEqual(sender.call_args.kwargs, {'mode': 'digest'})

    def test_disabled_never_reads_a_topic_or_changes_baseline_fingerprint(self):
        before = settings()['_fingerprint']
        self.assertEqual(settings()['_fingerprint'], before)
        os.environ.pop(notify.TOPIC_ENV)
        with patch('builtins.open', side_effect=AssertionError('disabled must not read files')):
            self.assertEqual(notify.send(mode='test'), {'status': 'disabled'})
            self.assertEqual(n.deliver_notification({}, [n.finding('new_ports')], {}, lambda: None), {'status': 'disabled'})
        self.assertEqual(settings()['_fingerprint'], before)

    def test_sender_payload_priorities_and_private_receipt(self):
        lines = ['New device at 10.20.30.9', 'New open ports on 10.20.30.9: 22'] + ['x'] * 8
        with self.server() as calls, patch.dict(os.environ, {'http_proxy': 'http://127.0.0.1:1', 'https_proxy': 'http://127.0.0.1:1', 'no_proxy': ''}):
            result = notify.send(lines, delayed=True)
            self.assertEqual(result, {'status': 'accepted', 'id': 'AbCdEf123456'})
            self.assertEqual(notify.send(mode='test'), result)
            self.assertEqual(notify.send(mode='failure'), result)
            self.assertEqual(notify.send([], mode='digest'), result)
            self.assertEqual(notify.send(['\N{SNOWMAN}'], mode='digest'), result)
        path, headers, body = calls[0]
        self.assertEqual(path, '/publish')
        self.assertEqual(headers['Priority'], '4')
        self.assertTrue(headers['Title'].isascii())
        self.assertEqual(body.decode().splitlines(), ['Delayed from an earlier delivery failure.', *lines[:8], '+2 more in the local report.', 'Alert only; nothing was changed.'])
        self.assertEqual(calls[1][1]['Priority'], '3')
        self.assertEqual(calls[1][2], b'Netguard test notification. Alert-only monitoring.')
        self.assertEqual(calls[2][1]['Priority'], '4')
        self.assertIn(b'scanner failed to complete; monitoring incomplete', calls[2][2])
        self.assertEqual(calls[3][2], b'Nothing new since the last digest.')
        self.assertEqual(calls[3][1]['Title'], 'Netguard morning digest')
        self.assertEqual(calls[4][2], b'?')
        self.assertNotIn(self.topic, body.decode() + json.dumps(result))

    def test_actual_redirect_rejected_and_errors_do_not_leak(self):
        with self.server(302, b'PRIVATE_RESPONSE') as calls:
            self.assertEqual(notify.send(mode='test'), {'status': 'failed', 'error_type': 'HTTPError'})
        self.assertEqual(len(calls), 1)
        with self.server(503, b'PRIVATE_RESPONSE'):
            self.assertEqual(notify.send(mode='test'), {'status': 'failed', 'error_type': 'HTTPError'})
        with patch.object(notify.urllib.request.OpenerDirector, 'open', side_effect=RuntimeError('PRIVATE_URL_TOPIC_RESPONSE')):
            self.assertEqual(notify.send(mode='test'), {'status': 'failed', 'error_type': 'TransportError'})

    def test_topic_validation_and_response_bounds(self):
        for topic in ('', 'bad/topic', 'bad\r\nTitle: leak', 'x' * 65, 'https://private.example', '\N{SNOWMAN}'):
            self.topic_file.write_text(topic)
            with self.subTest(topic=topic), patch.object(notify.urllib.request.OpenerDirector, 'open') as sender:
                self.assertEqual(notify.send(mode='test'), {'status': 'failed', 'error_type': 'TopicFileError'})
                sender.assert_not_called()
        self.topic_file.unlink()
        self.assertEqual(notify.send(mode='failure'), {'status': 'failed', 'error_type': 'TopicFileError'})
        self.topic_file.write_text(self.topic)
        for body in (b'not json', json.dumps({'id': 'https://private.example', 'topic': self.topic}).encode(), b'x' * 9000):
            response = io.BytesIO(body)
            response.status = 200
            with patch.object(notify.urllib.request.OpenerDirector, 'open', return_value=response):
                self.assertEqual(notify.send(mode='test'), {'status': 'accepted'})
        self.topic_file.write_text('AbCdEf123456')
        response = io.BytesIO(b'{"id":"AbCdEf123456"}')
        response.status = 200
        with patch.object(notify.urllib.request.OpenerDirector, 'open', return_value=response):
            self.assertEqual(notify.send(mode='test'), {'status': 'accepted'})

    def test_failed_page_is_retried_until_accepted_and_state_stays_bounded(self):
        state = {}
        failure = {'status': 'failed', 'error_type': 'HTTPError'}
        many = [n.finding('new_device', ip='192.168.%d.%d' % (i // 250, i % 250 + 1)) for i in range(400)]
        with patch.object(notify, 'send', return_value=failure) as sender:
            self.assertEqual(n.deliver_notification(state, many, lambda: None, now=100), failure)
            self.assertEqual(n.deliver_notification(state, [], lambda: None, now=200), failure)
            self.assertEqual(sender.call_count, 2)
            self.assertEqual(state['notification']['paged'], {})
        with patch.object(notify, 'send', return_value={'status': 'accepted'}):
            n.deliver_notification(state, [], lambda: None, now=300)
        self.assertEqual(state['notification']['pending'], {})
        saved = {key: len(state['notification'][key]) for key in ('paged', 'digest')}
        self.assertEqual(saved, {'paged': n.MAX_SAVED, 'digest': n.MAX_SAVED})

    def test_failed_transient_pending_survives_clean_scan_without_double_logs(self):
        output = self.root / 'reports'
        output.mkdir()
        c = settings(str(output))
        hosts = {'10.20.29.1': [22]}
        n.atomic_json(output / 'baseline.json', {'fingerprint': c['_fingerprint'], 'hosts': hosts})
        n.atomic_json(output / 'state.json', {'checkpoints': {'auth': 5}, 'snapshot': {'old': True}})
        def failed(lines, delayed=False):
            self.assertEqual(lines, ['New device at 10.20.30.9'])
            self.assertFalse(delayed)
            initial = list(output.glob('*.md'))
            self.assertEqual(len(initial), 1)
            self.assertIn('New device observed at 10.20.30.9', initial[0].read_text())
            self.assertFalse((output / 'alerts.jsonl').exists())
            saved = json.loads((output / 'state.json').read_text())
            self.assertEqual(saved['checkpoints'], {'auth': 5})
            self.assertEqual(saved['notification']['pending'], {'new_device:10.20.30.9': 'New device at 10.20.30.9'})
            self.assertEqual(saved['notification']['paged'], {})
            return {'status': 'failed', 'error_type': 'TransportError'}
        with contextlib.redirect_stdout(io.StringIO()), patch.object(n, 'scan', return_value=(hosts, [])), patch.object(n, 'triage', return_value={'severity': 'info', 'proposal': 'none'}):
            with patch.object(n, 'collect', return_value=({'auth': 100}, [n.finding('new_device', ip='10.20.30.9')])), patch.object(notify, 'send', side_effect=failed):
                self.assertEqual(n.run(c), 1)
            saved = json.loads((output / 'state.json').read_text())
            self.assertEqual(saved['checkpoints'], {'auth': 100})
            self.assertEqual(list(saved['notification']['pending']), ['new_device:10.20.30.9'])
            self.assertEqual(saved['notification']['delivery']['status'], 'failed')
            rows = (output / 'alerts.jsonl').read_text().splitlines()
            self.assertEqual(len(rows), 1)
            self.assertIn(n.finding('coverage', component='notification_delivery'), json.loads(rows[0])['findings'])
            self.assertIn('Phone notification delivery failed', (output / 'latest.md').read_text())
            with patch.object(n, 'collect', return_value=({'auth': 100}, [])), patch.object(notify, 'send', return_value={'status': 'accepted'}) as sender:
                self.assertEqual(n.run(c), 0)
                sender.assert_called_once_with(['New device at 10.20.30.9'], delayed=True)
                self.assertEqual(n.run(c), 0)
                self.assertEqual(sender.call_count, 1)
            saved = json.loads((output / 'state.json').read_text())
            self.assertEqual(saved['notification']['pending'], {})
            self.assertEqual(len((output / 'alerts.jsonl').read_text().splitlines()), 3)
            self.assertNotIn(self.topic, ''.join(p.read_text() for p in output.iterdir()))

    def test_scan_new_port_calls_real_sender_despite_model_none(self):
        output = self.root / 'reports'
        output.mkdir()
        c = settings(str(output))
        n.atomic_json(output / 'baseline.json', {'fingerprint': c['_fingerprint'], 'hosts': {'10.20.29.1': [22], '10.20.30.2': []}})
        def scan_command(args, timeout, input=None):
            if args[1] == '-sn':
                return xml({'10.20.30.2': []} if args[-1] == '10.20.30.0/24' else {'10.20.29.1': [], '10.20.29.2': []}, False)
            return xml({'10.20.29.1': [22, 80], '10.20.29.2': [], '10.20.30.2': []})
        with self.server() as calls, patch.object(n, 'command', side_effect=scan_command), patch.object(n, 'collect', return_value=({}, [])), patch.object(n, 'triage', return_value={'severity': 'info', 'proposal': 'none'}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(n.run(c), 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2].decode().splitlines(), ['New device at 10.20.29.2', 'New open ports on 10.20.29.1: 80', 'Alert only; nothing was changed.'])
        state = json.loads((output / 'state.json').read_text())
        self.assertEqual(state['notification']['delivery'], {'status': 'accepted', 'id': 'AbCdEf123456'})
        self.assertEqual(sorted(state['notification']['paged']), ['new_device:10.20.29.2', 'new_ports:10.20.29.1:80'])
        self.assertEqual(state['snapshot']['fingerprint'], c['_fingerprint'])
        self.assertIn('New open TCP ports at 10.20.29.1: 80', (output / 'latest.md').read_text())

    def test_routine_run_keeps_local_notes_without_phone_delivery(self):
        output = self.root / 'reports'
        output.mkdir()
        c = settings(str(output))
        hosts = {'10.20.29.1': [22]}
        n.atomic_json(output / 'baseline.json', {'fingerprint': c['_fingerprint'], 'hosts': hosts})
        notes = [n.finding('coverage', component=component) for component in ('log_rotated', 'log_history_skipped')]
        notes.append(n.finding('dns_long_label', count=17))
        with patch.object(n, 'scan', return_value=(hosts, [n.finding('coverage', component='host_offline', host='laptop-a', optional=True)])), patch.object(n, 'collect', return_value=({}, notes)), patch.object(n, 'triage', return_value={'severity': 'low', 'proposal': 'review_dns'}), patch.object(notify, 'send', side_effect=AssertionError('routine notes must stay local')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(n.run(c), 1)
        text = (output / 'latest.md').read_text()
        self.assertIn('Long DNS label events: 17', text)
        self.assertIn('A log rotated', text)
        self.assertIn('No phone notification was needed.', text)

    def test_report_failure_before_send_never_delivers_or_advances(self):
        with patch.object(n, 'scan', return_value=({'10.20.29.1': [22]}, [])), patch.object(n, 'collect', return_value=({'auth': 100}, [])), patch.object(n, 'triage', return_value={'status': 'not_needed'}), patch.object(n, 'private_file', side_effect=OSError('disk full')), patch.object(notify, 'send') as sender:
            with self.assertRaises(OSError):
                n.run(settings(str(self.root / 'reports')))
        sender.assert_not_called()
        self.assertFalse((self.root / 'reports' / 'state.json').exists())

    def test_final_report_failure_keeps_pending_and_old_checkpoints(self):
        output = self.root / 'reports'
        output.mkdir()
        c = settings(str(output))
        n.atomic_json(output / 'state.json', {'checkpoints': {'auth': 5}})
        original = os.replace
        def replace(source, target):
            if target == output / 'latest.md':
                raise OSError('disk full')
            return original(source, target)
        with patch.object(n, 'scan', return_value=({'10.20.29.1': [22]}, [])), patch.object(n, 'collect', return_value=({'auth': 100}, [n.finding('auth_failed', count=3)])), patch.object(n, 'triage', return_value={'status': 'not_needed'}), patch.object(n.os, 'replace', side_effect=replace), patch.object(notify, 'send', return_value={'status': 'accepted'}) as sender:
            with self.assertRaises(OSError):
                n.run(c)
        self.assertEqual(sender.call_count, 1)
        saved = json.loads((output / 'state.json').read_text())
        self.assertEqual(saved['checkpoints'], {'auth': 5})
        self.assertEqual(saved['notification']['paged'], {})
        self.assertEqual(saved['notification']['pending'], {'baseline_missing': n.PAGE_NOTES['baseline_missing']})
        self.assertEqual(saved['notification']['digest']['auth_failed']['count'], 3)
        self.assertEqual(len((output / 'alerts.jsonl').read_text().splitlines()), 1)

    def test_cli_notification_modes_do_not_read_config_or_scan(self):
        for flag in ('--test-notification', '--notify-failure'):
            with self.subTest(flag=flag), self.server() as calls, patch.object(n, 'config', side_effect=AssertionError('must not parse scan config')), patch.object(n, 'run', side_effect=AssertionError('must not scan')), contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(n.main([flag]), 0)
                self.assertEqual(n.main([flag, '--config', '/missing/private/config']), 0)
            self.assertEqual(len(calls), 2)
            self.assertEqual(stdout.getvalue(), 'Notification accepted. ID: AbCdEf123456\n' * 2)
        os.environ[notify.TOPIC_ENV] = '/missing/private/topic'
        for flag in ('--test-notification', '--notify-failure'):
            result = subprocess.run([sys.executable, str(Path(n.__file__)), flag], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, 'Notification failed (TopicFileError).\n')
            self.assertEqual(result.stderr, '')
        result = subprocess.run([sys.executable, str(Path(n.__file__))], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--config is required', result.stderr)


if __name__ == '__main__':
    unittest.main()
