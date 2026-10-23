#!/usr/bin/env python3
"""Prove real nmap -> baseline diff -> local Ollama -> durable alert -> cleanup."""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='config.json')
    parser.add_argument('--port', type=int, default=47653)
    parser.add_argument('--notify-plant', action='store_true', help='send a real phone alert for the planted-port scan only')
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('choose an unprivileged TCP port')
    source = Path(__file__).resolve().parent
    cfg = json.loads(Path(args.config).read_text())
    addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr']))
    lan = ipaddress.ip_network(cfg['lan_cidr'])
    ips = [a['local'] for interface in addresses for a in interface['addr_info']
           if ipaddress.ip_address(a['local']) in lan]
    if len(ips) != 1:
        raise RuntimeError('verification requires exactly one local address in the configured LAN')
    ip = ips[0]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    outdir = Path(cfg['output_dir']) / ('verification-' + stamp)
    outdir.mkdir(mode=0o700)
    cfg.update(ports=str(args.port), output_dir=str(outdir))
    config_path = outdir / 'config.json'
    config_path.write_text(json.dumps(cfg, indent=2) + '\n')
    config_path.chmod(0o600)
    command = [sys.executable, str(source / 'netguard.py'), '--config', str(config_path)]

    def run(*extra, notify=False):
        env = os.environ.copy()
        if not notify:
            env.pop('NETGUARD_NTFY_TOPIC_FILE', None)
        result = subprocess.run([*command, *extra], capture_output=True, text=True, timeout=1500, env=env)
        print(result.stdout, end='', flush=True)
        if result.returncode not in (0, 1):
            raise RuntimeError('scanner failed; see coverage report')
        return json.loads((outdir / 'alerts.jsonl').read_text().splitlines()[-1])

    with socket.socket() as probe:
        if probe.connect_ex((ip, args.port)) == 0:
            raise RuntimeError('test port is already open')
    run()
    run('--approve-baseline')
    baseline_before = (outdir / 'baseline.json').read_bytes()
    listener = socket.socket()
    try:
        listener.bind((ip, args.port))
        listener.listen(4)
        planted = run(notify=args.notify_plant)
        assert any(f['category'] == 'new_ports' and f.get('ip') == ip and args.port in f['ports']
                   for f in planted['findings']), 'real planted port was not detected'
        assert planted['triage'].get('severity') in ('info', 'low', 'medium', 'high', 'critical'), 'local model triage is unavailable'
        if args.notify_plant:
            assert planted.get('notification', {}).get('status') == 'accepted', 'planted-port notification was not accepted'
        planted_report = sorted(outdir.glob('[0-9]*.md'))[-1]
    finally:
        listener.close()
    after = run()
    assert not any(f['category'] == 'new_ports' and f.get('ip') == ip and args.port in f['ports']
                   for f in after['findings']), 'closed test port is still reported'
    assert baseline_before == (outdir / 'baseline.json').read_bytes(), 'baseline was silently changed'
    with socket.socket() as probe:
        assert probe.connect_ex((ip, args.port)) != 0, 'test listener remains open'
    evidence = {'ip': ip, 'port': args.port, 'detected': True, 'model_triage': planted['triage'],
                'closed': True, 'baseline_unchanged': True, 'planted_report': str(planted_report),
                'closed_report': str(sorted(outdir.glob('[0-9]*.md'))[-1]), 'output_dir': str(outdir)}
    if args.notify_plant:
        evidence['notification'] = planted['notification']
    proof = outdir / 'proof.json'
    proof.write_text(json.dumps(evidence, indent=2) + '\n')
    proof.chmod(0o600)
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()
