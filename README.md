# homelab-netguard

A local, alert-only network scanner for a home lab. It uses the Python
standard library, nmap, SSH, an optional local Ollama model, and a systemd
timer. There is no dashboard, cloud inference, agent framework, firewall
editing, automatic remediation, or raw log storage.

Each run discovers devices on your LAN, checks an explicit list of TCP ports,
reads recent DNS (AdGuard Home) and Linux auth logs, compares everything with
an approved baseline, and writes a plain-English report. A local model gives
advisory triage only and can never run anything.

## Quick start

1. Install Python 3.11+ and nmap.
2. Copy `config.example.json` to `config.json` and edit it. Every host you list
   must be an exact IPv4 address.

   ```sh
   python3 netguard.py --help
   ```
3. Run a scan, review the report, then approve it as the baseline. Approval
   fails if discovery or port scanning was incomplete.

   ```sh
   python3 netguard.py --config config.json
   python3 netguard.py --config config.json --approve-baseline
   ```
4. Run unit tests with `python3 -m unittest discover -s tests -v`.

## Configuration

| Key | Meaning |
|---|---|
| `lan_cidr` | Private IPv4 network to discover, between `/16` and `/30`. |
| `hosts` | Name to exact IPv4 address of the machines you want monitored by name. Names use letters, digits, `.`, `_`, `-`. |
| `local_host` | Optional. The `hosts` entry that is this machine. Its auth log is read locally instead of over SSH. |
| `dns_hosts` | `hosts` entries whose AdGuard Home query log is read over SSH. |
| `optional_hosts` | `hosts` entries that may be offline without triggering a phone alert (still shown in the report). |
| `ports` | TCP ports to check, such as `1-1024,8080,9000-9100`. Defaults to `1-65535`. |
| `output_dir` | Absolute directory for reports and state. Default `/var/lib/netguard`. |
| `model` | Ollama model for triage. Default `dolphin3:8b`. |
| `dns_paths`, `auth_paths` | Absolute log paths on the DNS hosts and `local_host`. |
| `suspicious_domains` | Optional exact domains or suffixes to flag. Empty means heuristics only. |

Remote log reads use your existing SSH configuration with
`StrictHostKeyChecking=yes`, so the scanning account needs working keys and
known-host entries. The remote account needs read-only `sudo -n python3` access
to the log files. No agent is installed on any monitored host.

## Local model

Triage uses a local Ollama model. `systemd/ollama.service` binds only
`127.0.0.1:11434`, disables Ollama cloud features, and runs under a dedicated
`netguard-ollama` account. Model download needs internet during setup;
scanning and inference stay local afterward. The model sees only sanitized
categories, IP addresses, port numbers, and counts. Its advice uses a fixed
vocabulary and is never executed. Findings stay in the report if triage fails.
See the [Ollama Linux guide](https://docs.ollama.com/linux).

## Reports and baseline

Reports, JSONL history, the baseline, and log cursors live under `output_dir`
(mode 0700, files 0600). Open `latest.md` for the current result. Reports also
go to stdout and the systemd journal. DNS labels and usernames are discarded;
no tokens, raw log lines, AdGuard configuration, or SSH keys are recorded.

The baseline is an explicit snapshot and is never promoted automatically. Review
the first scan before approving it. A baseline records observed exposure; it is
not a security audit or certification. Later new devices or ports stay findings
until you approve a new baseline.

## Install as a service

1. Create a `netguard` user with SSH access to your DNS hosts.
2. Copy `netguard.py`, `notifications.py`, and `config.json` to `/opt/netguard/`
   as root-owned files, and create `/var/lib/netguard` owned by `netguard`.
3. Install the units in `systemd/` into `/etc/systemd/system/`. If you do not
   use ntfy, delete the `Environment=NETGUARD_NTFY_TOPIC_FILE=...` line from
   `netguard.service` and `netguard-notify-failure.service`; otherwise every
   run reports a failed notification. Then run `sudo systemctl daemon-reload`
   and `sudo systemctl enable --now netguard.timer`.
4. Run `sudo -u netguard python3 /opt/netguard/netguard.py --config /opt/netguard/config.json`
   once, review it, and approve it with `--approve-baseline`.
5. Read `/var/lib/netguard/latest.md` or `journalctl -u netguard.service`.

The timer runs five minutes after boot, then 30 minutes after each completed
run. Runs cannot overlap. The service has no capabilities, read-only system
access, and write access only to the report directory. Stop it with
`sudo systemctl disable --now netguard.timer`.

## Phone notifications

Optional alerts go through [ntfy](https://docs.ntfy.sh/publish/). Scanning, log
analysis, and model inference stay local. There are two kinds of message:

- **Page** (high priority): a new device, new open TCP ports, or a baseline
  problem. The message names the item, for example `New device at 192.168.1.9` or
  `New open ports on 192.168.1.9: 22, 80`. Each distinct item pages once, so a
  DHCP device that sleeps and wakes does not page again. It can page again after
  14 days. Review it, then run `--approve-baseline` once the item is known.
- **Morning digest** (default priority): one message after 08:00 local time that
  lists everything else seen since the last digest, with `(xN)` counts: DNS
  patterns, failed sign-ins, monitoring gaps, and items that already paged and
  are still unreviewed. A day with nothing new still sends "Nothing new", so
  silence means the scanner is down, not that all is well.

Only private IP addresses, port numbers, host names, and fixed text go to ntfy.
Domains, usernames, raw logs, and model output stay local.

The ntfy topic acts like a password. Put it in a file outside Git (for example
`/etc/netguard/ntfy-topic`, mode 0640, readable by the service user) and point
`NETGUARD_NTFY_TOPIC_FILE` at it. Leave that variable unset to disable
notifications. Test delivery without scanning:

```sh
NETGUARD_NTFY_TOPIC_FILE=/etc/netguard/ntfy-topic python3 netguard.py --test-notification
```

Log rotation, skipped initial history, DNS label heuristics, the model's
severity, and offline `optional_hosts` never page; they stay in the report.
A failed delivery is retried on the next scan from bounded saved state, even if
the original event has cleared. Delivery is at least once, so a crash after
server acceptance can send a duplicate. A separate failure unit sends a generic
warning if the scanner fails or times out. It cannot notify if the host, its
internet connection, or ntfy is down.

## Limitations

- Only the configured TCP ports are checked. UDP and IPv6 are not probed.
  Scanning `1-65535` can exceed the 20-minute nmap limit on filtered devices.
- Offline hosts and timeouts reduce coverage; an unreachable host is not proof
  its ports are closed. Unprivileged discovery can miss devices that ignore its
  probes.
- DNS checks are heuristics for long or random-looking labels plus your own
  domain list. There is no reputation feed. Expect false positives from
  telemetry and CDNs.
- Auth checks cover Linux logs only, not Windows Event Logs or macOS events.
- Logs are read in bounded 1 MiB chunks, up to 32 MiB per source within a
  60-second budget. Reports mark coverage partial when a limit is hit, and the
  next run resumes from the saved cursor. Rotation, missing sources, and parse
  failures also show up as coverage gaps.
- It complements, and does not replace, firewalls, endpoint protection, and
  patching.

## Live verification

`python3 verify_live.py` briefly listens on TCP 47653 on this machine's LAN
address, scans only that port through the real discovery, diff, log, model, and
report code, and closes the socket even on failure. It writes a new directory
under `output_dir` and disables phone delivery unless you set
`NETGUARD_NTFY_TOPIC_FILE` and pass `--notify-plant`.

Do not commit baselines, raw logs, or model files.

## License

MIT. See [LICENSE](LICENSE).
