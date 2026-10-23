# Contributing

Issues and pull requests are welcome.

1. Keep changes small and focused. The scanner uses only the Python standard library; avoid new dependencies.
2. Run `python3 -m unittest discover -s tests -v` before opening a pull request. Add or update a test for any behavior you change.
3. Never include real network addresses, host names, logs, baselines, or notification topics in issues, tests, or commits. Use documentation values such as `192.168.1.0/24` or `10.0.0.0/24`.
4. The tool is alert-only by design. Changes that edit firewalls, run model output, or remediate automatically will not be accepted.
