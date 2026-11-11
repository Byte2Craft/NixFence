# Contributing to NixFence

Thanks for supporting **NixFence by Byte2craft**. We want a practical security tool that engineers can understand and improve.

## Starting a contribution

Please use **English** for issues, pull requests, code comments and documentation.

1. Open an Issue outlining the problem and intended behavior.
2. For policy engine changes, include test cases for malformed inputs and risky firewall situations.
3. Keep security-sensitive code small and reviewable. No generic remote shell APIs.
4. Install `pip install -e '.[dev]'`, then run `pytest -q` and `ruff check src tests`.
5. Submit a PR with a concise explanation, test evidence and security implications.

Do not submit benchmark content copied from CIS or another third party without confirmed redistribution rights. Do not include customer infrastructure data, SSH keys or screenshots containing secrets.

By contributing, you agree that your submission is your own or you have the right to license it under Apache-2.0. We currently do not require a CLA. If a dual-license strategy is pursued later, the contribution policy will be explicitly reviewed and communicated first; no retroactive relicense rights are assumed.

Community decisions should be transparent. We welcome changes that add CLI, import/export, safe policy modeling, tests, accessibility and distro adapters.
