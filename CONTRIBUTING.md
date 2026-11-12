# Contributing to NixFence Community

Thank you for supporting this Byte2craft open-source project. Use English for code comments, issues, documentation and pull requests.

1. Open an issue describing the engineering problem and intended safety behavior.
2. For every SSH or host-operation change, provide tests for the *unsafe* and failure paths, not only success cases.
3. Keep all target user input schema-validated. Do not add generic remote shell endpoints.
4. Run `python -m pip install -e '.[dev]'`, `ruff check src tests` and `pytest -q`.
5. Verify host changes in a disposable VM with console access. Clearly distinguish local mocking from real-host evidence.
6. Submit a reviewable PR with a threat/safety impact summary.

No actual host credentials, proprietary enterprise components, commercial marketing briefs, customer inventories or copied CIS benchmark content may be committed. Community contributions are made under Apache-2.0; no CLA is currently required.
