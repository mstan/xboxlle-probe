# Contributing

Safety documentation is part of the product. Changes that add hardware access must explain
the affected address space, expected side effects, tested Xbox revisions, failure behavior,
and how results are sanitized.

Before opening a pull request:

```sh
python -m unittest discover -s tests -v
python -m py_compile host/xbox_probe.py
```

If the agent or protocol changes, also build the XBE and update `docs/PROTOCOL.md`.

Do not attach raw console dumps, credentials, unique identifiers, copyrighted firmware, or
unreviewed payload binaries to issues or pull requests. Hardware validation reports should
include only the minimum sanitized facts needed to reproduce the observation.

Reports from emulators are useful comparisons but must not be represented as real-hardware
observations.
