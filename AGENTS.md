# Instructions for AI agents

> [!CAUTION]
> This repository controls real hardware. An incorrect action can freeze, corrupt, or brick
> an original Xbox. Treat network commands as physical side effects, not ordinary software
> tests.

## Mandatory operating rules

1. Do not scan a LAN, infer a host address, or search for an Xbox.
2. Before connecting, require a human to:
   - identify the exact target Xbox address;
   - confirm that they own or are authorized to test it;
   - confirm that it is on a trusted, non-internet-exposed network;
   - confirm that irreplaceable storage has been backed up.
3. Prefer source inspection, mock tests, `ping`, `info`, and the fixed `probe cpu` /
   `probe nv2a` commands.
4. Do not deploy an XBE, read arbitrary ranges, create a bulk dump, write memory/MMIO,
   launch an XBE, return to the dashboard, or execute a payload unless the human explicitly
   authorizes that exact operation in the current task.
5. Never add `--i-accept-the-risk` on the human's behalf based on implied consent. The human
   must explicitly request the dangerous operation.
6. Never weaken or bypass the Xbox-side `ARM I_ACCEPT_THE_RISK` gate.
7. Never commit or publish:
   - BIOS, flash, EEPROM, HDD, dashboard, kernel, or game dumps;
   - IP or MAC addresses;
   - FTP/HTTP credentials;
   - HDD serial numbers, console-unique keys, or other per-console identifiers;
   - unsanitized probe logs.
8. Stop after any timeout, malformed reply, unexpected register value, console freeze, or
   loss of video/network. Report what happened and require human inspection or a power cycle.
9. Do not retry a failed hardware operation automatically.
10. Clearly distinguish observed values from interpretations and emulator-derived expectations.

## Repository conventions

- `src/main.c` is the nxdk Xbox agent.
- `host/xbox_probe.py` is the zero-dependency Python client.
- `docs/PROTOCOL.md` is the wire-protocol contract.
- `tests/` must remain hardware-free and use only loopback mock servers.
- `.nxdk-version` pins the nxdk revision used by CI.
- Generated `.xbe`, `.iso`, payload, dump, and result files remain ignored.

When changing protocol behavior, update all four of:

1. `src/main.c`
2. `host/xbox_probe.py`
3. `docs/PROTOCOL.md`
4. mock-server tests

## Safe verification

Without a human-authorized hardware session, verification is limited to:

```sh
python -m unittest discover -s tests -v
python -m py_compile host/xbox_probe.py
```

Building the XBE is safe if it does not deploy or launch it.
