# Security and physical-risk warning

> [!CAUTION]
> `xboxlle-probe` is intentionally a powerful low-level debugging service. It is not hardened
> remote-administration software. Misuse can cause data loss or make a console unbootable.

## Threat model

The Xbox agent:

- listens on every Xbox network interface on TCP port 4380;
- has no user authentication;
- has no transport encryption;
- exposes memory and MMIO reads;
- can be explicitly armed for raw reads, dumps, writes, title control, and arbitrary x86
  code execution;
- runs with the privileges available to an Xbox title.

The `ARM I_ACCEPT_THE_RISK` phrase only reduces accidental execution. Anyone who can reach
the port can send it. It is not a password and provides no protection from a malicious or
compromised device on the same network.

## Required precautions

- Use only on a private, trusted, non-internet-routed LAN.
- Do not configure port forwarding, a public tunnel, UPnP exposure, or cloud relay.
- Prefer a dedicated switch or isolated VLAN with only the operator workstation and Xbox.
- Back up irreplaceable console storage before use.
- Stop the agent and return to the dashboard as soon as the measurement session is complete.
- Review all addresses and payload source before running them.
- Do not use raw `EXEC` with code from an untrusted source.
- Do not assume a read is harmless. Hardware registers can have side effects.
- Do not publish raw dumps or unsanitized results.

## Guardrails and their limits

The `R`, `RB`, and `W` handlers enforce address allowlists. `W` refuses flash ranges. All raw
access and title-control commands require session arming. These checks do not protect against:

- a bug in the agent or Xbox kernel;
- side effects from allowed MMIO;
- a malicious or incorrect `EXEC` payload;
- another device reaching port 4380;
- storage writes performed by a launched XBE or uploaded payload;
- hardware differences on untested Xbox revisions.

## Reporting a vulnerability

Open a GitHub security advisory or contact the repository owner privately. Do not include
console keys, credentials, private dumps, or personal hardware identifiers in a report.

## No warranty

This project is licensed under the MIT License and provided **“AS IS”, WITHOUT WARRANTY OF
ANY KIND**. See [LICENSE](LICENSE).
