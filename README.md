# xboxlle-probe

> [!CAUTION]
> # DANGER — THIS SOFTWARE CAN CRASH, CORRUPT, OR BRICK AN XBOX
>
> `xboxlle-probe` exposes low-level access to a real original Xbox. It can read hardware
> registers and memory, write RAM and MMIO registers, launch software, and execute uploaded
> machine code. A bad address, incorrect register write, faulty payload, network mistake, or
> software bug can freeze the console, corrupt storage, destroy data, or make the console
> unbootable.
>
> **There is no authentication or encryption. Never run it on an untrusted or
> internet-accessible network.**
>
> **USE ENTIRELY AT YOUR OWN RISK.** This software is provided under the MIT License,
> **“AS IS”, WITHOUT WARRANTY OF ANY KIND**, express or implied. The authors and
> contributors are not responsible for damage, data loss, or other consequences.

A small [nxdk](https://github.com/XboxDev/nxdk) homebrew agent and host-side Python client
for observing a real original Xbox. It originated as the hardware-oracle component of
`xboxlle`: emulator behavior could be compared with measurements from actual silicon instead
of assumptions or another emulator.

The Xbox runs `xboxlle-probe.xbe`, which listens on TCP port 4380. The host client can then:

- identify the running agent and Xbox kernel;
- run named, read-only CPU and NV2A probes with JSON output;
- read guarded RAM, NV2A/MCPX MMIO, and selected flash ranges;
- bulk-read a permitted range to a host file;
- in explicitly armed unsafe mode, write RAM/MMIO or execute an uploaded x86 payload;
- launch another XBE or return to the dashboard.

The named probes are the intended interface for humans and AI agents. Raw memory operations
exist for hardware research, but they are sharp tools.

## Safety model

This project reduces accidental misuse; it does not make low-level hardware access safe.

- The Xbox displays a warning and waits before opening its listener.
- Every raw read, dump, write, execution, and title-control request is refused until that TCP
  session sends the exact arming phrase.
- The host client requires `--i-accept-the-risk` before dangerous operations.
- Direct reads and writes are range-checked. Flash writes are never accepted by `WRITE`.
- Named probes use a small set of fixed registers that were tested on one Xbox v1.1.

Those measures are guardrails, not a security boundary. `EXEC` deliberately runs arbitrary
x86 machine code, which can bypass every range check and access storage or flash. Read-only
MMIO is not universally harmless: some hardware registers have read side effects, and an
incorrect address can still hang the machine.

Read [SECURITY.md](SECURITY.md) before running the agent.

## Requirements

- An original Xbox already capable of running unsigned homebrew.
- A private, trusted LAN shared by the Xbox and host computer.
- [nxdk](https://github.com/XboxDev/nxdk) and its prerequisites to build the XBE.
- Python 3.9 or newer on the host.
- A dashboard or other established method for transferring and launching an XBE.

This project does not bypass Xbox security, install a softmod, or provide Microsoft firmware,
keys, EEPROM contents, BIOS images, dashboards, or other copyrighted/per-console material.

## Build

Clone nxdk recursively, activate its environment, and point this Makefile at it:

```sh
git clone --recursive https://github.com/XboxDev/nxdk.git
git clone https://github.com/mstan/xboxlle-probe.git

export NXDK_DIR="$PWD/nxdk"
eval "$("$NXDK_DIR/bin/activate" -s)"
make -C xboxlle-probe -j
```

The XBE is generated as:

```text
xboxlle-probe/bin/default.xbe
```

The repository CI pins the nxdk revision recorded in `.nxdk-version`. Pinning is recommended
when measurements must be reproducible.

## Install and launch

Copy `bin/default.xbe` to your Xbox using your existing homebrew workflow. For example, place
it in:

```text
E:\Apps\xboxlle-probe\default.xbe
```

Launch it from your dashboard. The screen will show the danger warning, wait eight seconds,
initialize networking, and display its IP address and listening port.

An optional FTP deployment command is available, but it writes to Xbox storage and therefore
requires explicit risk acceptance:

```sh
python host/xbox_probe.py \
  --host 192.168.1.50 \
  --i-accept-the-risk \
  deploy bin/default.xbe \
  --ftp-user xbox
```

The password is requested interactively unless `--ftp-password` or
`XBOX_PROBE_FTP_PASSWORD` is supplied. Do not put passwords in scripts, shell history, Git,
issues, or probe results.

## Use

Set the address explicitly. The client intentionally has no built-in Xbox IP:

```sh
export XBOX_PROBE_HOST=192.168.1.50
```

Check connectivity and metadata:

```sh
python host/xbox_probe.py ping
python host/xbox_probe.py info
```

Run the fixed read-only probes:

```sh
python host/xbox_probe.py probe cpu
python host/xbox_probe.py probe nv2a
```

Example CPU result:

```json
{"probe":"cpu","agent":"xboxlle-probe v0.3.0","vendor":"GenuineIntel","max_leaf":2,"signature":"0x0000068a","features_edx":"0x0383f9ff","features_ecx":"0x00000000"}
```

Guarded raw read (still dangerous—v0.1 froze real hardware on a bad read):

```sh
python host/xbox_probe.py --i-accept-the-risk read 0xfd000000 4
```

Bulk-read a permitted range to a local file:

```sh
python host/xbox_probe.py \
  --i-accept-the-risk \
  bulk-read 0xff000000 262144 \
  --output flash.bin
```

> [!WARNING]
> A dump can contain copyrighted code, secrets, unique identifiers, or personal data.
> The client cannot determine whether you are legally entitled to copy or redistribute it.
> Never commit raw dumps.

All raw or state-changing commands require both the host flag and session arming:

```sh
python host/xbox_probe.py --i-accept-the-risk write 0x00011000 90909090
python host/xbox_probe.py --i-accept-the-risk exec payload.bin
```

For raw reads, dumps, writes, execution, and title control, the host client opens a new TCP
session, sends
`ARM I_ACCEPT_THE_RISK`, verifies the `ARMED` response, and only then sends the dangerous
request. The phrase is an accident guard, **not authentication**.

## AI-assisted use

AI agents should read [AGENTS.md](AGENTS.md) before interacting with hardware. The central
rules are:

1. Never discover or guess an Xbox IP by scanning a network.
2. Require the human to identify the target console and confirm it is safe to probe.
3. Prefer `ping`, `info`, and fixed named probes.
4. Do not deploy, write, launch, dump, or execute code without explicit human authorization
   for that exact action.
5. Treat all hardware results as potentially private until reviewed and sanitized.

Protocol details suitable for writing other clients are in [docs/PROTOCOL.md](docs/PROTOCOL.md).
A sanitized account of the original hardware session is in
[docs/ORIGIN.md](docs/ORIGIN.md).

## Development

Host-side tests require no Xbox:

```sh
python -m unittest discover -s tests -v
```

The test suite uses a local mock TCP agent to verify framing, bulk transfers, and unsafe
session arming.

## License

MIT. See [LICENSE](LICENSE).

The software is provided **AS IS, WITHOUT WARRANTY OF ANY KIND**. Use at your own risk.
