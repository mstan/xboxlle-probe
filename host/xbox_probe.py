#!/usr/bin/env python3
"""Host client for xboxlle-probe running on a real original Xbox.

DANGER: The remote agent can expose low-level memory and hardware access. Some commands can
crash, corrupt, or brick the console. Use only on hardware you are authorized to test, on an
isolated trusted network, after reading README.md and SECURITY.md. No warranty.
"""

from __future__ import annotations

import argparse
import ftplib
import getpass
import json
import os
from pathlib import Path
import socket
import sys
from typing import Optional


DEFAULT_PORT = 4380
MAX_READ = 4096
MAX_BULK = 1 << 20
RISK_ACK = "I_ACCEPT_THE_RISK"


class ProbeError(RuntimeError):
    """A protocol, transport, or safety failure."""


def parse_integer(value: str) -> int:
    """Parse a decimal or 0x-prefixed integer for argparse."""
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc


def _send_line(connection: socket.socket, line: str) -> None:
    if "\r" in line or "\n" in line:
        raise ProbeError("protocol command must be a single line")
    connection.sendall((line + "\n").encode("ascii"))


def _recv_line(connection: socket.socket, max_bytes: int = 16 * 1024) -> str:
    data = bytearray()
    while len(data) < max_bytes:
        chunk = connection.recv(1)
        if not chunk:
            raise ProbeError("connection closed before a complete reply")
        if chunk == b"\n":
            return data.rstrip(b"\r").decode("utf-8", errors="strict")
        data.extend(chunk)
    raise ProbeError(f"reply line exceeded {max_bytes} bytes")


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise ProbeError(
                f"connection closed after {len(data)} of {length} expected bytes"
            )
        data.extend(chunk)
    return bytes(data)


class AgentClient:
    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        timeout: float = 8.0,
    ) -> None:
        if not host:
            raise ValueError("host is required")
        self.host = host
        self.port = port
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        return socket.create_connection((self.host, self.port), timeout=self.timeout)

    @staticmethod
    def _arm(connection: socket.socket) -> None:
        _send_line(connection, f"ARM {RISK_ACK}")
        reply = _recv_line(connection)
        if reply != "ARMED":
            raise ProbeError(f"agent refused unsafe-session arming: {reply}")

    def request(
        self,
        command: str,
        *,
        payload: Optional[bytes] = None,
        dangerous: bool = False,
    ) -> str:
        with self._connect() as connection:
            connection.settimeout(self.timeout)
            if dangerous:
                self._arm(connection)
            _send_line(connection, command)
            if payload is not None:
                connection.sendall(payload)
            return _recv_line(connection)

    def bulk_read(self, address: int, length: int) -> bytes:
        if length <= 0 or length > MAX_BULK:
            raise ValueError(f"bulk length must be 1..{MAX_BULK}")
        with self._connect() as connection:
            connection.settimeout(self.timeout)
            self._arm(connection)
            _send_line(connection, f"RB {address:x} {length}")
            header = _recv_line(connection)
            if not header.startswith("OK "):
                raise ProbeError(header)
            try:
                announced = int(header[3:], 10)
            except ValueError as exc:
                raise ProbeError(f"malformed bulk header: {header}") from exc
            if announced != length:
                raise ProbeError(
                    f"agent announced {announced} bytes; requested {length}"
                )
            return _recv_exact(connection, length)


def _expect_prefix(reply: str, prefix: str) -> str:
    if not reply.startswith(prefix):
        raise ProbeError(reply)
    return reply[len(prefix) :]


def _require_risk(args: argparse.Namespace, action: str) -> None:
    if not args.i_accept_the_risk:
        raise ProbeError(
            f"{action} is dangerous and requires --i-accept-the-risk before the command"
        )


def _print_json_reply(reply: str) -> None:
    if reply.startswith("ERR"):
        raise ProbeError(reply)
    try:
        parsed = json.loads(reply)
    except json.JSONDecodeError as exc:
        raise ProbeError(f"agent returned malformed JSON: {reply}") from exc
    print(json.dumps(parsed, sort_keys=True, separators=(",", ":")))


def _ftp_password(args: argparse.Namespace) -> str:
    password = args.ftp_password or os.environ.get("XBOX_PROBE_FTP_PASSWORD")
    if password:
        return password
    return getpass.getpass("Xbox FTP password: ")


def deploy(
    host: str,
    xbe_path: Path,
    *,
    remote_dir: str,
    ftp_user: str,
    ftp_password: str,
    timeout: float,
) -> None:
    if not xbe_path.is_file():
        raise ProbeError(f"XBE not found: {xbe_path}")

    with ftplib.FTP() as ftp:
        ftp.connect(host, 21, timeout=timeout)
        ftp.login(ftp_user, ftp_password)
        ftp.cwd("/")
        for component in remote_dir.strip("/").split("/"):
            if not component:
                continue
            try:
                ftp.cwd(component)
            except ftplib.error_perm:
                ftp.mkd(component)
                ftp.cwd(component)
        with xbe_path.open("rb") as source:
            ftp.storbinary("STOR default.xbe", source)

    print(f"uploaded {xbe_path} -> /{remote_dir.strip('/')}/default.xbe")
    print("Launch default.xbe from your dashboard; automatic remote launch is not attempted.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Control xboxlle-probe on an authorized original Xbox.",
        epilog=(
            "DANGER: low-level operations can crash, corrupt, or brick the console. "
            "USE AT YOUR OWN RISK. NO WARRANTY."
        ),
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("XBOX_PROBE_HOST"),
        help="Xbox IP/hostname (or XBOX_PROBE_HOST); there is intentionally no default",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument(
        "--i-accept-the-risk",
        action="store_true",
        help="required for raw reads/dumps, writes, execution, launch, or deploy",
    )

    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ping", help="check agent liveness")
    commands.add_parser("info", help="read agent/kernel metadata as JSON")
    commands.add_parser("status", help="show SAFE/ARMED session state")

    probe = commands.add_parser("probe", help="run a fixed read-only probe")
    probe.add_argument("name", choices=("cpu", "nv2a"))

    read = commands.add_parser("read", help="DANGEROUS: guarded raw memory/MMIO read")
    read.add_argument("address", type=parse_integer)
    read.add_argument("length", type=int)

    bulk = commands.add_parser("bulk-read", help="DANGEROUS: raw read to a host file")
    bulk.add_argument("address", type=parse_integer)
    bulk.add_argument("length", type=int)
    bulk.add_argument("--output", type=Path, required=True)

    write = commands.add_parser("write", help="DANGEROUS: write RAM/MMIO bytes")
    write.add_argument("address", type=parse_integer)
    write.add_argument("hexbytes")

    execute = commands.add_parser("exec", help="DANGEROUS: execute raw x86 payload")
    execute.add_argument("payload", type=Path)

    launch = commands.add_parser("launch", help="DANGEROUS: launch an Xbox XBE path")
    launch.add_argument("path")

    commands.add_parser("dash", help="return to C:\\evoxdash.xbe")

    upload = commands.add_parser("deploy", help="DANGEROUS: upload XBE over FTP")
    upload.add_argument("xbe", type=Path)
    upload.add_argument("--remote-dir", default="/E/Apps/xboxlle-probe")
    upload.add_argument("--ftp-user", default=os.environ.get("XBOX_PROBE_FTP_USER"))
    upload.add_argument("--ftp-password", help=argparse.SUPPRESS)

    return parser


def run(args: argparse.Namespace) -> None:
    if not args.host:
        raise ProbeError(
            "Xbox host is required; pass --host or set XBOX_PROBE_HOST. "
            "The client will not scan or guess."
        )

    if args.command == "deploy":
        _require_risk(args, "deploy")
        if not args.ftp_user:
            raise ProbeError(
                "FTP username is required; pass --ftp-user or set XBOX_PROBE_FTP_USER"
            )
        deploy(
            args.host,
            args.xbe,
            remote_dir=args.remote_dir,
            ftp_user=args.ftp_user,
            ftp_password=_ftp_password(args),
            timeout=args.timeout,
        )
        return

    client = AgentClient(args.host, port=args.port, timeout=args.timeout)

    if args.command == "ping":
        print(client.request("PING"))
    elif args.command == "info":
        _print_json_reply(client.request("INFO"))
    elif args.command == "status":
        print(client.request("STATUS"))
    elif args.command == "probe":
        _print_json_reply(client.request(f"PROBE {args.name.upper()}"))
    elif args.command == "read":
        _require_risk(args, "read")
        if args.length <= 0 or args.length > MAX_READ:
            raise ProbeError(f"read length must be 1..{MAX_READ}")
        reply = client.request(
            f"R {args.address:x} {args.length}",
            dangerous=True,
        )
        print(_expect_prefix(reply, "OK "))
    elif args.command == "bulk-read":
        _require_risk(args, "bulk-read")
        data = client.bulk_read(args.address, args.length)
        args.output.write_bytes(data)
        print(f"wrote {len(data)} bytes to {args.output}")
    elif args.command == "write":
        _require_risk(args, "write")
        try:
            data = bytes.fromhex(args.hexbytes)
        except ValueError as exc:
            raise ProbeError("hexbytes must contain complete hexadecimal bytes") from exc
        if not data or len(data) > MAX_READ:
            raise ProbeError(f"write length must be 1..{MAX_READ} bytes")
        compact_hex = data.hex()
        print(
            client.request(
                f"W {args.address:x} {compact_hex}",
                dangerous=True,
            )
        )
    elif args.command == "exec":
        _require_risk(args, "exec")
        payload = args.payload.read_bytes()
        if not payload or len(payload) > MAX_BULK:
            raise ProbeError(f"payload length must be 1..{MAX_BULK} bytes")
        print(
            client.request(
                f"EXEC {len(payload)}",
                payload=payload,
                dangerous=True,
            )
        )
    elif args.command == "launch":
        _require_risk(args, "launch")
        print(client.request(f"L {args.path}", dangerous=True))
    elif args.command == "dash":
        _require_risk(args, "dash")
        print(client.request("DASH", dangerous=True))
    else:
        raise ProbeError(f"unsupported command: {args.command}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        run(args)
    except (OSError, ProbeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
