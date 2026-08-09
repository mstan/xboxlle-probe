"""Hardware-free protocol tests using a loopback mock agent."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import socketserver
import threading
import unittest


MODULE_PATH = Path(__file__).parents[1] / "host" / "xbox_probe.py"
SPEC = importlib.util.spec_from_file_location("xbox_probe", MODULE_PATH)
assert SPEC and SPEC.loader
xbox_probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(xbox_probe)


class MockAgentHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("ascii").rstrip("\r\n")
            self.server.commands.append(line)  # type: ignore[attr-defined]

            if line == "PING":
                self.wfile.write(b"PONG xboxlle-probe test\n")
                return
            if line == "PROBE CONTROLLER_S_HUB":
                self.wfile.write(
                    b'{"probe":"controller_s_hub","agent":"xboxlle-probe test",'
                    b'"available":false,"hardware_inspected":false,'
                    b'"usb_traffic":false,"reason":"agent_usb_stack_not_initialized",'
                    b'"device_descriptor":null,"configuration_descriptor":null,'
                    b'"hub_class_descriptor":null,"hub_status":null,'
                    b'"downstream_port_1_status":null,'
                    b'"downstream_port_1_enumeration":null}\n'
                )
                return
            if line == "ARM I_ACCEPT_THE_RISK":
                if self.server.allow_arm:  # type: ignore[attr-defined]
                    self.wfile.write(b"ARMED\n")
                else:
                    self.wfile.write(b"ERR arming disabled\n")
                    return
            elif line.startswith("EXEC "):
                length = int(line.split()[1])
                payload = self.rfile.read(length)
                self.server.payloads.append(payload)  # type: ignore[attr-defined]
                self.wfile.write(b"RET 2a\n")
                return
            elif line.startswith("W "):
                self.wfile.write(b"OK 2\n")
                return
            elif line.startswith("RB "):
                length = int(line.split()[2])
                body = bytes(range(length))
                self.wfile.write(f"OK {length}\n".encode("ascii") + body)
                return
            else:
                self.wfile.write(b"ERR unknown\n")
                return


class ThreadedMockAgent(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), MockAgentHandler)
        self.commands: list[str] = []
        self.payloads: list[bytes] = []
        self.allow_arm = True


class AgentClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadedMockAgent()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.client = xbox_probe.AgentClient(host, port=port, timeout=2)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_ping(self) -> None:
        self.assertEqual(
            self.client.request("PING"),
            "PONG xboxlle-probe test",
        )
        self.assertEqual(self.server.commands, ["PING"])

    def test_dangerous_request_arms_same_session_before_payload(self) -> None:
        reply = self.client.request(
            "EXEC 3",
            payload=b"\x90\x90\xc3",
            dangerous=True,
        )
        self.assertEqual(reply, "RET 2a")
        self.assertEqual(
            self.server.commands,
            ["ARM I_ACCEPT_THE_RISK", "EXEC 3"],
        )
        self.assertEqual(self.server.payloads, [b"\x90\x90\xc3"])

    def test_arming_refusal_stops_request(self) -> None:
        self.server.allow_arm = False
        with self.assertRaisesRegex(xbox_probe.ProbeError, "refused"):
            self.client.request("W 1000 0000", dangerous=True)
        self.assertEqual(self.server.commands, ["ARM I_ACCEPT_THE_RISK"])

    def test_bulk_read_validates_and_receives_exact_length(self) -> None:
        self.assertEqual(self.client.bulk_read(0x1000, 8), bytes(range(8)))
        self.assertEqual(
            self.server.commands,
            ["ARM I_ACCEPT_THE_RISK", "RB 1000 8"],
        )

    def test_single_line_commands_only(self) -> None:
        with self.assertRaisesRegex(xbox_probe.ProbeError, "single line"):
            self.client.request("PING\nEXEC 1")

    def test_controller_s_hub_probe_is_fixed_and_unarmed(self) -> None:
        reply = self.client.request("PROBE CONTROLLER_S_HUB")
        sentinel = json.loads(reply)
        self.assertEqual(sentinel["probe"], "controller_s_hub")
        self.assertFalse(sentinel["available"])
        self.assertFalse(sentinel["hardware_inspected"])
        self.assertFalse(sentinel["usb_traffic"])
        self.assertEqual(sentinel["reason"], "agent_usb_stack_not_initialized")
        for field in (
            "device_descriptor",
            "configuration_descriptor",
            "hub_class_descriptor",
            "hub_status",
            "downstream_port_1_status",
            "downstream_port_1_enumeration",
        ):
            self.assertIsNone(sentinel[field])
        self.assertEqual(self.server.commands, ["PROBE CONTROLLER_S_HUB"])


class CliSafetyTests(unittest.TestCase):
    def test_host_has_no_builtin_default(self) -> None:
        old = xbox_probe.os.environ.pop("XBOX_PROBE_HOST", None)
        try:
            args = xbox_probe.build_parser().parse_args(["ping"])
        finally:
            if old is not None:
                xbox_probe.os.environ["XBOX_PROBE_HOST"] = old
        self.assertIsNone(args.host)

    def test_write_requires_explicit_risk_acceptance(self) -> None:
        args = xbox_probe.build_parser().parse_args(
            ["--host", "127.0.0.1", "write", "0x1000", "0000"]
        )
        with self.assertRaisesRegex(xbox_probe.ProbeError, "requires"):
            xbox_probe._require_risk(args, "write")

    def test_read_requires_explicit_risk_acceptance(self) -> None:
        args = xbox_probe.build_parser().parse_args(
            ["--host", "127.0.0.1", "read", "0x1000", "4"]
        )
        with self.assertRaisesRegex(xbox_probe.ProbeError, "requires"):
            xbox_probe._require_risk(args, "read")

    def test_parse_integer_accepts_decimal_and_hex(self) -> None:
        self.assertEqual(xbox_probe.parse_integer("32"), 32)
        self.assertEqual(xbox_probe.parse_integer("0x20"), 32)

    def test_controller_s_hub_probe_cli_name_maps_to_fixed_wire_name(self) -> None:
        args = xbox_probe.build_parser().parse_args(
            ["--host", "127.0.0.1", "probe", "controller-s-hub"]
        )
        commands: list[str] = []

        class FixedProbeClient:
            def __init__(self, *unused_args: object, **unused_kwargs: object) -> None:
                pass

            def request(self, command: str) -> str:
                commands.append(command)
                return ('{"probe":"controller_s_hub","available":false,'
                        '"hardware_inspected":false,"usb_traffic":false}')

        original_client = xbox_probe.AgentClient
        xbox_probe.AgentClient = FixedProbeClient
        try:
            xbox_probe.run(args)
        finally:
            xbox_probe.AgentClient = original_client
        self.assertEqual(commands, ["PROBE CONTROLLER_S_HUB"])


if __name__ == "__main__":
    unittest.main()
