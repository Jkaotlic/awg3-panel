import base64
import copy
import importlib.util
import http.client
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock, Thread
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "keenetic-tune-bridge.py"
SPEC = importlib.util.spec_from_file_location("bridge", SOURCE)
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)

LAB = "lab0"
NAME = "Isolated test tunnel"
ROUTER_KEY = base64.b64encode(bytes(range(32))).decode()
UPDATE = {"jc": 5, "jmin": 10, "jmax": 60, "i1": "<r 10>", "i2": "", "i3": "", "i4": "", "i5": ""}
INTERFACE = {
    "privateKey": "", "address": "198.51.100.10/32", "mtu": 1280,
    "qlen": 1000, "jc": 2, "jmin": 10, "jmax": 90, "s1": 21, "s2": 22,
    "s3": 23, "s4": 24, "h1": "100", "h2": "200", "h3": "300", "h4": "400",
    "headerProtectionKey": ROUTER_KEY, "randomTrailers": True, "disableCookies": True,
    "contentPaddingAddition": "0-32", "keepaliveTimeout": "5-10", "i2": "<r 22>",
}


class Manager:
    def __init__(self):
        self.tunnel = {
            "id": LAB, "name": NAME, "type": "awg", "backend": "kernel",
            "state": "disabled", "enabled": False, "defaultRoute": False, "ispInterface": "",
            "interfaceName": "opkgtun9", "ndmsName": "OpkgTun9",
            "stateInfo": {"interfaceUp": False, "processRunning": False},
            "interface": copy.deepcopy(INTERFACE),
            "peer": {"endpoint": "example.com:443", "publicKey": "public",
                     "allowedIPs": ["0.0.0.0/0"], "persistentKeepalive": 0},
        }
        self.routes = {}
        self.requests = []
        self.after_write = lambda state: None

    def exchange(self, method, path, body=None, **_kwargs):
        self.requests.append((method, path, body))
        if path == "/api/tunnels/get?id=" + LAB:
            return copy.deepcopy(self.tunnel)
        if path == "/api/tunnels/list":
            return [
                {"id": LAB, "awgVersion": "awg3.1", "name": self.tunnel["name"], "backend": "kernel",
                 "enabled": False, "defaultRoute": False, "interfaceName": "opkgtun9", "ndmsName": "OpkgTun9",
                 "endpoint": self.tunnel["peer"]["endpoint"]},
                {"id": "old7", "ispInterface": self.routes.get("other_tunnel", "")},
            ]
        if path == "/api/tunnels/update?id=" + LAB:
            assert method == "POST"
            self.tunnel["interface"].update({k: v for k, v in body["interface"].items() if v != ""})
            for key in ("i1", "i2", "i3", "i4", "i5"):
                if not body["interface"][key]:
                    self.tunnel["interface"].pop(key, None)
            self.after_write(self.tunnel)
            return copy.deepcopy(self.tunnel)
        return self.routes.get(path, [])

    @property
    def writes(self):
        return [(path, body) for method, path, body in self.requests if method == "POST"]


class ObfuscationBridge(unittest.TestCase):
    def test_post_has_a_single_scoped_path_and_requires_the_rest_credential(self):
        self.assertEqual(bridge.request_route("POST", "/panel/tune/obfuscation?id=lab0", LAB),
                         ("/panel/tune/obfuscation", "id=lab0"))
        self.assertEqual(bridge.credential_file("POST", "/panel/tune/obfuscation?id=lab0"), "rest.token")
        self.assertEqual(bridge.credential_file("POST", "/mcp"), "mcp.token")
        for path in ("/api/tunnels/update?id=lab0", "/panel/tune/obfuscation?id=other",
                     "/panel/tune/obfuscation?id=lab0&id=lab0", "/mcp?"):
            with self.subTest(path=path), self.assertRaises(bridge.ContractError):
                bridge.request_route("POST", path, LAB)

    def test_update_replays_unchanged_interface_without_peer_or_private_key(self):
        manager = Manager()
        payload = bridge.update_obfuscation(manager.exchange, LAB, NAME, UPDATE)
        self.assertEqual(payload, {"success": True, "data": {"id": LAB}})
        self.assertEqual(len(manager.writes), 1)
        path, body = manager.writes[0]
        self.assertEqual(path, "/api/tunnels/update?id=lab0")
        self.assertEqual(set(body), {"interface"})
        self.assertNotIn("privateKey", body["interface"])
        self.assertEqual(body["interface"]["headerProtectionKey"], ROUTER_KEY)
        self.assertTrue(body["interface"]["randomTrailers"])
        self.assertEqual(body["interface"]["i2"], "")
        self.assertNotIn("i2", manager.tunnel["interface"])
        projected = bridge.project_rest("/api/tunnels/get", {"success": True, "data": manager.tunnel}, LAB, b"key")
        self.assertNotIn(ROUTER_KEY, repr(projected))

    def test_disabled_kernel_device_can_remain_present_without_a_process(self):
        manager = Manager()
        manager.tunnel["stateInfo"].update(processRunning=True, processPID=0, backendType="kernel")
        bridge.update_obfuscation(manager.exchange, LAB, NAME, UPDATE)
        self.assertEqual(len(manager.writes), 1)

    def test_rejects_extra_duplicate_null_and_malformed_values_before_writing(self):
        variants = (
            {**UPDATE, "peer": {}}, {**UPDATE, "i2": None}, {**UPDATE, "jc": True},
            {**UPDATE, "i1": "<r -1>"}, {**UPDATE, "i1": "<r 1000><r 1000>"},
            {k:v for k,v in UPDATE.items() if k != "i5"},
        )
        for body in variants:
            manager = Manager()
            with self.subTest(body=body), self.assertRaises(bridge.ContractError):
                bridge.update_obfuscation(manager.exchange, LAB, NAME, body)
            self.assertEqual(manager.writes, [])
        with self.assertRaises(bridge.ContractError):
            bridge.read_json(b'{"i1":"","i1":"<r 4>"}')

    def test_rejects_unsafe_lab_and_incomplete_replay_before_writing(self):
        variants = (
            lambda m: m.tunnel.update(enabled=True),
            lambda m: m.tunnel.update(defaultRoute=True),
            lambda m: m.tunnel.update(name="Wrong name"),
            lambda m: m.tunnel.update(ispInterface="tunnel:another"),
            lambda m: m.tunnel["stateInfo"].update(processRunning=True),
            lambda m: m.tunnel["stateInfo"].update(processRunning=True, processPID=42, backendType="kernel"),
            lambda m: m.tunnel["stateInfo"].update(interfaceUp=True, processRunning=True, processPID=0, backendType="kernel"),
            lambda m: m.tunnel["interface"].pop("qlen"),
            lambda m: m.tunnel["interface"].update(headerProtectionKey="redaction"),
            lambda m: m.tunnel["interface"].update(extra_new_option=123),
            lambda m: m.routes.update({"/api/access-policies?refresh=true": [{"held": ["OpkgTun9"]}]}),
            lambda m: m.routes.update(other_tunnel="tunnel:lab0"),
        )
        for unsafe in variants:
            manager = Manager()
            unsafe(manager)
            with self.subTest(unsafe=unsafe), self.assertRaises(bridge.ContractError):
                bridge.update_obfuscation(manager.exchange, LAB, NAME, UPDATE)
            self.assertEqual(manager.writes, [])

    def test_drift_after_update_is_rejected_and_never_echoed_back(self):
        manager = Manager()
        manager.after_write = lambda state: state["interface"].update(s3=99)
        with self.assertRaises(bridge.ContractError):
            bridge.update_obfuscation(manager.exchange, LAB, NAME, UPDATE)
        self.assertEqual(len(manager.writes), 1)
        self.assertEqual(manager.requests[-1], ("GET", "/api/tunnels/get?id=lab0", None))


    def test_http_rest_scope_and_mutual_exclusion(self):
        manager = Manager()
        rest = "rest-fixture-" + "0" * 24
        mcp = "mcp-fixture-" + "0" * 24
        upstream_rest = "upstream-rest-fixture-" + "0" * 24
        with TemporaryDirectory() as tmp, bridge.ThreadingHTTPServer(("127.0.0.1", 0), bridge.Bridge) as server:
            directory = Path(tmp)
            for name, value in (
                ("rest.token", rest), ("mcp.token", mcp), ("tunnel-id", LAB), ("tunnel-name", NAME),
                ("upstream-rest.token", upstream_rest),
            ):
                path = directory / name
                path.write_text(value)
                path.chmod(0o600)
            server.directory = directory
            server.upstream = "198.51.100.10"
            server.mutation_lock = Lock()
            thread = Thread(target=server.serve_forever)
            thread.start()

            def post(target, token, body=json.dumps(UPDATE)):
                client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                try:
                    client.request("POST", target, body, {
                        "Host": "127.0.0.1:12222", "Content-Type": "application/json",
                        "Authorization": "Bearer " + token,
                    })
                    with client.getresponse() as response:
                        return response.status, response.read()
                finally:
                    client.close()

            target = "/panel/tune/obfuscation?id=lab0"

            def exchange(_host, *args, headers, **kwargs):
                self.assertEqual(headers.get("Authorization"), "Bearer " + upstream_rest)
                return manager.exchange(*args, **kwargs)

            try:
                with mock.patch.object(bridge, "upstream_json", side_effect=exchange):
                    self.assertEqual(post(target, mcp)[0], 401)
                    self.assertEqual(post(target + "&x=1", rest)[0], 403)
                    self.assertEqual(post(target, rest, '{"i1":"","i1":""}')[0], 400)
                    with server.mutation_lock:
                        self.assertEqual(post(target, rest)[0], 409)
                    self.assertEqual(manager.writes, [])
                    status, body = post(target, rest)
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(body), {"success": True, "data": {"id": LAB}})
                    self.assertEqual(len(manager.writes), 1)
                    self.assertEqual(post(target, rest)[0], 200)
                    self.assertEqual(len(manager.writes), 1)
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    unittest.main()
