#!/usr/bin/env python3
"""Expose only the authorized test tunnel through a private loopback bridge."""

import base64
from contextlib import contextmanager, nullcontext
import hmac
import http.client
import ipaddress
import json
import re
import select
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock

PROTOCOL = "2025-06-18"
TUNNEL_DETAIL = "/api/tunnels/get"
TUNNEL_LIST = "/api/tunnels/list"
TUNNEL_UPDATE = "/api/tunnels/update"
OBFUSCATION = "/panel/tune/obfuscation"
ACCESS_POLICIES = "/api/access-policies"
DNS_ROUTES = "/api/dns-routes/list"
SIMPLE_ROUTES = ("/api/static-routes/list", "/api/client-routes")
READ_PATHS = {TUNNEL_DETAIL, TUNNEL_LIST, ACCESS_POLICIES, DNS_ROUTES, *SIMPLE_ROUTES}
TUNNEL_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
TOKEN = re.compile(r"[A-Za-z0-9_.~-]{24,128}")
SESSION_ID = re.compile(r"[!-~]{1,256}")
BODY_LIMIT = 8192
REST_LIMIT = 8 << 20
MCP_LIMIT = 256 << 10

DETAIL_FIELDS = """
id name backend state enabled defaultRoute ispInterface interfaceName ndmsName
""".split()
TUNNEL_FIELDS = """
id name backend awgVersion status enabled defaultRoute endpoint ispInterface
resolvedIspInterface interfaceName ndmsName hasAddressConflict startedAt lastHandshake rxBytes txBytes
""".split()

ROUTE_FIELDS = ("tunnelId", "interface", "fallback")
JITTER_FIELDS = ("jc", "jmin", "jmax")
CPS_FIELDS = ("i1", "i2", "i3", "i4", "i5")
OBFUSCATION_FIELDS = (*JITTER_FIELDS, *CPS_FIELDS)
CPS_TAG = re.compile(r"<b 0x((?:[0-9a-fA-F]{2})+)>|<r[cd]? ([1-9][0-9]{0,3})>|<t>")
CPS_TEXT_LIMIT = 3500
IP_UDP_OVERHEAD = 48

# AWG Manager v2.20.6 internal/storage/types.go. The update API replaces the
# whole interface when Address is present, so only replay a known complete
# pre-update response. Missing optional fields have their Go JSON zero value.
REQUIRED_INTERFACE = {
    "privateKey": str, "address": str, "mtu": int, "qlen": int,
    "jc": int, "jmin": int, "jmax": int,
    **dict.fromkeys(("s1", "s2", "s3", "s4"), int),
    **dict.fromkeys(("h1", "h2", "h3", "h4"), str),
}
OPTIONAL_INTERFACE = {
    **dict.fromkeys((*CPS_FIELDS, "dns", "headerProtectionKey", "contentPaddingAddition",
                    "rekeyAfterTime", "rekeyTimeout", "rejectAfterTime",
                    "keepaliveTimeout", "maxHandshakeAttempts"), str),
    "randomTrailers": bool, "disableCookies": bool,
}
INTERFACE_SCHEMA = REQUIRED_INTERFACE | OPTIONAL_INTERFACE
INTERFACE_FIELDS = tuple(field for field in INTERFACE_SCHEMA if field != "privateKey")
STABLE_TUNNEL_FIELDS = (*DETAIL_FIELDS, "type", "peer", "ispInterfaceLabel",
                        "obfuscator", "pingCheck", "connectivityCheck")


class ContractError(ValueError):
    pass


class BridgeBusy(RuntimeError):
    pass


@contextmanager
def mutation(lock):
    # An HTTP request whose client timed out must never wait in a write queue.
    if not lock.acquire(blocking=False):
        raise BridgeBusy()
    try:
        yield
    finally:
        lock.release()


def require(condition):
    if not condition:
        raise ContractError()


def exact(value, *fields):
    return isinstance(value, dict) and set(value) == set(fields)


def credential_file(method, target):
    if method == "POST" and target.partition("?")[0] != OBFUSCATION:
        return "mcp.token"
    return "rest.token"


def request_route(method, target, lab):
    endpoint, has_query, query = target.partition("?")
    if method == "POST" and target == "/mcp":
        return endpoint, query
    if method == "POST" and endpoint == OBFUSCATION:
        require(has_query and query == "id=" + lab)
        return endpoint, query
    require(method == "GET" and endpoint in READ_PATHS)
    if endpoint == TUNNEL_DETAIL:
        require(has_query and query == "id=" + lab)
    elif endpoint == ACCESS_POLICIES:
        require(has_query and query == "refresh=true")
    else:
        require(not has_query)
    return endpoint, query


def valid_jitter(value):
    if not exact(value, "jc", "jmin", "jmax") or any(type(item) is not int for item in value.values()):
        return False
    jc, minimum, maximum = (value[field] for field in ("jc", "jmin", "jmax"))
    return (jc == minimum == maximum == 0 or
            1 <= jc <= 122 and 1 <= minimum < maximum <= 1280)


def validate_mcp(document, lab):
    require(isinstance(document, dict) and document.get("jsonrpc") == "2.0")
    method = document.get("method")
    if method == "notifications/initialized":
        require(exact(document, "jsonrpc", "method"))
        return method
    require(exact(document, "jsonrpc", "method", "id", "params"))
    require(type(document["id"]) is int and 1 <= document["id"] < (1 << 64))
    params = document["params"]
    if method == "initialize":
        require(params == {"protocolVersion": PROTOCOL, "capabilities": {},
                           "clientInfo": {"name": "awg3panel", "version": "1"}})
        return method
    require(method == "tools/call" and exact(params, "name", "arguments"))
    tool, args = params["name"], params["arguments"]
    require(isinstance(args, dict) and args.get("tunnelId") == lab)
    if tool == "test_connectivity":
        require(exact(args, "tunnelId"))
    elif tool == "control_tunnel":
        require(exact(args, "tunnelId", "action") and args["action"] in ("start", "stop"))
    elif tool == "update_tunnel_settings":
        require(exact(args, "tunnelId", "awg") and valid_jitter(args["awg"]))
    else:
        raise ContractError()
    return tool


def scalar(value):
    require(value is None or type(value) in (str, int, bool))
    return value


def fields(value, names):
    require(isinstance(value, dict))
    return {name: scalar(value[name]) for name in names if name in value}


def array(value, project):
    require(isinstance(value, list))
    return [project(item) for item in value]


def with_collection(value, out, key, project):
    if key in value:
        out[key] = None if value[key] is None else array(value[key], project)


def project_detail(value, lab, fingerprint_key):
    out = fields(value, DETAIL_FIELDS)
    require(out.get("id") == lab)
    for key, names in (
        ("interface", INTERFACE_FIELDS),
        ("peer", ("endpoint", "publicKey", "persistentKeepalive")),
        ("stateInfo", ("interfaceUp",)),
        ("connectivityCheck", ("method",)),
        ("pingCheck", ("enabled",)),
        ("obfuscator", ()),
    ):
        if key in value:
            item = value[key]
            out[key] = None if item is None else fields(item, names)
    peer = out.get("peer")
    if peer is not None:
        with_collection(value["peer"], peer, "allowedIPs", scalar)
    interface = out.get("interface")
    if interface and interface.get("headerProtectionKey"):
        raw = interface["headerProtectionKey"]
        require(isinstance(raw, str))
        interface["headerProtectionKey"] = hmac.digest(
            fingerprint_key, b"awg3-panel-hpk\0" + raw.encode(), "sha256").hex()
    return out


def project_dns(value):
    require(isinstance(value, dict))
    out = {}
    with_collection(value, out, "hrPolicyInterfaces", scalar)
    with_collection(value, out, "routes", lambda target: fields(target, ROUTE_FIELDS))
    return out


def project_policy(value):
    require(isinstance(value, dict))
    out = {}
    with_collection(value, out, "held", scalar)
    with_collection(value, out, "interfaces", lambda item: fields(item, ("name",)))
    return out


def project_rest(endpoint, document, lab, fingerprint_key):
    require(isinstance(document, dict) and document.get("success") is True and "data" in document)
    value = document["data"]
    if endpoint == TUNNEL_DETAIL:
        data = project_detail(value, lab, fingerprint_key)
    elif endpoint == TUNNEL_LIST:
        data = array(value, lambda item: fields(item, TUNNEL_FIELDS if item.get("id") == lab
                                                else ("id", "ispInterface")))
    elif endpoint == DNS_ROUTES:
        data = array(value, project_dns)
    elif endpoint == ACCESS_POLICIES:
        data = array(value, project_policy)
    else:
        data = array(value, lambda item: fields(item, ROUTE_FIELDS))
    return {"success": True, "data": data}


def project_mcp(tool, response, request_id):
    require(isinstance(response, dict) and response.get("jsonrpc") == "2.0" and
            type(response.get("id")) is int and response["id"] == request_id)
    out = {"jsonrpc": "2.0", "id": request_id}
    if "error" in response:
        out["error"] = {"code": -32000, "message": "AWG Manager rejected the request"}
        return out
    result = response.get("result")
    require(isinstance(result, dict))
    if tool == "initialize":
        require(result.get("protocolVersion") == PROTOCOL)
        out["result"] = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                         "serverInfo": {"name": "awg-manager", "version": "restricted-bridge"}}
    elif result.get("isError", False) is not False:
        out["result"] = {"isError": True, "content": []}
    else:
        names = {
            "control_tunnel": ("tunnelId", "action"),
            "test_connectivity": ("tunnelId", "connected", "latencyMs"),
            "update_tunnel_settings": (),
        }[tool]
        content = fields(result.get("structuredContent"), names) if names else {}
        out["result"] = {"isError": False, "content": [], "structuredContent": content}
    return out


def unique_object(items):
    out = {}
    for key, value in items:
        require(key not in out)
        out[key] = value
    return out


def reject_constant(_value):
    raise ContractError()


def read_json(body):
    return json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_constant)


def read_upstream(response, limit, request_id=None):
    if not response.getheader("Content-Type", "").lower().startswith("text/event-stream"):
        body = response.read(limit + 1)
        require(len(body) <= limit)
        return read_json(body)
    require(request_id is not None)
    remaining, event = limit, []
    while remaining:
        line = response.readline(remaining + 1)
        require(line and len(line) <= remaining)
        remaining -= len(line)
        if line.startswith(b"data:"):
            event.append(line[5:].strip())
        elif not line.strip() and event:
            payload = read_json(b"\n".join(event))
            if isinstance(payload, dict) and payload.get("id") == request_id:
                return payload
            event = []
    raise ContractError()


def read_private_text(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o077 == 0)
    return path.read_text().strip()


def rest_headers(directory):
    headers = {"Accept": "application/json", "Connection": "close"}
    path = directory / "upstream-rest.token"
    if path.exists() or path.is_symlink():
        token = read_private_text(path)
        require(TOKEN.fullmatch(token))
        headers["Authorization"] = "Bearer " + token
    return headers


def packet_size(pattern):
    pos, size = 0, 0
    while pos < len(pattern):
        match = CPS_TAG.match(pattern, pos)
        require(match is not None)
        literal, random_size = match.groups()
        if literal is not None:
            size += len(literal) // 2
        elif random_size is not None:
            count = int(random_size)
            require(count <= 1000)
            size += count
        else:
            size += 4
        pos = match.end()
    return size


def validate_obfuscation(document, mtu=None):
    require(exact(document, *OBFUSCATION_FIELDS))
    require(valid_jitter({key: document[key] for key in JITTER_FIELDS}))
    require(all(type(document[key]) is str for key in CPS_FIELDS))
    require(sum(len(document[key]) for key in CPS_FIELDS) <= CPS_TEXT_LIMIT)
    for key in CPS_FIELDS:
        pattern = document[key]
        size = packet_size(pattern)
        if mtu is not None and pattern:
            require(size + IP_UDP_OVERHEAD <= mtu)
    if mtu is not None:
        require(document["jmax"] < mtu)


def replay_interface(value):
    require(isinstance(value, dict))
    require(REQUIRED_INTERFACE.keys() <= value.keys() <= INTERFACE_SCHEMA.keys())
    require(all(type(item) is INTERFACE_SCHEMA[key] for key, item in value.items()))
    require(value["privateKey"] == "" and value["mtu"] >= 576)
    key = value.get("headerProtectionKey", "")
    try:
        ipaddress.ip_interface(value["address"])
        if key:
            decoded = base64.b64decode(key, validate=True)
            require(len(decoded) == 32 and base64.b64encode(decoded).decode() == key)
    except ValueError:
        raise ContractError() from None
    return {field: item for field, item in value.items() if field != "privateKey"}


def stopped_lab(detail, lab, name):
    require(isinstance(detail, dict) and detail.get("id") == lab and detail.get("name") == name)
    require(detail.get("type") == "awg" and detail.get("backend") == "kernel")
    require(detail.get("enabled") is False and detail.get("defaultRoute") is False)
    require(detail.get("state") in ("disabled", "disconnected", "stopped", "not_created"))
    require(detail.get("obfuscator") is None)
    state = detail.get("stateInfo")
    require(isinstance(state, dict) and state.get("interfaceUp") is False)
    # KernelBackend.IsRunning reports that the device exists, with PID 0,
    # even after the administrative stop has brought its link down.
    require(state.get("processRunning") is False or (
        state.get("processRunning") is True and state.get("backendType") == "kernel"
        and type(state.get("processPID")) is int and state["processPID"] == 0
    ))
    route = detail.get("ispInterface")
    require(isinstance(route, str) and (route == "" or re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", route)))
    require(route != "none")
    peer = detail.get("peer")
    require(isinstance(peer, dict))
    require(isinstance(peer.get("endpoint"), str) and bool(peer["endpoint"]))
    require(isinstance(peer.get("allowedIPs"), list) and "0.0.0.0/0" in peer["allowedIPs"])
    ping_check = detail.get("pingCheck")
    require(ping_check is None or (isinstance(ping_check, dict) and ping_check.get("enabled") is False))
    connectivity = detail.get("connectivityCheck")
    require(connectivity is None or (isinstance(connectivity, dict) and connectivity.get("method") in ("", "http")))
    return replay_interface(detail.get("interface"))


def confirm_isolation(exchange, detail, lab):
    tunnels = exchange("GET", TUNNEL_LIST)
    require(isinstance(tunnels, list) and all(isinstance(row, dict) for row in tunnels))
    matches = [row for row in tunnels if row.get("id") == lab]
    require(len(matches) == 1)
    listed = matches[0]
    require(listed.get("awgVersion") == "awg3.1" and listed.get("name") == detail["name"] and
            listed.get("backend") == "kernel" and listed.get("endpoint") == detail["peer"]["endpoint"] and
            listed.get("enabled") is False and listed.get("defaultRoute") is False and
            not listed.get("hasAddressConflict"))
    tunnel_names = {value.casefold() for row in (detail, listed)
                    for name in ("interfaceName", "ndmsName")
                    if isinstance(value := row.get(name), str) and value}

    def uses_lab(value):
        return isinstance(value, str) and (value in (lab, "tunnel:" + lab) or value.casefold() in tunnel_names)

    route = detail["ispInterface"].casefold()
    for row in tunnels:
        if row.get("id") != lab:
            require(not uses_lab(row.get("ispInterface")))
            other_names = {row[field].casefold() for field in ("interfaceName", "ndmsName")
                           if isinstance(row.get(field), str) and row[field]}
            require(route not in other_names)
    for path in SIMPLE_ROUTES:
        for target in array(exchange("GET", path), lambda item: fields(item, ROUTE_FIELDS)):
            require(not any(uses_lab(value) for value in target.values()))
    for route in array(exchange("GET", DNS_ROUTES), project_dns):
        require(not any(uses_lab(value) for value in (route.get("hrPolicyInterfaces") or [])))
        for target in route.get("routes") or []:
            require(not any(uses_lab(value) for value in target.values()))
    for policy in array(exchange("GET", ACCESS_POLICIES + "?refresh=true"), project_policy):
        require(not any(uses_lab(value) for value in (policy.get("held") or [])))
        require(not any(uses_lab(entry.get("name")) for entry in (policy.get("interfaces") or [])))


def normalized_interface(value):
    # The API omits some zero values, in particular explicitly cleared CPS.
    return {**{key: kind() for key, kind in OPTIONAL_INTERFACE.items()}, **value}


def update_obfuscation(exchange, lab, name, document):
    validate_obfuscation(document)
    path = TUNNEL_DETAIL + "?id=" + lab
    before = exchange("GET", path)
    original = stopped_lab(before, lab, name)
    params = {key: original.get(key, "") for key in OBFUSCATION_FIELDS}
    validate_obfuscation(params, original["mtu"])
    validate_obfuscation(document, original["mtu"])
    confirm_isolation(exchange, before, lab)
    wanted = original | document
    if normalized_interface(wanted) != normalized_interface(original):
        result = exchange("POST", TUNNEL_UPDATE + "?id=" + lab, {"interface": wanted})
        require(isinstance(result, dict) and result.get("id") == lab)
        after = exchange("GET", path)
        observed = stopped_lab(after, lab, name)
        require(normalized_interface(observed) == normalized_interface(wanted))
        require(all(before.get(key) == after.get(key) for key in STABLE_TUNNEL_FIELDS))
    return {"success": True, "data": {"id": lab}}


def upstream_json(host, method, path, document=None, *, timeout, headers):
    conn = http.client.HTTPConnection(host, 2222, timeout=timeout)
    try:
        headers = headers.copy()
        body = None
        if document is not None:
            body = json.dumps(document, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body, headers)
        response = conn.getresponse()
        require(200 <= response.status < 300)
        envelope = read_upstream(response, REST_LIMIT)
        require(isinstance(envelope, dict) and envelope.get("success") is True and "data" in envelope)
        return envelope["data"]
    finally:
        conn.close()


class Bridge(BaseHTTPRequestHandler):
    server_version = "AWG3PanelLocalBridge"
    sys_version = ""

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, *_):
        pass

    def reply(self, status, payload=None, session=None):
        encoded = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        if session:
            self.send_header("Mcp-Session-Id", session)
        self.end_headers()
        if encoded:
            self.wfile.write(encoded)

    def handle_request(self):
        if self.headers.get_all("Host") not in (["127.0.0.1:12222"], ["127.0.0.1:12224"]):
            return self.reply(403)
        if self.requestline.split()[1] != self.path:
            return self.reply(403)
        credential = credential_file(self.command, self.path)
        try:
            token = read_private_text(self.server.directory / credential)
            require(TOKEN.fullmatch(token))
        except (OSError, ValueError):
            return self.reply(503)
        auth = self.headers.get_all("Authorization")
        if not auth or len(auth) != 1 or not hmac.compare_digest(auth[0].encode(), ("Bearer " + token).encode()):
            return self.reply(401)

        try:
            lab = read_private_text(self.server.directory / "tunnel-id")
            require(TUNNEL_ID.fullmatch(lab))
        except (OSError, ValueError):
            return self.reply(503)
        try:
            endpoint, query = request_route(self.command, self.path, lab)
        except ContractError:
            return self.reply(403)

        mcp = endpoint == "/mcp"
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding"):
            return self.reply(400)
        document = None
        if self.command == "POST":
            if (self.headers.get_content_type() != "application/json" or len(lengths) != 1 or
                    not re.fullmatch(r"[0-9]{1,4}", lengths[0]) or not 1 <= int(lengths[0]) <= BODY_LIMIT):
                return self.reply(400)
            try:
                body = self.rfile.read(int(lengths[0]))
                require(len(body) == int(lengths[0]))
                document = read_json(body)
            except (ValueError, UnicodeError, RecursionError):
                return self.reply(400)
        elif lengths not in ([], ["0"]):
            return self.reply(400)
        if endpoint == OBFUSCATION:
            return self.handle_obfuscation(lab, document)

        headers = {"Accept": "application/json", "Connection": "close"}
        tool = None
        if mcp:
            try:
                tool = validate_mcp(document, lab)
                session = self.headers.get_all("Mcp-Session-Id", [])
                protocol = self.headers.get_all("MCP-Protocol-Version", [])
                require(len(session) <= 1 and (not session or SESSION_ID.fullmatch(session[0])))
                require(protocol in ([], [PROTOCOL]) and (tool != "initialize" or not session))
            except (ValueError, UnicodeError, RecursionError, OSError):
                return self.reply(403)
            try:
                upstream = read_private_text(self.server.directory / "upstream-mcp.token")
                require(TOKEN.fullmatch(upstream))
            except (OSError, ValueError):
                return self.reply(503)
            headers.update({"Authorization": "Bearer " + upstream,
                            "Accept": "application/json, text/event-stream", "Content-Type": "application/json"})
            if session:
                headers["Mcp-Session-Id"] = session[0]
            if protocol:
                headers["MCP-Protocol-Version"] = protocol[0]
        else:
            try:
                headers = rest_headers(self.server.directory)
            except (OSError, ValueError):
                return self.reply(503)

        conn = http.client.HTTPConnection(self.server.upstream, 2222, timeout=25)
        mutating = tool in ("control_tunnel", "update_tunnel_settings")
        operation = mutation(self.server.mutation_lock) if mutating else nullcontext()
        try:
            with operation:
                payload, status, response_session = self.forward(
                    conn, endpoint, query, headers, tool, document, lab, token)
            return self.reply(status, payload, response_session)
        except BridgeBusy:
            return self.reply(409)
        except (ValueError, UnicodeError, RecursionError, TypeError, AttributeError, OSError, http.client.HTTPException):
            return self.reply(502)
        finally:
            conn.close()

    def handle_obfuscation(self, lab, document):
        try:
            validate_obfuscation(document)
        except ContractError:
            return self.reply(400)
        try:
            name = read_private_text(self.server.directory / "tunnel-name")
            require(0 < len(name) <= 128 and all(ord(char) >= 32 and ord(char) != 127 for char in name))
            headers = rest_headers(self.server.directory)
        except (OSError, ValueError):
            return self.reply(503)
        deadline = time.monotonic() + 10

        def exchange(method, path, body=None):
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            if method == "POST":
                # Leave time for the upstream update and postcondition below
                # the panel adapter's 12-second HTTP request timeout.
                require(remaining >= 3)
                readable, _, _ = select.select([self.connection], [], [], 0)
                if readable:
                    require(bool(self.connection.recv(1, socket.MSG_PEEK)))
            return upstream_json(self.server.upstream, method, path, body, timeout=min(remaining, 5), headers=headers)

        try:
            with mutation(self.server.mutation_lock):
                result = update_obfuscation(exchange, lab, name, document)
        except BridgeBusy:
            return self.reply(409)
        except (ValueError, RecursionError, TypeError, AttributeError, OSError, http.client.HTTPException):
            return self.reply(502)
        return self.reply(200, result)

    def forward(self, conn, endpoint, query, headers, tool, document, lab, token):
        mcp = endpoint == "/mcp"
        body = json.dumps(document, separators=(",", ":")).encode() if mcp else None
        conn.request(self.command, endpoint + ("?" + query if query else ""), body, headers)
        response = conn.getresponse()
        if not 200 <= response.status < 300:
            raise ContractError()
        if tool == "notifications/initialized":
            require(response.status in (202, 204))
            return None, response.status, None
        if mcp:
            response_session = response.getheader("Mcp-Session-Id") if tool == "initialize" else None
            require(response_session is None or SESSION_ID.fullmatch(response_session))
            payload = project_mcp(tool, read_upstream(response, MCP_LIMIT, document["id"]), document["id"])
            return payload, 200, response_session
        payload = project_rest(endpoint, read_upstream(response, REST_LIMIT), lab, token.encode())
        return payload, 200, None

    def dispatch(self):
        try:
            self.handle_request()
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    do_GET = dispatch
    do_POST = dispatch


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: keenetic-tune-bridge.py PRIVATE_CONFIG_DIRECTORY")
    directory = Path(sys.argv[1])
    try:
        upstream = ipaddress.ip_address(read_private_text(directory / "router-host"))
        require(upstream.version == 4 and upstream.is_private and not upstream.is_loopback)
    except (OSError, ValueError):
        raise SystemExit("Invalid bridge router configuration") from None
    with ThreadingHTTPServer(("127.0.0.1", 12224), Bridge) as server:
        server.directory = directory
        server.upstream = str(upstream)
        server.mutation_lock = Lock()
        server.serve_forever()


if __name__ == "__main__":
    main()
