import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const page = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const blocks = [...page.replace(/<!--[\s\S]*?-->/g, "").matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)]
  .map(match => match[1]);

function response(body, status = 200) {
  return {
    ok: status < 400,
    status,
    text: async () => typeof body === "string" ? body : JSON.stringify(body),
  };
}

function loadConsole(hash = "#a") {
  const handlers = new Map();
  const elements = new Map();
  const requests = [];
  const timers = [];
  const ifaces = ["a", "b"].map(iface => ({
    dataset: { iface },
    classList: { toggle() {} },
    setAttribute() {},
  }));
  const forms = {
    defaultsform: ["endpoint", "allowed_ips", "dns", "keepalive", "jc", "jmin", "jmax", "extra"],
    editform: ["name", "address", "jc", "jmin", "jmax", "extra"],
  };
  const document = {
    getElementById(id) {
      if (!elements.has(id)) {
        const element = {
          textContent: "", value: "", dataset: {}, style: {}, children: [],
          append(...nodes) { this.children.push(...nodes); },
          replaceChildren(...nodes) { this.children = nodes; },
          close() { this.open = false; },
          showModal() { this.open = true; },
          removeAttribute() {},
          addEventListener(event, listener) { handlers.set(id + ":" + event, listener); },
        };
        for (const key of forms[id] || []) {
          let value = "";
          element[key] = {
            name: key,
            parentElement: { querySelector() { return null; } },
            get value() { return value; },
            set value(next) { value = String(next); },
          };
        }
        if (id === "editform") {
          element.querySelectorAll = () => [element.jc, element.jmin, element.jmax];
        }
        elements.set(id, element);
      }
      return elements.get(id);
    },
    addEventListener() {},
    createElement() { return { textContent: "", value: "" }; },
    querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; },
    querySelectorAll(selector) { return selector === ".iface" ? ifaces : []; },
  };
  const context = vm.createContext({
    document,
    URLSearchParams,
    location: { hash },
    window: { addEventListener(event, handler) { handlers.set(event, handler); } },
    setInterval() {},
    setTimeout(fn) { timers.push(fn); },
    fetch(url, options = {}) {
      return new Promise(resolve => requests.push({ url, options, resolve }));
    },
  });
  for (const block of blocks) vm.runInContext(block, context);
  vm.runInContext("showToast = () => {}; showErr = () => {}", context);
  function reply(url, body, status) {
    const i = requests.findIndex(req => req.url === url);
    assert.notEqual(i, -1, "нет ожидаемого запроса " + url);
    requests.splice(i, 1)[0].resolve(response(body, status));
  }
  return { context, document, handlers, requests, timers, reply, run: code => vm.runInContext(code, context) };
}

const defaultsA = { endpoint: "198.51.100.10:443", allowed_ips: "0.0.0.0/0", jc: 4, jmin: 80, jmax: 600 };
const defaultsB = { endpoint: "203.0.113.20:3478", allowed_ips: "0.0.0.0/0", jc: 5, jmin: 100, jmax: 700 };

test("late defaults from A cannot overwrite the B form or be saved to B", async () => {
  const app = loadConsole();
  app.run('state.tab = "defaults"');
  const a = app.run("loadDefaultsTab()");
  const form = app.document.getElementById("defaultsform");
  app.run('switchIface("b")');
  const submit = () => app.handlers.get("defaultsform:submit")({ target: form, preventDefault() {} });
  await submit();
  assert.equal(app.requests.some(req => req.options.method === "PUT"), false);
  app.reply("/api/ifaces/b/defaults", defaultsB);
  await new Promise(setImmediate);
  app.reply("/api/ifaces/a/defaults", defaultsA);
  await a;
  assert.equal(form.endpoint.value, defaultsB.endpoint);
  const save = submit();
  const write = app.requests.find(req => req.options.method === "PUT");
  assert.equal(write.url, "/api/ifaces/b/defaults");
  assert.equal(JSON.parse(write.options.body).endpoint, defaultsB.endpoint);
  write.resolve(response({}));
  await save;
});

test("late peer and summary responses from A do not replace B data", async () => {
  const app = loadConsole();
  app.run('switchIface("b")');
  app.reply("/api/ifaces/b/peers", [{ id: "b", name: "peer B", address: "203.0.113.1" }]);
  app.reply("/api/ifaces/b/summary", { interface: "b", listen_port: 3478 });
  await new Promise(setImmediate);
  app.reply("/api/ifaces/a/peers", [{ id: "a", name: "peer A", address: "198.51.100.1" }]);
  app.reply("/api/ifaces/a/summary", { interface: "a", listen_port: 443 });
  await new Promise(setImmediate);
  assert.equal(app.run("window.__peers[0].id"), "b");
  assert.match(app.document.getElementById("srvline").innerHTML, /3478/);
});

test("unknown fragments and Back to a bare URL select the first interface", () => {
  const app = loadConsole("#unknown");
  assert.equal(app.run("state.iface"), "a");
  app.context.location.hash = "#b";
  app.handlers.get("hashchange")();
  assert.equal(app.run("state.iface"), "b");
  app.context.location.hash = "";
  app.handlers.get("hashchange")();
  assert.equal(app.run("state.iface"), "a");
});

test("plaintext auth and proxy errors retain their status and readable cause", async () => {
  const app = loadConsole();
  for (const status of [401, 429, 502]) {
    const failure = app.run('api("GET", "/probe")');
    app.reply("/api/ifaces/a/probe", "Проверьте подключение", status);
    await assert.rejects(failure, error => error.message.includes(String(status)) &&
      error.message.includes("Проверьте подключение"));
  }
});

test("peer table refresh restores focus to the matching control", async () => {
  const app = loadConsole();
  const control = { dataset: { id: "peer", act: "menu" }, classList: { contains: () => false } };
  app.document.activeElement = control;
  let focused = false;
  app.document.getElementById("rows").querySelectorAll = () => [{
    ...control,
    focus() { focused = true; },
  }];
  app.reply("/api/ifaces/a/peers", [{ id: "peer", name: "peer A", address: "198.51.100.1" }]);
  await new Promise(setImmediate);
  assert.equal(focused, true);
});

test("peer counts distinguish peers which have never connected", async () => {
  const app = loadConsole();
  app.reply("/api/ifaces/a/summary", { interface: "a", peers_total: 2, peers_online: 0, peers_stale: 0, peers_never: 2 });
  await new Promise(setImmediate);
  assert.match(app.document.getElementById("kpis").innerHTML, /Без первого хендшейка: 2/);
  assert.doesNotMatch(app.document.getElementById("kpis").innerHTML, /все на связи/);
});

test("detach posts the preview token only after confirmation", async () => {
  const app = loadConsole();
  app.run('state.tab = "manage"; confirmByName = id => id === "b"');
  const action = app.run('window.manageAction("b", "detach")');
  app.reply("/api/manage/preview?action=detach&id=b", {
    id: "b", action: "detach", preview_token: "token-for-b",
  });
  await new Promise(setImmediate);
  const dialog = app.document.getElementById("manage-preview");
  assert.equal(dialog.open, true);
  assert.match(app.document.getElementById("adopt-preview").textContent, /"id": "b"/);
  assert.equal(app.requests.some(req => req.options.method === "POST"), false);
  dialog.returnValue = "save";
  app.handlers.get("manage-preview:close")();
  await new Promise(setImmediate);
  const write = app.requests.find(req => req.options.method === "POST");
  assert.equal(write.url, "/api/manage/requests");
  assert.deepEqual(JSON.parse(write.options.body), { preview_token: "token-for-b" });
  write.resolve(response({ name: "request.json" }));
  await action;
});

test("peer config saves only junk settings and refreshes its QR", async () => {
  const app = loadConsole();
  app.run('showPeerConfig("test", "new-peer", "a")');
  const button = app.document.getElementById("qrgeneratejitter");
  assert.equal(typeof button.onclick, "function");
  const firstQR = app.document.getElementById("qrimg").src;

  const generate = button.onclick();
  app.reply("/api/ifaces/a/generate/jitter", { jc: 5, jmin: 90, jmax: 420 });
  await generate;
  assert.match(app.document.getElementById("qrjittervalues").textContent, /Jc = 5/);
  assert.equal(app.requests.some(req => req.options.method === "PATCH"), false);

  const saving = app.document.getElementById("qrsavejitter").onclick();
  const write = app.requests.find(req => req.options.method === "PATCH");
  assert.equal(write.url, "/api/ifaces/a/peers/new-peer");
  assert.deepEqual(JSON.parse(write.options.body), { jitter: { jc: 5, jmin: 90, jmax: 420 } });
  app.reply(write.url, {});
  await saving;
  assert.equal(app.document.getElementById("qrdlg").open, true);
  assert.notEqual(app.document.getElementById("qrimg").src, firstQR);
  assert.equal(app.document.getElementById("qrdl").href, "/api/ifaces/a/peers/new-peer/config");

  app.document.getElementById("qrvpn").onclick();
  assert.match(app.document.getElementById("qrimg").src, /vpnqr\?v=/);
});

test("closing the peer config discards a late junk generation response", async () => {
  const app = loadConsole();
  app.run('showPeerConfig("test", "test", "a")');
  const button = app.document.getElementById("qrgeneratejitter");
  assert.equal(typeof button.onclick, "function");

  const generate = button.onclick();
  app.document.getElementById("qrdlg").close();
  app.reply("/api/ifaces/a/generate/jitter", { jc: 5, jmin: 90, jmax: 420 });
  await generate;
  assert.equal(app.document.getElementById("qrjitterpreview").hidden, true);
});

test("new interface regenerates only the client junk settings", async () => {
  const app = loadConsole();
  app.document.getElementById("genifaceprofile").value = "sip";
  app.document.getElementById("drafttiming").checked = true;
  app.document.getElementById("draftpaddingon").checked = true;
  app.document.getElementById("draftpadding").value = "10-100";
  const generate = app.document.getElementById("genifacebtn").onclick();
  const endpoint = "/api/ifaces/a/generate/obfuscation-draft";
  assert.match(app.requests.find(r => r.url === endpoint).options.body, /"timing_jitter":true/);
  app.reply(endpoint, {
    server_block: "S1 = 21", jitter: { jc: 4, jmin: 70, jmax: 400 },
    client_block: "S1 = 21\nJc = 4\nJmin = 70\nJmax = 400\nI1 = <r 3>",
    cps: ["<r 3>", "<r 2>"], profile: "sip", listen_port: 5060, keepalive: "25-35",
  });
  await generate;

  const button = app.document.getElementById("genifacejitter");
  assert.equal(typeof button.onclick, "function");
  const jitter = button.onclick();
  app.reply("/api/ifaces/a/generate/jitter", { jc: 6, jmin: 85, jmax: 500 });
  await jitter;
  assert.match(app.document.getElementById("ifacejitter").textContent, /Jc = 6/);
  assert.equal(app.document.getElementById("ifaceblock").textContent, "S1 = 21");
  assert.match(app.document.getElementById("ifacei1").textContent, /<r 3>/);
  assert.match(app.document.getElementById("ifacei1").textContent, /I2 = <r 2>/);
  assert.match(app.document.getElementById("ifaceclientblock").textContent, /Jc = 6/);
  assert.match(app.document.getElementById("ifacemimicry").textContent, /SIP.*UDP 5060/);
});

test("peer config displays its effective CPS metadata and offers control export", async () => {
  const app = loadConsole();
  app.run('showPeerConfig("test", "test", "a")');
  app.reply("/api/ifaces/a/peers/test/mimicry", {
    profile: "dns", source: "peer", endpoint_port: 5300, profile_port: 53,
    port_mismatch: true, has_cps: true,
  });
  await new Promise(setImmediate);
  assert.match(app.document.getElementById("qrmimicry").textContent, /DNS.*5300.*Порт профиля.*53/);
  assert.equal(app.document.getElementById("qrnocps").href, "/api/ifaces/a/peers/test/config-no-cps");
});

test("autotune tab explains missing setup and does not contact a router", () => {
  const app = loadConsole();
  app.run('selectTab("junktune")');
  assert.match(app.document.getElementById("qrtunestatus").textContent, /подключите.*тестовый туннель/i);
  assert.equal(app.document.getElementById("qrtunestart").disabled, true);
  assert.equal(app.document.getElementById("tunesetup").hidden, false);
  assert.equal(app.requests.some(r => r.url.endsWith("/junktune")), false);
});

test("autotune shortcut only opens for the paired peer and results update that peer", async () => {
  const app = loadConsole();
  Object.assign(app.document.getElementById("qrtune").dataset, { iface: "b", peer: "lab" });
  app.run('showPeerConfig("working peer", "live", "a")');
  assert.equal(app.document.getElementById("qropentune").hidden, true);
  app.document.getElementById("qropentune").onclick();
  assert.equal(app.run("state.tab"), "peers");
  app.document.getElementById("qrdlg").close();
  app.run('switchIface("b"); showPeerConfig("Lab", "lab", "b")');
  assert.equal(app.document.getElementById("qropentune").hidden, false);
  app.document.getElementById("qropentune").onclick();
  assert.equal(app.run("state.tab"), "junktune");
  assert.equal(app.document.getElementById("qrdlg").open, false);
  assert.match(app.document.getElementById("tunetarget").textContent, /выделенный туннель интерфейса b/);
  const path = "/api/ifaces/b/peers/lab/junktune";
  app.reply(path, { options: {profile:"random", max_attempts:10, threshold_pct:95, auto_apply:true} });
  await new Promise(setImmediate);

  const start = app.document.getElementById("qrtunestart");
  assert.equal(typeof start.onclick, "function");
  const beginning = start.onclick();
  const submitted = JSON.parse(app.requests.find(r => r.url === path).options.body);
  assert.equal(submitted.profile, "random");
  assert.equal(submitted.auto_apply, false);
  const result = {
    id: "run", running: false,
    options: {profile: "random"}, can_apply: true, result: { best: 1, attempts: [
      { jitter: { jc: 4, jmin: 72, jmax: 323 }, successes: 0, runs: 3, median_ms: 0 },
      { jitter: { jc: 6, jmin: 99, jmax: 432 }, profile: "dns", domain: "example.com", cps: ["<r 8>"], successes: 3, runs: 3, avg_ms: 44 },
    ] },
  };
  app.reply(path, { id: "run", running: true }, 202);
  await beginning;
  assert.equal(app.document.getElementById("qrtunecancel").hidden, false);
  app.timers.shift()();
  app.reply(path, result);
  await new Promise(setImmediate);
  assert.match(app.document.getElementById("qrtuneattempts").children[1].textContent, /3 из 3/);
  const select = app.document.getElementById("qrtuneselection");
  assert.deepEqual(select.children.map(option => option.value), ["1"]);
  assert.match(app.document.getElementById("qrtuneattempts").children[1].textContent, /DNS.*example\.com/);
  assert.equal(app.document.getElementById("tunedpackets").textContent, "I1 = <r 8>");
  assert.equal(app.document.getElementById("tunedpreview").href, path + "/export?id=run&attempt=1");
  const applying = app.document.getElementById("qrtuneapply").onclick();
  const req = app.requests.find(r => r.url === path + "/apply");
  assert.deepEqual(JSON.parse(req.options.body), { id: "run", attempt: 1 });
  app.reply(req.url, {});
  await applying;

  assert.equal(app.document.getElementById("tunedconfig").href, "/api/ifaces/b/peers/lab/config");
  assert.equal(app.document.getElementById("tunedconfig").hidden, false);
  assert.equal(app.requests.some(r => r.url.includes("/live/junktune")), false);
});

test("connection card opens its editor and stages a measured recommendation without writing", async () => {
  const app = loadConsole();
  Object.assign(app.document.getElementById("qrtune").dataset, { iface: "a", peer: "lab" });
  app.run(`window.__peers = [{id:"client",name:"Laptop",enabled:true,never_connected:true,
    address:"198.51.100.4/32",overrides:{extra:{I1:"<r 2>",I2:"<r 3>",F:"on"}}}];
    state.defaults = {}; renderRows(); showPeerConfig("Laptop","client","a");`);
  assert.match(app.document.getElementById("rows").innerHTML, /data-act="connection" data-id="client">Laptop/);
  const config = app.document.getElementById("qrdlg");
  assert.match(app.document.getElementById("qrconnectionstatus").textContent, /первое подключение/i);
  assert.equal(app.document.getElementById("qropentune").hidden, true);
  await app.document.getElementById("qredit").onclick?.();
  assert.equal(config.open, false);
  assert.equal(app.document.getElementById("editdlg").open, true);

  const form = app.document.getElementById("editform");
  const pending = app.document.getElementById("edittunefill").onclick();
  const path = "/api/ifaces/a/peers/lab/junktune";
  app.reply(path, { id: "run", running: false, can_apply: true, options: {profile: "dns"},
    result: { best: 1, attempts: [
      { profile: "current", runs: 3, successes: 2 },
      { profile: "dns", runs: 3, successes: 3, jitter: {jc: 5, jmin: 25, jmax: 65}, cps: ["<r 7>", "", "<r 9>", "", ""] },
    ] },
  });
  await pending;
  assert.equal(form.extra.value, "F = on\nI1 = <r 7>\nI3 = <r 9>");
  assert.deepEqual([form.jc.value, form.jmin.value, form.jmax.value], ["5", "25", "65"]);
  assert.equal(app.document.getElementById("editexactcps").checked, true);
  assert.equal(app.requests.some(r => ["POST", "PATCH"].includes(r.options.method)), false);

  const saving = app.handlers.get("editform:submit")({target:form, preventDefault(){}});
  const write = app.requests.find(r => r.options.method === "PATCH");
  assert.equal(write.url, "/api/ifaces/a/peers/client");
  assert.deepEqual(JSON.parse(write.options.body).overrides, {
    jc: 5, jmin: 25, jmax: 65, cps: ["<r 7>", "", "<r 9>", "", ""], extra: { F: "on" },
  });
  app.reply(write.url, {});
  await saving;
  assert.equal(config.open, true);
  assert.equal(app.document.getElementById("qrdl").href, "/api/ifaces/a/peers/client/config");
});

test("recommendation without signature packets explicitly clears CPS in the editor", async () => {
  const app = loadConsole();
  Object.assign(app.document.getElementById("qrtune").dataset, { iface: "a", peer: "lab" });
  app.run(`window.__peers = [{id:"client",name:"Laptop",enabled:true,address:"198.51.100.4/32",
    overrides:{extra:{I1:"<r 8>",F:"on"}}}]; state.defaults = {};`);
  await app.run('openEdit("client")');
  const pending = app.document.getElementById("edittunefill").onclick();
  app.reply("/api/ifaces/a/peers/lab/junktune", { id: "run", can_apply: true, options: {profile: "none"},
    result: { best: 1, attempts: [
      { profile: "current", runs: 3, successes: 2 },
      { profile: "none", runs: 3, successes: 3, jitter: {jc: 5, jmin: 25, jmax: 65} },
    ] },
  });
  await pending;
  assert.equal(app.document.getElementById("editform").extra.value, "F = on");
  assert.equal(app.document.getElementById("editexactcps").checked, true);
  const overrides = JSON.parse(app.run("JSON.stringify(collectOverrides())"));
  assert.deepEqual(overrides, {jc:5,jmin:25,jmax:65,cps:["","","","",""],extra:{F:"on"}});
});
