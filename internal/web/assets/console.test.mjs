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
  const ifaces = ["a", "b"].map(iface => ({
    dataset: { iface },
    classList: { toggle() {} },
    setAttribute() {},
  }));
  const forms = {
    defaultsform: ["endpoint", "allowed_ips", "dns", "keepalive", "jc", "jmin", "jmax", "extra"],
  };
  const document = {
    getElementById(id) {
      if (!elements.has(id)) {
        const element = {
          textContent: "", value: "", dataset: {},
          close() { this.open = false; },
          showModal() { this.open = true; },
          removeAttribute() {},
          addEventListener(event, listener) { handlers.set(id + ":" + event, listener); },
        };
        for (const key of forms[id] || []) {
          let value = "";
          element[key] = {
            get value() { return value; },
            set value(next) { value = String(next); },
          };
        }
        elements.set(id, element);
      }
      return elements.get(id);
    },
    addEventListener() {},
    querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; },
    querySelectorAll(selector) { return selector === ".iface" ? ifaces : []; },
  };
  const context = vm.createContext({
    document,
    URLSearchParams,
    location: { hash },
    window: { addEventListener(event, handler) { handlers.set(event, handler); } },
    setInterval() {},
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
  return { context, document, handlers, requests, reply, run: code => vm.runInContext(code, context) };
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
