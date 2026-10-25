// قنواتي — صفحة الوصول عن بُعد (تعمل في متصفح الجوال).
//
// Protocol "qanawati-remote-1", the same on the television (RemoteAccess.kt):
//  pairing  (link #p=<tv id>.<secret>&w=<relay host>, shown on the TV once, valid minutes)
//
// This page is not served by the relay: it lives on GitHub Pages, so whoever
// runs the relay (Cloudflare, or anyone holding its deploy token) cannot hand
// the phone altered code. The relay only ever sees sealed bytes.
//    → {"t":"pair","d":D,"m":HMAC(secret,"qanawati-pair-1"‖D)}
//    ← {"t":"paired","k":T,"m":HMAC(secret,"qanawati-paired-1"‖T‖D)}
//  every login
//    → {"t":"hello","f":SHA256(D)}
//    ← {"t":"chal","e":ET,"s":sign_T("qanawati-chal-1"‖ET‖SHA256(D))}
//    → {"t":"auth","e":EC,"s":sign_D("qanawati-auth-1"‖ET‖EC)}
//    key = HKDF-SHA256(ECDH(et,EC), salt=SHA256(ET‖EC), info="qanawati-remote-1")
//  then binary frames: [counter: 8][AES-256-GCM], nonce = dir‖000‖counter,
//  dir "C" phone→TV, "T" TV→phone; plaintext = [header length: 4][JSON][body].
// D: this browser's ECDSA P-256 key, created here and never extractable;
// T: the television's. Each login gets a fresh session key; logging out, closing
// the page or 30 idle minutes end it, and the next visit logs in again.
"use strict";

const $ = (id) => document.getElementById(id);
const te = new TextEncoder();
const td = new TextDecoder();
const subtle = crypto.subtle;
const CHUNK = 192 * 1024;
// This page's folder (…/r/): the service worker, its scope and the TV's page live under it.
const BASE = location.pathname.replace(/[^/]*$/, "");
const HOST_FORM = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:[0-9]{2,5})?$/;
const wsBase = (host) => (/^(127\.0\.0\.1|localhost)(:|$)/.test(host) ? "ws" : "wss") + "://" + host;

function b64(buf) {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("bad data");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function cat(...parts) {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const sha256 = async (d) => new Uint8Array(await subtle.digest("SHA-256", d));

// ---------------------------------------------------------------- storage (this browser only)

function db() {
  return new Promise((res, rej) => {
    const r = indexedDB.open("qanawati-remote", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("kv");
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function dbDo(mode, fn) {
  const d = await db();
  return new Promise((res, rej) => {
    const tx = d.transaction("kv", mode);
    const req = fn(tx.objectStore("kv"));
    tx.oncomplete = () => { res(req && req.result); d.close(); };
    tx.onerror = () => { rej(tx.error); d.close(); };
  });
}
const loadLink = () => dbDo("readonly", (s) => s.get("link")).catch(() => null);
const saveLink = (v) => dbDo("readwrite", (s) => s.put(v, "link"));

// ---------------------------------------------------------------- screen

function show(title, text, opts = {}) {
  document.body.classList.remove("app");
  $("frame").removeAttribute("src");
  $("title").textContent = title;
  $("text").textContent = text || "";
  $("spin").hidden = !opts.spin;
  $("otpForm").hidden = !opts.otp;
  $("again").hidden = !opts.again;
  $("again").textContent = opts.againText || "دخول من جديد";
  $("msg").textContent = "";
  $("msg").className = "msg";
  if (opts.otp) setTimeout(() => $("otp").focus(), 50);
}
function status(text, cls) {
  $("state").textContent = text;
  $("dot").className = cls || "";
}
function note(text, bad) {
  $("msg").textContent = text || "";
  $("msg").className = bad ? "msg bad" : "msg";
}

// ---------------------------------------------------------------- session

let link = null;     // {tv, tvKey: Uint8Array, dev: CryptoKeyPair, devPub: Uint8Array}
let ws = null;
let key = null;      // AES-GCM, this login only
let sendCtr = 0n, recvCtr = 0n;
let sendQ = Promise.resolve(), recvQ = Promise.resolve();
let ready = false;   // approved: the TV's page may be shown
let ended = false;
let ping = null;
let nextId = 1;
const pending = new Map();

function nonce(dir, ctr) {
  const n = new Uint8Array(12);
  n[0] = dir.charCodeAt(0);
  new DataView(n.buffer).setBigUint64(4, ctr);
  return n;
}

function sendSecure(head, body) {
  if (!key || !ws) return Promise.resolve();
  sendQ = sendQ.then(async () => {
    if (!key || !ws || ws.readyState !== 1) return;
    const h = te.encode(JSON.stringify(head));
    const b = body ? new Uint8Array(body) : new Uint8Array(0);
    const plain = new Uint8Array(4 + h.length + b.length);
    new DataView(plain.buffer).setUint32(0, h.length);
    plain.set(h, 4); plain.set(b, 4 + h.length);
    sendCtr += 1n;
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce("C", sendCtr) }, key, plain));
    const frame = new Uint8Array(8 + ct.length);
    new DataView(frame.buffer).setBigUint64(0, sendCtr);
    frame.set(ct, 8);
    ws.send(frame);
  }).catch(() => {});
  return sendQ;
}

async function openSecure(buf) {
  const u = new Uint8Array(buf);
  if (u.length < 8 + 16 + 4) throw new Error("short");
  const ctr = new DataView(buf).getBigUint64(0);
  if (ctr !== recvCtr + 1n) throw new Error("order");
  const plain = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce("T", ctr) }, key, u.subarray(8)));
  recvCtr = ctr;
  const hl = new DataView(plain.buffer).getUint32(0);
  const head = JSON.parse(td.decode(plain.subarray(4, 4 + hl)));
  return { head, body: plain.slice(4 + hl) };
}

function end(title, text, again = true) {
  if (ended) return;
  ended = true;
  ready = false;
  key = null;
  clearInterval(ping);
  for (const p of pending.values()) answer(p.port, 503, "انتهت الجلسة.");
  pending.clear();
  $("out").hidden = true;
  try { ws && ws.close(); } catch {}
  ws = null;
  status("غير متصل", "off");
  show(title, text, { again });
}

function logout() {
  if (!ws) return;
  sendSecure({ t: "bye" }).then(() => end("تم تسجيل الخروج", "أُقفلت الجلسة ومُسح مفتاحها. الدخول التالي يحتاج موافقة جديدة."));
}

async function connect(pair) {
  ended = false; ready = false; key = null; sendCtr = 0n; recvCtr = 0n;
  sendQ = Promise.resolve(); recvQ = Promise.resolve();
  const tv = pair ? pair.tv : link.tv;
  const relay = pair ? pair.relay : link.relay;
  status("جارٍ الاتصال…", "wait");
  show("جارٍ الاتصال بالتلفزيون…", "", { spin: true });
  const sock = new WebSocket(`${wsBase(relay)}/r/ws?id=${tv}&role=c`);
  ws = sock;
  sock.binaryType = "arraybuffer";
  let ek = null, ET = null;

  sock.onopen = async () => {
    ping = setInterval(() => { try { sock.readyState === 1 && sock.send("ping"); } catch {} }, 30000);
    if (pair) {
      const mac = new Uint8Array(await subtle.sign("HMAC", pair.mk, cat(te.encode("qanawati-pair-1"), pair.devPub)));
      sock.send(JSON.stringify({ t: "pair", d: b64(pair.devPub), m: b64(mac) }));
    } else {
      sock.send(JSON.stringify({ t: "hello", f: b64(await sha256(link.devPub)) }));
    }
  };

  sock.onmessage = (ev) => {
    recvQ = recvQ.then(() => (typeof ev.data === "string" ? onText(ev.data) : onBinary(ev.data))).catch((e) => {
      end("تعذّر إكمال الاتصال", "رُفض الرد لأنه لا يطابق مفاتيح التلفزيون المربوط. أعد المحاولة.");
    });
  };

  async function onText(text) {
    if (text === "pong") return;
    const m = JSON.parse(text);
    if (m.e === "offline") return end("التلفزيون غير متصل", "افتح تطبيق قنواتي على التلفزيون (ويجب أن يكون «الوصول عن بُعد» مفعّلاً) ثم أعد المحاولة.");
    if (m.e === "busy") return end("محاولات كثيرة", "انتظر دقيقة ثم أعد المحاولة.");
    if (m.t === "err") {
      if (m.e === "unknown" || m.e === "pair") {
        return end("هذا المتصفح غير مربوط", m.e === "pair"
          ? "رابط الربط غير صالح أو انتهت مدته. افتح «الوصول عن بُعد» في التطبيق وامسح الرمز الجديد."
          : "رُبط جهاز آخر بالتلفزيون أو أُلغي الربط. اربط هذا الجوال من جديد من «الوصول عن بُعد» في التطبيق.", false);
      }
      return end("تعذّر الدخول", "رفض التلفزيون الطلب.");
    }
    if (m.t === "paired" && pair) {
      const T = unb64(m.k);
      const ok = await subtle.verify("HMAC", pair.mk, unb64(m.m), cat(te.encode("qanawati-paired-1"), T, pair.devPub));
      if (!ok || T.length !== 65) throw new Error("pair reply");
      link = { tv: pair.tv, relay: pair.relay, tvKey: T, dev: pair.dev, devPub: pair.devPub, at: Date.now() };
      await saveLink(link);
      pair = null;
      sock.send(JSON.stringify({ t: "hello", f: b64(await sha256(link.devPub)) }));
      return;
    }
    if (m.t === "chal" && link && !key) {
      ET = unb64(m.e);
      const tvKey = await subtle.importKey("raw", link.tvKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, tvKey, unb64(m.s), cat(te.encode("qanawati-chal-1"), ET, await sha256(link.devPub)));
      if (!ok) throw new Error("tv signature");
      ek = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
      const EC = new Uint8Array(await subtle.exportKey("raw", ek.publicKey));
      const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, link.dev.privateKey, cat(te.encode("qanawati-auth-1"), ET, EC));
      const etKey = await subtle.importKey("raw", ET, { name: "ECDH", namedCurve: "P-256" }, false, []);
      const z = await subtle.deriveBits({ name: "ECDH", public: etKey }, ek.privateKey, 256);
      const base = await subtle.importKey("raw", z, "HKDF", false, ["deriveKey"]);
      key = await subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: await sha256(cat(ET, EC)), info: te.encode("qanawati-remote-1") },
        base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      ek = null;
      sock.send(JSON.stringify({ t: "auth", e: b64(EC), s: b64(new Uint8Array(sig)) }));
      status("بانتظار الموافقة", "wait");
      return;
    }
  }

  async function onBinary(buf) {
    if (!key) return;
    const { head, body } = await openSecure(buf);
    switch (head.t) {
      case "wait":
        status("بانتظار الموافقة", "wait");
        show("تأكيد الدخول", head.otp
          ? "أدخل الرمز من تطبيق Microsoft Authenticator — أو اضغط «سماح» على شاشة التلفزيون."
          : "اضغط «سماح» على شاشة التلفزيون لإكمال الدخول.", { otp: !!head.otp, spin: !head.otp });
        return;
      case "otp-bad":
        $("otpGo").disabled = false;
        $("otp").value = ""; $("otp").focus();
        return note(head.left > 0 ? `الرمز غير صحيح — بقي ${head.left} محاولات.` : "الرمز غير صحيح.", true);
      case "otp-locked":
        $("otpGo").disabled = true;
        return note("محاولات خاطئة كثيرة — أُوقف الإدخال بالرمز مؤقتاً. يمكنك الموافقة من التلفزيون.", true);
      case "denied":
        return end("رُفض الدخول", "رُفض الطلب من التلفزيون.");
      case "ok":
        ready = true;
        status("متصل — مشفّر", "on");
        $("out").hidden = false;
        document.body.classList.add("app");
        $("frame").src = BASE + "app/";
        return;
      case "bye":
        return end("انتهت الجلسة", head.why === "idle" ? "أُقفلت الجلسة بعد 30 دقيقة دون استخدام."
          : head.why === "other" ? "بدأت جلسة أخرى لهذا الجهاز." : "أنهى التلفزيون الجلسة.");
      case "res":
      case "rb": {
        const p = pending.get(head.id);
        if (!p) return;
        if (head.t === "res") { p.s = head.s; p.h = head.h || {}; }
        p.parts.push(body);
        if (!head.more) {
          pending.delete(head.id);
          clearTimeout(p.timer);
          const all = cat(...p.parts);
          p.port.postMessage({ s: p.s, h: p.h, body: all.buffer }, [all.buffer]);
        }
        return;
      }
    }
  }

  sock.onclose = () => {
    if (ws !== sock) return;
    if (ready) end("انقطع الاتصال", "انقطع الاتصال بالتلفزيون. سيُطلب تأكيد الدخول من جديد.");
    else end("تعذّر الاتصال", "تحقق من الإنترنت ومن أن التطبيق مفتوح على التلفزيون، ثم أعد المحاولة.");
  };
}

// ---------------------------------------------------------------- requests from the TV's page (service worker)

function answer(port, s, text) {
  const body = te.encode(`<!doctype html><meta charset="utf-8"><body dir="rtl" style="font:16px system-ui;padding:24px">${text}</body>`);
  port.postMessage({ s, h: { "content-type": "text/html; charset=utf-8" }, body: body.buffer }, [body.buffer]);
}

async function onRequest(port, req) {
  if (!ready || !key) return answer(port, 503, "الجلسة غير مفتوحة.");
  const id = nextId++;
  const p = { port, parts: [], s: 502, h: {} };
  p.timer = setTimeout(() => { if (pending.delete(id)) answer(port, 504, "لم يرد التلفزيون في الوقت المحدد."); }, 120000);
  pending.set(id, p);
  const body = req.body ? new Uint8Array(req.body) : new Uint8Array(0);
  let off = 0;
  do {
    const part = body.subarray(off, off + CHUNK);
    off += part.length;
    const more = off < body.length;
    await sendSecure(off <= CHUNK ? { t: "req", id, m: req.m, p: req.p, ct: req.ct || null, more } : { t: "rb", id, more }, part);
  } while (off < body.length);
}

// ---------------------------------------------------------------- start

async function start() {
  const hash = location.hash.slice(1);
  if (hash) history.replaceState(null, "", location.pathname);
  if (!window.isSecureContext || !crypto.subtle || !("serviceWorker" in navigator) || !window.indexedDB) {
    return show("المتصفح غير مدعوم", "استخدم Chrome أو Safari أو Edge أو Firefox بإصدار حديث، وليس في وضع التصفح الخاص.");
  }
  navigator.serviceWorker.onmessage = (e) => { if (e.data && e.data.req && e.ports[0]) onRequest(e.ports[0], e.data.req); };
  try {
    await navigator.serviceWorker.register(BASE + "sw.js", { scope: BASE });
    await navigator.serviceWorker.ready;
  } catch (e) {
    return show("المتصفح غير مدعوم", "تعذّر تشغيل مكوّن الصفحة (Service Worker). أوقف وضع التصفح الخاص ثم أعد المحاولة.");
  }

  $("out").onclick = logout;
  $("again").onclick = () => { if (link) connect(null); else location.reload(); };
  $("otpForm").onsubmit = (e) => {
    e.preventDefault();
    const c = $("otp").value.replace(/\D/g, "");
    if (c.length !== 6) return note("الرمز من 6 أرقام.", true);
    note("");
    sendSecure({ t: "otp", c });
  };
  // Leaving the page closes its connection, which ends the session on the TV.
  addEventListener("pagehide", () => { if (ws && key) sendSecure({ t: "bye" }); });

  const m = /^p=([0-9a-f]{32})\.([A-Za-z0-9_-]{43})&w=([a-z0-9.:-]{4,260})$/.exec(hash);
  if (m && HOST_FORM.test(m[3])) {
    const secret = unb64(m[2]);
    const dev = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const devPub = new Uint8Array(await subtle.exportKey("raw", dev.publicKey));
    const mk = await subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    secret.fill(0);
    return connect({ tv: m[1], relay: m[3], dev, devPub, mk });
  }
  link = await loadLink();
  if (link && !link.relay) link = null;
  if (!link) {
    status("غير مربوط", "off");
    return show("هذا المتصفح غير مربوط",
      "على التلفزيون: الإعدادات ← الوصول عن بُعد، ثم امسح الرمز بكاميرا هذا الجوال (أو افتح «ربط هذا الجوال» من صفحة التحكم في البيت). بعدها احفظ هذه الصفحة للدخول من أي مكان.");
  }
  connect(null);
}

start();
