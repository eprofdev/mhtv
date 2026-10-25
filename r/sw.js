// قنواتي — the remote page's service worker.
// The television's pages are shown in a frame: the control page at …/r/app/,
// the watch page at …/r/watch/. Every request that frame makes (pages, forms,
// images, video) is caught here and handed to the open remote page, which sends
// it to the TV — over the encrypted session, or for video over the direct
// WebRTC channel — and streams the answer back. Nothing under these paths ever
// reaches a server.
"use strict";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

const BASE = new URL(self.registration.scope).pathname;    // …/r/
const SCOPES = { app: BASE + "app", watch: BASE + "watch" };

self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (u.origin !== self.location.origin) return;
  for (const [name, prefix] of Object.entries(SCOPES)) {
    if (u.pathname.startsWith(prefix + "/")) { e.respondWith(tunnel(e.request, u, name, prefix)); return; }
  }
});

const NO_BODY = new Set([101, 204, 205, 304]);

function page(text, status) {
  return new Response(`<!doctype html><meta charset="utf-8"><body dir="rtl" style="font:16px system-ui;padding:24px;color:#eef1fb;background:#0b1020">${text}</body>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

async function shell() {
  const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  const pages = all.filter((c) => { const p = new URL(c.url).pathname; return p === BASE || p === BASE + "index.html"; });
  return pages.find((c) => c.focused) || pages[0] || null;
}

// The remote page answers on a port: {head:{s,h}}, then {chunk}, … and {end}
// or {err}. The body is a stream the player pulls; each pull asks for more.
async function tunnel(req, u, scope, prefix) {
  const c = await shell();
  if (!c) return page("افتح صفحة الوصول عن بُعد أولاً.", 409);
  const body = req.method === "GET" || req.method === "HEAD" ? null : await req.arrayBuffer();
  const ch = new MessageChannel();
  const port = ch.port1;
  let ctrl = null;
  const early = [];
  const head = new Promise((res) => {
    const t = setTimeout(() => res(null), 130000);
    port.onmessage = (m) => {
      const d = m.data || {};
      if (d.head) { clearTimeout(t); res(d.head); return; }
      if (d.err && !ctrl) { clearTimeout(t); res({ s: 502, h: { "content-type": "text/html; charset=utf-8" }, text: d.err }); return; }
      if (ctrl) deliver(d); else early.push(d);
    };
  });
  function deliver(d) {
    try {
      if (d.chunk) ctrl.enqueue(new Uint8Array(d.chunk));
      else if (d.end) { ctrl.close(); port.close(); }
      else if (d.err) { ctrl.error(new Error(d.err)); port.close(); }
    } catch {}
  }
  c.postMessage({
    req: { scope, m: req.method, p: u.pathname.slice(prefix.length) + u.search, ct: req.headers.get("content-type"), range: req.headers.get("range"), body },
  }, body ? [ch.port2, body] : [ch.port2]);

  const r = await head;
  if (!r) { port.postMessage({ cancel: 1 }); return page("لم يرد التلفزيون في الوقت المحدد.", 504); }
  if (r.text) return page(r.text, r.s);

  const h = new Headers();
  for (const [k, v] of Object.entries(r.h || {})) {
    if (["content-type", "content-disposition", "location", "content-length", "content-range", "accept-ranges"].includes(k)) h.set(k, v);
  }
  h.set("Cache-Control", "no-store");
  h.set("X-Content-Type-Options", "nosniff");
  // The TV's pages: their own script and style; pictures (channel logos) from anywhere.
  h.set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data: blob:; img-src 'self' data: blob: https:; media-src 'self' blob:; frame-ancestors 'self'; form-action 'self'");
  if (r.s >= 300 && r.s < 400 && h.get("location")) {
    port.postMessage({ cancel: 1 });
    let to = h.get("location");
    if (to.startsWith("/")) to = prefix + to;
    const s = [301, 302, 303, 307, 308].includes(r.s) ? r.s : 302;
    return Response.redirect(new URL(to, u).href, s);
  }
  if (NO_BODY.has(r.s) || req.method === "HEAD") { port.postMessage({ cancel: 1 }); return new Response(null, { status: r.s, headers: h }); }
  const stream = new ReadableStream({
    start(c2) { ctrl = c2; early.splice(0).forEach(deliver); },
    pull() { port.postMessage({ pull: 1 }); },
    cancel() { port.postMessage({ cancel: 1 }); port.close(); },
  }, new ByteLengthQueuingStrategy({ highWaterMark: 1 << 20 }));
  return new Response(stream, { status: r.s, headers: h });
}
