// قنواتي — the remote page's service worker.
// The television's control page is shown in a frame at /r/app/. Every request
// that frame makes (pages, forms, images, downloads) is caught here and handed
// to the open remote page, which sends it to the TV over the encrypted session
// and returns the answer. Nothing under /r/app/ ever reaches the server.
"use strict";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

// …/r/ — this worker's own folder; the TV's page is under …/r/app/.
const BASE = new URL(self.registration.scope).pathname;
const APP = BASE + "app";

self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (u.origin !== self.location.origin || !u.pathname.startsWith(APP + "/")) return;
  e.respondWith(tunnel(e.request, u));
});

const NO_BODY = new Set([101, 204, 205, 304]);

function page(text, status) {
  return new Response(`<!doctype html><meta charset="utf-8"><body dir="rtl" style="font:16px system-ui;padding:24px">${text}</body>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

async function shell() {
  const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  const pages = all.filter((c) => { const p = new URL(c.url).pathname; return p === BASE || p === BASE + "index.html"; });
  return pages.find((c) => c.focused) || pages[0] || null;
}

async function tunnel(req, u) {
  const c = await shell();
  if (!c) return page("افتح صفحة الوصول عن بُعد أولاً.", 409);
  const body = req.method === "GET" || req.method === "HEAD" ? null : await req.arrayBuffer();
  const ch = new MessageChannel();
  const reply = new Promise((res) => {
    const t = setTimeout(() => res(null), 130000);
    ch.port1.onmessage = (m) => { clearTimeout(t); res(m.data); };
  });
  const path = u.pathname.slice(APP.length) + u.search;
  c.postMessage({ req: { m: req.method, p: path, ct: req.headers.get("content-type"), body } }, body ? [ch.port2, body] : [ch.port2]);
  const r = await reply;
  if (!r) return page("لم يرد التلفزيون في الوقت المحدد.", 504);

  const h = new Headers();
  for (const [k, v] of Object.entries(r.h || {})) {
    if (["content-type", "content-disposition", "location"].includes(k)) h.set(k, v);
  }
  h.set("Cache-Control", "no-store");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data: blob:; frame-ancestors 'self'; form-action 'self'");
  if (r.s >= 300 && r.s < 400 && h.get("location")) {
    let to = h.get("location");
    if (to.startsWith("/")) to = APP + to;
    const s = [301, 302, 303, 307, 308].includes(r.s) ? r.s : 302;
    return Response.redirect(new URL(to, u).href, s);
  }
  return new Response(NO_BODY.has(r.s) ? null : r.body, { status: r.s, headers: h });
}
