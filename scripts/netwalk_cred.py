#!/usr/bin/env python3
"""netwalk-login credential intake.

Serves a one-shot HTML form on 127.0.0.1 so the user can type credentials into a
browser instead of pasting them into a chat. The form POSTs back to this same
process, which writes a 0600 vault file and exits.

Design rules (do not relax these):
  * The vault lives under ~/.netwalk/creds/ (0700 dir, 0600 files) - never inside
    a git repo, never inside the Obsidian vault, never inside a scan record.
  * The agent MUST NOT read the vault file. It calls `list` (which prints only
    metadata) and hands the site slug to netwalk_exec.py.
  * Private KEY MATERIAL is never accepted - only a path to a key file.
  * Bound to loopback + a random URL token + JSON-only POST, so another page open
    in the same browser cannot post into it.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import secrets
import sys
import time
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netwalk_common as C  # noqa: E402

MAX_BODY = 256 * 1024

VENDORS = [
    "mikrotik", "cisco", "aruba", "hp", "ubiquiti", "ruckus", "fortinet",
    "tplink", "juniper", "extreme", "dell", "synology", "linux", "windows", "unknown",
]
METHODS = [
    ("key", "SSH key file"),
    ("password", "SSH password"),
    ("key+password", "SSH key + enable/secondary password"),
    ("api", "HTTP API token"),
    ("skip", "Skip this device"),
]

KEY_MATERIAL_MARKERS = ("-----BEGIN", "PRIVATE KEY", "ssh-rsa ", "ssh-ed25519 ")

# Access details are NOT secrets - a URL, a port, a jump host, a tenant id. They still
# belong on this form rather than in the chat, because the person who knows them is the
# one sitting at the browser, and asking for them one at a time in conversation turns a
# survey into an interrogation. They are stored alongside the secrets but, unlike the
# secrets, `answers` prints them back.
ACCESS_FIELDS = [
    ("mgmt_url", "Management URL or address",
     "https://10.2.30.10:8443  — if it differs from the IP above"),
    ("jump_host", "Reach it through (SSH jump host)",
     "user@10.100.2.30  — leave blank for a direct connection"),
    ("tenant", "Site / tenant / VDOM id",
     "UniFi site id, FortiGate VDOM, controller site name"),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def vault_path(site: str) -> Path:
    return C.creds_dir() / f"{C.slugify(site)}.json"


def load_vault(site: str) -> dict:
    p = vault_path(site)
    if not p.exists():
        return {"site": site, "created_at": now_iso(), "hosts": {}}
    return json.loads(p.read_text(encoding="utf-8"))


def write_vault(site: str, data: dict) -> tuple[Path, bool, str]:
    p = vault_path(site)
    ok, how = C.write_private(p, json.dumps(data, indent=2))
    return p, ok, how


# --------------------------------------------------------------------------- form

FORM_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#12151a;--muted:#5b6472;--line:#dfe3e9;
--accent:#1f6feb;--warn:#8a5a00;--warnbg:#fff8e6;--ok:#0f7b45}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#161a20;--ink:#e6e9ee;
--muted:#98a2b3;--line:#252b34;--accent:#4c8dff;--warn:#ffd479;--warnbg:#2a2110;--ok:#4ade80}}
*{box-sizing:border-box}
body{margin:0;padding:28px 18px 64px;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}
.wrap{max-width:860px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 20px;font-size:13px}
.note{background:var(--warnbg);color:var(--warn);border:1px solid var(--line);
border-radius:10px;padding:12px 14px;font-size:13px;margin:0 0 22px}
.note b{display:block;margin-bottom:4px}
.host{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:16px 18px;margin:0 0 14px}
.host h2{font-size:15px;margin:0 0 2px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.host .meta{color:var(--muted);font-size:12.5px;margin:0 0 12px}
.row{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 10px}
.f{flex:1 1 180px;min-width:0}
label{display:block;font-size:12px;color:var(--muted);margin:0 0 4px}
input,select{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;
background:var(--bg);color:var(--ink);font:14px ui-monospace,SFMono-Regular,Menlo,monospace}
input:focus,select:focus{outline:2px solid var(--accent);outline-offset:-1px}
.hidden{display:none}
.more{margin:8px 0 0;border-top:1px dashed var(--line);padding-top:8px}
.more summary{cursor:pointer;font-size:12.5px;color:var(--muted)}
.more .row{margin-top:10px}
.asks{margin:10px 0 0;padding:10px 12px;border-radius:9px;background:var(--bg);
border:1px solid var(--accent)}
.askhead{margin:0 0 8px;font-size:12.5px;font-weight:600;color:var(--accent)}
.bar{position:sticky;bottom:0;background:var(--bg);padding:14px 0 0;border-top:1px solid var(--line);
margin-top:22px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
button{background:var(--accent);color:#fff;border:0;border-radius:9px;padding:11px 22px;
font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
#status{font-size:13px;color:var(--muted)}
#status.ok{color:var(--ok);font-weight:600}
#status.err{color:#d23}
"""

FORM_JS = """
function sync(el){
  var card=el.closest('.host'), m=el.value;
  card.querySelectorAll('[data-when]').forEach(function(f){
    var show=f.dataset.when.split(' ').indexOf(m)>=0;
    f.classList.toggle('hidden',!show);
    f.querySelectorAll('input').forEach(function(i){i.disabled=!show});
  });
}
document.querySelectorAll('select[name=method]').forEach(function(s){sync(s);s.addEventListener('change',function(){sync(s)})});
document.getElementById('f').addEventListener('submit',function(e){
  e.preventDefault();
  var out={}, bad=null;
  document.querySelectorAll('.host').forEach(function(c){
    var id=c.dataset.host, g=function(n){var el=c.querySelector('[name='+n+']');return el&&!el.disabled?el.value.trim():''};
    var m=g('method');
    var skipAns={};
    c.querySelectorAll('[name^="ask::"]').forEach(function(el){
      if(el.value.trim()) skipAns[el.name.slice(5)]=el.value.trim();
    });
    if(m==='skip'){ if(Object.keys(skipAns).length) out[id]={method:'skip',answers:skipAns}; return; }
    var kp=g('key_path');
    if(/-----BEGIN|PRIVATE KEY/.test(kp)) bad='"'+id+'": paste the PATH to the key file, not the key itself.';
    var ans={};
    c.querySelectorAll('[name^="ask::"]').forEach(function(el){
      if(el.value.trim()) ans[el.name.slice(5)]=el.value.trim();
    });
    out[id]={ip:c.dataset.ip,vendor:c.dataset.vendor,method:m,port:g('port')||'22',
      username:g('username'),password:g('password'),key_path:kp,
      enable_password:g('enable_password'),api_token:g('api_token'),note:g('note'),
      mgmt_url:g('mgmt_url'),jump_host:g('jump_host'),tenant:g('tenant'),answers:ans};
  });
  var st=document.getElementById('status');
  if(bad){st.className='err';st.textContent=bad;return}
  if(!Object.keys(out).length){st.className='err';st.textContent='Nothing to save - every device is set to Skip and no question was answered.';return}
  st.className='';st.textContent='Saving...';
  document.getElementById('go').disabled=true;
  fetch(SAVE_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hosts:out})})
    .then(function(r){return r.json()})
    .then(function(j){
      if(j.ok){st.className='ok';st.textContent='Saved '+j.count+' device(s) to '+j.path+' (0600). You can close this tab.';
        document.getElementById('f').querySelectorAll('input,select').forEach(function(i){i.disabled=true});}
      else{st.className='err';st.textContent=j.error||'Save failed';document.getElementById('go').disabled=false}
    })
    .catch(function(){st.className='err';st.textContent='Could not reach the local receiver - it may have timed out. Re-run /netwalk-login.';
      document.getElementById('go').disabled=false});
});
"""


def field(label: str, name: str, placeholder: str = "", type_: str = "text", when: str | None = None) -> str:
    attr = f' data-when="{when}"' if when else ""
    return (
        f'<div class="f"{attr}><label>{html.escape(label)}</label>'
        f'<input type="{type_}" name="{name}" placeholder="{html.escape(placeholder)}" '
        f'autocomplete="off" autocapitalize="off" spellcheck="false"></div>'
    )


def render_form(site: str, hosts: list[dict], save_url: str, existing: dict,
                asks: list[dict] | None = None) -> str:
    asks = asks or []

    def asks_for(hid: str) -> str:
        mine = [a for a in asks if a["host"] in (hid, "*")]
        if not mine:
            return ""
        rows = "".join(
            f'<div class="f"><label>{html.escape(a["label"])}</label>'
            f'<input type="text" name="ask::{html.escape(a["key"])}" '
            f'placeholder="{html.escape(a.get("placeholder", ""))}" '
            f'autocomplete="off" spellcheck="false"></div>' for a in mine)
        return (f'<div class="asks"><p class="askhead">The assistant needs to know:</p>'
                f'<div class="row">{rows}</div></div>')

    cards = []
    for h in hosts:
        hid = h["id"]
        known = existing.get(hid, {})
        badge = ' <span style="color:var(--ok)">&#9679; already stored</span>' if known else ""
        opts = "".join(
            f'<option value="{v}"{" selected" if known.get("method") == v else ""}>{html.escape(t)}</option>'
            for v, t in METHODS
        )
        cards.append(f"""
<div class="host" data-host="{html.escape(hid)}" data-ip="{html.escape(h.get('ip',''))}" data-vendor="{html.escape(h.get('vendor','unknown'))}">
  <h2>{html.escape(hid)}{badge}</h2>
  <p class="meta">{html.escape(h.get('ip','no IP'))} &middot; {html.escape(h.get('vendor','unknown'))}
     {(' &middot; ' + html.escape(h['note'])) if h.get('note') else ''}</p>
  <div class="row">
    <div class="f"><label>How do we get in?</label><select name="method">{opts}</select></div>
    {field('Port', 'port', '22', when='key password key+password api')}
    {field('Username', 'username', 'admin', when='key password key+password api')}
  </div>
  <div class="row">
    {field('SSH key file path', 'key_path', '~/.ssh/id_ed25519', when='key key+password')}
    {field('Password', 'password', '', 'password', when='password key+password')}
    {field('Enable / secondary password', 'enable_password', '', 'password', when='key+password')}
    {field('API token', 'api_token', '', 'password', when='api')}
  </div>
  <div class="row">{field('Note (optional)', 'note', 'e.g. read-only account, jumps via 10.0.0.9', when='key password key+password api')}</div>
  <details class="more"><summary>Access details — how to reach it (optional, not secret)</summary>
    <div class="row">{''.join(field(lbl, k, ph) for k, lbl, ph in ACCESS_FIELDS)}</div>
  </details>
  {asks_for(hid)}
</div>""")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>netwalk-login &middot; {html.escape(site)}</title><style>{FORM_CSS}</style></head><body>
<div class="wrap">
<h1>netwalk-login</h1>
<p class="sub">Site <b>{html.escape(site)}</b> &middot; {len(hosts)} device(s) discovered</p>
<div class="note"><b>This page is served from your own machine (127.0.0.1) and nothing leaves it.</b>
What you type here is written straight to a 0600 file under <code>~/.netwalk/creds/</code>.
It is never sent to the chat, never written into a scan record, and never included in a report.
Give a <i>path</i> to your SSH key &mdash; never paste the key itself. This receiver stops as soon as you save.</div>
<form id="f">{''.join(cards)}
<div class="bar"><button id="go" type="submit">Save credentials</button><span id="status"></span></div>
</form></div>
<script>var SAVE_URL={json.dumps(save_url)};{FORM_JS}</script></body></html>"""


# --------------------------------------------------------------------------- server

class Receiver(BaseHTTPRequestHandler):
    server_version = "netwalk-login"
    sys_version = ""
    token = ""
    site = ""
    hosts: list[dict] = []
    existing: dict = {}
    asks: list[dict] = []
    result: dict | None = None

    def log_message(self, fmt, *a):  # noqa: A003 - the URL carries the token; never log it
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _authorised(self) -> bool:
        return self.path.rstrip("/").endswith("/" + type(self).token)

    def _own_origins(self) -> set[str]:
        port = self.server.server_address[1]
        return {f"http://127.0.0.1:{port}", f"http://localhost:{port}",
                f"http://[::1]:{port}"}

    def do_GET(self):  # noqa: N802
        if not self._authorised():
            return self._send(404, b"not found", "text/plain")
        page = render_form(type(self).site, type(self).hosts,
                           f"/{type(self).token}/save", type(self).existing,
                           type(self).asks)
        self._send(200, page.encode(), "text/html; charset=utf-8")

    def do_POST(self):  # noqa: N802
        cls = type(self)
        if self.path.rstrip("/") != f"/{cls.token}/save":
            return self._send(404, b"not found", "text/plain")
        # Browsers attach Origin to EVERY POST, same-origin included, so "has an
        # Origin" is not an attack signal - "has the WRONG Origin" is. Compare it
        # against our own listener instead of rejecting the header outright.
        origin = self.headers.get("Origin")
        if origin and origin.rstrip("/").lower() not in self._own_origins():
            return self._json(403, {"ok": False,
                                    "error": "this form was not served by this listener"})
        # A cross-origin page still cannot reach us without a preflight, which the
        # JSON content-type forces and we never answer.
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._json(415, {"ok": False, "error": "expected application/json"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._json(400, {"ok": False, "error": "bad length"})
        if length <= 0 or length > MAX_BODY:
            return self._json(413, {"ok": False, "error": "body too large or empty"})
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return self._json(400, {"ok": False, "error": "malformed json"})

        vault = load_vault(cls.site)
        vault.setdefault("hosts", {})
        count = 0
        for hid, spec in (payload.get("hosts") or {}).items():
            if not isinstance(spec, dict):
                continue
            method = str(spec.get("method") or "").strip()
            answers = {str(k): str(v) for k, v in (spec.get("answers") or {}).items()}
            if method in ("", "skip"):
                # a device we cannot log into may still be the one the user answered
                # questions about - keep the answers, drop nothing
                if answers:
                    prev = vault["hosts"].get(hid, {})
                    prev.setdefault("method", "skip")
                    prev["answers"] = {**prev.get("answers", {}), **answers}
                    prev["stored_at"] = now_iso()
                    vault["hosts"][hid] = prev
                    count += 1
                continue
            key_path = str(spec.get("key_path") or "").strip()
            if any(m in key_path for m in KEY_MATERIAL_MARKERS):
                return self._json(400, {"ok": False,
                                        "error": f'"{hid}": that looks like key material. Give the file path instead.'})
            if key_path:
                key_path = os.path.expanduser(key_path)
            entry = {
                "ip": str(spec.get("ip") or "").strip(),
                "vendor": str(spec.get("vendor") or "unknown").strip().lower(),
                "method": method,
                "port": int(str(spec.get("port") or "22") or 22),
                "username": str(spec.get("username") or "").strip(),
                "password": spec.get("password") or None,
                "key_path": key_path or None,
                "enable_password": spec.get("enable_password") or None,
                "api_token": spec.get("api_token") or None,
                "note": str(spec.get("note") or "").strip(),
                "mgmt_url": str(spec.get("mgmt_url") or "").strip() or None,
                "jump_host": str(spec.get("jump_host") or "").strip() or None,
                "tenant": str(spec.get("tenant") or "").strip() or None,
                "answers": answers,
                "stored_at": now_iso(),
            }
            vault["hosts"][hid] = entry
            count += 1

        if not count:
            return self._json(400, {"ok": False, "error": "nothing to store"})
        vault["updated_at"] = now_iso()
        path, ok, how = write_vault(cls.site, vault)
        cls.result = {"count": count, "path": str(path), "perm_ok": ok, "perm": how}
        self._json(200, {"ok": True, "count": count, "path": str(path),
                         "perm_ok": ok, "perm": how})


def cmd_request(args: argparse.Namespace) -> int:
    hosts = []
    for spec in args.host:
        parts = (spec.split(",") + ["", "", ""])[:4]
        hid = parts[0].strip()
        if not hid:
            raise SystemExit(f"netwalk_cred: bad --host {spec!r} (want id[,ip[,vendor[,note]]])")
        hosts.append({"id": hid, "ip": parts[1].strip(),
                      "vendor": (parts[2].strip() or "unknown").lower(), "note": parts[3].strip()})
    if not hosts:
        raise SystemExit("netwalk_cred: at least one --host is required")

    asks = []
    for spec in args.ask:
        parts = (spec.split("|") + ["", "", ""])[:4]
        if not parts[1].strip():
            raise SystemExit(f"netwalk_cred: bad --ask {spec!r} (want HOST|key|Label|placeholder)")
        asks.append({"host": parts[0].strip() or "*", "key": parts[1].strip(),
                     "label": parts[2].strip() or parts[1].strip(),
                     "placeholder": parts[3].strip()})

    existing = load_vault(args.site).get("hosts", {})
    Receiver.token = secrets.token_urlsafe(24)
    Receiver.site = args.site
    Receiver.hosts = hosts
    Receiver.existing = existing
    Receiver.asks = asks

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Receiver)
    httpd.timeout = 1
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/{Receiver.token}"
    print(f"NETWALK_LOGIN_URL {url}", flush=True)
    waiting = ("waiting until stopped" if args.timeout <= 0
               else f"waiting up to {args.timeout}s")
    print(f"{waiting} for the form to be submitted "
          f"({len(hosts)} device(s), site={args.site})", file=sys.stderr, flush=True)
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            print("could not open a browser automatically - open the URL above yourself",
                  file=sys.stderr)

    # --timeout 0 means no deadline. A listener that dies on its own takes the URL
    # with it - the token and port are fresh every run - so mid-engagement the least
    # surprising behaviour is to keep waiting until someone stops it.
    deadline = None if args.timeout <= 0 else time.monotonic() + args.timeout
    try:
        while Receiver.result is None and (deadline is None or time.monotonic() < deadline):
            httpd.handle_request()
    except KeyboardInterrupt:
        print("\nstopped before anything was submitted", file=sys.stderr)
    httpd.server_close()

    if Receiver.result is None:
        print("TIMEOUT no credentials submitted", file=sys.stderr)
        return 2
    r = Receiver.result
    print(f"SAVED {r['count']} host(s) -> {r['path']}")
    print(f"protection: {r['perm']}")
    if not r["perm_ok"]:
        print("WARNING the credential file could NOT be locked down on this machine. "
              "Treat it as readable by anyone with local access, and run "
              "`netwalk_cred.py forget --site <site>` as soon as the job is done.",
              file=sys.stderr)
    return 0


def cmd_set_key(args: argparse.Namespace) -> int:
    """Register a key-only credential straight from the CLI.

    Deliberately accepts NO password, token or passphrase - not as a convenience but
    as a guarantee. A key path is not a secret and never needed the browser round
    trip; a password on a command line lands in shell history, in the process list
    and in any transcript watching the terminal, so it has to stay in the form.
    """
    key = os.path.expanduser(args.key_path)
    if any(m in args.key_path for m in KEY_MATERIAL_MARKERS):
        raise SystemExit("netwalk_cred: that is key material, not a path. Pass a file path.")
    if not os.path.exists(key):
        print(f"WARNING key file does not exist: {key}", file=sys.stderr)

    vault = load_vault(args.site)
    vault.setdefault("hosts", {})[args.host] = {
        "ip": args.ip or args.host, "vendor": (args.vendor or "unknown").lower(),
        "method": "key", "port": args.port, "username": args.username,
        "password": None, "key_path": key, "enable_password": None,
        "api_token": None, "note": args.note or "", "stored_at": now_iso(),
    }
    vault["updated_at"] = now_iso()
    path, ok, how = write_vault(args.site, vault)
    print(f"stored key credential for {args.host} -> {path}")
    print(f"protection: {how}")
    if not ok:
        print("WARNING could not lock the file down on this machine", file=sys.stderr)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    p = vault_path(args.site)
    if not p.exists():
        print(f"no credential store for site {args.site!r} (expected {p})")
        return 1
    vault = load_vault(args.site)
    rows = []
    for hid, e in sorted(vault.get("hosts", {}).items()):
        have = [k for k in ("password", "key_path", "enable_password", "api_token") if e.get(k)]
        rows.append((hid, e.get("ip", ""), e.get("vendor", ""), e.get("method", ""),
                     e.get("username", ""), ",".join(have) or "-", e.get("note", "")))
    if not rows:
        print("vault exists but holds no hosts")
        return 1
    w = [max(len(str(r[i])) for r in rows + [("HOST", "IP", "VENDOR", "METHOD", "USER", "HAS", "NOTE")]) for i in range(7)]
    hdr = ("HOST", "IP", "VENDOR", "METHOD", "USER", "HAS", "NOTE")
    print("  ".join(h.ljust(w[i]) for i, h in enumerate(hdr)))
    for r in rows:
        print("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))
    print(f"\n{len(rows)} host(s) in {p} [{C.perm_report(p)}]"
          f" - secret VALUES are never printed by this tool")
    return 0


def cmd_answers(args: argparse.Namespace) -> int:
    """Print the non-secret access details. Safe for the assistant to read - by
    construction it touches no field that can authenticate anything."""
    p = vault_path(args.site)
    if not p.exists():
        print(f"no store for site {args.site!r}")
        return 1
    vault = load_vault(args.site)
    SAFE = ("ip", "port", "vendor", "method", "username", "note",
            "mgmt_url", "jump_host", "tenant")
    shown = 0
    for hid, e in sorted(vault.get("hosts", {}).items()):
        if args.host and hid != args.host:
            continue
        bits = {k: e.get(k) for k in SAFE if e.get(k)}
        answers = e.get("answers") or {}
        if not bits and not answers:
            continue
        shown += 1
        print(f"\n{hid}")
        for k, v in bits.items():
            print(f"  {k:<12}{v}")
        for k, v in answers.items():
            print(f"  {k:<12}{v}   (answered on the form)")
    if not shown:
        print("nothing recorded yet")
        return 1
    print("\nSecret values are deliberately absent from this output.")
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    p = vault_path(args.site)
    if not p.exists():
        print(f"nothing to forget for {args.site!r}")
        return 0
    if args.host:
        vault = load_vault(args.site)
        removed = [h for h in args.host if vault.get("hosts", {}).pop(h, None) is not None]
        write_vault(args.site, vault)
        print(f"removed {len(removed)} host(s): {', '.join(removed) or '(none matched)'}")
        return 0
    C.shred(p)
    print(f"deleted {p} (overwritten first; on a copy-on-write or SSD filesystem that "
          f"is not a forensic wipe - rotate the credentials if that matters)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="netwalk_cred.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("request", help="serve the intake form and wait for a submit")
    r.add_argument("--site", required=True)
    r.add_argument("--host", action="append", default=[],
                   metavar="id[,ip[,vendor[,note]]]", help="repeat once per device")
    r.add_argument("--port", type=int, default=0, help="0 = pick a free port")
    r.add_argument("--timeout", type=int, default=900,
                   help="seconds to wait for a submit; 0 = wait until stopped")
    r.add_argument("--no-open", action="store_true", help="do not launch a browser")
    r.add_argument("--ask", action="append", default=[],
                   metavar="HOST|key|Label|placeholder",
                   help="put a question on the form instead of asking in the chat. "
                        "HOST is a host id or * for every card. Repeatable.")
    r.set_defaults(func=cmd_request)

    k = sub.add_parser("set-key", help="register a KEY-ONLY credential from the CLI "
                                       "(no password option, by design)")
    k.add_argument("--site", required=True)
    k.add_argument("--host", required=True)
    k.add_argument("--ip")
    k.add_argument("--vendor", default="unknown")
    k.add_argument("--username", required=True)
    k.add_argument("--key-path", required=True, help="path to the private key file")
    k.add_argument("--port", type=int, default=22)
    k.add_argument("--note", default="")
    k.set_defaults(func=cmd_set_key)

    l = sub.add_parser("list", help="show WHICH hosts have credentials - never the values")
    l.add_argument("--site", required=True)
    l.set_defaults(func=cmd_list)

    a = sub.add_parser("answers", help="print the non-secret access details "
                                       "(URL, port, jump host, tenant, form answers)")
    a.add_argument("--site", required=True)
    a.add_argument("--host")
    a.set_defaults(func=cmd_answers)

    f = sub.add_parser("forget", help="delete stored credentials")
    f.add_argument("--site", required=True)
    f.add_argument("--host", action="append", default=[], help="omit to shred the whole site vault")
    f.set_defaults(func=cmd_forget)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
