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
import urllib.parse
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
# "I don't know" has to be an answer the form can give back. A crawl finds devices
# nobody remembers installing, and a blank card is ambiguous - did the user not know,
# or not get to it? Saying so explicitly is a real result: it goes in the report as a
# device the site owner could not identify, which is usually worth knowing.
METHODS = [
    ("key", "SSH key file"),
    ("password", "SSH password"),
    ("key+password", "SSH key + enable/secondary password"),
    ("api", "HTTP API token"),
    ("known-no-cred", "I know what it is \u2014 but I have no login for it"),
    ("unknown", "I don't know what this device is"),
    ("not-ours", "Not ours / out of scope — do not touch it"),
    ("skip", "Skip for now, ask me again later"),
]
# Verdicts that carry no credential. "known-no-cred" is the useful one: the device
# gets documented - what it is, what it does, who owns it - even though netwalk will
# never log into it. That turns a blank in the report into a described device that
# simply was not surveyed, which is a much more honest thing to hand a site owner.
NO_CREDENTIAL = ("known-no-cred", "unknown", "not-ours", "skip")

DEVICE_KINDS = [
    ("", "role, if you know it"), ("switch", "Switch"), ("ap", "Access point"),
    ("router", "Router"), ("gateway", "Gateway / firewall"), ("controller", "Controller"),
    ("server", "Server"), ("nas", "NAS / storage"), ("nvr", "NVR / camera recorder"),
    ("client", "Camera / phone / endpoint"), ("printer", "Printer"), ("ups", "UPS"),
    ("unmanaged-switch", "Unmanaged switch"), ("unknown", "Something else"),
]

KEY_MATERIAL_MARKERS = ("-----BEGIN", "PRIVATE KEY", "ssh-rsa ", "ssh-ed25519 ")

# Access details are NOT secrets - a URL, a port, a jump host, a tenant id. They still
# belong on this form rather than in the chat, because the person who knows them is the
# one sitting at the browser, and asking for them one at a time in conversation turns a
# survey into an interrogation. They are stored alongside the secrets but, unlike the
# secrets, `answers` prints them back.
ACCESS_FIELDS = [
    ("mgmt_url", "Management URL or address",
     "https://192.0.2.10:8443  — if it differs from the IP above"),
    ("jump_host", "Reach it through (SSH jump host)",
     "user@192.0.2.1  — leave blank for a direct connection"),
    ("tenant", "Site / tenant / VDOM id",
     "UniFi site id, FortiGate VDOM, controller site name"),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sessions_dir() -> Path:
    d = C.netwalk_home() / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    C.harden_path(d, is_dir=True)
    return d


def session_file(site: str) -> Path:
    return sessions_dir() / f"{C.slugify(site)}.session.json"


def hosts_file(site: str) -> Path:
    return sessions_dir() / f"{C.slugify(site)}.hosts.json"


def load_hosts_state(site: str) -> dict:
    p = hosts_file(site)
    if not p.exists():
        return {"version": 0, "hosts": [], "asks": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"version": 0, "hosts": [], "asks": []}


def save_hosts_state(site: str, state: dict) -> None:
    C.write_private(hosts_file(site), json.dumps(state, indent=2))


def parse_hosts(specs: list[str]) -> list[dict]:
    out = []
    for spec in specs:
        parts = (spec.split(",") + ["", "", ""])[:4]
        hid = parts[0].strip()
        if not hid:
            raise SystemExit(f"netwalk_cred: bad --host {spec!r} (want id[,ip[,vendor[,note]]])")
        out.append({"id": hid, "ip": parts[1].strip(),
                    "vendor": (parts[2].strip() or "unknown").lower(), "note": parts[3].strip()})
    return out


def parse_asks(specs: list[str]) -> list[dict]:
    out = []
    for spec in specs:
        parts = (spec.split("|") + ["", "", ""])[:4]
        if not parts[1].strip():
            raise SystemExit(f"netwalk_cred: bad --ask {spec!r} (want HOST|key|Label|placeholder)")
        out.append({"host": parts[0].strip() or "*", "key": parts[1].strip(),
                    "label": parts[2].strip() or parts[1].strip(),
                    "placeholder": parts[3].strip()})
    return out


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
--accent:#1f6feb;--warn:#8a5a00;--warnbg:#fff8e6;--ok:#0f7b45;--okbg:#e9f7ef}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#161a20;--ink:#e6e9ee;
--muted:#98a2b3;--line:#252b34;--accent:#4c8dff;--warn:#ffd479;--warnbg:#2a2110;--ok:#4ade80;
--okbg:#12261a}}
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
.live{display:flex;gap:10px;align-items:flex-start;background:var(--card);
border:1px solid var(--ok);border-radius:10px;padding:11px 14px;margin:0 0 16px;font-size:13.5px}
.live .dot{width:9px;height:9px;border-radius:50%;background:var(--ok);flex:0 0 9px;margin-top:5px;
animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.toast{max-height:0;overflow:hidden;opacity:0;transition:.35s;background:var(--accent);color:#fff;
border-radius:9px;font-size:13.5px;font-weight:600;margin:0 0 0}
.toast.show{max-height:60px;opacity:1;padding:10px 14px;margin:0 0 14px}
.cardstate{font:600 11.5px var(--sans);color:var(--muted);margin-top:8px;min-height:14px}
.cardstate.ok{color:var(--ok)}
.badge{font:600 10.5px var(--sans);padding:2px 7px;border-radius:99px;vertical-align:2px}
.badge.done{background:var(--okbg,#e9f7ef);color:var(--ok)}
.badge.new{background:var(--accent);color:#fff}
.host.isnew{border-color:var(--accent)}
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
  var pf=card.querySelector('[name=port]');
  if(pf){ pf.placeholder=PORT_FOR[m]||'22'; if(!pf.dataset.touched) pf.value=''; }
  card.querySelectorAll('[data-when]').forEach(function(f){
    var show=f.dataset.when.split(' ').indexOf(m)>=0;
    f.classList.toggle('hidden',!show);
    f.querySelectorAll('input').forEach(function(i){i.disabled=!show});
  });
}
var PORT_FOR={key:'22',password:'22','key+password':'22',api:'8443'};

function wire(card){
  card.querySelectorAll('[name=port]').forEach(function(p){
    p.addEventListener('input',function(){p.dataset.touched='1'});
  });
  card.querySelectorAll('input,select').forEach(function(el){
    el.addEventListener('input',function(){card.dataset.dirty='1';mark(card,'')});
    el.addEventListener('change',function(){card.dataset.dirty='1';mark(card,'')});
  });
  var sel=card.querySelector('select[name=method]');
  if(sel){ sync(sel); sel.addEventListener('change',function(){sync(sel)}); }
}
function mark(card,txt,cls){
  var el=card.querySelector('.cardstate');
  if(el){ el.textContent=txt||''; el.className='cardstate '+(cls||''); }
}
document.querySelectorAll('.host').forEach(wire);

function collect(all){
  var out={}, bad=null;
  document.querySelectorAll('.host').forEach(function(c){
    var id=c.dataset.host;
    var g=function(n){var el=c.querySelector('[name='+n+']');return el&&!el.disabled?el.value.trim():''};
    var m=g('method');
    // only send what the user actually touched, so a re-save never re-transmits a
    // credential that is already stored and never wipes one with a blank field
    if(!all && c.dataset.dirty!=='1') return;
    if(!m) return;
    var ans={};
    c.querySelectorAll('[name^="ask::"]').forEach(function(el){
      if(el.value.trim()) ans[el.name.slice(5)]=el.value.trim();
    });
    if(m==='skip'||m==='unknown'||m==='not-ours'||m==='known-no-cred'){
      out[id]={method:m,ip:c.dataset.ip,vendor:c.dataset.vendor,
               note:(c.querySelector('[name=note]:not([disabled])')||{}).value||'',
               described:g('described'),role_hint:g('role_hint'),
               purpose:g('purpose'),owner:g('owner'),answers:ans};
      return;
    }
    var kp=g('key_path');
    if(/-----BEGIN|PRIVATE KEY/.test(kp)) bad='"'+id+'": paste the PATH to the key file, not the key itself.';
    out[id]={ip:c.dataset.ip,vendor:c.dataset.vendor,method:m,
      port:g('port')||(m==='api'?'8443':'22'),
      username:g('username'),password:g('password'),key_path:kp,
      enable_password:g('enable_password'),api_token:g('api_token'),note:g('note'),
      mgmt_url:g('mgmt_url'),jump_host:g('jump_host'),tenant:g('tenant'),answers:ans};
  });
  return {out:out,bad:bad};
}

document.getElementById('f').addEventListener('submit',function(e){
  e.preventDefault();
  var st=document.getElementById('status'), r=collect(false);
  if(r.bad){st.className='err';st.textContent=r.bad;return}
  var ids=Object.keys(r.out);
  if(!ids.length){st.className='';st.textContent='Nothing new to save - fill something in first.';return}
  st.className='';st.textContent='Saving '+ids.length+' device(s)...';
  document.getElementById('go').disabled=true;
  fetch(SAVE_URL,{method:'POST',headers:{'Content-Type':'application/json'},
                  body:JSON.stringify({hosts:r.out})})
    .then(function(x){return x.json()})
    .then(function(j){
      document.getElementById('go').disabled=false;
      if(!j.ok){st.className='err';st.textContent=j.error||'Save failed';return}
      st.className='ok';st.textContent='Saved '+j.count+' device(s). Leave this tab open - the scan will add more as it finds them.';
      ids.forEach(function(id){
        var c=document.querySelector('.host[data-host="'+id+'"]');
        if(c){c.dataset.dirty='0';c.dataset.saved='1';c.classList.remove('isnew');
              mark(c,'saved','ok');}
      });
    })
    .catch(function(){document.getElementById('go').disabled=false;
      st.className='err';st.textContent='Could not reach the local receiver. It may have been stopped.';});
});

// The scan keeps running while this page is open. Poll for devices it finds and
// append them, never re-rendering a card the user might be typing into.
var VERSION=INITIAL_VERSION;
function poll(){
  fetch(STATE_URL+'?since='+VERSION,{headers:{'Accept':'application/json'}})
    .then(function(r){return r.json()})
    .then(function(j){
      if(!j || j.version===VERSION) return;
      VERSION=j.version;
      var added=0, list=document.getElementById('cards');
      (j.cards||[]).forEach(function(c){
        if(document.querySelector('.host[data-host="'+c.host+'"]')) return;
        var tmp=document.createElement('div'); tmp.innerHTML=c.html;
        var el=tmp.firstElementChild;
        list.appendChild(el); wire(el); added++;
      });
      if(added){
        var n=document.getElementById('newcount');
        n.textContent=added+' new device'+(added>1?'s':'')+' found by the scan just now';
        n.className='toast show';
        setTimeout(function(){n.className='toast'},9000);
      }
    })
    .catch(function(){});
}
setInterval(poll,4000);
"""


def field(label: str, name: str, placeholder: str = "", type_: str = "text", when: str | None = None) -> str:
    attr = f' data-when="{when}"' if when else ""
    return (
        f'<div class="f"{attr}><label>{html.escape(label)}</label>'
        f'<input type="{type_}" name="{name}" placeholder="{html.escape(placeholder)}" '
        f'autocomplete="off" autocapitalize="off" spellcheck="false"></div>'
    )


def select_field(label: str, name: str, options: list, when: str | None = None) -> str:
    attr = f' data-when="{when}"' if when else ""
    opts = "".join(f'<option value="{html.escape(v)}">{html.escape(t)}</option>' for v, t in options)
    return (f'<div class="f"{attr}><label>{html.escape(label)}</label>'
            f'<select name="{name}">{opts}</select></div>')


def render_form(site: str, hosts: list[dict], save_url: str, existing: dict,
                asks: list[dict] | None = None, rnd: int = 0, version: int = 1,
                state_url: str = "", persistent: bool = False) -> str:
    asks = asks or []
    round_note = f" &middot; crawl round {rnd}" if rnd else ""

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

    cards = [_card(h, existing, asks_for) for h in hosts]
    return page_html(site, hosts, save_url, existing, cards, round_note,
                     version, state_url, persistent)


def _card(h: dict, existing: dict, asks_for) -> str:
    """One device card. Rendered on its own so the server can inject cards the crawl
    discovers later, without reloading a page the user may be typing into."""
    if True:
        hid = h["id"]
        known = existing.get(hid, {})
        if known:
            m = known.get("method", "")
            label = {"unknown": "you said you did not recognise this",
                     "not-ours": "you marked this out of scope",
                     "skip": "you skipped this last time"}.get(m, "already answered")
            badge = f' <span class="badge done">&#9679; {html.escape(label)}</span>'
        else:
            badge = ' <span class="badge new">NEW this round</span>' 
        opts = "".join(
            f'<option value="{v}"{" selected" if known.get("method") == v else ""}>{html.escape(t)}</option>'
            for v, t in METHODS
        )
        return (f"""
<div class="host{'' if known else ' isnew'}" data-host="{html.escape(hid)}" data-ip="{html.escape(h.get('ip',''))}" data-vendor="{html.escape(h.get('vendor','unknown'))}">
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
  <div class="row">{field('Note (optional)', 'note', 'e.g. read-only account, jumps via 192.0.2.9', when='key password key+password api')}
    {field('Anything you can say about it?', 'note', 'e.g. "was here when we took the site over" — helps the report', when='unknown not-ours')}</div>
  <div class="row">
    {field('What is it?', 'described', 'e.g. Ricoh MP C4504 printer, staff room', when='known-no-cred')}
    {select_field('Role', 'role_hint', DEVICE_KINDS, when='known-no-cred')}
  </div>
  <div class="row">
    {field('What is it for?', 'purpose', 'e.g. serves the CCTV recorder for the north building', when='known-no-cred')}
    {field('Who looks after it?', 'owner', 'e.g. the CCTV contractor, or "us"', when='known-no-cred')}
  </div>
  <details class="more"><summary>Access details — how to reach it (optional, not secret)</summary>
    <div class="row">{''.join(field(lbl, k, ph) for k, lbl, ph in ACCESS_FIELDS)}</div>
  </details>
  {asks_for(hid)}
  <div class="cardstate"></div>
</div>""")


def page_html(site, hosts, save_url, existing, cards, round_note,
              version=1, state_url="", persistent=False) -> str:
    live = ("""<div class="live"><span class="dot"></span>This page stays open for the whole survey.
Fill in what you know, press Save, and leave the tab up &mdash; as the scan finds more devices they
appear here on their own and you can add them whenever you like. Save as many times as you want;
only the cards you changed are sent.</div>"""
            if persistent else
            """<p class="sub">This receiver stops as soon as you save.</p>""")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>netwalk-login &middot; {html.escape(site)}</title><style>{FORM_CSS}</style></head><body>
<div class="wrap">
<h1>netwalk-login</h1>
<p class="sub">Site <b>{html.escape(site)}</b>{round_note} &middot; <span id="count">{len(hosts)}</span> device(s),
{sum(1 for h in hosts if h["id"] not in existing)} of them not yet answered</p>
{live}
<div class="note"><b>This page is served from your own machine (127.0.0.1) and nothing leaves it.</b>
What you type here is written straight to a 0600 file under <code>~/.netwalk/creds/</code>.
It is never sent to the chat, never written into a scan record, and never included in a report.
Give a <i>path</i> to your SSH key &mdash; never paste the key itself.
<br><br>If you do not recognise a device, say so with <b>&ldquo;I don&rsquo;t know what this is&rdquo;</b> rather
than leaving it blank &mdash; an unidentified device on the network is a finding, and a blank card just looks
like an unanswered question. If you <i>do</i> know what it is but have no login for it, pick
<b>&ldquo;I know what it is&rdquo;</b> and describe it &mdash; it will appear in the report as a documented
device that simply was not surveyed, which is far more useful than a blank. Anything you mark
<b>Not ours</b> will not be logged into at all.</div>
<div id="newcount" class="toast"></div>
<form id="f"><div id="cards">{''.join(cards)}</div>
<div class="bar"><button id="go" type="submit">Save credentials</button><span id="status"></span></div>
</form></div>
<script>var SAVE_URL={json.dumps(save_url)};
var STATE_URL={json.dumps(state_url or save_url.replace("/save", "/state"))};
var INITIAL_VERSION={int(version)};
{FORM_JS}</script></body></html>"""


# --------------------------------------------------------------------------- server

class Receiver(BaseHTTPRequestHandler):
    server_version = "netwalk-login"
    sys_version = ""
    token = ""
    site = ""
    hosts: list[dict] = []
    existing: dict = {}
    asks: list[dict] = []
    rnd: int = 0
    version: int = 1
    persistent: bool = False
    saves: int = 0
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

    def _refresh(self):
        """Re-read what the crawl has discovered. `add` writes the file, the server
        never has to be restarted, and the URL the user has open stays valid."""
        cls = type(self)
        if not cls.persistent:
            return
        st = load_hosts_state(cls.site)
        cls.hosts = st.get("hosts", cls.hosts)
        cls.asks = st.get("asks", cls.asks)
        cls.version = st.get("version", cls.version)
        cls.existing = load_vault(cls.site).get("hosts", {})

    def do_GET(self):  # noqa: N802
        cls = type(self)
        if not self._authorised() and not self.path.rstrip("/").startswith(f"/{cls.token}/"):
            return self._send(404, b"not found", "text/plain")
        self._refresh()
        if self.path.split("?")[0].rstrip("/") == f"/{cls.token}/state":
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                since = int((q.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            if since >= cls.version:
                return self._json(200, {"version": cls.version, "cards": []})

            def asks_for(hid):
                mine = [a for a in cls.asks if a["host"] in (hid, "*")]
                if not mine:
                    return ""
                rows = "".join(
                    f'<div class="f"><label>{html.escape(a["label"])}</label>'
                    f'<input type="text" name="ask::{html.escape(a["key"])}" '
                    f'placeholder="{html.escape(a.get("placeholder", ""))}" '
                    f'autocomplete="off" spellcheck="false"></div>' for a in mine)
                return (f'<div class="asks"><p class="askhead">The assistant needs to know:'
                        f'</p><div class="row">{rows}</div></div>')

            cards = [{"host": h["id"], "html": _card(h, cls.existing, asks_for)}
                     for h in cls.hosts]
            return self._json(200, {"version": cls.version, "cards": cards})

        if not self._authorised():
            return self._send(404, b"not found", "text/plain")
        page = render_form(cls.site, cls.hosts, f"/{cls.token}/save", cls.existing,
                           cls.asks, cls.rnd, version=cls.version,
                           state_url=f"/{cls.token}/state", persistent=cls.persistent)
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
            if method in ("", *NO_CREDENTIAL):
                # No credential, but the answer itself matters: "I don't know what this
                # is" and "not ours" are results the report needs. Never fabricate a
                # credential here and never delete one the host already had.
                if not method:
                    continue
                prev = vault["hosts"].get(hid, {})
                prev["method"] = method
                prev.setdefault("ip", str(spec.get("ip") or "").strip())
                prev.setdefault("vendor", str(spec.get("vendor") or "unknown").strip().lower())
                if str(spec.get("note") or "").strip():
                    prev["note"] = str(spec["note"]).strip()
                for k in ("described", "role_hint", "purpose", "owner"):
                    v = str(spec.get(k) or "").strip()
                    if v:
                        prev[k] = v
                if answers:
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
        cls.saves += 1
        cls.existing = vault.get("hosts", {})
        cls.result = {"count": count, "path": str(path), "perm_ok": ok, "perm": how}
        print(f"[{now_iso()}] saved {count} device(s) (submission #{cls.saves})",
              file=sys.stderr, flush=True)
        self._json(200, {"ok": True, "count": count, "path": str(path),
                         "perm_ok": ok, "perm": how})
        if cls.persistent:
            cls.result = None      # keep serving; the page stays usable


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
    Receiver.rnd = args.round

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


def cmd_serve(args: argparse.Namespace) -> int:
    """Serve the form for the whole survey instead of for one submission.

    A crawl finds devices over minutes, and the person answering wants to fill in what
    they know now and come back to the rest. So the listener stays up, the URL stays
    valid, `add` pushes newly discovered devices into the page while it is open, and
    Save can be pressed as many times as the user likes.
    """
    state = load_hosts_state(args.site)
    new = parse_hosts(args.host)
    known = {h["id"] for h in state["hosts"]}
    state["hosts"] += [h for h in new if h["id"] not in known]
    seen = {(a["host"], a["key"]) for a in state["asks"]}
    state["asks"] += [a for a in parse_asks(args.ask) if (a["host"], a["key"]) not in seen]
    state["version"] = state.get("version", 0) + 1
    if not state["hosts"]:
        raise SystemExit("netwalk_cred: serve needs at least one --host to start with")
    save_hosts_state(args.site, state)

    Receiver.token = secrets.token_urlsafe(24)
    Receiver.site = args.site
    Receiver.hosts = state["hosts"]
    Receiver.asks = state["asks"]
    Receiver.existing = load_vault(args.site).get("hosts", {})
    Receiver.version = state["version"]
    Receiver.rnd = args.round
    Receiver.persistent = True

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Receiver)
    httpd.timeout = 1
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/{Receiver.token}"
    C.write_private(session_file(args.site), json.dumps(
        {"url": url, "port": port, "pid": os.getpid(), "started_at": now_iso()}, indent=2))

    print(f"NETWALK_LOGIN_URL {url}", flush=True)
    print(f"serving {len(state['hosts'])} device(s) for site={args.site}. The page stays open; "
          f"run `netwalk_cred.py add --site {args.site} --host ...` to push new devices into it. "
          f"Ctrl-C to stop.", file=sys.stderr, flush=True)
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass

    try:
        while True:
            httpd.handle_request()
    except KeyboardInterrupt:
        print(f"\nstopped after {Receiver.saves} submission(s)", file=sys.stderr)
    finally:
        httpd.server_close()
        session_file(args.site).unlink(missing_ok=True)
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    """Push newly discovered devices into a form that is already open."""
    state = load_hosts_state(args.site)
    known = {h["id"] for h in state["hosts"]}
    fresh = [h for h in parse_hosts(args.host) if h["id"] not in known]
    seen = {(a["host"], a["key"]) for a in state["asks"]}
    new_asks = [a for a in parse_asks(args.ask) if (a["host"], a["key"]) not in seen]
    if not fresh and not new_asks:
        print("nothing new to add - every device and question is already on the form")
        return 0
    state["hosts"] += fresh
    state["asks"] += new_asks
    state["version"] = state.get("version", 0) + 1
    save_hosts_state(args.site, state)

    sf = session_file(args.site)
    where = ""
    if sf.exists():
        try:
            where = json.loads(sf.read_text(encoding="utf-8")).get("url", "")
        except json.JSONDecodeError:
            where = ""
    print(f"added {len(fresh)} device(s) and {len(new_asks)} question(s); "
          f"the open form picks them up within a few seconds")
    if where:
        print(f"form: {where}")
    else:
        print("no form is currently serving this site - start one with "
              f"`netwalk_cred.py serve --site {args.site} --host ...`", file=sys.stderr)
    return 0


def cmd_url(args: argparse.Namespace) -> int:
    sf = session_file(args.site)
    if not sf.exists():
        print(f"no form is serving site {args.site!r}")
        return 1
    info = json.loads(sf.read_text(encoding="utf-8"))
    print(info.get("url", ""))
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    sf = session_file(args.site)
    if not sf.exists():
        print(f"no form is serving site {args.site!r}")
        return 1
    info = json.loads(sf.read_text(encoding="utf-8"))
    pid = info.get("pid")
    try:
        os.kill(int(pid), 15)
        print(f"stopped the form for {args.site} (pid {pid})")
    except (OSError, TypeError, ValueError) as e:
        print(f"could not stop pid {pid}: {e}", file=sys.stderr)
        return 1
    sf.unlink(missing_ok=True)
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
        if e.get("method") in NO_CREDENTIAL:
            have = [{"unknown": "not recognised", "not-ours": "OUT OF SCOPE",
                     "skip": "deferred",
                     "known-no-cred": "described, no login"}[e["method"]]]
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
            "mgmt_url", "jump_host", "tenant",
            "described", "role_hint", "purpose", "owner")
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


EXPORT_HEADER = """# Site access document \u2014 {site}

Generated by netwalk on {when}.

"""

SECRET_BANNER = """> **THIS FILE CONTAINS LIVE PASSWORDS AND TOKENS.**
> It was written with mode 0600. Do not email it, do not commit it, do not put it in
> the customer report, and delete it when the documentation it feeds is finished.
> If it has been anywhere it should not have, rotate every credential listed below.

"""

SAFE_BANNER = """Credentials are deliberately **not** in this file \u2014 only how to reach each device
and which account to use. Pass `--with-secrets` if you really need the values, and read
what that flag says before you do.

"""


def cmd_export(args: argparse.Namespace) -> int:
    """Write the access details as a document the engineer can build on.

    Two audiences, two different files. The customer report never contains any of
    this - the report renderer refuses to build from a record with credential
    material in it. This is the engineer's own working document, written to a path
    they choose, and by default it still carries no secret values: what a site
    document actually needs is which device, which address, which account and which
    route in - not the password itself.
    """
    p = vault_path(args.site)
    if not p.exists():
        print(f"no credential store for site {args.site!r}")
        return 1
    out = Path(args.out).expanduser().resolve()
    forbidden = [C.sites_dir().resolve()]
    for bad in forbidden:
        if bad in out.parents or out == bad:
            raise SystemExit(
                f"netwalk_cred: refusing to write into {bad} - that folder holds the "
                f"artefacts you hand to the customer. Choose a path outside it.")
    if args.with_secrets and not args.i_understand:
        raise SystemExit(
            "netwalk_cred: --with-secrets writes live passwords to disk. Re-run with "
            "--i-understand-this-file-contains-passwords if that is really what you want.")

    vault = load_vault(args.site)
    hosts = vault.get("hosts", {})
    if not hosts:
        print("the store holds no hosts")
        return 1

    lines = [EXPORT_HEADER.format(site=args.site, when=now_iso()),
             SECRET_BANNER if args.with_secrets else SAFE_BANNER]
    verdict = {"unknown": "not recognised by the site owner",
               "not-ours": "OUT OF SCOPE - do not connect",
               "skip": "deferred",
               "known-no-cred": "identified, no login available"}
    for hid, e in sorted(hosts.items()):
        lines.append(f"## {hid}\n")
        rows = [("Address", e.get("ip")), ("Port", e.get("port")),
                ("Vendor", e.get("vendor")), ("Account", e.get("username")),
                ("How", verdict.get(e.get("method"), e.get("method"))),
                ("Management URL", e.get("mgmt_url")),
                ("Reached through", e.get("jump_host")),
                ("Site / tenant", e.get("tenant")),
                ("What it is", e.get("described")), ("Role", e.get("role_hint")),
                ("Purpose", e.get("purpose")), ("Looked after by", e.get("owner")),
                ("Note", e.get("note"))]
        if e.get("key_path"):
            rows.append(("SSH key file", e["key_path"]))
        if args.with_secrets:
            for label, key in (("Password", "password"), ("Enable password", "enable_password"),
                               ("API token", "api_token")):
                if e.get(key):
                    rows.append((label, f"`{e[key]}`"))
        else:
            held = [n for n, k in (("password", "password"), ("enable password", "enable_password"),
                                   ("API token", "api_token")) if e.get(k)]
            if held:
                rows.append(("Stored secrets", ", ".join(held) + " (values not in this file)"))
        for label, val in rows:
            if val not in (None, "", []):
                lines.append(f"- **{label}:** {val}")
        for k, v in (e.get("answers") or {}).items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    ok, how = C.write_private(out, "\n".join(lines))
    print(f"wrote {out}  [{how}]")
    print(f"  {len(hosts)} device(s)"
          + ("  \u2014 WITH live secret values" if args.with_secrets
             else "  \u2014 access details only, no secret values"))
    if args.with_secrets:
        print("  Delete it when you are done, and never attach it to the customer report.",
              file=sys.stderr)
    if not ok:
        print("  WARNING could not lock the file down on this machine", file=sys.stderr)
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
    r.add_argument("--round", type=int, default=0,
                   help="crawl round number, shown in the form header")
    r.add_argument("--ask", action="append", default=[],
                   metavar="HOST|key|Label|placeholder",
                   help="put a question on the form instead of asking in the chat. "
                        "HOST is a host id or * for every card. Repeatable.")
    r.set_defaults(func=cmd_request)

    sv = sub.add_parser("serve", help="serve the form for the whole survey and keep it open")
    sv.add_argument("--site", required=True)
    sv.add_argument("--host", action="append", default=[],
                    metavar="id[,ip[,vendor[,note]]]")
    sv.add_argument("--ask", action="append", default=[], metavar="HOST|key|Label|placeholder")
    sv.add_argument("--port", type=int, default=0)
    sv.add_argument("--round", type=int, default=0)
    sv.add_argument("--no-open", action="store_true")
    sv.set_defaults(func=cmd_serve)

    ad = sub.add_parser("add", help="push newly discovered devices into the open form")
    ad.add_argument("--site", required=True)
    ad.add_argument("--host", action="append", default=[], metavar="id[,ip[,vendor[,note]]]")
    ad.add_argument("--ask", action="append", default=[], metavar="HOST|key|Label|placeholder")
    ad.set_defaults(func=cmd_add)

    u = sub.add_parser("url", help="print the URL of the form currently serving this site")
    u.add_argument("--site", required=True)
    u.set_defaults(func=cmd_url)

    sp = sub.add_parser("stop", help="stop the form serving this site")
    sp.add_argument("--site", required=True)
    sp.set_defaults(func=cmd_stop)

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

    ex = sub.add_parser("export", help="write the access details as a document for the "
                                       "engineer - never for the customer report")
    ex.add_argument("--site", required=True)
    ex.add_argument("--out", required=True, help="path OUTSIDE the site folder")
    ex.add_argument("--with-secrets", action="store_true",
                    help="include live passwords and tokens (needs the acknowledgement flag)")
    ex.add_argument("--i-understand-this-file-contains-passwords", dest="i_understand",
                    action="store_true")
    ex.set_defaults(func=cmd_export)

    f = sub.add_parser("forget", help="delete stored credentials")
    f.add_argument("--site", required=True)
    f.add_argument("--host", action="append", default=[], help="omit to shred the whole site vault")
    f.set_defaults(func=cmd_forget)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
