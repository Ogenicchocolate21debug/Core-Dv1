---
name: netwalk-login
description: "Collect device credentials for a netwalk survey through a local browser form instead of the chat. Serves a one-shot page on 127.0.0.1 where the user types usernames, passwords, SSH key PATHS or API tokens; the values are written to a private file on their machine and the assistant never sees them. Use when a scan needs to log into a device and there is no working credential yet, when a hop fails authentication, or when the user asks how to give access without pasting secrets."
---

# netwalk-login

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `{{TOOLKIT}}`.

## The one rule

**Never accept a credential in the conversation.** Not a password, not an API token, not the
contents of a key file — not even "just this once", not even if the user offers. Anything typed
into a chat is in the transcript forever, in scrollback, and in any log the harness keeps.

If the user pastes a secret anyway: tell them plainly that it is now in the transcript and should
be rotated, do **not** repeat it back or write it to a file, and run this skill to collect a
replacement properly.

A **path** to a key file (`~/.ssh/id_ed25519`, `C:\Users\me\.ssh\id_rsa`) is not a secret and is
fine to discuss. The key's *contents* never are.

## How it works

`netwalk_cred.py request` starts a throwaway HTTP listener on `127.0.0.1` with a random port and a
random URL token, opens the user's browser at it, and serves a form listing exactly the devices you
name. When the user hits Save, the browser POSTs back to that same local process, which writes
`~/.netwalk/creds/<site>.json` — `0600` on macOS/Linux, an owner-only ACL via `icacls` on Windows —
and exits. Nothing is transmitted off the machine and nothing passes through you.

## Steps

1. **Work out which devices need access.** Usually this is the list `netwalk-scan` just discovered
   and could not log into, plus the entry point if this is the start of a survey. You need, per
   device: a stable id (hostname or IP), the IP, and the vendor if you know it.

2. **Pick a site slug** — short, lowercase, no spaces (`acme-hq`, `branch-02`). Everything else in
   netwalk keys off it. Reuse the existing slug if the site has been scanned before; running the
   form again updates devices in place and leaves the rest alone.

3. **Serve the form:**

   ```bash
   python3 {{TOOLKIT}}/scripts/netwalk_cred.py request \
     --site acme-hq \
     --host 'gw01,192.168.1.1,mikrotik,entry point - user has this one' \
     --host 'sw-core,192.168.1.2,cisco' \
     --host 'ap-01,192.168.1.11,ubiquiti,found via LLDP'
   ```

   Each `--host` is `id[,ip[,vendor[,note]]]`. The note is shown on the card — use it to remind the
   user *why* you are asking for this device. Add `--no-open` if a browser should not be launched,
   `--timeout 1800` for a long session.

   The command prints `NETWALK_LOGIN_URL <url>` and then blocks. **Tell the user the URL** in case
   the browser did not open, and say plainly that you cannot see what they type.

4. **Wait.** It exits by itself on save. On success it prints `SAVED n host(s)` and the protection
   that was applied. If it prints a `WARNING` that the file could not be locked down (a Windows box
   with no `icacls`, an exotic filesystem), pass that warning on to the user verbatim — do not
   quietly accept it — and offer to `forget` the store as soon as the survey is finished.

5. **Confirm without looking.** `list` prints which hosts have which *kind* of credential and never
   a value:

   ```bash
   python3 {{TOOLKIT}}/scripts/netwalk_cred.py list --site acme-hq
   ```

6. **Prove each login works before handing back to the scan:**

   ```bash
   python3 {{TOOLKIT}}/scripts/netwalk_exec.py probe --site acme-hq --host gw01
   ```

   `REACHABLE` means the credential is good and the vendor profile matched. `FAILED` prints the SSH
   error — read it before re-asking. `Permission denied` is a wrong credential; `Connection refused`
   or a timeout is a reachability problem and asking for a new password will not fix it.

## Choosing the auth method on the form

| Method | Use when | Notes |
|---|---|---|
| SSH key file | there is a key on this machine | Give the **path**. Best option — no secret is stored by netwalk at all. |
| SSH password | the device only does passwords | Needs a helper: `paramiko` (any OS), `sshpass` (macOS/Linux) or `plink` (Windows). Run the preflight below if unsure. |
| SSH key + password | key login plus an enable/secondary password | e.g. Cisco `enable` |
| API token | the vendor is driven over HTTP, not SSH | netwalk stores it; you drive the API yourself. `netwalk_exec.py` only speaks SSH. |
| Skip | you do not have access and are not getting it | The device stays in the record as `reachable: false` with a reason. That is a legitimate result — say so in the report rather than leaving a gap. |

Environment check when password auth is in play:

```bash
python3 {{TOOLKIT}}/scripts/netwalk_common.py
```

## Cleaning up

Offer this at the end of every engagement, especially for someone else's network:

```bash
python3 {{TOOLKIT}}/scripts/netwalk_cred.py forget --site acme-hq            # whole site
python3 {{TOOLKIT}}/scripts/netwalk_cred.py forget --site acme-hq --host ap-01
```

The file is overwritten before deletion, which is not a forensic wipe on an SSD or a
copy-on-write filesystem. If the credentials were sensitive, tell the user to rotate them.

## Hard boundaries

- Never `cat`, `Read`, `type` or otherwise open `~/.netwalk/creds/*.json`. You do not need the
  values — `netwalk_exec.py` reads them for you. Opening it puts the secret in your context and
  therefore in the transcript.
- Never echo a credential into a scan record, a report, a diagram, a commit, or a note.
- Never write credentials to a password manager, a cloud service, or a repo on the user's behalf.
- If a `--json` run of `netwalk_exec.py` ever surfaces something secret-looking in device output,
  that is device config, not the vault — still keep it out of the report. `netwalk_report.py`
  refuses to render a record containing credential material, but do not rely on that as your
  first line of defence.

Next: `netwalk-scan` to crawl, or `netwalk-diag` if you already have the topology.
