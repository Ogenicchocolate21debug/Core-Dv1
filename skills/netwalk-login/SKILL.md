---
name: netwalk-login
description: "Collect device credentials for a netwalk survey through a local browser form instead of the chat. Serves a one-shot page on 127.0.0.1 where the user types usernames, passwords, SSH key PATHS or API tokens; the values are written to a private file on their machine and the assistant never sees them. Use when a scan needs to log into a device and there is no working credential yet, when a hop fails authentication, or when the user asks how to give access without pasting secrets."
---

# netwalk-login

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `{{TOOLKIT}}`.

## The two rules

**1. Never accept a credential in the conversation.** Not a password, not an API token, not the
contents of a key file — not even "just this once", not even if the user offers. Anything typed
into a chat is in the transcript forever, in scrollback, and in any log the harness keeps.

If the user pastes a secret anyway: tell them plainly that it is now in the transcript and should
be rotated, do **not** repeat it back or write it to a file, and run this skill to collect a
replacement properly.

A **path** to a key file (`~/.ssh/id_ed25519`, `C:\Users\me\.ssh\id_rsa`) is not a secret and is
fine to discuss. The key's *contents* never are.

**2. Anything you need to know about *how to reach* a device goes on the form too.**

Not because it is secret — a port, a URL, a jump host, a UniFi site id, a VDOM name are not
secrets — but because the person who knows the answer is the one sitting at the browser, and
drip-feeding them questions one conversational turn at a time turns a survey into an
interrogation. Put every open question on the form, let them answer in one pass, and read the
answers back with `answers`.

Every card already carries an **Access details** section (management URL, SSH jump host,
site/tenant id). For anything beyond that, attach your own question with `--ask`:

```bash
--ask 'unifi-ctrl|reach_how|How do you normally reach this controller? URL and port|https://192.0.2.10:8443'
--ask '*|window|When can we reboot, if it comes to that?|'
```

Format is `HOST|key|Label|placeholder`, repeatable; `*` puts the question on every card. Answers
come back through `answers --site <slug>`, which prints access details and question answers and
never prints a secret. A device set to **Skip** still records its answers — "why can't we get in"
is often the most useful thing on the page.

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

3. **Serve the form — and leave it up for the whole survey.**

   `serve` keeps the page alive instead of exiting on the first submit. The user fills in what they
   know now, presses Save, and leaves the tab open; as the crawl finds more devices you push them
   into the same page with `add`, and they appear within a few seconds without the URL changing.
   Only the cards the user actually edited are re-sent, so saving again never re-transmits a
   credential that is already stored.

   ```bash
   python3 {{TOOLKIT}}/scripts/netwalk_cred.py serve --site acme-hq \
     --host 'gw01,192.0.2.1,mikrotik,entry point'

   # later, mid-crawl, as neighbours turn up:
   python3 {{TOOLKIT}}/scripts/netwalk_cred.py add --site acme-hq \
     --host 'sw-core,192.0.2.2,cisco,found via LLDP on gw01 ether8' \
     --ask 'sw-core|why|What does this switch feed?|'

   python3 {{TOOLKIT}}/scripts/netwalk_cred.py url  --site acme-hq   # re-share the link
   python3 {{TOOLKIT}}/scripts/netwalk_cred.py stop --site acme-hq   # when the survey is done
   ```

   Start `serve` once, at the beginning. Do not stop and restart it to add a device — the URL is
   regenerated every time and the user loses the tab they had open.

   The one-shot form is still there as `request` for a single question, but `serve` is the default
   for a survey.

4. **Or, for a single question, serve it once:**

   ```bash
   python3 {{TOOLKIT}}/scripts/netwalk_cred.py request \
     --site acme-hq \
     --host 'gw01,192.0.2.1,mikrotik,entry point - user has this one' \
     --host 'sw-core,192.0.2.2,cisco' \
     --host 'ap-01,192.0.2.11,ubiquiti,found via LLDP'
   ```

   Each `--host` is `id[,ip[,vendor[,note]]]`. The note is shown on the card — use it to remind the
   user *why* you are asking for this device. Add `--no-open` if a browser should not be launched,
   `--timeout 1800` for a long session.

   The command prints `NETWALK_LOGIN_URL <url>` and then blocks. **Tell the user the URL** in case
   the browser did not open, and say plainly that you cannot see what they type.

   **Prefer handing this command to the user to run in their own terminal.** It waits on a human at
   a keyboard, which can be minutes, and an agent background task is the wrong place for that — it
   gets reaped, it hits a timeout, and when it dies the URL dies with it because the port and token
   are fresh on every run. In Claude Code the user can run it inline by prefixing `!`:

   ```
   ! python3 {{TOOLKIT}}/scripts/netwalk_cred.py request --site acme-hq --host 'gw01,192.0.2.1,mikrotik' --timeout 0
   ```

   `--timeout 0` waits until they stop it with Ctrl-C. Then continue from step 5 — `list` and
   `probe` tell you it worked without you ever seeing a value. Run it yourself only when the user
   is clearly at the keyboard and expecting it right now.

5. **Wait.** `request` exits by itself on save; `serve` keeps going. On success it prints `SAVED n host(s)` and the protection
   that was applied. If it prints a `WARNING` that the file could not be locked down (a Windows box
   with no `icacls`, an exotic filesystem), pass that warning on to the user verbatim — do not
   quietly accept it — and offer to `forget` the store as soon as the survey is finished.

6. **Confirm without looking.** `list` prints which hosts have which *kind* of credential and never
   a value:

   ```bash
   python3 {{TOOLKIT}}/scripts/netwalk_cred.py list --site acme-hq
   ```

7. **Read the non-secret answers back:**

   ```bash
   python3 {{TOOLKIT}}/scripts/netwalk_cred.py answers --site acme-hq
   ```

   This prints IP, port, vendor, username, management URL, jump host, tenant and every question
   answer. It is the one command in this skill you are meant to read the output of.

8. **Prove each login works before handing back to the scan:**

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
| API token | the vendor is driven over HTTP, not SSH — UniFi and Omada controllers | netwalk stores it; you drive the API yourself. `netwalk_exec.py` only speaks SSH. |
| I know what it is, no login | they can identify it but cannot give access | Fill in what it is, its role, what it is for and who owns it. The device is then documented in the report as a known device that was not surveyed - far more useful than a blank, and it gets a proper `role` on the diagram |
| Skip | you do not have access and are not getting it | The device stays in the record as `reachable: false` with a reason. Any questions on that card are still saved, and an existing credential is left alone — use `forget` to remove one. That is a legitimate result: say so in the report rather than leaving a gap. |

### Controller credentials

| Controller | Username field | API token field | Where the user finds it |
|---|---|---|---|
| UniFi (Network 9+) | — | API key | Control Plane → Admins → API keys |
| UniFi (older) | local admin | — | use the password field |
| Omada (Open API) | **client_id** | **client_secret** | Settings → Platform Integration → Open API |
| Omada (older) | controller admin | — | use the password field |

Put the controller's address in **Management URL** (`https://omada.example.com:8043`) — a controller
almost never answers on the port its devices use, and the port box defaults to SSH. Put the site id
in **Site / tenant** if they know it; both adapters will list the sites otherwise.

Environment check when password auth is in play:

```bash
python3 {{TOOLKIT}}/scripts/netwalk_common.py
```

## Giving the engineer something to document from

The customer report never contains a credential — the report renderer refuses to build from a record
that has any in it. But the engineer who ran the scan usually does need a site access document, and
that is a different file for a different audience:

```bash
# what a site document actually needs: which device, which address, which account,
# which route in - and no secret values at all
python3 {{TOOLKIT}}/scripts/netwalk_cred.py export --site acme-hq --out ~/Documents/acme-access.md

# only if they genuinely need the values, and only with both flags
python3 {{TOOLKIT}}/scripts/netwalk_cred.py export --site acme-hq --out ~/Documents/acme-secrets.md \
  --with-secrets --i-understand-this-file-contains-passwords
```

Both are written 0600. `export` refuses to write anywhere under the site folder, because that folder
holds the artefacts that get handed to the customer. Offer the default form; mention `--with-secrets`
only if they ask for the values, and say plainly that it puts live passwords on disk.

**Do not read either file.** You do not need to — you produced it for the user, not for yourself.

## Cleaning up

Offer this at the end of every engagement, especially for someone else's network:

```bash
python3 {{TOOLKIT}}/scripts/netwalk_cred.py forget --site acme-hq            # whole site
python3 {{TOOLKIT}}/scripts/netwalk_cred.py forget --site acme-hq --with-configs   # AND the config exports
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
