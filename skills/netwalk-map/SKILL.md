---
name: netwalk-map
description: "Draw a network topology diagram from a netwalk scan record. Produces a self-contained SVG with a vendor logo, hostname, management IP, model, OS version and live CPU/RAM/storage/temperature per device, one box per internet uplink, and port labels on every link. Use when the user asks for a network diagram, topology map or visual of a scanned site, or wants the picture refreshed after more devices were found."
---

# netwalk-map

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `{{TOOLKIT}}`.

## Run it

```bash
python3 {{TOOLKIT}}/scripts/netwalk_map.py ~/.netwalk/sites/acme-hq/scan-2026-08-22.json \
  -o ~/.netwalk/sites/acme-hq/map.svg \
  [--public] [--title "Acme HQ — after the switch swap"] [--top-down] [--no-group-aps]
```

Output is one self-contained SVG: no external fonts, no scripts, no network requests. It opens in a
browser, drops into a document, and follows the reader's light/dark setting. `netwalk-fullreport`
embeds the same renderer, so the diagram in the report and the standalone file never drift apart.

`--public` drops the scan date and the unreachable-device count from the caption.

## The record is the source of truth

The renderer draws only what the record says. **Never hand-edit the SVG** — fix the record and
re-render, or the diagram and the report start telling different stories and the next scan silently
reverts your edit.

Layout is deterministic and reads **left to right**, the way a packet travels: internet uplinks in
a column on the left, then the gateway, then each layer of switching, then the edge. Devices are
ranked by BFS depth from the gateway and ordered inside each rank to minimise crossings. A rank with
more devices than fit in one column wraps into another column rather than running off the page.
Same record in, same SVG out — so two scans of one site diff cleanly and a changed diagram means a
changed network.

`--top-down` stacks it vertically instead, which suits a shallow network or a portrait page.

## What the record needs for a good diagram

| Field | Effect if missing |
|---|---|
| `devices[].vendor` | falls back to a lettered chip instead of a logo |
| `devices[].hostname`, `mgmt_ip` | the box is hard to identify |
| `devices[].model`, `os_version` | the version line is empty — and version is what people read a diagram for at upgrade time |
| `devices[].role` | everything lands in one flat rank and the layout stops meaning anything |
| `devices[].health` | no CPU/RAM/storage/temperature chips |
| `topology_edges[].a_port` / `b_port` | links have no port labels, so nobody can trace a cable from the picture |
| `wan_links[]` | no uplink boxes at all |

Chips turn red past CPU 80%, RAM 85%, storage 85%, 65 °C — so an overloaded box is visible in the
picture, not just in a table.

## Access points are grouped per switch

A site with a hundred APs draws a hundred boxes and a comb of a hundred lines: accurate, unreadable,
and not what anyone opens a diagram for. Every AP whose only uplink is one switch is collapsed into
a single node on that switch showing **how many APs, the address range they occupy, the model mix,
and how many are up versus down**. The per-device detail is still in the report's inventory table —
only the picture groups them.

An AP with more than one uplink (a mesh AP, or one with a second cable) is never collapsed: its
extra link is exactly the thing a diagram exists to show. Pass `--no-group-aps` to draw every access
point separately.

## Conventions worth keeping

- **One box per internet uplink.** Primary and backup are separate boxes with ISP, IP and speed.
  Never merge them into a single "INTERNET" cloud — which link is which is the whole point.
- **Dashed = inferred.** Any edge with `discovered_via: "inferred"` is drawn dashed, and inferred
  devices (a suspected unmanaged switch) get a dashed red outline. Do not promote a guess to a solid
  line to make the picture tidier.
- **Unreachable devices still appear**, dashed, with the reason on the box. A device you could not
  log into is part of the network and leaving it out makes the map a lie.
- **`role` drives the layers**, left to right: `gateway`/`router`/`firewall` →
  `l3-switch`/`controller` → `switch` → `ap`/`server`/`nas`/`nvr` → everything else.
- **Port names sit above a link, the link's own label below it.** A short run between two adjacent
  ranks would otherwise print the port name straight through the speed label.

## Logos

`{{TOOLKIT}}/assets/logos/<vendor>.svg`, 24×24 viewBox, one path or text element, monochrome so it
can inherit the theme colour. To add a vendor, drop in `<vendor>.svg` matching the `vendor` string
in the record (or add an alias in `LOGO_ALIAS` in `netwalk_map.py`). No logo is not an error — the
device gets a lettered chip.

## If it looks wrong

- **Boxes overlapping or the picture is enormous** — usually many devices in one rank because
  `role` is missing or everything is `unknown`. Fix the roles.
- **Very tall (left to right) or very wide (top down)** — one rank holds far more devices than the
  others. Check the AP grouping did what you expected, then consider the other orientation.
- **A device floating with no links** — no `topology_edges` entry references it. Either you did not
  derive the edge, or it genuinely is not connected to anything you scanned; say which.
- **Wrong parent** — a discovery frame seen on a bridge/VLAN interface was recorded as a direct
  link. Prefer the physical port when the neighbour output names one.
- **Text clipped** — long hostnames are truncated on purpose to keep boxes uniform; the full name is
  in the report's inventory table.
