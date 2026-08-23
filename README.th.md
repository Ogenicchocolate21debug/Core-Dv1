# netwalk

*[English](README.md) · **ภาษาไทย***

**ชุดเครื่องมือสำรวจเครือข่ายแบบอ่านอย่างเดียว สำหรับ Claude Code** — ชี้ไปที่อุปกรณ์ตัวเดียวที่ล็อกอินได้
แล้ว netwalk จะเดินไล่เครือข่ายทีละ hop อ่านสุขภาพทุกตัวที่เจอ วาดผัง แล้วออกรายงานที่ส่งมอบเจ้าของไซต์ได้เลย

6 skill ใช้แยกกันก็ได้ หรือรันทั้งชุดเป็น workflow เดียว

```
/netwalk              สำรวจทั้งงาน ตั้งแต่ต้นจนจบ
/netwalk-login        เก็บ credential ผ่านฟอร์มในเบราว์เซอร์ ไม่ผ่านแชท
/netwalk-scan         crawl ผังเครือข่ายจากอุปกรณ์ตัวแรก
/netwalk-diag         export config แบบอ่านอย่างเดียว อ่าน health หาว่าอะไรพัง
/netwalk-map          วาดไดอะแกรม
/netwalk-fullreport   ออกรายงาน HTML ที่ส่งมอบได้
```

ใช้ได้บน **Windows, macOS และ Linux**

---

## สามคำสัญญา บังคับด้วยโค้ดทั้งหมด

### 1. netwalk ไม่แก้อะไรเลย

ทุกคำสั่งถูกตรวจกับ allowlist แบบอ่านอย่างเดียวของ vendor นั้น ๆ **ก่อนจะถูกส่งออกไป** การเขียน config,
`clear counters`, `dmesg -C`, `systemctl restart`, `reload`, `configure terminal` และ shell metacharacter
ถูกปฏิเสธโดยตัวเครื่องมือ — **ไม่ใช่ด้วย prompt ที่ขอร้องโมเดลดี ๆ** · config ถูก *export* ออกมาอ่าน
ไม่มีการ import กลับเข้าไปไม่ว่ากรณีใด

```
$ netwalk_exec.py check --vendor mikrotik --cmd '/interface print detail'
ALLOW [mikrotik] read-only

$ netwalk_exec.py check --vendor mikrotik --cmd '/interface print; /system reboot'
DENY  [mikrotik] contains command separator or redirection ';' - run one plain command at a time

$ netwalk_exec.py check --vendor cisco --cmd 'show running-config | redirect flash:x'
DENY  [cisco] pipes output into a file
```

allowlist อยู่ที่ `scripts/netwalk_policy.py` คุมด้วย `tests/test_policy.py` (**397 เคส** รวมทุกคำสั่งใน
pack ทุกไฟล์ที่แจกมาด้วย) — ถ้าจะขยาย allowlist ให้รันเทสต์

### 2. credential ไม่เคยเข้าไปในบทสนทนา

`/netwalk-login` เปิดหน้าเว็บใช้ครั้งเดียวบนเครื่องคุณเอง คุณพิมพ์รหัสลงในเบราว์เซอร์ รหัสนั้นถูกเขียนลงไฟล์ส่วนตัว
บนดิสก์ทันที (`0600` บน POSIX, ACL เจ้าของคนเดียวผ่าน `icacls` บน Windows) แล้ว listener ก็ปิดตัว
· ผู้ช่วยได้รับแค่ *path* ไม่เคยได้ค่า และตัว render รายงานจะ**ปฏิเสธไม่สร้างเอกสาร**ถ้า record มีข้อมูล credential ปนอยู่

**ฟอร์มนี้เข้าถึงจากที่อื่นในเครือข่ายไม่ได้** — listener ผูกกับ `127.0.0.1` (loopback) ไม่ใช่ `0.0.0.0`
kernel จึงไม่รับ packet ที่มาจาก host อื่นเลย เพื่อนร่วมงานที่อยู่ LAN เดียวกัน, แขกที่ต่อ Wi-Fi,
หรืออุปกรณ์ในเครือข่ายที่กำลังถูกสำรวจอยู่ **เปิดหน้านี้ไม่ได้ ต่อให้รู้เลขพอร์ต**

```
$ netwalk_cred.py serve --site acme-hq ...
   http://127.0.0.1:62742/Mnoc4Wmy1w80_h6RBlJgXXMPBs7VLkCk

$ lsof -nP -iTCP:62742 -sTCP:LISTEN          # บนเครื่องที่เปิดฟอร์ม
   Python  98900  TCP 127.0.0.1:62742 (LISTEN)      <- ไม่ใช่ *:62742

$ curl http://192.168.60.12:62742/            # จากเครื่องอื่น
   (connection refused)
```

มีอีก 4 ชั้นกั้นระหว่างหน้าเว็บกับคนที่ไม่ใช่คุณ:

| | |
|---|---|
| **พอร์ตสุ่ม** | สุ่มใหม่ทุกครั้ง ไม่เคยตายตัว |
| **URL token สุ่ม** | ต้องรู้ path (`/Mnoc4Wmy...`) ถึงจะได้อะไร ไม่รู้ = เซิร์ฟเวอร์ไม่ตอบ |
| **ปฏิเสธ POST ข้าม origin** | หน้าเว็บอื่นที่เปิดค้างในเบราว์เซอร์คุณยิงเข้ามาไม่ได้ — **นี่คือการโจมตีที่การผูก loopback อย่างเดียวกันไม่ได้** |
| **JSON เท่านั้น ครั้งเดียวจบ** | โหมด `request` ปิดตัวทันทีหลังรับข้อมูลที่รออยู่ |

**สิ่งที่ฟอร์มนี้กันไม่ได้ พูดตรง ๆ:** process อื่นที่รันในชื่อ user เดียวกันบนเครื่องคุณเอง เข้า loopback ได้
ซึ่งเป็น trust boundary เดียวกับไฟล์ `0600` อยู่แล้ว — ถ้าบัญชีคุณถูกเจาะ ฟอร์มนี้ไม่ใช่สิ่งที่ช่วยคุณ

### 3. netwalk ไม่ sweep ช่วง IP ที่ไม่มีใครอนุญาต

netwalk เดินไล่ออกจากอุปกรณ์ที่คุณระบุ และ**สามารถ sweep ช่วง IP ได้ด้วย** — แต่เฉพาะช่วงที่ถูกเขียนไว้ใน
scope ของไซต์นั้น **พร้อมชื่อคนที่อนุญาต** ซึ่งจะไปโผล่ในรายงานด้วย · การตรวจอยู่ในโค้ด และ**ไม่มี flag ให้ข้าม**

```
$ netwalk_sweep.py hosts --site acme-hq --range 198.51.100.0/24
DENY  198.51.100.0/24 is outside the authorised scope for this site
      (authorised: 192.0.2.0/24). Ask the owner and authorise it - there is no override flag
```

ช่วงที่อยู่นอก scope → ปฏิเสธ · **supernet ของช่วงที่อนุญาต → ปฏิเสธ** (อนุญาต /24 ไม่ได้แปลว่าอนุญาต /23
ที่ครอบ /24 นั้นอยู่) · public address space ถ้าไม่ใส่ flag ที่สองอย่างจงใจ → ปฏิเสธ เพราะการเป็นเจ้าของ IP เดียว
ใน /24 ของผู้ให้บริการ **ไม่ได้ทำให้อีก 253 ตัวเป็นของคุณ** · ใหญ่กว่า /16 → ปฏิเสธ · จำนวน probe
เกินเพดาน → ปฏิเสธ · คุมด้วย `tests/test_sweep.py` (81 เคส) และเคสที่สำคัญคือ**ฝั่งที่ปฏิเสธ**

---

## ติดตั้ง

```bash
git clone https://github.com/ripmilla/netwalk
cd netwalk
python3 install.py
```

คำสั่งนี้จะก๊อป runtime ไปที่ `~/.claude/skills/netwalk/toolkit/` แล้วเขียนโฟลเดอร์ skill ทั้ง 6 ตัว
โดยแทน path จริงบนเครื่องนี้ลงไป จากนั้นใน Claude Code พิมพ์:

```
/netwalk
```

ของเสริม:

```bash
python3 install.py --check                          # รายงานสภาพแวดล้อม
python3 ~/.claude/skills/netwalk/toolkit/scripts/netwalk_logos.py fetch    # โลโก้ vendor
python3 ~/.claude/skills/netwalk/toolkit/tests/test_policy.py              # self-test
python3 install.py --uninstall
```

### ใช้กับ AI agent ยี่ห้ออื่น

netwalk มีสองชั้น: **สคริปต์ Python ล้วนที่ไม่ต้องมี agent เลย** กับชุดคำสั่งที่บอก agent ว่าจะขับสคริปต์พวกนั้นยังไง
มีแค่ชั้นที่สองที่เป็นของ Claude โดยเฉพาะ และ `AGENTS.md` คือคำสั่งชุดเดียวกันในรูปที่ agent ยี่ห้อไหนก็อ่านได้

```bash
python3 /path/to/netwalk/install.py --agent cursor     # .cursor/rules/netwalk.mdc
python3 /path/to/netwalk/install.py --agent codex      # AGENTS.md
python3 /path/to/netwalk/install.py --agent gemini     # GEMINI.md
python3 /path/to/netwalk/install.py --agent cline      # .clinerules/netwalk.md
python3 /path/to/netwalk/install.py --agent copilot    # .github/copilot-instructions.md
python3 /path/to/netwalk/install.py --agent windsurf   # .windsurf/rules/netwalk.md
python3 /path/to/netwalk/install.py --agent continue   # .continue/rules/netwalk.md
python3 /path/to/netwalk/install.py --agent aider      # CONVENTIONS.md
python3 /path/to/netwalk/install.py --agent generic    # AGENTS.md สำหรับตัวอื่น ๆ
```

path เต็มของ clone คุณจะถูกแทนลงไปให้ ทุกคำสั่งในไฟล์จึง copy-paste ได้เลย · ไฟล์คำสั่งที่มีอยู่แล้วจะถูก
**เขียนต่อท้าย ไม่ทับของเดิม**

**ไม่มี agent เลยล่ะ?** ทุกอย่างรันจากเทอร์มินัลได้ — `install.py --check` แล้วดู Quick reference
ที่หัว `AGENTS.md` · หน้าที่ของ agent คือตัดสินใจว่า *จะรันอะไรต่อ* ระหว่างที่ crawl คลี่ออกมา
ส่วน**การรับประกันอยู่ในสคริปต์ ไม่ได้อยู่ใน agent**

### ต้องมีอะไรบ้าง

| | |
|---|---|
| Python | 3.9+ ใช้ standard library ล้วน |
| SSH แบบ key | OpenSSH client ตัวไหนก็ได้ — Windows 10+, macOS และ Linux มีมาให้แล้ว |
| SSH แบบรหัสผ่าน | อย่างใดอย่างหนึ่ง: `pip install paramiko` (ทุก OS), `sshpass` (macOS/Linux), `plink` (Windows) |

`python3 install.py --check` บอกได้ว่าเครื่องคุณมีอะไรบ้างจริง ๆ · บน Windows ถ้า Python ติดตั้งมาในชื่อ
`python` ก็ใช้ `python` แทน `python3`

---

## การสำรวจหนึ่งงานเป็นยังไง

```
        ┌─────────────────── วนจนกว่าจะไม่เหลืออุปกรณ์ใหม่ ───────────────────┐
        │                                                                     │
        ▼                                                                     │
  netwalk-login  ──►  netwalk-scan  ──►  netwalk-diag  ──────────────────────┘
   ขอ access          crawl ทีละ hop      อ่านสุขภาพ
   (ฟอร์มเปิดค้างไว้)   หาเพื่อนบ้าน        export config หาข้อบกพร่อง
        ▲                    │
        └── อุปกรณ์ใหม่ ──────┘   ของที่เจอแต่ละรอบกลับเข้าฟอร์มเดิม

                  เมื่อ crawl ไม่เจออะไรใหม่ หรือวิศวกรบอกว่าพอ
                                      │
                                      ▼
                    netwalk-map  ──►  netwalk-fullreport
                       วาดผัง             ส่งมอบ
```

`login`, `scan`, `diag` เป็น **loop เดียว ไม่ใช่สามเฟส** — ทุก hop จะเจออุปกรณ์ที่ไม่มีใครพูดถึง
ของพวกนั้นกลับเข้าฟอร์ม credential ที่เปิดค้างอยู่ทันที วิศวกรตอบตามจังหวะตัวเอง แล้ว crawl ก็เดินต่อ
· จบเมื่อรอบหนึ่งไม่เจออะไรที่วิศวกรยังไม่ตัดสิน หรือวิศวกรบอกว่าครอบคลุมพอแล้ว
· `map` กับ `fullreport` รันครั้งเดียวตอนท้าย บนสิ่งที่ loop ไปถึงจริง

**เริ่มที่ scope ก่อน** — netwalk เดินออกจากอุปกรณ์ตัวเดียวที่คุณระบุ และ sweep ช่วง IP ได้ด้วย
แต่เฉพาะช่วงที่อนุญาตไว้พร้อมชื่อคนอนุญาต ซึ่งจะไปโผล่ในรายงาน · การตรวจอยู่ในโค้ด ไม่ใช่ใน prompt
และไม่มี flag ให้ข้าม

**แล้ว netwalk ก็ crawl** — LLDP, CDP, MNDP, ARP, DHCP lease, routing table และ MAC table ต่อพอร์ต
ทีละ hop จนไม่เหลือเพื่อนบ้านที่ยังไม่ได้ไป · พอร์ตที่เรียนรู้ MAC หลายตัวแต่ไม่รายงาน LLDP neighbour
จะถูกทำเครื่องหมายว่า ***สงสัยว่าเป็น switch ที่ไม่มีการจัดการ*** — ของที่อยู่ตรงนั้นจริง ๆ แต่ไม่ประกาศตัว

**แล้ว netwalk ก็ sweep สิ่งที่ crawl มองไม่เห็น** — TCP-connect sweep ในช่วงที่อนุญาต หาเซิร์ฟเวอร์ที่ตั้ง IP นิ่ง
ปรินเตอร์ที่ไม่มีใครจำได้ และ firewall ตัวที่สอง — ทุกอย่างที่ไม่เคยพูด LLDP และไม่เคยโผล่ใน ARP
· **connection ที่ถูก refuse นับว่าเจอ host** เครื่องที่ปิดพอร์ตหมดก็ยังโผล่ · ตรวจพอร์ต well-known ~68 ตัว
เป็นค่าเริ่มต้น และตัวที่เป็น finding ในตัวเอง (telnet, SMB, RDP, VNC, Redis, Winbox, ฐานข้อมูลบน VLAN
ผู้ใช้) จะถูกทำเครื่องหมายไว้ · **sweep มองไม่เห็น UDP** และมองไม่เห็น host ที่ drop แทนที่จะ reject
ซึ่งข้อจำกัดนี้ถูกเขียนลงหัวข้อ coverage ของรายงานให้อัตโนมัติ ไม่ปล่อยให้เข้าใจเอาเอง

**แล้ว netwalk ตรวจ config เทียบกับ best practice ของ vendor** — ไม่ใช่จากความจำ แต่ checklist เป็น *data*
(`netwalk_audit.py guide`) checks ชุดเดียวกันจึงรันทุกไซต์: telnet และ management แบบ clear-text
ที่เปิดค้างไว้, firewall input chain ที่ไม่มี catch-all drop, SNMP community ค่าเริ่มต้น, RoMON และ
MAC-server เปิดโล่ง, root SSH login, ไม่มี BPDU guard, SSID แบบ open หรือ WEP, ฐานข้อมูลที่ฟังอยู่บน
VLAN ผู้ใช้ · **netwalk อ่าน config export จากดิสก์โดยตรง** config ที่เต็มไปด้วย PSK จึงไม่ผ่านโมเดล
และ check ที่รัน*ไม่ได้*จะถูกรายงานชื่อออกมา ไม่ใช่ถูกนับว่าผ่าน

**แล้ว netwalk อ่าน health** — CPU, memory, storage, อุณหภูมิ, งบ PoE, error และ CRC ของ interface,
**จำนวนครั้งที่ link ตก**, throughput, session table, service ที่รันและที่ล้ม, และ log
· ทุก finding พก output ของคำสั่งที่ทำให้เกิด finding นั้นมาด้วย · counter ถูกหารด้วย uptime ก่อนเสมอ
ก่อนจะเรียกอะไรว่าเป็นข้อบกพร่อง

**แล้วคุณก็ได้ของส่งมอบ** — ไดอะแกรม SVG แบบ deterministic (โลโก้ vendor, hostname, IP จัดการ, รุ่น,
เวอร์ชัน OS และชิป CPU/RAM/storage สดต่ออุปกรณ์, กล่องละหนึ่งอันต่อ uplink อินเทอร์เน็ต, ป้ายพอร์ตบนทุกลิงก์,
เส้นประสำหรับสิ่งที่อนุมานเอา) และรายงาน HTML ไฟล์เดียวจบที่เปิดแบบออฟไลน์ได้และตามโหมดสว่าง/มืดของคนอ่าน

### รองรับอุปกรณ์อะไรบ้าง

estate ที่มี controller จะถูกอ่านจาก controller ทีเดียว ไม่ไล่ทีละเครื่อง: **UniFi** (`netwalk_unifi.py`
รองรับทั้ง UniFi OS Integration API และ login แบบเดิม) และ **TP-Link Omada** (`netwalk_omada.py`
รองรับทั้ง Open API และ session API แบบเก่า)

command pack แบบอ่านอย่างเดียวมีให้สำหรับ **MikroTik RouterOS**, **Cisco IOS / IOS-XE / NX-OS**,
**ArubaOS-CX**, **HP/HPE ProCurve & Comware**, **FortiOS**, **Junos**, **Linux** (รวม Proxmox,
OpenWrt, EdgeOS, UniFi, Synology DSM) และ **Windows** · vendor อื่นตกไปที่ profile เข้มสุด
(`show`/`display`/`get`/`print` เท่านั้น) — **vendor ที่ไม่รู้จักจึงปลอดภัยโดยค่าเริ่มต้น แทนที่จะใช้ไม่ได้**

---

## ตรวจอะไรบ้างในแง่ security

สองเรื่องที่ควรแยกกันให้ชัด

### Hardening — config ตั้งตรงตามคำแนะนำของ vendor ไหม

`netwalk_audit.py` เก็บ checklist เป็น *data* checks ชุดเดียวกันจึงรันทุกไซต์ แทนที่จะขึ้นกับว่าใครจำได้ไหม
· **38 checks**: MikroTik, Cisco, Linux ครบจริง ส่วน Aruba, HP, Fortinet, Windows มีชุดตั้งต้น
ซึ่งเอกสารก็ไม่ได้โม้ว่าชุดนั้นครบกว่าที่เป็นจริง

```bash
netwalk_audit.py guide --vendor mikrotik              # ตัว checklist เอง ในรูปเอกสาร
netwalk_audit.py run --site acme-hq --record scan.json [--dry-run]
```

แต่ละ check พก: หลักฐานที่ใช้ตัดสิน, เหตุผลว่าทำไม check นั้นสำคัญ, วิธีแก้ที่ช่างทำตามได้ และ vendor guidance
ที่ check นั้นอ้างอิง

**3 คุณสมบัติที่สำคัญกว่าจำนวน check:**

- **netwalk_audit.py อ่าน config จากดิสก์ ไม่ผ่านบทสนทนา** — export อยู่ตรงนั้นอยู่แล้วเพราะ `netwalk_exec.py --out`
  เขียนไว้ · เนื้อเต็มไม่เคยเข้า context ของ agent ส่วน excerpt ที่แนบไป finding ยาวบรรทัดเดียว
  และผ่าน redactor ก่อน
- **`NOT CHECKED` เป็นส่วนหนึ่งของผลลัพธ์** — อุปกรณ์ที่ไม่มี export, check ที่คำสั่งหายไปจาก pack,
  และทุกข้อที่ต้องให้คนเดินไปดูของจริง ถูกพิมพ์ชื่อออกมาและเขียนลง `coverage.not_covered`
  · **6 finding โดยซ่อนว่ามี 10 check ไม่ได้รัน อ่านเหมือนใบรับรองว่าสะอาด ซึ่งแย่กว่าไม่มีหัวข้อ security เลย**
- **check ที่อ่าน setting เดียวต้องบอกว่าตัวเองอ่านแค่นั้น** — `mt-dns-remote` ยิงเมื่อเจอ
  `allow-remote-requests=yes` ซึ่งบอกว่า resolver *จะตอบ* ไม่ได้บอกว่ามีอะไร*เข้าถึง resolver นั้นได้*
  · check นี้จึงรายงานเป็น *suspected* พร้อมคำสั่งให้ไปอ่าน raw firewall ก่อนเอาไปบอกลูกค้า
  · ที่ไซต์จริง raw table drop UDP/53 ไว้อยู่แล้ว การ match pattern จะไปลบล้างข้อสรุปที่คนตรวจมาแล้ว

### Exposure — จริง ๆ แล้วอะไรเปิดอยู่

crawl เจอสิ่งที่ประกาศตัว ส่วน sweep ที่ได้รับอนุญาตเจอที่เหลือ — **สองอย่างรวมกันคือสิ่งที่ทำให้ finding
ประเภท "อุปกรณ์ที่ระบุตัวไม่ได้" เกิดขึ้นได้ตั้งแต่แรก** · เรื่อง gate ดูหัวข้อ *เริ่มที่ scope ก่อน* ด้านบน
· connection ที่ถูก refuse นับว่าเจอ host, sweep มองไม่เห็น UDP และทั้งสองข้อถูกเขียนลงรายงาน
ไม่ปล่อยให้เข้าใจเอาเอง

finding จากทั้งสองทางตั้งค่าเริ่มต้นเป็น `public_safe: false` — **รายการ hardening คือแผนที่ทางเข้า**

---

## โครงสร้างไฟล์

```
netwalk/
  install.py                     ตัวติดตั้งข้ามแพลตฟอร์ม
  skills/                        SKILL.md ทั้ง 6 ไฟล์
  scripts/
    netwalk_common.py            path, สิทธิ์ไฟล์, ตรวจหา SSH transport
    netwalk_policy.py            gate อ่านอย่างเดียว        <- ตัวรับประกันความปลอดภัย
    netwalk_cred.py              ฟอร์มรับ credential ในเบราว์เซอร์เครื่องตัวเอง
    netwalk_exec.py              ตัวรันคำสั่งที่ผ่าน gate + evidence log
    netwalk_map.py               ตัว render ไดอะแกรม SVG
    netwalk_report.py            ตัว render รายงาน HTML + ตรวจกวาดความลับ
    netwalk_sweep.py             subnet sweep ที่ได้รับอนุญาต + port scan
    netwalk_audit.py             แคตตาล็อก hardening ของ vendor + ตัวตรวจ
    netwalk_logos.py             ตัวดึงโลโก้ vendor (ไม่บังคับ)
    packs/*.txt                  รายการคำสั่งอ่านอย่างเดียวต่อ vendor
  schema/netwalk-record.schema.json    สัญญาระหว่างการเก็บข้อมูลกับการทำรายงาน
  tests/                         651 เคส
  examples/example-scan.json     record ครบชุดที่ render ได้โดยไม่ต้องแตะเครือข่ายจริง
  CHANGELOG.md                   อะไรเปลี่ยนบ้างในแต่ละเวอร์ชัน
```

ลองโดยไม่ต้องมีเครือข่าย:

```bash
python3 scripts/netwalk_report.py examples/example-scan.json -o /tmp/demo.html
python3 scripts/netwalk_map.py    examples/example-scan.json -o /tmp/demo.svg
```

### scan record

ไฟล์ JSON หนึ่งไฟล์ต่อหนึ่งไซต์ต่อหนึ่งวันที่สแกน คือแหล่งความจริงเดียว · ไดอะแกรมกับรายงาน render จาก record นี้
ทั้งคู่แบบ deterministic — record เดิมให้ output เดิมเสมอ, สแกนสองรอบของไซต์เดียว diff กันสะอาด,
และรายงานที่เปลี่ยนแปลว่าเครือข่ายเปลี่ยน · **ห้ามแก้ SVG หรือ HTML ด้วยมือ** ให้แก้ record แล้ว render ใหม่

ข้อมูลของงานจริงลงที่ `~/.netwalk/sites/<slug>/` ซึ่ง git ไม่แตะ:

```
~/.netwalk/sites/acme-hq/
  scan-2026-08-22.json     ตัว record
  evidence.jsonl           ทุกคำสั่งที่ถูกรัน
  configs/gw01.conf        config export (พวกนี้ *มี* ความลับ เก็บไว้ในเครื่องเท่านั้น)
  map.svg
  report.html              ฉบับเต็ม
  report-public.html       สำหรับเจ้าของไซต์
```

---

## credential เก็บไว้ที่ไหนกันแน่

`~/.netwalk/creds/<site>.json` อยู่นอก repository, `0600` / ACL เจ้าของคนเดียว
· เปลี่ยนที่เก็บได้ด้วย `NETWALK_HOME`

```bash
netwalk_cred.py list   --site acme-hq     # host ไหนมี credential ชนิดไหน — ไม่เคยแสดงค่า
netwalk_cred.py probe  --site acme-hq     # ผ่าน netwalk_exec.py: ล็อกอินได้จริงไหม
netwalk_cred.py forget --site acme-hq     # เขียนทับแล้วลบ
```

---

## ปิดงานสำรวจ

การสำรวจทิ้งอะไรไว้มากกว่าตัวรายงาน และรายงานคือส่วนเดียวที่คนจำได้ · พอจบงาน:

```bash
netwalk_cred.py stop   --site acme-hq                  # 1. ปิดฟอร์ม credential
netwalk_cred.py forget --site acme-hq --with-configs   # 2. ทำลาย credential *และ* config export
```

**ไม่มีอะไรหมดอายุเอง** — credential store ไม่มี TTL และไม่มีอะไรมาลบให้ตอนสแกนจบ,
และงานที่รันจากสองเครื่องทิ้งไว้สองชุด → **ต้องรันคำสั่งเดียวกันบนทุกเครื่อง**
· `forget` ที่ไม่ใส่ `--with-configs` จะบอกว่ายังมี export เหลือกี่ไฟล์ ขนาดเท่าไร แทนที่จะปล่อยไว้เงียบ ๆ

**อะไรถูกทิ้งไว้บ้าง และอันไหนแย่แค่ไหน:**

| | อยู่ที่ | มีอะไร |
|---|---|---|
| **credential store** | `~/.netwalk/creds/<site>.json` | รหัสผ่านและ path ของ key ที่คุณได้รับมา · JSON ธรรมดา กันด้วยสิทธิ์ไฟล์ **ไม่ได้เข้ารหัส** |
| **config export** | `~/.netwalk/sites/<site>/configs/` | PSK, SNMP community, password hash แบบ clear text · **ใหญ่กว่าและอ่อนไหวกว่าไฟล์ credential** และไม่มีเครื่องมืออื่นลบให้ |
| record, ผัง, รายงาน | `~/.netwalk/sites/<site>/` | ของส่งมอบ · ไม่มีความลับ — ตัว render ปฏิเสธไม่สร้างรายงานจาก record ที่มีความลับ |

รายงานฉบับเต็มยังพิมพ์กล่อง *Where this survey left sensitive files* ที่ระบุ path พวกนี้ด้วย
คนที่คุณส่งรายงานให้จะได้รู้ว่ามีอะไรอยู่บนเครื่องคุณ แทนที่จะมารู้ทีหลัง · กล่องนี้อยู่ในฉบับเต็มเท่านั้น
**ลูกค้าที่อ่านฉบับ `--public` ไม่มีเหตุผลที่จะต้องรู้ว่าช่างเก็บรหัสไว้ตรงไหน**

**การลบไม่ใช่การ rotate** — `forget` เขียนทับก่อน unlink ซึ่ง **ไม่ใช่** forensic wipe บน SSD
หรือ filesystem แบบ copy-on-write · ถ้า credential พวกนั้นสำคัญ ให้ rotate
และ**บอกเจ้าของไซต์ด้วย** แทนที่จะคิดเอาเองว่าลบแล้วพอ

---

## ข้อจำกัด พูดกันตรง ๆ

- netwalk อ่านสิ่งที่อุปกรณ์บอก · อุปกรณ์ที่โกหก หรือ CLI ของ vendor ที่ละอะไรไว้ จะให้ภาพที่ไม่ครบ —
  ซึ่งเป็นเหตุผลที่ `coverage.not_covered` เป็นส่วน**บังคับ**ของทุกรายงาน ไม่ใช่ของแถม
- topology ที่อนุมานคือการอนุมาน · switch ที่ไม่มีการจัดการถูกตรวจจากความไม่ตรงกันของ MAC กับ LLDP
  และวาดเป็นเส้นประ ไม่เคยถูกนำเสนอว่ายืนยันแล้ว
- โหมด `--public` ซ่อนหัวข้อ **แต่ไม่ได้ sanitise ข้อความที่คุณเขียนลง finding เอง**
- gate อ่านอย่างเดียวเป็น allowlist ที่แข็งแรง **ไม่ใช่การพิสูจน์เชิงรูปนัย** · gate นี้มี regression test คุม
  และนั่นคือเหตุผลที่คุณควรผ่าน `netwalk_exec.py` เสมอ แทนที่จะ SSH เข้าอุปกรณ์ที่กำลังสำรวจตรง ๆ
- เครื่องหมายการค้าของ vendor ไม่ได้แจกมากับ repository นี้ · `netwalk_logos.py fetch` ดึงจาก
  [Simple Icons](https://simpleicons.org) (CC0-1.0) เมื่อร้องขอ · vendor ที่ไม่มีโลโก้จะแสดงเป็นชิปตัวอักษร
  · เครื่องหมายการค้าทั้งหมดเป็นของเจ้าของ

## ประวัติเวอร์ชัน

`CHANGELOG.md` สรุปแต่ละ release ส่วน commit history คือบันทึกจริง — **commit message ทุกอันอธิบายว่า
ทำไมถึงเปลี่ยน ไม่ใช่เล่า diff ซ้ำ** · บน GitHub ปุ่ม **Blame** บนไฟล์ไหนก็ได้พาจากบรรทัดหนึ่ง
ไปที่ commit ที่อธิบายบรรทัดนั้นโดยตรง

```bash
git log --oneline v0.1.0..v0.2.0      # เปลี่ยนอะไรระหว่างสอง release
git log -p --follow scripts/netwalk_policy.py    # ประวัติทั้งหมดของไฟล์เดียว
```

## ข้อกฎหมาย

**รัน netwalk กับอุปกรณ์ที่คุณเป็นเจ้าของ หรือได้รับอนุญาตเป็นลายลักษณ์อักษรให้เข้าถึงเท่านั้น**
การล็อกอินเข้าเครือข่ายคนอื่นโดยไม่ได้รับอนุญาตเป็นความผิดอาญาในเขตอำนาจศาลส่วนใหญ่
และ **"ก็แค่อ่านเฉย ๆ" ไม่ใช่ข้อแก้ตัว**

สัญญาอนุญาต MIT ดู `LICENSE`
