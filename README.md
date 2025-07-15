
# NetExec add‑on: `logon_scripts_enum` & `logon_creds_scan`

Two lightweight **NetExec (`nxc`) modules** for _enumerating_ and _auditing_ Windows logon‑scripts.

---

## 1  Features
* **Zero config** – run once per DC / file server  
* Recursively enumerates classic logon‑script locations  
  `SYSVOL/<domain>/scripts` **and** every `scripts.ini` inside *Policies*  
* **Credential hunting** – regexes catch:
  * `net use \\srv\share /user:USER PASS`
  * PowerShell `-AsPlainText`
  * `$password = "hunter2"` …and friends  
* Works on **any SMB dialect** (1 → 3.1.1)  
* **CSV export** (`SAVE=<dir>`) for deeper digests  
* Minimal server load, no special privileges needed

---

## 2  Installation
```bash
# paths ≈ Debian/Ubuntu – adapt as needed
sudo cp logon_scripts_enum.py  /usr/lib/python3/dist-packages/nxc/modules/
sudo cp logon_creds_scan.py    /usr/lib/python3/dist-packages/nxc/modules/
```
No extra Python deps – everything ships with NetExec / Impacket.

---

## 3  Usage

### 3.1  List every logon‑script
```bash
nxc smb <dc> -u alice -p S3cret! -d corp.local -M logon_scripts_enum
```

### 3.2  Rip plain‑text credentials
```bash
nxc smb <dc> -u alice -p S3cret! -d corp.local -M logon_creds_scan SAVE=/tmp
```

---

## 4  Module option matrix

| Option          | Applies | Purpose                     |
|-----------------|---------|-----------------------------|
| `SAVE=<dir>`    | both    | dump results as CSV         |

---

## 5  Credits / License
Inspired by [ScriptSentry](https://github.com/techspence/ScriptSentry).
Thanks to [Pennyw0rth](https://github.com/Pennyw0rth/NetExec) and the whole team for this great tool.


If you like my scripts:

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/klau5t4ler0x90)

