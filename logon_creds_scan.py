from pathlib import Path, PurePosixPath
from io import BytesIO
import re
import csv
from typing import Iterable, Set, Tuple, List, Dict, Optional

# ---------------------------------------------------------------------------
# Helper utils (shared with logon_scripts_enum)
# ---------------------------------------------------------------------------

def _entry_name(entry):
    for cand in ("filename", "longname", "name", "get_longname"):
        if hasattr(entry, cand):
            attr = getattr(entry, cand)
            return attr() if callable(attr) else attr
    return ""

def _is_dir(entry):
    for cand in ("isDirectory", "is_directory", "is_dir"):
        if hasattr(entry, cand):
            method = getattr(entry, cand)
            return method() if callable(method) else bool(method)
    if hasattr(entry, "smbAttributes") and hasattr(entry.smbAttributes, "isDirectory"):
        return entry.smbAttributes.isDirectory()
    return False

# ---------------------------------------------------------------------------
# Regex patterns for plaintext credentials
# ---------------------------------------------------------------------------

_PATTERNS = [
    # net use \\srv\share /user:USER PASS
    re.compile(r"net\s+use\s+\\\\\S+\s+/user:(?P<user>\S+)\s+(?P<pw>\S+)", re.I),

    # PowerShell ConvertTo-SecureString -AsPlainText PASS
    re.compile(r"-AsPlainText\s+(?P<pw>\S+)", re.I),

    # key = value pairs ($user = "DOMAIN\\bob")
    re.compile(r"\$?user\s*=\s*['\"]?(?P<user>[^'\"\r\n]+)", re.I),

    # password = value, passwd=, pwd=
    re.compile(r"\$?pass(?:word|wd)?\s*=\s*['\"]?(?P<pw>[^'\"\r\n]+)", re.I),
]

_EXTS = {'.bat', '.cmd', '.ps1', '.vbs', '.kix'}

class NXCModule:
    """Scan SYSVOL/NETLOGON script files for plaintext credentials."""

    name = "logon_creds_scan"
    description = "Enumerate logon-script files and search for plaintext credentials"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self):
        self.save_dir: Optional[Path] = None
        self.findings: List[Dict[str, str]] = []

    # ----------------------------- Options ----------------------------- #
    def options(self, context, module_options):
        save = module_options.get("SAVE")
        if save:
            self.save_dir = Path(save).expanduser().resolve()
            self.save_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------ Core ------------------------------- #
    def on_login(self, context, connection):
        smb = connection.conn
        domain = connection.domain or connection.hostname or connection.host
        share = "SYSVOL"
        root  = f"{domain}/scripts"

        context.log.display(f"Collecting logon-script files from /{share}/{root} …")
        script_files = list(self._iter_files(smb, share, root, _EXTS))
        context.log.display(f"{len(script_files)} script file(s) collected")

        for sh, rel_path in script_files:
            data = self._read_file(smb, sh, rel_path)
            if not data:
                continue
            for pat in _PATTERNS:
                for m in pat.finditer(data):
                    user = m.groupdict().get("user", "")
                    pw   = m.groupdict().get("pw", "")
                    self._report(context, connection, sh, rel_path, user, pw)

        if not self.findings:
            context.log.display("No plaintext credentials found")

        if self.save_dir and self.findings:
            out = self.save_dir / "credentials.csv"
            with out.open("w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=self.findings[0].keys())
                writer.writeheader()
                writer.writerows(self.findings)
            context.log.success(f"Credentials CSV written to {out}")

    # --------------------------- SMB helpers --------------------------- #
    def _iter_files(self, smb, share: str, path: str, exts: Set[str]) -> Iterable[Tuple[str, str]]:
        try:
            win_path = path.replace('/', '\\')
            dir_list = smb.listPath(share, win_path + '\\*')
        except Exception:
            return []

        for entry in dir_list:
            name = _entry_name(entry)
            if name in {'.', '..'}:
                continue
            rel_path = f"{path}/{name}" if path else name
            if _is_dir(entry):
                yield from self._iter_files(smb, share, rel_path, exts)
            else:
                if Path(name).suffix.lower() in exts:
                    yield share, rel_path

    def _read_file(self, smb, share: str, path: str) -> str:
        win_path = path.replace('/', '\\')
        try:
            buf = BytesIO()
            smb.getFile(share, win_path, buf.write)
            return buf.getvalue().decode(errors='ignore')
        except Exception:
            try:
                fh = smb.openFile(share, win_path, desired_access=0x80)
                data = smb.readFile(share, fh)
                smb.closeFile(share, fh)
                return data.decode(errors='ignore')
            except Exception:
                return ""

    # --------------------------- Reporting ----------------------------- #
    def _report(self, context, connection, share: str, rel_path: str, user: str, pw: str):
        linux_path = f"//{connection.hostname}/{share}/{PurePosixPath(rel_path)}"
        context.log.highlight(f"CREDENTIAL | {linux_path} | user={user} pw={pw}")
        self.findings.append({
            "File": linux_path,
            "User": user,
            "Password": pw
        })
