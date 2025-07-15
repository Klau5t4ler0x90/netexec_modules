from pathlib import Path
import csv
from typing import Iterable, Set, Tuple

def _entry_name(entry):
    for cand in ("filename", "longname", "name", "get_longname"):
        if hasattr(entry, cand):
            attr = getattr(entry, cand)
            return attr() if callable(attr) else attr
    return ""  # fallback – shouldn’t happen


def _is_dir(entry):
    for cand in ("isDirectory", "is_directory", "is_dir"):
        if hasattr(entry, cand):
            method = getattr(entry, cand)
            return method() if callable(method) else bool(method)
    # Try to infer from DOS attribute bit if present
    if hasattr(entry, "smbAttributes") and hasattr(entry.smbAttributes, "isDirectory"):
        return entry.smbAttributes.isDirectory()
    return False


class NXCModule:
    """
    logon_scripts_enum – Enumerate logon and GPO scripts in SYSVOL/NETLOGON.

    * List ``*.bat, *.cmd, *.ps1, *.vbs, *.kix`` under
      ``//<domain>/SYSVOL/<domain>/scripts``
    * Parse every ``scripts.ini`` below ``Policies`` for referenced logon‑scripts
    * Output goes to ``context.log.display`` so that NetExec’s ``--log`` catches it.
    """

    name = "logon_scripts_enum"
    description = "Enumerate logon scripts in SYSVOL/NETLOGON and GPOs"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False  # 1× pro Domäne reicht

    # -------- Options -------- #
    def __init__(self):
        self.save_dir: Path | None = None
        self.csv_rows: list[dict] = []

    def options(self, context, module_options):
        """SAVE=<dir> → write CSV-list"""
        save = module_options.get("SAVE")
        if save:
            self.save_dir = Path(save).expanduser().resolve()
            self.save_dir.mkdir(parents=True, exist_ok=True)

    # -------- Core -------- #
    def on_login(self, context, connection):
        smb = connection.conn  # NetExec SMBConnection

        # find Domain
        domain = connection.domain or connection.hostname or connection.host
        scripts_share = "SYSVOL"
        scripts_root = f"{domain}/scripts"
        context.log.display(f"[*] Searching Logon‑Scripts /{scripts_share}/{scripts_root}")

        # 1. Klassische Logon‑Skripte
        exts: Set[str] = {".bat", ".cmd", ".ps1", ".vbs", ".kix"}
        logon_scripts = list(self._iter_files(smb, scripts_share, scripts_root, exts))

        if logon_scripts:
            for share, rel_path in logon_scripts:
                context.log.success(f"LOGON_SCRIPT | /{share}/{rel_path}")
                self._record("LogonScript", share, rel_path)
        else:
            context.log.display("[i] No Logon-Scripts found!")

        # 2. GPO scripts.ini
        gpo_root = f"{domain}/Policies"
        ini_paths = self._iter_files(smb, scripts_share, gpo_root, {".ini"})
        for share, rel_path in ini_paths:
            if rel_path.lower().endswith("scripts.ini"):
                context.log.display(f"[*] Analyze {rel_path}")
                data = self._read_file(smb, share, rel_path)
                for m in set(re.findall(r"\\\\.*?\.\w+", data, flags=re.I)):
                    context.log.success(f"GPO_SCRIPT_REF | {m} (in {rel_path})")
                    self._record("GpoScriptRef", share, rel_path, extra=m)

        # CSV‑Export
        if self.save_dir and self.csv_rows:
            out = self.save_dir / "logon_scripts_enum.csv"
            with out.open("w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=self.csv_rows[0].keys())
                writer.writeheader()
                writer.writerows(self.csv_rows)
            context.log.success(f"[+] CSV save → {out}")

    # -------- SMB helper -------- #
    def _iter_files(
        self, smb, share: str, path: str, exts: Set[str]
    ) -> Iterable[Tuple[str, str]]:
        """Yield (share, relative_path) for each remote file that matches exts."""
        try:
            dir_list = smb.listPath(share, path + "/*")
        except Exception:
            return []

        for entry in dir_list:
            name = _entry_name(entry)
            if name in {".", ".."}:
                continue
            rel_path = f"{path}/{name}" if path else name
            if _is_dir(entry):
                yield from self._iter_files(smb, share, rel_path, exts)
            else:
                if Path(name).suffix.lower() in exts:
                    yield share, rel_path

    def _read_file(self, smb, share: str, path: str) -> str:
        try:
            file_handle = smb.openFile(share, path, desired_access=0x80)  # FILE_READ_DATA
            data = smb.readFile(share, path)
            smb.closeFile(share, file_handle)
            return data.decode(errors="ignore")
        except Exception:
            return ""

    # -------- internal -------- #
    def _record(self, rtype: str, share: str, rel_path: str, extra: str | None = None):
        row = {"Type": rtype, "Share": share, "Path": rel_path, "Extra": extra or ""}
        self.csv_rows.append(row)
