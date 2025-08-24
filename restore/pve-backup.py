#!/usr/bin/env python3

"""

Beispiel:
  python pve_file_restore.py \
    --host pve.example.com --port 8006 --node pvenode1 --storage pbs-store \
    --token-id "root@pam!script" --token-secret "SECRET" \
    --vmid 101 \
    --download-dir ./downloads \
    --preserve-meta
"""

import argparse
import base64
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests


# --------------------------- CLI ---------------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="PVE Single-File-Restore via REST-API (requests)")
    ap.add_argument("--host", required=True, help="PVE Hostname oder IP")
    ap.add_argument("--port", type=int, default=8006, help="PVE API Port (Standard: 8006)")
    ap.add_argument("--node", required=True, help="PVE Node, auf dem der Restore-Helper läuft")
    ap.add_argument("--storage", required=True, help="PVE Storage-ID (PBS-Storage)")
    ap.add_argument("--token-id", required=True, help="API-Token ID, z.B. root@pam!script")
    ap.add_argument("--token-secret", required=True, help="API-Token Secret")
    ap.add_argument("--vmid", type=int, default=None, help="Optional: VMID zum Filtern der Backups")
    ap.add_argument("--insecure", action="store_true",
                    help="TLS-Validierung deaktivieren (nur Testumgebungen)")
    ap.add_argument("--download-dir", default="downloads",
                    help="Zielverzeichnis für Downloads (Standard: ./downloads)")
    ap.add_argument("--preserve-meta", action="store_true",
                    help="Nach Download Mode/Owner/GID/mtime setzen (sofern vorhanden)")
    return ap.parse_args()


# --------------------------- Helpers ------------------------------
def epoch_to_iso8601_z(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def print_table(rows: List[Tuple[str, ...]], header: Tuple[str, ...] = None, width: int = 120):
    def trunc(s, w): return (s if len(s) <= w else s[: w - 1] + "…")
    if header:
        print(" | ".join(trunc(h, width // max(1, len(header))) for h in header))
        print("-" * width)
    for r in rows:
        print(" | ".join(trunc(c, width // max(1, len(r))) for c in r))


def b64_path(path: str) -> str:
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    return base64.b64encode(path.encode("utf-8")).decode("ascii")


def is_dir(entry: Dict[str, Any]) -> bool:
    t = (entry.get("type") or "").lower()
    if t in ("d", "dir", "directory", "folder"):
        return True
    if t in ("f", "file", "regular"):
        return False
    return not bool(entry.get("leaf", True))


def parse_mode(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit():
            try:
                return int(s, 8)  # oktal interpretieren
            except ValueError:
                return None
    return None


def apply_metadata_if_possible(entry: Dict[str, Any], target: Path, verbose: bool = True):
    # mtime
    mtime = entry.get("mtime")
    if isinstance(mtime, (int, float)) and mtime > 0:
        try:
            os.utime(target, (mtime, mtime))
        except Exception as e:
            if verbose:
                print(f"  -> Hinweis: mtime konnte nicht gesetzt werden: {e}")

    # mode
    mode = entry.get("mode") if "mode" in entry else entry.get("permissions")
    pmode = parse_mode(mode)
    if pmode is not None:
        try:
            os.chmod(target, pmode)
        except Exception as e:
            if verbose:
                print(f"  -> Hinweis: chmod fehlgeschlagen ({mode}): {e}")

    # owner/group (nur als root sinnvoll)
    uid = entry.get("uid")
    gid = entry.get("gid")
    if uid is not None or gid is not None:
        try:
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                if verbose:
                    print("  -> Hinweis: chown übersprungen (nicht als root ausgeführt).")
            else:
                st = target.stat()
                tuid = int(uid) if uid is not None else st.st_uid
                tgid = int(gid) if gid is not None else st.st_gid
                if hasattr(os, "chown"):
                    os.chown(target, tuid, tgid)
                else:
                    if verbose:
                        print("  -> Hinweis: chown nicht unterstützt auf dieser Plattform.")
        except Exception as e:
            if verbose:
                print(f"  -> Hinweis: chown fehlgeschlagen: {e}")


# --------------------------- PVE API Client (requests) ------------
class PVEClient:
    LIST_TIMEOUT = (10, 60)   # (connect, read) Sekunden
    READ_TIMEOUT = (10, 600)  # (connect, read) für Downloads

    def __init__(self, base_url: str, token_id: str, token_secret: str, verify_tls: bool):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"PVEAPIToken {token_id}={token_secret}"})
        self.session.verify = verify_tls  # False -> unsicher (nur für Tests)

    def list_backups(self, node: str, storage: str, vmid: Optional[int] = None) -> List[Dict[str, Any]]:
        url = f"{self.base}/api2/json/nodes/{node}/storage/{storage}/content"
        params = {"content": "backup"}
        if vmid:
            params["vmid"] = vmid
        r = self.session.get(url, params=params, timeout=self.LIST_TIMEOUT)
        r.raise_for_status()
        data = r.json()["data"]
        data.sort(key=lambda e: e.get("ctime", 0), reverse=True)
        return data

    def fr_list(self, node: str, storage: str, volume: str, path_b64: str) -> List[Dict[str, Any]]:
        url = f"{self.base}/api2/json/nodes/{node}/storage/{storage}/file-restore/list"
        params = {"volume": volume, "filepath": path_b64}
        r = self.session.get(url, params=params, timeout=self.LIST_TIMEOUT)
        r.raise_for_status()
        return r.json()["data"]

    def fr_download(self, node: str, storage: str, volume: str, path_b64: str, out_path: Path) -> None:
        url = f"{self.base}/api2/json/nodes/{node}/storage/{storage}/file-restore/download"
        params = {"volume": volume, "filepath": path_b64}
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with self.session.get(url, params=params, stream=True, timeout=self.READ_TIMEOUT) as r:
            r.raise_for_status()
            with out_path.open("wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)


# --------------------------- Interaktiver Flow ---------------------
def choose_backup(backups: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not backups:
        sys.exit("Keine Backups gefunden (prüfe Storage, Rechte, VMID-Filter).")
    page = 0
    page_size = 20
    while True:
        start = page * page_size
        end = start + page_size
        chunk = backups[start:end]
        if not chunk:
            print("Keine weitere Seite.")
            page = max(0, page - 1)
            continue

        rows = []
        for i, b in enumerate(chunk, start=1):
            idx = start + i
            ctime = epoch_to_iso8601_z(int(b.get("ctime", 0))) if b.get("ctime") else ""
            rows.append((
                f"{idx}",
                b.get("volid", ""),
                b.get("format", ""),
                str(b.get("size", "")),
                ctime,
                b.get("notes", "") or "",
            ))
        print()
        print_table(rows, header=("Nr", "VolID", "Format", "Size", "ctime", "Notes"), width=140)
        print("\nBefehle: [zahl]=wählen, n=weiter, p=zurück, q=abbrechen")
        cmd = input("> Auswahl: ").strip().lower()
        if cmd == "n":
            page += 1; continue
        if cmd == "p":
            page = max(0, page - 1); continue
        if cmd == "q":
            sys.exit(0)
        if cmd.isdigit():
            idx = int(cmd)
            if 1 <= idx <= len(backups):
                return backups[idx - 1]
            else:
                print("Ungültige Nummer.")
        else:
            print("Eingabe nicht erkannt.")


def file_browser(client: PVEClient, node: str, storage: str, volume: str,
                 download_dir: Path, preserve_meta: bool):
    print(f"\n> Starte Dateibrowser für Backup:\n  VolID: {volume}")
    cwd = "/"
    base_target = download_dir / volume.replace("/", "_").replace(":", "_")

    while True:
        try:
            entries = client.fr_list(node, storage, volume, b64_path(cwd))
        except requests.HTTPError as e:
            print(f"Fehler beim Listen von '{cwd}': {e}")
            entries = []

        entries.sort(key=lambda e: (e.get("type") != "d", e.get("text") or ""))

        print(f"\nPfad: {cwd}")
        rows = []
        for i, e in enumerate(entries, start=1):
            name = e.get("text") or "?"
            size = str(e.get("size", "")) if e.get("size") is not None else ""
            mtime = ""
            if e.get("mtime"):
                try:
                    mtime = datetime.fromtimestamp(int(e["mtime"]), tz=timezone.utc).isoformat()
                except Exception:
                    mtime = str(e.get("mtime"))
            rows.append((str(i), "DIR" if is_dir(e) else "FILE", name, size, mtime))
        print_table(rows, header=("Nr", "Typ", "Name", "Size", "mtime"), width=120)

        print(
            "\nBefehle:\n"
            "  cd <nr|..>        Verzeichnis wechseln\n"
            "  dl <nr[,nr…]>     Datei(en) herunterladen\n"
            "  path <pfad>       Absoluten Pfad setzen (z. B. /etc)\n"
            "  up                Ein Verzeichnis hoch\n"
            "  q                 Beenden\n"
        )
        cmd = input("> ").strip()
        if not cmd:
            continue

        parts = cmd.split()
        op = parts[0].lower()

        if op == "q":
            break
        elif op == "up":
            if cwd != "/":
                parent = Path(cwd).parent
                cwd = "/" if str(parent) == "." else "/" + str(parent).lstrip("/")
        elif op == "cd":
            if len(parts) < 2:
                print("Nutze: cd <nr|..>"); continue
            arg = parts[1]
            if arg == "..":
                if cwd != "/":
                    parent = Path(cwd).parent
                    cwd = "/" if str(parent) == "." else "/" + str(parent).lstrip("/")
                continue
            if not arg.isdigit():
                print("Bitte Nummer angeben."); continue
            idx = int(arg)
            if not (1 <= idx <= len(entries)):
                print("Ungültige Nummer."); continue
            ent = entries[idx - 1]
            if not is_dir(ent):
                print("Das ist keine Directory."); continue
            name = ent.get("text") or "?"
            cwd = "/" + str(Path(cwd) / name).lstrip("/")
        elif op == "path":
            if len(parts) < 2:
                print("Nutze: path /absoluter/pfad"); continue
            p = parts[1]
            if not p.startswith("/"):
                print("Bitte absoluten Pfad angeben (beginnend mit /)."); continue
            cwd = p
        elif op == "dl":
            if len(parts) < 2:
                print("Nutze: dl <nr[,nr…]>"); continue
            nums = []
            for token in parts[1].split(","):
                token = token.strip()
                if token.isdigit():
                    nums.append(int(token))
            if not nums:
                print("Keine gültigen Nummern erkannt."); continue

            for n in nums:
                if not (1 <= n <= len(entries)):
                    print(f"Überspringe ungültige Nummer {n}."); continue
                ent = entries[n - 1]
                if is_dir(ent):
                    print(f"Überspringe Verzeichnis '{ent.get('text')}'. (Dieses Skript lädt nur Dateien)")
                    continue
                name = ent.get("text") or "download.bin"
                guest_path = (Path(cwd) / name).as_posix()
                out_path = base_target / guest_path.lstrip("/")
                print(f"Lade '{guest_path}' …")
                try:
                    client.fr_download(node, storage, volume, b64_path(guest_path), out_path)
                    print(f"  -> OK: {out_path}")
                    if preserve_meta:
                        apply_metadata_if_possible(ent, out_path, verbose=True)
                except requests.HTTPError as e:
                    print(f"  -> FEHLER: {e}")
            time.sleep(0.2)
        else:
            print("Unbekannter Befehl.")

    print("\nBrowser beendet.")


# --------------------------- Main --------------------------------
def main():
    args = parse_args()
    base = f"https://{args.host}:{args.port}"
    client = PVEClient(base, args.token_id, args.token_secret, verify_tls=not args.insecure)

    print("> Lade Backups …")
    backups = client.list_backups(args.node, args.storage, args.vmid)
    choice = choose_backup(backups)
    volid = choice["volid"]
    ctime = choice.get("ctime")
    print(f"\nGewählt:\n  VolID : {volid}\n  ctime : {epoch_to_iso8601_z(int(ctime)) if ctime else '-'}")

    download_dir = Path(args.download_dir).resolve()
    file_browser(client, args.node, args.storage, volid, download_dir, args.preserve_meta)

    print("\nFertig.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
