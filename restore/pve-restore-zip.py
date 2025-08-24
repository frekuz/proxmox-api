#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Beispiel:
  python pve-restore-zip.py \
    --host pve.example.com --port 8006 --node pvenode1 --storage pbs-store \
    --token-id "root@pam!script" --token-secret "SECRET" \
    --vmid 102 \
    --node example.node
    --storage PM-BACKUP
    --download-dir ./restore \
    --ca-cert /etc/pve/pve-root-ca.pem \
    --preserve-meta
"""

import argparse
import base64
import os
import sys
import time
import tempfile
import zipfile
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

# Warnungen bei --insecure gezielt abschalten
try:
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
except Exception:
    urllib3 = None
    InsecureRequestWarning = None


# --------------------------- CLI ---------------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="PVE Single-File/Folder-Restore via REST-API (requests)")
    ap.add_argument("--host", required=True, help="PVE Hostname oder IP")
    ap.add_argument("--port", type=int, default=8006, help="PVE API Port (Standard: 8006)")
    ap.add_argument("--node", required=True, help="PVE Node, auf dem der Restore-Helper läuft")
    ap.add_argument("--storage", required=True, help="PVE Storage-ID (PBS-Storage)")
    ap.add_argument("--token-id", required=True, help="API-Token ID, z.B. root@pam!script")
    ap.add_argument("--token-secret", required=True, help="API-Token Secret")
    ap.add_argument("--vmid", type=int, default=None, help="Optional: VMID zum Filtern der Backups")

    g = ap.add_mutually_exclusive_group()
    g.add_argument("--ca-cert", default=None,
                   help="Pfad zu einer CA-Bundle-PEM-Datei (empfohlen).")
    g.add_argument("--insecure", action="store_true",
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
                return int(s, 8)  # oktal interpretieren (z. B. "0644")
            except ValueError:
                return None
    return None


def apply_metadata_if_possible(entry: Dict[str, Any], target: Path, verbose: bool = True):
    """Setzt mtime/mode/owner (best-effort) anhand von PVE-List-Entry-Infos."""
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


def zipinfo_mode(zi: zipfile.ZipInfo) -> Optional[int]:
    """Gibt UNIX-Mode aus ZIP-Entry zurück, wenn vorhanden."""
    # obere 16 Bits enthalten Posix-Permissions, falls gesetzt
    perm = (zi.external_attr >> 16) & 0o7777
    return perm or None


def zipinfo_mtime_epoch(zi: zipfile.ZipInfo) -> Optional[int]:
    """Konvertiert ZIP DOS-Datetime -> epoch (best-effort, lokal)."""
    try:
        dt = datetime(*zi.date_time)
        # interpretieren als lokale Zeit (ZIP speichert kein TZ)
        return int(time.mktime(dt.timetuple()))
    except Exception:
        return None


def safe_extract_zip(zip_path: Path, dest_dir: Path, preserve_meta: bool, verbose: bool = True):
    """
    Entpackt ZIP sicher (verhindert Pfad-Traversal), setzt Mode/Mtime aus ZIP-Metadaten (wenn vorhanden).
    """
    with zipfile.ZipFile(zip_path) as zf:
        for zi in zf.infolist():
            # Zielpfad berechnen & absichern
            member = zi.filename
            # Normieren: vermeiden, dass absolute Pfade oder .. verwendet werden
            member_path = Path(member)
            # zip kann Ordner mit trailing "/" haben
            target = (dest_dir / member_path).resolve()
            if not str(target).startswith(str(dest_dir.resolve())):
                if verbose:
                    print(f"  -> WARN: Überspringe potenziell unsicheren Pfad: {member}")
                continue

            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                # Verzeichnis-Metadaten anwenden (Mode/Mtime aus ZIP, Owner nicht vorhanden)
                if preserve_meta:
                    try:
                        m = zipinfo_mode(zi)
                        if m:
                            os.chmod(target, m)
                        mt = zipinfo_mtime_epoch(zi)
                        if mt:
                            os.utime(target, (mt, mt))
                    except Exception as e:
                        if verbose:
                            print(f"  -> Hinweis: Konnte Dir-Metadaten nicht setzen: {e}")
                continue

            # Datei extrahieren (streamend)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(zi, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)

            # Metadaten aus dem ZIP anwenden
            if preserve_meta:
                try:
                    m = zipinfo_mode(zi)
                    if m:
                        os.chmod(target, m)
                    mt = zipinfo_mtime_epoch(zi)
                    if mt:
                        os.utime(target, (mt, mt))
                    # Owner/GID sind in ZIP i. d. R. NICHT enthalten -> wird übersprungen
                except Exception as e:
                    if verbose:
                        print(f"  -> Hinweis: Konnte File-Metadaten nicht setzen: {e}")


# --------------------------- PVE API Client (requests) ------------
class PVEClient:
    LIST_TIMEOUT = (10, 60)   # (connect, read) Sekunden
    READ_TIMEOUT = (10, 600)  # (connect, read) für Downloads

    def __init__(self, base_url: str, token_id: str, token_secret: str, verify: Union[bool, str]):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"PVEAPIToken {token_id}={token_secret}"})
        self.session.verify = verify  # True | False | Pfad zu CA-Bundle

        # Warnung nur deaktivieren, wenn verify==False gewünscht ist
        if verify is False and urllib3 and InsecureRequestWarning:
            urllib3.disable_warnings(InsecureRequestWarning)

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

    def fr_download_file(self, node: str, storage: str, volume: str, path_b64: str, out_path: Path) -> None:
        """Lädt EINZELDATEI herunter (kein ZIP)."""
        url = f"{self.base}/api2/json/nodes/{node}/storage/{storage}/file-restore/download"
        params = {"volume": volume, "filepath": path_b64}
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with self.session.get(url, params=params, stream=True, timeout=self.READ_TIMEOUT) as r:
            r.raise_for_status()
            with out_path.open("wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)

    def fr_download_zip_stream(self, node: str, storage: str, volume: str, path_b64: str, tmp_zip: Path) -> None:
        """Lädt VERZEICHNIS als ZIP (Stream) in eine temporäre Datei."""
        url = f"{self.base}/api2/json/nodes/{node}/storage/{storage}/file-restore/download"
        params = {"volume": volume, "filepath": path_b64}
        tmp_zip.parent.mkdir(parents=True, exist_ok=True)
        with self.session.get(url, params=params, stream=True, timeout=self.READ_TIMEOUT) as r:
            r.raise_for_status()
            with open(tmp_zip, "wb") as f:
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
            "  dl <nr[,nr…]>     Datei(en)/Ordner herunterladen (Ordner -> ZIP)\n"
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
                name = ent.get("text") or ("dir" if is_dir(ent) else "download.bin")
                guest_path = (Path(cwd) / name).as_posix()
                out_path = base_target / guest_path.lstrip("/")

                if is_dir(ent):
                    # Ordner -> ZIP laden & entpacken
                    print(f"Lade Ordner als ZIP: '{guest_path}' …")
                    try:
                        # 1) ZIP streamend in temp-Datei laden
                        with tempfile.TemporaryDirectory() as td:
                            tmp_zip = Path(td) / "folder.zip"
                            client.fr_download_zip_stream(node, storage, volume, b64_path(guest_path), tmp_zip)

                            # 2) Entpacken in Zielordner
                            out_dir = out_path  # out_path repräsentiert den Ordnerpfad
                            out_dir.mkdir(parents=True, exist_ok=True)
                            safe_extract_zip(tmp_zip, out_dir, preserve_meta=preserve_meta, verbose=True)

                        print(f"  -> OK: entpackt nach {out_dir}")

                        # 3) Metadaten auf Wurzelordner anwenden (aus Listing, falls vorhanden)
                        if preserve_meta:
                            try:
                                apply_metadata_if_possible(ent, out_dir, verbose=True)
                            except Exception as e:
                                print(f"  -> Hinweis: Konnte Root-Ordner-Metadaten nicht setzen: {e}")

                    except requests.HTTPError as e:
                        print(f"  -> FEHLER beim ZIP-Download: {e}")
                else:
                    # Einzeldatei
                    print(f"Lade Datei: '{guest_path}' …")
                    try:
                        client.fr_download_file(node, storage, volume, b64_path(guest_path), out_path)
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

    # verify-Parameter bestimmen:
    verify_param: Union[bool, str]
    if args.ca_cert:
        verify_param = args.ca_cert
        if not Path(args.ca_cert).exists():
            sys.exit(f"CA-Bundle nicht gefunden: {args.ca_cert}")
    elif args.insecure:
        verify_param = False
    else:
        verify_param = True

    client = PVEClient(base, args.token_id, args.token_secret, verify=verify_param)

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
