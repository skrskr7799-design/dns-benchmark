"""Offline consistent backup/restore of the entire persistent state.

Run with the controller stopped; the same filesystem lock prevents overlap.
The directory may contain credentials: keep backups private and encrypted at rest.
"""
import argparse
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import stat
from pathlib import Path
from contextlib import contextmanager

DATABASES=("history.sqlite","monitoring.sqlite","agents.sqlite","intelligence.sqlite")
FILES=DATABASES+("owner-password","owner-account.json","telegram-token","adguard.json","throughput.json")

@contextmanager
def ownership(root):
    if not root.is_dir():
        raise ValueError("Data directory missing")
    with open(root/"coordinator.lock","a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield

def checksum(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()

def check_db(path):
    with sqlite3.connect(path) as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0]!="ok":
            raise ValueError("Invalid SQLite backup: "+path.name)
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("Foreign key violation: "+path.name)

def backup(root,dest):
    root=Path(root).resolve();dest=Path(dest).resolve()
    if dest==root or root in dest.parents or dest in root.parents:
        raise ValueError("Use separate backup directory")
    with ownership(root):
        dest.mkdir(mode=0o700)
        try:
            manifest={}
            for name in FILES:
                src=root/name
                if src.is_symlink():
                    raise ValueError("Unexpected symlink: "+name)
                if not src.exists():
                    continue
                if not stat.S_ISREG(src.stat().st_mode):
                    raise ValueError("Not a regular file: "+name)
                dst=dest/name
                if name in DATABASES:
                    with sqlite3.connect(src) as source,sqlite3.connect(dst) as target:
                        source.backup(target)
                    check_db(dst)
                else:
                    shutil.copyfile(src,dst)
                dst.chmod(0o600)
                manifest[name]=checksum(dst)
            if "history.sqlite" not in manifest:
                raise ValueError("Missing history database")
            p=dest/"manifest.json"
            p.write_text(json.dumps({"version":1,"files":manifest},indent=2))
            p.chmod(0o600)
        except BaseException:
            shutil.rmtree(dest)
            raise

def restore(source,dest):
    source=Path(source).resolve();dest=Path(dest).resolve()
    if dest==source or source in dest.parents or dest in source.parents:
        raise ValueError("Use a new separate data directory")
    manifest=json.loads((source/"manifest.json").read_text())
    files=manifest["files"]
    if manifest["version"]!=1 or not isinstance(files,dict) or "history.sqlite" not in files or not set(files)<=set(FILES):
        raise ValueError("Invalid backup manifest")
    dest.mkdir(mode=0o700)
    try:
        for name,expected in files.items():
            src=source/name
            if src.is_symlink() or not src.is_file():
                raise ValueError("Invalid backup file: "+name)
            dst=dest/name
            shutil.copyfile(src,dst)
            dst.chmod(0o600)
            if checksum(dst)!=expected:
                raise ValueError("Checksum mismatch: "+name)
            if name in DATABASES:
                check_db(dst)
    except BaseException:
        shutil.rmtree(dest)
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=["backup","restore"])
    parser.add_argument("source")
    parser.add_argument("destination")
    args=parser.parse_args()
    (backup if args.action=="backup" else restore)(args.source,args.destination)

if __name__=="__main__":
    main()
