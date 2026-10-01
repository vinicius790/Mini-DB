#!/usr/bin/env python3
"""Comandos portáveis do projeto. Uso: python tools/dev.py test|build|bench|smoke|package."""
from pathlib import Path
import argparse
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
# Espelha o .gitignore: nada de dados de runtime nem de chaves privadas no pacote.
EXCLUDE_DIRS = {".git", "target", "dist", "data", "__pycache__", "corpus", "artifacts"}
EXCLUDE_DIRS |= {"wal-archive", ".vscode"}
EXCLUDE_SUFFIXES = {".pyc", ".mdb", ".spill", ".next", ".swp", ".bk"}
EXCLUDE_NAMES = {"LOCK", "wal.log", "backup.jsonl", ".DS_Store"}
# Só na raiz, como no .gitignore: os certificados de teste ficam em tests/fixtures/pki.
EXCLUDE_ROOT = {"tmp", "pki", "tls.key", "tls.crt"}
# `x.mdb.key`, `x.mdb.journal`, `x.mdb.convert.state`, `x.snapshot.next-1`...
EXCLUDE_INFIXES = (".mdb.", ".snapshot.next-")


def cargo(*args: str) -> None:
    subprocess.run(["cargo", *args], cwd=ROOT, check=True)


def package() -> Path:
    destination = ROOT / "dist" / f"{ROOT.name}.zip"
    destination.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as out:
        for path in sorted(ROOT.rglob("*")):
            parts = path.relative_to(ROOT).parts
            if (
                not path.is_file()
                or path.is_symlink()
                or any(part in EXCLUDE_DIRS for part in parts)
                or parts[0] in EXCLUDE_ROOT
                or path.suffix in EXCLUDE_SUFFIXES
                or path.name in EXCLUDE_NAMES
                or any(infix in path.name for infix in EXCLUDE_INFIXES)
            ):
                continue
            out.write(path, Path(ROOT.name) / path.relative_to(ROOT))
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["test", "build", "bench", "smoke", "package"])
    command = parser.parse_args().command
    if command == "test":
        cargo("test", "--all-targets", "--locked")
        cargo("test", "--doc")
    elif command == "build":
        cargo("build", "--bins", "--lib", "--locked")
    elif command == "bench":
        cargo("run", "--release", "--bin", "minidb-bench", "--", "20000")
    elif command == "smoke":
        subprocess.run(["bash", str(ROOT / "scripts" / "clients_smoke.sh")], check=True)
    else:
        print(package())


if __name__ == "__main__":
    main()
