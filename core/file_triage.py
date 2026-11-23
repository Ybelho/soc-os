import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional


@dataclass
class FileRecord:
    path: str
    filename: str
    size: int
    sha256: str
    sha1: str
    md5: str


def _hash_file(path: str, chunk_size: int = 1024 * 1024) -> FileRecord:
    h256 = hashlib.sha256()
    h1 = hashlib.sha1()
    hmd5 = hashlib.md5()

    size = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            size += len(b)
            h256.update(b)
            h1.update(b)
            hmd5.update(b)

    return FileRecord(
        path=path,
        filename=os.path.basename(path),
        size=size,
        sha256=h256.hexdigest(),
        sha1=h1.hexdigest(),
        md5=hmd5.hexdigest(),
    )


def _iter_files(root_dir: str) -> Iterator[str]:
    root = Path(root_dir)
    if not root.exists():
        return
    for p in root.rglob("*"):
        if p.is_file():
            yield str(p)


class FileTriage:
    """
    Hashing simple des objets exportés (HTTP export objects).
    Écrit un JSONL ingestable par DuckDB.
    """

    @staticmethod
    def hash_dir_to_jsonl(root_dir: str, out_jsonl: str, max_files: int = 5000) -> Optional[str]:
        files = list(_iter_files(root_dir))
        if not files:
            return None

        Path(os.path.dirname(out_jsonl) or ".").mkdir(parents=True, exist_ok=True)

        n = 0
        with open(out_jsonl, "w", encoding="utf-8") as f:
            for path in files:
                try:
                    rec = _hash_file(path)
                except Exception:
                    continue
                row = {
                    "path": rec.path,
                    "filename": rec.filename,
                    "size": rec.size,
                    "sha256": rec.sha256,
                    "sha1": rec.sha1,
                    "md5": rec.md5,
                }
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
                n += 1
                if n >= max_files:
                    break

        return out_jsonl
