import json
import os
import tempfile
from pathlib import Path


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     delete=False, suffix=".tmp") as f:
        tmp = Path(f.name)
        f.write(text)
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def write_json(path, data):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


