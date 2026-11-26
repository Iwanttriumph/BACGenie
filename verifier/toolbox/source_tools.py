from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from verifier.config import MAX_OPS_PER_ROUND, MAX_READ_LINES, MAX_SOURCE_CHARS

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".next"}
MAX_FILE_BYTES = 2 * 1024 * 1024


class ReadOnlySourceWorkspace:
    """Sandboxed read-only source navigator (`list` / `search` / `read`) for `repo_path`."""

    def __init__(self, repo_path: Optional[Path], char_budget: int = MAX_SOURCE_CHARS) -> None:
        self.root = repo_path.resolve() if (repo_path and repo_path.is_dir()) else None
        self.char_budget = char_budget
        self.chars_used = 0
        self.audit_log: List[Dict[str, Any]] = []
        self._files: List[Path] = []
        if self.root is not None:
            self._index_files()

    @property
    def available(self) -> bool:
        return self.root is not None and len(self._files) > 0

    def _index_files(self) -> None:
        assert self.root is not None
        collected: List[Path] = []
        for item in self.root.rglob("*"):
            if item.is_symlink():
                continue
            rel_parts = item.relative_to(self.root).parts
            if any(part in IGNORED_DIRS for part in rel_parts):
                continue
            if item.is_file():
                try:
                    if item.stat().st_size <= MAX_FILE_BYTES:
                        collected.append(item)
                except OSError:
                    continue
        self._files = sorted(collected)

    def _resolve_safe(self, rel_path: str) -> Path:
        if self.root is None:
            raise ValueError("Source repository is unavailable")
        norm = (rel_path or ".").strip().lstrip("/\\")
        cand = (self.root / norm).resolve()
        if cand != self.root and self.root not in cand.parents:
            raise ValueError(f"Path escapes repository root: {rel_path}")
        if cand.is_symlink():
            raise ValueError(f"Symlink access forbidden: {rel_path}")
        return cand

    def execute_ops(self, ops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for op_spec in ops[:MAX_OPS_PER_ROUND]:
            if self.chars_used >= self.char_budget:
                results.append({"op": op_spec, "error": "Source character budget exhausted"})
                break
            res = self._run_single(op_spec)
            serialized = str(res)
            self.chars_used += len(serialized)
            self.audit_log.append(res)
            results.append(res)
        return results

    def _run_single(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        op = str(spec.get("op") or "").lower()
        rel = str(spec.get("path") or "")
        offset = max(0, int(spec.get("offset") or 0))
        try:
            if op == "list":
                target = self._resolve_safe(rel)
                if not target.is_dir():
                    return {"op": "list", "path": rel, "error": "Not a directory"}
                entries = sorted(
                    p.name + ("/" if p.is_dir() else "")
                    for p in target.iterdir()
                    if not p.is_symlink() and p.name not in IGNORED_DIRS
                )
                page = entries[offset : offset + 80]
                return {"op": "list", "path": rel or ".", "total": len(entries), "offset": offset, "entries": page}

            if op == "search":
                query = str(spec.get("query") or "").strip()
                if not query:
                    return {"op": "search", "error": "Empty query"}
                prefix_dir = self._resolve_safe(rel) if rel else self.root
                assert self.root is not None and prefix_dir is not None
                q_low = query.lower()
                hits: List[Dict[str, Any]] = []
                for fpath in self._files:
                    if prefix_dir != self.root and prefix_dir not in fpath.parents and fpath != prefix_dir:
                        continue
                    try:
                        text = fpath.read_text(encoding="utf-8")
                    except (UnicodeDecodeError, OSError):
                        continue
                    if q_low not in text.lower():
                        continue
                    f_rel = fpath.relative_to(self.root).as_posix()
                    for lineno, line in enumerate(text.splitlines(), start=1):
                        if q_low in line.lower():
                            hits.append({"path": f_rel, "line": lineno, "snippet": line.strip()[:240]})
                            if len(hits) >= offset + 40:
                                break
                    if len(hits) >= offset + 40:
                        break
                return {"op": "search", "query": query, "path": rel or ".", "matches": hits[offset : offset + 40]}

            if op == "read":
                target = self._resolve_safe(rel)
                if not target.is_file():
                    return {"op": "read", "path": rel, "error": "File not found"}
                assert self.root is not None
                raw_bytes = target.read_bytes()
                text = raw_bytes.decode("utf-8", errors="replace")
                lines = text.splitlines()
                start = max(1, int(spec.get("start") or 1))
                end = min(len(lines), int(spec.get("end") or (start + MAX_READ_LINES - 1)))
                if end - start + 1 > MAX_READ_LINES:
                    end = start + MAX_READ_LINES - 1
                numbered = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
                return {
                    "op": "read",
                    "path": target.relative_to(self.root).as_posix(),
                    "start": start,
                    "end": end,
                    "total_lines": len(lines),
                    "sha256_12": hashlib.sha256(raw_bytes).hexdigest()[:12],
                    "content": numbered,
                }

            return {"op": op, "error": "Unsupported operation; use list, search, or read"}
        except Exception as exc:
            return {"op": op, "path": rel, "error": str(exc)}
