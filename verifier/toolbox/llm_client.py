from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

import requests

from verifier.config import DEFAULT_BASE_URL, DEFAULT_MODEL


def resolve_api_key() -> str:
    for env_name in ("OPENCODE_GO_API_KEY", "OPENAI_API_KEY"):
        val = os.getenv(env_name, "").strip()
        if val:
            return val
    if os.name == "nt":
        import winreg
        for env_name in ("OPENCODE_GO_API_KEY", "OPENAI_API_KEY"):
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                ) as reg:
                    val = str(winreg.QueryValueEx(reg, env_name)[0]).strip()
                    if val:
                        return val
            except OSError:
                pass
    raise ValueError("Missing API key: set OPENCODE_GO_API_KEY or OPENAI_API_KEY")


class LLMClient:
    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        max_tokens: int = 12000,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.max_tokens = max_tokens
        self.calls: List[Dict[str, Any]] = []
        self.session_id = str(uuid.uuid4())

    def complete(self, messages: List[Dict[str, str]], stage: str = "audit") -> str:
        for attempt in range(3):
            try:
                resp = requests.post(
                    self.url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                        "User-Agent": "bac-repro-verifier/1.0",
                        "x-opencode-session": self.session_id,
                    },
                    json={
                        "model": self.model,
                        "messages": messages,
                        "stream": False,
                        "max_tokens": self.max_tokens,
                    },
                    timeout=(30, 240),
                )
            except (requests.Timeout, requests.ConnectionError):
                if attempt == 2:
                    raise RuntimeError("LLM connection timed out after 3 attempts") from None
                time.sleep(2 ** (attempt + 1))
                continue

            if resp.status_code in (429,) or resp.status_code >= 500:
                if attempt < 2:
                    time.sleep(2 ** (attempt + 1))
                    continue

            if not resp.ok:
                detail = ""
                try:
                    err_obj = resp.json().get("error", {})
                    if isinstance(err_obj, dict) and isinstance(err_obj.get("message"), str):
                        detail = err_obj["message"].replace(self.api_key, "[REDACTED]")[:800]
                except Exception:
                    pass
                raise RuntimeError(f"LLM HTTP {resp.status_code}: {detail or 'request failed'}")

            payload = resp.json()
            choice = payload["choices"][0]
            content = choice["message"]["content"]
            self.calls.append({
                "stage": stage,
                "usage": payload.get("usage"),
                "finish_reason": choice.get("finish_reason"),
            })
            if choice.get("finish_reason") == "length":
                raise RuntimeError("LLM output truncated at max_tokens")
            if not isinstance(content, str) or not content.strip():
                raise RuntimeError("LLM returned empty content")
            return content.replace(self.api_key, "[REDACTED]")
        raise RuntimeError("Exhausted LLM retry loop")


def _repair_brackets(text: str) -> str:
    pairs = {"[": "]", "{": "}"}
    closers = {"]": "[", "}": "{"}
    stack: List[str] = []
    out: List[str] = []
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
        elif ch in "[{":
            stack.append(ch)
            out.append(ch)
        elif ch in "]}":
            wanted = closers[ch]
            if stack and stack[-1] == wanted:
                stack.pop()
                out.append(ch)
            elif wanted in stack:
                while stack and stack[-1] != wanted:
                    out.append(pairs[stack.pop()])
                if stack:
                    stack.pop()
                    out.append(ch)
        else:
            out.append(ch)
    while stack:
        out.append(pairs[stack.pop()])
    return "".join(out)


def parse_json_response(text: str) -> Any:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, count=1)
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as orig_err:
        starts = [idx for idx in (cleaned.find("{"), cleaned.find("[")) if idx >= 0]
        start = min(starts) if starts else 0
        repaired = _repair_brackets(cleaned[start:])
        try:
            val = json.loads(repaired)
            if isinstance(val, (dict, list)):
                return val
        except json.JSONDecodeError:
            pass
        decoder = json.JSONDecoder()
        for idx, ch in enumerate(cleaned):
            if ch not in "[{":
                continue
            try:
                val, _ = decoder.raw_decode(cleaned[idx:])
                if isinstance(val, (dict, list)):
                    return val
            except json.JSONDecodeError:
                continue
        raise orig_err


def run_validated_json_stage(
    client: Any,
    messages: List[Dict[str, str]],
    validator: Callable[[Any], None],
    stage: str,
    trace_log: List[Dict[str, Any]],
    max_repairs: int = 2,
    repair_prompt_builder: Optional[Callable[[Exception, str], str]] = None,
) -> Any:
    conv = list(messages)
    for attempt in range(max_repairs + 1):
        raw = client.complete(conv, stage=stage)
        trace_log.append({"stage": stage, "attempt": attempt + 1, "content": raw})
        try:
            parsed = parse_json_response(raw)
            validator(parsed)
            return parsed
        except Exception as exc:
            if attempt >= max_repairs:
                raise ValueError(f"Stage '{stage}' failed validation after {attempt + 1} attempts: {exc}") from None
            hint = (
                repair_prompt_builder(exc, raw)
                if repair_prompt_builder
                else f"JSON validation failed: {exc}. Return ONLY a valid JSON object matching the required schema."
            )
            conv.extend([
                {"role": "assistant", "content": raw},
                {"role": "user", "content": hint},
            ])
    raise RuntimeError("Unreachable")
