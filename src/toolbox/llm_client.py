import json
import os
import re
import time
import uuid
import requests
from src.config import MODEL, BASE_URL
def get_key():
    key = os.getenv("OPENCODE_GO_API_KEY", "").strip()
    if not key and os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as reg:
                key = str(winreg.QueryValueEx(reg, "OPENCODE_GO_API_KEY")[0]).strip()
        except FileNotFoundError:
            pass
    if not key:
        raise ValueError("未找到 OPENCODE_GO_API_KEY（进程环境或 Windows Machine 系统变量）")
    return key


class Client:
    def __init__(self, key, model=MODEL, base_url=BASE_URL):
        self.key, self.model = key, model
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.calls = []
        self.session_id = str(uuid.uuid4())

    def complete(self, messages, stage):
        for attempt in range(3):
            try:
                response = requests.post(self.url,
                    headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json",
                             "User-Agent": "trigger-pattern-agent/1.0",
                             "x-opencode-session": self.session_id},
                    json={"model": self.model, "messages": messages, "stream": False,
                          "max_tokens": 24000 if stage == "oracle" else 12000}, timeout=(30, 240))
            except (requests.Timeout, requests.ConnectionError):
                if attempt == 2:
                    raise RuntimeError("网络连接失败或请求超时（已重试两次）") from None
                time.sleep(2 ** (attempt + 1))
                continue
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < 2:
                    time.sleep(2 ** (attempt + 1))
                    continue
            if not response.ok:
                # Only expose the provider's message, never request headers/full response.
                detail = ""
                try:
                    problem = response.json().get("error", {})
                    if isinstance(problem, dict) and isinstance(problem.get("message"), str):
                        detail = problem["message"].replace(self.key, "[REDACTED]")[:1200]
                except (ValueError, AttributeError):
                    pass
                raise RuntimeError(f"模型接口 HTTP {response.status_code}；{detail or '检查认证、模型、额度或接口配置'}")
            try:
                payload = response.json()
                choice = payload["choices"][0]
                content = choice["message"]["content"]
            except (ValueError, KeyError, IndexError, TypeError):
                raise RuntimeError("模型接口返回了无法识别的响应结构") from None
            self.calls.append({"stage": stage, "usage": payload.get("usage"),
                               "finish_reason": choice.get("finish_reason")})
            if choice.get("finish_reason") == "length":
                raise RuntimeError("模型输出达到长度限制，未将截断内容保存为有效结果")
            if not isinstance(content, str) or not content.strip():
                raise RuntimeError("模型未返回非空文本回答")
            return content.replace(self.key, "[REDACTED]")


def _repair_brackets(text):
    """Insert missing closers before mismatched closers; skip stray closers."""
    pairs = {"[": "]", "{": "}"}
    closers = {"]": "[", "}": "{"}
    stack, out = [], []
    in_string = escape = False
    for char in text:
        if in_string:
            out.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            out.append(char)
        elif char in "[{":
            stack.append(char)
            out.append(char)
        elif char in "]}":
            wanted = closers[char]
            if stack and stack[-1] == wanted:
                stack.pop()
                out.append(char)
            elif wanted in stack:
                while stack and stack[-1] != wanted:
                    out.append(pairs[stack.pop()])
                if stack:
                    stack.pop()
                    out.append(char)
            # else: stray closer, drop it
        else:
            out.append(char)
    while stack:
        out.append(pairs[stack.pop()])
    return "".join(out)


def parse_json(text):
    text = text.strip()
    if text.startswith("```") and text.endswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, count=1).rsplit("```", 1)[0].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError as original:
        start = min([index for index in (text.find("{"), text.find("[")) if index >= 0] or [0])
        repaired = _repair_brackets(text[start:])
        if repaired != text[start:]:
            try:
                value = json.loads(repaired)
                if isinstance(value, (dict, list)):
                    return value
            except json.JSONDecodeError:
                pass
        # Models occasionally append a second object, a closing note or a
        # Markdown fence.  Accept the first complete JSON value; the stage
        # checker still validates its content.
        decoder = json.JSONDecoder()
        for index, char in enumerate(text):
            if char not in "[{":
                continue
            try:
                value, end = decoder.raw_decode(text[index:])
            except json.JSONDecodeError:
                continue
            if not isinstance(value, (dict, list)):
                continue
            rest = text[index + end:].strip()
            if isinstance(value, dict):
                # A common model failure is closing the root object after
                # "oracle" and appending ,"analysis":"..."} as extra data.
                if rest.startswith(","):
                    merged = text[index:index + end - 1] + rest
                    try:
                        candidate = json.loads(merged)
                    except json.JSONDecodeError:
                        candidate = None
                    if isinstance(candidate, dict):
                        return candidate
                # Another variant is two adjacent objects.
                if rest.startswith("{"):
                    try:
                        extra, _ = decoder.raw_decode(rest)
                    except json.JSONDecodeError:
                        extra = None
                    if isinstance(extra, dict):
                        return {**value, **extra}
            return value
        raise original


def run_stage(client, messages, checker, stage, trace, max_repairs=1, repair=None):
    messages = list(messages)
    for attempt in range(max_repairs + 1):
        raw = client.complete(messages, stage)
        trace.append({"stage": stage, "attempt": attempt + 1, "content": raw})
        try:
            data = parse_json(raw)
            checker(data)
            return data
        except (ValueError, TypeError, KeyError) as error:
            if attempt >= max_repairs:
                raise ValueError(f"{stage} 修正后仍不合法: {error}") from None
            hint = repair(error, raw) if repair else (
                f"校验失败：{error}。仅修正 JSON 和必要的一致性错误，"
                "仅依据当前阶段提供的数据，不补充外部信息。只返回完整 JSON。"
            )
            messages.extend([{"role": "assistant", "content": raw},
                             {"role": "user", "content": hint}])


