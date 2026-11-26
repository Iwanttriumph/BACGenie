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


def parse_json(text):
    text = text.strip()
    if text.startswith("```") and text.endswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, count=1).rsplit("```", 1)[0].strip()
    return json.loads(text)


def run_stage(client, messages, checker, stage, trace):
    messages = list(messages)
    for attempt in range(2):
        raw = client.complete(messages, stage)
        trace.append({"stage": stage, "attempt": attempt + 1, "content": raw})
        try:
            data = parse_json(raw)
            checker(data)
            return data
        except (ValueError, TypeError, KeyError) as error:
            if attempt:
                raise ValueError(f"{stage} 修正后仍不合法: {error}") from None
            messages.extend([{"role": "assistant", "content": raw},
                             {"role": "user", "content": f"校验失败：{error}。仅修正 JSON 和必要的一致性错误，仅依据当前阶段提供的数据，不补充外部信息。只返回完整 JSON。"}])


