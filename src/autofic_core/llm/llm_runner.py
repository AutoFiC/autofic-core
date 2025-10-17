from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

from openai import OpenAI, APIConnectionError, RateLimitError
from openai.types.chat import ChatCompletion

from autofic_core.errors import LLMExecutionError


DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
DEFAULT_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.2"))
MAX_RETRIES = int(os.getenv("OPENAI_MAX_RETRIES", "3"))
RETRY_BACKOFF = float(os.getenv("OPENAI_RETRY_BACKOFF", "2.0"))


@dataclass
class Prompt:
    prompt: str
    file_path: str
    prompt_id: Optional[str] = None


def _client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise LLMExecutionError("[LLM] OPENAI_API_KEY is not set")
    return OpenAI(api_key=api_key)


def _mk_messages(user_content: str) -> List[dict]:
    sys = os.getenv(
        "OPENAI_SYSTEM_PROMPT",
        "You are a helpful assistant that writes minimal, correct code patches.",
    )
    return [
        {"role": "system", "content": sys},
        {"role": "user", "content": user_content},
    ]


def _extract_text(resp: ChatCompletion) -> str:
    try:
        return resp.choices[0].message.content or ""
    except Exception:
        return ""


_filename_sanitize_re = re.compile(r"[^a-zA-Z0-9_.-]+")


def _safe_filename(s: str) -> str:
    s = s.replace("/", "_").replace("\\", "_").replace(":", "_")
    s = _filename_sanitize_re.sub("_", s)
    return s.strip("_") or "unknown"


def _get_prompt_meta(prompt_obj: Any) -> Tuple[str, str]:
    file_path = getattr(prompt_obj, "file_path", None)
    if file_path is None and isinstance(prompt_obj, dict):
        file_path = prompt_obj.get("file_path")
    file_path = file_path or "unknown"

    pid = getattr(prompt_obj, "prompt_id", None)
    if pid is None:
        pid = getattr(prompt_obj, "id", None)
    if pid is None:
        pid = getattr(prompt_obj, "uid", None)
    if pid is None and isinstance(prompt_obj, dict):
        pid = prompt_obj.get("prompt_id") or prompt_obj.get("id") or prompt_obj.get("uid")
    if pid is None:
        pid = str(time.time_ns())

    return str(file_path), str(pid)


def save_md_response(text: str, prompt_obj: Any, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    file_path, _ = _get_prompt_meta(prompt_obj)
    # ex) routes/app.js -> app
    base_stem = _safe_filename(Path(file_path).stem) or "response"
    name = f"{base_stem}.md"
    path = output_dir / name

    if path.exists():
        i = 1
        while True:
            candidate = output_dir / f"{base_stem}_{i}.md"
            if not candidate.exists():
                path = candidate
                break
            i += 1

    with path.open("w", encoding="utf-8") as f:
        f.write(text)
    return path


class LLMRunner:
    def __init__(self, model: Optional[str] = None, temperature: Optional[float] = None):
        self.model = model or DEFAULT_MODEL
        self.temperature = DEFAULT_TEMPERATURE if temperature is None else temperature
        self.client = _client()

    def run(self, user_prompt: str) -> str:
        last_err: Optional[Exception] = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=_mk_messages(user_prompt),
                    temperature=self.temperature,
                )
                text = _extract_text(resp)
                if not text.strip():
                    raise LLMExecutionError("[LLM] Empty response")
                return text
            except (RateLimitError, APIConnectionError) as e:
                last_err = e
                if attempt >= MAX_RETRIES:
                    break
                time.sleep(RETRY_BACKOFF * attempt)
            except Exception as e:
                last_err = e
                break
        raise LLMExecutionError(f"[LLM] call failed: {last_err}")
