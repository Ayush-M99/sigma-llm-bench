"""Thin client for OpenAI-compatible endpoints (NVIDIA API catalog by default)."""
import os
import time

from openai import OpenAI

BASE_URL = os.environ.get("LLM_BASE_URL", "https://integrate.api.nvidia.com/v1")
API_KEY = os.environ.get("NVIDIA_API_KEY", "nvapi-placeholder")

_client = OpenAI(base_url=BASE_URL, api_key=API_KEY, timeout=300, max_retries=0)


def chat(model, messages, temperature=0.2, max_tokens=8000, retries=3):
    """Return the completion text, retrying on rate limits and transient errors."""
    for attempt in range(retries):
        try:
            # Stream so long generations don't hit gateway timeouts (HTTP 502).
            stream = _client.chat.completions.create(
                model=model, messages=messages,
                temperature=temperature, max_tokens=max_tokens, stream=True,
            )
            text = "".join(c.choices[0].delta.content or "" for c in stream if c.choices)
            if not text.strip():
                raise RuntimeError("empty response")
            return text
        except Exception as e:  # noqa: BLE001 - surface the last error after retries
            if attempt == retries - 1:
                raise
            wait = 2 ** attempt * (5 if "429" in str(e) else 2)
            time.sleep(wait)
