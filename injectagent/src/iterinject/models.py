"""Explicit per-role OpenAI-compatible clients with lazy, single-call execution."""

from __future__ import annotations

import math
import os
import re
from copy import deepcopy
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.parse import parse_qsl, urlsplit

from iterinject.core.types import ExecutionFailure


_CREDENTIAL_QUERY_NAMES = frozenset({
    "api_key", "api-key", "apikey", "key", "token", "access_token", "secret",
    "password", "auth", "authorization",
})


@dataclass(frozen=True)
class ModelConfig:
    role: str
    model: str
    base_url: str
    temperature: float
    max_output_tokens: int
    api_key_env: str
    thinking: str | None = None

    def __post_init__(self) -> None:
        for name in ("role", "model", "base_url"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be nonempty text")
        try:
            endpoint = urlsplit(self.base_url)
            query_names = {name.lower() for name, _ in parse_qsl(endpoint.query, keep_blank_values=True)}
            contains_credentials = (endpoint.username is not None or endpoint.password is not None
                                    or bool(query_names & _CREDENTIAL_QUERY_NAMES)
                                    or bool(endpoint.fragment))
        except ValueError:
            raise ValueError("base_url must be a valid endpoint URL") from None
        if contains_credentials:
            raise ValueError("base_url must not contain userinfo, credential query parameters, or a fragment")
        if (isinstance(self.temperature, bool)
                or not isinstance(self.temperature, (int, float))
                or not math.isfinite(self.temperature) or self.temperature < 0):
            raise ValueError("temperature must be a finite nonnegative number")
        if type(self.max_output_tokens) is not int or self.max_output_tokens < 1:
            raise ValueError("max_output_tokens must be a positive integer")
        if (not isinstance(self.api_key_env, str)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.api_key_env) is None):
            raise ValueError("api_key_env must be an environment variable name")
        if self.thinking is not None and self.thinking not in ("enabled", "disabled"):
            raise ValueError("thinking must be enabled, disabled, or omitted")

    def to_dict(self) -> dict[str, Any]:
        """Public configuration contains the key variable's name, never its value."""
        return asdict(self)


class ModelCallError(RuntimeError):
    """An execution failure, never a four-level attack diagnosis."""

    def __init__(self, failure: ExecutionFailure):
        self.failure = failure
        super().__init__(failure.message)


def _redact(value: Any, key: str | None) -> Any:
    """Preserve request/response content except the configured credential value."""
    if isinstance(value, str):
        return value.replace(key, "[REDACTED]") if key else value
    if isinstance(value, dict):
        return {name: _redact(item, key) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item, key) for item in value]
    return value


def _context_error(error: Exception) -> bool:
    code = getattr(error, "code", None)
    body = getattr(error, "body", None)
    if isinstance(body, dict):
        inner = body.get("error", body)
        if isinstance(inner, dict):
            code = inner.get("code", code)
    # Inspect server text only for classification; never put it in a record or exception.
    text = str(error).lower()
    return code in {"context_length_exceeded", "context_window_exceeded"} or any(
        marker in text for marker in ("context_length_exceeded", "maximum context length",
                                     "context window exceeded"))


def _response_snapshot(response: Any) -> dict[str, Any]:
    if hasattr(response, "model_dump"):
        return response.model_dump(mode="json")
    # Minimal SDK-compatible test clients may expose attributes rather than Pydantic.
    return {
        "id": getattr(response, "id", None),
        "choices": [{"message": {"content": choice.message.content},
                     "finish_reason": getattr(choice, "finish_reason", None)}
                    for choice in getattr(response, "choices", ())],
    }


class OpenAICompatibleClient:
    """One SDK request per completion; failures keep complete reviewable records.

    The caller must stop its case after ModelCallError. No dotenv loader, SDK import,
    initialization, retries, history truncation, or model request occurs on import.
    """

    def __init__(self, config: ModelConfig, sdk_factory: Callable[..., Any] | None = None):
        self.config = config
        self._sdk_factory = sdk_factory
        self._sdk: Any = None
        self.call_records: list[dict[str, Any]] = []

    @property
    def call_count(self) -> int:
        return sum(record["api_calls"] for record in self.call_records)

    def _sdk_client(self, key: str | None) -> Any:
        if not key:
            raise ModelCallError(ExecutionFailure(
                "missing_api_key", f"Environment variable {self.config.api_key_env} is unset or empty."))
        if self._sdk is None:
            factory = self._sdk_factory
            try:
                if factory is None:
                    from openai import OpenAI
                    factory = OpenAI
                self._sdk = factory(api_key=key, base_url=self.config.base_url, max_retries=0)
            except Exception:
                # SDK initialization exceptions can contain authorization headers.
                raise ModelCallError(ExecutionFailure(
                    "model_initialization_error", "OpenAI-compatible SDK initialization failed.")) from None
        return self._sdk

    @staticmethod
    def _fail(record: dict[str, Any], kind: str, message: str) -> None:
        failure = ExecutionFailure(kind, message)
        record["failure"] = asdict(failure)
        raise ModelCallError(failure) from None

    def complete(self, messages: list[dict]) -> str:
        key = os.environ.get(self.config.api_key_env)
        record: dict[str, Any] = {
            "index": len(self.call_records), "role": self.config.role,
            "config": self.config.to_dict(), "messages": _redact(deepcopy(messages), key),
            "raw_response": None, "output": None, "failure": None, "api_calls": 0,
        }
        self.call_records.append(record)
        try:
            sdk = self._sdk_client(key)
        except ModelCallError as error:
            record["failure"] = asdict(error.failure)
            raise

        record["api_calls"] = 1
        request_error: ExecutionFailure | None = None
        request = dict(model=self.config.model, messages=messages,
                       temperature=self.config.temperature,
                       max_tokens=self.config.max_output_tokens)
        if self.config.thinking is not None:
            request["extra_body"] = {"thinking": {"type": self.config.thinking}}
        try:
            response = sdk.chat.completions.create(**request)
        except Exception as error:
            record["error_type"] = type(error).__name__
            status_code = getattr(error, "status_code", None)
            if type(status_code) is int:
                record["status_code"] = status_code
            if _context_error(error):
                request_error = ExecutionFailure(
                    "model_context_length_exceeded",
                    "Model context limit exceeded; complete input preserved without retry or truncation.")
            else:
                request_error = ExecutionFailure(
                    "model_request_error", "OpenAI-compatible completion request failed.")
        # Raise outside the SDK exception handler; caller-visible errors carry no server text.
        if request_error is not None:
            record["failure"] = asdict(request_error)
            raise ModelCallError(request_error)

        try:
            record["raw_response"] = _redact(_response_snapshot(response), key)
            choices = response.choices
            output = choices[0].message.content if choices else None
        except Exception:
            self._fail(record, "invalid_model_response", "Model response has an invalid completion structure.")
        record["output"] = _redact(output, key)
        if output is None or (isinstance(output, str) and not output.strip()):
            self._fail(record, "empty_model_response", "Model response contains no payload text.")
        if not isinstance(output, str):
            self._fail(record, "invalid_model_response", "Model response content must be text.")
        # No trimming, code-fence removal, repair, or retry: evaluated text is the model text.
        return output
