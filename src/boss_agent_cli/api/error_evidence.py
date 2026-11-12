"""把失败分层成可核对的证据，不把预算、超时或文案里的数字当成上游业务码。

``request_attempted`` / ``request_sent`` / ``response_received`` 只取 ``True``、
``False`` 或字符串 ``"unknown"``。没有对应证据时必须是 ``unknown``，不能省略后被
读成「已经发出」或「已经收到平台 JSON」。
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from boss_agent_cli.output import redact_sensitive_text

UNKNOWN = "unknown"
UPSTREAM_MESSAGE_LIMIT = 120

#: 与 ``normalize_risk_code`` 同一组码。只接受整个字段等于这些值，不扫描正文。
_RISK_CODES = (31, 32, 35, 36, 37, 38)
_STRONG_ENVIRONMENT_MARKERS = (
	"环境存在异常",
	"访问环境异常",
	"请求环境异常",
)
_URL_IN_TEXT = re.compile(r"https?://[^\s]+", re.IGNORECASE)


class BrowserKernelMissing(RuntimeError):
	"""本机 headless 内核文件不存在。预检在启动浏览器之前抛出，不下载、不发请求。"""

	def __init__(self, executable: str) -> None:
		self.details = kernel_missing_details(executable)
		super().__init__(
			"BrowserType.launch: Executable doesn't exist at "
			f"{executable}"
		)


class BrowserStartupError(RuntimeError):
	"""浏览器进程没有起来。此时还没有导航，也没有业务请求。"""

	def __init__(self, message: str) -> None:
		self.details = {
			"origin": "local_startup",
			"request_attempted": False,
			"request_sent": False,
			"response_received": False,
			"upstream": empty_upstream(),
		}
		super().__init__(message)


def empty_upstream() -> dict[str, Any]:
	return {"source": "none", "http_status": None, "code": None, "message": None}


def kernel_missing_details(executable: str | None = None) -> dict[str, Any]:
	details: dict[str, Any] = {
		"origin": "local_dependency",
		"request_attempted": False,
		"request_sent": False,
		"response_received": False,
		"upstream": empty_upstream(),
	}
	if executable:
		details["executable"] = executable
	return details


def public_upstream_text(value: str | None, *, limit: int = UPSTREAM_MESSAGE_LIMIT) -> str | None:
	"""保留最短的脱敏文本。去掉 URL query，再按凭据规则打码并截断。"""
	if not isinstance(value, str):
		return None
	text = _URL_IN_TEXT.sub(_strip_url_query, value)
	text = redact_sensitive_text(text)
	text = " ".join(text.split())
	if not text:
		return None
	if len(text) > limit:
		return text[: limit - 1] + "…"
	return text


def _strip_url_query(match: re.Match[str]) -> str:
	raw = match.group(0)
	try:
		parts = urlsplit(raw)
	except ValueError:
		return "[url]"
	if not parts.scheme or not parts.netloc:
		return "[url]"
	return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def explicit_text(response: dict[str, Any]) -> str:
	"""只读 message/msg/error 字符串。不把 zpData 或整段正文扫进来。"""
	parts: list[str] = []
	for key in ("message", "msg", "error"):
		value = response.get(key)
		if isinstance(value, str) and value.strip():
			parts.append(value.strip())
	return "\n".join(parts)


def strong_environment_text(text: str) -> bool:
	return any(marker in text for marker in _STRONG_ENVIRONMENT_MARKERS)


def structured_risk_code(value: Any) -> int | None:
	"""整个字段就是风险码时才返回整数。``"elapsed 37 ms"`` 这类文本返回 None。"""
	if isinstance(value, bool):
		return None
	if isinstance(value, int) and value in _RISK_CODES:
		return value
	if isinstance(value, str) and value in {str(code) for code in _RISK_CODES}:
		return int(value)
	return None


def structured_json_code(value: Any) -> int | None:
	"""JSON 业务码字段。负数是本工具哨兵，不算上游码；正文里的数字不算。"""
	if isinstance(value, bool):
		return None
	if isinstance(value, int):
		return value if value >= 0 else None
	if isinstance(value, str) and value.isdigit():
		return int(value)
	return None


def _detail_map(response: dict[str, Any]) -> dict[str, Any]:
	details = response.get("__cli_error_details__")
	return details if isinstance(details, dict) else {}


def http_status_of(response: dict[str, Any]) -> int | None:
	for value in (response.get("__cli_http_status__"), _detail_map(response).get("http_status")):
		if isinstance(value, bool):
			continue
		if isinstance(value, int) and 100 <= value <= 599:
			return value
	return None


def evidence_source_of(response: dict[str, Any]) -> str | None:
	for value in (response.get("__cli_evidence_source__"), _detail_map(response).get("evidence_source")):
		if isinstance(value, str) and value:
			return value
	return None


def environment_text_flag(response: dict[str, Any]) -> bool:
	if response.get("__cli_environment_text__") is True:
		return True
	return _detail_map(response).get("environment_text") is True


def observed_platform_code(response: dict[str, Any]) -> int | None:
	"""只承认结构化字段。显式 ``__cli_platform_code__: null`` 表示未知，不回退到内部码。"""
	if "__cli_platform_code__" in response:
		return structured_risk_code(response.get("__cli_platform_code__"))
	return structured_risk_code(response.get("code"))


def _transport_tri_state(response: dict[str, Any]) -> tuple[str, bool | str, bool | str]:
	"""根据响应对象自身的标记判断发送/收到，不读取预算库。"""
	if response.get("__cli_request_interrupted__") is True:
		return "transport", UNKNOWN, UNKNOWN
	# 官方限制页 / 安全页先于业务 JSON。内部码 36 不能盖过「原码未知」。
	if response.get("__cli_risk_source__") in ("access_restricted_page", "security_page"):
		return "http", True, True
	source = evidence_source_of(response)
	status = http_status_of(response)
	if source == "non_json":
		return ("http" if status is not None else "parse"), True, True
	if source == "upstream_json" or structured_json_code(response.get("code")) is not None:
		return "upstream_json", True, True
	return "unknown", UNKNOWN, UNKNOWN


def evidence_for_response(response: dict[str, Any], *, envelope_code: str | None = None) -> dict[str, Any]:
	"""给已经拿到的响应字典补证据。没有 HTTP 状态就留 null，不补造。"""
	origin, request_sent, response_received = _transport_tri_state(response)
	status = http_status_of(response)
	observed = observed_platform_code(response)
	message = public_upstream_text(explicit_text(response))
	if evidence_source_of(response) == "non_json" and not explicit_text(response):
		message = None
	if origin == "upstream_json":
		upstream_source = "upstream_json"
		upstream_code = observed if observed is not None else structured_json_code(response.get("code"))
	elif origin == "http" and response.get("__cli_risk_source__") in ("access_restricted_page", "security_page"):
		upstream_source = str(response.get("__cli_risk_source__"))
		upstream_code = observed
	elif origin == "http":
		upstream_source = "http"
		upstream_code = None
	else:
		upstream_source = "none"
		upstream_code = None
	attempted: bool | str = True if request_sent is True else (False if request_sent is False else UNKNOWN)
	fragment: dict[str, Any] = {
		"origin": origin,
		"request_attempted": attempted,
		"request_sent": request_sent,
		"response_received": response_received,
		"upstream": {
			"source": upstream_source,
			"http_status": status,
			"code": upstream_code,
			"message": message,
		},
	}
	# 只有风控信封才写 platform_code。其它码把原码留在 upstream.code，避免把 37 贴到可恢复错误上。
	risk_envelope = envelope_code in {None, "ACCOUNT_RISK", "ENVIRONMENT_RISK", "ENVIRONMENT_RISK_LOCKED"}
	if observed is not None and origin in {"upstream_json", "http"} and risk_envelope:
		fragment["platform_code"] = observed
	return fragment


def stash_transport_evidence(result: dict[str, Any]) -> None:
	"""把传输标记移入 __cli_error_details__，成功结果不保留这些内部键。"""
	status = result.pop("__cli_http_status__", None)
	source = result.pop("__cli_evidence_source__", None)
	environment = result.pop("__cli_environment_text__", None)
	if result.get("code") in (0, "0"):
		return
	details = result.get("__cli_error_details__")
	if not isinstance(details, dict):
		details = {}
	if isinstance(status, int) and not isinstance(status, bool):
		details["http_status"] = status
	if isinstance(source, str) and source:
		details["evidence_source"] = source
	if environment is True:
		details["environment_text"] = True
	if details:
		result["__cli_error_details__"] = details


def inference_details(response: dict[str, Any]) -> dict[str, Any]:
	"""文案像环境异常，但没有结构化业务码。停机，不写成 platform_code。"""
	# 没有传输标记时保持 unknown，不因为「函数被调用了」就升成已发送。
	_, request_sent, response_received = _transport_tri_state(response)
	return {
		"origin": "tool_inference",
		"request_attempted": True if request_sent is True else UNKNOWN,
		"request_sent": request_sent,
		"response_received": response_received,
		"platform_code": None,
		"upstream": {
			"source": "tool_inference",
			"http_status": http_status_of(response),
			"code": None,
			"message": public_upstream_text(explicit_text(response)),
		},
	}


def risk_details_from_response(response: dict[str, Any]) -> dict[str, Any]:
	if _should_infer_environment(response):
		return inference_details(response)
	return evidence_for_response(response)


def _should_infer_environment(response: dict[str, Any]) -> bool:
	if response.get("code") in (0, "0"):
		return False
	if response.get("__cli_request_interrupted__") is True:
		return False
	if structured_risk_code(response.get("code")) is not None:
		return False
	if "__cli_platform_code__" in response and structured_risk_code(response.get("__cli_platform_code__")) is not None:
		return False
	return strong_environment_text(explicit_text(response)) or environment_text_flag(response)


def merge_evidence(details: dict[str, Any] | None, fragment: dict[str, Any]) -> dict[str, Any]:
	merged: dict[str, Any] = dict(details or {})
	for key, value in fragment.items():
		if key == "platform_code" and value is None and merged.get("platform_code") is not None:
			continue
		if key not in merged or merged[key] is None:
			merged[key] = value
	return merged


def unknown_failure_details() -> dict[str, Any]:
	return {
		"origin": "unknown",
		"request_attempted": UNKNOWN,
		"request_sent": UNKNOWN,
		"response_received": UNKNOWN,
		"upstream": empty_upstream(),
	}


def transport_details_from_exception(exc: BaseException) -> dict[str, Any] | None:
	"""DNS / 连接失败可以证明没送出；读超时不能证明对方没收到，记 unknown。"""
	name = type(exc).__name__
	text = str(exc).lower()
	dns_markers = (
		"name or service not known",
		"nodename nor servname",
		"temporary failure in name resolution",
		"getaddrinfo",
		"name resolution",
		"errno -2",
		"errno -3",
	)
	if name in {"gaierror"} or any(marker in text for marker in dns_markers):
		return _transport(False, False)
	if name in {"ConnectError", "ConnectTimeout", "PoolTimeout"}:
		return _transport(False, False)
	if name in {"ReadTimeout"}:
		return _transport(True, UNKNOWN)
	if name in {"WriteTimeout", "WriteError", "ReadError", "TimeoutException", "TimeoutError"}:
		return _transport(UNKNOWN, UNKNOWN)
	if isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text:
		return _transport(UNKNOWN, UNKNOWN)
	if isinstance(exc, ConnectionError):
		return _transport(False, False)
	return None


def _transport(request_sent: bool | str, response_received: bool | str) -> dict[str, Any]:
	attempted: bool | str
	if request_sent is False:
		attempted = True
	elif request_sent is True:
		attempted = True
	else:
		attempted = UNKNOWN
	return {
		"origin": "transport",
		"request_attempted": attempted,
		"request_sent": request_sent,
		"response_received": response_received,
		"upstream": empty_upstream(),
	}


def is_kernel_missing_message(exc: BaseException) -> bool:
	text = str(exc).lower()
	return "executable doesn't exist" in text or "playwright was just installed" in text
