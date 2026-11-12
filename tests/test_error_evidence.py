"""离线错误分层：不访问招聘站点，也不把预算或正文里的 37 当成上游业务码。"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from boss_agent_cli.api.error_evidence import (
	BrowserKernelMissing,
	BrowserStartupError,
	evidence_for_response,
	public_upstream_text,
	transport_details_from_exception,
)
from boss_agent_cli.api.zhipin_errors import raise_platform_risk_response
from boss_agent_cli.services.browser_runtime import prove_headless_shell_missing


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
	"""禁止本文件里的用例发起连接或做 DNS。预检和分类都只该碰本地对象。"""

	def blocked(*_args: object, **_kwargs: object) -> None:
		raise AssertionError("offline test attempted a network call")

	monkeypatch.setattr(socket.socket, "connect", blocked)
	monkeypatch.setattr(socket, "create_connection", blocked)
	monkeypatch.setattr(socket, "getaddrinfo", blocked)


def test_missing_kernel_is_proven_offline_and_does_not_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
	missing = prove_headless_shell_missing(revision="1248", browsers_dir=tmp_path)
	assert missing is not None
	assert missing.name == "chrome-headless-shell"
	assert "chromium_headless_shell-1248" in str(missing)
	assert not missing.exists()

	present = tmp_path / "chromium_headless_shell-1248" / "chrome-headless-shell-linux64"
	present.mkdir(parents=True)
	(present / "chrome-headless-shell").write_bytes(b"not-a-real-browser")
	assert prove_headless_shell_missing(revision="1248", browsers_dir=tmp_path) is None

	from boss_agent_cli.api.browser_client import BrowserSession

	monkeypatch.setattr(
		"boss_agent_cli.services.browser_runtime.prove_headless_shell_missing",
		lambda **_kwargs: Path("/tmp/chromium_headless_shell-1248/chrome-headless-shell"),
	)
	session = BrowserSession.__new__(BrowserSession)
	session._pw = MagicMock()
	with pytest.raises(BrowserKernelMissing) as caught:
		session._start_headless()
	session._pw.chromium.launch.assert_not_called()
	assert caught.value.details["origin"] == "local_dependency"
	assert caught.value.details["request_attempted"] is False
	assert caught.value.details["request_sent"] is False
	assert caught.value.details["response_received"] is False
	assert caught.value.details["upstream"]["code"] is None


def test_other_startup_failure_is_not_a_sent_request(monkeypatch: pytest.MonkeyPatch) -> None:
	from boss_agent_cli.api.browser_client import BrowserSession

	monkeypatch.setattr(
		"boss_agent_cli.services.browser_runtime.prove_headless_shell_missing",
		lambda **_kwargs: None,
	)
	session = BrowserSession.__new__(BrowserSession)
	session._pw = MagicMock()
	session._pw.chromium.launch.side_effect = RuntimeError("libnss3.so: cannot open shared object file")
	with pytest.raises(BrowserStartupError) as caught:
		session._start_headless()
	assert session._pw.chromium.launch.call_count == 1
	assert caught.value.details["origin"] == "local_startup"
	assert caught.value.details["request_sent"] is False
	assert caught.value.details["response_received"] is False


def test_handle_auth_errors_does_not_retry_missing_kernel_as_network() -> None:
	from boss_agent_cli.display import handle_auth_errors

	ctx = MagicMock()
	ctx.obj = {"json_output": True, "data_dir": Path("/tmp/boss-evidence")}

	@handle_auth_errors("search")
	def impl(_ctx: object) -> None:
		raise BrowserKernelMissing("/tmp/chromium_headless_shell-1248/chrome-headless-shell")

	with pytest.MonkeyPatch.context() as patcher:
		recorded: dict[str, object] = {}

		def capture(*_args: object, **kwargs: object) -> None:
			recorded.update(kwargs)

		patcher.setattr("boss_agent_cli.display.handle_error_output", capture)
		impl(ctx)
	assert recorded["code"] == "BROWSER_KERNEL_MISSING"
	assert recorded["code"] != "NETWORK_ERROR"
	assert recorded["recovery_action"] != "重试"
	assert recorded["details"]["request_sent"] is False


def test_dns_is_unsent_and_timeout_stays_unknown() -> None:
	class ConnectError(Exception):
		pass

	class ReadTimeout(Exception):
		pass

	class TimeoutException(Exception):
		pass

	dns = transport_details_from_exception(ConnectError("[Errno -2] Name or service not known"))
	assert dns is not None
	assert dns["origin"] == "transport"
	assert dns["request_sent"] is False
	assert dns["response_received"] is False
	assert dns["upstream"]["code"] is None

	read_timeout = transport_details_from_exception(ReadTimeout("read timed out"))
	assert read_timeout is not None
	assert read_timeout["request_sent"] is True
	assert read_timeout["response_received"] == "unknown"
	assert read_timeout["upstream"]["http_status"] is None

	ambiguous = transport_details_from_exception(TimeoutException("deadline exceeded"))
	assert ambiguous is not None
	assert ambiguous["request_sent"] == "unknown"
	assert ambiguous["response_received"] == "unknown"

	# 预算记了一笔，也不等于收到了上游 JSON。
	budget_only = evidence_for_response({"note": "browser-fetch", "message": "timeout 37"})
	assert budget_only["request_sent"] == "unknown"
	assert budget_only["response_received"] == "unknown"
	assert budget_only["upstream"]["code"] is None
	assert "platform_code" not in budget_only


def test_structured_37_keeps_source_and_stops_the_next_send(tmp_path: Path) -> None:
	from boss_agent_cli.api.cdp_risk_lock import read_lock
	from boss_agent_cli.api.client import BossClient, EnvironmentRiskError, EnvironmentRiskLockedError

	auth = MagicMock()
	auth.data_dir = tmp_path
	auth._platform = "zhipin"
	client = BossClient(auth)
	browser = MagicMock()
	browser._is_cdp = False
	browser.request.return_value = {
		"code": 37,
		"message": "您的环境存在异常.",
		"__cli_http_status__": 200,
		"__cli_evidence_source__": "upstream_json",
	}
	client._browser_session = browser

	with pytest.raises(EnvironmentRiskError) as caught:
		client._browser_request("GET", "/wapi/zpgeek/search/joblist.json")

	details = caught.value.details
	assert details["platform_code"] == 37
	assert details["origin"] == "upstream_json"
	assert details["request_sent"] is True
	assert details["response_received"] is True
	assert details["upstream"] == {
		"source": "upstream_json",
		"http_status": 200,
		"code": 37,
		"message": "您的环境存在异常.",
	}
	assert browser.request.call_count == 1
	lock = read_lock(tmp_path)
	assert lock is not None and lock.platform_code == 37

	browser.request.side_effect = AssertionError("second platform send")
	with pytest.raises(EnvironmentRiskLockedError):
		client._browser_request("GET", "/wapi/zpgeek/search/joblist.json")
	assert browser.request.call_count == 1
	client.close()


def test_text_containing_37_does_not_forge_platform_code_and_does_not_retry() -> None:
	from boss_agent_cli.api.client import EnvironmentRiskError
	from boss_agent_cli.display import handle_auth_errors

	response = {
		"code": -1,
		"message": "您的环境存在异常. 参见37",
		"__cli_http_status__": 200,
		"__cli_evidence_source__": "non_json",
	}
	with pytest.raises(EnvironmentRiskError) as caught:
		raise_platform_risk_response(response)
	assert caught.value.details["platform_code"] is None
	assert caught.value.details["origin"] == "tool_inference"
	assert caught.value.details["upstream"]["code"] is None
	assert caught.value.details["upstream"]["source"] == "tool_inference"
	assert "37" in caught.value.details["upstream"]["message"]
	assert caught.value.code == "ENVIRONMENT_RISK"

	ctx = MagicMock()
	ctx.obj = {"json_output": True}

	@handle_auth_errors("search")
	def impl(_ctx: object) -> None:
		raise caught.value

	recorded: dict[str, object] = {}

	def capture(*_args: object, **kwargs: object) -> None:
		recorded.update(kwargs)

	with pytest.MonkeyPatch.context() as patcher:
		patcher.setattr("boss_agent_cli.display.handle_error_output", capture)
		impl(ctx)
	assert recorded["code"] == "ENVIRONMENT_RISK"
	assert recorded["recoverable"] is False
	assert "重试" not in str(recorded["recovery_action"])
	assert recorded["details"]["platform_code"] is None

	digits_only = {"code": -1, "message": "elapsed 37 ms"}
	assert raise_platform_risk_response(digits_only) is None
	evidence = evidence_for_response(digits_only)
	assert evidence["upstream"]["code"] is None
	assert "platform_code" not in evidence


def test_non_json_malformed_and_missing_http_evidence_stay_unclaimed() -> None:
	non_json = evidence_for_response(
		{
			"code": -1,
			"message": "browser response is not JSON",
			"__cli_evidence_source__": "non_json",
			"__cli_http_status__": 502,
		}
	)
	assert non_json["origin"] == "http"
	assert non_json["upstream"]["http_status"] == 502
	assert non_json["upstream"]["code"] is None
	assert non_json["request_sent"] is True
	assert "platform_code" not in non_json

	malformed = evidence_for_response(
		{"code": -1, "message": "browser response is not JSON", "__cli_evidence_source__": "non_json"}
	)
	assert malformed["origin"] == "parse"
	assert malformed["upstream"]["http_status"] is None
	assert malformed["upstream"]["code"] is None

	missing_http = evidence_for_response({"code": -1, "message": "browser request interrupted", "__cli_request_interrupted__": True})
	assert missing_http["origin"] == "transport"
	assert missing_http["request_sent"] == "unknown"
	assert missing_http["response_received"] == "unknown"
	assert missing_http["upstream"]["http_status"] is None
	assert missing_http["upstream"]["code"] is None


def test_redaction_and_length_limit() -> None:
	raw = "您的环境存在异常. token=sekret Authorization: Bearer abc.cookie cookie=wtf https://example.test/path?wt2=secret&page=3 " + ("字" * 200)
	text = public_upstream_text(raw)
	assert text is not None
	assert "sekret" not in text
	assert "Bearer abc" not in text
	assert "wt2=secret" not in text
	assert "cookie=wtf" not in text or "[REDACTED]" in text
	assert "?" not in text
	assert len(text) <= 120


def test_cli_and_mcp_share_the_same_evidence_envelope() -> None:
	from boss_agent_cli.mcp_server import _parse_cli_output
	from boss_agent_cli.output import envelope_error

	details = {
		"origin": "upstream_json",
		"request_attempted": True,
		"request_sent": True,
		"response_received": True,
		"platform_code": 37,
		"upstream": {
			"source": "upstream_json",
			"http_status": 200,
			"code": 37,
			"message": "您的环境存在异常. token=sekret",
		},
	}
	raw = envelope_error(
		"search",
		code="ENVIRONMENT_RISK",
		message="访问环境存在异常；停止自动化访问并在官方页面处理",
		details=details,
	)
	cli = json.loads(raw)
	mcp = _parse_cli_output(("search", "管理"), raw, "")
	assert mcp["error"]["code"] == cli["error"]["code"] == "ENVIRONMENT_RISK"
	assert mcp["error"]["recoverable"] is False
	assert mcp["error"]["details"] == cli["error"]["details"]
	assert cli["error"]["details"]["platform_code"] == 37
	assert cli["error"]["details"]["request_sent"] is True
	assert "sekret" not in raw
	assert "[REDACTED]" in cli["error"]["details"]["upstream"]["message"]
