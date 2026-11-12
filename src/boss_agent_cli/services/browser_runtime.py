"""探测 patchright 所需 Chromium 是否已安装（doctor 检查与启动前预检共用）。

预检只读本地 browsers.json 和浏览器缓存目录，不调用安装器，不打开网络。
"""

from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path


def patchright_chromium_revision() -> str | None:
	"""读取 patchright 自带 browsers.json 声明的 chromium 修订版。"""
	try:
		import patchright

		browsers_json = Path(patchright.__file__).resolve().parent / "driver" / "package" / "browsers.json"
		data = json.loads(browsers_json.read_text(encoding="utf-8"))
	except Exception:
		return None
	for browser in data.get("browsers", []):
		if browser.get("name") == "chromium":
			revision = browser.get("revision")
			return str(revision) if revision else None
	return None


def patchright_browser_cache_dirs() -> list[Path]:
	"""Return Playwright/Patchright browser cache directories for the current OS."""
	dirs = [
		Path.home() / ".cache" / "ms-playwright",
		Path.home() / "Library" / "Caches" / "ms-playwright",
	]
	if local_app_data := os.environ.get("LOCALAPPDATA"):
		dirs.append(Path(local_app_data) / "ms-playwright")
	return dirs


def evaluate_patchright_chromium(required_revision: str | None, installed: list[Path]) -> tuple[str, str]:
	"""Return (status, detail) for the patchright_chromium doctor check."""
	if required_revision:
		expected = f"chromium-{required_revision}"
		expected_headless = f"chromium_headless_shell-{required_revision}"
		has_chromium = any(p.name == expected for p in installed)
		has_headless = any(p.name == expected_headless for p in installed)
		if has_chromium and has_headless:
			return "ok", f"已安装 patchright 所需修订版 {expected} 与 {expected_headless}"
		if has_chromium:
			return (
				"warn",
				f"已安装 {expected}，但缺少 {expected_headless}；如全局 tool 环境启动失败，运行 "
				"patchright install chromium-headless-shell",
			)
		found = "、".join(sorted(p.name for p in installed)) or "无"
		return (
			"warn",
			f"patchright 需要 {expected}，本机缓存仅有：{found}；boss login 启动内置浏览器会失败，"
			"请运行 patchright install chromium",
		)
	if installed:
		return "ok", f"检测到 {len(installed)} 个 Chromium 安装（无法确认 patchright 所需修订版）"
	return "warn", "未检测到 patchright/Playwright Chromium 缓存"


def patchright_headless_shell_revision() -> str | None:
	"""读取本地 browsers.json 里的 headless shell 修订版；读不到就不假装知道。"""
	try:
		import patchright

		browsers_json = Path(patchright.__file__).resolve().parent / "driver" / "package" / "browsers.json"
		data = json.loads(browsers_json.read_text(encoding="utf-8"))
	except Exception:
		return None
	found: dict[str, str] = {}
	for browser in data.get("browsers", []):
		if not isinstance(browser, dict):
			continue
		name = browser.get("name")
		revision = browser.get("revision")
		if name and revision:
			found[str(name)] = str(revision)
	return found.get("chromium-headless-shell") or found.get("chromium")


def playwright_browsers_dir() -> Path | None:
	"""Playwright 默认缓存目录。``PLAYWRIGHT_BROWSERS_PATH=0`` 时路径在包内，无法离线证明。"""
	raw = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
	if raw == "0":
		return None
	if raw:
		return Path(raw)
	home = Path.home()
	if sys.platform == "darwin":
		return home / "Library" / "Caches" / "ms-playwright"
	if sys.platform == "win32":
		local = os.environ.get("LOCALAPPDATA")
		base = Path(local) if local else home / "AppData" / "Local"
		return base / "ms-playwright"
	return home / ".cache" / "ms-playwright"


def _expected_shell_executable(directory: Path) -> Path:
	machine = platform.machine().lower()
	if sys.platform.startswith("linux"):
		return directory / "chrome-headless-shell-linux64" / "chrome-headless-shell"
	if sys.platform == "darwin":
		arch = "arm64" if machine in {"arm64", "aarch64"} else "x64"
		return directory / f"chrome-headless-shell-mac-{arch}" / "chrome-headless-shell"
	if sys.platform == "win32":
		return directory / "chrome-headless-shell-win64" / "chrome-headless-shell.exe"
	return directory / "chrome-headless-shell"


def _shell_binary_present(directory: Path) -> bool:
	if not directory.is_dir():
		return False
	for name in ("chrome-headless-shell", "chrome-headless-shell.exe"):
		for candidate in directory.rglob(name):
			if candidate.is_file():
				return True
	return False


def prove_headless_shell_missing(
	*,
	revision: str | None = None,
	browsers_dir: Path | None = None,
) -> Path | None:
	"""内核文件确实不在时返回预期路径；无法证明时返回 None，交给启动器自己失败。

	不创建目录，不下载。修订版目录里只要已有 headless shell 可执行文件，就不判缺失。
	"""
	if browsers_dir is None and os.environ.get("PLAYWRIGHT_BROWSERS_PATH") == "0":
		return None
	rev = revision if revision is not None else patchright_headless_shell_revision()
	if not rev:
		return None
	root = browsers_dir if browsers_dir is not None else playwright_browsers_dir()
	if root is None:
		return None
	directory = root / f"chromium_headless_shell-{rev}"
	if _shell_binary_present(directory):
		return None
	return _expected_shell_executable(directory)
