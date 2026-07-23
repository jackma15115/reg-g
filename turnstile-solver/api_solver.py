import os
import sys
import time
import uuid
import random
import json
import logging
import asyncio
import platform
import shutil
import subprocess
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import unquote, urlparse
import argparse
from quart import Quart, request, jsonify
from camoufox.async_api import AsyncCamoufox
from patchright.async_api import async_playwright
from db_results import init_db, save_result, load_result, cleanup_old_results
from browser_configs import browser_config
from turnstile_diagnostics import classify_turnstile_failure, format_turnstile_failure
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box


def _normalize_task_proxy(raw: Optional[str]) -> Optional[str]:
    """Normalize a proxy URL / shorthand into a single string for context options."""
    s = (raw or "").strip()
    if not s:
        return None
    lower = s.lower()
    if lower.startswith("soket5://"):
        s = "socks5://" + s.split("://", 1)[1]
    elif lower.startswith("socket5://"):
        s = "socks5://" + s.split("://", 1)[1]
    elif "://" not in s:
        # host:port:user:pass or host:port
        parts = s.split(":")
        if len(parts) >= 4:
            host, port, user = parts[0], parts[1], parts[2]
            password = ":".join(parts[3:])
            s = f"http://{user}:{password}@{host}:{port}"
        else:
            s = f"http://{s}"
    return s


def _proxy_from_task_fields(task: dict) -> Optional[str]:
    """Extract proxy from YesCaptcha / CapSolver-style task fields."""
    if not isinstance(task, dict):
        return None
    direct = (
        task.get("proxy")
        or task.get("proxyUrl")
        or task.get("proxyURL")
        or task.get("proxy_url")
    )
    if isinstance(direct, str) and direct.strip():
        return _normalize_task_proxy(direct)

    # YesCaptcha split fields: proxyType + proxyAddress + proxyPort + login/password
    address = (task.get("proxyAddress") or task.get("proxy_address") or "").strip()
    port = task.get("proxyPort") or task.get("proxy_port")
    if address and port:
        scheme = (
            task.get("proxyType")
            or task.get("proxy_type")
            or "http"
        )
        scheme = str(scheme).strip().lower() or "http"
        if scheme in {"socks5h"}:
            scheme = "socks5"
        user = task.get("proxyLogin") or task.get("proxy_login") or task.get("proxyUsername") or ""
        password = task.get("proxyPassword") or task.get("proxy_password") or ""
        user = str(user or "").strip()
        password = str(password or "")
        if user:
            auth = f"{user}:{password}@" if password != "" else f"{user}@"
            return f"{scheme}://{auth}{address}:{port}"
        return f"{scheme}://{address}:{port}"
    return None


def _package_version(name: str) -> Optional[str]:
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return None
    except Exception:
        return None


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)) or default)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _is_linux_arm64(machine: Optional[str] = None, system: Optional[str] = None) -> bool:
    """Whether this is a native Linux ARM64 runtime (not an emulated x86 browser)."""
    current_machine = (machine if machine is not None else platform.machine()).lower()
    current_system = (system if system is not None else platform.system()).lower()
    return current_system == "linux" and current_machine in {"aarch64", "arm64"}


def _camoufox_display_mode(requested: Optional[str], *, headless: bool) -> str:
    """Select a display mode without relying on Firefox's tiny headless window."""
    mode = (requested or "auto").strip().lower()
    aliases = {
        "headless": "native",
        "xvfb": "virtual",
        "headful": "headed",
    }
    mode = aliases.get(mode, mode)
    if mode in {"native", "virtual", "headed"}:
        return mode
    if mode not in {"", "auto"}:
        logger.warning(
            "Unknown TURNSTILE_CAMOUFOX_DISPLAY=%r; using auto" % requested
        )
    if not headless:
        return "headed"
    # ARM64 Firefox's native headless surface commonly remains 500x100. The
    # bundled virtual-display path launches a normal browser window instead.
    return "virtual" if _is_linux_arm64() else "native"


def _elf_machine(path: Path) -> Optional[str]:
    """Return the ELF machine name without invoking the executable."""
    try:
        with path.open("rb") as executable:
            header = executable.read(20)
        if len(header) < 20 or header[:4] != b"\x7fELF":
            return None
        byteorder = "little" if header[5] == 1 else "big"
        machine = int.from_bytes(header[18:20], byteorder=byteorder)
        return {
            0x03: "x86",
            0x28: "ARM",
            0x3E: "x86_64",
            0xB7: "AArch64",
        }.get(machine, f"ELF_machine_{machine}")
    except Exception:
        return None


def _find_camoufox_executable(install_dir: Path) -> Optional[Path]:
    names = ("camoufox", "firefox", "camoufox-bin", "firefox-bin")
    for name in names:
        direct = install_dir / name
        if direct.is_file():
            return direct
    try:
        for name in names:
            for candidate in install_dir.rglob(name):
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return candidate
    except Exception:
        return None
    return None


def _collect_runtime_diagnostics(browser_type: str) -> dict:
    """Collect non-sensitive browser/architecture details for ARM diagnostics."""
    info = {
        "hostname": platform.node() or None,
        "platform": platform.platform(),
        "machine": platform.machine() or None,
        "python": platform.python_version(),
        "python_executable": sys.executable,
        "browser_type": browser_type,
        "xdg_cache_home": os.getenv("XDG_CACHE_HOME"),
        "playwright_browsers_path": os.getenv("PLAYWRIGHT_BROWSERS_PATH"),
        "camoufox_package": _package_version("camoufox"),
        "patchright_package": _package_version("patchright"),
    }
    if browser_type != "camoufox":
        return info

    try:
        from camoufox.pkgman import INSTALL_DIR, installed_verstr

        install_dir = Path(INSTALL_DIR)
        info["camoufox_install_dir"] = str(install_dir)
        info["camoufox_install_dir_exists"] = install_dir.is_dir()
        try:
            info["camoufox_browser_version"] = installed_verstr()
        except Exception as exc:
            info["camoufox_browser_version_error"] = f"{type(exc).__name__}: {exc}"

        executable = _find_camoufox_executable(install_dir)
        info["camoufox_executable"] = str(executable) if executable else None
        info["camoufox_executable_exists"] = bool(executable and executable.is_file())
        if executable:
            elf_machine = _elf_machine(executable)
            info["camoufox_elf_machine"] = elf_machine
            host_machine = (platform.machine() or "").lower()
            expected = {
                "aarch64": "AArch64",
                "arm64": "AArch64",
                "x86_64": "x86_64",
                "amd64": "x86_64",
            }.get(host_machine)
            info["camoufox_arch_matches_host"] = (
                elf_machine == expected if elf_machine and expected else None
            )

            ldd = shutil.which("ldd")
            if ldd and elf_machine:
                try:
                    result = subprocess.run(
                        [ldd, str(executable)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    output = result.stdout or ""
                    info["ldd_exit_code"] = result.returncode
                    info["missing_libraries"] = [
                        line.split("=>", 1)[0].strip()
                        for line in output.splitlines()
                        if "not found" in line
                    ]
                    if result.returncode and not info["missing_libraries"]:
                        info["ldd_error"] = " | ".join(output.strip().splitlines()[-3:])[:500]
                except Exception as exc:
                    info["ldd_error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        info["camoufox_diagnostic_error"] = f"{type(exc).__name__}: {exc}"
    return info



COLORS = {
    'MAGENTA': '\033[35m',
    'BLUE': '\033[34m',
    'GREEN': '\033[32m',
    'YELLOW': '\033[33m',
    'RED': '\033[31m',
    'RESET': '\033[0m',
}


class CustomLogger(logging.Logger):
    @staticmethod
    def format_message(level, color, message):
        timestamp = time.strftime('%H:%M:%S')
        return f"[{timestamp}] [{COLORS.get(color)}{level}{COLORS.get('RESET')}] -> {message}"

    def debug(self, message, *args, **kwargs):
        super().debug(self.format_message('DEBUG', 'MAGENTA', message), *args, **kwargs)

    def info(self, message, *args, **kwargs):
        super().info(self.format_message('INFO', 'BLUE', message), *args, **kwargs)

    def success(self, message, *args, **kwargs):
        super().info(self.format_message('SUCCESS', 'GREEN', message), *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        super().warning(self.format_message('WARNING', 'YELLOW', message), *args, **kwargs)

    def error(self, message, *args, **kwargs):
        super().error(self.format_message('ERROR', 'RED', message), *args, **kwargs)


logging.setLoggerClass(CustomLogger)
logger: CustomLogger = logging.getLogger("TurnstileAPIServer")  # type: ignore
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)


class TurnstileAPIServer:

    def __init__(self, headless: bool, useragent: Optional[str], debug: bool, browser_type: str, thread: int, proxy_support: bool, use_random_config: bool = False, browser_name: Optional[str] = None, browser_version: Optional[str] = None):
        self.app = Quart(__name__)
        self.debug = debug
        self.browser_type = browser_type
        self.headless = headless
        self.thread_count = max(1, int(thread or 1))
        self.proxy_support = proxy_support
        self.browser_pool = asyncio.Queue()
        self.use_random_config = use_random_config
        self.browser_name = browser_name
        self.browser_version = browser_version
        self.console = Console()
        self.viewport_width = _bounded_env_int("TURNSTILE_VIEWPORT_WIDTH", 1366, 800, 2560)
        self.viewport_height = _bounded_env_int("TURNSTILE_VIEWPORT_HEIGHT", 768, 600, 1440)
        self.camoufox_display_mode = _camoufox_display_mode(
            os.getenv("TURNSTILE_CAMOUFOX_DISPLAY"),
            headless=self.headless,
        )

        # Lazy pool: do not keep Camoufox/Chromium warm while idle.
        # TURNSTILE_LAZY=1 (default) starts browsers on first solve request.
        # TURNSTILE_IDLE_SEC (default 180) reclaims the pool after quiet period.
        lazy_raw = (os.getenv("TURNSTILE_LAZY", "1") or "1").strip().lower()
        self.lazy_browsers = lazy_raw not in ("0", "false", "no", "off")
        try:
            self.idle_sec = float(os.getenv("TURNSTILE_IDLE_SEC", "30") or 30)
        except (TypeError, ValueError):
            self.idle_sec = 180.0
        if self.idle_sec < 0:
            self.idle_sec = 0.0
        self._pool_ready = False
        self._pool_lock: Optional[asyncio.Lock] = None
        self._owned_browsers: list = []
        self._playwright = None
        self._camoufox = None
        self._last_used = 0.0
        self._idle_task: Optional[asyncio.Task] = None
        self._in_flight = 0
        self._runtime_info: dict = {}
        self._browser_init_attempts = 0
        self._browser_init_in_progress = False
        self._browser_init_last_started_at: Optional[str] = None
        self._browser_init_last_success_at: Optional[str] = None
        self._browser_init_last_duration_sec: Optional[float] = None
        self._browser_init_last_error: Optional[str] = None

        # Initialize useragent and sec_ch_ua attributes
        self.useragent = useragent
        self.sec_ch_ua = None


        if self.browser_type in ['chromium', 'chrome', 'msedge']:
            if browser_name and browser_version:
                config = browser_config.get_browser_config(browser_name, browser_version)
                if config:
                    useragent, sec_ch_ua = config
                    self.useragent = useragent
                    self.sec_ch_ua = sec_ch_ua
            elif useragent:
                self.useragent = useragent
            else:
                browser, version, useragent, sec_ch_ua = browser_config.get_random_browser_config(self.browser_type)
                self.browser_name = browser
                self.browser_version = version
                self.useragent = useragent
                self.sec_ch_ua = sec_ch_ua

        self.browser_args = []
        if self.useragent:
            self.browser_args.append(f"--user-agent={self.useragent}")

        self._setup_routes()

    def display_welcome(self):
        """Displays welcome screen with logo."""
        self.console.clear()
        
        combined_text = Text()
        combined_text.append("\n📢 Channel: ", style="bold white")
        combined_text.append("https://t.me/D3_vin", style="cyan")
        combined_text.append("\n💬 Chat: ", style="bold white")
        combined_text.append("https://t.me/D3vin_chat", style="cyan")
        combined_text.append("\n📁 GitHub: ", style="bold white")
        combined_text.append("https://github.com/D3-vin", style="cyan")
        combined_text.append("\n📁 Version: ", style="bold white")
        combined_text.append("1.2a", style="green")
        combined_text.append("\n")

        info_panel = Panel(
            Align.left(combined_text),
            title="[bold blue]Turnstile Solver[/bold blue]",
            subtitle="[bold magenta]Dev by D3vin[/bold magenta]",
            box=box.ROUNDED,
            border_style="bright_blue",
            padding=(0, 1),
            width=50
        )

        self.console.print(info_panel)
        self.console.print()




    def _setup_routes(self) -> None:
        """Set up the application routes."""
        self.app.before_serving(self._startup)
        self.app.route('/turnstile', methods=['GET'])(self.process_turnstile)
        self.app.route('/result', methods=['GET'])(self.get_result)
        # YesCaptcha / CapSolver 兼容协议
        self.app.route('/createTask', methods=['POST'])(self.create_task)
        self.app.route('/getTaskResult', methods=['POST'])(self.get_task_result)
        # Memory/ops helpers
        self.app.route('/health', methods=['GET'])(self.health)
        self.app.route('/reclaim', methods=['POST', 'GET'])(self.reclaim)
        # Hot-resize browser pool size without killing the process.
        self.app.route('/resize', methods=['POST', 'GET'])(self.resize)
        self.app.route('/')(self.index)
        

    async def _startup(self) -> None:
        """Boot HTTP + DB; optionally warm browsers (or wait for first task)."""
        self.display_welcome()
        self._pool_lock = asyncio.Lock()
        self._runtime_info = _collect_runtime_diagnostics(self.browser_type)
        logger.info(
            "Runtime diagnostics: "
            + json.dumps(self._runtime_info, ensure_ascii=True, sort_keys=True)
        )
        try:
            await init_db()
            # Periodic result cleanup (independent of browsers)
            asyncio.create_task(self._periodic_cleanup())

            if self.lazy_browsers:
                logger.info(
                    f"Lazy browser mode ON — pool starts on first captcha "
                    f"(thread={self.thread_count}, idle_reclaim={self.idle_sec:.0f}s)"
                )
                if self.idle_sec > 0:
                    self._idle_task = asyncio.create_task(self._idle_reaper())
            else:
                logger.info("Starting browser initialization (eager)")
                await self._initialize_browser_with_diagnostics("eager_startup")
                self._pool_ready = True
                self._last_used = time.time()
                if self.idle_sec > 0:
                    self._idle_task = asyncio.create_task(self._idle_reaper())
        except Exception as e:
            logger.error(f"Failed to start turnstile solver: {str(e)}")
            raise

    async def _initialize_browser_with_diagnostics(self, trigger: str) -> None:
        """Initialize browsers while retaining enough state to diagnose launch failures."""
        self._browser_init_attempts += 1
        attempt = self._browser_init_attempts
        self._browser_init_in_progress = True
        self._browser_init_last_started_at = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        )
        self._browser_init_last_error = None
        started = time.monotonic()
        self._runtime_info = _collect_runtime_diagnostics(self.browser_type)
        logger.info(
            f"Browser initialization started attempt={attempt} trigger={trigger} "
            f"runtime={json.dumps(self._runtime_info, ensure_ascii=True, sort_keys=True)}"
        )
        try:
            await self._initialize_browser()
        except Exception as exc:
            self._pool_ready = False
            self._browser_init_last_duration_sec = round(time.monotonic() - started, 3)
            self._browser_init_last_error = f"{type(exc).__name__}: {exc}"[:1000]
            logger.exception(
                f"Browser initialization failed attempt={attempt} trigger={trigger} "
                f"duration={self._browser_init_last_duration_sec}s"
            )
            raise
        else:
            self._browser_init_last_duration_sec = round(time.monotonic() - started, 3)
            self._browser_init_last_success_at = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            )
            logger.success(
                f"Browser initialization succeeded attempt={attempt} trigger={trigger} "
                f"duration={self._browser_init_last_duration_sec}s "
                f"queue={self.browser_pool.qsize()}"
            )
        finally:
            self._browser_init_in_progress = False

    async def _initialize_browser(self) -> None:
        """Initialize the browser and create the page pool."""
        # Drain any leftover entries before rebuilding.
        await self._drain_pool_discard()

        playwright = None
        camoufox = None

        if self.browser_type in ['chromium', 'chrome', 'msedge']:
            playwright = await async_playwright().start()
            self._playwright = playwright
        elif self.browser_type == "camoufox":
            launch_headless: Union[bool, str]
            if self.camoufox_display_mode == "virtual":
                launch_headless = "virtual"
            elif self.camoufox_display_mode == "headed":
                launch_headless = False
            else:
                launch_headless = True
            camoufox = AsyncCamoufox(
                headless=launch_headless,
                # Keep physical and fingerprinted window geometry out of the
                # Firefox headless 500x100 fallback, especially on ARM64.
                window=(self.viewport_width, self.viewport_height),
                # The Turnstile checkbox is cross-origin. Camoufox exposes this
                # switch specifically for controlled iframe interactions.
                disable_coop=True,
                humanize=0.35,
                # Camoufox isolates page.evaluate() by default. The solver must
                # explicitly opt into main-world execution to mount the widget
                # in the DOM that is actually painted and receives clicks.
                main_world_eval=True,
                debug=self.debug,
            )
            self._camoufox = camoufox
            logger.info(
                "Camoufox launch mode=%s window=%sx%s machine=%s"
                % (
                    self.camoufox_display_mode,
                    self.viewport_width,
                    self.viewport_height,
                    platform.machine() or "unknown",
                )
            )

        browser_configs = []
        for _ in range(self.thread_count):
            if self.browser_type in ['chromium', 'chrome', 'msedge']:
                if self.use_random_config:
                    browser, version, useragent, sec_ch_ua = browser_config.get_random_browser_config(self.browser_type)
                elif self.browser_name and self.browser_version:
                    config = browser_config.get_browser_config(self.browser_name, self.browser_version)
                    if config:
                        useragent, sec_ch_ua = config
                        browser = self.browser_name
                        version = self.browser_version
                    else:
                        browser, version, useragent, sec_ch_ua = browser_config.get_random_browser_config(self.browser_type)
                else:
                    browser = getattr(self, 'browser_name', 'custom')
                    version = getattr(self, 'browser_version', 'custom')
                    useragent = self.useragent
                    sec_ch_ua = getattr(self, 'sec_ch_ua', '')
            else:
                # Для camoufox и других браузеров используем значения по умолчанию
                browser = self.browser_type
                version = 'custom'
                useragent = self.useragent
                sec_ch_ua = getattr(self, 'sec_ch_ua', '')


            browser_configs.append({
                'browser_name': browser,
                'browser_version': version,
                'useragent': useragent,
                'sec_ch_ua': sec_ch_ua
            })

        owned = []
        for i in range(self.thread_count):
            config = browser_configs[i]

            browser_args = [
                "--window-position=0,0",
                "--force-device-scale-factor=1"
            ]
            if config['useragent']:
                browser_args.append(f"--user-agent={config['useragent']}")

            browser = None
            if self.browser_type in ['chromium', 'chrome', 'msedge'] and playwright:
                browser = await playwright.chromium.launch(
                    channel=self.browser_type,
                    headless=self.headless,
                    args=browser_args
                )
            elif self.browser_type == "camoufox" and camoufox:
                browser = await camoufox.start()

            if browser:
                item = (i + 1, browser, config)
                owned.append(item)
                await self.browser_pool.put(item)

            if self.debug:
                logger.info(f"Browser {i + 1} initialized successfully with {config['browser_name']} {config['browser_version']}")

        self._owned_browsers = owned
        self._pool_ready = True
        self._last_used = time.time()
        logger.info(f"Browser pool initialized with {self.browser_pool.qsize()} browsers")

        if self.use_random_config:
            logger.info(f"Each browser in pool received random configuration")
        elif self.browser_name and self.browser_version:
            logger.info(f"All browsers using configuration: {self.browser_name} {self.browser_version}")
        else:
            logger.info("Using custom configuration")

        if self.debug:
            for i, config in enumerate(browser_configs):
                logger.debug(f"Browser {i+1} config: {config['browser_name']} {config['browser_version']}")
                logger.debug(f"Browser {i+1} User-Agent: {config['useragent']}")
                logger.debug(f"Browser {i+1} Sec-CH-UA: {config['sec_ch_ua']}")

    async def _drain_pool_discard(self) -> None:
        """Empty the asyncio queue without closing browsers (caller closes)."""
        while True:
            try:
                self.browser_pool.get_nowait()
            except asyncio.QueueEmpty:
                break
            except Exception:
                break

    async def _close_maybe_async(self, obj, *method_names: str, label: str = "resource") -> bool:
        """Best-effort close helper for browser/driver objects."""
        if obj is None:
            return False
        for meth_name in method_names:
            meth = getattr(obj, meth_name, None)
            if meth is None:
                continue
            try:
                if meth_name == "__aexit__":
                    result = meth(None, None, None)
                else:
                    result = meth()
                if asyncio.iscoroutine(result):
                    await asyncio.wait_for(result, timeout=8.0)
                logger.debug(f"{label}: {meth_name} ok")
                return True
            except Exception as e:
                if self.debug:
                    logger.warning(f"{label}: {meth_name} failed: {e}")
        return False

    @staticmethod
    def _reap_zombie_children(limit: int = 256) -> int:
        """Reap exited child processes (zombies) that belong to this solver.

        Camoufox/Playwright often leave defunct children after kill/close.
        Only the parent can clear them via waitpid. Returns how many reaped.
        """
        import os as _os

        reaped = 0
        for _ in range(max(1, int(limit))):
            try:
                pid, _status = _os.waitpid(-1, _os.WNOHANG)
            except ChildProcessError:
                break
            except Exception:
                break
            if pid <= 0:
                break
            reaped += 1
        return reaped

    @staticmethod
    def _count_zombie_processes() -> int:
        """Best-effort count of zombie processes visible in this container/host."""
        try:
            with open("/proc/self/stat", "r", encoding="utf-8") as fh:
                _ = fh.read(1)
        except Exception:
            # Non-Linux: skip.
            return 0
        n = 0
        try:
            for name in os.listdir("/proc"):
                if not name.isdigit():
                    continue
                try:
                    with open(f"/proc/{name}/stat", "r", encoding="utf-8", errors="ignore") as fh:
                        stat = fh.read()
                    # comm is in parens and may contain spaces; state is after the last ')'.
                    rp = stat.rfind(")")
                    if rp < 0:
                        continue
                    parts = stat[rp + 2 :].split()
                    if parts and parts[0] == "Z":
                        n += 1
                except Exception:
                    continue
        except Exception:
            return 0
        return n

    def _kill_process_tree(self, proc) -> None:
        """Force-kill a browser child process tree (Camoufox/Chromium leftovers)."""
        if proc is None:
            return
        pid = getattr(proc, "pid", None)
        if not pid:
            return
        try:
            import signal
            import os as _os

            # Prefer process group kill when available.
            try:
                pgid = _os.getpgid(int(pid))
                _os.killpg(pgid, signal.SIGTERM)
            except Exception:
                try:
                    _os.kill(int(pid), signal.SIGTERM)
                except Exception:
                    pass
            try:
                # Give it a moment, then hard kill.
                time.sleep(0.15)
                try:
                    pgid = _os.getpgid(int(pid))
                    _os.killpg(pgid, signal.SIGKILL)
                except Exception:
                    try:
                        _os.kill(int(pid), signal.SIGKILL)
                    except Exception:
                        pass
            except Exception:
                pass
            # Also try Popen.wait if available so the direct child is reaped.
            try:
                wait = getattr(proc, "wait", None)
                if callable(wait):
                    wait(timeout=0.2)
            except Exception:
                pass
            reaped = self._reap_zombie_children()
            if reaped and self.debug:
                logger.debug(f"kill process tree pid={pid}: reaped {reaped} zombie child(ren)")
        except Exception as e:
            if self.debug:
                logger.warning(f"kill process tree pid={pid} failed: {e}")

    async def _force_kill_browser(self, browser, index: int | None = None) -> None:
        """Hard cleanup for browsers that ignore close()/aclose()."""
        label = f"Browser {index}" if index is not None else "Browser"
        # Playwright-style browser process
        for attr in ("process", "_process"):
            proc = getattr(browser, attr, None)
            if proc is not None:
                self._kill_process_tree(proc)
                if self.debug:
                    logger.debug(f"{label}: force-killed via {attr}")
                return
        # Nested browser objects (some wrappers)
        for attr in ("browser", "_browser", "impl_obj", "_impl_obj"):
            nested = getattr(browser, attr, None)
            if nested is None or nested is browser:
                continue
            for nested_attr in ("process", "_process"):
                proc = getattr(nested, nested_attr, None)
                if proc is not None:
                    self._kill_process_tree(proc)
                    if self.debug:
                        logger.debug(f"{label}: force-killed nested {attr}.{nested_attr}")
                    return

    async def _shutdown_browsers(self) -> None:
        """Close every browser and release Playwright/Camoufox drivers."""
        items = list(self._owned_browsers or [])
        self._owned_browsers = []
        await self._drain_pool_discard()

        for index, browser, _config in items:
            closed = await self._close_maybe_async(
                browser, "close", "aclose", label=f"Browser {index}"
            )
            if not closed:
                await self._force_kill_browser(browser, index=index)
            else:
                # Even after close(), Camoufox occasionally leaves zombie children.
                # Best-effort hard cleanup when process handle is still visible.
                try:
                    await self._force_kill_browser(browser, index=index)
                except Exception:
                    pass
            if self.debug:
                logger.debug(f"Browser {index}: closed")

        if self._playwright is not None:
            try:
                await asyncio.wait_for(self._playwright.stop(), timeout=8.0)
            except Exception as e:
                if self.debug:
                    logger.warning(f"Playwright stop failed: {e}")
            self._playwright = None

        if self._camoufox is not None:
            # AsyncCamoufox may expose aclose / __aexit__; best-effort.
            await self._close_maybe_async(
                self._camoufox, "aclose", "close", "__aexit__", label="Camoufox"
            )
            self._camoufox = None

        # Reap any defunct children left after close/kill.
        reaped = self._reap_zombie_children()
        zombies = self._count_zombie_processes()
        if reaped or zombies:
            logger.info(
                f"Browser shutdown cleanup: reaped={reaped} zombies_visible={zombies}"
            )

        # Idle reclaim must not keep a stuck counter forever.
        # If a solve task crashed without finally, _in_flight could block all future reclaim.
        if self._in_flight != 0:
            logger.warning(
                f"Resetting leaked in-flight counter during reclaim: was {self._in_flight}"
            )
            self._in_flight = 0

        self._pool_ready = False
        # Keep last_used as historical activity; do not bump it here or reclaim loops thrash.
        logger.info("Browser pool reclaimed (idle / rebuild)")

    async def _ensure_pool(self) -> None:
        """Make sure the browser pool is warm before solving."""
        self._last_used = time.time()
        if self._pool_ready and self.browser_pool.qsize() > 0:
            return
        if self._pool_lock is None:
            self._pool_lock = asyncio.Lock()
        async with self._pool_lock:
            self._last_used = time.time()
            if self._pool_ready and self.browser_pool.qsize() > 0:
                return
            # Rebuild if never ready, or all instances were dropped/disconnected.
            if self._pool_ready and self.browser_pool.empty() and self._in_flight > 0:
                # All browsers currently checked out — nothing to warm.
                return
            logger.info(
                f"Warming browser pool (thread={self.thread_count}, type={self.browser_type})"
            )
            if self._pool_ready or self._owned_browsers or self._playwright or self._camoufox:
                await self._shutdown_browsers()
            await self._initialize_browser_with_diagnostics("first_task_or_rebuild")

    async def _idle_reaper(self) -> None:
        """Close browsers after TURNSTILE_IDLE_SEC with no captcha activity."""
        # Check more frequently than idle window so reclaim is timely.
        interval = 15.0 if self.idle_sec <= 60 else min(30.0, max(10.0, self.idle_sec / 6.0))
        stuck_since = 0.0
        while True:
            try:
                await asyncio.sleep(interval)
                # Always try to reap any direct-child zombies (cheap WNOHANG).
                reaped = self._reap_zombie_children()
                if reaped and self.debug:
                    logger.debug(f"Idle reaper reaped {reaped} zombie child process(es)")
                if self.idle_sec <= 0:
                    continue
                # Nothing warm / owned → nothing to reclaim.
                if not self._pool_ready and not self._owned_browsers:
                    stuck_since = 0.0
                    continue

                idle_for = time.time() - (self._last_used or 0.0)
                if idle_for < self.idle_sec:
                    stuck_since = 0.0
                    continue

                # Guard against leaked in-flight counters: if we have been idle longer
                # than 2x idle window and still see in-flight > 0, force reclaim.
                if self._in_flight > 0:
                    if stuck_since <= 0:
                        stuck_since = time.time()
                    stuck_for = time.time() - stuck_since
                    if stuck_for < max(self.idle_sec * 2.0, 120.0):
                        if self.debug:
                            logger.debug(
                                f"Idle reaper waiting: in_flight={self._in_flight}, "
                                f"idle={idle_for:.0f}s, stuck={stuck_for:.0f}s"
                            )
                        continue
                    logger.warning(
                        f"Idle reaper force-reclaim: in_flight stuck at {self._in_flight} "
                        f"for {stuck_for:.0f}s (idle={idle_for:.0f}s)"
                    )
                else:
                    stuck_since = 0.0

                if self._pool_lock is None:
                    self._pool_lock = asyncio.Lock()
                async with self._pool_lock:
                    idle_for = time.time() - (self._last_used or 0.0)
                    if idle_for < self.idle_sec:
                        continue
                    if self._in_flight > 0 and idle_for < max(self.idle_sec * 2.0, 120.0):
                        continue
                    owned_n = len(self._owned_browsers or [])
                    qsize = self.browser_pool.qsize()
                    logger.info(
                        f"No captcha for {idle_for:.0f}s — reclaiming "
                        f"queue={qsize} owned={owned_n} in_flight={self._in_flight}"
                    )
                    await self._shutdown_browsers()
                    stuck_since = 0.0
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Idle reaper error: {e}")

    async def _periodic_cleanup(self):
        """Periodic cleanup of old results every hour"""
        while True:
            try:
                await asyncio.sleep(3600)
                deleted_count = await cleanup_old_results(days_old=7)
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old results")
            except Exception as e:
                logger.error(f"Error during periodic cleanup: {e}")

    async def _antishadow_inject(self, page):
        await page.add_init_script("""
          (function() {
            const originalAttachShadow = Element.prototype.attachShadow;
            window.__closedShadowRoots = [];
            Element.prototype.attachShadow = function(init) {
              const shadow = originalAttachShadow.call(this, init);
              if (init.mode === 'closed') {
                window.__lastClosedShadowRoot = shadow;
                window.__closedShadowRoots.push(shadow);
              }
              return shadow;
            };
          })();
        """)


    def _main_world_script(self, script: str) -> str:
        """Route DOM reads/writes to the real page when Camoufox isolation is active."""
        return "mw:" + script if self.browser_type == "camoufox" else script


    async def _evaluate_page(self, page, script: str):
        return await page.evaluate(self._main_world_script(script))


    async def _evaluate_page_handle(self, page, script: str):
        return await page.evaluate_handle(self._main_world_script(script))



    @staticmethod
    def _remember_diagnostic(items: list, value: Any, *, limit: int = 8) -> None:
        if value in (None, ""):
            return
        if isinstance(value, str):
            value = value.replace("\r", " ").replace("\n", " ").strip()[:500]
        if value not in items and len(items) < limit:
            items.append(value)

    @staticmethod
    def _is_diagnostic_request(url: str) -> bool:
        lowered = str(url or "").lower()
        return any(
            host in lowered
            for host in (
                "accounts.x.ai",
                "challenges.cloudflare.com",
                "static.cloudflareinsights.com",
            )
        )

    async def _collect_turnstile_page_diagnostics(self, page, diagnostics: dict) -> None:
        if page is None:
            return
        try:
            diagnostics["page_url"] = str(page.url or "")
        except Exception:
            pass
        try:
            diagnostics["page_title"] = str(await page.title())[:200]
        except Exception:
            pass
        try:
            state = await self._evaluate_page(
                page,
                """() => {
                    const shadowRoots = Array.from(window.__closedShadowRoots || []);
                    const roots = [document, ...shadowRoots];
                    const inputs = roots.flatMap((root) =>
                        Array.from(root.querySelectorAll('input[name="cf-turnstile-response"]'))
                    );
                    const isTurnstileFrame = (el) => {
                        const src = String(el.src || '');
                        const title = String(el.title || '').toLowerCase();
                        return src.includes('challenges.cloudflare.com') || src.includes('turnstile') || title.includes('turnstile');
                    };
                    const documentFrames = Array.from(document.querySelectorAll('iframe')).filter(isTurnstileFrame);
                    const shadowFrames = shadowRoots.flatMap((root) =>
                        Array.from(root.querySelectorAll('iframe')).filter(isTurnstileFrame)
                    );
                    const scripts = Array.from(document.scripts)
                        .map((el) => String(el.src || ''))
                        .filter((src) => src.includes('challenges.cloudflare.com'))
                        .slice(0, 5);
                    return {
                        ready_state: document.readyState,
                        turnstile_available: Boolean(window.turnstile && window.turnstile.render),
                        iframe_count: documentFrames.length + shadowFrames.length,
                        document_iframe_count: documentFrames.length,
                        shadow_iframe_count: shadowFrames.length,
                        closed_shadow_root_count: shadowRoots.length,
                        token_input_count: inputs.length,
                        token_value_lengths: inputs.map((el) => String(el.value || '').length),
                        viewport: {width: window.innerWidth, height: window.innerHeight},
                        challenge_scripts: scripts,
                        solver_root_count: document.querySelectorAll('#__turnstileSolverRoot').length,
                        solver_root_visible: Boolean(
                            document.getElementById('__turnstileSolverRoot')?.getClientRects().length
                        ),
                        widget: window.__turnstileDebug || null,
                    };
                }"""
            )
            if isinstance(state, dict):
                for key in (
                    "ready_state",
                    "turnstile_available",
                    "iframe_count",
                    "document_iframe_count",
                    "shadow_iframe_count",
                    "closed_shadow_root_count",
                    "token_input_count",
                    "token_value_lengths",
                    "viewport",
                    "challenge_scripts",
                    "solver_root_count",
                    "solver_root_visible",
                ):
                    if key in state:
                        diagnostics[key] = state[key]
                if isinstance(state.get("widget"), dict):
                    diagnostics["widget"] = state["widget"]
        except Exception as exc:
            diagnostics["snapshot_error"] = f"{type(exc).__name__}: {exc}"[:300]

    async def _save_turnstile_failure_screenshot(self, page, task_ref: str) -> str:
        enabled = (os.getenv("TURNSTILE_SAVE_FAILURES", "0") or "0").strip().lower()
        if enabled in ("0", "false", "no", "off") or page is None:
            return ""
        base = os.getenv("TURNSTILE_DIAGNOSTICS_DIR", "").strip()
        data_dir = os.getenv("GROK_REGISTER_LITE_DATA_DIR", "").strip()
        directory = (
            Path(base)
            if base
            else Path(data_dir) / "turnstile_diagnostics"
            if data_dir
            else Path(__file__).resolve().parent / "logs" / "diagnostics"
        )
        try:
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / f"turnstile-{task_ref}-{int(time.time())}.png"
            await page.screenshot(path=str(path), full_page=False)
            return str(path)
        except Exception as exc:
            logger.warning(f"Turnstile failure screenshot failed id={task_ref}: {exc}")
            return ""

    async def _find_turnstile_elements(self, page, index: int):
        """Умная проверка всех возможных Turnstile элементов"""
        selectors = [
            '.cf-turnstile',
            '[data-sitekey]',
            'iframe[src*="turnstile"]',
            'iframe[title*="widget"]',
            'div[id*="turnstile"]',
            'div[class*="turnstile"]'
        ]
        
        elements = []
        for selector in selectors:
            try:
                # Безопасная проверка count()
                try:
                    count = await page.locator(selector).count()
                except Exception:
                    # Если count() дает ошибку, пропускаем этот селектор
                    continue
                    
                if count > 0:
                    elements.append((selector, count))
                    if self.debug:
                        logger.debug(f"Browser {index}: Found {count} elements with selector '{selector}'")
            except Exception as e:
                if self.debug:
                    logger.debug(f"Browser {index}: Selector '{selector}' failed: {str(e)}")
                continue
        
        return elements

    async def _click_shadow_turnstile(self, page, index: int) -> bool:
        """Click a Turnstile iframe rendered inside a closed shadow root."""
        handle = None
        try:
            handle = await self._evaluate_page_handle(
                page,
                """() => {
                    const roots = Array.from(window.__closedShadowRoots || []);
                    const isTurnstileFrame = (el) => {
                        const src = String(el.src || '');
                        const title = String(el.title || '').toLowerCase();
                        return src.includes('challenges.cloudflare.com') ||
                            src.includes('turnstile') || title.includes('turnstile');
                    };
                    for (const root of roots) {
                        const frame = Array.from(root.querySelectorAll('iframe')).find(isTurnstileFrame);
                        if (frame) return frame;
                    }
                    return null;
                }"""
            )
            iframe_element = handle.as_element() if handle is not None else None
            if iframe_element is None:
                return False

            frame = await iframe_element.content_frame()
            if frame is not None:
                for selector in (
                    'input[type="checkbox"]',
                    '.cb-lb input[type="checkbox"]',
                    'label.cb-lb',
                    '.cb-lb',
                ):
                    try:
                        await frame.locator(selector).first.click(timeout=1500)
                        if self.debug:
                            logger.debug(
                                f"Browser {index}: clicked closed-shadow Turnstile via {selector}"
                            )
                        return True
                    except Exception:
                        continue

            # Cross-origin frame internals can be opaque. Click the checkbox
            # area relative to the iframe instead of treating container clicks
            # or JavaScript undefined as success.
            await iframe_element.click(position={"x": 32, "y": 32}, timeout=2000)
            if self.debug:
                logger.debug(f"Browser {index}: clicked closed-shadow Turnstile iframe at 32,32")
            return True
        except Exception as exc:
            if self.debug:
                logger.debug(f"Browser {index}: closed-shadow Turnstile click failed: {exc}")
            return False
        finally:
            if handle is not None:
                try:
                    await handle.dispose()
                except Exception:
                    pass

    async def _find_and_click_checkbox(self, page, index: int):
        """Найти и кликнуть по чекбоксу Turnstile CAPTCHA внутри iframe"""
        try:
            # Пробуем разные селекторы iframe с защитой от ошибок
            iframe_selectors = [
                'iframe[src*="challenges.cloudflare.com"]',
                'iframe[src*="turnstile"]',
                'iframe[title*="widget"]'
            ]
            
            iframe_locator = None
            for selector in iframe_selectors:
                try:
                    test_locator = page.locator(selector).first
                    # Безопасная проверка count для iframe
                    try:
                        iframe_count = await test_locator.count()
                    except Exception:
                        iframe_count = 0
                        
                    if iframe_count > 0:
                        iframe_locator = test_locator
                        if self.debug:
                            logger.debug(f"Browser {index}: Found Turnstile iframe with selector: {selector}")
                        break
                except Exception as e:
                    if self.debug:
                        logger.debug(f"Browser {index}: Iframe selector '{selector}' failed: {str(e)}")
                    continue
            
            if iframe_locator:
                try:
                    # Получаем frame из iframe
                    iframe_element = await iframe_locator.element_handle()
                    frame = await iframe_element.content_frame()
                    
                    if frame:
                        # Ищем чекбокс внутри iframe
                        checkbox_selectors = [
                            'input[type="checkbox"]',
                            '.cb-lb input[type="checkbox"]',
                            'label input[type="checkbox"]',
                            'label.cb-lb',
                            '.cb-lb',
                        ]
                        
                        for selector in checkbox_selectors:
                            try:
                                # Полностью избегаем locator.count() в iframe - используем альтернативный подход
                                try:
                                    # Пробуем кликнуть напрямую без count проверки
                                    checkbox = frame.locator(selector).first
                                    await checkbox.click(timeout=2000)
                                    if self.debug:
                                        logger.debug(f"Browser {index}: Successfully clicked checkbox in iframe with selector '{selector}'")
                                    return True
                                except Exception as click_e:
                                    # Если прямой клик не сработал, записываем в debug но не падаем
                                    if self.debug:
                                        logger.debug(f"Browser {index}: Direct checkbox click failed for '{selector}': {str(click_e)}")
                                    continue
                            except Exception as e:
                                if self.debug:
                                    logger.debug(f"Browser {index}: Iframe checkbox selector '{selector}' failed: {str(e)}")
                                continue
                    
                        # Если нашли iframe, но не смогли кликнуть чекбокс, пробуем клик по iframe
                        try:
                            if self.debug:
                                logger.debug(f"Browser {index}: Trying to click iframe directly as fallback")
                            await iframe_locator.click(position={"x": 32, "y": 32}, timeout=1500)
                            return True
                        except Exception as e:
                            if self.debug:
                                logger.debug(f"Browser {index}: Iframe direct click failed: {str(e)}")
                
                except Exception as e:
                    if self.debug:
                        logger.debug(f"Browser {index}: Failed to access iframe content: {str(e)}")
            
        except Exception as e:
            if self.debug:
                logger.debug(f"Browser {index}: General iframe search failed: {str(e)}")
        
        return False

    async def _try_click_strategies(self, page, index: int):
        strategies = [
            ('shadow_iframe', lambda: self._click_shadow_turnstile(page, index)),
            ('checkbox_click', lambda: self._find_and_click_checkbox(page, index)),
            ('iframe_click', lambda: self._safe_click(page, 'iframe[src*="turnstile"]', index)),
            ('js_click', lambda: self._evaluate_page(page, """() => {
                const el = document.querySelector('.cf-turnstile');
                if (!el) return false;
                el.click();
                return true;
            }""")),
            ('direct_widget', lambda: self._safe_click(page, '.cf-turnstile', index)),
            ('sitekey_attr', lambda: self._safe_click(page, '[data-sitekey]', index)),
            ('any_turnstile', lambda: self._safe_click(page, '*[class*="turnstile"]', index)),
            ('xpath_click', lambda: self._safe_click(page, "//div[@class='cf-turnstile']", index))
        ]
        
        for strategy_name, strategy_func in strategies:
            try:
                result = await strategy_func()
                if result is True:
                    if self.debug:
                        logger.debug(f"Browser {index}: Click strategy '{strategy_name}' succeeded")
                    return strategy_name
            except Exception as e:
                if self.debug:
                    logger.debug(f"Browser {index}: Click strategy '{strategy_name}' failed: {str(e)}")
                continue
        
        return ""

    async def _safe_click(self, page, selector: str, index: int):
        """Полностью безопасный клик с максимальной защитой от ошибок"""
        try:
            # Пробуем кликнуть напрямую без count() проверки
            locator = page.locator(selector).first
            await locator.click(timeout=1000)
            return True
        except Exception as e:
            # Логируем ошибку только в debug режиме
            if self.debug and "Can't query n-th element" not in str(e):
                logger.debug(f"Browser {index}: Safe click failed for '{selector}': {str(e)}")
            return False

    async def _inject_captcha_directly(self, page, websiteKey: str, action: str = '', cdata: str = '', index: int = 0):
        """Inject CAPTCHA directly into the target website"""
        script = f"""
        if (!window.__turnstileShadowCaptureInstalled) {{
            const originalAttachShadow = Element.prototype.attachShadow;
            window.__closedShadowRoots = [];
            Element.prototype.attachShadow = function(init) {{
                const shadow = originalAttachShadow.call(this, init);
                if (init && init.mode === 'closed') {{
                    window.__lastClosedShadowRoot = shadow;
                    window.__closedShadowRoots.push(shadow);
                }}
                return shadow;
            }};
            window.__turnstileShadowCaptureInstalled = true;
        }}

        window.__turnstileDebug = {{
            script_status: window.turnstile ? 'already_loaded' : 'not_loaded',
            render_status: 'not_started',
            error_codes: [],
            render_error: '',
            token_length: 0
        }};
        // Remove any existing turnstile widgets first
        document.querySelectorAll('.cf-turnstile').forEach(el => el.remove());
        document.querySelectorAll('[data-sitekey]').forEach(el => el.remove());

        const previousRoot = document.getElementById('__turnstileSolverRoot');
        if (previousRoot) previousRoot.remove();
        const solverRoot = document.createElement('div');
        solverRoot.id = '__turnstileSolverRoot';
        solverRoot.style.position = 'fixed';
        solverRoot.style.inset = '0';
        solverRoot.style.width = '100vw';
        solverRoot.style.height = '100vh';
        solverRoot.style.zIndex = '2147483647';
        solverRoot.style.isolation = 'isolate';
        solverRoot.style.display = 'flex';
        solverRoot.style.alignItems = 'flex-start';
        solverRoot.style.justifyContent = 'flex-start';
        solverRoot.style.boxSizing = 'border-box';
        solverRoot.style.padding = '8px';
        solverRoot.style.background = '#ffffff';
        solverRoot.style.colorScheme = 'light';
        solverRoot.style.pointerEvents = 'auto';
        if (document.body) {{
            document.body.replaceChildren(solverRoot);
            document.body.style.margin = '0';
            document.body.style.padding = '0';
            document.body.style.overflow = 'hidden';
            document.body.style.background = '#ffffff';
        }} else {{
            document.documentElement.appendChild(solverRoot);
        }}
        window.__turnstileDebug.isolated_root = true;
        solverRoot.dataset.executionWorld = 'main';
        
        // Create turnstile widget directly on the page
        const captchaDiv = document.createElement('div');
        captchaDiv.className = 'cf-turnstile';
        captchaDiv.setAttribute('data-sitekey', '{websiteKey}');
        captchaDiv.setAttribute('data-callback', 'onTurnstileCallback');
        {f'captchaDiv.setAttribute("data-action", "{action}");' if action else ''}
        {f'captchaDiv.setAttribute("data-cdata", "{cdata}");' if cdata else ''}
        captchaDiv.style.position = 'relative';
        captchaDiv.style.zIndex = '1';
        captchaDiv.style.width = '320px';
        captchaDiv.style.minHeight = '65px';
        captchaDiv.style.backgroundColor = 'white';
        captchaDiv.style.padding = '8px';
        captchaDiv.style.border = '2px solid #0f79af';
        captchaDiv.style.borderRadius = '8px';
        captchaDiv.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.3)';
        
        // Add to an isolated top layer so site cookies/layout cannot cover it.
        solverRoot.appendChild(captchaDiv);
        
        // Load Turnstile script and render widget
        const loadTurnstile = () => {{
            window.__turnstileDebug.script_status = 'loading';
            const script = document.createElement('script');
            script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
            script.async = true;
            script.defer = true;
            script.onload = function() {{
                window.__turnstileDebug.script_status = 'loaded';
                console.log('Turnstile script loaded');
                // Wait a bit for script to initialize
                setTimeout(() => {{
                    if (window.turnstile && window.turnstile.render) {{
                        try {{
                            window.__turnstileDebug.render_status = 'rendering';
                            window.turnstile.render(captchaDiv, {{
                                sitekey: '{websiteKey}',
                                theme: 'light',
                                appearance: 'always',
                                {f'action: "{action}",' if action else ''}
                                {f'cdata: "{cdata}",' if cdata else ''}
                                callback: function(token) {{
                                    window.__turnstileDebug.token_length = String(token || '').length;
                                    console.log('Turnstile solved; token length:', window.__turnstileDebug.token_length);
                                    // Create hidden input for token
                                    let tokenInput = document.querySelector('input[name="cf-turnstile-response"]');
                                    if (!tokenInput) {{
                                        tokenInput = document.createElement('input');
                                        tokenInput.type = 'hidden';
                                        tokenInput.name = 'cf-turnstile-response';
                                        document.body.appendChild(tokenInput);
                                    }}
                                    tokenInput.value = token;
                                }},
                                'error-callback': function(error) {{
                                    window.__turnstileDebug.error_codes.push(String(error));
                                    console.log('Turnstile error:', error);
                                }},
                                'expired-callback': function() {{
                                    window.__turnstileDebug.error_codes.push('token_expired');
                                }},
                                'timeout-callback': function() {{
                                    window.__turnstileDebug.error_codes.push('widget_timeout');
                                }},
                                'unsupported-callback': function() {{
                                    window.__turnstileDebug.error_codes.push('unsupported_browser');
                                }}
                            }});
                            window.__turnstileDebug.render_status = 'rendered';
                        }} catch (e) {{
                            window.__turnstileDebug.render_status = 'render_error';
                            window.__turnstileDebug.render_error = String(e);
                            console.log('Turnstile render error:', e);
                        }}
                    }} else {{
                        window.__turnstileDebug.script_status = 'missing';
                        console.log('Turnstile API not available');
                    }}
                }}, 1000);
            }};
            script.onerror = function() {{
                window.__turnstileDebug.script_status = 'load_failed';
                console.log('Failed to load Turnstile script');
            }};
            document.head.appendChild(script);
        }};
        
        // Check if Turnstile is already loaded
        if (window.turnstile) {{
            window.__turnstileDebug.script_status = 'already_loaded';
            console.log('Turnstile already loaded, rendering immediately');
            try {{
                window.__turnstileDebug.render_status = 'rendering';
                window.turnstile.render(captchaDiv, {{
                    sitekey: '{websiteKey}',
                    theme: 'light',
                    appearance: 'always',
                    {f'action: "{action}",' if action else ''}
                    {f'cdata: "{cdata}",' if cdata else ''}
                    callback: function(token) {{
                        window.__turnstileDebug.token_length = String(token || '').length;
                        console.log('Turnstile solved; token length:', window.__turnstileDebug.token_length);
                        let tokenInput = document.querySelector('input[name="cf-turnstile-response"]');
                        if (!tokenInput) {{
                            tokenInput = document.createElement('input');
                            tokenInput.type = 'hidden';
                            tokenInput.name = 'cf-turnstile-response';
                            document.body.appendChild(tokenInput);
                        }}
                        tokenInput.value = token;
                    }},
                    'error-callback': function(error) {{
                        window.__turnstileDebug.error_codes.push(String(error));
                        console.log('Turnstile error:', error);
                    }},
                    'expired-callback': function() {{
                        window.__turnstileDebug.error_codes.push('token_expired');
                    }},
                    'timeout-callback': function() {{
                        window.__turnstileDebug.error_codes.push('widget_timeout');
                    }},
                    'unsupported-callback': function() {{
                        window.__turnstileDebug.error_codes.push('unsupported_browser');
                    }}
                }});
                window.__turnstileDebug.render_status = 'rendered';
            }} catch (e) {{
                window.__turnstileDebug.render_status = 'render_error';
                window.__turnstileDebug.render_error = String(e);
                console.log('Immediate render error:', e);
                loadTurnstile();
            }}
        }} else {{
            loadTurnstile();
        }}
        
        // Setup global callback
        window.onTurnstileCallback = function(token) {{
            window.__turnstileDebug.token_length = String(token || '').length;
            console.log('Global turnstile callback executed; token length:', window.__turnstileDebug.token_length);
        }};

        """

        await self._evaluate_page(page, script)
        state = await self._evaluate_page(
            page,
            """() => {
                const root = document.getElementById('__turnstileSolverRoot');
                return {
                    solver_root_count: document.querySelectorAll('#__turnstileSolverRoot').length,
                    solver_root_visible: Boolean(root && root.getClientRects().length),
                    execution_world: root?.dataset.executionWorld || '',
                    body_child_count: document.body ? document.body.children.length : -1,
                };
            }""",
        )
        if not isinstance(state, dict) or state.get("solver_root_count") != 1:
            raise RuntimeError(f"main-world Turnstile injection was not visible: {state!r}")
        if not state.get("solver_root_visible"):
            raise RuntimeError(f"main-world Turnstile root was not rendered: {state!r}")
        if self.debug:
            logger.debug(
                f"Browser {index}: Injected CAPTCHA in main world "
                f"with sitekey={websiteKey} state={state}"
            )
        return state

    def _build_context_options(self, browser_config: dict, proxy: Optional[str] = None) -> dict:
        """Build browser context options with Camoufox-safe defaults."""
        context_options: dict = {}

        # Camoufox + newer Playwright rejects default viewport.isMobile scheme.
        # Always disable default viewport and set size after page creation.
        context_options["no_viewport"] = True
        if self.browser_type == "camoufox":
            # Main-world evaluation is required for the injected widget. Let
            # Playwright execute it even when accounts.x.ai forbids unsafe-eval.
            context_options["bypass_csp"] = True

        useragent = (browser_config or {}).get("useragent")
        if useragent:
            context_options["user_agent"] = useragent

        sec_ch_ua = (browser_config or {}).get("sec_ch_ua")
        if sec_ch_ua and str(sec_ch_ua).strip():
            context_options["extra_http_headers"] = {"sec-ch-ua": str(sec_ch_ua).strip()}

        if proxy:
            proxy = _normalize_task_proxy(proxy) or proxy
            try:
                parsed = urlparse(proxy)
                scheme = (parsed.scheme or "http").lower()
                if scheme in {"socks5h"}:
                    scheme = "socks5"
                host = parsed.hostname or ""
                port = parsed.port
                if not host or port is None:
                    raise ValueError(f"proxy missing host/port: {proxy}")
                server = f"{scheme}://{host}:{port}"
                proxy_opts: dict = {"server": server}
                if parsed.username is not None:
                    proxy_opts["username"] = unquote(parsed.username)
                if parsed.password is not None:
                    proxy_opts["password"] = unquote(parsed.password)
                context_options["proxy"] = proxy_opts
            except Exception:
                # Legacy fallbacks for non-URL forms.
                if "@" in proxy and "://" in proxy:
                    scheme_part, auth_part = proxy.split("://", 1)
                    auth, address = auth_part.rsplit("@", 1)
                    username, password = auth.split(":", 1)
                    context_options["proxy"] = {
                        "server": f"{scheme_part}://{address}",
                        "username": username,
                        "password": password,
                    }
                else:
                    parts = proxy.split(":")
                    if len(parts) == 5:
                        proxy_scheme, proxy_ip, proxy_port, proxy_user, proxy_pass = parts
                        context_options["proxy"] = {
                            "server": f"{proxy_scheme}://{proxy_ip}:{proxy_port}",
                            "username": proxy_user,
                            "password": proxy_pass,
                        }
                    elif "://" in proxy:
                        context_options["proxy"] = {"server": proxy}
                    else:
                        raise ValueError(f"Invalid proxy format: {proxy}")

        return context_options

    def _select_proxy(self, task_proxy: Optional[str] = None) -> Optional[str]:
        """Prefer per-task proxy (registration must share egress); else proxies.txt."""
        explicit = _normalize_task_proxy(task_proxy)
        if explicit:
            return explicit
        if not self.proxy_support:
            return None
        proxy_file_path = os.path.join(os.getcwd(), "proxies.txt")
        try:
            with open(proxy_file_path) as proxy_file:
                proxies = [line.strip() for line in proxy_file if line.strip()]
            return _normalize_task_proxy(random.choice(proxies)) if proxies else None
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.error(f"Error reading proxy file: {str(e)}")
            return None

    async def _solve_turnstile(
        self,
        task_id: str,
        url: str,
        sitekey: str,
        action: Optional[str] = None,
        cdata: Optional[str] = None,
        proxy: Optional[str] = None,
    ):
        """Solve the Turnstile challenge."""
        context = None
        page = None
        start_time = time.time()
        index = None
        browser = None
        browser_config = None
        acquired = False
        stage = "starting"
        proxy = self._select_proxy(proxy)
        task_ref = task_id[:8]
        try:
            target_host = urlparse(url).hostname or "unknown"
        except Exception:
            target_host = "unknown"
        diagnostics: dict[str, Any] = {
            "stage": stage,
            "target_host": target_host,
            "target_url": url,
            "browser": self.browser_type,
            "machine": platform.machine() or "unknown",
            "camoufox_display_mode": (
                self.camoufox_display_mode if self.browser_type == "camoufox" else None
            ),
            "proxy": bool(proxy),
            "resource_blocking": False,
            "sitekey_prefix": str(sitekey or "")[:12],
            "action_present": bool(action),
            "cdata_present": bool(cdata),
            "request_failures": [],
            "http_errors": [],
            "console_errors": [],
            "click_attempts": [],
        }

        async def record_failure(error: str) -> None:
            elapsed_time = round(time.time() - start_time, 3)
            diagnostics["stage"] = stage
            diagnostics["browser_index"] = index
            await self._collect_turnstile_page_diagnostics(page, diagnostics)
            screenshot = await self._save_turnstile_failure_screenshot(page, task_ref)
            if screenshot:
                diagnostics["screenshot"] = screenshot
            diagnostics["likely_reason"] = classify_turnstile_failure(error, diagnostics)
            await save_result(
                task_id,
                "turnstile",
                {
                    "value": "CAPTCHA_FAIL",
                    "elapsed_time": elapsed_time,
                    "error": error,
                    "diagnostics": diagnostics,
                },
            )
            logger.error(
                f"Turnstile diagnostic id={task_ref}: "
                f"{format_turnstile_failure(error, elapsed_time, diagnostics)}"
            )

        logger.info(
            f"Turnstile task started id={task_ref} host={target_host} "
            f"browser={self.browser_type} machine={platform.machine() or 'unknown'} "
            f"proxy={'yes' if proxy else 'no'} pool_ready={self._pool_ready}"
        )

        # Mark in-flight before warm-up so the idle reaper cannot reclaim mid-acquire.
        # Always pair with the outer finally decrement — never leave this sticky.
        self._in_flight += 1
        try:
            try:
                stage = "browser_pool_acquire"
                await self._ensure_pool()
                self._last_used = time.time()
                index, browser, browser_config = await self.browser_pool.get()
                acquired = True
                self._last_used = time.time()
                logger.info(
                    f"Turnstile task acquired browser id={task_ref} browser_index={index} "
                    f"queue_remaining={self.browser_pool.qsize()}"
                )
            except Exception as e:
                logger.exception(
                    f"Turnstile task browser acquire failed id={task_ref} "
                    f"elapsed={round(time.time() - start_time, 3)}s: {e}"
                )
                await record_failure(f"browser_pool_acquire: {type(e).__name__}: {e}")
                return

            try:
                if hasattr(browser, 'is_connected') and not browser.is_connected():
                    if self.debug:
                        logger.warning(f"Browser {index}: Browser disconnected, skipping")
                    await self.browser_pool.put((index, browser, browser_config))
                    acquired = False
                    stage = "browser_state_check"
                    await record_failure("browser_disconnected")
                    return
            except Exception as e:
                if self.debug:
                    logger.warning(f"Browser {index}: Cannot check browser state: {str(e)}")

            if proxy and self.debug:
                # Redact credentials in logs.
                try:
                    p = urlparse(proxy)
                    shown = f"{p.scheme}://{p.hostname}:{p.port}" if p.hostname else "(proxy)"
                except Exception:
                    shown = "(proxy)"
                logger.debug(f"Browser {index}: Creating context with proxy {shown}")
            elif self.debug:
                logger.debug(f"Browser {index}: Creating context without proxy")

            context_options = self._build_context_options(browser_config or {}, proxy)
            logger.info(
                f"Turnstile context creation started id={task_ref} browser_index={index} "
                f"proxy={'yes' if proxy else 'no'}"
            )
            stage = "context_creation"
            try:
                context = await browser.new_context(**context_options)
            except Exception as ctx_err:
                diagnostics["context_fallback_error"] = f"{type(ctx_err).__name__}: {ctx_err}"[:300]
                # Fallback for Camoufox protocol mismatches / stricter option sets.
                # If proxy was requested, do NOT silently drop it — fail the task so
                # registration does not mint a Turnstile token on the wrong egress.
                if proxy:
                    logger.error(
                        f"Browser {index}: new_context with proxy failed ({ctx_err}); "
                        f"refusing proxyless fallback to keep egress consistent"
                    )
                    await record_failure(f"proxy_context_failed: {ctx_err}")
                    if acquired:
                        try:
                            await self.browser_pool.put((index, browser, browser_config))
                            acquired = False
                        except Exception:
                            pass
                    return
                if self.debug:
                    logger.warning(f"Browser {index}: new_context failed ({ctx_err}); retry minimal options")
                context = await browser.new_context(no_viewport=True)
            logger.info(
                f"Turnstile context created id={task_ref} browser_index={index}"
            )

            stage = "page_creation"
            page = await context.new_page()
            logger.info(
                f"Turnstile page created id={task_ref} browser_index={index}"
            )

            def on_console(message) -> None:
                try:
                    kind = str(getattr(message, "type", "") or "")
                    body = str(getattr(message, "text", "") or "")
                    lowered = body.lower()
                    if kind == "warning" and "strict-dynamic" in lowered and "ignoring" in lowered:
                        return
                    if kind in {"error", "warning"} or any(
                        marker in lowered for marker in ("turnstile error", "render error", "failed to load")
                    ):
                        self._remember_diagnostic(
                            diagnostics["console_errors"],
                            {"type": kind or "log", "text": body[:400]},
                        )
                except Exception:
                    pass

            def on_page_error(error) -> None:
                try:
                    self._remember_diagnostic(
                        diagnostics["console_errors"],
                        {"type": "pageerror", "text": str(error)[:400]},
                    )
                except Exception:
                    pass

            def on_request_failed(failed_request) -> None:
                try:
                    failed_url = str(getattr(failed_request, "url", "") or "")
                    if "challenges.cloudflare.com" in failed_url.lower():
                        self._remember_diagnostic(
                            diagnostics["request_failures"],
                            {
                                "url": failed_url[:300],
                                "failure": str(getattr(failed_request, "failure", "") or "")[:220],
                                "resource_type": str(
                                    getattr(failed_request, "resource_type", "") or ""
                                )[:40],
                            },
                        )
                except Exception:
                    pass

            def on_response(response) -> None:
                try:
                    response_url = str(getattr(response, "url", "") or "")
                    status = int(getattr(response, "status", 0) or 0)
                    if status >= 400 and self._is_diagnostic_request(response_url):
                        self._remember_diagnostic(
                            diagnostics["http_errors"],
                            {"status": status, "url": response_url[:300]},
                        )
                except Exception:
                    pass

            page.on("console", on_console)
            page.on("pageerror", on_page_error)
            page.on("requestfailed", on_request_failed)
            page.on("response", on_response)

            if self.browser_type != "camoufox":
                try:
                    await page.set_viewport_size(
                        {"width": self.viewport_width, "height": self.viewport_height}
                    )
                except Exception:
                    pass

            await self._antishadow_inject(page)
            if self.browser_type != "camoufox":
                await page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            """)

            try:
                if self.debug:
                    logger.debug(
                        f"Browser {index}: Starting Turnstile solve task={task_ref} "
                        f"host={target_host} proxy={'yes' if proxy else 'no'}"
                    )
                    logger.debug(
                        f"Browser {index}: Loading full page resources at "
                        f"{self.viewport_width}x{self.viewport_height}"
                    )
                    logger.debug(f"Browser {index}: Loading target host: {target_host}")

                stage = "page_navigation"
                main_response = await page.goto(url, wait_until='domcontentloaded', timeout=30000)
                diagnostics["page_url"] = str(page.url or "")
                if main_response is not None:
                    diagnostics["main_status"] = int(main_response.status)
                    try:
                        main_headers = await main_response.all_headers()
                        if main_headers.get("cf-ray"):
                            diagnostics["cf_ray"] = str(main_headers.get("cf-ray"))[:120]
                        if main_headers.get("cf-mitigated"):
                            diagnostics["cf_mitigated"] = str(main_headers.get("cf-mitigated"))[:80]
                    except Exception:
                        pass
                logger.info(
                    f"Turnstile page loaded id={task_ref} browser_index={index} host={target_host}"
                )

                if self.debug:
                    logger.debug(f"Browser {index}: Injecting Turnstile widget directly into target site")

                stage = "widget_injection"
                injection_state = await self._inject_captcha_directly(
                    page, sitekey, action or '', cdata or '', index
                )
                diagnostics["injection"] = injection_state
                logger.info(
                    f"Turnstile widget injected id={task_ref} browser_index={index} "
                    f"world={injection_state.get('execution_world')}; waiting for token"
                )
                await asyncio.sleep(3)

                stage = "token_wait"
                locator = page.locator('input[name="cf-turnstile-response"]')
                max_attempts = 30
                click_count = 0
                max_clicks = 10

                for attempt in range(max_attempts):
                    try:
                        try:
                            count = await locator.count()
                        except Exception as e:
                            if self.debug:
                                logger.debug(f"Browser {index}: Locator count failed on attempt {attempt + 1}: {str(e)}")
                            count = 0

                        if count == 0:
                            if self.debug and attempt % 5 == 0:
                                logger.debug(f"Browser {index}: No token elements found on attempt {attempt + 1}")
                        elif count == 1:
                            try:
                                token = await locator.input_value(timeout=500)
                                if token:
                                    elapsed_time = round(time.time() - start_time, 3)
                                    logger.success(
                                        f"Turnstile task solved id={task_ref} browser_index={index} "
                                        f"elapsed={elapsed_time}s"
                                    )
                                    await save_result(task_id, "turnstile", {"value": token, "elapsed_time": elapsed_time})
                                    return
                            except Exception as e:
                                if self.debug:
                                    logger.debug(f"Browser {index}: Single token element check failed: {str(e)}")
                        else:
                            if self.debug:
                                logger.debug(f"Browser {index}: Found {count} token elements, checking all")
                            for i in range(count):
                                try:
                                    element_token = await locator.nth(i).input_value(timeout=500)
                                    if element_token:
                                        elapsed_time = round(time.time() - start_time, 3)
                                        logger.success(
                                            f"Turnstile task solved id={task_ref} browser_index={index} "
                                            f"elapsed={elapsed_time}s"
                                        )
                                        await save_result(task_id, "turnstile", {"value": element_token, "elapsed_time": elapsed_time})
                                        return
                                except Exception as e:
                                    if self.debug:
                                        logger.debug(f"Browser {index}: Token element {i} check failed: {str(e)}")
                                    continue

                        if attempt > 2 and attempt % 3 == 0 and click_count < max_clicks:
                            click_strategy = await self._try_click_strategies(page, index)
                            click_count += 1
                            self._remember_diagnostic(
                                diagnostics["click_attempts"],
                                {
                                    "attempt": attempt + 1,
                                    "strategy": click_strategy or "none",
                                },
                                limit=max_clicks,
                            )
                            if click_strategy and self.debug:
                                logger.debug(
                                    f"Browser {index}: Click strategy={click_strategy} "
                                    f"(click #{click_count}/{max_clicks})"
                                )
                            elif not click_strategy and self.debug:
                                logger.debug(f"Browser {index}: All click strategies failed on attempt {attempt + 1} (click #{click_count}/{max_clicks})")

                        wait_time = min(0.5 + (attempt * 0.05), 2.0)
                        await asyncio.sleep(wait_time)

                        if self.debug and attempt % 5 == 0:
                            logger.debug(f"Browser {index}: Attempt {attempt + 1}/{max_attempts} - Waiting for token (clicks: {click_count}/{max_clicks})")

                    except Exception as e:
                        if self.debug:
                            logger.debug(f"Browser {index}: Attempt {attempt + 1} error: {str(e)}")
                        continue

                elapsed_time = round(time.time() - start_time, 3)
                await record_failure("timeout_waiting_for_token")
                logger.error(
                    f"Turnstile task timed out id={task_ref} browser_index={index} "
                    f"elapsed={elapsed_time}s"
                )
            except Exception as e:
                elapsed_time = round(time.time() - start_time, 3)
                await record_failure(f"{stage}: {type(e).__name__}: {e}")
                logger.exception(
                    f"Turnstile task failed id={task_ref} browser_index={index} "
                    f"elapsed={elapsed_time}s: {e}"
                )
            finally:
                if self.debug:
                    logger.debug(f"Browser {index}: Closing browser context and cleaning up")

                if context is not None:
                    try:
                        await context.close()
                        if self.debug:
                            logger.debug(f"Browser {index}: Context closed successfully")
                    except Exception as e:
                        if self.debug:
                            logger.warning(f"Browser {index}: Error closing context: {str(e)}")

                try:
                    if acquired and browser is not None and index is not None:
                        connected = True
                        try:
                            if hasattr(browser, 'is_connected'):
                                connected = bool(browser.is_connected())
                        except Exception:
                            connected = True
                        if connected:
                            await self.browser_pool.put((index, browser, browser_config))
                            if self.debug:
                                logger.debug(f"Browser {index}: Browser returned to pool")
                        elif self.debug:
                            logger.warning(f"Browser {index}: Browser disconnected, not returning to pool")
                except Exception as e:
                    if self.debug:
                        logger.warning(f"Browser {index}: Error returning browser to pool: {str(e)}")
        finally:
            # Always release in-flight even on early return / unexpected exception.
            if self._in_flight > 0:
                self._in_flight -= 1
            self._last_used = time.time()






    def _check_client_key(self, client_key: Optional[str]) -> Optional[dict]:
        """校验 clientKey。未设置 API_KEY 时跳过鉴权。"""
        expected = os.getenv("API_KEY", "").strip()
        if not expected:
            return None
        if not client_key or client_key.strip() != expected:
            return {
                "errorId": 1,
                "errorCode": "ERROR_KEY_DOES_NOT_EXIST",
                "errorDescription": "Invalid clientKey"
            }
        return None

    async def _enqueue_turnstile(
        self,
        url: str,
        sitekey: str,
        action: Optional[str] = None,
        cdata: Optional[str] = None,
        proxy: Optional[str] = None,
    ):
        """创建任务并异步求解，返回 (task_id, error_response)。"""
        if not url or not sitekey:
            return None, {
                "errorId": 1,
                "errorCode": "ERROR_WRONG_PAGEURL",
                "errorDescription": "Both 'url' and 'sitekey' are required"
            }

        task_id = str(uuid.uuid4())
        try:
            target_host = urlparse(url).hostname or "unknown"
        except Exception:
            target_host = "unknown"
        await save_result(task_id, "turnstile", {
            "status": "CAPTCHA_NOT_READY",
            "createTime": int(time.time()),
            "url": url,
            "sitekey": sitekey,
            "action": action,
            "cdata": cdata,
            "proxy": bool(_normalize_task_proxy(proxy)),
        })
        logger.info(
            f"Turnstile task queued id={task_id[:8]} host={target_host} "
            f"browser={self.browser_type} machine={platform.machine() or 'unknown'} "
            f"proxy={'yes' if _normalize_task_proxy(proxy) else 'no'}"
        )

        try:
            asyncio.create_task(
                self._solve_turnstile(
                    task_id=task_id,
                    url=url,
                    sitekey=sitekey,
                    action=action,
                    cdata=cdata,
                    proxy=proxy,
                )
            )
            if self.debug:
                logger.debug(f"Request completed with taskid {task_id}.")
            return task_id, None
        except Exception as e:
            logger.error(f"Unexpected error processing request: {str(e)}")
            return None, {
                "errorId": 1,
                "errorCode": "ERROR_UNKNOWN",
                "errorDescription": str(e)
            }

    def _format_task_result(self, task_id: str, result) -> dict:
        """统一格式化任务结果（兼容 YesCaptcha）。"""
        if not result:
            return {
                "errorId": 1,
                "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                "errorDescription": "Task not found"
            }

        if result == "CAPTCHA_NOT_READY" or (
            isinstance(result, dict) and result.get("status") == "CAPTCHA_NOT_READY"
        ):
            return {
                "errorId": 0,
                "status": "processing",
                "taskId": task_id,
            }

        if isinstance(result, dict) and result.get("value") == "CAPTCHA_FAIL":
            error = str(result.get("error") or "unknown_turnstile_failure")
            elapsed_time = result.get("elapsed_time")
            diagnostics = (
                dict(result.get("diagnostics") or {})
                if isinstance(result.get("diagnostics"), dict)
                else {}
            )
            description = format_turnstile_failure(error, elapsed_time, diagnostics)
            return {
                "errorId": 1,
                "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                "errorDescription": description,
                "rawError": error,
                "elapsedTime": elapsed_time,
                "diagnostics": diagnostics,
            }

        if isinstance(result, dict) and result.get("value") and result.get("value") != "CAPTCHA_FAIL":
            return {
                "errorId": 0,
                "status": "ready",
                "taskId": task_id,
                "solution": {
                    "token": result["value"]
                }
            }

        return {
            "errorId": 1,
            "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
            "errorDescription": "Workers could not solve the Captcha"
        }

    async def process_turnstile(self):
        """Handle the /turnstile endpoint requests."""
        url = request.args.get('url')
        sitekey = request.args.get('sitekey')
        action = request.args.get('action')
        cdata = request.args.get('cdata')

        task_id, err = await self._enqueue_turnstile(url, sitekey, action, cdata)
        if err:
            return jsonify(err), 200
        return jsonify({"errorId": 0, "taskId": task_id}), 200

    async def get_result(self):
        """Return solved data"""
        task_id = request.args.get('id')

        if not task_id:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_WRONG_CAPTCHA_ID",
                "errorDescription": "Invalid task ID/Request parameter"
            }), 200

        result = await load_result(task_id)
        return jsonify(self._format_task_result(task_id, result)), 200

    async def create_task(self):
        """YesCaptcha 兼容：POST /createTask"""
        try:
            body = await request.get_json(force=True, silent=True) or {}
        except Exception:
            body = {}

        auth_err = self._check_client_key(body.get("clientKey"))
        if auth_err:
            return jsonify(auth_err), 200

        task = body.get("task") or {}
        task_type = (task.get("type") or "").strip()
        # Local Camoufox solver only has one Turnstile path. Accept YesCaptcha /
        # CapSolver premium aliases (M1/M2) as Proxyless so registration clients
        # that default premium=True do not fail createTask with
        # ERROR_TASK_NOT_SUPPORTED before falling back.
        supported = {
            "TurnstileTaskProxyless",
            "TurnstileTaskProxylessM1",
            "TurnstileTaskProxylessM2",
            "TurnstileTask",
            "AntiTurnstileTaskProxyLess",
            "AntiTurnstileTaskProxyless",
            "AntiTurnstileTask",
        }
        if task_type and task_type not in supported:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_TASK_NOT_SUPPORTED",
                "errorDescription": f"Unsupported task type: {task_type}"
            }), 200

        url = task.get("websiteURL") or task.get("websiteUrl") or task.get("url")
        sitekey = task.get("websiteKey") or task.get("sitekey") or task.get("siteKey")
        action = task.get("action") or task.get("pageAction")
        cdata = task.get("cdata") or task.get("data")
        proxy = _proxy_from_task_fields(task)

        # CapSolver 风格 metadata
        metadata = task.get("metadata") or {}
        if isinstance(metadata, dict):
            action = action or metadata.get("action")
            cdata = cdata or metadata.get("cdata")
            if not proxy:
                proxy = _proxy_from_task_fields(metadata)

        task_id, err = await self._enqueue_turnstile(
            url, sitekey, action, cdata, proxy=proxy
        )
        if err:
            return jsonify(err), 200
        return jsonify({"errorId": 0, "taskId": task_id}), 200

    async def get_task_result(self):
        """YesCaptcha 兼容：POST /getTaskResult"""
        try:
            body = await request.get_json(force=True, silent=True) or {}
        except Exception:
            body = {}

        auth_err = self._check_client_key(body.get("clientKey"))
        if auth_err:
            return jsonify(auth_err), 200

        task_id = body.get("taskId") or body.get("id")
        if not task_id:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_WRONG_CAPTCHA_ID",
                "errorDescription": "Invalid task ID/Request parameter"
            }), 200

        result = await load_result(task_id)
        return jsonify(self._format_task_result(task_id, result)), 200

    

    async def health(self):
        """Lightweight pool status for ops / memory debugging."""
        idle_for = None
        if self._last_used:
            idle_for = round(time.time() - self._last_used, 1)
        return jsonify({
            "ok": True,
            "lazy": bool(self.lazy_browsers),
            "idle_sec": self.idle_sec,
            "pool_ready": bool(self._pool_ready),
            "thread": self.thread_count,
            "browser_type": self.browser_type,
            "queue": self.browser_pool.qsize(),
            "owned": len(self._owned_browsers or []),
            "in_flight": int(self._in_flight or 0),
            "idle_for_sec": idle_for,
            "zombies": self._count_zombie_processes(),
            "browser_init": {
                "attempts": self._browser_init_attempts,
                "in_progress": self._browser_init_in_progress,
                "last_started_at": self._browser_init_last_started_at,
                "last_success_at": self._browser_init_last_success_at,
                "last_duration_sec": self._browser_init_last_duration_sec,
                "last_error": self._browser_init_last_error,
            },
            "runtime": self._runtime_info,
        }), 200

    async def reclaim(self):
        """Force reclaim browser pool (manual memory drop)."""
        if self._pool_lock is None:
            self._pool_lock = asyncio.Lock()
        async with self._pool_lock:
            owned = len(self._owned_browsers or [])
            qsize = self.browser_pool.qsize()
            in_flight = int(self._in_flight or 0)
            await self._shutdown_browsers()
        reaped = self._reap_zombie_children()
        return jsonify({
            "ok": True,
            "reclaimed": True,
            "owned_before": owned,
            "queue_before": qsize,
            "in_flight_before": in_flight,
            "pool_ready": bool(self._pool_ready),
            "owned": len(self._owned_browsers or []),
            "queue": self.browser_pool.qsize(),
            "in_flight": int(self._in_flight or 0),
            "reaped_zombies": reaped,
            "zombies": self._count_zombie_processes(),
        }), 200

    async def resize(self):
        """Hot-resize browser pool thread count without process restart.

        Accepts JSON body ``{"thread": N}`` (POST) or query ``?thread=N`` (GET).
        Updates ``thread_count`` and rebuilds/reclaims the pool so the next
        captcha wave uses the new size. Lazy mode only updates the target and
        reclaims any warm browsers; the next solve warms N browsers.
        """
        from quart import request

        previous = int(self.thread_count or 1)
        raw = None
        try:
            if request.method == "POST":
                payload = await request.get_json(force=True, silent=True) or {}
                if isinstance(payload, dict):
                    raw = payload.get("thread", payload.get("threads", payload.get("n")))
            if raw is None:
                raw = request.args.get("thread") or request.args.get("threads") or request.args.get("n")
        except Exception:
            raw = request.args.get("thread") if hasattr(request, "args") else None

        try:
            n = max(1, min(50, int(raw if raw is not None else previous)))
        except (TypeError, ValueError):
            return jsonify({
                "ok": False,
                "error": f"invalid thread value: {raw!r}",
                "thread": previous,
                "previous_thread": previous,
            }), 400

        if n == previous:
            # Already at target; still report success so callers don't process-restart.
            # (Do not require pool_ready — lazy mode often has pool_ready=false while idle.)
            return jsonify({
                "ok": True,
                "resized": False,
                "thread": n,
                "previous_thread": previous,
                "pool_ready": bool(self._pool_ready),
                "owned": len(self._owned_browsers or []),
                "queue": self.browser_pool.qsize(),
                "lazy": bool(self.lazy_browsers),
                "message": "already at target thread count",
            }), 200

        if self._pool_lock is None:
            self._pool_lock = asyncio.Lock()
        async with self._pool_lock:
            self.thread_count = n
            owned_before = len(self._owned_browsers or [])
            # Drop any warm browsers so next ensure uses the new thread_count.
            if self._pool_ready or self._owned_browsers or self._playwright or self._camoufox:
                await self._shutdown_browsers()
            # Eager mode: rebuild immediately. Lazy mode: warm on first captcha.
            if not self.lazy_browsers:
                await self._initialize_browser()
                self._pool_ready = True
                self._last_used = time.time()

        logger.info(
            f"Browser pool resized {previous} -> {n} "
            f"(lazy={self.lazy_browsers}, owned_before={owned_before})"
        )
        return jsonify({
            "ok": True,
            "resized": True,
            "thread": int(self.thread_count),
            "previous_thread": previous,
            "pool_ready": bool(self._pool_ready),
            "owned": len(self._owned_browsers or []),
            "queue": self.browser_pool.qsize(),
            "lazy": bool(self.lazy_browsers),
            "owned_before": owned_before,
            "message": (
                f"resized to {n}; lazy warm on next captcha"
                if self.lazy_browsers
                else f"resized and warmed pool to {n}"
            ),
        }), 200

    @staticmethod
    async def index():
        """Serve the API documentation page."""
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Turnstile Solver API</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-900 text-gray-200 min-h-screen flex items-center justify-center">
                <div class="bg-gray-800 p-8 rounded-lg shadow-md max-w-2xl w-full border border-red-500">
                    <h1 class="text-3xl font-bold mb-6 text-center text-red-500">Welcome to Turnstile Solver API</h1>

                    <p class="mb-4 text-gray-300">支持两套协议：原生 GET，以及 YesCaptcha/CapSolver 兼容 POST。</p>

                    <h2 class="text-xl font-semibold mb-3 text-red-400">1) 原生协议</h2>
                    <ul class="list-disc pl-6 mb-4 text-gray-300">
                        <li><code>GET /turnstile?url=...&amp;sitekey=...</code> → 返回 taskId</li>
                        <li><code>GET /result?id=TASK_ID</code> → 轮询结果</li>
                    </ul>
                    <div class="bg-gray-700 p-4 rounded-lg mb-6 border border-red-500">
                        <p class="font-semibold mb-2 text-red-400">Example:</p>
                        <code class="text-sm break-all text-red-300">/turnstile?url=https://example.com&sitekey=0x4AAAA...</code>
                    </div>

                    <h2 class="text-xl font-semibold mb-3 text-red-400">2) YesCaptcha 兼容协议</h2>
                    <ul class="list-disc pl-6 mb-4 text-gray-300">
                        <li><code>POST /createTask</code></li>
                        <li><code>POST /getTaskResult</code></li>
                    </ul>
                    <div class="bg-gray-700 p-4 rounded-lg mb-6 border border-red-500">
                        <p class="font-semibold mb-2 text-red-400">createTask body:</p>
                        <pre class="text-sm text-red-300 whitespace-pre-wrap">{
  "clientKey": "optional-if-API_KEY-set",
  "task": {
    "type": "TurnstileTaskProxyless",
    "websiteURL": "https://example.com",
    "websiteKey": "0x4AAAA..."
  }
}</pre>
                    </div>


                    <div class="bg-gray-700 p-4 rounded-lg mb-6">
                        <p class="text-gray-200 font-semibold mb-3">📢 Connect with Us</p>
                        <div class="space-y-2 text-sm">
                            <p class="text-gray-300">
                                📢 <strong>Channel:</strong> 
                                <a href="https://t.me/D3_vin" class="text-red-300 hover:underline">https://t.me/D3_vin</a> 
                                - Latest updates and releases
                            </p>
                            <p class="text-gray-300">
                                💬 <strong>Chat:</strong> 
                                <a href="https://t.me/D3vin_chat" class="text-red-300 hover:underline">https://t.me/D3vin_chat</a> 
                                - Community support and discussions
                            </p>
                            <p class="text-gray-300">
                                📁 <strong>GitHub:</strong> 
                                <a href="https://github.com/D3-vin" class="text-red-300 hover:underline">https://github.com/D3-vin</a> 
                                - Source code and development
                            </p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        """


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Turnstile API Server")

    parser.add_argument('--no-headless', action='store_true', help='Run the browser with GUI (disable headless mode). By default, headless mode is enabled.')
    parser.add_argument('--useragent', type=str, help='User-Agent string (if not specified, random configuration is used)')
    parser.add_argument('--debug', action='store_true', help='Enable or disable debug mode for additional logging and troubleshooting information (default: False)')
    parser.add_argument('--browser_type', type=str, default='chromium', help='Specify the browser type for the solver. Supported options: chromium, chrome, msedge, camoufox (default: chromium)')
    parser.add_argument('--thread', type=int, default=1, help='Set the number of browser threads to use for multi-threaded mode. Increasing this will speed up execution but requires more resources (default: 1)')
    parser.add_argument('--proxy', action='store_true', help='Enable proxy support for the solver (Default: False)')
    parser.add_argument('--random', action='store_true', help='Use random User-Agent and Sec-CH-UA configuration from pool')
    parser.add_argument('--browser', type=str, help='Specify browser name to use (e.g., chrome, firefox)')
    parser.add_argument('--version', type=str, help='Specify browser version to use (e.g., 139, 141)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Specify the IP address where the API solver runs. (Default: 127.0.0.1)')
    parser.add_argument('--port', type=str, default='5072', help='Set the port for the API solver to listen on. (Default: 5072)')
    return parser.parse_args()


def create_app(headless: bool, useragent: str, debug: bool, browser_type: str, thread: int, proxy_support: bool, use_random_config: bool, browser_name: str, browser_version: str) -> Quart:
    server = TurnstileAPIServer(headless=headless, useragent=useragent, debug=debug, browser_type=browser_type, thread=thread, proxy_support=proxy_support, use_random_config=use_random_config, browser_name=browser_name, browser_version=browser_version)
    return server.app


if __name__ == '__main__':
    args = parse_args()
    browser_types = [
        'chromium',
        'chrome',
        'msedge',
        'camoufox',
    ]
    if args.browser_type not in browser_types:
        logger.error(f"Unknown browser type: {COLORS.get('RED')}{args.browser_type}{COLORS.get('RESET')} Available browser types: {browser_types}")
    else:
        app = create_app(
            headless=not args.no_headless, 
            debug=args.debug, 
            useragent=args.useragent, 
            browser_type=args.browser_type, 
            thread=args.thread, 
            proxy_support=args.proxy,
            use_random_config=args.random,
            browser_name=args.browser,
            browser_version=args.version
        )
        app.run(host=args.host, port=int(args.port))
