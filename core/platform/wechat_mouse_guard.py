"""微信窗口鼠标防占用 hook 封装。"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import shutil
import sys
import tempfile
import weakref
from pathlib import Path
from typing import Optional, Set, Union

from loguru import logger


# 默认函数 RVA（DLL 无导出表时用作 fallback）
_DEFAULT_RVA_A = 0x1450
_DEFAULT_RVA_D = 0x14D8

# 允许的微信进程名；仅对微信小程序容器进程启用，避免影响主微信客户端。
_WECHAT_PROCESSES: Set[str] = {
    'wechatappex.exe',
}


def _is_64bit() -> bool:
    return sys.maxsize > 2**32


def _dll_arch(path: Path) -> Optional[str]:
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        machine = pe.FILE_HEADER.Machine
        pe.close()
        return {
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']: 'x64',
            pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: 'x86',
        }.get(machine)
    except Exception as exc:
        logger.warning('无法判断 DLL 架构: {}', exc)
        return None


def _find_dll(dll_path: Optional[Union[str, Path]] = None) -> Path:
    if dll_path is not None:
        p = Path(dll_path)
        if p.is_file():
            return p.resolve()
        raise FileNotFoundError(f'指定的 DLL 不存在: {p}')

    candidates = [
        Path(__file__).with_name('assets') / 'm.dll',
        Path(__file__).parent / 'm.dll',
        Path.cwd() / 'm.dll',
        Path.cwd() / 'assets' / 'm.dll',
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError('未找到 m.dll')


def _copy_dll_to_temp(src: Path) -> Path:
    temp_dir = Path(tempfile.gettempdir())
    dst = temp_dir / 'qq_farm_copilot_m.dll'
    try:
        if dst.exists() and dst.stat().st_size == src.stat().st_size:
            return dst
    except OSError:
        pass
    try:
        shutil.copy2(src, dst)
    except Exception as exc:
        raise OSError(f'拷贝 DLL 失败: {exc}') from exc
    return dst


def _load_dll(path: Path, verify_arch: bool = True) -> ctypes.WinDLL:
    if not _is_64bit():
        raise OSError('必须使用 64 位 Python 加载 64 位 DLL')
    if verify_arch:
        arch = _dll_arch(path)
        if arch and arch != 'x64':
            raise OSError(f'DLL 架构为 {arch}，但当前 Python 为 64 位')
    try:
        return ctypes.WinDLL(str(path))
    except OSError as exc:
        raise OSError(f'加载 DLL 失败: {exc}') from exc


def _get_proc_address(module: int, name: str) -> Optional[int]:
    kernel32 = ctypes.windll.kernel32
    kernel32.GetProcAddress.restype = wt.LPVOID
    kernel32.GetProcAddress.argtypes = [wt.HMODULE, wt.LPCSTR]
    addr = kernel32.GetProcAddress(module, name.encode('ascii'))
    return addr if addr else None


def _get_proc_address_by_ordinal(module: int, ordinal: int) -> Optional[int]:
    kernel32 = ctypes.windll.kernel32
    kernel32.GetProcAddress.restype = wt.LPVOID
    kernel32.GetProcAddress.argtypes = [wt.HMODULE, wt.LPCSTR]
    addr = kernel32.GetProcAddress(module, wt.LPCSTR(ordinal))
    return addr if addr else None


def _image_base(path: Path) -> int:
    try:
        import pefile

        pe = pefile.PE(str(path), fast_load=True)
        base = pe.OPTIONAL_HEADER.ImageBase
        pe.close()
        return base
    except Exception as exc:
        logger.warning('读取 ImageBase 失败: {}', exc)
        return 0x180000000


def _make_function(addr: int, argtypes: list, restype):
    return ctypes.WINFUNCTYPE(restype, *argtypes)(addr)


def _resolve_exports(module: int, names: Optional[dict] = None) -> Optional[tuple[int, int]]:
    names = names or {}
    name_a = names.get('a', 'n')
    name_d = names.get('d', 'q')

    addr_a = None
    for variant in (name_a, name_a.capitalize(), f'_{name_a}'):
        addr_a = _get_proc_address(module, variant)
        if addr_a:
            break
    if not addr_a:
        addr_a = _get_proc_address_by_ordinal(module, 1)

    addr_d = None
    for variant in (name_d, name_d.capitalize(), f'_{name_d}'):
        addr_d = _get_proc_address(module, variant)
        if addr_d:
            break
    if not addr_d:
        addr_d = _get_proc_address_by_ordinal(module, 2)

    if addr_a and addr_d:
        return addr_a, addr_d
    return None


class _DllWrapper:
    """底层 DLL 加载与函数解析封装。"""

    def __init__(
        self,
        dll_path: Optional[Union[str, Path]] = None,
        rva_a: Optional[int] = None,
        rva_d: Optional[int] = None,
        use_rva: bool = True,
        verify_arch: bool = True,
        names: Optional[dict] = None,
    ):
        src = _find_dll(dll_path)
        temp_path = _copy_dll_to_temp(src)
        self._dll = _load_dll(temp_path, verify_arch)
        self._handle = self._dll._handle
        self._image_base = _image_base(temp_path)
        self._names = names or {}

        addrs = _resolve_exports(self._handle, self._names)
        if addrs:
            addr_a, addr_d = addrs
            self._use_exports = True
        elif use_rva:
            ra = rva_a if rva_a is not None else _DEFAULT_RVA_A
            rd = rva_d if rva_d is not None else _DEFAULT_RVA_D
            addr_a = self._handle + ra
            addr_d = self._handle + rd
            self._use_exports = False
            logger.warning('DLL 无导出表，使用 RVA fallback: a=0x{:X}, d=0x{:X}', addr_a, addr_d)
        else:
            raise OSError('无法解析 DLL 函数')

        if self._use_exports:
            self._fn_a = _make_function(addr_a, [wt.HWND], ctypes.c_uint64)
            self._fn_d = _make_function(addr_d, [wt.HWND], wt.BOOL)
        else:
            self._fn_a = _make_function(addr_a, [wt.HWND, wt.DWORD], ctypes.c_uint64)
            self._fn_d = None

        self._addr_d = addr_d

    def apply(self, hwnd: int, tid: Optional[int] = None) -> int:
        hwnd = int(hwnd)
        if tid is None:
            tid = ctypes.windll.user32.GetWindowThreadProcessId(hwnd, None)
        try:
            if self._use_exports:
                result = self._fn_a(hwnd)
            else:
                result = self._fn_a(hwnd, tid)
        except OSError as exc:
            logger.error('调用 hook apply 异常: {}', exc)
            return 0
        if not result:
            logger.error('调用 hook apply 返回 0')
            return 0
        logger.info('微信鼠标防占用已启用: hwnd=0x{:X}, old=0x{:X}', hwnd, result)
        return int(result)

    def restore(self, hwnd: int, old: int = 0) -> bool:
        hwnd = int(hwnd)
        if self._fn_d is not None:
            try:
                return bool(self._fn_d(hwnd))
            except OSError as exc:
                logger.error('调用 hook restore 异常: {}', exc)
                return False
        if old:
            user32 = ctypes.windll.user32
            user32.SetWindowLongPtrW.restype = ctypes.c_void_p
            user32.SetWindowLongPtrW.argtypes = [wt.HWND, wt.INT, ctypes.c_void_p]
            prev = user32.SetWindowLongPtrW(hwnd, -4, old)
            return prev != 0 or ctypes.windll.kernel32.GetLastError() == 0
        logger.warning('没有 old 值，无法恢复 hook')
        return False


def _process_name(hwnd: int) -> Optional[str]:
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    pid = wt.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value == 0:
        return None

    process_handle = kernel32.OpenProcess(0x0410, False, pid.value)
    if not process_handle:
        return None
    try:
        buffer = ctypes.create_unicode_buffer(512)
        psapi.GetModuleBaseNameW(process_handle, None, buffer, 512)
        return buffer.value.lower() if buffer.value else None
    finally:
        kernel32.CloseHandle(process_handle)


def _is_valid_window(hwnd: int) -> bool:
    return bool(ctypes.windll.user32.IsWindow(hwnd))


class WeChatMouseGuard:
    """微信窗口鼠标防占用管理器。

    对单个 hwnd 应用 hook，并在实例停止时自动恢复。
    """

    _instances: weakref.WeakSet = weakref.WeakSet()

    def __init__(
        self,
        dll_path: Optional[Union[str, Path]] = None,
        allowed_processes: Optional[Set[str]] = None,
        rva_a: Optional[int] = None,
        rva_d: Optional[int] = None,
        verify_arch: bool = True,
        use_rva: bool = True,
        names: Optional[dict] = None,
    ):
        self._dll = _DllWrapper(
            dll_path=dll_path,
            rva_a=rva_a,
            rva_d=rva_d,
            use_rva=use_rva,
            verify_arch=verify_arch,
            names=names,
        )
        self._allowed = allowed_processes or set(_WECHAT_PROCESSES)
        self._hwnd: Optional[int] = None
        self._old: int = 0
        WeChatMouseGuard._instances.add(self)

    @property
    def hwnd(self) -> Optional[int]:
        return self._hwnd

    def is_active(self) -> bool:
        return self._hwnd is not None

    def _check_hwnd(self, hwnd: int) -> None:
        if not _is_valid_window(hwnd):
            raise ValueError(f'无效窗口句柄: 0x{hwnd:X}')
        process = _process_name(hwnd)
        if process is None:
            logger.warning('无法读取进程名，继续执行')
            return
        if process not in self._allowed:
            raise ValueError(f'进程 {process} 不在允许列表中')

    def apply(self, hwnd: int) -> bool:
        """对指定 hwnd 启用鼠标防占用 hook。"""
        hwnd = int(hwnd)
        try:
            self._check_hwnd(hwnd)
        except Exception as exc:
            logger.warning('启用微信鼠标防占用前校验失败: {}', exc)
            return False

        # 如果已经应用到了同一个 hwnd，直接跳过，避免重复 hook
        if self._hwnd is not None and self._hwnd == hwnd:
            logger.debug('微信鼠标防占用已应用于同一窗口，跳过: hwnd=0x{:X}', hwnd)
            return True
        # 如果之前应用到了不同 hwnd，先恢复旧窗口
        if self._hwnd is not None and self._hwnd != hwnd:
            self.restore()

        logger.info('启用微信鼠标防占用: hwnd=0x{:X}', hwnd)
        old = self._dll.apply(hwnd)
        if not old:
            logger.error('启用微信鼠标防占用失败')
            return False
        self._hwnd = hwnd
        self._old = old
        return True

    def restore(self, hwnd: Optional[int] = None) -> bool:
        """恢复指定 hwnd 的 hook；不传则恢复当前记录的 hwnd。"""
        target = hwnd if hwnd is not None else self._hwnd
        if target is None:
            logger.debug('restore 被调用，但没有已应用的句柄，跳过')
            return True
        target = int(target)
        if not _is_valid_window(target):
            logger.debug('恢复微信鼠标防占用: 窗口已销毁，跳过 restore | hwnd=0x{:X}', target)
            if self._hwnd == target:
                self._hwnd = None
                self._old = 0
            return True
        logger.info('恢复微信鼠标防占用: hwnd=0x{:X}', target)
        ok = self._dll.restore(target, old=self._old)
        if ok and self._hwnd == target:
            self._hwnd = None
            self._old = 0
        return ok

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.restore()
        return False

    def __del__(self):
        try:
            self.restore()
        except Exception:
            pass

    @classmethod
    def restore_all(cls) -> None:
        for inst in list(cls._instances):
            try:
                inst.restore()
            except Exception as exc:
                logger.debug('恢复 WeChatMouseGuard 实例时出错: {}', exc)


import atexit

atexit.register(WeChatMouseGuard.restore_all)
