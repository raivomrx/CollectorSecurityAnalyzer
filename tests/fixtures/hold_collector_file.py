"""Hold an actual Windows exclusive file handle in another process."""
import ctypes
from ctypes import wintypes
from pathlib import Path
import sys
import time

api = ctypes.WinDLL("kernel32", use_last_error=True)
api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
api.CreateFileW.restype = wintypes.HANDLE
api.CloseHandle.argtypes = [wintypes.HANDLE]
deadline = time.monotonic() + 10
Path(sys.argv[2] + ".watching").write_text("WATCHING", encoding="utf-8")
while True:
    handle = api.CreateFileW(sys.argv[1], 0x80000000, 0, None, 3, 0, None)
    if handle != ctypes.c_void_p(-1).value:
        break
    if time.monotonic() >= deadline:
        raise ctypes.WinError(ctypes.get_last_error())
    time.sleep(0.002)
try:
    Path(sys.argv[2]).write_text(str(time.monotonic()), encoding="utf-8")
    if len(sys.argv) > 4:
        deadline = time.monotonic() + 30
        while not Path(sys.argv[4]).exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("Collector verification never signaled readiness")
            time.sleep(0.002)
    time.sleep(float(sys.argv[3]))
finally:
    api.CloseHandle(handle)
