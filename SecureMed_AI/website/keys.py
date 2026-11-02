"""Backend-only key storage. Windows DPAPI binds the key to this OS account."""
import base64
import ctypes
import os
import secrets
from pathlib import Path

def backend_key(path: Path):
    configured = os.environ.get('SECUREMED_ENCRYPTION_KEY')
    if configured:
        key = base64.b64decode(configured, validate=True)
        if len(key) != 32:
            raise RuntimeError('SECUREMED_ENCRYPTION_KEY must encode 32 random bytes.')
        return key
    if os.name != 'nt':
        raise RuntimeError('Set SECUREMED_ENCRYPTION_KEY to a base64-encoded 32-byte secret on this platform.')
    class Blob(ctypes.Structure):
        _fields_ = [('size', ctypes.c_ulong), ('data', ctypes.POINTER(ctypes.c_ubyte))]
    def protect(raw, decrypt=False):
        buffer = ctypes.create_string_buffer(raw)
        source = Blob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
        out = Blob()
        crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
        function = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
        function.restype = ctypes.c_int
        if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(out)):
            raise RuntimeError(f'Windows key protection failed (error {ctypes.get_last_error()}). Run under the original Windows account.')
        try:
            return ctypes.string_at(out.data, out.size)
        finally:
            free = ctypes.windll.kernel32.LocalFree
            free.argtypes = [ctypes.c_void_p]
            free.restype = ctypes.c_void_p
            free(out.data)
    if path.exists() and path.stat().st_size:
        return protect(path.read_bytes(), True)
    key = secrets.token_bytes(32)
    protected = protect(key)
    # A failed first-time protection attempt in an older version could leave a
    # zero-byte file. It contains no key and is safe to replace after protection.
    if path.exists() and path.stat().st_size == 0:
        path.unlink()
    try:
        with path.open('xb') as file:
            file.write(protected)
    except FileExistsError:
        return protect(path.read_bytes(), True)
    return key
