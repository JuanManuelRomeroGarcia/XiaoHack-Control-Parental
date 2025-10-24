# xiao_gui/icon_manager.py — gestor de iconos (assets / heurística / EXE)
from __future__ import annotations

import os
import math
import base64
import io
import tkinter as tk
from test_app.utils import ASSETS
from logs import get_logger

log = get_logger("gui.icons")

ICONS_DIR = ASSETS / "icons"

KNOWN_ICON_MAP = {
    "discord.exe": "discord",
    "steam.exe": "steam",
    "epicgameslauncher.exe": "epic",
    "fortniteclient-win64-shipping.exe": "fortnite",
    "robloxplayerbeta.exe": "roblox",
    "minecraft.exe": "minecraft",
    "valorant.exe": "riot",
    "riotclientservices.exe": "riot",
    "leagueclient.exe": "league",
    "battlenet.exe": "bnet",
    "chrome.exe": "chrome",
    "msedge.exe": "edge",
}

# Opcional: PIL para convertir el icono del .exe a PNG en memoria
try:
    from PIL import Image
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False
    log.debug("Pillow no disponible: no se extraerán iconos desde .exe")

# Windows APIs (solo si estamos en Windows)
_IS_WIN = (os.name == "nt")
if _IS_WIN:
    try:
        import ctypes
        from ctypes import wintypes

        SHGFI_ICON = 0x000000100
        SHGFI_LARGEICON = 0x000000000
        SHGFI_SMALLICON = 0x000000001

        class SHFILEINFO(ctypes.Structure):
            _fields_ = [
                ("hIcon", wintypes.HICON),
                ("iIcon", ctypes.c_int),
                ("dwAttributes", wintypes.DWORD),
                ("szDisplayName", wintypes.WCHAR * 260),
                ("szTypeName", wintypes.WCHAR * 80),
            ]

        # GDI
        class BITMAP(ctypes.Structure):
            _fields_ = [
                ("bmType", ctypes.c_long),
                ("bmWidth", ctypes.c_long),
                ("bmHeight", ctypes.c_long),
                ("bmWidthBytes", ctypes.c_long),
                ("bmPlanes", ctypes.c_ushort),
                ("bmBitsPixel", ctypes.c_ushort),
                ("bmBits", ctypes.c_void_p),
            ]

        class ICONINFO(ctypes.Structure):
            _fields_ = [
                ("fIcon", wintypes.BOOL),
                ("xHotspot", wintypes.DWORD),
                ("yHotspot", wintypes.DWORD),
                ("hbmMask", wintypes.HBITMAP),
                ("hbmColor", wintypes.HBITMAP),
            ]

        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        shell32 = ctypes.windll.shell32

        SHGetFileInfoW = shell32.SHGetFileInfoW
        SHGetFileInfoW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.POINTER(SHFILEINFO), wintypes.UINT, wintypes.UINT
        ]
        SHGetFileInfoW.restype = wintypes.DWORD

        GetIconInfo = user32.GetIconInfo
        GetIconInfo.argtypes = [wintypes.HICON, ctypes.POINTER(ICONINFO)]
        GetIconInfo.restype = wintypes.BOOL

        GetObject = gdi32.GetObjectW
        GetObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p]
        GetObject.restype = ctypes.c_int

        GetDIBits = gdi32.GetDIBits
        GetDIBits.argtypes = [
            wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT,
            ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT
        ]
        GetDIBits.restype = ctypes.c_int

        CreateCompatibleDC = gdi32.CreateCompatibleDC
        DeleteDC = gdi32.DeleteDC
        DeleteObject = gdi32.DeleteObject
        DestroyIcon = user32.DestroyIcon
    except Exception as e:
        _IS_WIN = False
        log.warning("APIs Win32 no disponibles: %s", e)


class IconManager:
    def __init__(self):
        # cache por clave: "<nombre|ruta>@<alto>"
        self.cache: dict[str, tk.PhotoImage] = {}

    def clear_cache(self):
        """Libera referencias a PhotoImage para permitir GC si recargas la UI."""
        self.cache.clear()
        log.debug("Cache de iconos vaciada")

    # -------------------- Carga desde assets (PNG) --------------------
    def _load_scaled_png(self, name: str, max_h: int) -> tk.PhotoImage | None:
        """
        Carga assets/icons/<name>.png y lo reescala con subsample
        para que NO supere max_h px de alto (evita iconos gigantes).
        """
        key = f"asset:{name.lower().strip()}@{int(max_h)}"
        if key in self.cache:
            log.debug("icon cache hit: %s", key)
            return self.cache[key]

        path = ICONS_DIR / f"{name}.png"
        if not path.exists():
            log.debug("asset no encontrado: %s", path)
            return None
        try:
            img = tk.PhotoImage(file=str(path))
            h = img.height()
            if h > max_h:
                factor = max(1, math.ceil(h / max_h))
                img = img.subsample(factor, factor)
                log.debug("scaled asset %s → factor=%d (h=%d→<=%d)", name, factor, h, max_h)
            self.cache[key] = img
            return img
        except Exception as e:
            log.warning("Error cargando asset %s: %s", path, e)
            return None

    # -------------------- Carga desde .exe (Windows) --------------------
    def _photoimage_from_exe(self, exe_path: str, max_h: int) -> tk.PhotoImage | None:
        """
        Intenta extraer el icono del .exe en Windows y convertirlo a PhotoImage.
        Requiere Pillow para convertir a PNG en memoria. Si no hay Pillow o algo falla, devuelve None.
        """
        if not (_IS_WIN and _HAS_PIL):
            return None
        try:
            # 1) Obtener HICON del archivo
            sfi = SHFILEINFO()
            flags = SHGFI_ICON | (SHGFI_SMALLICON if max_h <= 24 else SHGFI_LARGEICON)
            r = SHGetFileInfoW(exe_path, 0, ctypes.byref(sfi), ctypes.sizeof(sfi), flags)
            if r == 0 or not sfi.hIcon:
                return None

            hicon = sfi.hIcon
            try:
                # 2) Obtener bitmaps del icono
                ii = ICONINFO()
                if not GetIconInfo(hicon, ctypes.byref(ii)):
                    return None

                try:
                    # 3) Leer el HBITMAP color (32bpp BGRA)
                    class BITMAPINFOHEADER(ctypes.Structure):
                        _fields_ = [
                            ("biSize", wintypes.DWORD),
                            ("biWidth", ctypes.c_long),
                            ("biHeight", ctypes.c_long),
                            ("biPlanes", wintypes.WORD),
                            ("biBitCount", wintypes.WORD),
                            ("biCompression", wintypes.DWORD),
                            ("biSizeImage", wintypes.DWORD),
                            ("biXPelsPerMeter", ctypes.c_long),
                            ("biYPelsPerMeter", ctypes.c_long),
                            ("biClrUsed", wintypes.DWORD),
                            ("biClrImportant", wintypes.DWORD),
                        ]

                    class BITMAPINFO(ctypes.Structure):
                        _fields_ = [("bmiHeader", BITMAPINFOHEADER),
                                    ("bmiColors", wintypes.DWORD * 3)]

                    bm = BITMAP()
                    GetObject(ii.hbmColor, ctypes.sizeof(BITMAP), ctypes.byref(bm))
                    width, height = bm.bmWidth, bm.bmHeight

                    BI_RGB = 0
                    DIB_RGB_COLORS = 0
                    bmi = BITMAPINFO()
                    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
                    bmi.bmiHeader.biWidth = width
                    bmi.bmiHeader.biHeight = -height  # top-down
                    bmi.bmiHeader.biPlanes = 1
                    bmi.bmiHeader.biBitCount = 32
                    bmi.bmiHeader.biCompression = BI_RGB

                    buf_size = width * height * 4
                    buf = (ctypes.c_ubyte * buf_size)()

                    hdc = CreateCompatibleDC(0)
                    try:
                        res = GetDIBits(hdc, ii.hbmColor, 0, height, ctypes.byref(buf), ctypes.byref(bmi), DIB_RGB_COLORS)
                        if res == 0:
                            return None
                    finally:
                        DeleteDC(hdc)

                    im = Image.frombuffer("BGRA", (width, height), bytes(buf), "raw", "BGRA", 0, 1)
                    if im.height > max_h:
                        ratio = max_h / float(im.height)
                        new_w = max(1, int(im.width * ratio))
                        im = im.resize((new_w, max_h), Image.LANCZOS)

                    b = io.BytesIO()
                    im.save(b, format="PNG")
                    b64 = base64.b64encode(b.getvalue()).decode("ascii")
                    log.debug("icono extraído de EXE: %s (%dx%d → <=%d)", exe_path, width, height, max_h)
                    return tk.PhotoImage(data=b64)
                finally:
                    if ii.hbmColor:
                        DeleteObject(ii.hbmColor)
                    if ii.hbmMask:
                        DeleteObject(ii.hbmMask)
            finally:
                DestroyIcon(hicon)
        except Exception as e:
            log.warning("Fallo extrayendo icono de %s: %s", exe_path, e)
            return None

    # -------------------- API pública --------------------
    def icon_for_entry(self, tipo: str, valor: str, max_h: int = 22) -> tk.PhotoImage | None:
        """Devuelve un PhotoImage adecuado (escalado a max_h)."""
        # Carpeta → icono de carpeta si lo tienes, si no exe genérico
        if tipo == "Carpeta":
            im = self._load_scaled_png("folder", max_h) or self._load_scaled_png("exe", max_h)
            log.debug("icon Carpeta → %s", "folder" if im else "exe")
            return im

        # Si tenemos RUTA al .exe, intentamos icono real del ejecutable (Windows + PIL)
        if tipo == "Ruta":
            exe_path = os.path.normpath(valor)
            if exe_path.lower().endswith(".exe") and os.path.exists(exe_path):
                key = f"exe:{exe_path}@{int(max_h)}"
                if key in self.cache:
                    log.debug("icon cache hit exe: %s", exe_path)
                    return self.cache[key]
                img = self._photoimage_from_exe(exe_path, max_h)
                if img:
                    self.cache[key] = img
                    return img
            # si no hay ruta válida o falló, seguimos con la heurística por nombre

        # Heurística por nombre (nombre de exe o cadena)
        base = (os.path.basename(valor) if tipo == "Ruta" else valor).strip().lower()

        if base in KNOWN_ICON_MAP:
            img = self._load_scaled_png(KNOWN_ICON_MAP[base], max_h)
            if img:
                return img

        for key, icon in [
            ("discord", "discord"),
            ("steam", "steam"),
            ("epic", "epic"),
            ("fortnite", "fortnite"),
            ("roblox", "roblox"),
            ("minecraft", "minecraft"),
            ("valorant", "riot"),
            ("riot", "riot"),
            ("league", "league"),
            ("battlenet", "bnet"),
            ("chrome", "chrome"),
            ("edge", "edge"),
        ]:
            if key in base:
                img = self._load_scaled_png(icon, max_h)
                if img:
                    return img

        # Fallback final
        log.debug("icon fallback 'exe' para: %s (%s)", valor, tipo)
        return self._load_scaled_png("exe", max_h)

    @staticmethod
    def label_for_entry(tipo: str, valor: str) -> str:
        if tipo == "Carpeta":
            v = os.path.normpath(valor)
            name = os.path.basename(v) or v
            return name
        if tipo == "Ruta":
            return os.path.basename(os.path.normpath(valor)) or valor
        return valor
