#!/usr/bin/env python3
"""Configuration and brightness calculation for Chromium Gamma 2.2 / HDR SDR boost."""

from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import winreg

from gamma22_patcher import SRGB_TRANSFER_FUNCTION, GAMMA22_TRANSFER_FUNCTION

DEFAULT_TARGET_NITS = 1000.0
DEFAULT_SDR_WHITE_NITS = 480.0

CONFIG_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "ChromiumGamma22"
CONFIG_FILE = CONFIG_DIR / "config.json"


def get_system_sdr_white_level() -> float:
    """Read primary monitor SDRWhiteLevel from GraphicsDrivers registry in nits."""
    path = r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers\MonitorDataStore"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            max_level = 0
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    i += 1
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        try:
                            val, _ = winreg.QueryValueEx(subkey, "SDRWhiteLevel")
                            if val > max_level:
                                max_level = val
                        except OSError:
                            pass
                except OSError:
                    break
            if max_level > 0:
                return float(max_level) * 80.0 / 1000.0
    except OSError:
        pass
    return DEFAULT_SDR_WHITE_NITS


def calculate_boost_factor(target_nits: float, sdr_white: float | None = None) -> float:
    """Calculate the linear multiplier M = target_nits / sdr_white."""
    if sdr_white is None:
        sdr_white = get_system_sdr_white_level()
    if sdr_white <= 0 or target_nits <= sdr_white:
        return 1.0
    return target_nits / sdr_white


def calculate_a(target_nits: float, sdr_white: float | None = None, gamma: float = 2.2) -> float:
    """Calculate the Skia transfer function parameter 'a' for linear boost M:

    y = (a * x)^gamma = a^gamma * x^gamma = M * x^gamma => a = M^(1 / gamma).
    """
    boost = calculate_boost_factor(target_nits, sdr_white)
    return boost ** (1.0 / gamma)


def make_transfer_function(gamma: float = 2.2, a: float = 1.0) -> bytes:
    """Serialize skcms_TransferFunction struct (7 floats: g, a, b, c, d, e, f)."""
    return struct.pack("<7f", gamma, a, 0.0, 0.0, 0.0, 0.0, 0.0)


def is_valid_transfer_function(data: bytes, allow_srgb: bool = True) -> bool:
    """Check if 28 bytes correspond to a valid sRGB or pure-gamma Skia transfer function."""
    if len(data) != 28:
        return False
    if allow_srgb and data == SRGB_TRANSFER_FUNCTION:
        return True
    try:
        g, a, b, c, d, e, f = struct.unpack("<7f", data)
        return abs(g - 2.2) < 0.05 and a > 0.0 and b == 0.0 and c == 0.0 and d == 0.0 and e == 0.0 and f == 0.0
    except struct.error:
        return False


_in_memory_target_nits: float | None = None


def load_config() -> dict:
    """Load configuration from %LOCALAPPDATA%/ChromiumGamma22/config.json."""
    if not CONFIG_FILE.exists():
        return {"target_nits": DEFAULT_TARGET_NITS}
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"target_nits": DEFAULT_TARGET_NITS}


def save_config(cfg: dict) -> None:
    """Save configuration to %LOCALAPPDATA%/ChromiumGamma22/config.json."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with CONFIG_FILE.open("w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"Failed to save config: {e}")


def get_target_nits() -> float:
    """Get currently configured target SDR brightness in nits."""
    global _in_memory_target_nits
    if _in_memory_target_nits is not None:
        return _in_memory_target_nits
    cfg = load_config()
    return float(cfg.get("target_nits", DEFAULT_TARGET_NITS))


def set_target_nits(nits: float, persist: bool = True) -> None:
    """Set target SDR brightness in nits."""
    global _in_memory_target_nits
    _in_memory_target_nits = float(nits)
    if persist:
        cfg = load_config()
        cfg["target_nits"] = float(nits)
        save_config(cfg)


def get_active_transfer_function(target_nits: float | None = None) -> bytes:
    """Return the 28-byte transfer function corresponding to target_nits."""
    if target_nits is None:
        target_nits = get_target_nits()
    a = calculate_a(target_nits)
    return make_transfer_function(gamma=2.2, a=a)
