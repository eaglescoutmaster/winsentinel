"""Module registry: every submodule exposing NAME, DESCRIPTION, ORDER and run(ctx).

A module may set PLATFORMS (a tuple of "windows", "linux", "macos"); without it the module runs
everywhere. Two modules may share a NAME as long as their platforms do not overlap, so
`--module persistence` means the right thing on each operating system.
"""
from __future__ import annotations

import importlib
import pkgutil

from ..osinfo import OS

_mods = []
UNSUPPORTED: dict[str, tuple[str, ...]] = {}  # module name -> platforms it does exist for
for _info in pkgutil.iter_modules(__path__):
    _m = importlib.import_module(f"{__name__}.{_info.name}")
    if not (hasattr(_m, "NAME") and hasattr(_m, "run")):
        continue
    _plats = getattr(_m, "PLATFORMS", ("windows", "linux", "macos"))
    if OS in _plats:
        _mods.append(_m)
    else:
        UNSUPPORTED[_m.NAME] = tuple(sorted(set(UNSUPPORTED.get(_m.NAME, ())) | set(_plats)))

REGISTRY = {m.NAME: m for m in sorted(_mods, key=lambda m: m.ORDER)}
for _name in REGISTRY:
    UNSUPPORTED.pop(_name, None)
