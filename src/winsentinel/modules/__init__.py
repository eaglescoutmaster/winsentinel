"""Module registry: every submodule exposing NAME, DESCRIPTION, ORDER and run(ctx)."""
from __future__ import annotations

import importlib
import pkgutil

_mods = []
for _info in pkgutil.iter_modules(__path__):
    _m = importlib.import_module(f"{__name__}.{_info.name}")
    if hasattr(_m, "NAME") and hasattr(_m, "run"):
        _mods.append(_m)

REGISTRY = {m.NAME: m for m in sorted(_mods, key=lambda m: m.ORDER)}
