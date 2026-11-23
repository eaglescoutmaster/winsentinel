"""Compile YARA rule packs, tolerating rules this yara-python build cannot support.

yara-python built without OpenSSL lacks pe.signatures / pe.number_of_signatures.
Rules using unsupported features are removed (and counted) instead of failing
the whole pack. The compiled result is cached under state/.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yara

_RULE_START = re.compile(r"^(?:(?:private|global)\s+)*rule\s+(\w+)", re.M)
_UNSUPPORTED = re.compile(r"pe\.(?:number_of_signatures|signatures|is_signed)|\bcuckoo\.|\bmagic\.")
_ERR_LINE = re.compile(r"\((\d+)\)")
OWN_RULES = Path(__file__).parent / "rules" / "winsentinel.yar"


def _split(source: str) -> tuple[str, list[tuple[str, str]]]:
    """Return (header with imports, [(rule_name, rule_text)])."""
    starts = [(m.start(), m.group(1)) for m in _RULE_START.finditer(source)]
    if not starts:
        return source, []
    header = source[: starts[0][0]]
    rules = []
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(source)
        rules.append((name, source[pos:end]))
    return header, rules


def compile_tolerant(source: str, max_rounds: int = 60) -> tuple[yara.Rules, int, int]:
    """Returns (rules, kept, dropped)."""
    header, rules = _split(source)
    kept = [(n, t) for n, t in rules if not _UNSUPPORTED.search(t)]
    dropped = len(rules) - len(kept)
    for _ in range(max_rounds):
        text = header + "".join(t for _, t in kept)
        try:
            return yara.compile(source=text), len(kept), dropped
        except yara.SyntaxError as e:
            m = _ERR_LINE.search(str(e))
            if not m:
                raise
            line = int(m.group(1))
            # Map the failing line back to a rule and drop it (also catches rules depending on dropped ones).
            offset = header.count("\n")
            for i, (_, t) in enumerate(kept):
                n = t.count("\n")
                if offset < line <= offset + n + 1:
                    kept.pop(i)
                    dropped += 1
                    break
                offset += n
            else:
                raise
    raise yara.Error("too many unsupported rules")


def load_pack(path: Path, cache_dir: Path) -> tuple[yara.Rules, dict]:
    raw = path.read_bytes()
    tag = hashlib.sha256(raw + yara.YARA_VERSION.encode()).hexdigest()[:16]
    cache = cache_dir / f"yara-{path.stem}-{tag}.compiled"
    meta_file = cache.with_suffix(".meta")
    if cache.exists() and meta_file.exists():
        try:
            kept, dropped = (int(x) for x in meta_file.read_text().split())
            return yara.load(str(cache)), {"rules": kept, "dropped_unsupported": dropped, "tag": tag}
        except (yara.Error, ValueError, OSError):
            pass
    rules, kept, dropped = compile_tolerant(raw.decode("utf-8", "replace"))
    cache_dir.mkdir(parents=True, exist_ok=True)
    rules.save(str(cache))
    meta_file.write_text(f"{kept} {dropped}")
    return rules, {"rules": kept, "dropped_unsupported": dropped, "tag": tag}


def load_own() -> yara.Rules:
    return yara.compile(filepath=str(OWN_RULES))
