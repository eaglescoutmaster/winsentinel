"""Static traits of ELF and Mach-O binaries (the PE equivalent lives in modules/files.py).

ELF is parsed with pyelftools. Mach-O is handled without a parser: load commands are not walked,
imported symbol names are taken from the string table as plain strings. That is approximate, and
the output says so. Nothing here executes the file.
"""
from __future__ import annotations

import io
import math
import re
from collections import Counter

MACHO_MAGIC = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
               b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")

# symbol (lower case) -> capability. Imports show what a program can do, not what it does.
POSIX_CAPS: dict[str, set[str]] = {
    "process injection or tracing": {"ptrace", "process_vm_writev", "process_vm_readv", "task_for_pid",
                                     "mach_vm_write", "mach_vm_protect", "thread_create_running"},
    "in-memory execution": {"memfd_create", "fexecve", "mprotect", "nscreateobjectfileimagefrommemory"},
    "network": {"socket", "connect", "bind", "listen", "accept", "getaddrinfo", "sendto", "recvfrom",
                "curl_easy_perform", "ssl_connect"},
    "process creation": {"execve", "execvp", "execl", "system", "popen", "posix_spawn", "fork", "vfork"},
    "privilege changes": {"setuid", "setgid", "setreuid", "setresuid", "seteuid", "capset", "prctl",
                          "authorizationexecutewithprivileges"},
    "dynamic code loading": {"dlopen", "dlsym"},
    "keyboard or screen capture": {"xgrabkeyboard", "xquerykeymap", "cgeventtapcreate",
                                   "cgwindowlistcreateimage", "cgdisplaycreateimage", "iohidmanagercreate"},
    "kernel module loading": {"init_module", "finit_module", "delete_module", "kextload"},
    "anti-debug or evasion": {"sysctl", "getppid", "unsetenv", "clearenv"},
    "credential access": {"getspnam", "seckeychainfindgenericpassword", "seckeychainitemcopycontent",
                          "secitemcopymatching"},
    "file timestamp changes": {"utimes", "utimensat", "futimens"},
}
COMMON_CAPS = {"network", "process creation", "dynamic code loading", "anti-debug or evasion"}
_PACKERS = (b"UPX!", b"$Info: This file is packed with the UPX", b"MPRESS", b"PyInstaller")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def capabilities(symbols: set[str]) -> dict[str, list[str]]:
    out = {}
    for cap, names in POSIX_CAPS.items():
        hit = sorted(symbols & names)
        if hit:
            out[cap] = hit
    return out


def _signals(caps: dict[str, list[str]], packed: str, extra: list[str]) -> list[str]:
    sig = list(extra)
    if packed:
        sig.append(f"binary: packed or self-extracting ({packed})")
    for cap in ("process injection or tracing", "in-memory execution", "kernel module loading",
                "keyboard or screen capture", "credential access"):
        if cap not in caps:
            continue
        if cap == "in-memory execution" and not ({"memfd_create", "fexecve"} & set(caps[cap])):
            continue  # mprotect alone is ordinary
        if cap == "process injection or tracing" and len(caps[cap]) < 2:
            continue  # a lone ptrace import is what debuggers and crash handlers have
        if True:
            sig.append(f"binary: {cap} imports ({', '.join(caps[cap])})")
    return sig


def analyse_elf(data: bytes) -> dict:
    """Static ELF traits, or {} when the file cannot be parsed."""
    try:
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection

        elf = ELFFile(io.BytesIO(data))
        info: dict = {"format": "ELF", "machine": elf["e_machine"], "type": elf["e_type"], "bits": elf.elfclass}
        sections, symbols, needed = [], set(), []
        has_symtab = False
        for s in elf.iter_sections():
            raw = s.data()[: 4 * 1024 * 1024] if s["sh_type"] != "SHT_NOBITS" else b""
            sections.append({"name": s.name, "size": s["sh_size"], "entropy": round(entropy(raw), 2),
                             "executable": bool(s["sh_flags"] & 0x4), "writable": bool(s["sh_flags"] & 0x1)})
            if isinstance(s, SymbolTableSection):
                has_symtab = has_symtab or s.name == ".symtab"
                if s.name == ".dynsym":
                    for sym in s.iter_symbols():
                        if sym.name and sym["st_shndx"] == "SHN_UNDEF":
                            symbols.add(sym.name.split("@")[0].lower())
            if isinstance(s, DynamicSection):
                needed = [t.needed for t in s.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
        interp = next((seg.get_interp_name() for seg in elf.iter_segments() if seg["p_type"] == "PT_INTERP"), "")
        info.update(sections=sections, import_count=len(symbols), needed_libraries=needed, interpreter=interp,
                    stripped=not has_symtab, static=not interp and not needed)
    except Exception as e:  # truncated or deliberately malformed headers
        return {"format": "ELF", "parse_error": type(e).__name__, "signals": ["binary: ELF headers could not be parsed"]}
    caps = capabilities(symbols)
    packed = next((p.decode("ascii", "replace")[:12] for p in _PACKERS[:3] if p in data[: 2 * 1024 * 1024] or p in data[-4096:]), "")
    extra = []
    if not sections and len(data) > 4096:
        extra.append("binary: ELF has no section headers (stripped to hinder analysis)")
    hi = [s for s in sections if s["executable"] and s["size"] > 4096 and s["entropy"] > 7.2]
    if hi and len(symbols) < 10 and not packed:
        extra.append("binary: high-entropy code section with almost no imports (packed or encrypted)")
    info["capabilities_from_imports"] = caps
    info["signals"] = _signals(caps, packed, extra)
    return info


_SYM = re.compile(rb"\x00_([A-Za-z][A-Za-z0-9_]{3,60})(?=\x00)")
_DYLIB = re.compile(rb"((?:/usr/lib|/System/Library|@rpath|@executable_path|@loader_path)/[\x21-\x7e]{4,200}?(?:\.dylib|\.framework/[\x21-\x7e]{1,80}))\x00")


def analyse_macho(data: bytes) -> dict:
    """Approximate Mach-O traits taken from the string table (no load-command parsing)."""
    head = data[:4]
    info: dict = {"format": "Mach-O", "universal": head in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"),
                  "method": "string-table scan; approximate"}
    window = data[: 32 * 1024 * 1024]
    symbols = {m.group(1).decode("ascii", "replace").lower() for m in _SYM.finditer(window)}
    libs = sorted({m.group(1).decode("ascii", "replace") for m in _DYLIB.finditer(window)})[:80]
    caps = capabilities(symbols)
    packed = next((p.decode("ascii", "replace")[:12] for p in _PACKERS if p in window[: 2 * 1024 * 1024]), "")
    info.update(symbol_count=len(symbols), linked_libraries=libs, capabilities_from_imports=caps,
                has_code_signature=b"__LINKEDIT" in window and b"\xfa\xde\x0c\xc0" in data,
                entropy=round(entropy(window[: 8 * 1024 * 1024]), 2))
    info["signals"] = _signals(caps, packed, [])
    return info
