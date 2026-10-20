#!/usr/bin/env python3
"""model_supply_chain.py — Scan ML model artifacts for code-execution risk.

Many model formats (pickle, .pt, .bin, .ckpt, joblib) deserialize via Python
pickle, which can execute arbitrary code on load. This tool statically inspects
pickle opcodes for dangerous reduce/global imports WITHOUT unpickling, and flags
unsafe formats vs. safe ones (safetensors / ONNX / GGUF). Maps to OWASP LLM03.

The opcode walk resolves both the legacy ``GLOBAL`` opcode (protocol <= 3, which
carries ``module name`` inline) and ``STACK_GLOBAL`` (protocol >= 4, which pushes
the module and attribute as separate string opcodes first), so dangerous imports
in modern PyTorch/transformers checkpoints are not missed.

Usage:
    python model_supply_chain.py --path model.pt
    python model_supply_chain.py --path ./models --recursive --output scan.json
    python model_supply_chain.py --demo            # self-test on a synthetic pickle
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import pickletools
import sys
import zipfile

logger = logging.getLogger("model_supply_chain")

UNSAFE_EXT = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".dill", ".npy", ".npz"}
SAFE_EXT = {".safetensors", ".onnx", ".gguf", ".ggml", ".json"}

# Opcodes that push a string literal onto the stack (candidate STACK_GLOBAL operands).
_STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"}

# Modules/attributes that enable code execution or process/network side effects
# when imported inside a pickle stream.
DANGEROUS_MODULES = {
    "os", "subprocess", "sys", "builtins", "__builtin__", "posix", "nt",
    "shutil", "socket", "pty", "commands", "popen2", "platform", "importlib",
    "runpy", "operator", "functools", "codecs", "webbrowser", "ctypes",
    "multiprocessing", "asyncio", "pip", "setuptools", "requests", "urllib",
}
DANGEROUS_CALLABLES = {
    "system", "exec", "eval", "compile", "__import__", "getattr", "call",
    "check_call", "check_output", "Popen", "run", "popen", "spawn", "fork",
    "methodcaller", "attrgetter", "apply", "FromImport",
}


def scan_pickle_bytes(data: bytes) -> list[str]:
    """Return an ordered, de-duplicated list of dangerous findings from a pickle stream."""
    findings: list[str] = []
    recent_strings: list[str] = []  # trailing string literals, for STACK_GLOBAL resolution
    try:
        ops = list(pickletools.genops(data))
    except Exception as exc:  # noqa: BLE001 — malformed/truncated streams are expected input
        return [f"unparseable pickle stream ({exc})"]

    def flag_global(module: str, attr: str) -> None:
        ref = f"{module}.{attr}" if attr else module
        base = module.split(".")[0]
        if base in DANGEROUS_MODULES or attr in DANGEROUS_CALLABLES:
            findings.append(f"GLOBAL import: {ref}")

    for opcode, arg, _pos in ops:
        name = opcode.name
        if name in _STRING_OPS and arg is not None:
            recent_strings.append(str(arg))
            recent_strings = recent_strings[-2:]
        elif name == "GLOBAL" and arg:
            parts = str(arg).split(" ", 1)
            flag_global(parts[0], parts[1] if len(parts) > 1 else "")
            recent_strings.clear()
        elif name == "STACK_GLOBAL":
            if len(recent_strings) >= 2:
                flag_global(recent_strings[-2], recent_strings[-1])
            else:
                findings.append("STACK_GLOBAL with undetermined operands (manual review)")
            recent_strings.clear()
        elif name == "REDUCE":
            findings.append("REDUCE opcode (callable invocation on load)")
        elif name in ("INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"):
            findings.append(f"{name} opcode (object construction on load)")
        elif name in ("GLOBAL", "STACK_GLOBAL"):
            recent_strings.clear()

    seen: set[str] = set()
    out: list[str] = []
    for item in findings:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _verdict_from_findings(findings: list[str]) -> str:
    if any(f.startswith("GLOBAL import") for f in findings):
        return "DANGEROUS"
    if any(f.startswith("REDUCE") or "STACK_GLOBAL" in f for f in findings):
        return "review"
    return "review" if findings else "info"


def scan_file(path: str) -> dict:
    ext = os.path.splitext(path)[1].lower()
    result: dict = {"path": path, "ext": ext, "verdict": "info", "findings": []}

    if ext in SAFE_EXT:
        result["verdict"] = "safe"
        result["findings"].append("safe-by-design format (no arbitrary code execution on load)")
        return result

    if ext not in UNSAFE_EXT:
        result["findings"].append("unknown format — review manually")
        result["verdict"] = "review"
        return result

    try:
        if zipfile.is_zipfile(path):
            # PyTorch .pt/.pth and many .ckpt are zip archives containing pickle(s).
            with zipfile.ZipFile(path) as zf:
                for nm in zf.namelist():
                    if nm.endswith((".pkl", ".pickle")) or nm.endswith("data.pkl") or "pickle" in nm.lower():
                        result["findings"] += [f"[{nm}] {x}" for x in scan_pickle_bytes(zf.read(nm))]
            if not result["findings"]:
                result["findings"].append("zip archive, no embedded pickle entries detected")
        else:
            with open(path, "rb") as fh:
                result["findings"] += scan_pickle_bytes(fh.read())
    except Exception as exc:  # noqa: BLE001 — report I/O/zip errors as findings, never crash a batch scan
        logger.warning("error scanning %s: %s", path, exc)
        result["findings"].append(f"error: {exc}")
        result["verdict"] = "review"
        return result

    result["verdict"] = _verdict_from_findings([f.split("] ", 1)[-1] for f in result["findings"]])
    return result


def iter_paths(root: str, recursive: bool):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            yield os.path.join(dirpath, name)
        if not recursive:
            break


def _run_demo() -> int:
    """Self-test: confirm detection on synthetic pickles at legacy and modern protocols."""

    class _Probe:
        def __reduce__(self):
            return (os.system, ("echo demo",))

    for proto in (2, pickle.DEFAULT_PROTOCOL):
        findings = scan_pickle_bytes(pickle.dumps(_Probe(), protocol=proto))
        named = [f for f in findings if f.startswith("GLOBAL import")]
        status = "OK" if named else "FAIL"
        print(f"  [proto {proto}] {status}: {findings}")
        if not named:
            print("  [!] demo FAILED: dangerous global not resolved", file=sys.stderr)
            return 1
    print("[+] demo passed — GLOBAL/STACK_GLOBAL imports resolved at both protocols")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan ML model files for load-time code execution risk")
    ap.add_argument("--path", help="Model file or directory")
    ap.add_argument("--recursive", action="store_true", help="Recurse into subdirectories")
    ap.add_argument("--output", help="Write JSON report")
    ap.add_argument("--strict", action="store_true", help="Exit non-zero (3) if any DANGEROUS artifact is found")
    ap.add_argument("--demo", action="store_true", help="Run a built-in self-test and exit")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    if args.demo:
        sys.exit(_run_demo())

    if not args.path:
        ap.error("--path is required (or use --demo)")
    if not os.path.exists(args.path):
        print(f"[!] No such path: {args.path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning model artifacts: {args.path}\n")
    results, danger = [], 0
    base = args.path if os.path.isdir(args.path) else os.path.dirname(args.path) or "."
    for p in iter_paths(args.path, args.recursive):
        ext = os.path.splitext(p)[1].lower()
        if ext not in UNSAFE_EXT and ext not in SAFE_EXT:
            continue
        r = scan_file(p)
        results.append(r)
        tag = {"DANGEROUS": "[DANGER]", "review": "[review]",
               "safe": "[ safe ]", "info": "[ info ]"}.get(r["verdict"], "[      ]")
        print(f"  {tag} {os.path.relpath(p, base)}")
        for f in r["findings"][:8]:
            print(f"            - {f}")
        if r["verdict"] == "DANGEROUS":
            danger += 1

    print(f"\n=== {len(results)} artifact(s) scanned | {danger} DANGEROUS ===")
    if danger:
        print("[!] Prefer safetensors. Verify provenance/signature before loading (OWASP LLM03).")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"[+] Wrote {args.output}")

    if args.strict and danger:
        sys.exit(3)


if __name__ == "__main__":
    main()
