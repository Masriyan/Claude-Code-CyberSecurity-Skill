#!/usr/bin/env python3
"""
model_supply_chain.py — Scan ML model artifacts for code-execution risk.

Many model formats (pickle, .pt, .bin, .ckpt, joblib) deserialize via Python
pickle, which can execute arbitrary code on load. This tool statically inspects
pickle opcodes for dangerous reduce/global imports WITHOUT unpickling, and flags
unsafe formats vs. safe ones (safetensors / ONNX / GGUF). Maps to OWASP LLM03.

Usage:
    python model_supply_chain.py --path model.pt
    python model_supply_chain.py --path ./models --recursive --output scan.json
"""
import argparse
import json
import os
import pickletools
import sys
import zipfile

UNSAFE_EXT = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".dill", ".npy"}
SAFE_EXT = {".safetensors", ".onnx", ".gguf", ".ggml", ".json"}

# Globals that enable code execution when present in a pickle stream.
DANGEROUS_GLOBALS = {
    "os", "subprocess", "sys", "builtins", "posix", "nt", "shutil",
    "socket", "pty", "commands", "popen2", "platform", "importlib",
    "__builtin__", "eval", "exec", "system", "runpy", "operator.methodcaller",
}


def scan_pickle_bytes(data: bytes) -> list[str]:
    """Return list of dangerous findings from a pickle byte stream."""
    findings = []
    try:
        ops = list(pickletools.genops(data))
    except Exception as e:  # noqa: BLE001
        return [f"unparseable pickle stream ({e})"]
    for opcode, arg, _pos in ops:
        name = opcode.name
        if name in ("GLOBAL", "STACK_GLOBAL") and arg:
            mod = str(arg).split(" ")[0].split(".")[0]
            if mod in DANGEROUS_GLOBALS or str(arg) in DANGEROUS_GLOBALS:
                findings.append(f"GLOBAL import: {arg}")
        if name == "REDUCE":
            findings.append("REDUCE opcode (callable invocation on load)")
        if name in ("INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"):
            findings.append(f"{name} opcode (object construction on load)")
    # De-duplicate while keeping order
    seen, out = set(), []
    for f in findings:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def scan_file(path: str) -> dict:
    ext = os.path.splitext(path)[1].lower()
    result = {"path": path, "ext": ext, "verdict": "info", "findings": []}

    if ext in SAFE_EXT:
        result["verdict"] = "safe"
        result["findings"].append("safe-by-design format (no arbitrary code execution on load)")
        return result

    if ext not in UNSAFE_EXT:
        result["findings"].append("unknown format — review manually")
        return result

    try:
        # PyTorch .pt/.pth are usually zip archives containing pickle(s).
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for nm in zf.namelist():
                    if nm.endswith(("data.pkl", ".pkl", ".pickle")) or "pickle" in nm:
                        f = scan_pickle_bytes(zf.read(nm))
                        result["findings"] += [f"[{nm}] {x}" for x in f]
            if not result["findings"]:
                result["findings"].append("zip archive, no embedded pickle entries detected")
        else:
            with open(path, "rb") as fh:
                head = fh.read()
            result["findings"] += scan_pickle_bytes(head)
    except Exception as e:  # noqa: BLE001
        result["findings"].append(f"error: {e}")

    dangerous = any(("GLOBAL import" in f or "REDUCE" in f) for f in result["findings"])
    result["verdict"] = "DANGEROUS" if dangerous else "review"
    return result


def iter_paths(root: str, recursive: bool):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            yield os.path.join(dirpath, f)
        if not recursive:
            break


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan ML model files for load-time code execution risk")
    ap.add_argument("--path", required=True, help="Model file or directory")
    ap.add_argument("--recursive", action="store_true", help="Recurse into subdirectories")
    ap.add_argument("--output", help="Write JSON report")
    args = ap.parse_args()

    if not os.path.exists(args.path):
        print(f"[!] No such path: {args.path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning model artifacts: {args.path}\n")
    results, danger = [], 0
    for p in iter_paths(args.path, args.recursive):
        ext = os.path.splitext(p)[1].lower()
        if ext not in UNSAFE_EXT and ext not in SAFE_EXT:
            continue
        r = scan_file(p)
        results.append(r)
        tag = {"DANGEROUS": "[DANGER]", "review": "[review]",
               "safe": "[ safe ]", "info": "[ info ]"}.get(r["verdict"], "[      ]")
        print(f"  {tag} {os.path.relpath(p, args.path if os.path.isdir(args.path) else '.')}")
        for f in r["findings"][:6]:
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


if __name__ == "__main__":
    main()
