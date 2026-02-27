---
name: Reverse Engineering & Binary Analysis
description: Binary analysis, disassembly, decompilation, firmware RE, and protocol reverse engineering
version: 1.0.0
author: Masriyan
tags:
  [
    cybersecurity,
    reverse-engineering,
    binary-analysis,
    disassembly,
    firmware,
    malware,
  ]
---

# 🔬 Reverse Engineering & Binary Analysis

## Overview

This skill enables Claude to assist with reverse engineering tasks including binary analysis, disassembly, decompilation, firmware reverse engineering, and protocol analysis. Claude will help interpret assembly code, identify patterns, map control flows, and extract meaningful information from binaries.

---

## Prerequisites

### Required

- Python 3.8+
- `capstone`, `pyelftools`, `pefile`

### Optional

- **Ghidra** — NSA's reverse engineering framework
- **IDA Pro / Free** — Interactive disassembler
- **radare2** — Open-source RE framework
- **Binary Ninja** — RE platform
- **GDB + GEF/PEDA** — Debugging
- **Binwalk** — Firmware analysis
- **strings, file, objdump** — Standard Linux utilities

```bash
pip install capstone pyelftools pefile lief
```

---

## Core Capabilities

### 1. Static Binary Analysis

Claude can analyze binaries without executing them:

**When the user asks to analyze a binary:**

1. Identify the file type (ELF, PE, Mach-O, raw firmware)
2. Extract file metadata (architecture, endianness, entry point, sections)
3. Parse headers and section tables
4. Extract string references (ASCII, Unicode, encrypted)
5. Identify linked libraries and imported/exported functions
6. Detect packing, obfuscation, or anti-analysis techniques
7. Identify cryptographic constants and known algorithms
8. Map out function call graph and control flow
9. Perform entropy analysis to detect encrypted/compressed sections
10. Generate a structured analysis report

**Analysis Checklist:**

```
[ ] File identification (magic bytes, file type)
[ ] Architecture & ABI determination
[ ] Section analysis (code, data, resources)
[ ] Import/Export table enumeration
[ ] String extraction and categorization
[ ] Entropy analysis (packed/encrypted detection)
[ ] Security features (ASLR, DEP, Stack Canary, PIE)
[ ] Compiler/linker identification
[ ] Embedded resources extraction
```

### 2. Disassembly & Decompilation

Claude can help interpret disassembled code:

**When the user shares disassembled code:**

1. Identify the instruction set architecture (x86, x64, ARM, MIPS)
2. Trace execution flow from entry point
3. Identify function boundaries and calling conventions
4. Recognize common patterns (loops, conditionals, switches)
5. Identify library function calls and system calls
6. Reconstruct high-level logic from assembly
7. Identify vulnerability patterns in disassembly
8. Annotate code with meaningful comments

**Common Patterns to Recognize:**
| Pattern | Indicators |
|---------|-----------|
| Function prologue | `push rbp; mov rbp, rsp` |
| Stack buffer | `sub rsp, N` |
| Loop | `cmp/jl` or `dec/jnz` pairs |
| Switch/case | Jump table with indexed indirect jump |
| String operations | `rep movs`, `rep stos` |
| Crypto operations | Known constants (AES S-Box, SHA constants) |
| Anti-debug | `IsDebuggerPresent`, `ptrace`, timing checks |

### 3. Firmware Reverse Engineering

Claude can assist with embedded firmware analysis:

**When the user asks to analyze firmware:**

1. Identify firmware format and extract filesystem
2. Find and analyze bootloader code
3. Identify the RTOS or embedded OS
4. Map memory layout and peripheral registers
5. Extract hardcoded credentials and keys
6. Identify communication protocols and interfaces
7. Analyze update mechanisms for vulnerabilities
8. Check for debug interfaces (JTAG, UART, SWD)

### 4. Protocol Reverse Engineering

Claude can help reverse engineer network and serial protocols:

**When the user asks to reverse a protocol:**

1. Analyze captured traffic/data for structure patterns
2. Identify message boundaries and framing
3. Determine field types (length, type, checksum, payload)
4. Map command-response pairs
5. Identify authentication and encryption mechanisms
6. Build protocol state machine
7. Create protocol specification document
8. Generate parser code for the protocol

### 5. Anti-Reversing Technique Identification

Claude can identify and explain anti-analysis measures:

**When the user encounters anti-reversing:**

1. Detect packing (UPX, Themida, VMProtect, custom)
2. Identify anti-debugging techniques
3. Detect anti-VM/sandbox checks
4. Identify code obfuscation methods
5. Detect control flow flattening
6. Identify string encryption routines
7. Suggest bypass techniques for each measure

---

## Usage Instructions

### Example Prompts

```
> Analyze this ELF binary and describe its functionality
> Explain this x86_64 assembly code and identify what it does
> Help me reverse engineer this firmware image from an IoT device
> Identify the protocol structure from this captured network traffic
> What anti-debugging techniques are used in this sample?
> Parse this PE file and list all imports with their DLLs
```

---

## Script Reference

### `binary_analyzer.py`

```bash
python scripts/binary_analyzer.py --file suspicious.elf --output analysis.json
python scripts/binary_analyzer.py --file malware.exe --strings --imports
python scripts/binary_analyzer.py --file firmware.bin --entropy
```

---

## Integration Guide

### Chaining with Other Skills

- **← Malware Analysis (05)**: Receive samples requiring deeper RE analysis
- **→ Exploit Development (03)**: Feed vulnerability findings for exploit creation
- **→ Threat Hunting (06)**: Extract IOCs and behavioral signatures
- **→ Blue Team Defense (15)**: Create detection rules from RE findings

---

## References

- [Ghidra Documentation](https://ghidra-sre.org/)
- [radare2 Book](https://book.rada.re/)
- [x86 Assembly Guide (Intel)](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)
- [ELF Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [PE File Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
