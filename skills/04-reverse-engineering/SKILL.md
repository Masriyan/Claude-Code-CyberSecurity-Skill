---
name: Reverse Engineering & Binary Analysis
description: Binary analysis, assembly interpretation, disassembly, decompilation, firmware RE, and protocol reverse engineering
version: 3.0.0
author: Masriyan
tags: [cybersecurity, reverse-engineering, binary-analysis, disassembly, firmware, assembly, ctf]
---

# Reverse Engineering & Binary Analysis

## Purpose

Enable Claude to assist with reverse engineering tasks including binary analysis, assembly interpretation, decompilation, firmware reverse engineering, and protocol analysis. Claude directly reads and interprets disassembled code, identifies patterns, reconstructs logic, and helps navigate complex binaries using RE tool output.

---

## Activation Triggers

This skill activates when the user asks about:
- Analyzing an ELF, PE (exe/dll), Mach-O, or raw binary
- Interpreting x86, x64, ARM, MIPS, or RISC-V assembly code
- Reverse engineering firmware from embedded/IoT devices
- Reverse engineering a network protocol
- Using Ghidra, IDA Pro, radare2, or Binary Ninja output
- Identifying what a binary or function does
- Finding vulnerabilities in disassembly
- CTF binary challenges (pwn, reversing categories)
- Anti-debugging or anti-analysis technique identification
- Unpacking or deobfuscating binaries

---

## Prerequisites

```bash
pip install capstone pyelftools pefile lief
```

**Recommended RE tools:**
- `Ghidra` — NSA open-source RE framework (free)
- `radare2` / `Cutter` — Open-source RE framework
- `Binary Ninja` — Commercial RE platform with scripting
- `IDA Pro / Free` — Industry standard disassembler
- `GDB + GEF/PEDA/pwndbg` — Dynamic debugging
- `Binwalk` — Firmware extraction and analysis
- `strings, file, objdump, readelf` — Standard Linux utilities

---

## Core Capabilities

### 1. Initial Binary Triage

**When the user provides a binary or asks what a file is:**

Run these commands and share output with Claude for analysis:

```bash
# File type identification
file suspicious_binary

# Strings extraction (often reveals C2, keys, paths)
strings -a suspicious_binary | grep -E "(http|/etc|password|key|secret|flag)"

# ELF analysis
readelf -a suspicious_binary
objdump -d suspicious_binary | head -100

# PE analysis
python scripts/binary_analyzer.py --file malware.exe --strings --imports

# Entropy analysis (high entropy = packed/encrypted)
python scripts/binary_analyzer.py --file binary --entropy
```

**Binary Triage Checklist:**
```
[ ] File type and format (magic bytes): ELF / PE / Mach-O / raw
[ ] Target architecture: x86 / x64 / ARM32 / ARM64 / MIPS / RISC-V
[ ] Endianness: little-endian / big-endian
[ ] Linking type: statically linked / dynamically linked
[ ] Security features: PIE / ASLR / NX/DEP / Stack Canary / RELRO
[ ] Packing detected: UPX / Themida / custom (high entropy sections)
[ ] Compiler identified: GCC / MSVC / Clang / Rust / Go
[ ] Interesting strings: URLs, IPs, credentials, file paths
[ ] Import/Export table: suspicious API calls
[ ] Entry point and sections mapping
```

**Security feature detection:**
```bash
# Linux: checksec (from pwntools)
checksec --file=./binary

# Or check manually:
readelf -l binary | grep GNU_STACK    # NX bit
readelf -d binary | grep RELRO        # RELRO
```

### 2. Assembly Code Interpretation

**When the user pastes disassembled code or Ghidra decompilation:**

Claude will:
1. Identify the architecture from instruction syntax
2. Trace execution flow from the provided entry point
3. Identify function calls (call/bl/jal instructions)
4. Reconstruct high-level logic from the assembly
5. Annotate each block with a comment explaining its purpose
6. Flag security-relevant patterns

**Common x86-64 Patterns:**

| Pattern | Instructions | Meaning |
|---------|--------------|---------|
| Function prologue | `push rbp; mov rbp, rsp; sub rsp, N` | Stack frame setup |
| Function epilogue | `leave; ret` or `pop rbp; ret` | Stack frame teardown |
| Local variable | `mov [rbp-N], rax` | Store value on stack |
| Loop counter | `cmp rax, N; jl/jge loop_top` | Loop with counter |
| Buffer on stack | `sub rsp, 0x100` | 256-byte local buffer |
| String copy | `rep movsb` | Memory copy |
| Memset | `rep stosb` | Memory zero/fill |
| Switch-case | Indirect jump: `jmp [rax*8 + table]` | Jump table |
| System call (Linux) | `mov rax, N; syscall` | Direct system call |
| Printf/format string | `lea rdi, [rip+str]; call printf@plt` | Print statement |
| Heap allocation | `call malloc` / `call operator new` | Dynamic memory |

**Common ARM64 Patterns:**
| Pattern | Instructions | Meaning |
|---------|--------------|---------|
| Function prologue | `stp x29, x30, [sp, #-N]!` | Save frame pointer & LR |
| Return | `ret` (uses x30) | Return from function |
| Load/store pair | `ldp/stp` | Load/store two registers |
| Branch + link | `bl func` | Call function |
| Conditional branch | `b.eq / b.ne / b.lt` | Conditional jump |
| System call | `svc #0` | System call |

**Crypto constant detection:**
```python
# Common crypto constants to watch for:
AES_SBOX = bytes.fromhex("637c777bf26b6fc5...") # AES SubBytes table
SHA256_K = [0x428a2f98, 0x71374491, ...]         # SHA-256 round constants
RC4_INIT_PATTERN                                   # Sequential 0x00-0xFF
```

### 3. Firmware Reverse Engineering

**When the user asks to analyze embedded firmware:**

```bash
# Step 1: Identify firmware format
file firmware.bin
binwalk firmware.bin

# Step 2: Extract filesystem
binwalk -e firmware.bin
# Extracts to _firmware.bin.extracted/

# Step 3: Analyze extracted filesystem
ls -la _firmware.bin.extracted/
find . -name "*.cgi" -o -name "passwd" -o -name "shadow" -o -name "*.conf"

# Step 4: Find sensitive data
grep -r "password\|admin\|secret\|key" . --include="*.conf" --include="*.xml"

# Step 5: Find binary entry points
file _firmware.bin.extracted/bin/*
strings -a httpd | grep -E "(password|auth|key)"
```

**Firmware Analysis Checklist:**
```
[ ] Identify firmware packaging format (SquashFS, JFFS2, CPIO, raw)
[ ] Extract filesystem using binwalk -e
[ ] Identify target OS and RTOS (Linux, VxWorks, ThreadX, FreeRTOS)
[ ] Find hardcoded credentials in /etc/passwd, config files, binaries
[ ] Identify web interface binaries (httpd, lighttpd, uhttpd)
[ ] Check for debug interfaces (JTAG, UART, SSH enabled)
[ ] Identify update mechanism and signing verification
[ ] Search for private keys, certificates, API keys
[ ] Check for command injection in shell scripts and CGI handlers
[ ] Map memory layout from linker scripts or binary headers
```

### 4. Protocol Reverse Engineering

**When the user wants to reverse engineer a protocol:**

**Given captured traffic or binary data:**

1. **Frame structure analysis** — Look for:
   - Magic bytes or sync patterns (fixed byte sequences at start)
   - Length fields (2 or 4 bytes, often at offset 2-4)
   - Message type/command identifier (1-2 bytes)
   - Checksum/CRC (last 1-4 bytes)
   - Padding patterns (0x00 or 0xFF fills)

2. **Field type identification:**
   ```
   Common field patterns:
   - 4 bytes, big-endian, values 0-65535 → likely length or port
   - 16 bytes uniform random → UUID or AES key
   - Null-terminated variable sequence → ASCII string
   - Fixed 4 bytes: 0xDEADBEEF, 0xCAFEBABE → magic number
   ```

3. **Command-response mapping** — Analyze pairs to find:
   - Request: specific type byte → Response: matching acknowledgment
   - Error responses: common error code patterns

4. **State machine construction:**
   ```
   [INIT] → send magic handshake → [AUTH] → send credentials →
   [CONNECTED] → send commands → [DATA] → receive data → [IDLE]
   ```

5. **Generate parser code:**
   ```python
   import struct
   
   MAGIC = b"\xDE\xAD\xBE\xEF"
   
   def parse_packet(data: bytes) -> dict:
       if not data.startswith(MAGIC):
           raise ValueError("Invalid magic bytes")
       
       msg_type, length = struct.unpack(">HH", data[4:8])
       payload = data[8:8 + length]
       checksum = struct.unpack(">H", data[8 + length:8 + length + 2])[0]
       
       return {
           "type": msg_type,
           "length": length,
           "payload": payload,
           "checksum": checksum
       }
   ```

### 5. Anti-Reversing Technique Identification & Bypass

**When the user encounters anti-analysis measures:**

| Technique | Indicators | Bypass |
|-----------|-----------|--------|
| UPX packing | `UPX!` string, high entropy | `upx -d binary` |
| Anti-debug: IsDebuggerPresent | API call in imports | Patch: NOP or force return 0 |
| Anti-debug: ptrace check | `ptrace(PTRACE_TRACEME)` | GDB: `catch syscall ptrace` + return 1 |
| Timing checks | RDTSC, GetTickCount loops | Patch jumps or NOP timing checks |
| VM detection | Check for VMware registry/files | Run on bare metal or patch |
| String encryption | No readable strings, XOR loops | Find decryption routine, set breakpoint after |
| Control flow flattening | Switch dispatch with state machine | Trace execution to map real CFG |
| Code virtualization | Custom VM interpreter | Analyze VM bytecode semantics |
| Self-modifying code | WriteProcessMemory, VirtualProtect | Set breakpoint at write target |

**Ghidra scripting for automation:**
```java
// Ghidra script: find all XOR loops (common string decryption)
FunctionManager fm = currentProgram.getFunctionManager();
for (Function f : fm.getFunctions(true)) {
    // Analyze function for XOR instructions
    // Flag functions with XOR + loop patterns
}
```

### 6. CTF Binary Challenges

**When the user is working on a CTF challenge (pwn/rev category):**

**Quick CTF triage:**
```bash
# Check protections
checksec --file=./challenge

# Find win functions, hidden strings
strings ./challenge | grep -i "flag\|win\|cat\|/bin"
objdump -d ./challenge | grep -A2 "win\|backdoor\|system"

# Run with strace to see syscalls
strace ./challenge < /dev/null 2>&1 | head -50

# Dynamic analysis with pwndbg
gdb ./challenge
# In GDB:
# info functions       → list all functions
# disas main           → disassemble main
# b *0x401234          → breakpoint at address
# r < input.txt        → run with input
```

**Common CTF patterns:**
- `gets()` / `scanf("%s")` without bounds → stack buffer overflow
- `printf(user_input)` without format string → format string vulnerability
- `strcmp(input, flag)` → timing attack or direct comparison
- Custom cipher with key → find key, XOR to decrypt
- VM-based challenge → trace bytecode execution to find flag check

---

## Output Standards

When analyzing binaries, Claude produces:
- **File summary**: type, arch, security features
- **Function list**: key functions and their purpose
- **Annotated disassembly**: line-by-line explanation
- **Vulnerability assessment**: security issues found in the code
- **Pseudocode reconstruction**: high-level equivalent of the assembly

---

## Script Reference

### `binary_analyzer.py`
```bash
# Full static analysis
python scripts/binary_analyzer.py --file suspicious.elf --output analysis.json

# Extract strings and imports only
python scripts/binary_analyzer.py --file malware.exe --strings --imports

# Entropy analysis (detect packing/encryption)
python scripts/binary_analyzer.py --file firmware.bin --entropy
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| Sample needs dynamic behavioral analysis | → Skill 05 (Malware Analysis) |
| Vulnerability found → develop exploit | → Skill 03 (Exploit Development) |
| Extract IOCs from analysis | → Skill 06 (Threat Hunting) |
| Create detection from findings | → Skill 15 (Blue Team Defense) |

---

## References

- [Ghidra Official Documentation](https://ghidra-sre.org/)
- [radare2 Book](https://book.rada.re/)
- [Intel x86-64 Software Developer Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)
- [ELF Specification (Linux Foundation)](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [PE Format Reference (Microsoft)](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Binwalk Documentation](https://github.com/ReFirmLabs/binwalk)
- [pwndbg Documentation](https://pwndbg.re/)


---

## v3.0 Enhancements (2026 Update)

**Faster, more capable RE workflow:**

- **AI-assisted decompilation** — use Claude to annotate Ghidra/IDA decompiler output: rename variables, recover structs, infer function purpose, and summarize control flow. Treat AI naming as hypotheses to verify, not ground truth.
- **Ghidra headless automation** — script bulk analysis (`analyzeHeadless`) with post-scripts for cross-binary IOC and string extraction.
- **Emulation-first triage** — Qiling/Unicorn to run snippets and resolve dynamic strings/config without a full debugger; angr for symbolic exploration of CTF-style logic.
- **Go / Rust / Nim binaries** — apply language-specific recovery (Go: `gopclntab` function/string recovery; Rust: demangling, panic-string pivots) since stripped modern binaries dominate.
- **eBPF & kernel objects** — recognize eBPF bytecode and kernel modules used for stealth.
- **Firmware** — `binwalk` extraction → filesystem mount → emulate with FirmAE/QEMU; locate hardcoded creds, update mechanisms, and crypto keys.

**Precision rule:** record load address/base, architecture, calling convention, and compiler/toolchain in every analysis so offsets are reproducible.
