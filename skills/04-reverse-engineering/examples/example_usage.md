# Reverse Engineering — Example Usage

## Binary Analysis

### Full Analysis

```bash
python scripts/binary_analyzer.py -f suspicious.elf -o analysis.json
```

### PE Analysis (Windows Binary)

```bash
python scripts/binary_analyzer.py -f malware.exe -o pe_analysis.json
```

### Skip Strings (Faster)

```bash
python scripts/binary_analyzer.py -f large_binary.bin --no-strings -o quick_analysis.json
```
