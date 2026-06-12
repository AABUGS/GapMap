# GapMap

Maps a PIC payload into the alignment padding between PE sections of a loaded system
DLL and executes it from there.

When Windows loads a DLL, each section aligns to 0x1000 (4KB page boundary). Sections
rarely end exactly on a page boundary, so the remaining bytes are zero-filled padding.
These bytes are mapped and share the page protection of the section they sit in. Tail
of `.text` = already `PAGE_EXECUTE_READ`.

GapMap finds the largest `.text` tail gap across loaded system DLLs, writes a payload
into the padding, and launches it. The pages are already executable — no protection
changes needed in the final state.

> PoC quality. Your problem if it breaks.
>
> Concept by the repo owner. Implementation assisted by AI (Claude).

## `.text` tail gaps in System32 DLLs (x64, Windows 11)

| DLL | Bytes | Sections |
|-----|-------|----------|
| crypt32.dll | 4053 | `.text` -> `fothk` |
| dwmapi.dll | 3984 | `.text` -> `fothk` |
| normaliz.dll | 3978 | `.text` -> `.rdata` |
| clbcatq.dll | 3748 | `.text` -> `fothk` |
| ucrtbase.dll | 3741 | `.text` -> `fothk` |
| bcrypt.dll | 3708 | `.text` -> `fothk` |
| urlmon.dll | 3661 | `.text` -> `fothk` |
| shlwapi.dll | 3649 | `.text` -> `fothk` |
| uxtheme.dll | 3628 | `.text` -> `fothk` |
| dxgi.dll | 3588 | `.text` -> `fothk` |
| user32.dll | 3416 | `.text` -> `fothk` |
| ntdll.dll | 3174 | `.text` -> `SCPCFG` |
| advapi32.dll | 3164 | `.text` -> `fothk` |
| kernelbase.dll | 3051 | `.text` -> `fothk` |

All gaps are `PAGE_EXECUTE_READ` by default. `fothk` is a Microsoft telemetry/CFG
section — the gap before it is pure alignment padding, zero-referenced at runtime.

## How it works

1. Scans loaded system DLLs for the largest executable section gap
2. Briefly flips the gap to `PAGE_READWRITE`, writes the payload, restores original
   protection
3. Launches the payload via `CreateThread` — runs from the DLL's own `.text` address
   range

The `VirtualProtect` round-trip is the only API call that touches the target pages.
After the write, the page state is back to the original `PAGE_EXECUTE_READ`.

## Detection

- **`VirtualProtect` hook** could catch the brief RW flip during the write. Bypassable
  with manual syscalls.
- **CI/HVCI page hashes** validate page contents against the PE's authenticode catalog
  at page-in time. If the modified page gets paged out and back in, the hash won't match.
  Only applies on HVCI-enabled systems.
- **Disk-vs-memory byte comparison** of the full page (including padding past
  `VirtualSize`) would catch the non-zero bytes. Most integrity checkers only hash up to
  `VirtualSize` and miss the padding.

## Build

MinGW-w64, x64 only.

```
gcc -O2 -nostdlib -fno-asynchronous-unwind-tables -fno-ident \
    -e payload_entry -Wl,--section-alignment,4096 \
    -Wl,--file-alignment,512 -Wl,-s -Wl,--no-seh \
    -o payload.exe payload.c

gcc -O2 -o gapmap.exe gapmap.c
```

## Run

```
gapmap.exe
```

Both binaries in the same directory.

## License

MIT
