# python-win7

**Run the official 32-bit CPython 3.13 on Windows 7 SP1 — without forking CPython and without recompiling it.**

[中文说明](README.zh-CN.md) · [How it works](docs/how-it-works.md) · [Build](docs/build.md) · [Verification](docs/verification.md) · [FAQ](docs/faq.md)

---

## The problem

| Fact | Detail |
|---|---|
| 32-bit Windows is still Tier 1 | PEP 11 keeps `i686-pc-windows-msvc` supported. Every release, including 3.13 and 3.15, ships a 32-bit installer and a 32-bit embeddable zip. **The 32-bit part was never the problem.** |
| Support floor moved | Since 3.9 the minimum is Windows 8.1; since 3.14 it is Windows 10. Windows 7 has been unsupported for years. |
| Failure mode is silent | The DLL statically imports APIs that only exist on Windows 8+. The loader refuses the image *before* `main`, so `python.exe` exits instantly with no output at all (`0xC0000135`). No traceback, no message. |

So the job is narrow: remove the handful of Windows 8/8.1-only dependencies from one DLL, and give the rest of the standard library back the trust anchors Windows 7 never received.

## What breaks on Windows 7

Six imports in `python313.dll` (seven in 3.15) plus one whole DLL:

| Missing on Win7 | Introduced | Replacement / behaviour |
|---|---|---|
| `GetSystemTimePreciseAsFileTime` | 8 | renamed in-place to `GetSystemTimeAsFileTime` (same signature) |
| `CopyFile2` | 8 | shim → `CopyFileW`, HRESULT mapped |
| `AddDllDirectory` / `RemoveDllDirectory` | 8 | shim → `SetDllDirectoryW` (global scope, not per-call) |
| `PssCaptureSnapshot` / `PssQuerySnapshot` / `PssFreeSnapshot` | 8.1 | shim returns `ERROR_CALL_NOT_IMPLEMENTED` |
| `GetCurrentThreadStackLimits` (3.15 only) | 8 | shim reads TEB `StackBase`/`StackLimit` — the same fields Windows 8 reads |
| `api-ms-win-core-path-l1-1-0.dll` | 8 | standalone shim forwarding `PathCchSkipRoot`/`PathCchCombineEx` to `shlwapi` |

Any one of these missing is enough to kill the process at load time.

## How it works

**1. Import-table surgery** — no code is moved, no relocation is touched.

- Import names are rewritten **in place, equal length** (31 bytes → 22 bytes + 9 NULs), so every RVA in the image stays valid.
- A new section `.w7imp` is appended containing a fresh `IMAGE_IMPORT_DESCRIPTOR` array: the six redirects get their own descriptors pointing at `win7k32shim.dll`, with `FirstThunk` aimed **exactly at the original IAT slots**.
- The loader processes descriptors in order, so `KERNEL32` writes a placeholder address first and the shim descriptor overwrites that same 4-byte slot afterwards.
- The PE checksum is recomputed from the final bytes; the build refuses to package if any Win8+ static import survives (it scans all 174 KERNEL32 imports).

**2. Probe-then-forward shim** — the same binaries stay correct on Windows 8/10/11.

Every shim export calls `GetProcAddress` on first use: if the real API exists it is forwarded verbatim, otherwise the Windows 7 path runs. Nothing is downgraded on systems that never needed the shim. Calling conventions (stdcall, `ret N`) were verified by disassembly.

**3. Restore the trust anchors** — the reason HTTPS fails even after Python starts.

Windows 7's ROOT store is frozen in time and lacks anchors such as ISRG Root X1, so *every* modern certificate chain looks like "unable to get local issuer certificate". The package ships `cacert.pem` (118 Mozilla roots) and a `sitecustomize.py` that **appends** it to the default SSL context at interpreter start — appending, not replacing, and without disabling verification. A `check.bat` item prints the live CA count and performs a real HTTPS request.

## Status

| Build | State |
|---|---|
| **3.13.16 (32-bit)** | **Stable** — verified on real Windows 7 SP1 hardware; 7/7 self-check items, stress tests pass |
| 3.15.2 (32-bit) | Experimental — built and statically verified, **not** yet run on real hardware |

Self-check on Windows 7 SP1 (screenshot from the actual machine):

```
[2] python.exe            SHA256: PASS
[3] python313.dll         SHA256: PASS
[4] shims present
[5] --version:            Python 3.13.16   exit code 0
[6] modules (os/time/socket/ssl/sqlite3/hashlib/json):   OK 3.13.16
[8] cacert.pem present · CA loaded: 132 · HTTPS: 200
```

Stress results (same machine): asyncio Proactor with 100 concurrent file operations 332 ms · asyncio TCP echo 10 ms · `multiprocessing` spawn 1182 ms · `ThreadPoolExecutor` 400 ms · socket options/timeouts OK.

## Install

1. Grab `Python-3.13.16-win32-win7.zip` from [Releases](../../releases).
2. Extract, then run `install.bat` (it elevates itself, installs the VC++ runtime, copies files, updates user `PATH`, verifies hashes, and smoke-tests).
3. Run `check.bat` — expect `Python 3.13.16` and, at item [8], an HTTPS 200.

Default target is `C:\Python313-Win7`; override with `install.bat D:\Python313`. Full log: `install.log`.

> Requires Windows 7 **SP1** plus KB4474419 (SHA-2 support) for the VC++ runtime installer.

## Build from source

Requirements: Python 3 with `pefile`, `i686-w64-mingw32-gcc`, `curl`, `unzip`.

```bash
pip install pefile
./build.sh                 # downloads the official embeddable zip, patches, packages
VER=3.15.2 ./build.sh      # any version the scripts already support
```

Output: `dist/Python-<ver>-win32-Win7-补丁版.zip`. See [docs/build.md](docs/build.md) for the step-by-step pipeline.

## Known limitations

- `time.time()` drops from ~1 µs to the system clock tick (~15.6 ms). `time.perf_counter()` is unaffected — it uses `QueryPerformanceCounter`, which Windows 7 has.
- The `Pss*Snapshot` family returns "not implemented"; diagnostic features that depend on it degrade instead of crashing.
- `python313.dll` no longer carries a valid Authenticode signature (the bytes changed). Antivirus may flag it; this is expected.
- The VC++ 2015-2022 runtime (UCRT) is still required. Without it you get the same silent `0xC0000135`.
- Not a security-maintained fork: there are no CPython security backports for Windows 7 here. Patch level equals upstream at build time.

## FAQ

**Is this a CPython fork?** No. It is the official binary with a patched import table, repackaged. Standard library and interpreter bytecode are untouched.

**Does it make Python worse on Windows 10/11?** No. The shim forwards to the real API whenever it exists.

**Why not just use Python 3.8?** 3.8 is also out of support; 3.13 gives you a modern stdlib and wheels. If 3.8 is enough for you, use it — it needs no patch.

**Does this fix TLS 1.3?** TLS 1.3 is not the issue. `libssl-3.dll` is OpenSSL 3 and negotiates TLS 1.3 in user space regardless of OS version. The failure was the missing *trust anchor*, which is what this fixes.

**Is `pip` usable?** Yes — `site` is enabled in the package, so `get-pip.py` works; a mirror index is recommended on old machines.

## Repository layout

```
shim/     C sources + .def for the two forwarder DLLs, build_shim.sh
tools/    add_win7_import_shim.py (PE surgery), build_payload.py, make_python_pkg.py, sitecustomize.py
certs/    cacert.pem (Mozilla bundle)
docs/     how-it-works, build, verification, faq
build.sh  one-command reproducible build
```

## License

Scripts, shim sources and docs: MIT. Released binaries are patched CPython and remain under the PSF License. Third-party components and their terms: [NOTICE.md](NOTICE.md).
