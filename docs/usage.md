# Usage

```
staticer <input> -o <output> [--exclude NAME[,NAME...]] [--lib-dir PATH]
```

## Arguments

| Argument | Required | Description |
|---|---|---|
| `input` | yes | Path to the dynamically-linked executable or shared library (DLL/`.so`) to process. |
| `-o`, `--output` | yes | Path to write the resulting binary. **Overwrites an existing file at that path without warning or backup.** |
| `--exclude NAME[,NAME...]` | no | Comma-separated dependency names to keep as ordinary dynamic imports — never embedded, resolved at runtime exactly as today. Case-insensitive on PE (matching Windows filename semantics), case-sensitive on ELF (matching Linux filesystem semantics). |
| `--lib-dir PATH` | no | Restrict embedding to dependencies actually found inside this folder. Dependencies resolved from anywhere else — including system directories — are left as ordinary dynamic imports. The directory must exist; an empty or missing value is rejected with a clear error rather than silently falling back to the current directory. Omit this flag entirely for an unrestricted search (every resolvable dependency is a candidate for embedding, system libraries included, unless `--exclude`d). |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Embedding succeeded. |
| `1` | A clean, reported error — unrecognized/malformed input, a dependency cycle, an unsupported construct (e.g. TLS in a dependency), a base-address conflict, or similar. The message is printed to stderr as `error: ...`; no raw Python traceback. |
| `2` | A command-line usage error (e.g. a malformed `--lib-dir`), reported by the argument parser itself. |

## Quick reference

```bash
# Embed everything resolvable, including system libraries
staticer app.exe -o app_static.exe

# Keep two specific dependencies dynamic, embed the rest
staticer app.exe -o app_static.exe --exclude kernel32.dll,user32.dll

# Only embed dependencies found in this folder; everything else stays dynamic
staticer app.exe -o app_static.exe --lib-dir ./vendor/libs

# Combine both
staticer app.exe -o app_static.exe --lib-dir ./vendor/libs --exclude mylib.dll
```

See [Examples](examples.md) for complete, runnable walkthroughs.
