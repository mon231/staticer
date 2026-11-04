# Examples

## 1. Make a Windows executable self-contained

You built `app.exe` against a couple of your own DLLs, and want to ship
one file instead of three:

```bash
staticer app.exe -o app_static.exe
```

```
$ dir
app.exe  helper.dll  render.dll

$ staticer app.exe -o app_static.exe

$ dir
app.exe  helper.dll  render.dll  app_static.exe

$ copy app_static.exe C:\clean-machine\
$ cd C:\clean-machine
$ app_static.exe
# runs correctly -- helper.dll and render.dll are not needed here
```

`helper.dll` and `render.dll` are resolved (since they sit next to
`app.exe`), embedded, and their import-table entries in `app_static.exe`
are removed. System DLLs like `kernel32.dll` are embedded too, by
default, unless excluded — see the next example if you don't want that.

## 2. Keep system DLLs dynamic, embed only your own libraries

By default, every resolvable dependency is a candidate — including
system libraries. Use `--lib-dir` to scope embedding to just the folder
your own libraries live in:

```bash
staticer app.exe -o app_static.exe --lib-dir .
```

Only `helper.dll`/`render.dll` (found in `.`) get embedded;
`kernel32.dll`, `user32.dll`, etc. (found in `System32`, outside
`--lib-dir`) stay ordinary dynamic imports, resolved normally at
runtime.

## 3. Exclude one specific dependency

Maybe `render.dll` needs to stay a separate, independently-updatable
file (a plugin, say), but `helper.dll` should still be folded in:

```bash
staticer app.exe -o app_static.exe --exclude render.dll
```

`render.dll` remains a dynamic import; `app_static.exe` still needs
`render.dll` next to it at runtime, but no longer needs `helper.dll`.

## 4. Combine `--lib-dir` and `--exclude`

```bash
staticer app.exe -o app_static.exe --lib-dir ./vendor --exclude render.dll
```

Only dependencies found in `./vendor` are embedding candidates, and
`render.dll` is excluded even if it happens to live there too.

## 5. Make a Linux binary self-contained

Same shape on ELF:

```bash
staticer my_tool -o my_tool_static --lib-dir ./lib
```

```
$ ls
my_tool  lib/libparser.so  lib/libformat.so

$ staticer my_tool -o my_tool_static --lib-dir ./lib

$ ldd my_tool_static
	linux-vdso.so.1 (0x...)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)
# libparser.so / libformat.so are gone -- they're embedded now
```

## 6. Embed a dependency into a DLL/`.so` (not just an executable)

The input doesn't have to be the top-level executable — a shared
library can itself be the thing being made more self-contained:

```bash
staticer render.dll -o render_static.dll --lib-dir .
```

`render_static.dll` can now be loaded by anything that expects
`render.dll`, with its own dependencies already folded in.

## 7. A dependency conflict, caught early

If two fixed-base (non-relocatable) dependencies would end up occupying
the same address range, `staticer` fails loudly instead of producing a
binary that corrupts itself at runtime:

```
$ staticer app.exe -o app_static.exe
error: base address conflict at 0x10000000 between liba.dll and libb.dll
```

Re-run with one of them excluded, or rebuilt at a different preferred
base, and try again.
