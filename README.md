# staticer
Know it when you create a dynamiclly-linked executable, <br />
And try to execute it on other machines, but it fails to find expected symbols? <br />
Using your linux-executable on other machines with different libc, and can't find expected GLIBC function versions? <br />
Compiling a Windows-program and failing to run it on other machines? Or simply want your project to be published as onefile? <br />
Wait no more as `staticer` is here to the rescue! <br />
No more execution failures or long-taking compilation adaptions, <br />
Just to simply support same-kernel different-OS / OS versioning!

**NOTE** you should use this tool for legit-development / debugging / educational purposes only!

## Installation
Simply run:
> pip install staticer

Make sure to have python scripts folder in your path, <br/>
And use the correct version of pip for python3.

## Usage
```
staticer <input> -o <output> [--exclude NAME[,NAME...]] [--lib-dir PATH]
```

**NOTE** `-o`/`--output` overwrites an existing file at that path without warning or backup.

## Goals & Parctice
We want to get en executable-file and embed its dependencies recursively. <br />
We need to patch the executable-file's import-table and prevent it from loading the dynamic libraries. <br />
We need to patch the executable-file's import-table and have the resolved symbol addresses in it, <br />
And make the loader ignore that import-table in order not to clash, as it is invalidated. <br />
We need to embed the code/data/... sections of each embedded dependency, <br />
Patch their import-table the same way, and call their initializers (i.e. `DllMain` / `Constructor`)

In order to intercept explicit dynamic-loading (from the executed code itself), <br />
We'll have to hook `dlopen`+`dlsym` / `LoadLibraryW`+`GetProcAddress` and make them return addresses to embedded resources, <br />
Or make them call the original functions, if they try to access dynamic-libraries that weren't embedded.

**NOTE** OS-based / C++ `exception` unwinding works across embedded-dependency boundaries (unwind metadata is preserved); a self-contained embedded module that both throws and catches internally may still hit compiler-specific personality-routine details beyond the documented ABI
**NOTE** we currently do NOT support invoking `elf-destructor` / `DllMain` process-detach
**NOTE** we might never support `DllMain` invoking for thread attach/detach reasons

## Limitations
- Explicit dynamic-loading from the executed code itself (`dlopen`+`dlsym` / `LoadLibraryW`+`GetProcAddress`) is not hooked yet; only dependencies resolved through the input's own import/dynamic-section table are embedded.
- A "full closure" embed on ELF still bottoms out at glibc's own dynamic linker/loader internals, which stay dynamically linked rather than embedded.
- Process-detach cleanup (`elf-destructor` / `DllMain` `DLL_PROCESS_DETACH`) is not invoked for embedded dependencies, and thread attach/detach notifications may never be supported.
- `-o`/`--output` silently overwrites an existing file at that path (see Usage above).
