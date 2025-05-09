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

**NOTE** we currently do NOT support dependencies that uses OS-based / C++ `exception`s
**NOTE** we currently do NOT support invoking `elf-destructor` / `DllMain` process-detach
**NOTE** we might never support `DllMain` invoking for thread attach/detach reasons
