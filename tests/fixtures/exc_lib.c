// Compiled as C++ (see conftest.py's `cpp=True` build option) despite the
// ".c" name -- the task brief calls for this exact filename, and real C++
// exception handling needs a C++ compiler regardless of what the file is
// named.
//
// Exports `call_through`, which invokes a callback and returns its
// result. The callback (supplied by exc_main.c) is what actually
// `throw`s -- see exc_main.c's comment for why the exception's throw
// point is deliberately in the *host*, not in this embedded function.
extern "C" __declspec(dllexport) int call_through(int (*fn)(void)) {
    // Enough local stack use to force the compiler to emit real (non-
    // trivial) prologue/epilogue unwind codes -- callee-saved-register
    // pushes that RtlVirtualUnwind must correctly undo while walking
    // back through this frame once it's been relocated into the host.
    volatile long long guard[8];
    for (int i = 0; i < 8; i++) {
        guard[i] = i;
    }
    long long acc = 0;
    for (int i = 0; i < 8; i++) {
        acc += guard[i];
    }
    int r = fn();
    return r + (int)(acc - 28);
}
