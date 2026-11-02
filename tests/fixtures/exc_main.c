// Compiled as C++ (see conftest.py's `cpp=True` build option) -- needs
// try/catch to catch the exception that crosses the embedded boundary.
//
// `thrower` is a local (host-side) function -- deliberately *not*
// exported/embedded -- that performs the actual `throw`. `call_through`
// (exc_lib.c, embedded) is a pass-through frame the exception must
// unwind *through* on its way from `thrower` up to this file's own
// `catch`: exactly the scenario the merged IMAGE_DIRECTORY_ENTRY_EXCEPTION
// (".pdata") exists to keep working, without needing the deeper (and
// undocumented/compiler-internal) per-frame exception-handler state
// (MSVC's FuncInfo / GCC's LSDA) that a *catching or throwing* embedded
// frame would additionally require -- see task-7-report.md for why that
// turned out to be a separate, deeper gap than "preserve .pdata/.xdata"
// covers, confirmed against both MSVC and MinGW/GCC.
extern "C" int call_through(int (*fn)(void));

static int thrower(void) {
    throw 42;
    return 0;
}

int main(void) {
    try {
        call_through(thrower);
        return 2;  // unreachable if the unwind through call_through's
                   // embedded frame works correctly
    } catch (int) {
        return 7;  // only reachable if that unwind (and the catch here,
                   // in the host's own untouched frame) worked
    }
}
