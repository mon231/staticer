// Compiled as C++ (see conftest.py's `cpp=True` build option) despite the
// ".c" name, matching exc_lib.c's convention.
//
// Unlike exc_lib.c/exc_main.c's pass-through-frame design (see that pair's
// comments), this exports a function that both `throw`s *and* `catch`es
// entirely within itself, embedded or not -- used by
// test_self_contained_throw_in_embedded_dll (B4 re-examination) to check
// whether the final review's B4 finding (dependency PE headers never
// copied into the embedded blob, so HINSTANCE/self-referential header
// reads see zeros) was the real cause of the GCC/MinGW half of Task 7's
// documented "self-contained throw in an embedded frame reliably
// crashed" finding, now that B4 is fixed.
extern "C" __declspec(dllexport) int self_contained_throw_catch(void) {
    try {
        throw 42;
    } catch (int e) {
        return e;
    }
    return -1;
}
