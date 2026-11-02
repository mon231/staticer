// Exported C function that throws a C++ exception. Used to confirm the
// embedder's `.eh_frame`/`.eh_frame_hdr` merge keeps the embedded function's
// unwind info reachable from the host (which catches the exception on the
// other side of what used to be a dynamic-linking boundary).
extern "C" int thrower(int x) {
    if (x) {
        throw 7;
    }
    return x;
}
