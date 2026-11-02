/* Regression fixture for the generated Linux entrypoint stub's stack-
 * realignment code (see staticer/stubs/linux/elf_stub.py's own
 * docstring). This constructor's `buf` is a LOCAL, stack-resident,
 * 16-byte-aligned array -- GCC computes its address as a fixed offset
 * from the incoming %rsp/%esp, trusting (by default, matching this
 * platform's own ABI convention, with no defensive realignment of its
 * own) that the caller already handed it a 16-byte-aligned stack --
 * and `_mm_load_ps`/`_mm_store_ps` compile straight to `movaps`
 * (the *aligned* SSE move, not `movups`), which faults with #GP on any
 * address that isn't actually 16-byte aligned. lib_ctor_b.c/lib_ctor_a.c
 * deliberately avoid exercising this at all (rdtsc + a plain integer
 * store needs no stack alignment whatsoever), which is exactly why an
 * earlier, broken revision of the stub's own realignment code passed
 * every one of this project's other constructor-calling tests while
 * still reliably crashing on real embedded dependencies whose own
 * constructors do anything alignment-sensitive. */
#include <xmmintrin.h>

long long sse_align_result = -1;

__attribute__((constructor))
static void sse_align_ctor(void) {
    float buf[4] __attribute__((aligned(16))) = {1.0f, 2.0f, 3.0f, 4.0f};
    __m128 v = _mm_load_ps(buf);
    v = _mm_add_ps(v, v);
    _mm_store_ps(buf, v);
    sse_align_result = (long long)(buf[0] + buf[1] + buf[2] + buf[3]);
}

long long sse_align_value(void) {
    return sse_align_result;
}
