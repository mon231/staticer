extern long long sse_align_value(void);

int main(void) {
    /* 20.0 == (1+2+3+4)*2 -- the known result of sse_align_ctor()'s own
     * SSE math, only observable if that constructor ran (via the
     * generated stub) without faulting on its own aligned stack access. */
    return (sse_align_value() == 20) ? 42 : 1;
}
