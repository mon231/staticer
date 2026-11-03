// Host for exc_lib_selfcontained.c -- see that file's comment.
extern "C" int self_contained_throw_catch(void);

int main(void) {
    return self_contained_throw_catch();
}
