#include <stdio.h>

int lib_value(void);

int main(void) {
    int v = lib_value();
    printf("%d\n", v);
    return v;
}
