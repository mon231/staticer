#include <stdio.h>

int needs_further_value(void);

int main(void) {
    int v = needs_further_value();
    printf("%d\n", v);
    return v;
}
