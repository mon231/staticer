extern "C" int thrower(int x);

int main() {
    try {
        thrower(1);
    } catch (int e) {
        return e;
    }
    return 1;
}
