import pkg.Helper;

class Main {
    static void sink(int x) {}

    void test() {
        int v = Helper.source();
        sink(v);
    }
}
