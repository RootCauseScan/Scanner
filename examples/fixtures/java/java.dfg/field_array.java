class FieldArray {
    int f;

    void sink(int x) {}

    void test(int y) {
        int[] arr = new int[1];
        this.f = y;
        int a = this.f;
        arr[0] = a;
        int b = arr[0];
        sink(this.f);
        sink(arr[0]);
    }
}
