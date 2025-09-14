class Bad {
    String id(String p) {
        return p;
    }

    void caller() {
        String src = dangerous();
        String a = id(src);
        sink(a);
    }
}
