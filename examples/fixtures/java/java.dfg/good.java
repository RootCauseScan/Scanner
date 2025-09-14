class Good {
    int callee(int x) {
        return x;
    }

    int caller(int y) {
        int result = callee(y);
        return result;
    }
}
