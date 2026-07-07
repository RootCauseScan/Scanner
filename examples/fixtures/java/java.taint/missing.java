class Missing {
    void run() {
        String data = source();
        // data is defined from source() but never reaches sink()
    }
}
