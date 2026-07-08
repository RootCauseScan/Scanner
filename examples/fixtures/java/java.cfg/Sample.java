class Sample {
    void run(String input) {
        if (input != null) {
            String safe = sanitize(input);
            sink(safe);
        } else {
            log(input);
        }
    }

    String sanitize(String s) {
        return s.trim();
    }

    void sink(String s) {}

    void log(String s) {}
}
