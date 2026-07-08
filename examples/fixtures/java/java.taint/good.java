class Good {
    void run() {
        String data = source();
        data = org.apache.commons.text.StringEscapeUtils.escapeHtml(data);
        sink(data);
    }
}
