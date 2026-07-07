class Good {
    String id(String p) {
        return p;
    }

    void caller() {
        String src = dangerous();
        src = id(src);
        src = org.apache.commons.text.StringEscapeUtils.escapeHtml(src);
        sink(src);
    }
}
