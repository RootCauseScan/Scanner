import static org.apache.commons.text.StringEscapeUtils.escapeHtml;

class Good {
    String id(String p) {
        return p;
    }

    void caller() {
        String src = dangerous();
        String tmp = id(src);
        String s = escapeHtml(tmp);
        sink(s);
    }
}
