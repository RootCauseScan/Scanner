import static org.apache.commons.text.StringEscapeUtils.escapeHtml;

class Good {
    void foo() {
        String s = dangerous();
        String clean = escapeHtml(s);
        String alias = clean;
        sink(alias);
    }
}
