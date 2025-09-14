import static org.apache.commons.text.StringEscapeUtils.escapeHtml;

class Bad {
    void foo() {
        String s = dangerous();
        String alias = s;
        sink(alias);
    }
}
