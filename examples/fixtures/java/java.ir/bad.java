import java.lang.Class;

public class Demo {
    public void foo(int a) {
        int x = 0;
        bar(a);
        x = x + a;
        if (a > 0) {
            foo(a - 1);
        }
    }

    private String bar(int a) {
        return "hi";
    }

    public static void main(String[] args) throws Exception {
        Demo d = new Demo();
        d.foo(1);
        Class.forName("java.lang.String");
    }
}
