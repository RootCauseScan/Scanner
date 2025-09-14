import java.util.function.Function;

class Good {
    void demo(String input) {
        Function<String, String> f = s -> s;
        Function<String, String> g = String::valueOf;
        String a = f.apply(input);
        String b = g.apply(input);
    }
}
