fn main() {
    let mut user = source();
    user = escape(user);
    sink(user);
}
