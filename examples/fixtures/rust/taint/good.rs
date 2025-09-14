fn main() {
    let mut user = source();
    user = sanitize(user);
    sink(user);
}
