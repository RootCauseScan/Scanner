fn main() {
    let mut user = source();
    user = clean(user);
    sink(user);
}
