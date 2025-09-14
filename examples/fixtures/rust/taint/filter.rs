fn main() {
    let mut user = source();
    user = filter(user);
    sink(user);
}
