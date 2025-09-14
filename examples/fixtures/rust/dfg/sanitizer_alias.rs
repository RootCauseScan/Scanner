fn main() {
    let mut data = source();
    let copy = data;
    data = sanitize(data);
    sink(copy);
}
