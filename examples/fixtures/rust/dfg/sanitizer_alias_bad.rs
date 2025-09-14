fn main() {
    let mut data = source();
    let mut copy = data;
    copy = sanitize(copy);
    sink(data);
}
