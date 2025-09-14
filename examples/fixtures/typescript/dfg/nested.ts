function outer() {
    let data = source();
    function inner() {
        let data = source();
        sink(data);
    }
    sink(data);
}
