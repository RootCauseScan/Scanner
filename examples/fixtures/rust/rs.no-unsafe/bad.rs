unsafe fn dangerous() {
    println!("very unsafe");
}

fn main() {
    dangerous();
    unsafe {
        println!("danger");
    }
}
