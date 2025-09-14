mod outer {
    pub mod inner {
        pub fn local() {}

        pub fn wrapper() {
            local();
            super::shared();
        }
    }

    pub fn shared() {}
}

fn main() {
    outer::inner::wrapper();
}
