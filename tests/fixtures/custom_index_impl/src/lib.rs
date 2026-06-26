use std::ops::Index;

pub fn custom_index_panics() {
    let foo = Foo;
    let _ = foo[10];
}

struct Foo;

impl Index<usize> for Foo {
    type Output = ();

    fn index(&self, _index: usize) -> &Self::Output {
        panic!("custom index impl")
    }
}
