// TODO: this should actually pass, but I think we're doing monomorphization improperly. Gonna merge this and then work on that.

#[sniff_tool::check_panics]
fn main() {
    let foo = Foo;
    let a = foo[10];
    println!("{a:?}");
}

struct Foo;

impl std::ops::Index<usize> for Foo {
    type Output = ();
    fn index(&self, _index: usize) -> &Self::Output {
        panic!();
    }
}
