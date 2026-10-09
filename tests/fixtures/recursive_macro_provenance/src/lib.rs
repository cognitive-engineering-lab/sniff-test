pub struct Input;
impl Input {
    pub fn checkpoint(&self) {}
    pub fn reset(&mut self, _: &()) {}
}
pub struct Error;
impl Error {
    pub fn is_backtrack(&self) -> bool {
        true
    }
    pub fn or(self, _: Self) -> Self {
        self
    }
    pub fn append(self, _: &mut Input, _: &()) -> Self {
        self
    }
}
pub trait Parser {
    fn parse_next(&mut self, input: &mut Input) -> Result<(), Error>;
}
pub trait Alt {
    fn choice(&mut self, input: &mut Input) -> Result<(), Error>;
}
macro_rules! succ {
    (1, $submac:ident ! ($($rest:tt)*)) => ($submac!(2, $($rest)*));
    (2, $submac:ident ! ($($rest:tt)*)) => ($submac!(3, $($rest)*));
}
macro_rules! alt_trait_inner {
    ($it:tt, $self:expr, $input:expr, $start:ident, $err:expr, $head:ident $($id:ident)+) => ({
        $input.reset(&$start);
        match $self.$it.parse_next($input) {
            Err(e) if e.is_backtrack() => {
                let err = $err.or(e);
                succ!($it, alt_trait_inner!($self, $input, $start, err, $($id)+))
            }
            res => res,
        }
    });
    ($it:tt, $self:expr, $input:expr, $start:ident, $err:expr, $head:ident) => ({
        Err($err.append($input, &$start))
    });
}
macro_rules! alt_trait_impl {
    ($($id:ident)+) => (
        impl<$($id: Parser),+> Alt for ($($id),+) {
            fn choice(&mut self, input: &mut Input) -> Result<(), Error> {
                let start = input.checkpoint();
                match self.0.parse_next(input) {
                    Err(e) if e.is_backtrack() => alt_trait_inner!(1, self, input, start, e, $($id)+),
                    res => res,
                }
            }
        }
    );
}
alt_trait_impl!(A B C);

fn leaf() {
    std::hint::black_box(());
}

macro_rules! self_recursive_call {
    () => { leaf() };
    ($head:tt $($rest:tt)*) => { self_recursive_call!($($rest)*) };
}

pub fn directly_recursive_call() {
    self_recursive_call!(a b c)
}

macro_rules! self_recursive_operation {
    ($pointer:expr;) => { unsafe { *$pointer } };
    ($pointer:expr; $head:tt $($rest:tt)*) => {
        self_recursive_operation!($pointer; $($rest)*)
    };
}

pub fn directly_recursive_operation(pointer: *const u8) -> u8 {
    self_recursive_operation!(pointer; a b c)
}
