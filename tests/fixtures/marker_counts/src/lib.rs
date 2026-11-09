pub fn source_match(first: usize, second: usize) -> (usize, usize) {
    // PANIC: first denominator is nonzero.
    // PANIC: second denominator is nonzero.
    (12 / first, 24 / second)
}

pub fn source_under(first: usize, second: usize) -> (usize, usize) {
    // PANIC: both denominators are nonzero.
    (12 / first, 24 / second)
}

pub fn source_over(first: usize, second: usize) -> (usize, usize) {
    // PANIC: checked.
    // PANIC: checked.
    // PANIC: checked.
    (12 / first, 24 / second)
}

pub fn override_sites(first: usize, second: usize) -> (usize, usize) {
    (12 / first, 24 / second)
}

/// # Panics
/// - first: first condition holds.
/// - second: second condition holds.
fn contract_a() {}

/// # Panics
/// - first: first condition holds.
/// - second: second condition holds.
fn contract_b() {}

pub fn source_bullets() {
    // PANIC:
    // - first: checked.
    // - second: checked.
    contract_a();
}

pub fn named_match() {
    // PANIC: second: both second conditions checked.
    // PANIC: first: both first conditions checked.
    (contract_a(), contract_b());
}

pub fn named_missing() {
    // PANIC: first: first condition checked.
    // PANIC: first: first condition also checked.
    (contract_a(), contract_b());
}

pub fn safety_group(left: &u8, right: &u8) -> (u8, u8) {
    let left = left as *const u8;
    let right = right as *const u8;
    // SAFETY: both pointers refer to live initialized bytes.
    unsafe { (*left, *right) }
}

pub fn safety_over(left: &u8, right: &u8) -> (u8, u8) {
    let left = left as *const u8;
    let right = right as *const u8;
    // SAFETY: left points to a live initialized byte.
    // SAFETY: right points to a live initialized byte.
    unsafe { (*left, *right) }
}

fn generic<T>(first: usize, second: usize, _tag: T) -> (usize, usize) {
    // PANIC: first denominator is nonzero.
    // PANIC: second denominator is nonzero.
    (12 / first, 24 / second)
}

pub fn generic_root(first: usize, second: usize) -> ((usize, usize), (usize, usize)) {
    (generic(first, second, 0_u8), generic(first, second, 0_u16))
}

macro_rules! divide_pair {
    ($first:expr, $second:expr) => {{
        // PANIC: first denominator is nonzero.
        // PANIC: second denominator is nonzero.
        (12 / $first, 24 / $second)
    }};
}

pub fn macro_root(first: usize, second: usize) -> ((usize, usize), (usize, usize)) {
    (divide_pair!(first, second), divide_pair!(first, second))
}

fn generic_contracts<T>(_tag: T) {
    // PANIC: first: both first conditions checked.
    // PANIC: second: both second conditions checked.
    (contract_a(), contract_b());
}

pub fn generic_contract_root() {
    generic_contracts(0_u8);
    generic_contracts(0_u16);
}
