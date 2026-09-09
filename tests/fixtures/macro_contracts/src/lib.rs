pub fn plain_println() {
    println!("hello");
}

pub fn justified_println() {
    // PANIC: the caller accepts a stdout write failure.
    println!("hello");
}

pub fn empty_println() {
    println!();
}

fn helper() {
    std::hint::black_box(());
}

/// # Panics
///
/// Panics if the caller has not prepared the operation.
macro_rules! documented_call {
    () => {{
        helper();
        helper();
    }};
}

macro_rules! nested_call {
    () => {
        documented_call!();
    };
}

pub fn custom_macro() {
    documented_call!();
}

pub fn justified_custom_macro() {
    // PANIC: the caller prepared this operation.
    documented_call!();
}

pub fn direct_helper_has_no_macro_contract() {
    helper();
}

pub fn nested_macro() {
    nested_call!();
}

pub fn repeated_macro_sites() {
    documented_call!();
    documented_call!();
}

/// # Panics
///
/// Panics if the caller has not selected an available value.
macro_rules! documented_literal {
    () => {
        7_u8
    };
}

pub fn literal_macro() -> u8 {
    documented_literal!()
}

pub async fn async_literal_macro() -> u8 {
    documented_literal!()
}

/// # Safety
///
/// The caller must ensure the value is suitable for its intended use.
macro_rules! safety_literal {
    () => {
        11_u8
    };
}

pub fn safety_macro() -> u8 {
    safety_literal!()
}

pub fn justified_safety_macro() -> u8 {
    // SAFETY: this caller accepts the returned value.
    safety_literal!()
}

/// # Panics
///
/// Panics if the ignored operation is not prepared.
macro_rules! ignored_call {
    () => {
        helper();
    };
}

pub fn ignored_macro() {
    ignored_call!();
}
