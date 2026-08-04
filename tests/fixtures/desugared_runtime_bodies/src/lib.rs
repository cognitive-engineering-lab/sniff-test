#[derive(Debug)]
pub enum RootError {
    Missing,
    Byte(u8),
    Word(u16),
    Struct { code: u32 },
}

fn fallible(value: Option<u8>) -> Result<u8, RootError> {
    value.ok_or(RootError::Missing)
}

pub fn question_mark_root(value: Option<u8>) -> Result<u8, RootError> {
    let value = fallible(value)?;
    Ok(value)
}

pub fn derived_debug_root(error: &RootError) -> String {
    format!("{error:?}")
}
