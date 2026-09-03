//! Trait-impl dispatch into trusted std namespaces: indexing must be treated
//! as the same trusted boundary as inherent methods on the same type.

pub fn get(values: &Vec<u8>, index: usize) -> u8 {
    // PANIC: callers accept that an out-of-bounds index panics.
    values[index]
}

pub fn put(values: &mut Vec<u8>, value: u8) {
    values.push(value);
}
