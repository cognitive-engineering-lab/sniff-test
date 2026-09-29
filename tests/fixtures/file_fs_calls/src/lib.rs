#![feature(write_all_vectored)]

use std::io;
use std::io::Write;
use std::path::Path;

pub fn read(path: &Path) -> io::Result<String> {
    std::fs::read_to_string(path)
}

pub fn write(path: &Path, contents: &[u8]) -> io::Result<()> {
    std::fs::write(path, contents)
}

pub fn metadata(path: &Path) -> io::Result<std::fs::Metadata> {
    std::fs::metadata(path)
}

fn private_read(path: &Path) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

pub fn through_wrapper(path: &Path) -> io::Result<Vec<u8>> {
    private_read(path)
}

pub fn justified(path: &Path) -> io::Result<Vec<u8>> {
    // FILE: this path is an intended file input.
    std::fs::read(path)
}

/// # File
///
/// Reads the requested path from the file system.
pub fn documented(path: &Path) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

pub fn excluded_method(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

pub fn create(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::create(path)
}

pub fn create_new(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::create_new(path)
}

pub fn truncate(file: &std::fs::File) -> io::Result<()> {
    file.set_len(0)
}

pub fn delete(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)
}

pub fn write_all(file: &mut std::fs::File, contents: &[u8]) -> io::Result<()> {
    file.write_all(contents)
}

pub fn write_direct(file: &mut std::fs::File, contents: &[u8]) -> io::Result<usize> {
    file.write(contents)
}

pub fn write_shared(mut file: &std::fs::File, contents: &[u8]) -> io::Result<usize> {
    file.write(contents)
}

fn private_write(file: &mut std::fs::File, contents: &[u8]) -> io::Result<()> {
    file.write_all(contents)
}

pub fn through_write_wrapper(file: &mut std::fs::File, contents: &[u8]) -> io::Result<()> {
    private_write(file, contents)
}

pub fn write_vectored(file: &mut std::fs::File, contents: &[u8]) -> io::Result<usize> {
    file.write_vectored(&[io::IoSlice::new(contents)])
}

pub fn write_all_vectored(file: &mut std::fs::File, contents: &[u8]) -> io::Result<()> {
    file.write_all_vectored(&mut [io::IoSlice::new(contents)])
}

pub fn write_fmt(file: &mut std::fs::File) -> io::Result<()> {
    write!(file, "value: {}", 42)
}

pub fn write_to_vec(contents: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    output.write_all(contents)?;
    Ok(output)
}

/// # File
///
/// Writes the given bytes to a file.
pub fn documented_write(file: &mut std::fs::File, contents: &[u8]) -> io::Result<()> {
    file.write_all(contents)
}

pub fn justified_write(file: &mut std::fs::File, contents: &[u8]) -> io::Result<()> {
    // FILE: the caller selected this output file.
    file.write_all(contents)
}

pub fn justified_fs_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    // FILE: the caller selected this output file.
    std::fs::write(path, contents)
}
