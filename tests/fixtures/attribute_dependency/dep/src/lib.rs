pub fn write(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::write(path, b"data")
}
