#![cfg_attr(sniff_test, feature(register_tool), register_tool(sniff_test))]

#[cfg_attr(sniff_test, deny(sniff_test::file))]
pub fn write_through_dependency(path: &std::path::Path) -> std::io::Result<()> {
    attribute_dependency::write(path)
}
