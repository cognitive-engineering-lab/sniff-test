use dependency_identity::Sniffer;

pub fn sniff_buffer(buffer: &Vec<u8>, flag: bool) {
    buffer.sniff(flag);
}
