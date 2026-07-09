use dependency_identity::{Sniffer, Widget};

pub fn sniff_widget(flag: bool) {
    Widget.sniff(flag);
}

pub fn sniff_buffer(buffer: &Vec<u8>, flag: bool) {
    buffer.sniff(flag);
}

pub fn run_reexported(flag: bool) {
    dependency_identity::run(flag);
}

pub fn sniff_dyn(flag: bool) {
    let sniffer: &dyn Sniffer = &Widget;
    sniffer.sniff(flag);
}
