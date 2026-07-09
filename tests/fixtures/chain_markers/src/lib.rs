pub struct Widget(bool);

impl Widget {
    /// # Panics
    ///
    /// Panics when the inner flag is false.
    pub fn risky(&self) -> bool {
        assert!(self.0, "flag must be set");
        self.0
    }

    pub fn calm(&self) -> &Widget {
        self
    }
}

pub fn marker_on_chain_link(widget: &Widget) -> bool {
    widget
        .calm()
        // PANIC: the constructor guarantees the flag is set.
        .risky()
}

pub fn blanket_marker_above_chain(widget: &Widget) -> bool {
    // PANIC: a statement-level marker cannot single out one chain link.
    widget
        .calm()
        .risky()
}

pub fn marker_on_single_line(widget: &Widget) -> bool {
    // PANIC: the constructor guarantees the flag is set.
    widget.calm().risky()
}
