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

pub fn marked_and_unmarked_chain_links(widget: &Widget) -> bool {
    let marked = widget
        .calm()
        // PANIC: the constructor guarantees the flag is set.
        .risky();
    let unmarked = widget.calm().risky();
    marked && unmarked
}
