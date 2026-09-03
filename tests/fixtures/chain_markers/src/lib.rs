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

pub fn whole_statement_marker_is_ambiguous(widget: &Widget) -> bool {
    // PANIC: both calls appear in this statement, so the marker is ambiguous.
    let results = (widget.risky(), widget.risky());
    results.0 && results.1
}

#[rustfmt::skip]
pub fn unnamed_marker_applies_to_a_whole_multiline_call(widget: &Widget) -> bool {
    // PANIC: the constructor guarantees the flag is set.
    widget
        .calm()
        .risky()
}

#[rustfmt::skip]
pub fn tail_expression_marker_without_semicolon(widget: &Widget) -> bool {
    // PANIC: the constructor guarantees the flag is set.
    (
        widget.risky(),
        true,
    ).1
}

#[rustfmt::skip]
pub fn tail_expression_marker_with_semicolon(widget: &Widget) {
    // PANIC: the constructor guarantees the flag is set.
    (
        widget.risky(),
        true,
    );
}
