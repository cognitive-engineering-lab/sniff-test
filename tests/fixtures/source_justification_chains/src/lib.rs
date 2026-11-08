pub struct Widget;

impl Widget {
    /// # Panics
    /// The first condition must hold.
    pub fn first(&self) -> &Self {
        self
    }

    /// # Panics
    /// The second condition must hold.
    pub fn second(&self) -> &Self {
        self
    }
}

#[rustfmt::skip]
pub fn chain(widget: &Widget) {
    widget
        .first()
        .second();
}

#[rustfmt::skip]
pub fn statement(widget: &Widget) {
    let _result = (
        widget.first(),
    );
}

#[rustfmt::skip]
pub fn source_link(widget: &Widget) {
    widget
        // PANIC: the first condition has been checked.
        .first()
        .second();
}

#[rustfmt::skip]
pub fn source_statement(widget: &Widget) {
    // PANIC: both conditions have been checked.
    let _value = widget
        .first()
        .second();
}

#[rustfmt::skip]
pub fn source_each_link(widget: &Widget) {
    widget
        // PANIC: the first condition has been checked.
        .first()
        // PANIC: the second condition has been checked.
        .second();
}
