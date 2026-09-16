//! Trusted dependency library for the untrusted higher-order fixture.

/// # Panics
/// This function will panic if `closure` panics.
pub fn consume_maybe_untrusted_closure(closure: impl Fn()) {
    closure();
}

pub trait BlanketFromUntrustedParty  {
    fn maybe_untrusted_impl(&self);
    /// # Panics
    /// This method might panic if
    fn boom(&self) {
        self.maybe_untrusted_impl();
    }
}
/// # Panics
/// Panics if the callback panics.
pub fn consume_documented_closure(closure: impl Fn()) {
    closure();
}

pub trait DocumentedBlanket {
    fn maybe_untrusted_impl(&self);

    /// # Panics
    /// Panics if the implementer's method panics.
    fn boom(&self) {
        self.maybe_untrusted_impl();
    }
}
