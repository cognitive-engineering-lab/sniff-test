use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

use rustc_errors::{Diag, DiagCtxtHandle};
use rustc_middle::ty::TyCtxt;
use rustc_span::ErrorGuaranteed;

pub trait SniffTestDiagnostic: Debug {
    /// Build the [`Diag`] for a given error, but do not emit it.
    fn diag<'s, 'a: 's>(&'s self, dcx: DiagCtxtHandle<'a>) -> Diag<'_>;

    /// Build and emit the [`Diag`] for this [`ParsingError`].
    fn emit<'s, 'a: 's>(&'s self, dcx: DiagCtxtHandle<'a>) -> ErrorGuaranteed {
        self.diag(dcx).emit()
    }
}

pub trait MultiEmittable {
    type Emitted;
    fn emit_all_errors(self, tcx: TyCtxt) -> Self::Emitted;
}

impl<K: Eq + Hash + Debug, V: Debug, E: SniffTestDiagnostic> MultiEmittable
    for HashMap<K, Result<V, E>>
{
    type Emitted = Result<HashMap<K, V>, ErrorGuaranteed>;
    fn emit_all_errors(self, tcx: TyCtxt) -> Self::Emitted {
        let errs = self
            .values()
            .filter_map(|err| Some(err.as_ref().err()?.diag(tcx.dcx()).emit()))
            .collect::<Box<[_]>>();

        if let box [first, ..] = errs {
            // We have emitted errors, take the first one as a guarantee that they've been emitted
            Err(first)
        } else {
            // No errors to emit, go through everything and get the value
            Ok(self
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        v.expect("we already checked that none of there are errr"),
                    )
                })
                .collect::<HashMap<K, V>>())
        }
    }
}
