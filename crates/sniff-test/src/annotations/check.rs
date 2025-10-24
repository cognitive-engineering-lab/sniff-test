use rustc_span::source_map::Spanned;

use crate::annotations::{Justification, Requirement, types::ConditionName};

pub struct ConsistencyIssue<'r> {
    missing_cond: &'r Spanned<Requirement>,
}

pub fn check_consistency<'r>(
    justifications: &[Spanned<Justification>],
    for_requirements: &'r [Spanned<Requirement>],
) -> Result<(), ConsistencyIssue<'r>> {
    // println!("does {justifications:?} satisfy {for_requirements:?}??");
    for req in for_requirements {
        let sat = justifications
            .iter()
            .any(|just| just.node.name().as_str() == req.node.name().as_str());
        if !sat {
            return Err(ConsistencyIssue { missing_cond: req });
        }
    }

    Ok(())
}

mod error {
    use rustc_errors::{Diag, DiagCtxtHandle};

    use crate::annotations::check::ConsistencyIssue;

    impl ConsistencyIssue<'_> {
        pub fn diag<'tcx>(&self, dcx: DiagCtxtHandle<'tcx>) -> Diag<'tcx> {
            dcx.struct_span_err(
                self.missing_cond.span,
                format!(
                    "no justification for requirement {}",
                    self.missing_cond.node.name().as_str()
                ),
            )
        }
    }
}
