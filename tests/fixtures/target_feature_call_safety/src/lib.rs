#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64"
))]
#[cfg_attr(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature(enable = "avx2")
)]
#[cfg_attr(target_arch = "aarch64", target_feature(enable = "sve"))]
/// # Safety
///
/// The caller must enable the target feature selected above.
pub fn target_feature_callee() {}

// Keep the fixture and its snapshot runnable on architectures without one of
// the target features above. Those hosts exercise the ordinary unsafe-call
// fallback; x86 and AArch64 exercise caller-relative target-feature safety.
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64"
)))]
/// # Safety
///
/// This fallback models the caller-relative target-feature requirement.
pub unsafe fn target_feature_callee() {}

pub fn ordinary_caller() {
    unsafe {
        target_feature_callee();
    }
}

#[cfg_attr(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature(enable = "avx2")
)]
#[cfg_attr(target_arch = "aarch64", target_feature(enable = "sve"))]
pub fn matching_feature_caller() {
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64"
    ))]
    // SAFETY: this caller enables the same target feature as the callee.
    target_feature_callee();
}
