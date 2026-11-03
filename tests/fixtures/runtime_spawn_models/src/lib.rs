#![allow(unexpected_cfgs)]
use tokio_alias as tokio;
use std::{future::Future, pin::Pin, task::{Context, Poll}};

async fn payload() { panic!("spawn payload"); }
async fn other_payload() { panic!("other payload"); }
/// # Panics
/// The submitted task fails.
async fn documented() { panic!("documented payload"); }
unsafe fn dangerous() {}

pub fn tokio_free() { drop(tokio::spawn(payload())); }
pub fn tokio_task() { drop(tokio::task::spawn(payload())); }
pub fn tokio_local() { drop(tokio::task::spawn_local(payload())); }
pub fn tokio_runtime(rt: &tokio::runtime::Runtime) { drop(rt.spawn(payload())); }
pub fn tokio_handle(h: &tokio::runtime::Handle) { drop(h.spawn(payload())); }
pub fn tokio_local_set(s: &tokio::task::LocalSet) { drop(s.spawn_local(payload())); }
pub fn tokio_join_set(s: &mut tokio::task::JoinSet<()>) { s.spawn(payload()); }
pub fn tokio_join_set_on(s: &mut tokio::task::JoinSet<()>, h: &tokio::runtime::Handle) { s.spawn_on(payload(), h); }
pub fn tokio_join_set_local(s: &mut tokio::task::JoinSet<()>) { s.spawn_local(payload()); }
pub fn tokio_join_set_local_on(s: &mut tokio::task::JoinSet<()>, l: &tokio::task::LocalSet) { s.spawn_local_on(payload(), l); }
pub fn smol_free() { drop(smol::spawn(payload())); }
pub fn smol_executor(e: &smol::Executor<'static>) { drop(e.spawn(payload())); }
pub fn smol_local_executor(e: &smol::LocalExecutor<'static>) { drop(e.spawn(payload())); }
pub fn smol_static(e: &'static async_executor::StaticExecutor) { drop(e.spawn(payload())); }
pub fn smol_static_local(e: &'static async_executor::StaticLocalExecutor) { drop(e.spawn(payload())); }
pub fn nested() { drop(tokio::spawn(async { drop(smol::spawn(payload())); })); }
fn submit<F: Future<Output = ()> + Send + 'static>(f: F) { drop(tokio::spawn(f)); }
pub fn generic_wrapper() { submit(payload()); }
pub fn own_contract() { drop(tokio::spawn(documented())); }
pub fn safety() { drop(tokio::spawn(async { unsafe { dangerous(); } })); }
pub fn unpolled() { drop(payload()); }
fn spawn<F: Future>(_: F) {}
pub fn unrelated() { spawn(payload()); }
pub fn separate() { drop(tokio::spawn(other_payload())); }
pub fn boxed_known() {
    let f: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(payload());
    drop(tokio::spawn(f));
}
pub fn boxed_unknown(f: Pin<Box<dyn Future<Output = ()> + Send>>) { drop(tokio::spawn(f)); }
pub fn boxed_mixed(f: Pin<Box<dyn Future<Output = ()> + Send>>, choose: bool) {
    let known: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(payload());
    drop(tokio::spawn(if choose { f } else { known }));
}
struct Custom;
impl Future for Custom {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> { panic!("custom poll"); }
}
pub fn custom_future() { drop(tokio::spawn(Custom)); }
pub fn concrete_boxed() { drop(tokio::spawn(Box::pin(payload()))); }

#[cfg(tokio_unstable)]
pub fn tokio_builder_spawn() { let _ = tokio::task::Builder::new().spawn(payload()); }
#[cfg(tokio_unstable)]
pub fn tokio_builder_spawn_on(h: &tokio::runtime::Handle) { let _ = tokio::task::Builder::new().spawn_on(payload(), h); }
#[cfg(tokio_unstable)]
pub fn tokio_builder_spawn_local() { let _ = tokio::task::Builder::new().spawn_local(payload()); }
#[cfg(tokio_unstable)]
pub fn tokio_builder_spawn_local_on(l: &tokio::task::LocalSet) { let _ = tokio::task::Builder::new().spawn_local_on(payload(), l); }
#[cfg(tokio_unstable)]
pub fn tokio_join_builder_spawn(s: &mut tokio::task::JoinSet<()>) { let _ = s.build_task().spawn(payload()); }
#[cfg(tokio_unstable)]
pub fn tokio_join_builder_spawn_on(s: &mut tokio::task::JoinSet<()>, h: &tokio::runtime::Handle) { let _ = s.build_task().spawn_on(payload(), h); }
#[cfg(tokio_unstable)]
pub fn tokio_join_builder_spawn_local(s: &mut tokio::task::JoinSet<()>) { let _ = s.build_task().spawn_local(payload()); }
#[cfg(tokio_unstable)]
pub fn tokio_join_builder_spawn_local_on(s: &mut tokio::task::JoinSet<()>, l: &tokio::task::LocalSet) { let _ = s.build_task().spawn_local_on(payload(), l); }
#[cfg(tokio_unstable)]
pub fn tokio_local_runtime(rt: &tokio::runtime::LocalRuntime) { drop(rt.spawn_local(payload())); }

pub fn justified() {
    let future = payload();
    // PANIC: Both the runtime context and the submitted task's failure are intentional.
    let task = tokio::spawn(future);
    drop(task);
}
pub fn unpolled_documented() { drop(documented()); }
pub fn boxed_separate() {
    let f: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(other_payload());
    drop(tokio::spawn(f));
}

pub fn boxed_forwarded() {
    let f: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(payload());
    submit(f);
}

pub fn two_tasks() {
    let first = tokio::spawn(payload());
    let second = tokio::spawn(other_payload());
    drop((first, second));
}

pub fn boxed_alternatives(choose: bool) {
    let future: Pin<Box<dyn Future<Output = ()> + Send>> = if choose {
        Box::pin(payload())
    } else {
        Box::pin(other_payload())
    };
    drop(tokio::spawn(future));
}

pub fn smol_safety() {
    drop(smol::spawn(async { unsafe { dangerous(); } }));
}

fn thread_payload() { panic!("thread payload"); }
fn other_thread_payload() { panic!("other thread payload"); }
/// # Panics
/// The thread payload fails.
fn documented_thread() { panic!("documented thread payload"); }

pub fn thread_free() { drop(std::thread::spawn(|| thread_payload())); }
pub fn thread_builder() { let _ = std::thread::Builder::new().spawn(|| thread_payload()); }
pub fn thread_scoped<'scope, 'env>(
    scope: &'scope std::thread::Scope<'scope, 'env>,
    borrowed: &'scope str,
) {
    scope.spawn(move || { let _ = borrowed.len(); thread_payload(); });
}
pub fn thread_builder_scoped<'scope, 'env>(
    scope: &'scope std::thread::Scope<'scope, 'env>,
    borrowed: &'scope str,
) {
    let _ = std::thread::Builder::new().spawn_scoped(scope, move || {
        let _ = borrowed.len();
        thread_payload();
    });
}
fn submit_thread<F: FnOnce() + Send + 'static>(f: F) { drop(std::thread::spawn(f)); }
pub fn thread_generic_wrapper() { submit_thread(|| thread_payload()); }
pub fn thread_unknown<F: FnOnce() + Send + 'static>(f: F) { drop(std::thread::spawn(f)); }
pub fn thread_function_item() { drop(std::thread::spawn(thread_payload)); }
pub fn thread_safety() { drop(std::thread::spawn(|| unsafe { dangerous(); })); }
pub fn thread_contract() { drop(std::thread::spawn(documented_thread)); }
pub fn thread_nested() {
    drop(std::thread::spawn(|| { drop(std::thread::spawn(thread_payload)); }));
}
pub fn thread_justified() {
    // PANIC: Thread creation and the payload's failure are intentional.
    let handle = std::thread::spawn(thread_payload);
    drop(handle);
}
fn ignore_closure<F: FnOnce()>(_: F) {}
pub fn thread_unsubmitted() { ignore_closure(|| thread_payload()); }
mod unrelated_thread_api {
    pub fn spawn<F: FnOnce()>(_: F) {}
}
pub fn thread_unrelated() { unrelated_thread_api::spawn(|| thread_payload()); }
pub fn two_threads() {
    let first = std::thread::spawn(thread_payload);
    let second = std::thread::spawn(other_thread_payload);
    drop((first, second));
}
