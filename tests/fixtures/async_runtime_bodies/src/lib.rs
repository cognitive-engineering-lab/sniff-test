pub async fn async_root() {
    panic!("panic in the async runtime body");
}

pub async fn invoked_async_closure() {
    let captured = 7_u8;
    let invoked = async move || {
        let _captured = captured;
        panic!("panic in an invoked async closure");
    };
    invoked().await;
}

// These futures are constructed, but none of their bodies execute.
pub fn unpolled() {
    let _block = async { panic!("unused block"); };
    let _function = async_root();
    let closure = async || { panic!("unused closure result"); };
    let _result = closure();
}

pub fn poll_generic(cx: &mut std::task::Context<'_>) {
    fn drive<F: std::future::Future>(future: std::pin::Pin<&mut F>, cx: &mut std::task::Context<'_>) {
        let _ = future.poll(cx);
    }
    let mut future = std::pin::pin!(async_root());
    drive(future.as_mut(), cx);
}

pub fn poll_erased(cx: &mut std::task::Context<'_>) {
    let mut future = std::pin::pin!(async_root());
    let erased: std::pin::Pin<&mut dyn std::future::Future<Output = ()>> = future.as_mut();
    let _ = erased.poll(cx);
}

/// # Panics
/// The future always panics when polled.
async fn documented() {
    panic!("documented panic");
}

pub fn unpolled_documented() {
    let _future = documented();
}

pub async fn await_documented() {
    documented().await;
}

pub async fn generic_root<T>() {
    let _ = std::marker::PhantomData::<T>;
    async_root().await;
}

unsafe fn unsafe_operation() {}

pub fn unpolled_safety() {
    let _future = async { unsafe { unsafe_operation(); } };
}

pub async fn polled_safety() {
    async { unsafe { unsafe_operation(); } }.await;
}
