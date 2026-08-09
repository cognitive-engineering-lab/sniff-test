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
