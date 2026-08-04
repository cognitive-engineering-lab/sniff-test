pub async fn async_root() {
    panic!("panic in the async runtime body");
}

pub async fn generic_async_root<T>(_value: T) {
    panic!("panic in a generic async runtime body");
}

pub async fn nested_async_runtime_bodies() {
    async {
        panic!("panic in an awaited async block");
    }
    .await;

    let captured = 7_u8;
    let invoked = async move || {
        let _captured = captured;
        panic!("panic in an invoked async closure");
    };
    invoked().await;
}

pub fn unused_async_closure() {
    let _unused = async || panic!("an uncalled async closure must stay unreachable");
}
