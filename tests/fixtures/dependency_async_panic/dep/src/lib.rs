pub async fn dependency_async_api<T>(_value: T) {
    private_async_helper().await;
}

async fn private_async_helper() {
    panic!("panic in a private cached dependency coroutine");
}
