use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn check_unsafe(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
