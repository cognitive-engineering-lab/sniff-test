#![feature(proc_macro_quote)]

use proc_macro::TokenStream;
use quote::quote;

#[proc_macro_attribute]
pub fn check_unsafe(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = quote!(
        #[sniff_tool::check_unsafe]
    );
    let mut t = TokenStream::new();
    t.extend(TokenStream::from(attrs));
    t.extend(item);
    t
}
