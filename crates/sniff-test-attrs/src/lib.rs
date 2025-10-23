#![feature(proc_macro_quote)]

use proc_macro::TokenStream;
use quote::quote;

const TOOL_ENV_VAR: &str = "USING_SNIFF_TOOL";

#[proc_macro]
pub fn tool_env_var(_item: TokenStream) -> TokenStream {
    format!("\"{TOOL_ENV_VAR}\"",).parse().unwrap()
}

#[proc_macro_attribute]
pub fn check_unsafe(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut t = TokenStream::new();

    // println!("expanding check unsafe!!");
    // let env_vars = ;

    // println!("vars are {env_vars:?}");

    if let Ok(rust_flags) = std::env::var("RUSTFLAGS") {
        if rust_flags.contains("-Zcrate-attr=register_tool(sniff_tool)") {
            t.extend(TokenStream::from(quote!(
                #[sniff_tool::check_unsafe]
            )));
        }
    }

    t.extend(item);
    t
}
