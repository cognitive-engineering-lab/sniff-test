#![feature(proc_macro_quote)]

use proc_macro::TokenStream;
use quote::quote;

macro_rules! define_sniff_tool_annotation {
    ($name: ident) => {
        #[proc_macro_attribute]
        pub fn $name(_attr: TokenStream, item: TokenStream) -> TokenStream {
            let mut t = TokenStream::new();

            // If we're registering the sniff-test tool, add the actual attribute to check unsafe.
            if let Ok(rust_flags) = std::env::var("RUSTFLAGS")
                && rust_flags.contains("-Zcrate-attr=register_tool(sniff_tool)")
            {
                t.extend(TokenStream::from(quote!(
                    #[sniff_tool::$name]
                )));
            }

            t.extend(item);
            t
        }
    };
}

define_sniff_tool_annotation!(check_unsafe);
