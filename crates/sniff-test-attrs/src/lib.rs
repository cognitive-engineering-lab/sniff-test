#![feature(proc_macro_quote)]

use proc_macro::TokenStream;
use quote::quote;

macro_rules! define_sniff_tool_annotation {
    ($name: ident) => {
        #[proc_macro_attribute]
        pub fn $name(_attr: TokenStream, item: TokenStream) -> TokenStream {
            let mut t = TokenStream::new();

            // If we're registering the sniff-test tool, add the actual attribute to check unsafe.
            let rustflags = std::env::var("RUSTFLAGS")
                .map(|rust_flags| rust_flags.contains("-Zcrate-attr=register_tool(sniff_tool)"))
                .unwrap_or(false);
            if rustflags || std::env::var("PLUGIN_ARGS").is_ok()
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
