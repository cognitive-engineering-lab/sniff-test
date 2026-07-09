use std::path::PathBuf;

#[derive(Debug, Default)]
pub(crate) struct RustcInvocation {
    pub(crate) crate_types: Vec<String>,
    pub(crate) metadata: Option<String>,
    pub(crate) extra_filename: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) externs: Vec<ExternCrateArg>,
}

impl RustcInvocation {
    pub(crate) fn parse(args: &[String]) -> Self {
        let mut parsed = Self::default();
        let mut args = args.iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--crate-type" => {
                    if let Some(value) = args.next() {
                        parsed.crate_types.push(value.clone());
                    }
                }
                "--target" => {
                    if let Some(value) = args.next() {
                        parsed.target = Some(value.clone());
                    }
                }
                "--extern" => {
                    if let Some(value) = args.next()
                        && let Some(extern_arg) = ExternCrateArg::parse(value)
                    {
                        parsed.externs.push(extern_arg);
                    }
                }
                "--color" => {
                    args.next();
                }
                "-C" => {
                    if let Some(value) = args.next() {
                        parsed.parse_codegen_option(value);
                    }
                }
                _ => {
                    if let Some(value) = arg.strip_prefix("--crate-type=") {
                        parsed.crate_types.push(value.to_owned());
                    } else if let Some(value) = arg.strip_prefix("--target=") {
                        parsed.target = Some(value.to_owned());
                    } else if let Some(value) = arg.strip_prefix("--extern=") {
                        if let Some(extern_arg) = ExternCrateArg::parse(value) {
                            parsed.externs.push(extern_arg);
                        }
                    } else if let Some(value) = arg.strip_prefix("-C") {
                        parsed.parse_codegen_option(value);
                    }
                }
            }
        }

        parsed
    }

    fn parse_codegen_option(&mut self, value: &str) {
        if let Some(value) = value.strip_prefix("metadata=") {
            self.metadata = Some(value.to_owned());
        } else if let Some(value) = value.strip_prefix("extra-filename=") {
            self.extra_filename = Some(value.to_owned());
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExternCrateArg {
    pub(crate) name: String,
    pub(crate) path: Option<PathBuf>,
}

impl ExternCrateArg {
    fn parse(value: &str) -> Option<Self> {
        let (name, path) = match value.split_once('=') {
            Some((name, path)) => (name, (!path.is_empty()).then(|| PathBuf::from(path))),
            // Cargo passes pathless externs such as `--extern proc_macro`.
            None => (value, None),
        };
        // Cargo can glue modifiers onto the name, such as `noprelude:std`
        // under -Zbuild-std or `priv:` under -Zpublic-dependency.
        let name = name.rsplit_once(':').map_or(name, |(_, name)| name);
        (!name.is_empty()).then(|| Self {
            name: name.to_owned(),
            path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ExternCrateArg;

    #[test]
    fn extern_args_keep_pathless_externs_and_strip_modifiers() {
        let parsed = ExternCrateArg::parse("serde=/deps/libserde-1234.rmeta").expect("parses");
        assert_eq!(parsed.name, "serde");
        assert_eq!(
            parsed.path.as_deref(),
            Some("/deps/libserde-1234.rmeta".as_ref())
        );

        let pathless = ExternCrateArg::parse("proc_macro").expect("parses");
        assert_eq!(pathless.name, "proc_macro");
        assert_eq!(pathless.path, None);

        let modified =
            ExternCrateArg::parse("noprelude:std=/deps/libstd-1234.rmeta").expect("parses");
        assert_eq!(modified.name, "std");

        assert!(ExternCrateArg::parse("").is_none());
        assert!(ExternCrateArg::parse("=path-without-name").is_none());
    }
}
