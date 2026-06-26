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
        let (name, path) = value.split_once('=')?;
        Some(Self {
            name: name.to_owned(),
            path: (!path.is_empty()).then(|| PathBuf::from(path)),
        })
    }
}
