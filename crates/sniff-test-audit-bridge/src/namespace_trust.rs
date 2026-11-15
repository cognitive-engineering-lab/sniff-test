//! Shared configuration editing for effect-specific namespace trust.
use super::*;

pub(super) fn read_config(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn namespace_patterns(
    config: &toml_edit::Document,
    effect: &str,
    setting: &str,
    defaults: &[String],
) -> Result<Vec<String>> {
    let Some(table) = config.get(effect) else {
        return Ok(defaults.to_vec());
    };
    ensure!(
        table.as_table_like().is_some(),
        "effect configuration must be a table"
    );
    let Some(value) = table.get(setting) else {
        return Ok(defaults.to_vec());
    };
    value
        .as_array()
        .with_context(|| format!("{setting} must be an array"))?
        .iter()
        .map(|p| {
            p.as_str()
                .map(str::to_owned)
                .with_context(|| format!("invalid {setting} entry"))
        })
        .collect()
}

pub(super) fn namespace_matches(patterns: &[String], namespace: &str) -> Result<bool> {
    let mut builder = globset::GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            globset::GlobBuilder::new(&pattern.replace("::", "/"))
                .literal_separator(true)
                .build()?,
        );
        if let Some(root) = pattern.strip_suffix("::**") {
            builder.add(
                globset::GlobBuilder::new(&root.replace("::", "/"))
                    .literal_separator(true)
                    .build()?,
            );
        }
    }
    Ok(builder.build()?.is_match(namespace.replace("::", "/")))
}

pub(super) fn edit_namespace(
    config: &mut toml_edit::Document,
    effect: &str,
    setting: &str,
    defaults: &[String],
    pattern: &str,
    trusted: bool,
) -> Result<()> {
    let existing = namespace_patterns(config, effect, setting, defaults)?;
    // Validate existing glob syntax before changing the document.
    namespace_matches(&existing, "")?;
    if config.get(effect).is_none() {
        config[effect] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    if config[effect].get(setting).is_none() {
        let mut array = toml_edit::Array::new();
        for value in existing {
            array.push(value);
        }
        config[effect][setting] = toml_edit::value(array);
    }
    let patterns = config[effect][setting].as_array_mut().unwrap();
    let exact = patterns.iter().any(|p| p.as_str() == Some(pattern));
    if trusted {
        if !exact {
            patterns.push(pattern);
        }
    } else {
        ensure!(exact, "no exact trust entry exists; refresh the selection");
        for index in (0..patterns.len()).rev() {
            if patterns.get(index).and_then(toml_edit::Value::as_str) == Some(pattern) {
                patterns.remove(index);
            }
        }
    }
    Ok(())
}

impl Session {
    pub(super) fn save_trust_config(
        &mut self,
        manifest: &Path,
        original: Option<String>,
        config: toml_edit::Document,
    ) -> Result<()> {
        let content = config.to_string();
        content.parse::<toml::Value>()?;
        ensure!(
            read_config(manifest)? == original,
            "configuration changed; select it again"
        );
        atomic_write(manifest, content.as_bytes())?;
        self.analysis.override_revision += 1;
        self.analysis.overrides_changed = true;
        self.analysis.stale = true;
        Ok(())
    }
}
