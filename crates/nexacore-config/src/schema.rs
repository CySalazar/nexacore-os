//! Per-key schema and the schema registry (WS17-01.1).

use alloc::collections::BTreeMap;

use crate::{
    ConfigError, Key,
    value::{ConfigValue, ValueType},
};

/// The schema for a single configuration key (WS17-01.1): its type + range,
/// its default value, and a human description.
#[derive(Debug, Clone)]
pub struct KeySchema {
    /// The value type and its constraints.
    pub ty: ValueType,
    /// The default value (used when neither a user override nor a system value
    /// is set). Validated against `ty` at registration.
    pub default: ConfigValue,
    /// Human-readable description of what the key controls.
    pub description: &'static str,
}

impl KeySchema {
    /// Construct a schema, validating that `default` satisfies `ty`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::DefaultInvalid`] if the default does not satisfy the
    /// type/range (so a registry can never hand out an invalid default).
    pub fn new(
        ty: ValueType,
        default: ConfigValue,
        description: &'static str,
    ) -> Result<Self, ConfigError> {
        if ty.validate(&default).is_err() {
            return Err(ConfigError::DefaultInvalid);
        }
        Ok(Self {
            ty,
            default,
            description,
        })
    }
}

/// The registry of key schemas (WS17-01.1). Maps each [`Key`] to its
/// [`KeySchema`]; the store validates every write against this registry.
#[derive(Debug, Clone, Default)]
pub struct SchemaRegistry {
    entries: BTreeMap<Key, KeySchema>,
}

impl SchemaRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Register (or replace) the schema for `key`. The default is validated by
    /// [`KeySchema::new`] before the schema reaches here.
    pub fn register(&mut self, key: Key, schema: KeySchema) {
        self.entries.insert(key, schema);
    }

    /// Look up the schema for `key`.
    #[must_use]
    pub fn get(&self, key: &Key) -> Option<&KeySchema> {
        self.entries.get(key)
    }

    /// Whether a schema is registered for `key`.
    #[must_use]
    pub fn contains(&self, key: &Key) -> bool {
        self.entries.contains_key(key)
    }

    /// Iterate over all registered keys.
    pub fn keys(&self) -> impl Iterator<Item = &Key> {
        self.entries.keys()
    }

    /// Number of registered keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn schema_rejects_invalid_default() {
        // Default 5 is outside [0, 3].
        let r = KeySchema::new(ValueType::Int { min: 0, max: 3 }, ConfigValue::Int(5), "x");
        assert_eq!(r.unwrap_err(), ConfigError::DefaultInvalid);
    }

    #[test]
    fn schema_accepts_valid_default() {
        let s = KeySchema::new(
            ValueType::Enum(&["light", "dark"]),
            ConfigValue::Str("dark".to_string()),
            "theme mode",
        );
        assert!(s.is_ok());
    }

    #[test]
    fn registry_register_and_get() {
        let mut reg = SchemaRegistry::new();
        let key = Key::new("desktop.theme.mode").unwrap();
        let schema = KeySchema::new(
            ValueType::Enum(&["light", "dark", "auto"]),
            ConfigValue::Str("auto".to_string()),
            "theme mode",
        )
        .unwrap();
        reg.register(key.clone(), schema);
        assert!(reg.contains(&key));
        assert_eq!(reg.len(), 1);
        assert_eq!(
            reg.get(&key).unwrap().default,
            ConfigValue::Str("auto".to_string())
        );
    }
}
