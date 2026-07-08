//! Configuration value types and schema-driven validation (WS17-01.1/.4).

use alloc::string::String;

use crate::ConfigError;

/// A configuration value.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    /// Boolean.
    Bool(bool),
    /// Signed 64-bit integer.
    Int(i64),
    /// 64-bit float.
    Float(f64),
    /// UTF-8 string (also carries enum-typed values).
    Str(String),
}

impl ConfigValue {
    /// Human-readable type name of this value.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Str(_) => "string",
        }
    }

    /// Borrow as a `bool` if this value is one.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Borrow as an `i64` if this value is one.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Borrow as an `f64` if this value is one.
    #[must_use]
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(x) => Some(*x),
            _ => None,
        }
    }

    /// Borrow as a `&str` if this value is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// The type + constraints a key's value must satisfy (WS17-01.1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ValueType {
    /// Boolean.
    Bool,
    /// Integer constrained to the inclusive range `[min, max]`.
    Int {
        /// Inclusive minimum.
        min: i64,
        /// Inclusive maximum.
        max: i64,
    },
    /// Float constrained to the inclusive range `[min, max]`.
    Float {
        /// Inclusive minimum.
        min: f64,
        /// Inclusive maximum.
        max: f64,
    },
    /// String with a maximum byte length.
    Str {
        /// Maximum length in bytes.
        max_len: usize,
    },
    /// Enumeration: the value must be one of these string variants.
    Enum(&'static [&'static str]),
}

impl ValueType {
    /// Human-readable name of this type.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Int { .. } => "int",
            Self::Float { .. } => "float",
            Self::Str { .. } => "string",
            Self::Enum(_) => "enum",
        }
    }

    /// Validate `value` against this type and its range/length/variant
    /// constraints (WS17-01.4).
    ///
    /// # Errors
    ///
    /// - [`ConfigError::TypeMismatch`] if the value's kind does not match.
    /// - [`ConfigError::OutOfRange`] for an out-of-range numeric value.
    /// - [`ConfigError::TooLong`] for an over-length string.
    /// - [`ConfigError::NotAllowedValue`] for an enum value not in the set.
    pub fn validate(&self, value: &ConfigValue) -> Result<(), ConfigError> {
        let mismatch = || ConfigError::TypeMismatch {
            expected: self.type_name(),
            found: value.type_name(),
        };
        match *self {
            Self::Bool => {
                if value.as_bool().is_some() {
                    Ok(())
                } else {
                    Err(mismatch())
                }
            }
            Self::Int { min, max } => {
                let i = value.as_int().ok_or_else(mismatch)?;
                if (min..=max).contains(&i) {
                    Ok(())
                } else {
                    Err(ConfigError::OutOfRange)
                }
            }
            Self::Float { min, max } => {
                let x = value.as_float().ok_or_else(mismatch)?;
                if x >= min && x <= max {
                    Ok(())
                } else {
                    Err(ConfigError::OutOfRange)
                }
            }
            Self::Str { max_len } => {
                let s = value.as_str().ok_or_else(mismatch)?;
                if s.len() <= max_len {
                    Ok(())
                } else {
                    Err(ConfigError::TooLong)
                }
            }
            Self::Enum(variants) => {
                let s = value.as_str().ok_or_else(mismatch)?;
                if variants.contains(&s) {
                    Ok(())
                } else {
                    Err(ConfigError::NotAllowedValue)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn bool_validation() {
        assert!(ValueType::Bool.validate(&ConfigValue::Bool(true)).is_ok());
        assert_eq!(
            ValueType::Bool.validate(&ConfigValue::Int(1)),
            Err(ConfigError::TypeMismatch {
                expected: "bool",
                found: "int"
            })
        );
    }

    #[test]
    fn int_range_validation() {
        let ty = ValueType::Int { min: 0, max: 100 };
        assert!(ty.validate(&ConfigValue::Int(0)).is_ok());
        assert!(ty.validate(&ConfigValue::Int(100)).is_ok());
        assert_eq!(
            ty.validate(&ConfigValue::Int(101)),
            Err(ConfigError::OutOfRange)
        );
        assert_eq!(
            ty.validate(&ConfigValue::Int(-1)),
            Err(ConfigError::OutOfRange)
        );
        assert!(matches!(
            ty.validate(&ConfigValue::Bool(true)),
            Err(ConfigError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn float_range_validation() {
        let ty = ValueType::Float { min: 0.0, max: 1.0 };
        assert!(ty.validate(&ConfigValue::Float(0.5)).is_ok());
        assert!(ty.validate(&ConfigValue::Float(1.0)).is_ok());
        assert_eq!(
            ty.validate(&ConfigValue::Float(1.5)),
            Err(ConfigError::OutOfRange)
        );
    }

    #[test]
    fn string_length_validation() {
        let ty = ValueType::Str { max_len: 4 };
        assert!(ty.validate(&ConfigValue::Str("abcd".to_string())).is_ok());
        assert_eq!(
            ty.validate(&ConfigValue::Str("abcde".to_string())),
            Err(ConfigError::TooLong)
        );
    }

    #[test]
    fn enum_variant_validation() {
        let ty = ValueType::Enum(&["light", "dark", "auto"]);
        assert!(ty.validate(&ConfigValue::Str("dark".to_string())).is_ok());
        assert_eq!(
            ty.validate(&ConfigValue::Str("blue".to_string())),
            Err(ConfigError::NotAllowedValue)
        );
        assert!(matches!(
            ty.validate(&ConfigValue::Int(1)),
            Err(ConfigError::TypeMismatch { .. })
        ));
    }
}
