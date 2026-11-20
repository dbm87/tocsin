//! Minimal Package URL (purl) parsing.
//!
//! Only what advisory matching needs: type, namespace, name and version.
//! Qualifiers and subpath are accepted and ignored.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Purl {
    pub ty: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PurlError {
    #[error("a purl must start with `pkg:`")]
    MissingScheme,
    #[error("a purl must contain a type and a name, e.g. `pkg:npm/lodash`")]
    MissingTypeOrName,
}

impl Purl {
    /// True when both purls designate the same package, whatever the version.
    pub fn same_package(&self, other: &Purl) -> bool {
        self.ty == other.ty && self.namespace == other.namespace && self.name == other.name
    }
}

fn decode(segment: &str) -> String {
    // Enough for the common case of npm scopes (`%40scope`); full
    // percent-decoding will come with a dedicated purl dependency.
    segment
        .replace("%40", "@")
        .replace("%2F", "/")
        .replace("%2f", "/")
}

impl FromStr for Purl {
    type Err = PurlError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let rest = input
            .get(..4)
            .filter(|scheme| scheme.eq_ignore_ascii_case("pkg:"))
            .map(|_| &input[4..])
            .ok_or(PurlError::MissingScheme)?;
        let rest = rest.trim_start_matches('/');
        let rest = rest.split('#').next().unwrap_or_default();
        let rest = rest.split('?').next().unwrap_or_default();

        // The version follows the last `@`, unless that `@` belongs to a path
        // segment (e.g. an unencoded npm scope such as `@scope/name`).
        let (path, version) = match rest.rsplit_once('@') {
            Some((path, version))
                if !version.contains('/') && !path.is_empty() && !path.ends_with('/') =>
            {
                (path, Some(decode(version)))
            }
            _ => (rest, None),
        };

        let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 2 {
            return Err(PurlError::MissingTypeOrName);
        }
        let ty = segments.remove(0).to_ascii_lowercase();
        let name = decode(segments.pop().ok_or(PurlError::MissingTypeOrName)?);
        let namespace = (!segments.is_empty()).then(|| decode(&segments.join("/")));

        Ok(Purl {
            ty,
            namespace,
            name,
            version,
        })
    }
}

impl fmt::Display for Purl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pkg:{}/", self.ty)?;
        if let Some(namespace) = &self.namespace {
            write!(f, "{}/", namespace.replace('@', "%40"))?;
        }
        write!(f, "{}", self.name)?;
        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_purl() {
        let p: Purl = "pkg:npm/lodash@4.17.20".parse().unwrap();
        assert_eq!(p.ty, "npm");
        assert_eq!(p.namespace, None);
        assert_eq!(p.name, "lodash");
        assert_eq!(p.version.as_deref(), Some("4.17.20"));
    }

    #[test]
    fn parses_namespace_qualifiers_and_subpath() {
        let p: Purl = "pkg:deb/debian/openssl@3.0.11-1?arch=amd64#usr/lib"
            .parse()
            .unwrap();
        assert_eq!(p.namespace.as_deref(), Some("debian"));
        assert_eq!(p.name, "openssl");
        assert_eq!(p.version.as_deref(), Some("3.0.11-1"));
    }

    #[test]
    fn handles_npm_scopes_encoded_or_not() {
        let encoded: Purl = "pkg:npm/%40angular/core@17.0.0".parse().unwrap();
        let raw: Purl = "pkg:npm/@angular/core@17.0.0".parse().unwrap();
        assert_eq!(encoded, raw);
        assert_eq!(raw.namespace.as_deref(), Some("@angular"));
        let no_version: Purl = "pkg:npm/@angular/core".parse().unwrap();
        assert_eq!(no_version.version, None);
        assert_eq!(no_version.name, "core");
    }

    #[test]
    fn same_package_ignores_version() {
        let a: Purl = "pkg:npm/example-widget@2.3.1".parse().unwrap();
        let b: Purl = "pkg:npm/example-widget".parse().unwrap();
        assert!(a.same_package(&b));
    }

    #[test]
    fn rejects_invalid_input() {
        assert_eq!("npm/lodash".parse::<Purl>(), Err(PurlError::MissingScheme));
        assert_eq!("pkg:npm".parse::<Purl>(), Err(PurlError::MissingTypeOrName));
    }
}
