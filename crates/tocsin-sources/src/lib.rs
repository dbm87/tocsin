//! Fallback vulnerability sources (spec section 11): OSV.dev for advisories,
//! the CISA KEV catalog for known exploitation.
//!
//! Privacy: querying OSV.dev sends package names and versions. The KEV catalog
//! is downloaded whole, so nothing about the machine leaves it for that part.

pub mod cache;
pub mod kev;
pub mod osv;

use std::time::Duration;

/// HTTP client shared by the sources. The user agent names the tool only.
pub fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .user_agent(concat!("tocsin/", env!("CARGO_PKG_VERSION")))
        .build()
}
