//! Reference implementation of the formats defined by the Tocsin specification.
//!
//! * [`declaration`]: how a component declares its alert channel (spec section 5).
//! * [`advisory`]: OSV advisories with the `tocsin` extension (spec section 6).
//! * [`purl`]: the minimal Package URL handling needed to match advisories.
//! * [`priority`]: effective priority computation (spec section 9.2).
//! * [`policy`]: the administrator's reaction policy (spec section 9.3).

pub mod advisory;
pub mod cvss;
pub mod declaration;
pub mod policy;
pub mod priority;
pub mod purl;

/// Version of the Tocsin specification implemented by this crate.
pub const SPEC_VERSION: &str = "0.1";

pub use advisory::{Advisory, Mitigation, TocsinExtension};
pub use declaration::Declaration;
pub use policy::{Action, Decision, Exposure, Policy};
pub use priority::{Signals, Urgency, effective_priority};
pub use purl::Purl;
