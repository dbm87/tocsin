//! Version comparison per OSV ecosystem, needed to evaluate `ECOSYSTEM`
//! ranges locally (offline mode) instead of asking OSV.dev.
//!
//! * Debian and Ubuntu: the dpkg algorithm (`epoch:upstream-revision`, `~`
//!   sorting before everything).
//! * RPM distributions: the `rpmvercmp` algorithm with an optional epoch
//!   (`~` sorting before, `^` after).
//! * PyPI: PEP 440, without local version labels ordering subtleties.
//! * npm, crates.io and other semver ecosystems: Semantic Versioning.

use std::cmp::Ordering;

/// How versions of an ecosystem are ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Dpkg,
    Rpm,
    Pep440,
    Semver,
}

impl Scheme {
    /// The scheme of an OSV ecosystem name such as `Ubuntu:24.04:LTS`,
    /// `Rocky Linux:9` or `npm`. `None` when this agent cannot order its versions.
    pub fn for_ecosystem(ecosystem: &str) -> Option<Scheme> {
        let base = ecosystem.split(':').next().unwrap_or(ecosystem);
        Some(match base {
            "Debian" | "Ubuntu" => Scheme::Dpkg,
            "AlmaLinux" | "Rocky Linux" | "Red Hat" | "openSUSE" | "SUSE" | "Mageia"
            | "openEuler" | "Azure Linux" => Scheme::Rpm,
            "PyPI" => Scheme::Pep440,
            "npm" | "crates.io" | "Hex" | "Pub" | "SwiftURL" => Scheme::Semver,
            _ => return None,
        })
    }

    /// Compares two versions; `None` when one of them is not valid in this scheme.
    pub fn compare(self, a: &str, b: &str) -> Option<Ordering> {
        match self {
            Scheme::Dpkg => Some(dpkg_compare(a, b)),
            Scheme::Rpm => Some(rpm_compare(a, b)),
            Scheme::Pep440 => Some(Pep440::parse(a)?.cmp(&Pep440::parse(b)?)),
            Scheme::Semver => Some(parse_semver(a)?.cmp(&parse_semver(b)?)),
        }
    }
}

fn parse_semver(raw: &str) -> Option<semver::Version> {
    semver::Version::parse(raw.trim().trim_start_matches('v')).ok()
}

/// Splits an optional leading `epoch:`; a missing or invalid epoch is 0.
fn split_epoch(version: &str) -> (u64, &str) {
    match version.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            (epoch.parse().unwrap_or(u64::MAX), rest)
        }
        _ => (0, version),
    }
}

/// Compares two runs of digits without overflowing: leading zeros are
/// ignored, then the longer run is larger.
fn compare_digits(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

// ---------------------------------------------------------------------------
// dpkg

/// Compares Debian package versions as `dpkg --compare-versions` does.
pub fn dpkg_compare(a: &str, b: &str) -> Ordering {
    let (epoch_a, rest_a) = split_epoch(a.trim());
    let (epoch_b, rest_b) = split_epoch(b.trim());
    let split = |v: &'_ str| -> (String, String) {
        match v.rsplit_once('-') {
            Some((upstream, revision)) => (upstream.to_owned(), revision.to_owned()),
            None => (v.to_owned(), String::new()),
        }
    };
    let (upstream_a, revision_a) = split(rest_a);
    let (upstream_b, revision_b) = split(rest_b);
    epoch_a
        .cmp(&epoch_b)
        .then_with(|| verrevcmp(&upstream_a, &upstream_b))
        .then_with(|| verrevcmp(&revision_a, &revision_b))
}

/// Weight of a non-digit character in dpkg ordering: `~` first, then the
/// end of the string, then letters, then other characters.
fn dpkg_order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        // Non-digit prefix, character by character.
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ca = dpkg_order(a.get(i).copied().filter(|c| !c.is_ascii_digit()));
            let cb = dpkg_order(b.get(j).copied().filter(|c| !c.is_ascii_digit()));
            if ca != cb {
                return ca.cmp(&cb);
            }
            if i < a.len() && !a[i].is_ascii_digit() {
                i += 1;
            }
            if j < b.len() && !b[j].is_ascii_digit() {
                j += 1;
            }
        }
        // Numeric part.
        let start_a = i;
        while i < a.len() && a[i].is_ascii_digit() {
            i += 1;
        }
        let start_b = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        // Digits are ASCII, so these slices are valid UTF-8.
        let da = std::str::from_utf8(&a[start_a..i]).unwrap_or("");
        let db = std::str::from_utf8(&b[start_b..j]).unwrap_or("");
        let ordering = compare_digits(da, db);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

// ---------------------------------------------------------------------------
// RPM

/// Compares RPM `[epoch:]version[-release]` strings as rpm does.
pub fn rpm_compare(a: &str, b: &str) -> Ordering {
    let (epoch_a, rest_a) = split_epoch(a.trim());
    let (epoch_b, rest_b) = split_epoch(b.trim());
    let split = |v: &'_ str| -> (String, Option<String>) {
        match v.rsplit_once('-') {
            Some((version, release)) => (version.to_owned(), Some(release.to_owned())),
            None => (v.to_owned(), None),
        }
    };
    let (version_a, release_a) = split(rest_a);
    let (version_b, release_b) = split(rest_b);
    epoch_a
        .cmp(&epoch_b)
        .then_with(|| rpmvercmp(&version_a, &version_b))
        .then_with(|| match (release_a, release_b) {
            (Some(ra), Some(rb)) => rpmvercmp(&ra, &rb),
            // A missing release matches any release, as in rpm.
            _ => Ordering::Equal,
        })
}

fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    let separator = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    loop {
        while i < a.len() && separator(a[i]) {
            i += 1;
        }
        while j < b.len() && separator(b[j]) {
            j += 1;
        }
        // Tilde sorts before everything, even the end of the string.
        let tilde_a = a.get(i) == Some(&b'~');
        let tilde_b = b.get(j) == Some(&b'~');
        if tilde_a || tilde_b {
            if !(tilde_a && tilde_b) {
                return if tilde_a {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
            i += 1;
            j += 1;
            continue;
        }
        // Caret sorts after the end of the string, but before anything else.
        let caret_a = a.get(i) == Some(&b'^');
        let caret_b = b.get(j) == Some(&b'^');
        if caret_a || caret_b {
            if i >= a.len() {
                return Ordering::Less;
            }
            if j >= b.len() {
                return Ordering::Greater;
            }
            if !(caret_a && caret_b) {
                return if caret_a {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
            i += 1;
            j += 1;
            continue;
        }
        if i >= a.len() || j >= b.len() {
            break;
        }
        let numeric = a[i].is_ascii_digit();
        let take = |s: &[u8], mut k: usize| {
            let start = k;
            while k < s.len()
                && if numeric {
                    s[k].is_ascii_digit()
                } else {
                    s[k].is_ascii_alphabetic()
                }
            {
                k += 1;
            }
            (start, k)
        };
        let (sa, ea) = take(a, i);
        let (sb, eb) = take(b, j);
        if sb == eb {
            // Segments of different kinds: a numeric one is newer.
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let seg_a = std::str::from_utf8(&a[sa..ea]).unwrap_or("");
        let seg_b = std::str::from_utf8(&b[sb..eb]).unwrap_or("");
        let ordering = if numeric {
            compare_digits(seg_a, seg_b)
        } else {
            seg_a.cmp(seg_b)
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
        i = ea;
        j = eb;
    }
    // The one with segments left is newer.
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

// ---------------------------------------------------------------------------
// PEP 440

/// A parsed PEP 440 version. Ordering follows the specification: dev
/// releases before pre-releases before the release before post-releases.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pep440 {
    epoch: u64,
    release: Vec<u64>,
    /// (phase 0 = a, 1 = b, 2 = rc, number)
    pre: Option<(u8, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
}

impl Pep440 {
    fn parse(raw: &str) -> Option<Pep440> {
        let mut s = raw.trim().to_ascii_lowercase();
        if let Some(stripped) = s.strip_prefix('v') {
            s = stripped.to_owned();
        }
        // Local version labels (`+ubuntu1`) are ignored.
        if let Some((public, _)) = s.split_once('+') {
            s = public.to_owned();
        }
        let (epoch, rest) = match s.split_once('!') {
            Some((e, r)) => (e.parse().ok()?, r.to_owned()),
            None => (0, s),
        };
        let bytes = rest.as_bytes();
        let mut k = 0;
        let number = |k: &mut usize| -> Option<u64> {
            let start = *k;
            while *k < bytes.len() && bytes[*k].is_ascii_digit() {
                *k += 1;
            }
            if start == *k {
                return None;
            }
            rest[start..*k].parse().ok()
        };
        let mut release = vec![number(&mut k)?];
        while k + 1 < bytes.len() && bytes[k] == b'.' && bytes[k + 1].is_ascii_digit() {
            k += 1;
            release.push(number(&mut k)?);
        }
        let skip_sep = |k: &mut usize| {
            if *k < bytes.len() && b"._-".contains(&bytes[*k]) {
                *k += 1;
            }
        };
        let starts = |k: usize, word: &str| rest[k..].starts_with(word);
        let mut version = Pep440 {
            epoch,
            release,
            pre: None,
            post: None,
            dev: None,
        };
        let mut save = k;
        skip_sep(&mut k);
        let phases: [(&str, u8); 8] = [
            ("alpha", 0),
            ("beta", 1),
            ("preview", 2),
            ("pre", 2),
            ("rc", 2),
            ("a", 0),
            ("b", 1),
            ("c", 2),
        ];
        if let Some((word, phase)) = phases.iter().find(|(w, _)| starts(k, w)) {
            k += word.len();
            skip_sep(&mut k);
            version.pre = Some((*phase, number(&mut k).unwrap_or(0)));
            save = k;
        } else {
            k = save;
        }
        skip_sep(&mut k);
        if let Some(word) = ["post", "rev", "r"].iter().find(|w| starts(k, w)) {
            k += word.len();
            skip_sep(&mut k);
            version.post = Some(number(&mut k).unwrap_or(0));
            save = k;
        } else if k > save && k < bytes.len() && bytes[k].is_ascii_digit() && bytes[k - 1] == b'-' {
            // `1.0-1` is an implicit post-release.
            version.post = Some(number(&mut k)?);
            save = k;
        } else {
            k = save;
        }
        skip_sep(&mut k);
        if starts(k, "dev") {
            k += 3;
            skip_sep(&mut k);
            version.dev = Some(number(&mut k).unwrap_or(0));
        } else {
            k = save;
        }
        (k == bytes.len()).then_some(version)
    }

    /// Sort key of the pre/post/dev suffixes.
    fn suffix_key(&self) -> (i8, u64, i8, u64, i8, u64) {
        // A dev release without pre or post sorts before any pre-release.
        let (pre_phase, pre_number) = match (self.pre, self.post, self.dev) {
            (Some((phase, n)), _, _) => (phase as i8, n),
            (None, None, Some(_)) => (-1, 0),
            _ => (i8::MAX, 0),
        };
        let (post_flag, post_number) = match self.post {
            Some(n) => (1, n),
            None => (0, 0),
        };
        let (dev_flag, dev_number) = match self.dev {
            Some(n) => (0, n),
            None => (1, 0),
        };
        (
            pre_phase,
            pre_number,
            post_flag,
            post_number,
            dev_flag,
            dev_number,
        )
    }
}

impl Ord for Pep440 {
    fn cmp(&self, other: &Self) -> Ordering {
        let len = self.release.len().max(other.release.len());
        let padded = |r: &[u64]| {
            let mut v = r.to_vec();
            v.resize(len, 0);
            v
        };
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| padded(&self.release).cmp(&padded(&other.release)))
            .then_with(|| self.suffix_key().cmp(&other.suffix_key()))
    }
}

impl PartialOrd for Pep440 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::{Equal, Greater, Less};

    #[test]
    fn dpkg_ordering() {
        for (a, b, expected) in [
            ("1.0", "1.0", Equal),
            ("1.0-1", "1.0-2", Less),
            ("2.35-0ubuntu3.1", "2.35-0ubuntu3.4", Less),
            ("2.35-0ubuntu3.10", "2.35-0ubuntu3.4", Greater),
            ("1:1.0", "2.0", Greater),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1-1", "1.0-1", Less),
            ("1.0", "1.0a", Less),
            ("1.0a", "1.0+", Less),
            ("3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3", Greater),
            ("1.2.3", "1.2.3-0", Equal),
            ("0", "0.1", Less),
            ("1.0.0+dfsg-1", "1.0.0-1", Greater),
            ("99999999999999999999999", "1", Greater),
        ] {
            assert_eq!(dpkg_compare(a, b), expected, "{a} vs {b}");
            assert_eq!(dpkg_compare(b, a), expected.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn rpm_ordering() {
        for (a, b, expected) in [
            ("1.0-1.el9", "1.0-1.el9", Equal),
            ("1.0-1.el9", "1.0-2.el9", Less),
            ("1.0-1.el9_2", "1.0-1.el9", Greater),
            ("1:1.0-1", "2.0-1", Greater),
            ("1.0~rc1-1", "1.0-1", Less),
            ("1.0^git1-1", "1.0-1", Greater),
            ("1.0^git1-1", "1.0.1-1", Less),
            ("1.0a-1", "1.0-1", Greater),
            ("1.0a-1", "1.01-1", Less),
            ("2.34-60.el9", "2.34-100.el9", Less),
            ("1.0", "1.0-5", Equal),
            ("0:1.0-1", "1.0-1", Equal),
        ] {
            assert_eq!(rpm_compare(a, b), expected, "{a} vs {b}");
            assert_eq!(rpm_compare(b, a), expected.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn pep440_ordering() {
        let ordered = [
            "1.0.dev1",
            "1.0a1",
            "1.0a2.dev1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0.post1",
            "1.0.1",
            "1.1",
            "2!0.1",
        ];
        for pair in ordered.windows(2) {
            assert_eq!(
                Scheme::Pep440.compare(pair[0], pair[1]),
                Some(Less),
                "{pair:?}"
            );
        }
        assert_eq!(Scheme::Pep440.compare("1.0", "1.0.0"), Some(Equal));
        assert_eq!(Scheme::Pep440.compare("1.0-1", "1.0.post1"), Some(Equal));
        assert_eq!(Scheme::Pep440.compare("1.0+local", "1.0"), Some(Equal));
        assert_eq!(Scheme::Pep440.compare("not a version", "1.0"), None);
    }

    #[test]
    fn schemes_by_ecosystem() {
        assert_eq!(
            Scheme::for_ecosystem("Ubuntu:24.04:LTS"),
            Some(Scheme::Dpkg)
        );
        assert_eq!(Scheme::for_ecosystem("Debian:12"), Some(Scheme::Dpkg));
        assert_eq!(Scheme::for_ecosystem("Rocky Linux:9"), Some(Scheme::Rpm));
        assert_eq!(Scheme::for_ecosystem("PyPI"), Some(Scheme::Pep440));
        assert_eq!(Scheme::for_ecosystem("crates.io"), Some(Scheme::Semver));
        assert_eq!(Scheme::for_ecosystem("Maven"), None);
        assert_eq!(Scheme::Semver.compare("1.2.3", "v1.10.0"), Some(Less));
    }
}
