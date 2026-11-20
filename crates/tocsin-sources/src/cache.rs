//! A small file cache, so that repeated scans do not download everything again.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Cache { dir: dir.into() }
    }

    /// `$XDG_CACHE_HOME/tocsin`, else `~/.cache/tocsin`.
    pub fn default_dir() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_CACHE_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".cache")))?;
        Some(base.join("tocsin"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, key: &str) -> Option<PathBuf> {
        // Keys come partly from remote data: refuse anything that could escape
        // the directory. A leading `/` would make `join` discard the base.
        let safe = !key.is_empty()
            && !key.starts_with(['.', '/'])
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._:-/".contains(c))
            && !key.contains("..");
        safe.then(|| self.dir.join(key))
    }

    pub fn get(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(self.path(key)?).ok()
    }

    /// Age of a cached entry, `None` when absent.
    pub fn age(&self, key: &str) -> Option<Duration> {
        let modified = std::fs::metadata(self.path(key)?).ok()?.modified().ok()?;
        SystemTime::now().duration_since(modified).ok()
    }

    /// Writes atomically (temporary file, then rename). Errors are ignored:
    /// a cache that cannot be written only makes the next run slower.
    pub fn put(&self, key: &str, content: &str) {
        let Some(path) = self.path(key) else { return };
        let Some(parent) = path.parent() else { return };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        if std::fs::write(&tmp, content).is_ok() && std::fs::rename(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cache(name: &str) -> Cache {
        let dir =
            std::env::temp_dir().join(format!("tocsin-cache-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Cache::new(dir)
    }

    #[test]
    fn round_trip_and_age() {
        let cache = temp_cache("rt");
        assert_eq!(cache.get("osv/GHSA-1.json"), None);
        cache.put("osv/GHSA-1.json", "{}");
        assert_eq!(cache.get("osv/GHSA-1.json").as_deref(), Some("{}"));
        assert!(cache.age("osv/GHSA-1.json").unwrap() < Duration::from_secs(60));
        let _ = std::fs::remove_dir_all(cache.dir());
    }

    #[test]
    fn refuses_keys_escaping_the_directory() {
        let cache = temp_cache("esc");
        for key in [
            "../evil",
            "osv/../../evil",
            "/etc/passwd",
            ".hidden",
            "a b",
            "",
        ] {
            cache.put(key, "x");
            assert_eq!(cache.get(key), None, "{key}");
        }
        let _ = std::fs::remove_dir_all(cache.dir());
    }
}
