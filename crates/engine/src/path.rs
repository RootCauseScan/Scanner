use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};

pub static CANONICAL_PATHS: OnceLock<RwLock<HashMap<PathBuf, PathBuf>>> = OnceLock::new();
pub static CANONICAL_STATS: OnceLock<CacheStats> = OnceLock::new();
pub static CANONICAL_ORDER: OnceLock<RwLock<VecDeque<PathBuf>>> = OnceLock::new();
static PATH_REGEX_CACHE: OnceLock<Mutex<PathRegexCache>> = OnceLock::new();

#[cfg(test)]
pub const CANONICAL_CACHE_CAPACITY: usize = 3;
#[cfg(not(test))]
pub const CANONICAL_CACHE_CAPACITY: usize = 1024;

#[cfg(test)]
pub const PATH_REGEX_CACHE_CAPACITY: usize = 3;
#[cfg(not(test))]
pub const PATH_REGEX_CACHE_CAPACITY: usize = 1024;

#[derive(Default)]
pub struct CacheStats {
    hits: AtomicUsize,
    misses: AtomicUsize,
}

struct PathRegexCache {
    map: HashMap<String, Regex>,
    order: VecDeque<String>,
    capacity: usize,
}

impl PathRegexCache {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn get(&mut self, key: &str) -> Option<&Regex> {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            let k = self.order.remove(pos).expect("order index must exist");
            self.order.push_back(k);
            return self.map.get(key);
        }
        None
    }

    fn insert(&mut self, key: String, value: Regex) {
        if self.map.contains_key(&key) {
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, value);
        if self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }

    #[cfg(test)]
    fn contains(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }
}

pub fn canonicalize_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let path_ref = path.as_ref();
    let cache = CANONICAL_PATHS.get_or_init(|| RwLock::new(HashMap::new()));
    let order = CANONICAL_ORDER.get_or_init(|| RwLock::new(VecDeque::new()));
    let stats = CANONICAL_STATS.get_or_init(Default::default);
    if let Some(cached) = cache
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(path_ref)
        .cloned()
    {
        stats.hits.fetch_add(1, Ordering::Relaxed);
        let mut ord = order.write().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = ord.iter().position(|p| p == path_ref) {
            ord.remove(pos);
        }
        ord.push_back(path_ref.to_path_buf());
        return cached;
    }
    stats.misses.fetch_add(1, Ordering::Relaxed);
    let canonical = fs::canonicalize(path_ref).unwrap_or_else(|_| {
        #[cfg(windows)]
        {
            PathBuf::from(path_ref.to_string_lossy().replace('\\', "/"))
        }
        #[cfg(not(windows))]
        {
            path_ref.to_path_buf()
        }
    });
    let mut map = cache.write().unwrap_or_else(|e| e.into_inner());
    let mut ord = order.write().unwrap_or_else(|e| e.into_inner());
    map.insert(path_ref.to_path_buf(), canonical.clone());
    ord.push_back(path_ref.to_path_buf());
    if ord.len() > CANONICAL_CACHE_CAPACITY {
        if let Some(oldest) = ord.pop_front() {
            map.remove(&oldest);
        }
    }
    canonical
}

pub(crate) fn cache_stats() -> (usize, usize) {
    let stats = CANONICAL_STATS.get_or_init(Default::default);
    (
        stats.hits.load(Ordering::Relaxed),
        stats.misses.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
pub fn reset_canonical_cache() {
    if let Some(map) = CANONICAL_PATHS.get() {
        map.write().unwrap_or_else(|e| e.into_inner()).clear();
    }
    if let Some(ord) = CANONICAL_ORDER.get() {
        ord.write().unwrap_or_else(|e| e.into_inner()).clear();
    }
    if let Some(stats) = CANONICAL_STATS.get() {
        stats.hits.store(0, Ordering::Relaxed);
        stats.misses.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
pub fn canonical_cache_stats() -> (usize, usize) {
    cache_stats()
}

#[cfg(test)]
pub fn reset_path_regex_cache() {
    if let Some(cache) = PATH_REGEX_CACHE.get() {
        cache.lock().unwrap().clear();
    }
}

#[cfg(test)]
pub fn path_regex_cache_size() -> usize {
    PATH_REGEX_CACHE
        .get()
        .map(|c| c.lock().unwrap().len())
        .unwrap_or(0)
}

#[cfg(test)]
pub fn path_regex_cache_contains(pat: &str) -> bool {
    PATH_REGEX_CACHE
        .get()
        .map(|c| c.lock().unwrap().contains(pat))
        .unwrap_or(false)
}

pub fn path_matches(pattern: &str, candidate: &str) -> bool {
    if !pattern
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c) || c == '*')
    {
        return false;
    }
    let cache =
        PATH_REGEX_CACHE.get_or_init(|| Mutex::new(PathRegexCache::new(PATH_REGEX_CACHE_CAPACITY)));
    let mut cache = cache.lock().expect("path regex cache lock poisoned");
    if let Some(rx) = cache.get(pattern) {
        return rx.is_match(candidate);
    }
    let mut re = String::from("^");
    for ch in pattern.chars() {
        if ch == '*' {
            re.push_str(".*");
        } else {
            re.push_str(&regex::escape(&ch.to_string()));
        }
    }
    re.push('$');
    match Regex::new(&re) {
        Ok(rx) => {
            let is_match = rx.is_match(candidate);
            cache.insert(pattern.to_string(), rx);
            is_match
        }
        Err(_) => false,
    }
}
