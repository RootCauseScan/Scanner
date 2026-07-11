use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::Finding;

pub type RuleCacheValue = Vec<Finding>;

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct RuleCacheKey {
    pub file: PathBuf,
    pub rule_id: String,
    pub content_hash: String,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<RuleCacheKey, RuleCacheValue>,
    /// Keys in least-recently-used order (front = oldest). Kept consistent with
    /// `entries`: a key is present here iff it is present in `entries`.
    order: VecDeque<RuleCacheKey>,
}

pub struct RuleCache {
    inner: Mutex<Inner>,
    stats: CacheStats,
}

impl Default for RuleCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            stats: CacheStats::default(),
        }
    }

    pub fn get_or_insert<F>(
        &self,
        key: RuleCacheKey,
        capacity: usize,
        compute: F,
    ) -> (RuleCacheValue, bool)
    where
        F: FnOnce() -> RuleCacheValue,
    {
        // Fast path: a cache hit. On hit, refresh recency (rare in a full scan,
        // where every (file, rule, hash) key is unique, so this reorder cost is
        // not on the hot path).
        {
            let mut inner = self.lock();
            if let Some(value) = inner.entries.get(&key).cloned() {
                self.stats.record_hit();
                move_to_back(&mut inner.order, &key);
                return (value, true);
            }
        }

        // Miss: compute WITHOUT holding the lock (the closure is the expensive
        // rule evaluation and must not serialize other threads).
        self.stats.record_miss();
        let value = compute();

        let mut inner = self.lock();
        // A fresh miss key is not in `order`, so append in O(1) — no scan.
        if inner.entries.insert(key.clone(), value.clone()).is_none() {
            inner.order.push_back(key);
        }
        while inner.order.len() > capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.entries.remove(&oldest);
            }
        }
        (value, false)
    }

    pub fn reset(&self) {
        let mut inner = self.lock();
        inner.entries.clear();
        inner.order.clear();
        self.stats.reset();
    }

    pub fn stats(&self) -> (usize, usize) {
        self.stats.snapshot()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Moves `key` to the back (most-recently-used) of `order` if present.
fn move_to_back(order: &mut VecDeque<RuleCacheKey>, key: &RuleCacheKey) {
    if let Some(pos) = order.iter().position(|k| k == key) {
        if let Some(k) = order.remove(pos) {
            order.push_back(k);
        }
    }
}

#[derive(Default)]
pub struct CacheStats {
    hits: AtomicUsize,
    misses: AtomicUsize,
}

impl CacheStats {
    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (usize, usize) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }
}
