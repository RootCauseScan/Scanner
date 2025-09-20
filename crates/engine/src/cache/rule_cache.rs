use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::Finding;

pub type RuleCacheValue = Vec<Finding>;

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct RuleCacheKey {
    pub file: PathBuf,
    pub rule_id: String,
}

pub struct RuleCache {
    pub(crate) entries: RwLock<HashMap<RuleCacheKey, RuleCacheValue>>,
    pub(crate) order: RwLock<VecDeque<RuleCacheKey>>,
    pub(crate) stats: CacheStats,
}

impl Default for RuleCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleCache {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            order: RwLock::new(VecDeque::new()),
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
        if let Some(value) = self.try_get(&key) {
            return (value, true);
        }

        self.stats.record_miss();
        let value = compute();
        self.insert(key, value.clone(), capacity);
        (value, false)
    }

    pub fn reset(&self) {
        write_lock(&self.entries).clear();
        write_lock(&self.order).clear();
        self.stats.reset();
    }

    pub fn stats(&self) -> (usize, usize) {
        self.stats.snapshot()
    }

    fn try_get(&self, key: &RuleCacheKey) -> Option<RuleCacheValue> {
        let value = read_lock(&self.entries).get(key).cloned();
        if value.is_some() {
            self.stats.record_hit();
            self.mark_used(key.clone());
        }
        value
    }

    fn insert(&self, key: RuleCacheKey, value: RuleCacheValue, capacity: usize) {
        write_lock(&self.entries).insert(key.clone(), value);
        self.mark_used(key);
        self.evict_if_needed(capacity);
    }

    fn mark_used(&self, key: RuleCacheKey) {
        let mut order = write_lock(&self.order);
        if let Some(pos) = order.iter().position(|k| k == &key) {
            order.remove(pos);
        }
        order.push_back(key);
    }

    fn evict_if_needed(&self, capacity: usize) {
        let mut entries = write_lock(&self.entries);
        let mut order = write_lock(&self.order);
        while order.len() > capacity {
            if let Some(oldest) = order.pop_front() {
                entries.remove(&oldest);
            }
        }
    }
}

#[derive(Default)]
pub struct CacheStats {
    hits: AtomicUsize,
    misses: AtomicUsize,
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
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
