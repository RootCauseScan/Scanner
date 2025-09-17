use std::collections::{HashMap, HashSet};
use std::sync::{OnceLock, RwLock};

#[derive(Default)]
pub struct Catalog {
    pub sources: HashSet<String>,
    pub sinks: HashSet<String>,
    pub sanitizers: HashSet<String>,
}

static CATALOGS: OnceLock<RwLock<HashMap<String, Catalog>>> = OnceLock::new();

fn catalogs() -> &'static RwLock<HashMap<String, Catalog>> {
    CATALOGS.get_or_init(|| {
        let mut map = HashMap::new();
        
        // Load catalogs from language-specific modules
        map.insert("python".to_string(), crate::languages::python::catalog::load_catalog());
        map.insert("rust".to_string(), crate::languages::rust::catalog::load_catalog());
        map.insert("java".to_string(), crate::languages::java::catalog::load_catalog());
        map.insert("php".to_string(), crate::languages::php::catalog::load_catalog());
        
        RwLock::new(map)
    })
}

pub fn extend(lang: &str, sources: &[&str], sinks: &[&str], sanitizers: &[&str]) {
    let mut map = catalogs().write().expect("catalogs lock poisoned");
    let entry = map.entry(lang.to_string()).or_default();
    entry.sources.extend(sources.iter().map(|s| s.to_string()));
    entry.sinks.extend(sinks.iter().map(|s| s.to_string()));
    entry
        .sanitizers
        .extend(sanitizers.iter().map(|s| s.to_string()));
}

fn is_in<F>(lang: &str, name: &str, field: F) -> bool
where
    F: Fn(&Catalog) -> &HashSet<String>,
{
    let map = catalogs().read().expect("catalogs lock poisoned");
    map.get(lang).is_some_and(|c| {
        let set = field(c);
        set.contains(name) || set.contains(&format!("macro::{name}"))
    })
}

pub fn is_source(lang: &str, name: &str) -> bool {
    is_in(lang, name, |c| &c.sources)
}

pub fn is_sink(lang: &str, name: &str) -> bool {
    is_in(lang, name, |c| &c.sinks)
}

pub fn is_sanitizer(lang: &str, name: &str) -> bool {
    is_in(lang, name, |c| &c.sanitizers)
}
