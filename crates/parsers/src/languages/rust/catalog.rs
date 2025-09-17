use std::collections::HashSet;

use crate::catalog::Catalog;

pub fn load_catalog() -> Catalog {
    Catalog {
        sources: HashSet::from(["source".into()]),
        sinks: HashSet::from(["sink".into(), "macro::println".into()]),
        sanitizers: HashSet::from(["sanitize".into(), "clean".into(), "escape".into()]),
    }
}
