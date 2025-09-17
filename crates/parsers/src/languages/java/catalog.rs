use std::collections::HashSet;

use crate::catalog::Catalog;

pub fn load_catalog() -> Catalog {
    Catalog {
        sources: HashSet::new(),
        sinks: HashSet::new(),
        sanitizers: HashSet::from([
            "StringEscapeUtils.escapeHtml".into(),
            "org.apache.commons.text.StringEscapeUtils.escapeHtml".into(),
        ]),
    }
}
