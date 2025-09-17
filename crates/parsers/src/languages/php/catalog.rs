use std::collections::HashSet;

use crate::catalog::Catalog;

pub fn load_catalog() -> Catalog {
    Catalog {
        sources: HashSet::new(),
        sinks: HashSet::new(),
        sanitizers: HashSet::from([
            "htmlspecialchars".into(),
            "htmlentities".into(),
            "mysqli_real_escape_string".into(),
            "strip_tags".into(),
            "sanitize".into(),
        ]),
    }
}
