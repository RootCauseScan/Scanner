/// This file serves the diferents parsers for the SAST engine
///
/// The parsers are grouped by language type:
/// - Configuration Languages
/// - Programing Languages
///
/// Each parser is a module that contains the parse_<language> function.
///
/// The parsers are used in the engine to parse the code and generate the IR.
///
// ====================================
// Configuration Languages           ==
// ====================================
pub mod yaml;
pub use yaml::parse_yaml;

pub mod dockerfile;
pub use dockerfile::parse_dockerfile;

pub mod hcl;
pub use hcl::parse_hcl;
pub mod json;
pub use json::parse_json;
pub mod generic;
pub use generic::parse_generic;
// ====================================

// ====================================
// Programing Languages              ==
// ====================================
pub mod python;

pub mod rust;
pub use rust::parse_rust;
// ====================================

// ====================================================================
// ! NO STABLES
// ! This languages are not stable, the code just stay for the future
// ====================================================================

pub mod go;
pub use go::parse_go;

pub mod java;
pub use java::parse_java;

pub mod javascript;
pub use javascript::parse_javascript;

pub mod typescript;
pub use typescript::parse_typescript;

pub mod php;
pub use php::{parse_php, parse_php_project};

pub mod ruby;
pub use ruby::parse_ruby;
