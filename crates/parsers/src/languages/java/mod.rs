mod ast;
pub mod catalog;
mod dfg_builder;
mod parser;
mod symbol_table;
mod tokens;

pub use parser::{parse_java, parse_java_project, parse_java_project_uncached};

#[cfg(test)]
mod tests;
