---
id: Maturity
title: Maturity Guide
description: Parser maturity levels (L1-L8) and evaluation criteria
sidebar_position: 2
---

# Maturity Guide

**Parser Maturity Levels (L1-L8)**

This document defines parser/engine maturity levels (not rules) and the tests that justify each level.
To declare a level Lk, all tests from L1..Lk must be passed.

In short: less faith, more #[test]. Truth fits in an assert!.

## How it is evaluated

The project exposes a common `tests.rs` suite with modules by level (`l1_*`, `l2_*`, …).

Each language imports that suite and provides the minimal snippets that make sense in its semantics.

If a test does not apply to a language (e.g., `unsafe` in Python), it is ignored only in that language.

## Engine scoring map (0–100)

- **L1**: 10–20
- **L2**: 21–35  
- **L3(BASIC)**: 36–50
- **L4**: 51–65
- **L5**: 66–75
- **L6(ADVANCED)**: 76–85
- **L7**: 86–95
- **L8 (Complete)**: 96–100

(Points come from internal scoring: AST/IR, names, CFG/CallGraph, DFG, taint, language semantics, precision and scale.)

## L1 — Basic syntactic

**What this level means**: The parser can build a real Abstract Syntax Tree from source code and extract basic semantic events into an Intermediate Representation. This is the foundation level that proves the parser can understand the language syntax.

**Capabilities**:
- AST from real grammar, with file/line/column
- IR with events: import, assign, call
- Basic call canonicalization (resolves simple aliases)

**Does not cover**: Dataflow, taint, interprocedural, CFG

**Required tests to verify and prevent regressions**:
- `l1_ast_and_ir_minimos`: 
  - AST exists and contains nodes with correct file/line/column metadata
  - IR captures at least import, assign, and call events
  - All nodes have metadata > 0 (non-zero line/column)
- `l1_canonicalizacion_basica`: 
  - Simple alias (import x as y) is resolved in call path
  - Function calls use canonical names after alias resolution
- `l1_syntax_error_handling`: 
  - Parser gracefully handles syntax errors without crashing
  - Returns partial AST for valid portions of malformed code

## L2 — Name resolution

**What this level means**: The parser can resolve symbol names correctly, understanding imports, aliases, and namespaces. This enables accurate tracking of where symbols come from and how they are used throughout the codebase.

**Capabilities**:
- Aliasing by import as and by assignment (b = a)
- Namespaces/qualifiers (e.g., pkg.mod.func, self/super/crate in Rust)
- Relative/wildcard imports (Python) or nested use (Rust) reflected in IR

**Does not cover**: Dataflow beyond simple alias

**Required tests to verify and prevent regressions**:
- `l2_aliasing_y_canonicalizacion`: 
  - Calls use canonical path after alias resolution
  - Import aliases are properly resolved in function calls
  - Assignment aliases (b = a) are tracked correctly
- `l2_imports_compuestos`: 
  - Python `from .mod import *` appears expanded in IR
  - Rust `use std::{fmt, io::{self, Read}}` appears expanded in IR
  - Relative imports resolve to correct module paths
- `l2_namespace_resolution`: 
  - Qualified names (pkg.mod.func) are resolved correctly
  - Language-specific qualifiers (self/super/crate) work as expected
- `l2_import_cycle_detection`: 
  - Circular imports are detected and handled gracefully
  - Parser doesn't crash on import cycles

## L3 — Intra-procedural dataflow (with catalog)

**What this level means**: The parser can track data flow within functions, understanding how values flow from definitions to uses, and can identify security-relevant sources, sinks, and sanitizers using a centralized catalog. This enables basic taint analysis within single functions.

**Capabilities**:
- DFG with Def/Use/Assign
- Central catalog of sources/sinks/sanitizers (extensible at runtime)
- Direct call graph (callee by simple name)

**Does not cover**: Interprocedural or path-sensitivity

**Required tests to verify and prevent regressions**:
- `l3_def_use_y_sanitizers_catalogo`: 
  - `a = source(); b = sanitize(a); sink(b)` → edge a→b and b.sanitized=true
  - Data flow edges are correctly established between def and use
  - Sanitization status is properly tracked and propagated
- `l3_call_graph_directo`: 
  - Function f defined and called → call graph registers caller→f
  - Direct function calls are captured in call graph
  - Method calls on objects are included in call graph
- `l3_catalog_integration`: 
  - Sources/sinks/sanitizers from catalog are correctly identified
  - Runtime catalog extensions work properly
  - Language-specific patterns are recognized (e.g., SQL injection patterns)
- `l3_taint_propagation_basic`: 
  - Taint flows through assignments: `x = tainted; y = x` → y is tainted
  - Taint is cleared by sanitizers: `x = sanitize(tainted)` → x is clean
  - Multiple sanitizers work correctly: `x = sanitize1(sanitize2(tainted))`

## L4 — Basic interprocedural (context-insensitive)

**What this level means**: The parser can track data flow across function boundaries, connecting arguments to parameters and return values to their destinations. This enables taint analysis that spans multiple functions, though without considering the specific calling context.

**Capabilities**:
- Param and Return nodes in DFG
- Link arg(i) → param(i) and return → callsite assignment
- Taint/sanitization propagation through calls (without context)

**Does not cover**: Call context (per-callsite), complex polymorphism

**Required tests to verify and prevent regressions**:
- `l4_args_a_params`: 
  - `def f(p): return p; x=source(); y=f(x)` → edge x.def → p.param
  - Function arguments are correctly linked to parameters
  - Multiple parameters are handled correctly
- `l4_returns_a_destino`: 
  - Edge return(f) → y.def is established
  - Return values are linked to their assignment destinations
  - Multiple return statements are handled
- `l4_taint_a_traves_de_llamada`: 
  - `sanitize(f(source()))` cleans the propagated value
  - Taint flows through function calls correctly
  - Sanitization in called functions affects the result
- `l4_nested_calls`: 
  - `f(g(source()))` correctly propagates taint through nested calls
  - Complex call chains maintain taint information
- `l4_method_calls`: 
  - Object method calls propagate taint correctly
  - `obj.method(tainted)` → method parameter is tainted

## L5 — Path sensitivity

**What this level means**: The parser can distinguish between different execution paths (branches) and merge state information conservatively. This prevents false negatives by ensuring that a variable is only considered sanitized if it's sanitized in ALL possible execution paths.

**Capabilities**:
- Branch labels on nodes (e.g., branch_id)
- Merge: a variable is sanitized only if it is in all branches
- if/elif/else, while, for generate coherent uses

**Does not cover**: Explicit CFG by blocks; it is "light path-sensitivity"

**Required tests to verify and prevent regressions**:
- `l5_merge_conservador`:

```python
if cond: 
    a = sanitize(x)
else:    
    a = x
sink(a)  # must be considered NOT sanitized
```

- `l5_while_for_uso`: 
  - Variables in conditions/loops appear as Use and link to their Def
  - Loop variables are properly tracked across iterations
  - Break/continue statements don't break data flow
- `l5_nested_branches`: 
  - Nested if statements maintain separate branch contexts
  - Complex conditional logic preserves path information
- `l5_switch_case_handling`: 
  - Switch/case statements are handled as separate paths
  - Default cases are properly merged with other paths
- `l5_exception_handling`: 
  - Try/catch blocks create separate execution paths
  - Exception handling doesn't break taint propagation

## L6 — Language-specific semantics + heap/fields

**What this level means**: The parser understands language-specific features and can track data flow through object fields, container operations, and language-specific constructs. This enables more precise analysis by understanding how data flows through complex data structures and language-specific operations.

**Capabilities**:
- Python: relative imports, wildcard, and heuristics for dynamics (getattr/setattr) or async/await in IR/DFG
- Rust: unsafe in IR/DFG, macros as "calls" queried in catalog, complete nested use
- Field/heap/container flow: `obj.attr`, `map["k"]`, `Vec::push/pop`, `Option/Result` (basic flow)

**Does not cover**: Type inference or advanced points-to (alias)

**Required tests to verify and prevent regressions**:
- `l6_fields_y_containers`: 
  - `cfg.endpoint = source(); sink(cfg.endpoint)` → edge source → cfg.endpoint → sink
  - Object field access propagates taint correctly
  - Container operations (push/pop) maintain data flow
- `l6_semantica_especifica`:
  - Python: `from .utils import *` and `getattr(obj, "m")(x)` produce reasonable IR/DFG
  - Rust: `unsafe { ... }` labels nodes; `println!` registered as macro::println and queried in catalog
- `l6_dynamic_features`: 
  - Dynamic method calls (getattr/setattr) are handled appropriately
  - Reflection and metaprogramming features don't break analysis
- `l6_container_operations`: 
  - Array/list operations maintain taint: `arr[0] = tainted; sink(arr[0])`
  - Map/dictionary operations: `map[key] = tainted; sink(map[key])`
  - Language-specific containers (Vec, HashMap, etc.) work correctly
- `l6_async_await`: 
  - Async/await constructs are properly represented in IR/DFG
  - Promise/future handling maintains data flow

## L7 — Engineering and scale

**What this level means**: The parser can handle real-world projects with multiple files, provides robust error handling, and includes engineering features like caching and incremental analysis. This level focuses on production readiness and scalability.

**Capabilities**:
- Multi-file/project: real unit resolution (mod, packages)
- Incremental analysis/cache/parallelism
- Error tolerance (does not "crash" on a faulty file)
- Reproducible reporting (stable IDs, correct positions)
- Internal metrics (tests/corpus; harness for FP/FN)

**Does not cover**: SSA or advanced alias/points-to analysis

**Required tests to verify and prevent regressions**:
- `l7_multi_archivo`: 
  - A mod or `from pkg import x` resolves to its real unit
  - Cross-file imports are correctly resolved
  - Package/module boundaries are respected
- `l7_incremental_basico`: 
  - Recompiling without changes does not redo everything (measured by counter/cache)
  - Cache invalidation works correctly when files change
  - Only modified files and their dependents are re-analyzed
- `l7_robustez`: 
  - File with broken syntax → the rest of the project is analyzed
  - Parser continues analysis despite individual file failures
  - Error reporting is comprehensive and actionable
- `l7_parallel_analysis`: 
  - Multiple files can be analyzed in parallel
  - Thread safety is maintained during analysis
  - Performance scales with available CPU cores
- `l7_stable_reporting`: 
  - Finding IDs remain stable across runs
  - Line/column positions are accurate and consistent
  - Reports are deterministic and reproducible
- `l7_memory_management`: 
  - Large projects don't cause memory exhaustion
  - Memory usage scales reasonably with project size
  - Garbage collection of unused analysis data works correctly

## L8 — Complete (industrial)

**What this level means**: The parser achieves industrial-grade precision with advanced analysis techniques like SSA, context-sensitive interprocedural analysis, and type-aware data flow. This level provides the highest accuracy while maintaining reasonable performance through sophisticated optimizations.

**Capabilities**:
- SSA-lite or version-based renaming (`x#1`, `x#2`) for merges and aliases
- Context-sensitive interprocedural (summaries per callsite or k-CFA light)
- Approximate type inference/constraints to improve dataflow
- Simple alias/points-to heuristics (`refs/borrows/Box/Arc` in Rust; common objects in Python)
- Time/memory budgets, limits and reasonable timeouts

**Required tests to verify and prevent regressions**:
- `l8_ssa_y_merge`: 
  - Two definitions of x in branches do not get confused when merged
  - SSA form correctly distinguishes different versions of variables
  - Phi nodes properly merge values from different paths
- `l8_context_sensitive`: 
  - Two calls to the same function with different sanitizer do not share state
  - Context-sensitive analysis maintains separate state per call site
  - Function summaries are context-aware
- `l8_tipos_mejoran_precision`: 
  - A constant numeric value marked as safe does not contaminate a string sink
  - Type information improves data flow precision
  - Type constraints prevent impossible flows
- `l8_presupuestos`: 
  - Analysis of large corpus within configured budget
  - Time and memory limits are respected
  - Performance remains acceptable on industrial-scale codebases
- `l8_alias_analysis`: 
  - Simple alias/points-to heuristics work correctly
  - Reference tracking (`refs/borrows/Box/Arc` in Rust) is accurate
  - Object aliasing in dynamic languages is handled appropriately
- `l8_precision_metrics`: 
  - False positive rate is below acceptable threshold
  - False negative rate is minimized
  - Analysis precision is measured and tracked

## Test Implementation Guidelines

### File Organization

Each language parser should implement maturity tests in separate files by level:

```
crates/parsers/src/languages/<lang>/tests/
├── maturity_l1.rs    # L1 tests
├── maturity_l2.rs    # L2 tests
├── maturity_l3.rs    # L3 tests
├── maturity_l4.rs    # L4 tests
├── maturity_l5.rs    # L5 tests
├── maturity_l6.rs    # L6 tests
├── maturity_l7.rs    # L7 tests
└── maturity_l8.rs    # L8 tests
```

### Running maturity tests

```bash
# Run all tests for a specific level
cargo test -p parsers l1_tests
cargo test -p parsers l2_tests

# Run all maturity tests for a specific language
cargo test -p parsers maturity_python

# Run tests for a specific level across all languages
cargo test -p parsers l1_ast_and_ir_minimos

# Run all maturity tests
cargo test -p parsers maturity
```

### Test requirements

- **File organization**: Each level in separate file (`maturity_l<X>.rs`)
- **Documentation**: Each test file and function must be well documented
- **Fixtures**: Use `examples/fixtures/<language>/` for test data
- **Good/Bad cases**: Each test should have clear positive and negative examples
- **Assertions**: Tests must be deterministic and fail fast on regressions
- **Coverage**: Each capability must have at least one test case
- **Performance**: Tests should complete within reasonable time limits
- **Error messages**: Assertions should include descriptive error messages

## Minimal glossary

- **AST**: Abstract syntax tree
- **IR**: Intermediate representation (normalized events)
- **DFG**: Data flow graph (Def/Use/Assign/Param/Return nodes + edges)
- **Call graph**: Call graph (caller→callee)
- **Catalog**: Central table of sources/sinks/sanitizers per language
- **Path-sensitive**: Analysis distinguishes branches and merges state

## Current status of languages

| Language | Level Achieved | Score | Status |
| --- | --- | --- | --- |
| Python | L8 | 96 | Industrial |
| Rust | L6 | 65 | Advanced |
| Java | L4 | 40 | Intermediate |
| PHP | L4 | 40 | Intermediate |
| Dockerfile | L1 | 15 | Prototype |
| YAML | L1 | 15 | Prototype |
| HCL (Terraform) | L1 | 15 | Prototype |
| TypeScript | L1 | 15 | Prototype |
| JavaScript | L1 | 15 | Prototype |
| Go | L1 | 15 | Prototype |
| Ruby | L1 | 15 | Prototype |

Python reached L8 by incorporating:
- Multi-file analysis and incremental cache (L7)
- SSA-lite and context-sensitive interprocedural analysis (L8)
- Type-aware data flow and precision metrics (L8)
- Industrial-grade performance and scalability (L8)

### Classification by status

- **Prototype (L1)**: Minimal AST, science fiction and courage
- **Syntactic (L2)**: Basic AST/IR, limited semantics  
- **Intermediate (L3-L5)**: Useful DFG, intra taint, path-sensitive
- **Advanced (L6-L7)**: Specific semantics, engineering and scale
- **Industrial (L8)**: High precision and context, complete scale
