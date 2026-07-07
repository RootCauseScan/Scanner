use ir::{AstNode, BasicBlock, CfgEdge, CfgEdgeKind, FileCFG, FileIR};
use std::collections::HashMap;

/// Builds a real basic-block CFG for a file by walking its AST.
/// Supports JS, TS, Python, and Java; returns None when no AST is available.
pub fn build_file_cfg(file: &FileIR) -> Option<FileCFG> {
    match file.file_type.as_str() {
        "javascript" | "typescript" | "python" | "java" => {}
        _ => return None,
    }
    let ast = file.ast.as_ref()?;

    let mut all_blocks: Vec<BasicBlock> = Vec::new();
    let mut all_edges: Vec<CfgEdge> = Vec::new();
    let mut functions: HashMap<String, (usize, usize)> = HashMap::new();

    for root in &ast.nodes {
        collect_functions(
            root,
            file.file_type.as_str(),
            &mut all_blocks,
            &mut all_edges,
            &mut functions,
        );
    }

    Some(FileCFG {
        blocks: all_blocks,
        edges: all_edges,
        functions,
    })
}

// ── per-function builder ──────────────────────────────────────────────────────

struct Ctx {
    blocks: Vec<BasicBlock>,
    edges: Vec<CfgEdge>,
    /// Stack of (cond_block_id, after_block_id) for break/continue resolution.
    loop_stack: Vec<(usize, usize)>,
    /// Id offset applied to all block ids when merging into the file-level CFG.
    offset: usize,
    fn_name: Option<String>,
    exit_id: usize,
}

impl Ctx {
    fn new(offset: usize, fn_name: Option<String>) -> Self {
        Self {
            blocks: Vec::new(),
            edges: Vec::new(),
            loop_stack: Vec::new(),
            offset,
            fn_name,
            exit_id: 0,
        }
    }

    fn new_block(&mut self, label: &str) -> usize {
        let local_id = self.blocks.len();
        let global_id = self.offset + local_id;
        self.blocks.push(BasicBlock {
            id: global_id,
            label: label.to_string(),
            stmts: Vec::new(),
            line_start: 0,
            line_end: 0,
            function: self.fn_name.clone(),
        });
        global_id
    }

    fn add_edge(&mut self, from: usize, to: usize, kind: CfgEdgeKind) {
        self.edges.push(CfgEdge { from, to, kind });
    }

    fn set_lines(&mut self, block_id: usize, start: usize, end: usize) {
        if let Some(b) = self.block_mut(block_id) {
            if b.line_start == 0 || start < b.line_start {
                b.line_start = start;
            }
            if end > b.line_end {
                b.line_end = end;
            }
        }
    }

    fn add_stmt(&mut self, block_id: usize, stmt_id: usize, line: usize) {
        if let Some(b) = self.block_mut(block_id) {
            b.stmts.push(stmt_id);
            if b.line_start == 0 || line < b.line_start {
                b.line_start = line;
            }
            if line > b.line_end {
                b.line_end = line;
            }
        }
    }

    fn block_mut(&mut self, global_id: usize) -> Option<&mut BasicBlock> {
        self.blocks.get_mut(global_id.wrapping_sub(self.offset))
    }
}

// ── function-level dispatcher ─────────────────────────────────────────────────

fn is_function_node(node: &AstNode, file_type: &str) -> bool {
    match file_type {
        "python" => node.kind == "FunctionDefinition",
        "java" => matches!(
            node.kind.as_str(),
            "MethodDeclaration" | "ConstructorDeclaration"
        ),
        _ => matches!(
            node.kind.as_str(),
            "FunctionDeclaration"
                | "FunctionExpression"
                | "ArrowFunction"
                | "MethodDefinition"
                | "Function"
        ),
    }
}

fn collect_functions(
    node: &AstNode,
    file_type: &str,
    all_blocks: &mut Vec<BasicBlock>,
    all_edges: &mut Vec<CfgEdge>,
    functions: &mut HashMap<String, (usize, usize)>,
) {
    if is_function_node(node, file_type) {
        let fn_name = node.value.as_str().map(|s| s.to_string());
        let offset = all_blocks.len();
        let mut ctx = Ctx::new(offset, fn_name.clone());

        let entry_id = ctx.new_block("entry");
        let exit_id = ctx.new_block("exit");
        ctx.exit_id = exit_id;
        ctx.set_lines(entry_id, node.meta.line, node.meta.line);
        ctx.set_lines(exit_id, node.meta.line, node.meta.line);

        let final_block = process_stmt_list(&node.children, &mut ctx, entry_id, file_type);
        if final_block != exit_id {
            ctx.add_edge(final_block, exit_id, CfgEdgeKind::Sequential);
        }

        if let Some(name) = fn_name {
            functions.insert(name, (entry_id, exit_id));
        }

        all_blocks.extend(ctx.blocks);
        all_edges.extend(ctx.edges);
        return; // don't descend further into function body — already processed
    }

    for child in &node.children {
        collect_functions(child, file_type, all_blocks, all_edges, functions);
    }
}

// ── statement list processor ──────────────────────────────────────────────────

/// Processes a list of statements into `current_block`, returning the block
/// that is "live" after the last statement.
fn process_stmt_list(stmts: &[AstNode], ctx: &mut Ctx, mut current: usize, file_type: &str) -> usize {
    for stmt in stmts {
        current = process_stmt(stmt, ctx, current, file_type);
    }
    current
}

fn process_stmt(node: &AstNode, ctx: &mut Ctx, current: usize, file_type: &str) -> usize {
    let line = node.meta.line;
    match node.kind.as_str() {
        // ── transparent block wrappers — descend into children ─────────────
        // JS/TS StatementBlock, Java Block: don't create a new CFG block,
        // just process the children sequentially in the current block.
        "StatementBlock" | "Block" => {
            process_stmt_list(&node.children, ctx, current, file_type)
        }

        // ── branching ──────────────────────────────────────────────────────
        "IfStatement" | "If" => process_if(node, ctx, current, file_type),
        "WhileStatement" | "While" | "DoStatement" | "Do" => {
            process_while(node, ctx, current, file_type)
        }
        "ForStatement" | "For" => process_for(node, ctx, current, file_type),
        // Java enhanced-for + JS for-in/of
        "ForInStatement" | "ForOfStatement" | "ForIn" | "ForOf" | "EnhancedForStatement" => {
            process_for_in(node, ctx, current, file_type)
        }
        "TryStatement" | "Try" => process_try(node, ctx, current, file_type),
        "SwitchStatement" | "Switch" => process_switch(node, ctx, current, file_type),

        // ── early exits ───────────────────────────────────────────────────
        "ReturnStatement" | "Return" | "ThrowStatement" | "Throw" => {
            ctx.add_stmt(current, node.id, line);
            ctx.add_edge(current, ctx.exit_id, CfgEdgeKind::Sequential);
            // Dead block for any code after return/throw
            ctx.new_block("dead")
        }
        "BreakStatement" | "Break" => {
            if let Some(&(_, after)) = ctx.loop_stack.last() {
                ctx.add_edge(current, after, CfgEdgeKind::Sequential);
            }
            ctx.new_block("dead")
        }
        "ContinueStatement" | "Continue" => {
            if let Some(&(cond, _)) = ctx.loop_stack.last() {
                ctx.add_edge(current, cond, CfgEdgeKind::LoopBack);
            }
            ctx.new_block("dead")
        }

        // ── nested function — don't descend ───────────────────────────────
        k if is_function_node_kind(k, file_type) => current,

        // ── everything else goes into the current block ───────────────────
        _ => {
            ctx.add_stmt(current, node.id, line);
            current
        }
    }
}

fn is_function_node_kind(kind: &str, file_type: &str) -> bool {
    match file_type {
        "python" => kind == "FunctionDefinition",
        "java" => matches!(kind, "MethodDeclaration" | "ConstructorDeclaration" | "LambdaExpression"),
        _ => matches!(
            kind,
            "FunctionDeclaration"
                | "FunctionExpression"
                | "ArrowFunction"
                | "MethodDefinition"
                | "Function"
                | "LambdaExpression"
        ),
    }
}

// ── control flow constructors ─────────────────────────────────────────────────

fn process_if(node: &AstNode, ctx: &mut Ctx, current: usize, file_type: &str) -> usize {
    let line = node.meta.line;
    let cond_block = current;
    ctx.set_lines(cond_block, line, line);

    let true_block = ctx.new_block("if_true");
    let false_block = ctx.new_block("if_false");
    let merge_block = ctx.new_block("if_merge");

    ctx.add_edge(cond_block, true_block, CfgEdgeKind::ConditionalTrue);
    ctx.add_edge(cond_block, false_block, CfgEdgeKind::ConditionalFalse);

    // consequence and alternative children — heuristic: first two non-condition children
    let body_nodes: Vec<&AstNode> = node
        .children
        .iter()
        .filter(|c| !matches!(c.kind.as_str(), "condition" | "Condition"))
        .collect();

    let (consequence, alternative) = match body_nodes.as_slice() {
        [cons] => (Some(*cons), None),
        [cons, alt, ..] => (Some(*cons), Some(*alt)),
        _ => (None, None),
    };

    let true_exit = if let Some(cons) = consequence {
        process_stmt(cons, ctx, true_block, file_type)
    } else {
        true_block
    };
    ctx.add_edge(true_exit, merge_block, CfgEdgeKind::Sequential);

    let false_exit = if let Some(alt) = alternative {
        process_stmt(alt, ctx, false_block, file_type)
    } else {
        false_block
    };
    ctx.add_edge(false_exit, merge_block, CfgEdgeKind::Sequential);

    merge_block
}

fn process_while(node: &AstNode, ctx: &mut Ctx, current: usize, file_type: &str) -> usize {
    let line = node.meta.line;
    let cond_block = ctx.new_block("while_cond");
    let body_block = ctx.new_block("while_body");
    let after_block = ctx.new_block("while_after");

    ctx.add_edge(current, cond_block, CfgEdgeKind::Sequential);
    ctx.set_lines(cond_block, line, line);
    ctx.add_edge(cond_block, body_block, CfgEdgeKind::ConditionalTrue);
    ctx.add_edge(cond_block, after_block, CfgEdgeKind::ConditionalFalse);

    ctx.loop_stack.push((cond_block, after_block));
    let body_exit = process_stmt_list(&node.children, ctx, body_block, file_type);
    ctx.loop_stack.pop();

    ctx.add_edge(body_exit, cond_block, CfgEdgeKind::LoopBack);
    after_block
}

fn process_for(node: &AstNode, ctx: &mut Ctx, current: usize, file_type: &str) -> usize {
    let line = node.meta.line;
    // init stays in current block
    let cond_block = ctx.new_block("for_cond");
    let body_block = ctx.new_block("for_body");
    let update_block = ctx.new_block("for_update");
    let after_block = ctx.new_block("for_after");

    ctx.add_edge(current, cond_block, CfgEdgeKind::Sequential);
    ctx.set_lines(cond_block, line, line);
    ctx.add_edge(cond_block, body_block, CfgEdgeKind::ConditionalTrue);
    ctx.add_edge(cond_block, after_block, CfgEdgeKind::ConditionalFalse);
    ctx.add_edge(update_block, cond_block, CfgEdgeKind::LoopBack);

    // continue → update_block (not cond_block)
    ctx.loop_stack.push((update_block, after_block));
    let body_exit = process_stmt_list(&node.children, ctx, body_block, file_type);
    ctx.loop_stack.pop();

    ctx.add_edge(body_exit, update_block, CfgEdgeKind::Sequential);
    after_block
}

fn process_for_in(node: &AstNode, ctx: &mut Ctx, current: usize, file_type: &str) -> usize {
    let line = node.meta.line;
    let cond_block = ctx.new_block("forin_cond");
    let body_block = ctx.new_block("forin_body");
    let after_block = ctx.new_block("forin_after");

    ctx.add_edge(current, cond_block, CfgEdgeKind::Sequential);
    ctx.set_lines(cond_block, line, line);
    ctx.add_edge(cond_block, body_block, CfgEdgeKind::ConditionalTrue);
    ctx.add_edge(cond_block, after_block, CfgEdgeKind::ConditionalFalse);

    ctx.loop_stack.push((cond_block, after_block));
    let body_exit = process_stmt_list(&node.children, ctx, body_block, file_type);
    ctx.loop_stack.pop();

    ctx.add_edge(body_exit, cond_block, CfgEdgeKind::LoopBack);
    after_block
}

fn process_try(node: &AstNode, ctx: &mut Ctx, current: usize, file_type: &str) -> usize {
    let try_block_id = current;
    let catch_block = ctx.new_block("catch");
    let after_block = ctx.new_block("try_after");

    // Separate try-body, catch, finally children by kind
    let mut try_body = Vec::new();
    let mut catch_body = Vec::new();
    let mut finally_body = Vec::new();
    for child in &node.children {
        match child.kind.as_str() {
            "CatchClause" | "Catch" | "ExceptHandler" => catch_body.push(child),
            "FinallyClause" | "Finally" => finally_body.push(child),
            _ => try_body.push(child),
        }
    }

    ctx.add_edge(try_block_id, catch_block, CfgEdgeKind::Exception);

    let try_exit = process_stmt_list(
        &try_body.into_iter().cloned().collect::<Vec<_>>(),
        ctx,
        try_block_id,
        file_type,
    );

    let catch_exit = if catch_body.is_empty() {
        catch_block
    } else {
        process_stmt_list(
            &catch_body.into_iter().flat_map(|n| n.children.clone()).collect::<Vec<_>>(),
            ctx,
            catch_block,
            file_type,
        )
    };

    if finally_body.is_empty() {
        ctx.add_edge(try_exit, after_block, CfgEdgeKind::Sequential);
        ctx.add_edge(catch_exit, after_block, CfgEdgeKind::Sequential);
    } else {
        let finally_block = ctx.new_block("finally");
        ctx.add_edge(try_exit, finally_block, CfgEdgeKind::ExceptionFinally);
        ctx.add_edge(catch_exit, finally_block, CfgEdgeKind::ExceptionFinally);
        let finally_exit = process_stmt_list(
            &finally_body.into_iter().flat_map(|n| n.children.clone()).collect::<Vec<_>>(),
            ctx,
            finally_block,
            file_type,
        );
        ctx.add_edge(finally_exit, after_block, CfgEdgeKind::Sequential);
    }

    after_block
}

fn process_switch(node: &AstNode, ctx: &mut Ctx, current: usize, file_type: &str) -> usize {
    let after_block = ctx.new_block("switch_after");
    ctx.loop_stack.push((current, after_block));

    // Java wraps cases in SwitchBlock; unwrap one level if present.
    let children_ref: &[AstNode];
    let switch_block_children: Vec<AstNode>;
    if let Some(block) = node.children.iter().find(|c| c.kind == "SwitchBlock") {
        switch_block_children = block.children.clone();
        children_ref = &switch_block_children;
    } else {
        children_ref = &node.children;
    }
    let cases: Vec<&AstNode> = children_ref
        .iter()
        .filter(|c| matches!(
            c.kind.as_str(),
            "SwitchCase" | "SwitchDefault" | "Case" | "Default"
            | "SwitchBlockStatementGroup" | "SwitchRule"
        ))
        .collect();

    let mut prev_exit = current;
    for case in cases {
        let case_block = ctx.new_block("case");
        ctx.add_edge(prev_exit, case_block, CfgEdgeKind::ConditionalTrue);
        prev_exit = process_stmt_list(&case.children, ctx, case_block, file_type);
    }

    ctx.add_edge(prev_exit, after_block, CfgEdgeKind::Sequential);
    ctx.loop_stack.pop();
    after_block
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ir::{AstNode, FileAst, FileIR, Meta};

    fn meta(line: usize) -> Meta {
        Meta { file: "test.js".into(), line, column: 1 }
    }

    fn leaf(kind: &str, line: usize) -> AstNode {
        AstNode {
            id: line * 100,
            kind: kind.to_string(),
            value: serde_json::Value::Null,
            meta: meta(line),
            children: vec![],
            parent: None,
        }
    }

    fn func_node(name: &str, children: Vec<AstNode>) -> AstNode {
        AstNode {
            id: 1,
            kind: "FunctionDeclaration".to_string(),
            value: serde_json::Value::String(name.to_string()),
            meta: meta(1),
            children,
            parent: None,
        }
    }

    fn build(root: AstNode) -> FileCFG {
        let mut fir = FileIR::new("test.js".into(), "javascript".into());
        fir.ast = Some(FileAst {
            file_path: "test.js".into(),
            file_type: "javascript".into(),
            nodes: vec![root],
            index: vec![],
        });
        build_file_cfg(&fir).unwrap()
    }

    #[test]
    fn empty_function_has_entry_and_exit() {
        let cfg = build(func_node("foo", vec![]));
        assert_eq!(cfg.blocks.len(), 2);
        assert_eq!(cfg.edges.len(), 1);
        assert_eq!(cfg.edges[0].kind, CfgEdgeKind::Sequential);
    }

    #[test]
    fn if_creates_four_blocks() {
        let if_node = AstNode {
            id: 10,
            kind: "IfStatement".to_string(),
            value: serde_json::Value::Null,
            meta: meta(2),
            children: vec![leaf("ExpressionStatement", 3)],
            parent: None,
        };
        let cfg = build(func_node("foo", vec![if_node]));
        // entry, if_true, if_false, if_merge, exit = 5 blocks
        assert_eq!(cfg.blocks.len(), 5);
    }

    #[test]
    fn if_else_edge_types() {
        let if_node = AstNode {
            id: 10,
            kind: "IfStatement".to_string(),
            value: serde_json::Value::Null,
            meta: meta(2),
            children: vec![
                leaf("ExpressionStatement", 3),
                leaf("ExpressionStatement", 5),
            ],
            parent: None,
        };
        let cfg = build(func_node("foo", vec![if_node]));
        let has_true = cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::ConditionalTrue);
        let has_false = cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::ConditionalFalse);
        assert!(has_true, "expected ConditionalTrue edge");
        assert!(has_false, "expected ConditionalFalse edge");
    }

    #[test]
    fn while_has_loop_back_edge() {
        let while_node = AstNode {
            id: 20,
            kind: "WhileStatement".to_string(),
            value: serde_json::Value::Null,
            meta: meta(2),
            children: vec![leaf("ExpressionStatement", 3)],
            parent: None,
        };
        let cfg = build(func_node("foo", vec![while_node]));
        assert!(
            cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::LoopBack),
            "expected LoopBack edge"
        );
    }

    #[test]
    fn return_connects_to_exit() {
        let ret = leaf("ReturnStatement", 2);
        let cfg = build(func_node("foo", vec![ret]));
        // entry → exit (from return) + dead → exit (sequential from process_stmt_list end)
        assert!(
            cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::Sequential),
            "return should create sequential edge to exit"
        );
    }

    #[test]
    fn functions_map_populated() {
        let cfg = build(func_node("myFunc", vec![]));
        assert!(cfg.functions.contains_key("myFunc"));
    }

    // ── Java-specific tests ────────────────────────────────────────────────

    fn meta_java(line: usize) -> Meta {
        Meta { file: "Test.java".into(), line, column: 1 }
    }

    fn java_method(name: &str, children: Vec<AstNode>) -> AstNode {
        AstNode {
            id: 1,
            kind: "MethodDeclaration".to_string(),
            value: serde_json::Value::String(name.to_string()),
            meta: meta_java(1),
            children,
            parent: None,
        }
    }

    fn build_java(method: AstNode) -> FileCFG {
        // Wrap in ClassDeclaration → ClassBody to match real Java AST structure
        let class_body = AstNode {
            id: 1000,
            kind: "ClassBody".to_string(),
            value: serde_json::Value::Null,
            meta: meta_java(1),
            children: vec![method],
            parent: None,
        };
        let class = AstNode {
            id: 999,
            kind: "ClassDeclaration".to_string(),
            value: serde_json::Value::Null,
            meta: meta_java(1),
            children: vec![class_body],
            parent: None,
        };
        let mut fir = FileIR::new("Test.java".into(), "java".into());
        fir.ast = Some(FileAst {
            file_path: "Test.java".into(),
            file_type: "java".into(),
            nodes: vec![class],
            index: vec![],
        });
        build_file_cfg(&fir).unwrap()
    }

    fn java_leaf(kind: &str, line: usize) -> AstNode {
        AstNode {
            id: line * 100,
            kind: kind.to_string(),
            value: serde_json::Value::Null,
            meta: meta_java(line),
            children: vec![],
            parent: None,
        }
    }

    #[test]
    fn java_method_produces_entry_and_exit() {
        let cfg = build_java(java_method("run", vec![]));
        assert_eq!(cfg.blocks.len(), 2, "entry + exit");
        assert!(cfg.functions.contains_key("run"));
    }

    #[test]
    fn java_block_wrapper_is_transparent() {
        // MethodDeclaration → Block → statements
        // The Block should be transparent: no extra CFG block created
        let block = AstNode {
            id: 50,
            kind: "Block".to_string(),
            value: serde_json::Value::Null,
            meta: meta_java(2),
            children: vec![java_leaf("LocalVariableDeclaration", 3)],
            parent: None,
        };
        let cfg = build_java(java_method("run", vec![block]));
        // entry + exit only — Block doesn't add an extra block
        assert_eq!(cfg.blocks.len(), 2);
    }

    #[test]
    fn java_if_in_block_creates_correct_blocks() {
        let if_node = AstNode {
            id: 10,
            kind: "IfStatement".to_string(),
            value: serde_json::Value::Null,
            meta: meta_java(3),
            children: vec![java_leaf("ExpressionStatement", 4)],
            parent: None,
        };
        let block = AstNode {
            id: 50,
            kind: "Block".to_string(),
            value: serde_json::Value::Null,
            meta: meta_java(2),
            children: vec![if_node],
            parent: None,
        };
        let cfg = build_java(java_method("run", vec![block]));
        // entry, if_true, if_false, if_merge, exit
        assert_eq!(cfg.blocks.len(), 5);
        assert!(cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::ConditionalTrue));
        assert!(cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::ConditionalFalse));
    }

    #[test]
    fn java_enhanced_for_has_loop_back() {
        let for_node = AstNode {
            id: 20,
            kind: "EnhancedForStatement".to_string(),
            value: serde_json::Value::Null,
            meta: meta_java(3),
            children: vec![java_leaf("ExpressionStatement", 4)],
            parent: None,
        };
        let cfg = build_java(java_method("run", vec![for_node]));
        assert!(
            cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::LoopBack),
            "enhanced-for should produce LoopBack edge"
        );
    }

    #[test]
    fn java_lambda_inside_method_is_not_descended() {
        // LambdaExpression inside the method body should be treated as
        // an opaque nested function — the builder should NOT descend into it.
        let lambda = AstNode {
            id: 30,
            kind: "LambdaExpression".to_string(),
            value: serde_json::Value::Null,
            meta: meta_java(3),
            // Contains a ReturnStatement that would create extra blocks if descended
            children: vec![java_leaf("ReturnStatement", 4)],
            parent: None,
        };
        let cfg = build_java(java_method("run", vec![lambda]));
        // Only entry + exit — lambda body not processed
        assert_eq!(cfg.blocks.len(), 2);
    }

    #[test]
    fn java_try_catch_has_exception_edge() {
        let try_node = AstNode {
            id: 40,
            kind: "TryStatement".to_string(),
            value: serde_json::Value::Null,
            meta: meta_java(3),
            children: vec![
                java_leaf("ExpressionStatement", 4),
                AstNode {
                    id: 41,
                    kind: "CatchClause".to_string(),
                    value: serde_json::Value::Null,
                    meta: meta_java(5),
                    children: vec![java_leaf("ExpressionStatement", 6)],
                    parent: None,
                },
            ],
            parent: None,
        };
        let cfg = build_java(java_method("run", vec![try_node]));
        assert!(
            cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::Exception),
            "try-catch should produce Exception edge"
        );
    }
}
