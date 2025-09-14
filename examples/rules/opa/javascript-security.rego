package audit.javascript

# Detect use of eval()
deny[msg] if {
    input.file_type == "javascript"
    node := input.nodes[_]
    node.type == "CallExpression"
    node.callee.name == "eval"
    msg := "eval() with untrusted input can lead to code injection"
}

# Detect innerHTML with concatenation
deny[msg] if {
    input.file_type == "javascript"
    node := input.nodes[_]
    node.type == "AssignmentExpression"
    node.left.property.name == "innerHTML"
    node.right.type == "BinaryExpression"
    node.right.operator == "+"
    msg := "innerHTML with string concatenation can lead to XSS - use textContent or createElement"
}

# Detect document.write()
deny[msg] if {
    input.file_type == "javascript"
    node := input.nodes[_]
    node.type == "CallExpression"
    node.callee.property.name == "write"
    node.callee.object.name == "document"
    msg := "document.write() can lead to XSS vulnerabilities"
}

# Detect setTimeout with string
deny[msg] if {
    input.file_type == "javascript"
    node := input.nodes[_]
    node.type == "CallExpression"
    node.callee.name == "setTimeout"
    node.arguments[0].type == "Literal"
    msg := "setTimeout with string can lead to code injection - use function"
}

