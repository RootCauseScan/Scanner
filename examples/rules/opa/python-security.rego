package audit.python

# Detect use of eval()
deny[msg] if {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.id == "eval"
    msg := "eval() with untrusted input can lead to code injection"
}

# Detect use of exec()
deny[msg] if {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.id == "exec"
    msg := "exec() with untrusted input can lead to code injection"
}

# Detect pickle.load() on untrusted data
deny[msg] if {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.attr == "load"
    node.func.value.id == "pickle"
    msg := "pickle.load() can execute arbitrary code - use safe alternatives"
}

# Detect subprocess with shell=True
deny[msg] if {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.attr == "run"
    node.func.value.id == "subprocess"
    # Find argument shell=True
    arg := node.args[_]
    arg.arg == "shell"
    arg.value.value == true
    msg := "subprocess with shell=True can lead to command injection"
}

