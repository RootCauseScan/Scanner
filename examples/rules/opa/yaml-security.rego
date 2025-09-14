package audit.yaml

# Detect plain-text passwords
deny[msg] if {
    input.file_type == "yaml"
    node := input.nodes[_]
    node.key == "password"
    msg := "Password stored in plain text - use secrets or environment variables"
}

# Detect default passwords
deny[msg] if {
    input.file_type == "yaml"
    node := input.nodes[_]
    node.key == "password"
    node.value in ["admin", "root", "password", "123456", "default"]
    msg := "Using default password is a security risk"
}

# Detect privileged containers in docker-compose
deny[msg] if {
    input.file_type == "yaml"
    node := input.nodes[_]
    node.key == "privileged"
    node.value == true
    msg := "Privileged containers have full host access - security risk"
}

# Detect exposed ports without restrictions
deny[msg] if {
    input.file_type == "yaml"
    node := input.nodes[_]
    node.key == "ports"
    port := node.value[_]
    contains(port, "0.0.0.0:")
    msg := "Exposing ports to all interfaces (0.0.0.0) - consider restricting access"
}

